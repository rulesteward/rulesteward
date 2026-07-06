//! fapolicyd trust-DB reader (heed, read-only).

use std::path::{Path, PathBuf};

use heed::types::Bytes;
use heed::{Database, Env};
use serde::Serialize;

mod decode;
mod env;
mod hash;

use decode::validate_trust_key;
use env::{MDB_MAX_KEY_SIZE, hashed_key_forms};
use hash::path_to_hash;

pub use decode::TrustSource;
pub use env::{IntegrityMode, open_trustdb_readonly};
pub use hash::{sha256_file, verify_entry, weak_digest_algorithm};

pub(crate) use decode::parse_trust_value;

#[cfg(any(test, feature = "test-fixtures"))]
pub use env::open_trustdb_readonly_nolock;

// Only referenced from `mod tests` below (via `super::to_hex` /
// `super::render_raw_bytes`), which is itself `#[cfg(test)]`-gated; without
// this gate a non-test build reports these as unused imports.
#[cfg(test)]
use decode::render_raw_bytes;
#[cfg(test)]
use hash::to_hex;

#[derive(Debug, thiserror::Error)]
pub enum TrustDbError {
    #[error("trust DB has no \"trust.db\" sub-database at {0}")]
    Missing(PathBuf),
    #[error("heed error: {0}")]
    Open(#[from] heed::Error),
    #[error("malformed trust-DB value for key {key:?}: {raw:?}")]
    MalformedValue { key: String, raw: String },
    /// A trust-DB record failed a structural sanity check that a faithfully
    /// written fapolicyd record can never fail: the value carried a NUL or a
    /// non-`{digit, space, lowercase-hex}` byte, or the key was neither a
    /// legitimate fapolicyd key shape (an absolute NUL-free path, OR a
    /// `path_to_hash` 128-hex digest for an over-long path). Under the `NO_LOCK`
    /// fallback reader (#291/#317) this is the most likely surface of a torn read
    /// (the daemon freed and reused the page under our borrow), so it is reported
    /// as its own variant rather than folded into `MalformedValue`: in a log it
    /// names the actual hazard. `raw` carries a FAITHFUL escaped rendering of the
    /// original bytes (`\xHH` for non-printable / high-bit), not the lossy string,
    /// so the actual torn byte stays visible. NOTE (Layer-2 caveat): detection is
    /// PROBABILISTIC - a torn window can still be shape-valid - so this is the
    /// floor, not the guarantee; the locked prevention path (Layer 1) is what
    /// guarantees integrity on a writable dir.
    #[error("torn/corrupt trust-DB record for key {key:?}: {raw:?}")]
    TornRead { key: String, raw: String },
}

/// A single entry read from the fapolicyd trust DB.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TrustEntry {
    pub path: String,
    pub source: TrustSource,
    pub size: u64,
    pub digest: String,
}

/// Result of comparing a `TrustEntry`'s recorded metadata against the file
/// currently on disk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum DiskVerdict {
    /// File exists on disk and both size and hash match.
    Match,
    /// File is absent from disk (or is a dangling symlink).
    Missing,
    /// File exists but its on-disk size differs from the recorded size.
    SizeMismatch { recorded: u64, actual: u64 },
    /// File exists and size matches, but the SHA-256 digest differs.
    HashMismatch { recorded: String, actual: String },
    /// The file could not be read; contains the OS error message.
    ReadError(String),
}

/// Read-only handle on a fapolicyd trust DB. Owns the heed `Env`; each query
/// opens its own short-lived read transaction (`Database` is a cheap Copy dbi handle).
#[derive(Debug)]
pub struct TrustDb {
    env: Env,
    db: Database<Bytes, Bytes>,
    path: PathBuf,
}

impl TrustDb {
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Return all entries in the trust DB as a flat `Vec<TrustEntry>`.
    ///
    /// Each distinct key may have multiple value rows (fapolicyd uses DUPSORT);
    /// every value-row surfaces as its own `TrustEntry` (no key dedup).
    pub fn iter_entries(&self) -> Result<Vec<TrustEntry>, TrustDbError> {
        let rtxn = self.env.read_txn()?;
        let mut out: Vec<TrustEntry> = Vec::new();
        for item in self.db.iter(&rtxn)? {
            let (k, v) = item?;
            let decoded = String::from_utf8_lossy(k).into_owned();
            // Layer-2 torn-read floor (#291/#317): the key must be a legitimate
            // fapolicyd key shape (an absolute path, OR a path_to_hash 128-hex
            // key for an over-long path). Returns the canonical surfaced key
            // (hashed-key trailing NUL trimmed); a torn/garbage key is rejected.
            let path = validate_trust_key(k, &decoded)?;
            let (source, size, digest) = parse_trust_value(v)?;
            out.push(TrustEntry {
                path,
                source,
                size,
                digest,
            });
        }
        Ok(out)
    }

    /// Return all `TrustEntry` rows for the given absolute path, or `None` if
    /// the path is not present in the DB. DUPSORT keys surface every value-row.
    ///
    /// For paths whose byte-length exceeds `MDB_MAX_KEY_SIZE` (511), fapolicyd
    /// stores the entry under the `path_to_hash` hashed key (lowercase-hex
    /// SHA-512 of the path bytes; see trustdb.rs:243-271 and `path_to_hash`
    /// above). This method transparently hashes long-path lookups so callers
    /// always supply the real path rather than a pre-hashed key.
    pub fn get_entry(&self, p: &str) -> Result<Option<Vec<TrustEntry>>, TrustDbError> {
        let rtxn = self.env.read_txn()?;
        // `get_duplicates` yields every value-row stored under the key (or None
        // if the key is absent). For a non-DUPSORT db it still yields the single
        // row, so this is correct for both fixture shapes.
        let collect = |lookup_bytes: &[u8]| -> Result<Option<Vec<TrustEntry>>, TrustDbError> {
            let Some(iter) = self.db.get_duplicates(&rtxn, lookup_bytes)? else {
                return Ok(None);
            };
            let mut rows: Vec<TrustEntry> = Vec::new();
            for item in iter {
                let (_k, v) = item?;
                let (source, size, digest) = parse_trust_value(v)?;
                rows.push(TrustEntry {
                    path: p.to_owned(),
                    source,
                    size,
                    digest,
                });
            }
            Ok(if rows.is_empty() { None } else { Some(rows) })
        };

        if p.len() > MDB_MAX_KEY_SIZE {
            // Long path: stored under a path_to_hash key. Try the daemon's real
            // 129-byte (128 hex + NUL) form first, then the bare 128-hex form
            // (see hashed_key_forms). Short paths key by their literal bytes.
            let hash = path_to_hash(p);
            for lookup in hashed_key_forms(&hash) {
                if let Some(rows) = collect(&lookup)? {
                    return Ok(Some(rows));
                }
            }
            Ok(None)
        } else {
            collect(p.as_bytes())
        }
    }

    /// True iff `p` is an exact key in the trust DB.
    ///
    /// For paths whose byte-length exceeds `MDB_MAX_KEY_SIZE` (511), fapolicyd
    /// stores the entry under the `path_to_hash` hashed key (lowercase-hex
    /// SHA-512 of the path bytes; see trustdb.rs:243-271 and `path_to_hash`
    /// above). This method transparently hashes long-path lookups so callers
    /// always supply the real path.
    #[must_use]
    pub fn contains_path(&self, p: &str) -> bool {
        // A txn-open failure is intentionally treated as "not in DB" (fail-safe:
        // the trust-DB lints warn on an absent path rather than erroring out).
        let Ok(rtxn) = self.env.read_txn() else {
            return false;
        };
        // Literal key for short paths; for long paths try the daemon's real
        // 129-byte (128 hex + NUL) hashed key, then the bare 128-hex form (see
        // hashed_key_forms), so this matches a real daemon-written DB.
        if p.len() > MDB_MAX_KEY_SIZE {
            let hash = path_to_hash(p);
            hashed_key_forms(&hash)
                .iter()
                .any(|k| matches!(self.db.get(&rtxn, k), Ok(Some(_))))
        } else {
            matches!(self.db.get(&rtxn, p.as_bytes()), Ok(Some(_)))
        }
    }

    /// All distinct keys (paths). DUPSORT yields one row per value; consecutive
    /// duplicate keys are collapsed.
    pub fn iter_paths(&self) -> Result<Vec<String>, TrustDbError> {
        let rtxn = self.env.read_txn()?;
        let mut out: Vec<String> = Vec::new();
        for item in self.db.iter(&rtxn)? {
            let (k, _v) = item?;
            let decoded = String::from_utf8_lossy(k).into_owned();
            // Layer-2 torn-read floor (#291/#317): accept an absolute path OR a
            // path_to_hash 128-hex key; reject a torn/garbage key. Returns the
            // canonical surfaced key (hashed-key trailing NUL trimmed).
            let key = validate_trust_key(k, &decoded)?;
            if out.last().map(String::as_str) != Some(key.as_str()) {
                out.push(key);
            }
        }
        Ok(out)
    }
}

/// Shared trust-DB test fixture. Used by `trustdb`, `trust_path` (W06), and
/// `cross_db` (X01) unit tests - do not duplicate; import via
/// `crate::trustdb::write_fixture`.
///
/// Opens a fresh LMDB environment in `dir` with a named `"trust.db"` database
/// and inserts one row per path key. Values mimic the fapolicyd on-disk
/// format: `"<src_int> <size_bytes> <sha256_hex>"`. The environment is closed
/// (dropped) before returning, so the caller can immediately re-open it
/// read-only.
#[cfg(test)]
#[allow(unsafe_code)]
pub(crate) fn write_fixture(dir: &Path, keys: &[&str]) {
    // SAFETY: opens a freshly-created tempdir LMDB env RW to build a test
    // fixture; no other process touches it. heed's open is unsafe (mmap).
    let env = unsafe {
        heed::EnvOpenOptions::new()
            .max_dbs(1)
            .open(dir)
            .expect("write_fixture: failed to open LMDB env")
    };
    let mut wtxn = env.write_txn().expect("write_fixture: write_txn failed");
    let db: heed::Database<heed::types::Bytes, heed::types::Bytes> = env
        .create_database(&mut wtxn, Some("trust.db"))
        .expect("write_fixture: create_database failed");
    for key in keys {
        // Value mimics fapolicyd: "<src_int> <size> <sha256_hex>"
        let value = b"1 12345 aabbccdd0011223344556677889900aabbccdd0011223344556677889900aabb";
        db.put(&mut wtxn, key.as_bytes(), value)
            .expect("write_fixture: put failed");
    }
    wtxn.commit().expect("write_fixture: commit failed");
    // env is dropped here - LMDB file is flushed and closed.
}

/// Build a trust-DB-shaped LMDB fixture with caller-controlled raw value bytes.
///
/// Unlike `write_fixture` (which writes a single hard-coded value per key), this
/// inserts arbitrary `(key, raw-value)` rows, so tests can control the exact
/// `"<src_int> <size> <sha256_hex>"` bytes (for `verify_entry` Match/Mismatch
/// cases) and store TWO distinct value-rows under ONE key (for DUPSORT
/// `iter_entries`/`get_entry` coverage).
///
/// The database is created with `MDB_DUPSORT` (matching fapolicyd's on-disk
/// layout) under the named `"trust.db"` sub-database with `max_dbs(2)`, exactly
/// what `open_trustdb_readonly` expects. The env is dropped before returning so
/// the caller can immediately re-open it read-only.
///
/// Feature-gated behind `test-fixtures` (off in the shipped binary); enabled by
/// the CLI crate's dev-dependencies for e2e + DUPSORT tests. Also compiled for
/// this crate's own `#[cfg(test)]` runs so the inline DUPSORT tests can use it
/// without requiring `--features test-fixtures`.
#[cfg(any(test, feature = "test-fixtures"))]
#[allow(unsafe_code)]
pub fn write_trustdb_fixture_kv(dir: &Path, rows: &[(&str, &[u8])]) {
    // SAFETY: opens a freshly-created tempdir LMDB env RW to build a test
    // fixture; no other process touches it. heed's open is unsafe (mmap aliasing
    // contract). This mirrors the audited `write_fixture` above; the only unsafe
    // in shipped code remains the read-only open in `open_trustdb_readonly`.
    let env = unsafe {
        heed::EnvOpenOptions::new()
            .max_dbs(2)
            .open(dir)
            .expect("write_trustdb_fixture_kv: failed to open LMDB env")
    };
    let mut wtxn = env
        .write_txn()
        .expect("write_trustdb_fixture_kv: write_txn failed");
    let db: heed::Database<heed::types::Bytes, heed::types::Bytes> = env
        .database_options()
        .types::<heed::types::Bytes, heed::types::Bytes>()
        .flags(heed::DatabaseFlags::DUP_SORT)
        .name("trust.db")
        .create(&mut wtxn)
        .expect("write_trustdb_fixture_kv: create_database failed");
    for (key, value) in rows {
        db.put(&mut wtxn, key.as_bytes(), value)
            .expect("write_trustdb_fixture_kv: put failed");
    }
    wtxn.commit()
        .expect("write_trustdb_fixture_kv: commit failed");
    // env is dropped here - LMDB file is flushed and closed.
}

#[cfg(test)]
// The `verify_matches_sha512_file` frozen test uses `.map(|b| format!("{b:02x}")).collect()`
// which triggers `clippy::format_collect`. The fix (fold + write!) would require editing
// a frozen test body - the allow is added at the module level instead.
#[allow(clippy::format_collect)]
mod tests {
    use super::to_hex;
    use super::write_fixture;
    use super::write_trustdb_fixture_kv;
    use super::{
        DiskVerdict, IntegrityMode, TrustDbError, TrustEntry, TrustSource, open_trustdb_readonly,
        open_trustdb_readonly_nolock, parse_trust_value, render_raw_bytes, validate_trust_key,
        verify_entry,
    };
    use proptest::prelude::*;
    use sha2::{Digest, Sha256};
    use std::io::Write as _;
    use tempfile::tempdir;

    /// A real, externally-verified SHA-256 + size pair for the literal bytes
    /// `b"hello trustdb\n"` (14 bytes). Computed with coreutils `sha256sum`
    /// (`printf 'hello trustdb\n' | sha256sum`) so the value is grounded in a
    /// primary source, not derived from the impl under test. The
    /// `known_content_digest_is_stable` test re-derives it via the `sha2` crate
    /// and asserts equality, so a wrong constant cannot slip through.
    const KNOWN_BYTES: &[u8] = b"hello trustdb\n";
    const KNOWN_SIZE: u64 = 14;
    const KNOWN_SHA256: &str = "3ea762cdbe2e0e8bd475edcfbe4ef960df0389bab22131b18ca9d9ccf08ccc27";

    /// Build the canonical fapolicyd value bytes for a row.
    fn value_bytes(src_int: u32, size: u64, sha256_hex: &str) -> Vec<u8> {
        format!("{src_int} {size} {sha256_hex}").into_bytes()
    }

    /// Write `KNOWN_BYTES` into a fresh temp file and return its path. The file
    /// must outlive the test, so the caller holds the returned `NamedTempFile`.
    fn known_temp_file() -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().expect("tempfile");
        f.write_all(KNOWN_BYTES).expect("write known bytes");
        f.flush().expect("flush");
        f
    }

    // -- failing tests (symbols absent until impl lands) ----------------------

    /// A correct `contains_path` must return `true` for a present key AND
    /// `false` for an absent key. A stub that always returns `true` fails the
    /// negative assertion; a stub that always returns `false` fails the positive
    /// assertion.
    #[test]
    fn open_and_contains_path() {
        let tmp = tempdir().expect("tempdir");
        write_fixture(tmp.path(), &["/usr/bin/ls", "/usr/bin/cat"]);

        let db = open_trustdb_readonly(tmp.path()).expect("open_trustdb_readonly");

        assert!(
            db.contains_path("/usr/bin/ls"),
            "contains_path must return true for a key that was inserted"
        );
        assert!(
            !db.contains_path("/usr/bin/nonexistent"),
            "contains_path must return false for a key that was never inserted"
        );
        assert_eq!(
            db.path(),
            tmp.path(),
            "path() must round-trip the directory passed to open_trustdb_readonly"
        );
    }

    /// A correct `iter_paths` must return exactly the inserted keys. A stub that
    /// returns `[]` fails the length assertion; a stub that returns extra entries
    /// fails the equality assertion after sorting.
    #[test]
    fn iter_paths_returns_all_keys_deduped() {
        let tmp = tempdir().expect("tempdir");
        write_fixture(tmp.path(), &["/a", "/b", "/c"]);

        let db = open_trustdb_readonly(tmp.path()).expect("open_trustdb_readonly");

        let mut paths = db.iter_paths().expect("iter_paths");
        paths.sort();
        assert_eq!(
            paths,
            vec!["/a".to_owned(), "/b".to_owned(), "/c".to_owned()],
            "iter_paths must return exactly the inserted keys, sorted"
        );
    }

    /// `open_trustdb_readonly` on an empty directory (no `data.mdb`) must return
    /// an `Err(TrustDbError::Missing(_) | TrustDbError::Open(_))` and must NOT
    /// panic. This test passes against any impl that maps the failure into the
    /// error enum rather than unwrapping.
    #[test]
    fn missing_db_is_error_not_panic() {
        let tmp = tempdir().expect("tempdir");
        // tmp is freshly empty - no data.mdb / lock.mdb present.
        let result = open_trustdb_readonly(tmp.path());
        assert!(
            matches!(
                result,
                Err(TrustDbError::Open(_) | TrustDbError::Missing(_))
            ),
            "expected Err(Open|Missing), got: {result:?}"
        );
    }

    /// RE-TARGETED for the #291/#317 torn-read fix. The OLD invariant
    /// ("`open_trustdb_readonly` must NEVER create lock.mdb") was the very
    /// behavior that allowed the torn read: a `NO_LOCK` reader takes no reader-
    /// table slot, so the daemon can free+reuse the reader's pages. Layer 1 now
    /// opens `READ_ONLY` WITH the lock table on a WRITABLE dir, which DOES create
    /// lock.mdb - that is the prevention. So:
    ///
    /// 1. On a writable dir, the DEFAULT `open_trustdb_readonly` (prevention
    ///    path) MUST create lock.mdb. Asserting this kills a mutant that drops
    ///    the lock-table participation (e.g. flips the prevention flags back to
    ///    `NO_LOCK`, or removes the Layer-1 attempt entirely).
    /// 2. The TEST-ONLY `open_trustdb_readonly_nolock` (the fallback path) must
    ///    NOT create lock.mdb - preserving the original `NO_LOCK`-flag coverage
    ///    and killing the `READ_ONLY | NO_LOCK` -> `&` mutant on that path
    ///    (`READ_ONLY`=`0x20000`, `NO_LOCK`=`0x400000` are disjoint bits; `&`
    ///    collapses to `0x0`, dropping `NO_LOCK` so LMDB creates lock.mdb).
    #[test]
    fn open_prevention_creates_lock_fallback_does_not() {
        // --- Part 1: prevention path creates lock.mdb on a writable dir. ---
        let tmp = tempdir().expect("tempdir");
        write_fixture(tmp.path(), &["/usr/bin/ls"]);
        let lock = tmp.path().join("lock.mdb");
        // write_fixture opens RW without NO_LOCK, so it may have created
        // lock.mdb; remove it so we observe ONLY what the readers do.
        let _ = std::fs::remove_file(&lock);
        let _db = open_trustdb_readonly(tmp.path()).expect("open ro (prevention)");
        assert!(
            lock.exists(),
            "open_trustdb_readonly (Layer-1 prevention) must create lock.mdb on a \
             writable dir: the reader-table slot is what prevents the torn read (#291)"
        );

        // --- Part 2: NO_LOCK fallback path does NOT create lock.mdb. ---
        let tmp2 = tempdir().expect("tempdir2");
        write_fixture(tmp2.path(), &["/usr/bin/ls"]);
        let lock2 = tmp2.path().join("lock.mdb");
        let _ = std::fs::remove_file(&lock2);
        let _db2 = open_trustdb_readonly_nolock(tmp2.path()).expect("open ro (NO_LOCK fallback)");
        assert!(
            !lock2.exists(),
            "open_trustdb_readonly_nolock created lock.mdb; the fallback must keep NO_LOCK set"
        );
    }

    // ---- #291/#317 Layer-2 torn-read detection (parse_trust_value) ----------

    /// A value carrying a NUL byte (classic page-padding splice from a torn
    /// read) must be `TornRead`, NOT `MalformedValue` and NOT a silent `Ok`.
    /// Kills a mutant that removes the raw-byte alphabet screen (which would let
    /// the NUL-bearing buffer fall through to the structural parse or, worse,
    /// parse as valid once lossy-decoded).
    #[test]
    fn parse_value_with_nul_is_torn_read() {
        // "1 12345 <hex>" with a NUL spliced into the middle of the hex.
        let mut raw = value_bytes(1, 12345, KNOWN_SHA256);
        raw[12] = 0; // overwrite a hex byte with NUL
        assert!(
            matches!(parse_trust_value(&raw), Err(TrustDbError::TornRead { .. })),
            "NUL-bearing value must be TornRead, got {:?}",
            parse_trust_value(&raw)
        );
    }

    /// A value with a high-bit (non-ASCII) byte must be `TornRead`, and the
    /// detection must run on the RAW bytes (before lossy decode would mask the
    /// byte as U+FFFD). Kills a mutant that screens the lossy STRING instead of
    /// the raw `&[u8]`, and a mutant that drops the non-ASCII screen.
    #[test]
    fn parse_value_with_non_ascii_byte_is_torn_read() {
        let mut raw = value_bytes(2, 999, KNOWN_SHA256);
        raw[0] = 0xFF; // high-bit byte in the src field position
        assert!(
            matches!(parse_trust_value(&raw), Err(TrustDbError::TornRead { .. })),
            "non-ASCII byte in value must be TornRead, got {:?}",
            parse_trust_value(&raw)
        );
    }

    /// A value with a NUL byte at the END (page zero-fill, the byte the lossy
    /// decode keeps as `\0`) must still be `TornRead`. Pins that the screen runs
    /// over the WHOLE buffer, killing a mutant that screens only a prefix.
    #[test]
    fn parse_value_with_trailing_nul_is_torn_read() {
        let mut raw = value_bytes(1, 12345, KNOWN_SHA256);
        raw.push(0); // trailing NUL
        assert!(
            matches!(parse_trust_value(&raw), Err(TrustDbError::TornRead { .. })),
            "trailing-NUL value must be TornRead, got {:?}",
            parse_trust_value(&raw)
        );
    }

    /// PRINTABLE-ASCII malformations OUTSIDE the value grammar but WITHOUT a
    /// NUL/non-ASCII byte (an uppercase hex letter, a slash, a non-numeric src,
    /// a 4th field) must stay `MalformedValue`, NOT be misclassified as
    /// `TornRead`. This pins the boundary between the two error classes (the
    /// torn screen is NUL/non-ASCII only; printable-grammar violations remain
    /// structural) so a mutant that routes every failure through one variant is
    /// caught, AND it documents that these inputs still yield a CLEAN error
    /// (never a silent corrupt `Ok`).
    #[test]
    fn parse_printable_grammar_errors_stay_malformed() {
        // Uppercase hex letter (printable ASCII) -> structural -> MalformedValue.
        let upper = b"1 12345 Aabbccdd0011223344556677889900aabbccdd0011223344556677889900";
        assert!(
            matches!(
                parse_trust_value(upper),
                Err(TrustDbError::MalformedValue { .. })
            ),
            "uppercase-hex value must be MalformedValue, got {:?}",
            parse_trust_value(upper)
        );
        // Slash in the hex (printable ASCII) -> structural -> MalformedValue.
        let slash = b"1 12345 /usr/bin/ls0011223344556677889900aabbccdd00112233445566778";
        assert!(
            matches!(
                parse_trust_value(slash),
                Err(TrustDbError::MalformedValue { .. })
            ),
            "slash-bearing value must be MalformedValue, got {:?}",
            parse_trust_value(slash)
        );
    }

    // ---- #291/#317 TornRead.raw fidelity (render_raw_bytes) -----------------

    /// `render_raw_bytes` must (a) pass printable ASCII through verbatim,
    /// (b) escape NUL and high-bit bytes as `\xHH` so the ACTUAL torn byte is
    /// visible (not the U+FFFD a lossy decode would show), and (c) escape a
    /// literal backslash. Pins the faithful-rendering contract the spec/idiomatic
    /// reviewers asked for; kills a mutant that drops any escape branch.
    #[test]
    fn render_raw_bytes_escapes_non_printable_faithfully() {
        // "ab" + NUL + 0xFF + backslash + "9"
        let raw = b"ab\x00\xff\\9";
        assert_eq!(
            render_raw_bytes(raw),
            "ab\\x00\\xff\\\\9",
            "printable passes through; NUL/high-bit -> \\xHH; backslash -> \\\\"
        );
        // A high-bit byte must NOT collapse to U+FFFD (the whole point).
        assert!(
            !render_raw_bytes(b"\xff").contains('\u{fffd}'),
            "high-bit byte must be escaped, not rendered as the replacement char"
        );
    }

    // ---- #291/#317 Layer-2 key validation (validate_trust_key) --------------

    /// An absolute, NUL-free path key validates OK and surfaces verbatim.
    #[test]
    fn validate_key_absolute_nul_free_ok() {
        let raw = b"/usr/bin/ls";
        assert_eq!(
            validate_trust_key(raw, "/usr/bin/ls").expect("absolute path must validate"),
            "/usr/bin/ls",
            "an absolute path key must surface verbatim"
        );
    }

    /// A `path_to_hash` key (128 lowercase-hex chars, the shape fapolicyd stores
    /// for a path longer than the LMDB key limit) validates OK and surfaces the
    /// 128-hex string. NO leading `/`. Kills a mutant that drops the hashed-key
    /// acceptance branch (which would reject this real key as `TornRead`).
    #[test]
    fn validate_key_path_to_hash_128hex_ok() {
        // 128 lowercase-hex chars (a real SHA-512 hex shape; value irrelevant).
        let hex = "ab".repeat(64);
        assert_eq!(hex.len(), 128, "fixture must be 128 hex chars");
        let surfaced = validate_trust_key(hex.as_bytes(), &hex)
            .expect("128-hex path_to_hash key must validate");
        assert_eq!(
            surfaced, hex,
            "hashed key must surface as the 128-hex string"
        );
    }

    /// A `path_to_hash` key WITH the trailing C-string NUL fapolicyd stores
    /// (`mv_size = (SHA512_LEN*2)+1`, so the raw key is 128 hex + one NUL)
    /// validates OK and surfaces the 128-hex with the trailing NUL TRIMMED.
    /// Kills a mutant that drops the trailing-NUL handling.
    #[test]
    fn validate_key_path_to_hash_128hex_trailing_nul_ok() {
        let hex = "0f".repeat(64);
        let mut raw = hex.clone().into_bytes();
        raw.push(0); // the stored C-string terminator
        assert_eq!(raw.len(), 129);
        let lossy = String::from_utf8_lossy(&raw).into_owned();
        let surfaced =
            validate_trust_key(&raw, &lossy).expect("128-hex + trailing NUL key must validate");
        assert_eq!(
            surfaced, hex,
            "hashed key must surface as the 128-hex string with the trailing NUL trimmed"
        );
    }

    /// A 128-char string that is NOT all lowercase-hex (an uppercase letter, or a
    /// non-hex byte) must NOT be accepted as a hashed key - it is a torn splice
    /// that merely happens to be 128 bytes. Kills a mutant that relaxes the
    /// hex-alphabet check on the hashed-key branch.
    #[test]
    fn validate_key_128_non_hex_is_torn_read() {
        // 128 chars but with an uppercase 'A' - not lowercase hex.
        let mut s = "ab".repeat(64);
        s.replace_range(0..1, "A");
        assert_eq!(s.len(), 128);
        assert!(
            matches!(
                validate_trust_key(s.as_bytes(), &s),
                Err(TrustDbError::TornRead { .. })
            ),
            "128-char non-hex key must be TornRead, got {:?}",
            validate_trust_key(s.as_bytes(), &s)
        );
    }

    /// A 128-byte key whose trailing region is a NON-NUL interior byte (i.e. it
    /// is NOT the 128-hex shape and not an absolute path) is rejected. Guards the
    /// boundary: only EXACTLY 128 hex (optionally + one trailing NUL) is the
    /// hashed shape; a 129-byte key whose 129th byte is not NUL is torn.
    #[test]
    fn validate_key_129_non_nul_tail_is_torn_read() {
        let mut raw = "ab".repeat(64).into_bytes(); // 128 hex
        raw.push(b'x'); // 129th byte is NOT a NUL -> not the hashed shape
        let lossy = String::from_utf8_lossy(&raw).into_owned();
        assert!(
            matches!(
                validate_trust_key(&raw, &lossy),
                Err(TrustDbError::TornRead { .. })
            ),
            "129-byte key with a non-NUL tail must be TornRead"
        );
    }

    /// A relative (non-`/`-rooted) key is `TornRead`. Kills a mutant that drops
    /// the `starts_with('/')` guard.
    #[test]
    fn validate_key_relative_is_torn_read() {
        let raw = b"usr/bin/ls";
        assert!(
            matches!(
                validate_trust_key(raw, "usr/bin/ls"),
                Err(TrustDbError::TornRead { .. })
            ),
            "relative key must be TornRead"
        );
    }

    /// A key whose raw bytes carry an interior NUL is `TornRead` even though the
    /// lossy-decoded string still starts with '/'. Kills a mutant that drops the
    /// raw-byte NUL check (relying only on the decoded string).
    #[test]
    fn validate_key_with_nul_is_torn_read() {
        let raw = b"/usr/bin\0/ls";
        let lossy = String::from_utf8_lossy(raw).into_owned();
        assert!(
            matches!(
                validate_trust_key(raw, &lossy),
                Err(TrustDbError::TornRead { .. })
            ),
            "NUL-bearing key must be TornRead, got {:?}",
            validate_trust_key(raw, &lossy)
        );
    }

    /// The TEST-ONLY `open_trustdb_readonly_nolock` reads a CLEAN fixture
    /// identically to the locked `open_trustdb_readonly` (same entries). This
    /// proves the fallback constructor is a faithful reader (not a stub) so the
    /// harness's detection-branch assertions rest on a real read path.
    #[test]
    fn nolock_reader_reads_clean_fixture_like_locked() {
        let tmp = tempdir().expect("tempdir");
        let row = value_bytes(1, 111, KNOWN_SHA256);
        write_trustdb_fixture_kv(tmp.path(), &[("/usr/bin/python3", row.as_slice())]);

        // heed forbids two open envs on the same path in one process
        // (EnvAlreadyOpened), so open + read + DROP the locked handle before
        // opening the nolock one on the same dir.
        let a = {
            let locked = open_trustdb_readonly(tmp.path()).expect("locked open");
            locked.iter_entries().expect("locked iter")
        };
        let b = {
            let nolock = open_trustdb_readonly_nolock(tmp.path()).expect("nolock open");
            nolock.iter_entries().expect("nolock iter")
        };
        assert_eq!(
            a, b,
            "nolock reader must read the same entries as the locked reader"
        );
        assert_eq!(a.len(), 1, "fixture has exactly one row");
        assert_eq!(a[0].path, "/usr/bin/python3");
    }

    // ---- #291/#317 Layer-2 DETECTION end-to-end (deterministic, NO writer) --
    //
    // The live-writer NO_LOCK contention test was DROPPED: a `NO_LOCK` reader
    // racing a live writer can SIGABRT inside LMDB's C cursor code
    // (`mdb_cursor_sibling`), which is un-gateable and proves nothing as an
    // assertion. These tests exercise the Layer-2 DETECTION floor
    // DETERMINISTICALLY instead: write a STATIC DB whose records are already
    // torn-shaped (a NUL/non-ASCII value byte, a relative or NUL-bearing key),
    // open it via the `NO_LOCK` reader, and assert the read path converts the
    // corruption into a CLEAN `TrustDbError` (never a silently-corrupt `Ok`,
    // never a panic). This proves the `?` propagation through
    // `iter_entries`/`iter_paths` end-to-end on the fallback reader.

    /// A value carrying a NUL byte, read back through the `NO_LOCK` reader's
    /// `iter_entries`, must surface as a clean `TornRead` error - not a corrupt
    /// `Ok`, not a panic. Proves Layer-2 detection propagates through the real
    /// DB read path on the fallback reader.
    #[test]
    fn nolock_iter_entries_on_nul_value_is_clean_torn_read() {
        let tmp = tempdir().expect("tempdir");
        // "1 12345 <hex>" with a NUL spliced into the hex region.
        let mut torn = value_bytes(1, 12345, KNOWN_SHA256);
        torn[12] = 0;
        write_trustdb_fixture_kv(tmp.path(), &[("/usr/bin/ls", torn.as_slice())]);

        let db = open_trustdb_readonly_nolock(tmp.path()).expect("nolock open");
        let result = db.iter_entries();
        assert!(
            matches!(result, Err(TrustDbError::TornRead { .. })),
            "NUL-bearing value must read back as a clean TornRead, got {result:?}"
        );
    }

    /// A value carrying a non-ASCII (high-bit) byte must read back as a clean
    /// `TornRead` through the `NO_LOCK` reader.
    #[test]
    fn nolock_iter_entries_on_non_ascii_value_is_clean_torn_read() {
        let tmp = tempdir().expect("tempdir");
        let mut torn = value_bytes(2, 999, KNOWN_SHA256);
        torn[0] = 0xFF;
        write_trustdb_fixture_kv(tmp.path(), &[("/usr/bin/cat", torn.as_slice())]);

        let db = open_trustdb_readonly_nolock(tmp.path()).expect("nolock open");
        let result = db.iter_entries();
        assert!(
            matches!(result, Err(TrustDbError::TornRead { .. })),
            "non-ASCII value must read back as a clean TornRead, got {result:?}"
        );
    }

    /// A RELATIVE (non-`/`-rooted) KEY must read back as a clean `TornRead`
    /// through BOTH `iter_entries` and `iter_paths` on the `NO_LOCK` reader. The
    /// value here is well-formed, so the rejection is purely the key check.
    #[test]
    fn nolock_relative_key_is_clean_torn_read() {
        let tmp = tempdir().expect("tempdir");
        let good = value_bytes(1, 111, KNOWN_SHA256);
        // A relative key (no leading '/') - the torn-key signature.
        write_trustdb_fixture_kv(tmp.path(), &[("usr/bin/relative", good.as_slice())]);

        let db = open_trustdb_readonly_nolock(tmp.path()).expect("nolock open");
        assert!(
            matches!(db.iter_entries(), Err(TrustDbError::TornRead { .. })),
            "relative key must read back as a clean TornRead via iter_entries, got {:?}",
            db.iter_entries()
        );
        assert!(
            matches!(db.iter_paths(), Err(TrustDbError::TornRead { .. })),
            "relative key must read back as a clean TornRead via iter_paths, got {:?}",
            db.iter_paths()
        );
    }

    /// A KEY carrying a NUL byte must read back as a clean `TornRead` (the
    /// decoded key still starts with '/', so this exercises the raw-byte NUL
    /// branch of the key check end-to-end on the `NO_LOCK` reader).
    #[test]
    fn nolock_nul_key_is_clean_torn_read() {
        let tmp = tempdir().expect("tempdir");
        let good = value_bytes(1, 111, KNOWN_SHA256);
        write_trustdb_fixture_kv(tmp.path(), &[("/usr/bin\0/ls", good.as_slice())]);

        let db = open_trustdb_readonly_nolock(tmp.path()).expect("nolock open");
        assert!(
            matches!(db.iter_entries(), Err(TrustDbError::TornRead { .. })),
            "NUL-bearing key must read back as a clean TornRead, got {:?}",
            db.iter_entries()
        );
    }

    // ---- #291/#317 REGRESSION: path_to_hash (long-path) keys read back OK ----
    //
    // For a trusted path longer than the LMDB key limit (511; paths are legal up
    // to PATH_MAX=4096), fapolicyd stores a bare 128-char lowercase-hex SHA-512
    // of the path as the key (database.c path_to_hash + write_db), NOT the path.
    // The naive "key must be `/`-rooted, NUL-free" check rejected this, so a real
    // DB containing even ONE long-path entry made iter_entries/iter_paths return
    // TornRead for the WHOLE iteration (trustdb list/report/cross_db lint failed
    // entirely). These tests pin that a hashed-key entry reads back as an Ok
    // entry surfacing the hashed key, end-to-end through the real DB read path.

    /// A fixture whose KEY is a 128-hex `path_to_hash` digest (with a normal
    /// value) reads back as an `Ok` entry whose surfaced path is the 128-hex
    /// string - NOT `Err(TornRead)`. Exercises the whole
    /// `iter_entries`/`iter_paths` path.
    #[test]
    fn iter_reads_path_to_hash_128hex_key_as_ok_entry() {
        let tmp = tempdir().expect("tempdir");
        let hex = "ab".repeat(64); // 128 lowercase-hex chars
        let v = value_bytes(1, 4096, KNOWN_SHA256);
        write_trustdb_fixture_kv(tmp.path(), &[(hex.as_str(), v.as_slice())]);

        let db = open_trustdb_readonly(tmp.path()).expect("open ro");

        let entries = db
            .iter_entries()
            .expect("hashed-key entry must read OK, not TornRead");
        assert_eq!(entries.len(), 1, "exactly one row");
        assert_eq!(
            entries[0].path, hex,
            "hashed key must surface as the 128-hex string"
        );
        assert_eq!(entries[0].size, 4096);

        let paths = db.iter_paths().expect("iter_paths must read OK");
        assert_eq!(paths, vec![hex], "iter_paths must surface the 128-hex key");
    }

    /// Same, but the stored key carries the trailing C-string NUL fapolicyd
    /// writes (`mv_size = (SHA512_LEN*2)+1`). The entry reads back OK and the
    /// surfaced path has the trailing NUL trimmed.
    #[test]
    fn iter_reads_path_to_hash_128hex_trailing_nul_key_as_ok_entry() {
        let tmp = tempdir().expect("tempdir");
        let hex = "0f".repeat(64);
        // Key bytes = 128 hex + one trailing NUL (a &str may contain '\0').
        let mut key_bytes = hex.clone();
        key_bytes.push('\0');
        let v = value_bytes(2, 5000, KNOWN_SHA256);
        write_trustdb_fixture_kv(tmp.path(), &[(key_bytes.as_str(), v.as_slice())]);

        let db = open_trustdb_readonly(tmp.path()).expect("open ro");
        let entries = db
            .iter_entries()
            .expect("trailing-NUL hashed-key entry must read OK, not TornRead");
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].path, hex,
            "surfaced path must be the 128-hex with the trailing NUL trimmed"
        );
    }

    /// A genuinely TORN key (a 64-char string that is neither `/`-rooted nor the
    /// 128-hex hashed shape) STILL fails the whole iteration as `TornRead` - the
    /// regression fix widened acceptance to the two LEGITIMATE shapes only, it did
    /// not stop detecting garbage.
    #[test]
    fn iter_still_rejects_garbage_key_as_torn_read() {
        let tmp = tempdir().expect("tempdir");
        // 64 hex chars: a valid-looking but ILLEGITIMATE key shape (not a path,
        // not the 128-hex hashed shape).
        let garbage = "ab".repeat(32);
        let v = value_bytes(1, 111, KNOWN_SHA256);
        write_trustdb_fixture_kv(tmp.path(), &[(garbage.as_str(), v.as_slice())]);

        let db = open_trustdb_readonly(tmp.path()).expect("open ro");
        assert!(
            matches!(db.iter_entries(), Err(TrustDbError::TornRead { .. })),
            "a 64-hex (non-path, non-hashed) key must still be TornRead, got {:?}",
            db.iter_entries()
        );
    }

    // ---- #291/#317 Layer-1 EACCES -> NO_LOCK fallback branch -----------------

    /// On a READ-ONLY trust-DB directory that contains a valid fixture, the
    /// locked Layer-1 open fails with EACCES (it cannot create `lock.mdb`), so
    /// `open_trustdb_readonly` MUST fall back to the `NO_LOCK` reader and still
    /// return `Ok`, reading the fixture, WITHOUT creating `lock.mdb`.
    ///
    /// Kills the `replace match guard ... with false` survivor: with the guard
    /// forced false the EACCES error propagates and this returns `Err`, failing
    /// the `Ok` assertion. The no-`lock.mdb` assertion proves it was the
    /// `NO_LOCK` FALLBACK that succeeded (not the locked path, which would have
    /// created lock.mdb).
    ///
    /// Skipped under root: root bypasses DAC, so `chmod 0555` does not make lock
    /// creation fail and the locked path would succeed (no fallback exercised).
    #[test]
    fn readonly_dir_falls_back_to_nolock_and_reads() {
        let tmp = tempdir().expect("tempdir");
        let v = value_bytes(1, 111, KNOWN_SHA256);
        write_trustdb_fixture_kv(tmp.path(), &[("/usr/bin/ls", v.as_slice())]);
        // The fixture writer opens RW (no NO_LOCK) and may create lock.mdb;
        // remove it so we can assert the fallback open does NOT recreate it.
        let lock = tmp.path().join("lock.mdb");
        let _ = std::fs::remove_file(&lock);

        // Make the directory read-only so lock CREATION fails with EACCES while
        // data.mdb stays readable.
        let chmod_ro = std::process::Command::new("chmod")
            .args(["0555", tmp.path().to_str().expect("utf8 path")])
            .status()
            .expect("chmod 0555");
        assert!(chmod_ro.success(), "chmod 0555 failed");

        // Probe for root: if we can still create a file in the read-only dir we
        // are root (DAC bypassed) and cannot observe the EACCES fallback; skip.
        let probe = tmp.path().join(".root_probe");
        if std::fs::write(&probe, b"x").is_ok() {
            let _ = std::fs::remove_file(&probe);
            let _ = std::process::Command::new("chmod")
                .args(["0755", tmp.path().to_str().expect("utf8 path")])
                .status();
            return; // running as root; skip
        }

        let result = open_trustdb_readonly(tmp.path());
        // Restore perms before any assertion can unwind, so tempdir cleanup works.
        let _ = std::process::Command::new("chmod")
            .args(["0755", tmp.path().to_str().expect("utf8 path")])
            .status();

        let db = result.expect("read-only dir must fall back to NO_LOCK and open Ok");
        let entries = db
            .iter_entries()
            .expect("fallback reader must read entries");
        assert_eq!(entries.len(), 1, "fixture has exactly one row");
        assert_eq!(entries[0].path, "/usr/bin/ls");
        assert!(
            !lock.exists(),
            "the EACCES fallback must use the NO_LOCK reader (no lock.mdb); a created \
             lock.mdb would mean the locked path ran instead of the fallback"
        );
    }

    /// The EACCES->NO_LOCK fallback must fire ONLY for a permission/read-only
    /// error, NOT for any other open error. On a path that is a regular FILE
    /// (heed open fails with `NotADirectory`, errno 20 -- an `Error::Io` whose
    /// kind is NEITHER `PermissionDenied` nor `ReadOnlyFilesystem`), the correct code
    /// propagates the error WITHOUT taking the fallback, so it emits NO stderr
    /// warning. We assert that by re-execing this test binary in a child whose
    /// stderr we capture: the fallback-warning substring must be ABSENT.
    ///
    /// Kills the `replace match guard ... with true` survivor: with the guard
    /// forced true the fallback fires for the `NotADirectory` error too, emitting
    /// the warning -- which this test then detects in the child's stderr and
    /// fails on. (We use a child process because the warning goes to THIS
    /// process's stderr, which an in-process test cannot redirect cleanly.)
    #[test]
    fn non_permission_open_error_does_not_warn_or_fall_back() {
        const CHILD_ENV: &str = "RS_TRUSTDB_NONPERM_CHILD";
        // Exact substring of the fallback warning emitted in `open_trustdb_readonly`
        // (case-sensitive; the warning text says "WITHOUT reader-lock participation").
        const WARNING_MARKER: &str = "reader-lock participation";

        // Child mode: open a regular file AS a trust-DB dir and exit. The
        // fallback warning (if it wrongly fires) lands on this child's stderr.
        if std::env::var(CHILD_ENV).is_ok() {
            let f = tempfile::NamedTempFile::new().expect("tempfile");
            // A regular file is not an LMDB dir -> NotADirectory (non-perm Io).
            let _ = open_trustdb_readonly(f.path());
            return;
        }

        // Parent: re-exec ONLY this test in a child, capture its stderr.
        let exe = std::env::current_exe().expect("current_exe");
        let out = std::process::Command::new(exe)
            .args([
                "--exact",
                "trustdb::tests::non_permission_open_error_does_not_warn_or_fall_back",
                "--nocapture",
            ])
            .env(CHILD_ENV, "1")
            .output()
            .expect("spawn child");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            !stderr.contains(WARNING_MARKER),
            "a NON-permission open error (NotADirectory) must NOT trigger the NO_LOCK \
             fallback warning; the guard must match only PermissionDenied/ReadOnlyFilesystem. \
             child stderr was:\n{stderr}"
        );
    }

    // -- Section 3d: RED adversarial suite for the 3d impl pipeline -----------
    // The following tests target the stubbed (`todo!()`) bodies:
    // `TrustSource::from_int`, `parse_trust_value`, `iter_entries`,
    // `get_entry`, and `verify_entry`. They panic on the `todo!()` until the
    // implementer fills each body. Every assertion is grounded in a cited
    // primary source (fapolicyd `fapolicyd-backend.h`, coreutils `sha256sum`).

    /// Re-derive `KNOWN_SHA256` from `KNOWN_BYTES` via the `sha2` crate and
    /// assert equality. This pins the hard-coded constant to a value the test
    /// itself can reproduce, so a wrong constant cannot silently let the
    /// `verify_entry` Match/Mismatch tests pass. (The constant was independently
    /// produced by coreutils `sha256sum`; this is the cross-check.)
    #[test]
    fn known_content_digest_is_stable() {
        let mut h = Sha256::new();
        h.update(KNOWN_BYTES);
        let got = to_hex(&h.finalize());
        assert_eq!(
            got, KNOWN_SHA256,
            "KNOWN_SHA256 constant must equal the sha2-crate digest of KNOWN_BYTES"
        );
        assert_eq!(
            KNOWN_BYTES.len() as u64,
            KNOWN_SIZE,
            "KNOWN_SIZE must equal the byte length of KNOWN_BYTES"
        );
        // SHA-256 digests are 64 lowercase hex chars - one of the accepted lengths.
        assert_eq!(
            KNOWN_SHA256.len(),
            64,
            "sha256 hex must be 64 chars (the SHA-256 accepted digest length)"
        );
        assert!(
            KNOWN_SHA256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "sha256 hex must be lowercase hex only"
        );
    }

    // ---- TrustSource::from_int (primary source: fapolicyd-backend.h) --------
    // `typedef enum { SRC_UNKNOWN, SRC_RPM, SRC_FILE_DB, SRC_DEB } trust_src_t;`
    // => 0=Unknown, 1=Rpm, 2=FileDb, 3=Deb; any other value => Unknown.
    // One assert per mapping so a collapsed-match mutant dies on a specific arm.

    #[test]
    fn from_int_zero_is_unknown() {
        assert_eq!(TrustSource::from_int(0), TrustSource::Unknown);
    }

    #[test]
    fn from_int_one_is_rpmdb() {
        // Corroborated by spike-heed-results.md:66 (real Fedora DB src_int=1).
        assert_eq!(TrustSource::from_int(1), TrustSource::RpmDb);
    }

    #[test]
    fn from_int_two_is_filedb() {
        assert_eq!(TrustSource::from_int(2), TrustSource::FileDb);
    }

    #[test]
    fn from_int_three_is_deb() {
        assert_eq!(TrustSource::from_int(3), TrustSource::Deb);
    }

    #[test]
    fn from_int_unrecognized_small_is_unknown() {
        assert_eq!(TrustSource::from_int(7), TrustSource::Unknown);
    }

    #[test]
    fn from_int_overflow_max_is_unknown() {
        assert_eq!(TrustSource::from_int(u32::MAX), TrustSource::Unknown);
    }

    // ---- parse_trust_value --------------------------------------------------

    /// Round-trip: a well-formed value `"<src> <size> <hex64>"` parses back to
    /// the same `(source, size, hex)`. ASYMMETRIC inputs (src != size, and a
    /// hex string whose own bytes are not all equal) so a field-swap mutant
    /// (returning size where source belongs, or vice versa) is caught.
    #[test]
    fn parse_trust_value_explicit_roundtrip() {
        // src=2 (FileDb), size=987654 - deliberately src != size.
        let raw = value_bytes(2, 987_654, KNOWN_SHA256);
        let (src, size, hex) = parse_trust_value(&raw).expect("well-formed value must parse");
        assert_eq!(src, TrustSource::FileDb, "src int 2 must map to FileDb");
        assert_eq!(size, 987_654, "size field must round-trip");
        assert_eq!(hex, KNOWN_SHA256, "sha256 hex field must round-trip");
    }

    /// A src int the format does not recognize still parses (it is not a
    /// `MalformedValue`) and maps to `Unknown`; the size/hex still round-trip.
    /// Kills a mutant that errors on any unknown src instead of mapping it.
    #[test]
    fn parse_trust_value_unknown_src_int_maps_to_unknown_source() {
        let raw = value_bytes(99, 42, KNOWN_SHA256);
        let (src, size, hex) = parse_trust_value(&raw).expect("unknown src int must still parse");
        assert_eq!(src, TrustSource::Unknown);
        assert_eq!(size, 42);
        assert_eq!(hex, KNOWN_SHA256);
    }

    /// The `fuzz-targets` shim `fuzz_hooks::parse_trust_value_fuzz` must be a
    /// faithful pass-through to `parse_trust_value` (it exists only so the
    /// nightly fuzz crate can reach the crate-private parser). Compiled only
    /// under the `fuzz-targets` feature, where the shim itself is compiled, so it
    /// kills the constant-return mutants on the shim (which would otherwise
    /// return `Default::default()` / size 0 or 1 / empty-or-"xyzzy" instead of
    /// the real parsed tuple). The default-features mutation gate never compiles
    /// the shim, so those same mutants are documented as cfg-phantoms in
    /// `.cargo/mutants.toml`; this test is what actually exercises the shim.
    #[cfg(feature = "fuzz-targets")]
    #[test]
    fn parse_trust_value_fuzz_shim_matches_parser() {
        // Asymmetric (src != size) so a field-swap/constant mutant cannot pass.
        let raw = value_bytes(2, 987_654, KNOWN_SHA256);
        let (src, size, hex) = super::fuzz_hooks::parse_trust_value_fuzz(&raw)
            .expect("well-formed value must parse through the shim");
        assert_eq!(src, TrustSource::FileDb, "src int 2 must map to FileDb");
        assert_eq!(size, 987_654, "size field must round-trip through the shim");
        assert_eq!(hex, KNOWN_SHA256, "sha256 hex field must round-trip");
    }

    #[test]
    fn parse_trust_value_wrong_field_count_is_malformed() {
        // Only two fields (missing the hash).
        let raw = b"1 12345";
        assert!(
            matches!(
                parse_trust_value(raw),
                Err(TrustDbError::MalformedValue { .. })
            ),
            "two-field value must be MalformedValue, got {:?}",
            parse_trust_value(raw)
        );
    }

    #[test]
    fn parse_trust_value_extra_field_is_malformed() {
        // Four space-separated fields.
        let raw = format!("1 12345 {KNOWN_SHA256} extra").into_bytes();
        assert!(
            matches!(
                parse_trust_value(&raw),
                Err(TrustDbError::MalformedValue { .. })
            ),
            "four-field value must be MalformedValue, got {:?}",
            parse_trust_value(&raw)
        );
    }

    #[test]
    fn parse_trust_value_non_numeric_src_is_malformed() {
        let raw = format!("x 12345 {KNOWN_SHA256}").into_bytes();
        assert!(
            matches!(
                parse_trust_value(&raw),
                Err(TrustDbError::MalformedValue { .. })
            ),
            "non-numeric src must be MalformedValue, got {:?}",
            parse_trust_value(&raw)
        );
    }

    #[test]
    fn parse_trust_value_non_numeric_size_is_malformed() {
        let raw = format!("1 notanumber {KNOWN_SHA256}").into_bytes();
        assert!(
            matches!(
                parse_trust_value(&raw),
                Err(TrustDbError::MalformedValue { .. })
            ),
            "non-numeric size must be MalformedValue, got {:?}",
            parse_trust_value(&raw)
        );
    }

    #[test]
    fn parse_trust_value_off_length_hex_is_malformed() {
        // 63 hex chars: not in the accepted set {32, 40, 64, 128}.
        let short = &KNOWN_SHA256[..63];
        let raw = format!("1 12345 {short}").into_bytes();
        assert!(
            matches!(
                parse_trust_value(&raw),
                Err(TrustDbError::MalformedValue { .. })
            ),
            "63-char hex must be MalformedValue (not in accepted lengths 32/40/64/128), got {:?}",
            parse_trust_value(&raw)
        );

        // 65 hex chars: also not in the accepted set.
        let long = format!("{KNOWN_SHA256}a");
        let raw_long = format!("1 12345 {long}").into_bytes();
        assert!(
            matches!(
                parse_trust_value(&raw_long),
                Err(TrustDbError::MalformedValue { .. })
            ),
            "65-char hex must be MalformedValue (not in accepted lengths 32/40/64/128), got {:?}",
            parse_trust_value(&raw_long)
        );

        // 50 hex chars: also not in the accepted set.
        let fifty = "a".repeat(50);
        let raw_50 = format!("1 12345 {fifty}").into_bytes();
        assert!(
            matches!(
                parse_trust_value(&raw_50),
                Err(TrustDbError::MalformedValue { .. })
            ),
            "50-char hex must be MalformedValue (not in accepted lengths 32/40/64/128), got {:?}",
            parse_trust_value(&raw_50)
        );
    }

    #[test]
    fn parse_trust_value_non_hex_chars_is_malformed() {
        // 64 chars but contains non-hex ('z' and 'G').
        let bad = "z".repeat(64);
        let raw = format!("1 12345 {bad}").into_bytes();
        assert!(
            matches!(
                parse_trust_value(&raw),
                Err(TrustDbError::MalformedValue { .. })
            ),
            "non-hex 64-char string must be MalformedValue, got {:?}",
            parse_trust_value(&raw)
        );
    }

    proptest! {
        /// Round-trip property: for any src in 0..=3, any u64 size, and any
        /// lowercase-hex string whose length is one of {32, 40, 64, 128},
        /// `parse_trust_value` recovers the same fields.
        /// The hex strategy emits chars from [0-9a-f] at each accepted length.
        #[test]
        fn parse_trust_value_roundtrip_prop(
            src_int in 0u32..=3,
            size in any::<u64>(),
            len_idx in 0usize..4,
            hex in proptest::collection::vec(
                proptest::sample::select(b"0123456789abcdef".as_slice()),
                128..=128,
            ),
        ) {
            let accepted_lens = [32usize, 40, 64, 128];
            let len = accepted_lens[len_idx];
            let hex: String = hex.into_iter().take(len).map(char::from).collect();
            let raw = value_bytes(src_int, size, &hex);
            let (got_src, got_size, got_hex) =
                parse_trust_value(&raw).expect("well-formed value must parse");
            let expected_src = match src_int {
                0 => TrustSource::Unknown,
                1 => TrustSource::RpmDb,
                2 => TrustSource::FileDb,
                3 => TrustSource::Deb,
                _ => unreachable!(),
            };
            prop_assert_eq!(got_src, expected_src);
            prop_assert_eq!(got_size, size);
            prop_assert_eq!(got_hex, hex);
        }
    }

    // ---- iter_entries / get_entry (DUPSORT) ---------------------------------

    /// DUPSORT: ONE key carrying TWO distinct value-rows must surface as TWO
    /// `TrustEntry`s (NO key dedup). Kills a re-added key-dedup mutant. Also
    /// asserts the parsed fields of a known row (source/size/sha256) so a
    /// mutant that returns the right COUNT but wrong field mapping dies.
    #[test]
    fn iter_entries_emits_one_row_per_dupsort_value() {
        let tmp = tempdir().expect("tempdir");
        // Same key "/usr/bin/python3", two different value-rows.
        // Row A: src=1 (RpmDb), size=111. Row B: src=2 (FileDb), size=222.
        let row_a = value_bytes(1, 111, KNOWN_SHA256);
        let row_b = value_bytes(2, 222, KNOWN_SHA256);
        write_trustdb_fixture_kv(
            tmp.path(),
            &[
                ("/usr/bin/python3", row_a.as_slice()),
                ("/usr/bin/python3", row_b.as_slice()),
            ],
        );

        let db = open_trustdb_readonly(tmp.path()).expect("open ro");
        let entries = db.iter_entries().expect("iter_entries");

        let py: Vec<&TrustEntry> = entries
            .iter()
            .filter(|e| e.path == "/usr/bin/python3")
            .collect();
        assert_eq!(
            py.len(),
            2,
            "DUPSORT key with two value-rows must surface TWO TrustEntries (no dedup), got {py:?}"
        );

        // The two rows must carry the distinct (source, size) pairs we wrote.
        let mut seen: Vec<(TrustSource, u64)> = py.iter().map(|e| (e.source, e.size)).collect();
        seen.sort_by_key(|(_, size)| *size);
        assert_eq!(
            seen,
            vec![(TrustSource::RpmDb, 111), (TrustSource::FileDb, 222)],
            "both value-rows must parse to their respective (source, size) pairs"
        );
        for e in &py {
            assert_eq!(
                e.digest, KNOWN_SHA256,
                "each row's digest field must round-trip from the fixture value"
            );
        }
    }

    /// `get_entry` returns `Some(rows)` for a present key (all DUPSORT rows) and
    /// `None` for an absent key. A stub returning `Ok(None)` always fails the
    /// present-key arm; one returning `Ok(Some(_))` always fails the absent arm.
    #[test]
    fn get_entry_present_returns_all_rows_absent_returns_none() {
        let tmp = tempdir().expect("tempdir");
        let row_a = value_bytes(1, 111, KNOWN_SHA256);
        let row_b = value_bytes(3, 333, KNOWN_SHA256);
        write_trustdb_fixture_kv(
            tmp.path(),
            &[
                ("/bin/sh", row_a.as_slice()),
                ("/bin/sh", row_b.as_slice()),
                ("/bin/ls", value_bytes(1, 999, KNOWN_SHA256).as_slice()),
            ],
        );

        let db = open_trustdb_readonly(tmp.path()).expect("open ro");

        let present = db.get_entry("/bin/sh").expect("get_entry");
        let rows = present.expect("present key must return Some");
        assert_eq!(
            rows.len(),
            2,
            "get_entry must return ALL DUPSORT rows for a present key, got {rows:?}"
        );
        assert!(
            rows.iter().all(|r| r.path == "/bin/sh"),
            "every returned row must carry the queried path"
        );

        let absent = db.get_entry("/bin/nonexistent").expect("get_entry");
        assert!(
            absent.is_none(),
            "get_entry must return None for an absent key, got {absent:?}"
        );
    }

    // ---- #318: get_entry / contains_path for >511-byte paths -----------------
    //
    // fapolicyd stores a trusted file whose path byte-length exceeds the LMDB
    // max key size (MDB_maxkeysize = 511; database.c path_to_hash) under the
    // lowercase-hex SHA-512 of the path bytes as the DB key (see trustdb.rs:243-271
    // for the source-grounded doc). A literal lookup by the path bytes misses the
    // hashed key and falsely reports the path as absent.
    //
    // Fixture construction: the hashed key is computed INDEPENDENTLY in each test
    // using sha2::Sha512 + the existing to_hex helper DIRECTLY - NOT via the new
    // path_to_hash helper (so a buggy helper cannot false-pass by being consistently
    // wrong in both the fixture write and the lookup).

    /// `get_entry` must find a path whose byte-length exceeds 511 when the DB
    /// holds the entry under the `path_to_hash` hashed key.
    ///
    /// RED: current `get_entry` looks up `p.as_bytes()` literally, so the hashed
    /// key is missed and the call returns `None` instead of `Some(rows)`.
    #[test]
    fn get_entry_long_path_stored_under_hashed_key_returns_some() {
        use sha2::Sha512;

        let tmp = tempdir().expect("tempdir");

        // Build a >511-byte absolute path (512 bytes: "/" + 511 'a's).
        let long_path = format!("/{}", "a".repeat(511));
        assert_eq!(
            long_path.len(),
            512,
            "fixture path must exceed MDB_maxkeysize=511"
        );

        // Compute the hashed key INDEPENDENTLY of the impl: lowercase-hex SHA-512
        // of the path BYTES (no trailing NUL in the hash input; see trustdb.rs:254-258).
        let hashed_key: String = {
            let mut h = Sha512::new();
            h.update(long_path.as_bytes());
            to_hex(&h.finalize())
        };
        assert_eq!(hashed_key.len(), 128, "hashed key must be 128 hex chars");
        assert!(
            hashed_key
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "hashed key must be lowercase hex"
        );

        // Write the fixture under the HASHED key (as fapolicyd does for long paths).
        let row = value_bytes(1, 999, KNOWN_SHA256);
        write_trustdb_fixture_kv(tmp.path(), &[(hashed_key.as_str(), row.as_slice())]);

        let db = open_trustdb_readonly(tmp.path()).expect("open ro");

        // Primary: get_entry(long_path) must find the hashed-key entry and return Some.
        let result = db
            .get_entry(&long_path)
            .expect("get_entry must not error on a hashed-key long-path entry");
        assert!(
            result.is_some(),
            "get_entry must return Some for a >511-byte path stored under its hashed key; \
             got None (literal-lookup bug: the key in the DB is the SHA-512 hex of the path, \
             not the path bytes themselves)"
        );
        let rows = result.unwrap();
        assert_eq!(rows.len(), 1, "exactly one row expected");
        assert_eq!(
            rows[0].path, long_path,
            "get_entry must set path to the queried path, not the hashed key"
        );
        assert_eq!(
            rows[0].size, 999,
            "size must round-trip from the fixture value"
        );

        // Counter-case: an ABSENT long path must return None, not a false positive.
        let other_long = format!("/{}", "b".repeat(511));
        assert!(
            db.get_entry(&other_long)
                .expect("get_entry absent long path must not error")
                .is_none(),
            "get_entry must return None for an absent >511-byte path"
        );
    }

    /// `get_entry` must find a >511-byte path stored under the DAEMON'S real
    /// hashed-key form: 128 lowercase-hex + a trailing C-string NUL
    /// (`mv_size = (SHA512_LEN*2)+1` = 129 bytes; database.c
    /// `trust_db_key_init_with_max`, used for BOTH write and read). The daemon
    /// ALWAYS writes this 129-byte form, so a lookup that only tries the bare
    /// 128-byte hex MISSES every real daemon-written long-path entry (the #318
    /// follow-up defect found by impl-aware review). The 128-byte fixture in
    /// `get_entry_long_path_stored_under_hashed_key_returns_some` is the other
    /// shape `validate_trust_key` accepts; keyed lookup must find BOTH.
    #[test]
    fn get_entry_long_path_stored_under_daemon_129byte_key_returns_some() {
        use sha2::Sha512;

        let tmp = tempdir().expect("tempdir");
        let long_path = format!("/{}", "a".repeat(511)); // 512 bytes, > 511.

        // Independent hash (NOT via path_to_hash), then the daemon's trailing NUL.
        let hashed_key: String = {
            let mut h = Sha512::new();
            h.update(long_path.as_bytes());
            to_hex(&h.finalize())
        };
        let mut daemon_key = hashed_key.clone();
        daemon_key.push('\0'); // 128 hex + 1 NUL = the 129-byte stored key.
        assert_eq!(
            daemon_key.len(),
            129,
            "daemon stores 128 hex + 1 trailing NUL (mv_size = SHA512_LEN*2+1)"
        );

        let row = value_bytes(1, 999, KNOWN_SHA256);
        write_trustdb_fixture_kv(tmp.path(), &[(daemon_key.as_str(), row.as_slice())]);

        let db = open_trustdb_readonly(tmp.path()).expect("open ro");
        let rows = db
            .get_entry(&long_path)
            .expect("get_entry must not error on a daemon 129-byte hashed key")
            .expect(
                "get_entry must find the daemon's 129-byte (128 hex + NUL) hashed key; \
                 a 128-byte-only lookup misses every real daemon-written long path (#318)",
            );
        assert_eq!(rows.len(), 1, "exactly one row");
        assert_eq!(rows[0].path, long_path, "path is the queried path");
        assert_eq!(rows[0].size, 999, "size round-trips from the fixture value");
    }

    /// `contains_path` must return `true` for a >511-byte path stored under the
    /// daemon's 129-byte hashed key (128 hex + trailing NUL), mirroring
    /// `get_entry_long_path_stored_under_daemon_129byte_key_returns_some`.
    #[test]
    fn contains_path_long_path_stored_under_daemon_129byte_key_returns_true() {
        use sha2::Sha512;

        let tmp = tempdir().expect("tempdir");
        let long_path = format!("/{}", "z".repeat(512)); // 513 bytes.

        let hashed_key: String = {
            let mut h = Sha512::new();
            h.update(long_path.as_bytes());
            to_hex(&h.finalize())
        };
        let mut daemon_key = hashed_key.clone();
        daemon_key.push('\0');

        let row = value_bytes(2, 42, KNOWN_SHA256);
        write_trustdb_fixture_kv(tmp.path(), &[(daemon_key.as_str(), row.as_slice())]);

        let db = open_trustdb_readonly(tmp.path()).expect("open ro");
        assert!(
            db.contains_path(&long_path),
            "contains_path must find the daemon's 129-byte (128 hex + NUL) hashed key (#318)"
        );
    }

    /// A path of EXACTLY `MDB_MAX_KEY_SIZE` (511) bytes is stored under its
    /// LITERAL key: the daemon hashes only when the path length EXCEEDS the max
    /// key size (`strlen(idx) > maxkeysize`, database.c `trust_db_key_init_with_max`),
    /// so 511 bytes still fits as a literal LMDB key. `get_entry`/`contains_path`
    /// must look a 511-byte path up LITERALLY, not hashed -- this pins the
    /// `> MDB_MAX_KEY_SIZE` boundary (a `>=` would wrongly hash it and miss).
    #[test]
    fn get_entry_and_contains_path_at_511_byte_boundary_use_literal_key() {
        let tmp = tempdir().expect("tempdir");
        // Exactly 511 bytes: "/" + 510 'a's. 511 == MDB_MAX_KEY_SIZE, NOT > it.
        let boundary_path = format!("/{}", "a".repeat(510));
        assert_eq!(
            boundary_path.len(),
            511,
            "boundary path must be exactly MDB_maxkeysize"
        );

        // Stored under the LITERAL path key (as the daemon does for len <= 511).
        let row = value_bytes(1, 511, KNOWN_SHA256);
        write_trustdb_fixture_kv(tmp.path(), &[(boundary_path.as_str(), row.as_slice())]);

        let db = open_trustdb_readonly(tmp.path()).expect("open ro");
        // A `> -> >=` mutation would HASH this 511-byte path and miss the literal key.
        assert!(
            db.get_entry(&boundary_path)
                .expect("get_entry must not error on a 511-byte literal-key entry")
                .is_some(),
            "a 511-byte path is stored LITERALLY (not hashed); get_entry must use the literal key"
        );
        assert!(
            db.contains_path(&boundary_path),
            "a 511-byte path is stored LITERALLY; contains_path must use the literal key"
        );
    }

    /// `contains_path` must return `true` for a path whose byte-length exceeds
    /// 511 when the DB holds the entry under the `path_to_hash` hashed key.
    ///
    /// RED: current `contains_path` looks up `p.as_bytes()` literally, so the
    /// hashed key is missed and the call returns `false` instead of `true`.
    #[test]
    fn contains_path_long_path_stored_under_hashed_key_returns_true() {
        use sha2::Sha512;

        let tmp = tempdir().expect("tempdir");

        // 513-byte path (different length from the get_entry test, exercises the
        // predicate boundary independently).
        let long_path = format!("/{}", "z".repeat(512));
        assert_eq!(
            long_path.len(),
            513,
            "fixture path must exceed MDB_maxkeysize=511"
        );

        // Compute hashed key independently.
        let hashed_key: String = {
            let mut h = Sha512::new();
            h.update(long_path.as_bytes());
            to_hex(&h.finalize())
        };

        let row = value_bytes(2, 42, KNOWN_SHA256);
        write_trustdb_fixture_kv(tmp.path(), &[(hashed_key.as_str(), row.as_slice())]);

        let db = open_trustdb_readonly(tmp.path()).expect("open ro");

        assert!(
            db.contains_path(&long_path),
            "contains_path must return true for a >511-byte path stored under its hashed key; \
             got false (literal-lookup bug: the key in the DB is the SHA-512 hex of the path)"
        );

        // Counter-case: a <=511 path stored under its literal key is still found.
        let short_path = "/usr/bin/ls";
        let short_row = value_bytes(1, 111, KNOWN_SHA256);
        // Need a second DB for this counter-case (same tempdir reuse pattern).
        let tmp2 = tempdir().expect("tempdir2");
        write_trustdb_fixture_kv(tmp2.path(), &[(short_path, short_row.as_slice())]);
        let db2 = open_trustdb_readonly(tmp2.path()).expect("open ro short");
        assert!(
            db2.contains_path(short_path),
            "contains_path must still work for <=511-byte paths stored under literal keys"
        );
        assert!(
            !db2.contains_path("/nonexistent"),
            "contains_path must return false for an absent <=511 path"
        );
    }

    // ---- end #318 tests -------------------------------------------------------

    // ---- verify_entry (order: Missing -> SizeMismatch -> Hash compare) -------

    /// A `TrustEntry` whose recorded size+hash MATCH the real file on disk
    /// yields `DiskVerdict::Match`. The recorded hash is `KNOWN_SHA256`
    /// (sha256sum-verified) and the size is `KNOWN_SIZE`.
    #[test]
    fn verify_entry_matching_file_is_match() {
        let f = known_temp_file();
        let entry = TrustEntry {
            path: f.path().display().to_string(),
            source: TrustSource::FileDb,
            size: KNOWN_SIZE,
            digest: KNOWN_SHA256.to_owned(),
        };
        assert_eq!(verify_entry(&entry), DiskVerdict::Match);
    }

    /// Flipping ONE hex nibble of the recorded hash (size still correct) yields
    /// `HashMismatch`, NOT `Match`. The recorded hash differs from the file's
    /// real digest, so a correct impl must hash + compare.
    #[test]
    fn verify_entry_wrong_hash_is_hash_mismatch() {
        let f = known_temp_file();
        // Flip the first hex char: '3' -> '4' in KNOWN_SHA256.
        let mut wrong = KNOWN_SHA256.to_owned();
        let flipped = if KNOWN_SHA256.starts_with('3') {
            '4'
        } else {
            '3'
        };
        wrong.replace_range(0..1, &flipped.to_string());
        assert_ne!(wrong, KNOWN_SHA256, "flipped hash must differ from real");

        let entry = TrustEntry {
            path: f.path().display().to_string(),
            source: TrustSource::FileDb,
            size: KNOWN_SIZE,
            digest: wrong.clone(),
        };
        match verify_entry(&entry) {
            DiskVerdict::HashMismatch { recorded, actual } => {
                assert_eq!(recorded, wrong, "recorded hash must be the entry's hash");
                assert_eq!(
                    actual, KNOWN_SHA256,
                    "actual hash must be the file's real digest"
                );
            }
            other => panic!("expected HashMismatch, got {other:?}"),
        }
    }

    /// A recorded size that differs from the on-disk size yields `SizeMismatch`
    /// WITHOUT needing a correct hash: the recorded hash here is all-zeros
    /// (definitely NOT the file's real digest), yet the verdict must be
    /// `SizeMismatch` because size is checked first. Kills a mutant that hashes
    /// before comparing sizes (it would report `HashMismatch` instead).
    #[test]
    fn verify_entry_wrong_size_is_size_mismatch_before_hashing() {
        let f = known_temp_file();
        let bogus_hash = "0".repeat(64);
        let recorded_size = KNOWN_SIZE + 1000;
        let entry = TrustEntry {
            path: f.path().display().to_string(),
            source: TrustSource::FileDb,
            size: recorded_size,
            digest: bogus_hash,
        };
        match verify_entry(&entry) {
            DiskVerdict::SizeMismatch { recorded, actual } => {
                assert_eq!(recorded, recorded_size, "recorded size must be the entry's");
                assert_eq!(
                    actual, KNOWN_SIZE,
                    "actual size must be the file's real size"
                );
            }
            other => panic!("expected SizeMismatch (size checked before hash), got {other:?}"),
        }
    }

    /// A `TrustEntry` whose path does not exist on disk yields `Missing`,
    /// checked BEFORE size/hash. Kills a mutant that reports `ReadError` or
    /// `SizeMismatch` for an absent file.
    #[test]
    fn verify_entry_nonexistent_path_is_missing() {
        let entry = TrustEntry {
            path: "/nonexistent/path/rs-3d-trustdb/zzz".to_owned(),
            source: TrustSource::FileDb,
            size: KNOWN_SIZE,
            digest: KNOWN_SHA256.to_owned(),
        };
        assert_eq!(verify_entry(&entry), DiskVerdict::Missing);
    }

    /// A `TrustEntry` whose path traverses through a REGULAR FILE as if it
    /// were a directory (e.g. `/tmp/realfile/child`) causes `std::fs::metadata`
    /// to return `ErrorKind::NotADirectory` (POSIX ENOTDIR, errno 20). This is
    /// NOT `NotFound`, so the correct verdict is `ReadError`, not `Missing`.
    ///
    /// Kills the `trustdb.rs:128:19` mutation survivor that replaces the
    /// `e.kind() == ErrorKind::NotFound` guard with `true`, which would
    /// incorrectly return `Missing` for any metadata error regardless of kind.
    ///
    /// Platform note: on Linux `metadata("file/child")` always returns
    /// `ErrorKind::NotADirectory`; confirmed empirically on the build host.
    #[test]
    fn verify_entry_metadata_not_a_directory_is_read_error() {
        let f = known_temp_file();
        // Build a path whose parent component IS the regular file above.
        // metadata() will fail with NotADirectory (ENOTDIR), not NotFound.
        let impossible_child = format!("{}/child", f.path().display());
        let entry = TrustEntry {
            path: impossible_child,
            source: TrustSource::FileDb,
            size: KNOWN_SIZE,
            digest: KNOWN_SHA256.to_owned(),
        };
        match verify_entry(&entry) {
            DiskVerdict::ReadError(msg) => {
                // The OS message must mention ENOTDIR, not ENOENT.
                assert!(
                    !msg.contains("No such file or directory"),
                    "verdict must be ReadError(ENOTDIR), not a NotFound proxy; got: {msg:?}"
                );
            }
            other => panic!("expected ReadError for metadata NotADirectory path, got {other:?}"),
        }
    }

    /// A `TrustEntry` whose metadata succeeds (file exists, size matches) but
    /// whose `File::open` is refused with `PermissionDenied` yields `ReadError`,
    /// not `Missing`. This distinguishes the two error-kind arms at line 144.
    ///
    /// Setup: write a file, record its real size, then `chmod 000` it. After
    /// that, `std::fs::metadata` still succeeds (the parent directory is
    /// accessible and metadata does not require read permission on the file
    /// itself), the size passes the equality check, and then `File::open`
    /// returns `ErrorKind::PermissionDenied`.
    ///
    /// Kills two mutation survivors at `trustdb.rs:144`:
    /// - `guard -> true`: would return `Missing` for ANY open error (wrong for
    ///   `PermissionDenied`).
    /// - `== -> !=`: `PermissionDenied != NotFound` is `true`, so the mutant
    ///   would also return `Missing` (wrong).
    ///
    /// The third survivor at line 144 (`guard -> false`, which returns `ReadError`
    /// even for `NotFound`) is a genuine equivalent mutant: reaching it requires
    /// `File::open` to return `NotFound` after `metadata` already succeeded, which
    /// is only possible via a TOCTOU race (file deleted between the two calls).
    /// That case is excluded in `.cargo/mutants.toml` with a precise rationale.
    ///
    /// Skipped if running as root (root bypasses DAC; `chmod 000` has no effect).
    #[test]
    fn verify_entry_open_permission_denied_is_read_error() {
        let dir = tempdir().expect("tempdir");
        let file_path = dir.path().join("no_perm");
        std::fs::write(&file_path, KNOWN_BYTES).expect("write known bytes");

        // Confirm real size before locking down permissions.
        let real_size = std::fs::metadata(&file_path)
            .expect("metadata before chmod")
            .len();
        assert_eq!(real_size, KNOWN_SIZE, "fixture size must match KNOWN_SIZE");

        // Remove all permissions so File::open returns PermissionDenied.
        let status = std::process::Command::new("chmod")
            .args(["000", file_path.to_str().expect("utf8 path")])
            .status()
            .expect("chmod");
        assert!(status.success(), "chmod 000 failed");

        // Skip under root: DAC checks are bypassed and chmod 000 has no effect.
        // Probe by attempting to open the file; if it succeeds, we are root and
        // the test cannot observe PermissionDenied at all.
        if std::fs::File::open(&file_path).is_ok() {
            // Restore and skip; root bypasses DAC.
            let _ = std::process::Command::new("chmod")
                .args(["644", file_path.to_str().expect("utf8 path")])
                .status();
            return;
        }

        let entry = TrustEntry {
            path: file_path.display().to_string(),
            source: TrustSource::FileDb,
            size: real_size,
            digest: KNOWN_SHA256.to_owned(),
        };

        match verify_entry(&entry) {
            DiskVerdict::ReadError(msg) => {
                assert!(
                    msg.contains("ermission") || msg.contains("EPERM") || msg.contains("13"),
                    "expected PermissionDenied message, got: {msg:?}"
                );
            }
            other => {
                panic!("expected ReadError(PermissionDenied) for chmod-000 file, got {other:?}")
            }
        }

        // Restore permissions so tempdir cleanup succeeds.
        let _ = std::process::Command::new("chmod")
            .args(["644", file_path.to_str().expect("utf8 path")])
            .status();
    }

    // ---- CLEAN-3b RED tests: 4-length parse + SHA-512 verify ----------------

    /// Parser must accept all four fapolicyd digest lengths: MD5 (32), SHA1 (40),
    /// SHA256 (64), SHA512 (128). Each well-formed line must parse Ok and the
    /// returned digest must round-trip exactly.
    ///
    /// RED today: the parser's `hex_field.len() != 64` guard rejects lengths 32,
    /// 40, and 128 with `MalformedValue`.
    #[test]
    fn parse_accepts_all_four_digest_lengths() {
        for len in [32usize, 40, 64, 128] {
            let hex = "a".repeat(len);
            let raw = format!("2 100 {hex}");
            let (src, size, got_hex) = parse_trust_value(raw.as_bytes())
                .unwrap_or_else(|e| panic!("len {len} should parse Ok, got Err: {e:?}"));
            assert_eq!(
                src,
                TrustSource::FileDb,
                "len {len}: src int 2 must map to FileDb"
            );
            assert_eq!(size, 100u64, "len {len}: size must round-trip");
            assert_eq!(got_hex, hex, "len {len}: digest must round-trip exactly");
        }
    }

    /// Parser must still reject off-length hex (e.g. 4 chars) and uppercase hex
    /// (even when the length is accepted). This is a preservation guard - the
    /// rejection of non-hex and off-length is expected both before and after the
    /// widening. It will likely PASS today (current code rejects both); it
    /// confirms no regression.
    ///
    /// Note: this test is a guard, not a RED test. The implementer must not weaken it.
    #[test]
    fn parse_rejects_off_length_and_uppercase() {
        // 4-char hex: not in accepted set {32, 40, 64, 128}.
        assert!(
            parse_trust_value(b"2 100 abcd").is_err(),
            "4-char hex must be rejected (not in accepted lengths 32/40/64/128)"
        );
        // 64 uppercase hex chars: uppercase is not lowercase-hex.
        let upper64 = "A".repeat(64);
        let raw_upper = format!("2 100 {upper64}");
        assert!(
            parse_trust_value(raw_upper.as_bytes()).is_err(),
            "64 uppercase hex chars must be rejected (not lowercase)"
        );
    }

    /// The verifier must compute SHA-512 and return `DiskVerdict::Match` when the
    /// trust entry records a 128-hex (SHA-512) digest that matches the file.
    ///
    /// The expected digest is computed with the same `sha2::Sha512` the impl will
    /// use, so the test is self-consistent (not grounded in an external `sha512sum`
    /// value - a note for future grounding if the impl changes).
    ///
    /// RED today: `verify_entry` only calls `Sha256`; a 128-hex digest will compare
    /// against a 64-char actual hex and return `HashMismatch` instead of `Match`.
    #[test]
    fn verify_matches_sha512_file() {
        use sha2::Sha512;
        use std::io::Write as _;

        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("blob");
        let mut f = std::fs::File::create(&path).expect("create blob file");
        f.write_all(b"hello").expect("write blob");
        drop(f);

        // Compute SHA-512 of b"hello" using sha2::Sha512, so the expected value
        // is derived from the same crate the impl will use. Both the test and the
        // impl call sha2::Sha512 - a future grounding pass could pin against
        // coreutils sha512sum output.
        let want: String = {
            let mut h = Sha512::new();
            h.update(b"hello");
            h.finalize().iter().map(|b| format!("{b:02x}")).collect()
        };
        assert_eq!(want.len(), 128, "SHA-512 hex must be 128 chars");

        let entry = TrustEntry {
            path: path.to_string_lossy().into_owned(),
            source: TrustSource::FileDb,
            size: 5, // b"hello" is 5 bytes
            digest: want.clone(),
        };
        assert_eq!(
            verify_entry(&entry),
            DiskVerdict::Match,
            "SHA-512 digest must verify as Match; current impl only does SHA-256 so this is RED"
        );
    }

    /// The verifier must compute MD5 and return `DiskVerdict::Match` when the
    /// trust entry records a 32-hex (MD5) digest that matches the file.
    ///
    /// The expected digest is grounded in coreutils `md5sum`:
    ///   `printf 'hello' | md5sum` => `5d41402abc4b2a76b9719d911017c592`
    /// The md-5 crate is not yet a dependency (the implementer adds it), so the
    /// expected value is a verified literal constant, not computed in the test.
    ///
    /// RED today: `verify_entry` length-dispatches on `entry.digest.len()`. The
    /// MD5 arm (`len == 32`) does not exist yet, so a 32-hex digest compared
    /// against the 64-char SHA-256 actual hex yields `HashMismatch`, not `Match`.
    /// A mutant that swaps or deletes the 32/MD5 arm would also survive without
    /// this test.
    #[test]
    fn verify_matches_md5_file() {
        use std::io::Write as _;

        // MD5 of b"hello" (5 bytes, no newline), grounded in coreutils md5sum:
        //   printf 'hello' | md5sum  =>  5d41402abc4b2a76b9719d911017c592
        const MD5_OF_HELLO: &str = "5d41402abc4b2a76b9719d911017c592";
        assert_eq!(MD5_OF_HELLO.len(), 32, "MD5 hex must be 32 chars");
        assert!(
            MD5_OF_HELLO
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "MD5 hex must be lowercase hex only"
        );

        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("blob_md5");
        let mut f = std::fs::File::create(&path).expect("create blob file");
        f.write_all(b"hello").expect("write blob");
        drop(f);

        let entry = TrustEntry {
            path: path.to_string_lossy().into_owned(),
            source: TrustSource::FileDb,
            size: 5, // b"hello" is 5 bytes
            digest: MD5_OF_HELLO.to_owned(),
        };
        assert_eq!(
            verify_entry(&entry),
            DiskVerdict::Match,
            "MD5 digest (32-hex) must verify as Match; current impl only does SHA-256 so this is RED"
        );
    }

    /// The verifier must compute SHA-1 and return `DiskVerdict::Match` when the
    /// trust entry records a 40-hex (SHA-1) digest that matches the file.
    ///
    /// The expected digest is grounded in coreutils `sha1sum`:
    ///   `printf 'hello' | sha1sum` => `aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d`
    /// The sha-1 crate is not yet a dependency (the implementer adds it), so the
    /// expected value is a verified literal constant, not computed in the test.
    ///
    /// RED today: `verify_entry` length-dispatches on `entry.digest.len()`. The
    /// SHA-1 arm (`len == 40`) does not exist yet, so a 40-hex digest compared
    /// against the 64-char SHA-256 actual hex yields `HashMismatch`, not `Match`.
    /// A mutant that swaps or deletes the 40/SHA-1 arm would also survive without
    /// this test.
    #[test]
    fn verify_matches_sha1_file() {
        use std::io::Write as _;

        // SHA-1 of b"hello" (5 bytes, no newline), grounded in coreutils sha1sum:
        //   printf 'hello' | sha1sum  =>  aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d
        const SHA1_OF_HELLO: &str = "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d";
        assert_eq!(SHA1_OF_HELLO.len(), 40, "SHA-1 hex must be 40 chars");
        assert!(
            SHA1_OF_HELLO
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "SHA-1 hex must be lowercase hex only"
        );

        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("blob_sha1");
        let mut f = std::fs::File::create(&path).expect("create blob file");
        f.write_all(b"hello").expect("write blob");
        drop(f);

        let entry = TrustEntry {
            path: path.to_string_lossy().into_owned(),
            source: TrustSource::FileDb,
            size: 5, // b"hello" is 5 bytes
            digest: SHA1_OF_HELLO.to_owned(),
        };
        assert_eq!(
            verify_entry(&entry),
            DiskVerdict::Match,
            "SHA-1 digest (40-hex) must verify as Match; current impl only does SHA-256 so this is RED"
        );
    }

    // ---- IntegrityMode::from_conf_value (grounded in fapolicyd.conf(5)) -----
    // The four exact values (none/size/ima/sha256) must map 1:1. Anything else
    // maps to IntegrityMode::None (the daemon default when the key is absent).

    #[test]
    fn integrity_mode_from_conf_none_str_maps_to_none() {
        assert_eq!(
            IntegrityMode::from_conf_value(Some("none")),
            IntegrityMode::None
        );
    }

    #[test]
    fn integrity_mode_from_conf_size_str_maps_to_size() {
        assert_eq!(
            IntegrityMode::from_conf_value(Some("size")),
            IntegrityMode::Size
        );
    }

    #[test]
    fn integrity_mode_from_conf_ima_str_maps_to_ima() {
        assert_eq!(
            IntegrityMode::from_conf_value(Some("ima")),
            IntegrityMode::Ima
        );
    }

    #[test]
    fn integrity_mode_from_conf_sha256_str_maps_to_sha256() {
        assert_eq!(
            IntegrityMode::from_conf_value(Some("sha256")),
            IntegrityMode::Sha256
        );
    }

    /// Absent key (`Option::None`) must map to `IntegrityMode::None` (daemon default).
    #[test]
    fn integrity_mode_from_conf_absent_key_maps_to_none() {
        assert_eq!(IntegrityMode::from_conf_value(None), IntegrityMode::None);
    }

    /// Garbage / unrecognised value must map to `IntegrityMode::None`.
    #[test]
    fn integrity_mode_from_conf_garbage_maps_to_none() {
        assert_eq!(
            IntegrityMode::from_conf_value(Some("unknown_value")),
            IntegrityMode::None
        );
        assert_eq!(
            IntegrityMode::from_conf_value(Some("")),
            IntegrityMode::None
        );
    }

    /// Whitespace-only value must map to `IntegrityMode::None` (not a valid keyword).
    #[test]
    fn integrity_mode_from_conf_whitespace_maps_to_none() {
        assert_eq!(
            IntegrityMode::from_conf_value(Some("  ")),
            IntegrityMode::None
        );
    }

    /// A value with trailing inline `#` (literal per `conf_value` semantics) must
    /// NOT match "sha256" -- `conf_value` already strips leading/trailing whitespace
    /// around `=` but does NOT strip inline comments. So "sha256 # important"
    /// is the raw value, which is unrecognised and maps to `IntegrityMode::None`.
    #[test]
    fn integrity_mode_from_conf_trailing_hash_comment_maps_to_none() {
        // conf_value returns the literal trimmed value including inline `#` text.
        // "sha256 # inline" is NOT the keyword "sha256", so it maps to None.
        assert_eq!(
            IntegrityMode::from_conf_value(Some("sha256 # important")),
            IntegrityMode::None,
            "a value with trailing inline # is literal (not a comment) and must not match sha256"
        );
    }

    /// "SHA256" (uppercase) is not a valid fapolicyd.conf keyword; maps to `IntegrityMode::None`.
    #[test]
    fn integrity_mode_from_conf_uppercase_sha256_maps_to_none() {
        assert_eq!(
            IntegrityMode::from_conf_value(Some("SHA256")),
            IntegrityMode::None
        );
    }

    // ---- IntegrityMode::as_keyword (inverse of from_conf_value) --------------

    /// `as_keyword` must emit the exact lowercase `fapolicyd.conf` keyword for
    /// each variant. One assert per arm so a swapped/collapsed-match mutant dies
    /// on a specific variant. `sha256` (not `sha-256`) is load-bearing: the CLI
    /// `--integrity` value-enum and the conf parser both spell it `sha256`.
    #[test]
    fn integrity_mode_as_keyword_spells_each_variant() {
        assert_eq!(IntegrityMode::None.as_keyword(), "none");
        assert_eq!(IntegrityMode::Size.as_keyword(), "size");
        assert_eq!(IntegrityMode::Ima.as_keyword(), "ima");
        assert_eq!(IntegrityMode::Sha256.as_keyword(), "sha256");
    }

    /// Round-trip: every mode's keyword parses back to the same mode via
    /// `from_conf_value`. This pins `as_keyword` as the true inverse of
    /// `from_conf_value` for the four recognised keywords, so the two can never
    /// silently drift apart.
    #[test]
    fn integrity_mode_keyword_roundtrips_through_from_conf_value() {
        for mode in [
            IntegrityMode::None,
            IntegrityMode::Size,
            IntegrityMode::Ima,
            IntegrityMode::Sha256,
        ] {
            assert_eq!(
                IntegrityMode::from_conf_value(Some(mode.as_keyword())),
                mode,
                "as_keyword({mode:?}) must parse back to {mode:?}"
            );
        }
    }

    // ---- IntegrityMode::enforces -- full 5x4 enforcement table (RED) ---------
    // These tests assert the INTENDED post-impl behavior. The stub always returns
    // `true`, so:
    //   - Tests asserting enforces()==true will PASS (stub agrees).
    //   - Tests asserting enforces()==false will FAIL (stub returns true instead).
    // This makes them RED in the right way: they fail because the gating logic
    // isn't implemented yet, NOT because of a compile or panic.
    //
    // Per the grounded contract (fapolicyd.conf(5)):
    //   SizeMismatch: enforced under size|ima|sha256; NOT under none.
    //   HashMismatch: enforced ONLY under sha256.
    //   Missing:      ALWAYS enforced (not integrity-gated).
    //   ReadError:    ALWAYS enforced.
    //   NotInDb:      (handled by CheckVerdict; not a DiskVerdict; covered in e2e)
    //
    // One test per (mode, verdict) cell so a wrong-cell mutant dies on exactly
    // that assertion.

    // -- SizeMismatch --
    // Enforced under size, ima, sha256. NOT under none.

    #[test]
    fn integrity_none_does_not_enforce_size_mismatch() {
        // RED: stub returns true; real impl must return false.
        assert!(
            !IntegrityMode::None.enforces(&DiskVerdict::SizeMismatch {
                recorded: 100,
                actual: 200
            }),
            "integrity=none must NOT enforce SizeMismatch (it is visible but not exit-code-raising)"
        );
    }

    #[test]
    fn integrity_size_enforces_size_mismatch() {
        assert!(
            IntegrityMode::Size.enforces(&DiskVerdict::SizeMismatch {
                recorded: 100,
                actual: 200
            }),
            "integrity=size must enforce SizeMismatch"
        );
    }

    #[test]
    fn integrity_ima_enforces_size_mismatch() {
        assert!(
            IntegrityMode::Ima.enforces(&DiskVerdict::SizeMismatch {
                recorded: 100,
                actual: 200
            }),
            "integrity=ima must enforce SizeMismatch (size check is a prerequisite to IMA)"
        );
    }

    #[test]
    fn integrity_sha256_enforces_size_mismatch() {
        assert!(
            IntegrityMode::Sha256.enforces(&DiskVerdict::SizeMismatch {
                recorded: 100,
                actual: 200
            }),
            "integrity=sha256 must enforce SizeMismatch"
        );
    }

    // -- HashMismatch --
    // Enforced ONLY under sha256. NOT under none, size, or ima.

    #[test]
    fn integrity_none_does_not_enforce_hash_mismatch() {
        // RED: stub returns true; real impl must return false.
        assert!(
            !IntegrityMode::None.enforces(&DiskVerdict::HashMismatch {
                recorded: "a".repeat(64),
                actual: "b".repeat(64)
            }),
            "integrity=none must NOT enforce HashMismatch"
        );
    }

    #[test]
    fn integrity_size_does_not_enforce_hash_mismatch() {
        // RED: stub returns true; real impl must return false.
        assert!(
            !IntegrityMode::Size.enforces(&DiskVerdict::HashMismatch {
                recorded: "a".repeat(64),
                actual: "b".repeat(64)
            }),
            "integrity=size must NOT enforce HashMismatch (only size, not digest)"
        );
    }

    #[test]
    fn integrity_ima_does_not_enforce_hash_mismatch() {
        // RED: stub returns true; real impl must return false.
        // ima checks the IMA xattr hash (not the trust-DB digest), so HashMismatch
        // in the trust DB is NOT enforced under ima.
        assert!(
            !IntegrityMode::Ima.enforces(&DiskVerdict::HashMismatch {
                recorded: "a".repeat(64),
                actual: "b".repeat(64)
            }),
            "integrity=ima must NOT enforce trust-DB HashMismatch (ima uses the IMA xattr, not the DB digest)"
        );
    }

    #[test]
    fn integrity_sha256_enforces_hash_mismatch() {
        assert!(
            IntegrityMode::Sha256.enforces(&DiskVerdict::HashMismatch {
                recorded: "a".repeat(64),
                actual: "b".repeat(64)
            }),
            "integrity=sha256 must enforce HashMismatch"
        );
    }

    // -- Missing -- ALWAYS enforced under all modes.

    #[test]
    fn integrity_none_enforces_missing() {
        assert!(
            IntegrityMode::None.enforces(&DiskVerdict::Missing),
            "integrity=none must enforce Missing (file absence is always an integrity violation)"
        );
    }

    #[test]
    fn integrity_size_enforces_missing() {
        assert!(
            IntegrityMode::Size.enforces(&DiskVerdict::Missing),
            "integrity=size must enforce Missing"
        );
    }

    #[test]
    fn integrity_ima_enforces_missing() {
        assert!(
            IntegrityMode::Ima.enforces(&DiskVerdict::Missing),
            "integrity=ima must enforce Missing"
        );
    }

    #[test]
    fn integrity_sha256_enforces_missing() {
        assert!(
            IntegrityMode::Sha256.enforces(&DiskVerdict::Missing),
            "integrity=sha256 must enforce Missing"
        );
    }

    // -- ReadError -- ALWAYS enforced under all modes.

    #[test]
    fn integrity_none_enforces_read_error() {
        assert!(
            IntegrityMode::None.enforces(&DiskVerdict::ReadError("permission denied".to_owned())),
            "integrity=none must enforce ReadError (I/O failure is always an integrity violation)"
        );
    }

    #[test]
    fn integrity_size_enforces_read_error() {
        assert!(
            IntegrityMode::Size.enforces(&DiskVerdict::ReadError("err".to_owned())),
            "integrity=size must enforce ReadError"
        );
    }

    #[test]
    fn integrity_ima_enforces_read_error() {
        assert!(
            IntegrityMode::Ima.enforces(&DiskVerdict::ReadError("err".to_owned())),
            "integrity=ima must enforce ReadError"
        );
    }

    #[test]
    fn integrity_sha256_enforces_read_error() {
        assert!(
            IntegrityMode::Sha256.enforces(&DiskVerdict::ReadError("err".to_owned())),
            "integrity=sha256 must enforce ReadError"
        );
    }

    // -- Match -- never enforced (it is clean; enforces does not apply to Match
    // in the gating sense, but we test it returns true for all modes to confirm
    // the stub doesn't accidentally skip clean verdicts through the exit-code path).
    // This is a GREEN stability test (stub returns true, real impl should also be
    // true for Match -- a match is never a gating event but should not be suppressed).
    // Actually: enforces(Match) is never called in the gating path (only called
    // for divergence verdicts). We skip Match tests to avoid specification ambiguity.
}

// ---------------------------------------------------------------------------
// fuzz-targets shim
// ---------------------------------------------------------------------------
// This block is compiled ONLY when the `fuzz-targets` feature is enabled.
// It re-exports `parse_trust_value` as a hidden public symbol so the fuzz
// crate (nightly-only, excluded from the stable workspace) can call it
// without requiring the fuzzer to recreate the parsing logic.  Nothing in
// the default feature set or the shipped binary activates this feature.

#[cfg(feature = "fuzz-targets")]
#[doc(hidden)]
pub mod fuzz_hooks {
    /// Public shim over the crate-private [`super::parse_trust_value`].
    ///
    /// **Not part of the stable public API.** Enabled only under the
    /// `fuzz-targets` Cargo feature; do not depend on it from non-fuzz code.
    pub fn parse_trust_value_fuzz(
        raw: &[u8],
    ) -> Result<(super::TrustSource, u64, String), super::TrustDbError> {
        super::parse_trust_value(raw)
    }
}
