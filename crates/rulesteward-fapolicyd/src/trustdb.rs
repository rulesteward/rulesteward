//! fapolicyd trust-DB reader (heed, read-only).

use std::io::Read as _;
use std::path::{Path, PathBuf};

use heed::types::Bytes;
use heed::{Database, Env, EnvFlags, EnvOpenOptions};
use md5::Md5;
use serde::Serialize;
use sha1::Sha1;
use sha2::{Sha256, Sha512};

#[derive(Debug, thiserror::Error)]
pub enum TrustDbError {
    #[error("trust DB has no \"trust.db\" sub-database at {0}")]
    Missing(PathBuf),
    #[error("heed error: {0}")]
    Open(#[from] heed::Error),
    #[error("malformed trust-DB value for key {key:?}: {raw:?}")]
    MalformedValue { key: String, raw: String },
}

/// Which database populated a trust-DB entry (fapolicyd source integer).
///
/// Mirrors fapolicyd's `trust_src_t` enum (`fapolicyd-backend.h`):
/// `SRC_UNKNOWN = 0`, `SRC_RPM = 1`, `SRC_FILE_DB = 2`, `SRC_DEB = 3`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum TrustSource {
    FileDb,
    RpmDb,
    Deb,
    Unknown,
}

impl TrustSource {
    /// Map the on-disk source integer to a `TrustSource` variant.
    ///
    /// fapolicyd encodes the origin of each trust entry as a small integer
    /// in the value field (`SRC_UNKNOWN = 0`, `SRC_RPM = 1`, `SRC_FILE_DB = 2`,
    /// `SRC_DEB = 3`; any other value maps to `Unknown`).
    #[must_use]
    pub fn from_int(n: u32) -> Self {
        match n {
            1 => Self::RpmDb,
            2 => Self::FileDb,
            3 => Self::Deb,
            // 0 (SRC_UNKNOWN) and any unrecognized value both map to Unknown.
            _ => Self::Unknown,
        }
    }
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

/// Parse the raw bytes of a trust-DB value (`"<src_int> <size> <digest_hex>"`).
///
/// Returns `(source, size, digest_hex)` on success. The value must be EXACTLY
/// three ASCII-space-separated fields: a u32 source integer, a u64 size, and a
/// lowercase-hex digest whose length is one of {32, 40, 64, 128} (MD5, SHA-1,
/// SHA-256, SHA-512). Any deviation (wrong field count, non-numeric src/size,
/// non-accepted-length or non-lowercase-hex digest) is a `MalformedValue`
/// error. The fn does not know the entry key, so both `key` and `raw` carry the
/// lossy-decoded raw value bytes.
pub(crate) fn parse_trust_value(raw: &[u8]) -> Result<(TrustSource, u64, String), TrustDbError> {
    let raw_str = String::from_utf8_lossy(raw);
    let malformed = || TrustDbError::MalformedValue {
        key: raw_str.clone().into_owned(),
        raw: raw_str.clone().into_owned(),
    };

    // Split on ASCII space into EXACTLY three fields. `splitn(4, ' ')` lets a
    // 4th-and-beyond field surface as a single trailing element so a four-field
    // value is rejected (the trailing element would be non-empty).
    let mut fields = raw_str.split(' ');
    let (Some(src_field), Some(size_field), Some(hex_field), None) =
        (fields.next(), fields.next(), fields.next(), fields.next())
    else {
        return Err(malformed());
    };

    let src_int: u32 = src_field.parse().map_err(|_| malformed())?;
    let size: u64 = size_field.parse().map_err(|_| malformed())?;

    // Accept MD5 (32) / SHA-1 (40) / SHA-256 (64) / SHA-512 (128) lowercase-hex.
    if !matches!(hex_field.len(), 32 | 40 | 64 | 128)
        || !hex_field
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(malformed());
    }

    Ok((TrustSource::from_int(src_int), size, hex_field.to_owned()))
}

/// Lowercase-hex encode raw digest bytes.
///
/// Kept as a single helper so `stream_hex` and the digest-stability test agree
/// on the encoding. We hex-encode by hand rather than via `{:x}`: in the
/// `digest` 0.11 line the finalize output type moved from `generic-array` to
/// `hybrid-array::Array`, which does not implement `std::fmt::LowerHex`.
fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        // Writing to a String is infallible.
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// Stream a file through digest `D` and return its lowercase-hex digest string.
///
/// `D` must implement `sha2::Digest` (the trait `sha2` re-exports from the
/// `digest` crate). `Md5`, `Sha1`, `Sha256`, and `Sha512` all satisfy this
/// bound when linked from the same `digest` major version.
fn stream_hex<D: sha2::Digest>(file: &mut std::fs::File) -> Result<String, std::io::Error> {
    let mut hasher = D::new();
    let mut buf = [0u8; 8192];
    loop {
        match file.read(&mut buf)? {
            0 => break,
            n => hasher.update(&buf[..n]),
        }
    }
    Ok(to_hex(&hasher.finalize()))
}

/// Verify a single `TrustEntry` against the file currently on disk.
///
/// Reads the file at `entry.path`, computes its size and digest (algorithm
/// selected by the recorded digest length: 32=MD5, 40=SHA-1, 64=SHA-256,
/// 128=SHA-512), and returns a `DiskVerdict` describing the comparison result.
///
/// Order is load-bearing: `Missing` (no file) -> `SizeMismatch` (size differs,
/// checked BEFORE hashing) -> hash compare (`Match` / `HashMismatch`). A file
/// whose size already differs is never hashed.
#[must_use]
pub fn verify_entry(entry: &TrustEntry) -> DiskVerdict {
    let metadata = match std::fs::metadata(&entry.path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return DiskVerdict::Missing,
        Err(e) => return DiskVerdict::ReadError(e.to_string()),
    };

    let actual_size = metadata.len();
    if actual_size != entry.size {
        return DiskVerdict::SizeMismatch {
            recorded: entry.size,
            actual: actual_size,
        };
    }

    // Stream the file in fixed-size chunks: never slurp the whole file into
    // memory (trust DBs reference arbitrarily large binaries). Dispatch the
    // hash algorithm on the recorded digest length.
    let mut file = match std::fs::File::open(&entry.path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return DiskVerdict::Missing,
        Err(e) => return DiskVerdict::ReadError(e.to_string()),
    };
    let actual_hex = match entry.digest.len() {
        32 => stream_hex::<Md5>(&mut file),
        40 => stream_hex::<Sha1>(&mut file),
        64 => stream_hex::<Sha256>(&mut file),
        128 => stream_hex::<Sha512>(&mut file),
        // parse_trust_value already guarantees one of the four; defensive only.
        _ => return DiskVerdict::ReadError("unsupported digest length".into()),
    };
    let actual_hex = match actual_hex {
        Ok(h) => h,
        Err(e) => return DiskVerdict::ReadError(e.to_string()),
    };

    if actual_hex == entry.digest {
        DiskVerdict::Match
    } else {
        DiskVerdict::HashMismatch {
            recorded: entry.digest.clone(),
            actual: actual_hex,
        }
    }
}

/// Read-only handle on a fapolicyd trust DB. Owns the heed `Env`; each query
/// opens its own short-lived read transaction (`Database` is a cheap Copy dbi handle).
#[derive(Debug)]
pub struct TrustDb {
    env: Env,
    db: Database<Bytes, Bytes>,
    path: PathBuf,
}

/// Open a fapolicyd trust DB read-only. Spec section 6.3 shape: `max_dbs(2)`,
/// `READ_ONLY | NO_LOCK`, named sub-database `"trust.db"`. The flag set is
/// load-bearing: omitting `NO_LOCK` would write the daemon's `lock.mdb` on every run.
pub fn open_trustdb_readonly(path: &Path) -> Result<TrustDb, TrustDbError> {
    // SAFETY: read-only mmap of an LMDB dir we open with READ_ONLY|NO_LOCK; the
    // CLI is the only in-process accessor and never writes. heed marks open
    // unsafe due to the mmap aliasing contract (file mutated out-of-process).
    // This is the ONLY unsafe in shipped (non-test) code (unsafe_code = "deny";
    // the cfg(test) write_fixture below carries its own audited allow).
    #[allow(unsafe_code)]
    let env = unsafe {
        EnvOpenOptions::new()
            .max_dbs(2)
            .flags(EnvFlags::READ_ONLY | EnvFlags::NO_LOCK)
            .open(path)?
    };
    let rtxn = env.read_txn()?;
    let db: Database<Bytes, Bytes> = env
        .open_database(&rtxn, Some("trust.db"))?
        .ok_or_else(|| TrustDbError::Missing(path.to_path_buf()))?;
    // LMDB requires commit (not just drop) on the read txn used to open the database
    // handle, so that metadata is synchronized with the global env handle. Without this,
    // subsequent read transactions raise EINVAL (code 22). See heed's RoTxn::commit docs.
    rtxn.commit()?;
    Ok(TrustDb {
        env,
        db,
        path: path.to_path_buf(),
    })
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
            let path = String::from_utf8_lossy(k).into_owned();
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
    pub fn get_entry(&self, p: &str) -> Result<Option<Vec<TrustEntry>>, TrustDbError> {
        let rtxn = self.env.read_txn()?;
        let mut rows: Vec<TrustEntry> = Vec::new();
        // `get_duplicates` yields every value-row stored under the key (or None
        // if the key is absent). For a non-DUPSORT db it still yields the single
        // row, so this is correct for both fixture shapes.
        let Some(iter) = self.db.get_duplicates(&rtxn, p.as_bytes())? else {
            return Ok(None);
        };
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
        if rows.is_empty() {
            Ok(None)
        } else {
            Ok(Some(rows))
        }
    }

    /// True iff `p` is an exact key in the trust DB.
    #[must_use]
    pub fn contains_path(&self, p: &str) -> bool {
        // A txn-open failure is intentionally treated as "not in DB" (fail-safe:
        // the trust-DB lints warn on an absent path rather than erroring out).
        let Ok(rtxn) = self.env.read_txn() else {
            return false;
        };
        matches!(self.db.get(&rtxn, p.as_bytes()), Ok(Some(_)))
    }

    /// All distinct keys (paths). DUPSORT yields one row per value; consecutive
    /// duplicate keys are collapsed.
    pub fn iter_paths(&self) -> Result<Vec<String>, TrustDbError> {
        let rtxn = self.env.read_txn()?;
        let mut out: Vec<String> = Vec::new();
        for item in self.db.iter(&rtxn)? {
            let (k, _v) = item?;
            let key = String::from_utf8_lossy(k).into_owned();
            if out.last().map(String::as_str) != Some(key.as_str()) {
                out.push(key);
            }
        }
        Ok(out)
    }
}

/// Weak hash algorithm implied by a hex digest's length, if any.
///
/// 32 hex chars = MD5, 40 = SHA1 (both cryptographically weak). 64 (SHA256),
/// 128 (SHA512), and any other length return `None`. Shared by the fapd-W11
/// surfaces: rule `filehash=`/`sha256hash=` value validation, the trust-DB
/// weak-digest lint, and the `trustdb list` report annotation. The trust DB
/// stores already-length-validated hex (32/40/64/128); rule values are
/// hex-validated by fapd-E02 before this is consulted for the weak/strong split.
#[must_use]
pub fn weak_digest_algorithm(digest: &str) -> Option<&'static str> {
    // Digests are ASCII hex, so byte length (O(1)) equals char count.
    match digest.len() {
        32 => Some("MD5"),
        40 => Some("SHA1"),
        _ => None,
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
        DiskVerdict, TrustDbError, TrustEntry, TrustSource, open_trustdb_readonly,
        parse_trust_value, verify_entry,
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

    /// `open_trustdb_readonly` must NOT create a `lock.mdb` file. `NO_LOCK` is
    /// load-bearing (spec section 6.3): opening the daemon's trust DB read-only
    /// must never write the daemon's lock file. This kills the
    /// `READ_ONLY | NO_LOCK` -> `&` mutant: with `&` the flags collapse to `0x0`
    /// (`READ_ONLY`=`0x20000`, `NO_LOCK`=`0x400000` are disjoint bits), dropping
    /// `NO_LOCK` so `LMDB` creates `lock.mdb` on open, failing the assertion below.
    #[test]
    fn open_does_not_create_lock_mdb() {
        let tmp = tempdir().expect("tempdir");
        write_fixture(tmp.path(), &["/usr/bin/ls"]);
        // write_fixture opens RW without NO_LOCK, so it may have created lock.mdb;
        // remove it so we observe ONLY what open_trustdb_readonly does.
        let lock = tmp.path().join("lock.mdb");
        let _ = std::fs::remove_file(&lock);
        let _db = open_trustdb_readonly(tmp.path()).expect("open ro");
        assert!(
            !lock.exists(),
            "open_trustdb_readonly created lock.mdb; NO_LOCK must be set (spec 6.3)"
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
