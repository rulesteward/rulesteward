//! fapolicyd trust-DB reader (heed, read-only).

use std::io::Read as _;
use std::path::{Path, PathBuf};

use heed::types::Bytes;
use heed::{Database, Env, EnvFlags, EnvOpenOptions};
use serde::Serialize;
use sha2::{Digest as _, Sha256};

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
    pub sha256: String,
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

/// Parse the raw bytes of a trust-DB value (`"<src_int> <size> <sha256_hex>"`).
///
/// Returns `(source, size, sha256_hex)` on success. The value must be EXACTLY
/// three ASCII-space-separated fields: a u32 source integer, a u64 size, and a
/// 64-char lowercase-hex SHA-256 digest. Any deviation (wrong field count,
/// non-numeric src/size, non-64-char or non-lowercase-hex digest) is a
/// `MalformedValue` error. The fn does not know the entry key, so both `key`
/// and `raw` carry the lossy-decoded raw value bytes.
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

    // Exactly 64 lowercase-hex chars.
    if hex_field.len() != 64
        || !hex_field
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(malformed());
    }

    Ok((TrustSource::from_int(src_int), size, hex_field.to_owned()))
}

/// Verify a single `TrustEntry` against the file currently on disk.
///
/// Reads the file at `entry.path`, computes its size and SHA-256, and
/// returns a `DiskVerdict` describing the comparison result.
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

    // Stream the file through SHA-256 in fixed-size chunks: never slurp the
    // whole file into memory (trust DBs reference arbitrarily large binaries).
    let mut file = match std::fs::File::open(&entry.path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return DiskVerdict::Missing,
        Err(e) => return DiskVerdict::ReadError(e.to_string()),
    };
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        match file.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => hasher.update(&buf[..n]),
            Err(e) => return DiskVerdict::ReadError(e.to_string()),
        }
    }
    let digest = hasher.finalize();
    // Lowercase hex via a {:02x} loop (no `hex` crate dependency).
    let mut actual_hex = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        // Writing to a String is infallible.
        let _ = write!(actual_hex, "{byte:02x}");
    }

    if actual_hex == entry.sha256 {
        DiskVerdict::Match
    } else {
        DiskVerdict::HashMismatch {
            recorded: entry.sha256.clone(),
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
            let (source, size, sha256) = parse_trust_value(v)?;
            out.push(TrustEntry {
                path,
                source,
                size,
                sha256,
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
            let (source, size, sha256) = parse_trust_value(v)?;
            rows.push(TrustEntry {
                path: p.to_owned(),
                source,
                size,
                sha256,
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
mod tests {
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
        let got = format!("{:x}", h.finalize());
        assert_eq!(
            got, KNOWN_SHA256,
            "KNOWN_SHA256 constant must equal the sha2-crate digest of KNOWN_BYTES"
        );
        assert_eq!(
            KNOWN_BYTES.len() as u64,
            KNOWN_SIZE,
            "KNOWN_SIZE must equal the byte length of KNOWN_BYTES"
        );
        // Defend the "exactly 64 lowercase hex" invariant the parser relies on.
        assert_eq!(
            KNOWN_SHA256.len(),
            64,
            "sha256 hex must be exactly 64 chars"
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
    fn parse_trust_value_short_hex_is_malformed() {
        // 63 hex chars: one short of the required 64.
        let short = &KNOWN_SHA256[..63];
        let raw = format!("1 12345 {short}").into_bytes();
        assert!(
            matches!(
                parse_trust_value(&raw),
                Err(TrustDbError::MalformedValue { .. })
            ),
            "63-char hex must be MalformedValue, got {:?}",
            parse_trust_value(&raw)
        );
    }

    #[test]
    fn parse_trust_value_long_hex_is_malformed() {
        // 65 hex chars: one over the required 64.
        let long = format!("{KNOWN_SHA256}a");
        let raw = format!("1 12345 {long}").into_bytes();
        assert!(
            matches!(
                parse_trust_value(&raw),
                Err(TrustDbError::MalformedValue { .. })
            ),
            "65-char hex must be MalformedValue, got {:?}",
            parse_trust_value(&raw)
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
        /// 64-char lowercase-hex string, `parse_trust_value` recovers the same
        /// fields. The hex strategy emits exactly 64 chars from [0-9a-f].
        #[test]
        fn parse_trust_value_roundtrip_prop(
            src_int in 0u32..=3,
            size in any::<u64>(),
            hex in proptest::collection::vec(
                proptest::sample::select(b"0123456789abcdef".as_slice()),
                64..=64,
            ),
        ) {
            let hex: String = hex.into_iter().map(char::from).collect();
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
                e.sha256, KNOWN_SHA256,
                "each row's sha256 field must round-trip from the fixture value"
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
            sha256: KNOWN_SHA256.to_owned(),
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
            sha256: wrong.clone(),
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
            sha256: bogus_hash,
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
            sha256: KNOWN_SHA256.to_owned(),
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
            sha256: KNOWN_SHA256.to_owned(),
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
            sha256: KNOWN_SHA256.to_owned(),
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
}
