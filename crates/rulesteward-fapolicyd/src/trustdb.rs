//! fapolicyd trust-DB reader (heed, read-only).

use std::path::{Path, PathBuf};

use heed::types::Bytes;
use heed::{Database, Env, EnvFlags, EnvOpenOptions};
use serde::Serialize;

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
    /// `SRC_DEB = 3`; any other value maps to `Unknown`). The exact mapping is
    /// filled by the 3d impl pipeline.
    #[must_use]
    pub fn from_int(_n: u32) -> Self {
        todo!() // stub: filled by 3d impl pipeline
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
/// Returns `(source, size, sha256_hex)` on success. Body filled by the 3d
/// impl pipeline; the parse logic belongs to fapolicyd's on-disk format.
#[allow(dead_code)] // stub: called by iter_entries/get_entry once filled by 3d impl pipeline
pub(crate) fn parse_trust_value(_raw: &[u8]) -> Result<(TrustSource, u64, String), TrustDbError> {
    todo!() // stub: filled by 3d impl pipeline
}

/// Verify a single `TrustEntry` against the file currently on disk.
///
/// Reads the file at `entry.path`, computes its size and SHA-256, and
/// returns a `DiskVerdict` describing the comparison result. Body filled
/// by the 3d impl pipeline.
#[must_use]
pub fn verify_entry(_entry: &TrustEntry) -> DiskVerdict {
    todo!() // stub: filled by 3d impl pipeline
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
    /// Each distinct key may have multiple value rows (fapolicyd uses DUPSORT).
    /// Body filled by the 3d impl pipeline.
    pub fn iter_entries(&self) -> Result<Vec<TrustEntry>, TrustDbError> {
        todo!() // stub: filled by 3d impl pipeline
    }

    /// Return all `TrustEntry` rows for the given absolute path, or `None` if
    /// the path is not present in the DB. Body filled by the 3d impl pipeline.
    pub fn get_entry(&self, _p: &str) -> Result<Option<Vec<TrustEntry>>, TrustDbError> {
        todo!() // stub: filled by 3d impl pipeline
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

#[cfg(test)]
mod tests {
    use super::write_fixture;
    use super::{TrustDbError, open_trustdb_readonly};
    use tempfile::tempdir;

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
}
