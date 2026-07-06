//! LMDB environment open path for the fapolicyd trust-DB reader (the crate's
//! only `unsafe` code), the `fapolicyd.conf` `integrity=` gating mode, and the
//! trust-DB key-size constants.

use std::path::Path;

use heed::types::Bytes;
use heed::{Database, Env, EnvFlags, EnvOpenOptions};
use serde::Serialize;

use super::{DiskVerdict, TrustDb, TrustDbError};

/// Which `fapolicyd.conf` integrity check governs trust-DB drift enforcement.
///
/// The gating key is `integrity` in `fapolicyd.conf` (values: `none` | `size` |
/// `ima` | `sha256`; absent key or unrecognised value maps to `None`). Controls
/// which `DiskVerdict` variants are *enforced* (flip the exit code and the
/// `enforced` flag on the row) vs merely *visible* (shown with an annotation but
/// exit-code clean).
///
/// Enforcement table (the overall contract; `enforces` implements the four
/// `DiskVerdict` rows; `NotInDb` is a `CheckVerdict`-only state the CLI layer
/// always enforces, shown here for completeness but not an `enforces` input):
///
/// | Verdict           | none  | size  | ima   | sha256 |
/// |-------------------|-------|-------|-------|--------|
/// | `SizeMismatch`    | no    | yes   | yes   | yes    |
/// | `HashMismatch`    | no    | no    | no    | yes    |
/// | `Missing`         | yes   | yes   | yes   | yes    |
/// | `ReadError`       | yes   | yes   | yes   | yes    |
/// | `NotInDb`         | yes   | yes   | yes   | yes    |
///
/// When NO conf file is found at all, the mode is treated as `sha256` (STRICT).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum IntegrityMode {
    /// `integrity = none` (or key absent in a found conf): no hash/size checking.
    None,
    /// `integrity = size`: only size mismatches are enforced.
    Size,
    /// `integrity = ima`: IMA xattr-hash checking; size mismatches enforced too.
    Ima,
    /// `integrity = sha256`: full hash enforcement (trust-DB digest).
    Sha256,
}

impl IntegrityMode {
    /// Parse the trimmed value string from `fapolicyd.conf` (already extracted by
    /// `conf_value`). Exact matches only: `"none"` -> `None`, `"size"` -> `Size`,
    /// `"ima"` -> `Ima`, `"sha256"` -> `Sha256`. Any other string (including
    /// whitespace-only, garbage, or unknown variant) maps to `IntegrityMode::None`
    /// (daemon default when the key is absent). A trailing inline `#` is part of
    /// the literal value (per `conf_value` semantics); a raw value of
    /// e.g. `"sha256 # important"` does NOT match `"sha256"` and returns `None`.
    ///
    /// Pass `None` when the key is absent from the conf (daemon default: `None`).
    #[must_use]
    pub fn from_conf_value(v: Option<&str>) -> Self {
        match v {
            Some("size") => Self::Size,
            Some("ima") => Self::Ima,
            Some("sha256") => Self::Sha256,
            // "none", absent key, unknown value, whitespace -> daemon default None.
            _ => Self::None,
        }
    }

    /// The canonical lowercase `fapolicyd.conf` `integrity=` keyword for this
    /// mode (`none` / `size` / `ima` / `sha256`).
    ///
    /// Inverse of [`from_conf_value`](Self::from_conf_value) for the four
    /// recognised keywords, so a round-trip
    /// `from_conf_value(Some(m.as_keyword())) == m` holds. The single source of
    /// truth for the keyword spelling shared by the CLI's `--integrity` header
    /// and its "not enforced under integrity=<X>" annotations.
    #[must_use]
    pub fn as_keyword(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Size => "size",
            Self::Ima => "ima",
            Self::Sha256 => "sha256",
        }
    }

    /// True iff `verdict` is enforced under this integrity mode.
    ///
    /// Enforcement table (grounded in `fapolicyd.conf(5)` and the fapolicyd
    /// daemon's trust-verification logic):
    ///
    /// | Verdict           | None  | Size  | Ima   | Sha256 |
    /// |-------------------|-------|-------|-------|--------|
    /// | `SizeMismatch`    | no    | yes   | yes   | yes    |
    /// | `HashMismatch`    | no    | no    | no    | yes    |
    /// | `Missing`         | yes   | yes   | yes   | yes    |
    /// | `ReadError`       | yes   | yes   | yes   | yes    |
    /// | `Match`           | no    | no    | no    | no     |
    ///
    /// `NotInDb` is a `CheckVerdict`-only state handled at the CLI layer and is
    /// always enforced there; this function is never called for it.
    #[must_use]
    pub fn enforces(&self, verdict: &DiskVerdict) -> bool {
        match verdict {
            // A clean match is never a divergence; enforcement is irrelevant.
            DiskVerdict::Match => false,
            // Missing and ReadError are always enforced regardless of mode.
            DiskVerdict::Missing | DiskVerdict::ReadError(_) => true,
            // SizeMismatch: enforced under Size, Ima, and Sha256 but NOT under None.
            DiskVerdict::SizeMismatch { .. } => {
                matches!(self, Self::Size | Self::Ima | Self::Sha256)
            }
            // HashMismatch: enforced ONLY under Sha256 (IMA checks the xattr hash,
            // not the trust-DB digest, so a DB hash mismatch is not enforced under Ima).
            DiskVerdict::HashMismatch { .. } => matches!(self, Self::Sha256),
        }
    }
}

/// Length in bytes of a `path_to_hash` hashed key: a lowercase-hex SHA-512
/// digest is `SHA512_LEN(64) * 2 = 128` chars. fapolicyd stores the key with a
/// trailing C-string NUL (`mv_size = (SHA512_LEN * 2) + 1`), so the raw key
/// bytes from LMDB are 128 hex + one NUL.
pub(super) const PATH_TO_HASH_HEX_LEN: usize = 128;

/// LMDB default maximum key size (`MDB_maxkeysize`). Paths longer than this
/// (in bytes) are stored under a `path_to_hash` hashed key rather than the
/// literal path (database.c:667-683). Corresponds to the `MDB_maxkeysize`
/// compile-time default in the vendored LMDB library fapolicyd bundles.
pub(super) const MDB_MAX_KEY_SIZE: usize = 511;

/// The LMDB key byte-forms a `path_to_hash` long-path entry may be stored under,
/// in lookup-priority order. fapolicyd writes the hashed key as a C string -
/// 128 lowercase-hex + a trailing NUL (`mv_size = (SHA512_LEN*2)+1` = 129;
/// database.c `trust_db_key_init_with_max`, used for BOTH write and read) - so a
/// keyed lookup MUST try that 129-byte form to match a real daemon-written DB.
/// The bare 128-hex form is the other shape [`validate_trust_key`] accepts on the
/// iter side, tried second so keyed lookup finds whatever iteration surfaces.
pub(super) fn hashed_key_forms(hash: &str) -> [Vec<u8>; 2] {
    let mut with_nul = Vec::with_capacity(hash.len() + 1);
    with_nul.extend_from_slice(hash.as_bytes());
    with_nul.push(0);
    [with_nul, hash.as_bytes().to_vec()]
}

/// Open a fapolicyd trust DB read-only, PREVENTING torn reads on a writable
/// trust-DB directory and DETECTING them on the fallback path (#291/#317).
///
/// LAYER 1 - PREVENT (default): open `READ_ONLY` WITH the LMDB lock table
/// (i.e. WITHOUT `NO_LOCK`). Participating in the lock table gives the reader a
/// real reader slot, so the single LMDB writer (the fapolicyd daemon or
/// `fapolicyd-cli --file update`) cannot free and reuse the pages this reader is
/// iterating: the torn read that issue #291 reproduced empirically CANNOT
/// happen. This DOES create the daemon's `lock.mdb` in a writable directory -
/// an intentional change from the prior `NO_LOCK`-always behavior, and the cost
/// of correctness.
///
/// FALLBACK: a `READ_ONLY` (locked) env still calls `mdb_env_setup_locks`, which
/// `goto fail`s on a permission error opening/creating the lock file (it
/// tolerates ONLY EROFS, a read-only mount, as a lockless success it handles
/// internally). So on a non-writable trust-DB directory the locked open returns
/// `EACCES`/`EPERM` (or `EROFS` if the lock file specifically is unwritable),
/// which heed surfaces as `Error::Io(io::Error)` with a
/// `PermissionDenied`/`ReadOnlyFilesystem` kind (heed maps a non-MDB errno via
/// `MdbError::Other(e) -> Error::Io(from_raw_os_error(e))`; LMDB errno 13 ==
/// "Permission denied"). We catch exactly that and fall back to the legacy
/// `READ_ONLY | NO_LOCK` open so a read-only-mounted or restricted trust DB is
/// still readable. Any OTHER open error (missing dir, corrupt DB, wrong type) is
/// a genuine failure and propagates unchanged.
///
/// LAYER 2 - DETECT (always-on, both paths): `parse_trust_value` + key
/// validation reject a torn/corrupt record as a clean `TrustDbError::TornRead`
/// (see its docs), so the `NO_LOCK` fallback path - where prevention is
/// impossible - degrades a SURVIVABLE torn read into a typed error instead of a
/// silently-corrupt `Ok`. Detection is only a best-effort FLOOR: it is
/// probabilistic (a torn window can stay shape-valid) AND it cannot catch a
/// C-level LMDB abort (the harness observed a `NO_LOCK` reader under a live
/// writer SIGABRT inside `mdb_cursor_sibling`, which no Rust check can convert
/// to a `Result`). Layer 1 is the only GUARANTEE; it is why the fallback is
/// last-resort and loudly warned about.
pub fn open_trustdb_readonly(path: &Path) -> Result<TrustDb, TrustDbError> {
    // LAYER 1: try the locked read-only open first.
    match open_env_readonly(path, false) {
        Ok(env) => finish_open(env, path),
        Err(TrustDbError::Open(heed::Error::Io(io_err)))
            if matches!(
                io_err.kind(),
                std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::ReadOnlyFilesystem
            ) =>
        {
            // The lock table could not be set up (read-only mount or restricted
            // permissions). Fall back to the lockless `NO_LOCK` reader.
            //
            // WHY THIS IS DANGEROUS (#291/#317, empirically established by the
            // contention harness): a `NO_LOCK` reader takes NO reader-table slot,
            // so a LIVE writer (the fapolicyd daemon / `fapolicyd-cli --file
            // update`) can free and reuse the pages we are iterating. That does
            // NOT merely corrupt a value: it was observed to corrupt LMDB's OWN
            // B-tree cursor traversal and ABORT THE PROCESS via an internal C
            // assertion (SIGABRT: `IS_BRANCH(...) failed in mdb_cursor_sibling`).
            // A C-level abort cannot be caught in Rust, so Layer-2 detection is
            // only a best-effort floor for SURVIVABLE torn values - it CANNOT
            // make this path safe. Only the Layer-1 lock-table prevention above
            // is safe under a live writer, which is why this is fallback-only.
            //
            // Warn on stderr ONLY (never stdout, so the JSON/CSV machine contract
            // is untouched) and tell the operator how to get the safe path back.
            eprintln!(
                "rulesteward: warning: trust DB opened WITHOUT reader-lock \
                 participation (the directory is read-only or not writable). \
                 This NO_LOCK fallback is UNSAFE against a live fapolicyd daemon: \
                 a concurrent write may yield a read error OR abort this process. \
                 Re-run with write access to the trust-DB directory, or point at a \
                 static/quiesced copy of the trust DB, to use the safe locked reader."
            );
            let env = open_env_readonly(path, true)?;
            finish_open(env, path)
        }
        Err(other) => Err(other),
    }
}

/// Open the LMDB env at `path` read-only. When `no_lock` is true, add
/// `EnvFlags::NO_LOCK` (the lockless fallback that cannot prevent torn reads);
/// when false, participate in the lock table (the prevention path).
///
/// Factored out of `open_trustdb_readonly` so the locked (Layer 1) and lockless
/// (fallback) paths share one audited `unsafe` open site.
fn open_env_readonly(path: &Path, no_lock: bool) -> Result<Env, TrustDbError> {
    let flags = if no_lock {
        EnvFlags::READ_ONLY | EnvFlags::NO_LOCK
    } else {
        EnvFlags::READ_ONLY
    };
    // SAFETY: read-only mmap of an LMDB dir. heed marks `open` unsafe due to the
    // mmap aliasing contract (the file may be mutated out-of-process). On the
    // LOCKED path (no_lock = false) we hold a reader-table slot so the writer
    // cannot reuse our pages; on the NO_LOCK fallback Layer-2 detection guards
    // the aliasing risk. This is the ONLY unsafe in shipped (non-test) code
    // (unsafe_code = "deny"; the cfg(test) fixtures carry their own audited allow).
    #[allow(unsafe_code)]
    let env = unsafe { EnvOpenOptions::new().max_dbs(2).flags(flags).open(path)? };
    Ok(env)
}

/// Open the named `"trust.db"` sub-database on an already-opened env and build
/// the `TrustDb` handle. Shared by the locked and lockless open paths.
fn finish_open(env: Env, path: &Path) -> Result<TrustDb, TrustDbError> {
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

/// TEST-ONLY: open a fapolicyd trust DB read-only forcing the legacy
/// `READ_ONLY | NO_LOCK` path, bypassing the Layer-1 lock-table prevention.
///
/// This exists so the #291 contention harness can DETERMINISTICALLY drive the
/// torn-read-prone fallback branch (and assert the Layer-2 clean-error
/// behavior) on any platform, without resorting to chmod / EROFS / uid tricks
/// in CI. It is gated behind `cfg(any(test, feature = "test-fixtures"))`, so the
/// shipped binary never exposes a way to opt out of the prevention path.
#[cfg(any(test, feature = "test-fixtures"))]
pub fn open_trustdb_readonly_nolock(path: &Path) -> Result<TrustDb, TrustDbError> {
    let env = open_env_readonly(path, true)?;
    finish_open(env, path)
}
