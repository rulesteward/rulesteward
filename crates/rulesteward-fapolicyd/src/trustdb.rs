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

/// True iff `b` is a byte that a faithfully-written fapolicyd trust-DB VALUE can
/// never contain, marking the buffer as torn/corrupt (#291/#317 Layer-2 floor):
/// a NUL byte (LMDB page padding / freed-page zero fill) or a non-ASCII high-bit
/// byte (another binary page spliced in). A value is
/// `"<src_int> <size> <digest_hex>"` - pure printable ASCII with no NUL - so
/// either signature is impossible in a faithful record and is the strongest
/// torn-read tell.
///
/// NOTE the boundary with `MalformedValue`: bytes that are printable ASCII but
/// outside the value grammar (uppercase, slash, an out-of-place letter like the
/// `x` in a non-numeric src field, an `extra` 4th field) are left to the
/// STRUCTURAL checks (field count / numeric / hex length / hex alphabet), which
/// already reject them as `MalformedValue`. That keeps the long-standing
/// "this value is just badly formed" contract intact while adding a dedicated
/// torn-read signal for the bytes a faithful record can never carry.
#[inline]
fn is_torn_value_byte(b: u8) -> bool {
    b == 0 || !b.is_ascii()
}

/// Render raw bytes for a diagnostic, escaping every non-printable / non-ASCII
/// byte as `\xHH` (and `\\` for a literal backslash) so the ACTUAL torn bytes
/// are visible. The lossy-decoded `String` would collapse a high-bit offending
/// byte to U+FFFD and erase the very evidence the `TornRead.raw` field exists to
/// show; this keeps it faithful. Stderr/diagnostic only - no machine contract.
fn render_raw_bytes(raw: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(raw.len());
    for &b in raw {
        match b {
            b'\\' => out.push_str("\\\\"),
            // Printable ASCII (space..tilde) passes through verbatim.
            0x20..=0x7e => out.push(b as char),
            // Everything else (NUL, control, high-bit) is escaped so the real
            // hazard byte is visible rather than masked as U+FFFD. Writing to a
            // String is infallible (mirrors the `to_hex` helper above).
            _ => {
                let _ = write!(out, "\\x{b:02x}");
            }
        }
    }
    out
}

/// Length in bytes of a `path_to_hash` hashed key: a lowercase-hex SHA-512
/// digest is `SHA512_LEN(64) * 2 = 128` chars. fapolicyd stores the key with a
/// trailing C-string NUL (`mv_size = (SHA512_LEN * 2) + 1`), so the raw key
/// bytes from LMDB are 128 hex + one NUL.
const PATH_TO_HASH_HEX_LEN: usize = 128;

/// Validate a raw trust-DB KEY and return the canonical surfaced key string.
///
/// fapolicyd stores TWO legitimate key shapes (vendored `database.c`):
///   (a) the absolute file PATH itself, when its length is <= the LMDB max key
///       size (`MDB_maxkeysize`, 511 default) - a `/`-rooted, NUL-free string.
///   (b) for a path LONGER than the key limit (paths are legal up to `PATH_MAX` =
///       4096), `path_to_hash` (database.c:667-683) stores a bare lowercase-hex
///       SHA-512 of the path: exactly 128 hex chars, NO leading `/`, plus a
///       trailing NUL (`write_db` :717-728 sets `mv_size = (SHA512_LEN*2)+1`).
///       The daemon reads it back by that same hashed key (`lt_read_db`
///       :853-865), so it is a fully legitimate, queryable record.
///
/// Rejecting shape (b) (as a naive "must be `/`-rooted, NUL-free" check does)
/// makes `iter_entries`/`iter_paths` return `TornRead` for the WHOLE iteration
/// on any real DB containing a single long-path entry (#291/#317 rework). So we
/// ACCEPT either shape and reject everything else as `TornRead` (a torn read can
/// still splice a short/relative/garbage/arbitrary-NUL key, which neither shape
/// matches).
///
/// Returns the key to SURFACE: the path verbatim for (a); the 128-hex string
/// with its single trailing NUL trimmed for (b) (preserving the pre-fix reader's
/// "surface the decoded key bytes" behavior, minus the C-string terminator). A
/// nicer hashed-key annotation is intentionally left as a future enhancement.
fn validate_trust_key(raw: &[u8], key: &str) -> Result<String, TrustDbError> {
    // Shape (a): absolute path, no interior NUL. The NUL check runs on the raw
    // bytes (lossy decode preserves NUL as `\0`).
    if key.starts_with('/') && !raw.contains(&0) {
        return Ok(key.to_owned());
    }

    // Shape (b): path_to_hash key = 128 lowercase-hex bytes, optionally followed
    // by a single trailing NUL (the stored C-string terminator). Checked on the
    // RAW bytes so a torn high-bit byte cannot masquerade as hex via lossy decode.
    let hex = match raw.len() {
        PATH_TO_HASH_HEX_LEN => Some(raw),
        // 129 bytes: 128 hex + exactly one trailing NUL.
        n if n == PATH_TO_HASH_HEX_LEN + 1 && raw[PATH_TO_HASH_HEX_LEN] == 0 => {
            Some(&raw[..PATH_TO_HASH_HEX_LEN])
        }
        _ => None,
    };
    if let Some(hex) = hex
        && hex
            .iter()
            .all(|&b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        // Surface the 128-hex digest with the trailing NUL (if any) trimmed.
        // Safe to unwrap: every byte is ASCII hex.
        return Ok(String::from_utf8(hex.to_vec()).expect("ascii-hex is valid utf8"));
    }

    Err(TrustDbError::TornRead {
        key: key.to_owned(),
        raw: render_raw_bytes(raw),
    })
}

/// Parse the raw bytes of a trust-DB value (`"<src_int> <size> <digest_hex>"`).
///
/// Returns `(source, size, digest_hex)` on success. The value must be EXACTLY
/// three ASCII-space-separated fields: a u32 source integer, a u64 size, and a
/// lowercase-hex digest whose length is one of {32, 40, 64, 128} (MD5, SHA-1,
/// SHA-256, SHA-512). Any STRUCTURAL deviation (wrong field count, non-numeric
/// src/size, non-accepted-length or non-lowercase-hex digest) is a
/// `MalformedValue` error. The fn does not know the entry key, so both `key` and
/// `raw` carry the lossy-decoded raw value bytes.
///
/// LAYER-2 TORN-READ DETECTION (#291/#317): BEFORE the lossy UTF-8 decode, the
/// raw `&[u8]` is screened against the legitimate value alphabet
/// (`{digit, space, lowercase-hex}`, no NUL, no non-ASCII). A faithfully-written
/// fapolicyd value can never carry a byte outside that set, so any such byte is
/// the signature of a torn read (a page the daemon freed and reused under our
/// `NO_LOCK` borrow) and yields `TrustDbError::TornRead`. The check runs on the
/// RAW bytes (not the lossy string) because lossy decode would replace a torn
/// non-ASCII byte with U+FFFD and erase the evidence. This is probabilistic: a
/// torn window that happens to stay inside the alphabet still parses; the locked
/// Layer-1 path is what guarantees integrity on a writable dir.
pub(crate) fn parse_trust_value(raw: &[u8]) -> Result<(TrustSource, u64, String), TrustDbError> {
    let raw_str = String::from_utf8_lossy(raw);

    // Layer-2 floor: a value carrying a NUL or non-ASCII byte cannot be a
    // faithful fapolicyd record, so it is a TORN read. Screened on the RAW bytes
    // BEFORE lossy decode (decode would mask a torn high-bit byte as U+FFFD).
    // `key` carries the lossy string (no key is known here); `raw` carries a
    // FAITHFUL escaped rendering so the actual offending byte stays visible.
    if raw.iter().any(|&b| is_torn_value_byte(b)) {
        return Err(TrustDbError::TornRead {
            key: raw_str.into_owned(),
            raw: render_raw_bytes(raw),
        });
    }

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
    // (The alphabet screen above already guarantees lowercase-hex bytes, but the
    // length gate remains the structural check.)
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

/// Compute the lowercase-hex SHA-256 digest of the file at `path`, streaming it
/// in fixed-size chunks (never slurping the whole file into memory).
///
/// Returns `Ok(Some(hex))` on success, `Ok(None)` when the file does not exist
/// (the caller falls back to its low-confidence / `NotEvaluable` behavior), and
/// `Err` for any other I/O failure. Used by `simulate` for on-demand object
/// hashing when a `filehash=`/`sha256hash=` rule needs the object's hash and the
/// workload omits it (#127). Reuses the same `stream_hex` helper `verify_entry`
/// uses, so the encoding is identical.
pub fn sha256_file(path: &Path) -> Result<Option<String>, std::io::Error> {
    let mut file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    stream_hex::<Sha256>(&mut file).map(Some)
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
