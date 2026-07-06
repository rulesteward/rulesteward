//! Hashing helpers for the fapolicyd trust-DB reader: hex encoding, streaming
//! file digests, on-disk entry verification, and weak-digest classification.

use md5::Md5;
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use std::io::Read as _;
use std::path::Path;

use super::{DiskVerdict, TrustEntry};

/// Compute the `path_to_hash` lookup key for `path`: the lowercase-hex SHA-512
/// of the path bytes (no trailing NUL in the hash input), exactly as
/// `database.c:path_to_hash` (667-683) does. Returns the key as an owned
/// `String` of 128 lowercase-hex chars.
///
/// This ONLY hashes the bytes of the path string itself - the stored LMDB key
/// has a trailing C-string NUL (`mv_size = (SHA512_LEN*2)+1`; see
/// trustdb.rs:243-271), but the NUL is NOT part of the hash input per the
/// vendored source (the digest is over the raw path chars, not the C-string).
pub(super) fn path_to_hash(path: &str) -> String {
    use sha2::Digest as _;
    let mut h = Sha512::new();
    h.update(path.as_bytes());
    to_hex(&h.finalize())
}

/// Lowercase-hex encode raw digest bytes.
///
/// Kept as a single helper so `stream_hex` and the digest-stability test agree
/// on the encoding. We hex-encode by hand rather than via `{:x}`: in the
/// `digest` 0.11 line the finalize output type moved from `generic-array` to
/// `hybrid-array::Array`, which does not implement `std::fmt::LowerHex`.
pub(super) fn to_hex(bytes: &[u8]) -> String {
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
