//! Trust-DB key/value decoding: torn-read byte-level screening, raw-byte
//! diagnostic rendering, key-shape validation, value parsing, and the
//! `trust_src_t` source-integer mapping.

use serde::Serialize;

use super::TrustDbError;
use super::env::PATH_TO_HASH_HEX_LEN;

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
pub(super) fn render_raw_bytes(raw: &[u8]) -> String {
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
pub(super) fn validate_trust_key(raw: &[u8], key: &str) -> Result<String, TrustDbError> {
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
