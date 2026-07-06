//! The typed `FieldValue` interpretation of a `-F` value string, and the
//! base-0 numeric parsing it rests on. Split out of `value.rs` (#438); see the
//! parent `value` module doc for the overall design.

use rulesteward_core::parse_base0_u64 as parse_u64_base0;

use crate::lints::field_type::FieldType;

/// The typed interpretation of a `-F` value string, under its field's type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldValue {
    /// The uid/gid/sessionid "unset" sentinel: `-1`, `4294967295`, or `unset` on
    /// a [`FieldType::Uid`]/[`FieldType::Gid`]/[`FieldType::SessionId`] field.
    UidGidUnset,
    /// A concrete value on the SIGNED integer line (`exit`, which takes a
    /// negative errno).
    Signed(i64),
    /// A concrete value on the UNSIGNED integer line (concrete uid/gid, and all
    /// unsigned `Numeric`/`NumericEqNe` fields).
    Unsigned(u64),
    /// Not numerically interpretable for folding or intervals (username, errno
    /// symbol, a hex literal on a string-typed field, any string/special-typed
    /// field, a malformed or out-of-range number). Compares only by exact
    /// spelling.
    Opaque,
}

impl FieldValue {
    /// The concrete integer position of this value on the `i128` number line,
    /// or `None` for the sentinel and opaque values (which have no single
    /// orderable position). `i128` holds every `u64` and `i64` with room for
    /// the `+/-1` boundary adjustments without overflow.
    ///
    /// `pub(super)`: called by `interval()` in the sibling `compare` module.
    pub(super) fn position(self) -> Option<i128> {
        match self {
            FieldValue::Signed(n) => Some(i128::from(n)),
            FieldValue::Unsigned(n) => Some(i128::from(n)),
            FieldValue::UidGidUnset | FieldValue::Opaque => None,
        }
    }
}

/// Signed base-0 parse for `exit` (#229): an optional leading `-` on a
/// [`parse_u64_base0`] magnitude (so `-0x10` is -16). The magnitude must fit
/// `i64`, else `None` (conservative).
fn parse_i64_base0(s: &str) -> Option<i64> {
    if let Some(mag) = s.strip_prefix('-') {
        let m = parse_u64_base0(mag)?;
        // i64::MIN has magnitude 2^63 = i64::MAX + 1, which does not fit i64;
        // handle it explicitly so `exit=-9223372036854775808` classifies as
        // Signed rather than falling through to Opaque (#270 AUD-2).
        if m == (i64::MAX as u64) + 1 {
            Some(i64::MIN)
        } else {
            i64::try_from(m).ok().map(|n| -n)
        }
    } else {
        i64::try_from(parse_u64_base0(s)?).ok()
    }
}

/// Interpret `raw` as a [`FieldValue`] under `ft`. See the parent `value`
/// module doc for the uid/gid sentinel rule and the conservative-opaque
/// fallback.
#[must_use]
pub fn classify(ft: FieldType, raw: &str) -> FieldValue {
    let v = raw.trim();
    match ft {
        FieldType::Uid | FieldType::Gid | FieldType::SessionId => {
            if v.eq_ignore_ascii_case("unset") || v == "-1" {
                return FieldValue::UidGidUnset;
            }
            // libaudit parses uid/gid/sessionid with strtoul base 0 (#229):
            // hex/octal/decimal all accepted. Narrow to u32 (anything above is
            // not a valid id -> opaque); u32::MAX is the sentinel; usernames and
            // malformed numbers fail the parse and stay opaque. sessionid shares
            // this u32 unset sentinel but has no name resolution (#270 AUD-3).
            match parse_u64_base0(v).and_then(|n| u32::try_from(n).ok()) {
                Some(u32::MAX) => FieldValue::UidGidUnset,
                Some(n) => FieldValue::Unsigned(u64::from(n)),
                None => FieldValue::Opaque,
            }
        }
        // exit takes a negative errno: signed, base-0 magnitude (#229).
        FieldType::NumericSigned => {
            parse_i64_base0(v).map_or(FieldValue::Opaque, FieldValue::Signed)
        }
        // pid/a0..a3/inode/etc: unsigned, base-0 (#229). A negative or malformed
        // spelling fails the parse and stays opaque.
        FieldType::Numeric | FieldType::NumericEqNe => {
            parse_u64_base0(v).map_or(FieldValue::Opaque, FieldValue::Unsigned)
        }
        // Every string / special-grammar field: never numerically folded.
        FieldType::String
        | FieldType::StringEqNe
        | FieldType::Arch
        | FieldType::Perm
        | FieldType::MsgType
        | FieldType::Filetype
        | FieldType::Key
        | FieldType::FsType
        | FieldType::SaddrFam => FieldValue::Opaque,
    }
}
