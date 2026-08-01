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
    /// A `-F perm=` value that parses as a `rwxa` permission-letter
    /// set on a [`FieldType::Perm`] field, folded into an order-free bitmask
    /// (session 9m lane 1, round 3 ATL, issues #600/#601). `lib/libaudit.c`'s
    /// `audit_rule_fieldpair_data` case-folds every character
    /// (`tolower((unsigned char)v[i])`) and ORs the letters into one bitmask
    /// before the kernel ever compares it, so `perm=wa`/`perm=aw`/`perm=WA`
    /// are the SAME kernel value. A value that does not parse as perm
    /// letters (e.g. a too-long or invalid-letter spelling that only reaches
    /// this classifier because its `-F perm!=...` operator skipped the
    /// parser's letter-set check) stays [`FieldValue::Opaque`] instead --
    /// never a partial/best-effort parse.
    Perm(PermMask),
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
            FieldValue::UidGidUnset | FieldValue::Opaque | FieldValue::Perm(_) => None,
        }
    }
}

/// A parsed `-F perm=` permission-letter set, folded into a 4-bit
/// order-free bitmask matching `AUDIT_PERM_READ`/`WRITE`/`EXEC`/`ATTR`
/// (`permtab.h:28-31`). A newtype rather than reusing `crate::ast::PermBits`:
/// that type is not `Copy`/`Eq`, both of which `FieldValue` needs. `pub`
/// (matching `FieldValue`'s own visibility -- the derived `Perm(PermMask)`
/// variant field is reachable wherever `FieldValue` is), but the inner `u8`
/// stays private, so nothing outside this module can construct one or peek
/// at the raw bits; only (in)equality and `Debug` are exposed via the derive.
/// Deliberately NOT unified with `parser::parse_perms` or
/// `stig_required::perm_bits_from_field_value` -- each call site's fix is
/// scoped to its own file, and the grammar is small and stable (4 letters,
/// `permtab.h:28-31`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PermMask(u8);

impl PermMask {
    const READ: u8 = 0b0001;
    const WRITE: u8 = 0b0010;
    const EXEC: u8 = 0b0100;
    const ATTR: u8 = 0b1000;

    /// Fold `raw` (already trimmed by the caller) into a `PermMask`,
    /// ASCII-case-folded per `lib/libaudit.c`'s `audit_rule_fieldpair_data`
    /// `AUDIT_PERM` case. `None` for any character outside `rwxa` -- an
    /// unparseable value stays `Opaque` rather than a partial parse. No
    /// length limit here: the `<= 4` bound is a userspace-parser concern
    /// (`src/parser.rs`'s `op == Eq`-gated length check), not part of the
    /// kernel-level bitmask identity this type models, and a value that
    /// reaches this classifier via a non-`=` operator (e.g. the too-long
    /// `-F perm!=rwxar`) was never length-checked by the parser at all.
    fn parse(raw: &str) -> Option<Self> {
        let mut bits = 0u8;
        for ch in raw.chars() {
            bits |= match ch.to_ascii_lowercase() {
                'r' => Self::READ,
                'w' => Self::WRITE,
                'x' => Self::EXEC,
                'a' => Self::ATTR,
                _ => return None,
            };
        }
        Some(Self(bits))
    }

    /// Canonical `rwxa`-ordered spelling of this bitmask, matching
    /// `normalize::perm_letters`'s convention for a `Watch` rule's `-p`
    /// value, so a `-F perm=` predicate's canonical form and a `-p` value's
    /// canonical form agree on the same bitmask.
    ///
    /// `pub(super)`: called by `canonical_value` in the sibling `canonical`
    /// module.
    pub(super) fn to_letters(self) -> String {
        let mut s = String::new();
        if self.0 & Self::READ != 0 {
            s.push('r');
        }
        if self.0 & Self::WRITE != 0 {
            s.push('w');
        }
        if self.0 & Self::EXEC != 0 {
            s.push('x');
        }
        if self.0 & Self::ATTR != 0 {
            s.push('a');
        }
        s
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
        // -F perm=: fold rwxa letters into an order-free bitmask (session 9m
        // lane 1, round 3 ATL). Falls back to Opaque for a value that fails to
        // parse as perm letters -- see PermMask::parse. A WATCH's -p never
        // reaches here: FieldType::Perm comes only from AuditField::Perm
        // (field_type.rs), and a watch's perms travel as PermBits through
        // normalize::perm_letters instead. `to_letters` documents why the two
        // independent paths still agree on a canonical spelling.
        FieldType::Perm => PermMask::parse(v).map_or(FieldValue::Opaque, FieldValue::Perm),
        // Every other string / special-grammar field: never numerically folded.
        FieldType::String
        | FieldType::StringEqNe
        | FieldType::Arch
        | FieldType::MsgType
        | FieldType::Filetype
        | FieldType::Key
        | FieldType::FsType
        | FieldType::SaddrFam => FieldValue::Opaque,
    }
}
