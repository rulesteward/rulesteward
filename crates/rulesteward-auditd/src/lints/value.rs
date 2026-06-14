//! Shared `-F` value interpretation for the duplicate/shadow/suppression lints
//! (#219 interval-aware subsumption, #220 value-spelling folding).
//!
//! Both enhancements need to interpret a `-F field op value` literal BY the
//! field's [`FieldType`]: #220 folds equivalent spellings into one canonical
//! form for [`crate::lints::normalize::canonical_key`]; #219 compares numeric
//! thresholds for [`crate::lints::ordering`]'s au-W02 subsumption and au-W03
//! disjointness. This module is the single place that decides what a value
//! "means", so the two lints can never disagree on value identity.
//!
//! # The uid/gid "unset" sentinel
//! libaudit treats uid/gid as `uid_t`/`gid_t`, which are `u32`. The value `-1`
//! is the conventional "unset" sentinel; cast to `u32` it is `4294967295`
//! (`u32::MAX`), and libaudit's symbolic name for it is `unset`. So for
//! [`FieldType::Uid`]/[`FieldType::Gid`] the three spellings `-1`,
//! `4294967295`, and `unset` denote the IDENTICAL kernel value and fold to one
//! ([`FieldValue::UidGidUnset`]). This equivalence is uid/gid-ONLY: a
//! `pid=4294967295` (`FieldType::Numeric`) is a concrete pid and an
//! `exit=4294967295` (`FieldType::NumericSigned`) is a concrete signed value;
//! neither folds.
//!
//! # Numeric spellings (base-0, #229)
//! Numeric fields parse their value with C `strtoul`/`strtol` base 0, matching
//! libaudit `audit_rule_fieldpair_data` @ 3bfa048: `0x80` is hex 128, `010` is
//! octal 8, `80` is decimal 80. So equivalent spellings of the same number fold
//! (`a0=0x80` == `a0=128`), and the leading-zero octal case is read correctly
//! (`a0=010` is 8, NOT 10). Parsing is strict: a value that is not a clean
//! base-0 number in its detected radix stays [`FieldValue::Opaque`] rather than
//! taking strtoul's parse-a-prefix-then-stop shortcut (so `08` is opaque, not 0).
//!
//! # Conservative by construction
//! Anything not numerically interpretable (a username, an errno symbol, a hex
//! literal on a string-typed field, or a malformed number) is
//! [`FieldValue::Opaque`]: it only ever compares by exact (trimmed) spelling,
//! never by interval. The numeric relations below return their answer only when
//! they can PROVE it; on any doubt they decline, so #219 never manufactures a
//! false subsumption or a false disjointness.

use std::borrow::Cow;

use crate::ast::{CompareOp, FieldFilter};
use crate::lints::field_type::{FieldType, field_type};

/// The typed interpretation of a `-F` value string, under its field's type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldValue {
    /// The uid/gid "unset" sentinel: `-1`, `4294967295`, or `unset` on a
    /// [`FieldType::Uid`]/[`FieldType::Gid`] field.
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
    fn position(self) -> Option<i128> {
        match self {
            FieldValue::Signed(n) => Some(i128::from(n)),
            FieldValue::Unsigned(n) => Some(i128::from(n)),
            FieldValue::UidGidUnset | FieldValue::Opaque => None,
        }
    }
}

/// Parse `s` as a non-negative integer the way C `strtoul(s, NULL, 0)` reads the
/// magnitude: a `0x`/`0X` prefix is hex, a leading `0` (with more digits) is
/// octal, otherwise decimal. CONSERVATIVE by construction: the WHOLE string must
/// be a clean number in the detected radix, so this returns `None` (the caller
/// then keeps the value [`FieldValue::Opaque`]) on any ambiguity rather than
/// replicating strtoul's parse-a-prefix-then-stop (so `08` is `None` here, not
/// `0`, and never produces a fold libaudit would not). No sign handling;
/// [`parse_i64_base0`] adds the leading `-`. Grounded in libaudit
/// `audit_rule_fieldpair_data` (lib/libaudit.c @ 3bfa048), which parses every
/// numeric `-F` value with `strtoul`/`strtol` base 0 (#229).
fn parse_u64_base0(s: &str) -> Option<u64> {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        if hex.is_empty() || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        u64::from_str_radix(hex, 16).ok()
    } else if s.len() > 1 && s.starts_with('0') {
        let octal = &s[1..];
        if !octal.bytes().all(|b| (b'0'..=b'7').contains(&b)) {
            return None;
        }
        u64::from_str_radix(octal, 8).ok()
    } else if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        None
    } else {
        s.parse::<u64>().ok()
    }
}

/// Signed base-0 parse for `exit` (#229): an optional leading `-` on a
/// [`parse_u64_base0`] magnitude (so `-0x10` is -16). The magnitude must fit
/// `i64`, else `None` (conservative).
fn parse_i64_base0(s: &str) -> Option<i64> {
    if let Some(mag) = s.strip_prefix('-') {
        Some(-i64::try_from(parse_u64_base0(mag)?).ok()?)
    } else {
        i64::try_from(parse_u64_base0(s)?).ok()
    }
}

/// Interpret `raw` as a [`FieldValue`] under `ft`. See the module doc for the
/// uid/gid sentinel rule and the conservative-opaque fallback.
#[must_use]
pub fn classify(ft: FieldType, raw: &str) -> FieldValue {
    let v = raw.trim();
    match ft {
        FieldType::Uid | FieldType::Gid => {
            if v.eq_ignore_ascii_case("unset") || v == "-1" {
                return FieldValue::UidGidUnset;
            }
            // libaudit parses uid/gid with strtoul base 0 (#229): hex/octal/
            // decimal all accepted. Narrow to u32 (anything above is not a valid
            // uid/gid -> opaque); u32::MAX is the sentinel; usernames and
            // malformed numbers fail the parse and stay opaque.
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

/// The canonical spelling of `raw` under `ft`, for content identity (#220).
///
/// The uid/gid unset triple collapses to `"unset"`; concrete numerics
/// decimal-normalize (a value-preserving bijection); opaque values keep their
/// trimmed spelling. Equal canonical values mean the two predicates match the
/// same kernel value.
#[must_use]
pub fn canonical_value(ft: FieldType, raw: &str) -> Cow<'_, str> {
    match classify(ft, raw) {
        FieldValue::UidGidUnset => Cow::Borrowed("unset"),
        // Decimal-normalize concrete numerics (a value-preserving bijection, so
        // it only ever merges spellings of the SAME number, never distinct ones).
        FieldValue::Unsigned(n) => Cow::Owned(n.to_string()),
        FieldValue::Signed(n) => Cow::Owned(n.to_string()),
        FieldValue::Opaque => Cow::Borrowed(raw.trim()),
    }
}

/// True when the later predicate `pl` IMPLIES the earlier predicate `pe`: every
/// value matching `pl` also matches `pe` (so `pl`'s matched set is a subset of
/// `pe`'s, i.e. `pe` is at least as broad). Both predicates must be on the same
/// field. Used by au-W02 subsumption (#219): the earlier rule subsumes the
/// later one when every earlier predicate is implied by a later predicate.
///
/// Conservative: returns true only for provable implication; any unsupported
/// operator pairing returns false (a false negative, never a false positive).
#[must_use]
pub fn implies(pe: &FieldFilter, pl: &FieldFilter) -> bool {
    if pe.field != pl.field {
        return false;
    }
    let ft = field_type(&pe.field);
    // I0: identical operator and folded-equal value. Covers Eq, Ne, the bitmask
    // ops, and exact relational, and folds the uid/gid sentinel spellings, so
    // au-W02 agrees with au-W01 on value identity.
    if pe.op == pl.op && canonical_value(ft, &pe.value) == canonical_value(ft, &pl.value) {
        return true;
    }
    // Otherwise pl implies pe iff pl's matched interval is contained in pe's.
    // interval() yields None for Ne/bitmask/opaque/sentinel operands, so those
    // reach implication ONLY through the exact I0 case above (conservative).
    match (interval(ft, pe), interval(ft, pl)) {
        (Some((elo, ehi)), Some((llo, lhi))) => elo <= llo && lhi <= ehi,
        _ => false,
    }
}

/// True when two same-field predicates are PROVABLY non-co-matching: no single
/// event value can satisfy both. Used by au-W03 (#219) to prove two rules
/// cannot overlap. Conservative: returns true only when provable; on any doubt
/// returns false (the rules are then treated as overlapping, keeping the
/// suppression warning).
#[must_use]
pub fn disjoint(pa: &FieldFilter, pb: &FieldFilter) -> bool {
    if pa.field != pb.field {
        return false;
    }
    let ft = field_type(&pa.field);
    // Eq vs Eq: one event carries one value per field, so two equalities
    // contradict iff their values are PROVABLY different kernel values. Handled
    // here (not via interval) because it must cover string/opaque fields and the
    // folded sentinel, and must NOT call alias-bearing spellings disjoint.
    if pa.op == CompareOp::Eq && pb.op == CompareOp::Eq {
        return eq_values_provably_differ(ft, &pa.value, &pb.value);
    }
    // Otherwise prove disjointness only via non-overlapping concrete intervals.
    // Ne/bitmask/opaque/sentinel yield None -> not provably disjoint -> overlap.
    match (interval(ft, pa), interval(ft, pb)) {
        (Some((alo, ahi)), Some((blo, bhi))) => ahi < blo || bhi < alo,
        _ => false,
    }
}

/// True when two `=` values on the same field are PROVABLY different kernel
/// values. Difference is provable for:
/// * concrete-comparable values (a numeric value or the uid/gid sentinel) whose
///   canonical forms differ - e.g. `uid=0` vs `uid=1000`; or
/// * a free-form string field ([`FieldType::String`]/[`FieldType::StringEqNe`]/
///   [`FieldType::Key`]: path, dir, exe, subj_*, obj_*, key) where the kernel does
///   an exact string match with no symbolic aliases - e.g. `path=/a` vs `path=/b`.
///
/// Alias-bearing fields where one spelling can denote the same value as another
/// (uid/gid NAMES like `uid=root` == `uid=0`; `arch=b64` == `arch=x86_64`;
/// `msgtype=SYSCALL` == `msgtype=1300`; filetype/fstype symbolic names) are NOT
/// provably different from a spelling mismatch alone, so this returns false
/// (the rules are then treated as overlapping). That keeps au-W03 conservative:
/// it never DROPS a real suppression warning on a value it cannot disprove. The
/// cost is over-warning on a genuinely-distinct alias-bearing pair (e.g.
/// `msgtype=1300` vs `msgtype=1301`), the safe direction for a suppression lint.
fn eq_values_provably_differ(ft: FieldType, a: &str, b: &str) -> bool {
    let comparable = |v: FieldValue| {
        matches!(
            v,
            FieldValue::Unsigned(_) | FieldValue::Signed(_) | FieldValue::UidGidUnset
        )
    };
    let both_concrete = comparable(classify(ft, a)) && comparable(classify(ft, b));
    let free_form = matches!(
        ft,
        FieldType::String | FieldType::StringEqNe | FieldType::Key
    );
    if both_concrete || free_form {
        canonical_value(ft, a) != canonical_value(ft, b)
    } else {
        false
    }
}

/// The closed `i128` interval `[lo, hi]` of event values a predicate matches,
/// or `None` when the operand is not a concrete orderable number (`Ne`, the
/// bitmask ops, opaque values, and the uid/gid sentinel have no interval). The
/// half-line infinities use `i128::MIN`/`MAX`; real `u64`/`i64` values plus the
/// `+/-1` boundary adjustments stay well inside `i128`.
fn interval(ft: FieldType, p: &FieldFilter) -> Option<(i128, i128)> {
    let c = classify(ft, &p.value).position()?;
    match p.op {
        CompareOp::Eq => Some((c, c)),
        CompareOp::Ge => Some((c, i128::MAX)),
        CompareOp::Gt => Some((c + 1, i128::MAX)),
        CompareOp::Le => Some((i128::MIN, c)),
        CompareOp::Lt => Some((i128::MIN, c - 1)),
        CompareOp::Ne | CompareOp::BitAnd | CompareOp::BitAndEq => None,
    }
}

#[cfg(test)]
mod tests {
    // Test bindings use families like ge1000/ge2000 and ne5/ne5b in one scope
    // (clippy::similar_names), and the `ft` helper takes the small `AuditField`
    // enum by value for call-site ergonomics (clippy::needless_pass_by_value).
    #![allow(clippy::similar_names, clippy::needless_pass_by_value)]

    use super::{FieldValue, canonical_value, classify, disjoint, implies};
    use crate::ast::{AuditField, CompareOp, FieldFilter};
    use crate::lints::field_type::field_type;

    fn ft(field: AuditField) -> crate::lints::field_type::FieldType {
        field_type(&field)
    }

    fn ff(field: AuditField, op: CompareOp, value: &str) -> FieldFilter {
        FieldFilter {
            field,
            op,
            value: value.to_string(),
        }
    }

    // --- classify: uid/gid sentinel -------------------------------------

    #[test]
    fn uid_sentinel_spellings_all_classify_unset() {
        for s in ["-1", "4294967295", "unset", "UNSET", "Unset"] {
            assert_eq!(
                classify(ft(AuditField::Auid), s),
                FieldValue::UidGidUnset,
                "auid value {s:?} must be the unset sentinel"
            );
        }
        assert_eq!(classify(ft(AuditField::Gid), "-1"), FieldValue::UidGidUnset);
        assert_eq!(
            classify(ft(AuditField::Egid), "4294967295"),
            FieldValue::UidGidUnset
        );
    }

    #[test]
    fn uid_concrete_values_classify_unsigned() {
        assert_eq!(classify(ft(AuditField::Auid), "0"), FieldValue::Unsigned(0));
        assert_eq!(
            classify(ft(AuditField::Uid), "1000"),
            FieldValue::Unsigned(1000)
        );
        // u32::MAX-1 is concrete (only u32::MAX itself is the sentinel).
        assert_eq!(
            classify(ft(AuditField::Uid), "4294967294"),
            FieldValue::Unsigned(4_294_967_294)
        );
    }

    #[test]
    fn uid_non_numeric_and_out_of_range_are_opaque() {
        assert_eq!(classify(ft(AuditField::Auid), "root"), FieldValue::Opaque);
        // > u32::MAX is not a valid uid -> opaque, not a wrapped sentinel.
        assert_eq!(
            classify(ft(AuditField::Auid), "4294967296"),
            FieldValue::Opaque
        );
        // A negative other than -1 is not meaningful for uid -> opaque. (#229: we
        // do NOT replicate libaudit's negative-uid wrap; conservative Opaque.)
        assert_eq!(classify(ft(AuditField::Auid), "-2"), FieldValue::Opaque);
    }

    #[test]
    fn uid_parses_hex_octal_base0() {
        // libaudit parses uid with strtoul base 0 (#229): hex/octal accepted.
        assert_eq!(
            classify(ft(AuditField::Auid), "0x10"),
            FieldValue::Unsigned(16)
        );
        assert_eq!(
            classify(ft(AuditField::Auid), "010"),
            FieldValue::Unsigned(8)
        );
        // 0xFFFFFFFF == u32::MAX == the unset sentinel.
        assert_eq!(
            classify(ft(AuditField::Uid), "0xFFFFFFFF"),
            FieldValue::UidGidUnset
        );
    }

    // --- classify: the 4294967295 distinctness invariant ----------------

    #[test]
    fn big_value_on_non_uid_numeric_is_concrete_not_sentinel() {
        // pid is Numeric (unsigned): 4294967295 is a concrete pid, NOT unset.
        assert_eq!(
            classify(ft(AuditField::Pid), "4294967295"),
            FieldValue::Unsigned(4_294_967_295)
        );
        // exit is NumericSigned: 4294967295 is a concrete signed value, -1 is a
        // concrete -1, NEITHER is the uid sentinel.
        assert_eq!(
            classify(ft(AuditField::Exit), "4294967295"),
            FieldValue::Signed(4_294_967_295)
        );
        assert_eq!(classify(ft(AuditField::Exit), "-1"), FieldValue::Signed(-1));
    }

    #[test]
    fn signed_and_unsigned_numeric_classify_by_type() {
        assert_eq!(
            classify(ft(AuditField::Exit), "-13"),
            FieldValue::Signed(-13)
        );
        assert_eq!(classify(ft(AuditField::Exit), "EPERM"), FieldValue::Opaque);
        assert_eq!(
            classify(ft(AuditField::Pid), "1000"),
            FieldValue::Unsigned(1000)
        );
        // a negative on an unsigned numeric does not parse -> opaque.
        assert_eq!(classify(ft(AuditField::Pid), "-1"), FieldValue::Opaque);
        // inode is NumericEqNe (still unsigned numeric for value purposes).
        assert_eq!(
            classify(ft(AuditField::Inode), "42"),
            FieldValue::Unsigned(42)
        );
    }

    #[test]
    fn string_typed_fields_are_always_opaque() {
        assert_eq!(
            classify(ft(AuditField::Path), "/etc/passwd"),
            FieldValue::Opaque
        );
        assert_eq!(classify(ft(AuditField::Exe), "/bin/sh"), FieldValue::Opaque);
        assert_eq!(classify(ft(AuditField::Arch), "b64"), FieldValue::Opaque);
        assert_eq!(classify(ft(AuditField::Key), "exec"), FieldValue::Opaque);
        // even a numeric-looking string on a string field stays opaque.
        assert_eq!(classify(ft(AuditField::Path), "1000"), FieldValue::Opaque);
    }

    // --- canonical_value: #220 folding ----------------------------------

    #[test]
    fn canonical_folds_uid_sentinel_triple() {
        let u = ft(AuditField::Auid);
        assert_eq!(canonical_value(u, "-1"), "unset");
        assert_eq!(canonical_value(u, "4294967295"), "unset");
        assert_eq!(canonical_value(u, "unset"), "unset");
        assert_eq!(canonical_value(u, "UNSET"), "unset");
        assert_eq!(canonical_value(ft(AuditField::Gid), "-1"), "unset");
    }

    #[test]
    fn canonical_keeps_concrete_uid_distinct_from_sentinel() {
        let u = ft(AuditField::Auid);
        assert_eq!(canonical_value(u, "0"), "0"); // root is not unset
        assert_eq!(canonical_value(u, "1000"), "1000");
        assert_ne!(canonical_value(u, "0"), canonical_value(u, "unset"));
    }

    #[test]
    fn canonical_does_not_fold_big_value_on_other_types() {
        // pid 4294967295 stays itself; exit -1 / 4294967295 stay themselves.
        assert_eq!(
            canonical_value(ft(AuditField::Pid), "4294967295"),
            "4294967295"
        );
        assert_eq!(canonical_value(ft(AuditField::Exit), "-1"), "-1");
        assert_eq!(
            canonical_value(ft(AuditField::Exit), "4294967295"),
            "4294967295"
        );
        assert_ne!(
            canonical_value(ft(AuditField::Exit), "-1"),
            canonical_value(ft(AuditField::Exit), "4294967295")
        );
    }

    #[test]
    fn canonical_opaque_values_keep_spelling_but_hex_octal_fold() {
        let u = ft(AuditField::Auid);
        assert_eq!(canonical_value(u, "root"), "root");
        // #229: hex/octal now parse base-0 and fold to decimal (match libaudit).
        assert_eq!(canonical_value(u, "0x10"), "16");
        assert_eq!(canonical_value(u, "0x10"), canonical_value(u, "16"));
        // A genuinely unparseable value still keeps its trimmed spelling.
        assert_eq!(canonical_value(u, "0xZZ"), "0xZZ");
    }

    // --- classify / canonical: base-0 numeric parsing (#229) ------------

    #[test]
    fn classify_parses_hex_octal_decimal_base0() {
        // Numeric -F values parse base-0 like libaudit strtoul/strtol @ 3bfa048.
        assert_eq!(
            classify(ft(AuditField::A0), "0x80"),
            FieldValue::Unsigned(128)
        );
        // leading-0 is OCTAL, not decimal (the latent-bug case).
        assert_eq!(classify(ft(AuditField::A0), "010"), FieldValue::Unsigned(8));
        assert_eq!(classify(ft(AuditField::A0), "80"), FieldValue::Unsigned(80));
        // signed exit: base-0 magnitude with an optional leading '-'.
        assert_eq!(
            classify(ft(AuditField::Exit), "0x10"),
            FieldValue::Signed(16)
        );
        assert_eq!(
            classify(ft(AuditField::Exit), "-0x10"),
            FieldValue::Signed(-16)
        );
        assert_eq!(classify(ft(AuditField::Exit), "-1"), FieldValue::Signed(-1));
    }

    #[test]
    fn canonical_folds_hex_octal_decimal_same_value() {
        let a = ft(AuditField::A0);
        assert_eq!(canonical_value(a, "0x80"), "128");
        assert_eq!(canonical_value(a, "0x80"), canonical_value(a, "128"));
        assert_eq!(canonical_value(a, "010"), "8");
    }

    #[test]
    fn octal_distinct_from_decimal() {
        // The latent-bug guard: a0=010 is octal 8, NOT decimal 10.
        let a = ft(AuditField::A0);
        assert_ne!(canonical_value(a, "010"), canonical_value(a, "10"));
        assert_eq!(canonical_value(a, "010"), canonical_value(a, "8"));
    }

    #[test]
    fn ambiguous_numeric_stays_opaque_conservative() {
        // We do NOT replicate strtoul's parse-prefix-then-stop; anything that is
        // not a clean base-0 number stays Opaque (#229; never a false fold).
        let a = ft(AuditField::A0);
        for s in ["08", "0x", "0xZZ", "12x", "", " "] {
            assert_eq!(classify(a, s), FieldValue::Opaque, "{s:?} must be opaque");
        }
    }

    // --- implies: au-W02 subsumption (#219) -----------------------------
    // implies(pe, pl): does later pl imply earlier pe (pl's set subset of pe's)?

    #[test]
    fn implies_exact_same_predicate() {
        let pe = ff(AuditField::Auid, CompareOp::Ge, "1000");
        let pl = ff(AuditField::Auid, CompareOp::Ge, "1000");
        assert!(implies(&pe, &pl));
    }

    #[test]
    fn implies_folds_sentinel_in_exact_case() {
        // auid!=-1 and auid!=4294967295: same op, folded-equal value.
        let pe = ff(AuditField::Auid, CompareOp::Ne, "-1");
        let pl = ff(AuditField::Auid, CompareOp::Ne, "4294967295");
        assert!(implies(&pe, &pl));
        assert!(implies(&pl, &pe));
    }

    #[test]
    fn implies_lower_bound_broader_subsumes_narrower() {
        // auid>=1000 (earlier, broad) is implied by auid>=2000 (later, narrow).
        let pe = ff(AuditField::Auid, CompareOp::Ge, "1000");
        let pl = ff(AuditField::Auid, CompareOp::Ge, "2000");
        assert!(implies(&pe, &pl), "auid>=1000 must subsume auid>=2000");
        // and not the reverse.
        assert!(!implies(&pl, &pe), "auid>=2000 must NOT subsume auid>=1000");
    }

    #[test]
    fn implies_gt_ge_boundary() {
        let gt1000 = ff(AuditField::Auid, CompareOp::Gt, "1000");
        let ge2000 = ff(AuditField::Auid, CompareOp::Ge, "2000");
        let ge1000 = ff(AuditField::Auid, CompareOp::Ge, "1000");
        let gt1000b = ff(AuditField::Auid, CompareOp::Gt, "1000");
        // >1000 implied by >=2000 (2000 > 1000)
        assert!(implies(&gt1000, &ge2000));
        // >=1000 implied by >1000  (>1000 == >=1001, subset of >=1000)
        assert!(implies(&ge1000, &gt1000b));
        // >1000 NOT implied by >=1000 (1000 satisfies pl but not pe)
        assert!(!implies(&gt1000, &ge1000));
    }

    #[test]
    fn implies_upper_bound_direction() {
        let le2000 = ff(AuditField::Uid, CompareOp::Le, "2000");
        let le1000 = ff(AuditField::Uid, CompareOp::Le, "1000");
        let lt2000 = ff(AuditField::Uid, CompareOp::Lt, "2000");
        assert!(implies(&le2000, &le1000), "uid<=2000 subsumes uid<=1000");
        assert!(
            !implies(&le1000, &lt2000),
            "uid<=1000 does NOT subsume uid<2000"
        );
    }

    #[test]
    fn implies_opposite_direction_never() {
        let ge = ff(AuditField::Auid, CompareOp::Ge, "1000");
        let le = ff(AuditField::Auid, CompareOp::Le, "2000");
        assert!(!implies(&ge, &le));
        assert!(!implies(&le, &ge));
    }

    #[test]
    fn implies_signed_exit() {
        let ge_m13 = ff(AuditField::Exit, CompareOp::Ge, "-13");
        let ge_m5 = ff(AuditField::Exit, CompareOp::Ge, "-5");
        let ge_m20 = ff(AuditField::Exit, CompareOp::Ge, "-20");
        assert!(implies(&ge_m13, &ge_m5), "exit>=-13 subsumes exit>=-5");
        assert!(
            !implies(&ge_m13, &ge_m20),
            "exit>=-13 does NOT subsume exit>=-20"
        );
    }

    #[test]
    fn implies_eq_point_inside_relational_i2() {
        // I2: a later Eq whose point lies inside the earlier relational range.
        let ge1000 = ff(AuditField::Auid, CompareOp::Ge, "1000");
        let eq1500 = ff(AuditField::Auid, CompareOp::Eq, "1500");
        let eq500 = ff(AuditField::Auid, CompareOp::Eq, "500");
        assert!(implies(&ge1000, &eq1500), "auid>=1000 subsumes auid=1500");
        assert!(
            !implies(&ge1000, &eq500),
            "auid>=1000 does NOT subsume auid=500"
        );
        let le1000 = ff(AuditField::Auid, CompareOp::Le, "1000");
        let eq500b = ff(AuditField::Auid, CompareOp::Eq, "500");
        assert!(implies(&le1000, &eq500b), "auid<=1000 subsumes auid=500");
    }

    #[test]
    fn implies_relational_does_not_imply_eq() {
        // The reverse of I2: a relational later does NOT imply an Eq earlier.
        let eq1500 = ff(AuditField::Auid, CompareOp::Eq, "1500");
        let ge1000 = ff(AuditField::Auid, CompareOp::Ge, "1000");
        assert!(!implies(&eq1500, &ge1000));
    }

    #[test]
    fn implies_ne_and_bitmask_only_exact() {
        // Ne never participates in interval implication.
        let ne5 = ff(AuditField::Auid, CompareOp::Ne, "5");
        let ge1000 = ff(AuditField::Auid, CompareOp::Ge, "1000");
        assert!(!implies(&ne5, &ge1000));
        assert!(!implies(&ge1000, &ne5));
        let ne5b = ff(AuditField::Auid, CompareOp::Ne, "5");
        assert!(implies(&ne5, &ne5b), "exact Ne==Ne implies");
        // bitmask: exact only.
        let band4 = ff(AuditField::A0, CompareOp::BitAnd, "4");
        let band4b = ff(AuditField::A0, CompareOp::BitAnd, "4");
        let band6 = ff(AuditField::A0, CompareOp::BitAnd, "6");
        assert!(implies(&band4, &band4b));
        assert!(!implies(&band4, &band6));
    }

    #[test]
    fn implies_sentinel_in_relational_is_conservative() {
        // auid>=0 (concrete 0) vs auid>=4294967295 (sentinel): no interval math
        // on the sentinel -> conservative false.
        let ge0 = ff(AuditField::Auid, CompareOp::Ge, "0");
        let ge_sentinel = ff(AuditField::Auid, CompareOp::Ge, "4294967295");
        assert!(!implies(&ge0, &ge_sentinel));
        assert!(!implies(&ge_sentinel, &ge0));
        // but >=-1 and >=4294967295 are the SAME predicate (folded) -> implies.
        let ge_m1 = ff(AuditField::Auid, CompareOp::Ge, "-1");
        assert!(implies(&ge_m1, &ge_sentinel));
    }

    #[test]
    fn implies_requires_same_field_and_numeric_type() {
        // Different fields never imply.
        let a = ff(AuditField::Auid, CompareOp::Ge, "1000");
        let b = ff(AuditField::Uid, CompareOp::Ge, "2000");
        assert!(!implies(&a, &b));
        // String field with relational op: opaque, never interval.
        let pa = ff(AuditField::Path, CompareOp::Ge, "/a");
        let pb = ff(AuditField::Path, CompareOp::Ge, "/b");
        assert!(!implies(&pa, &pb));
        // generic Numeric (pid) intervals work too.
        let p1 = ff(AuditField::Pid, CompareOp::Ge, "1000");
        let p2 = ff(AuditField::Pid, CompareOp::Ge, "2000");
        assert!(implies(&p1, &p2));
    }

    // --- disjoint: au-W03 suppression (#219) ----------------------------

    #[test]
    fn disjoint_eq_eq_different_values() {
        let a = ff(AuditField::Auid, CompareOp::Eq, "0");
        let b = ff(AuditField::Auid, CompareOp::Eq, "1000");
        assert!(disjoint(&a, &b));
    }

    #[test]
    fn disjoint_eq_eq_folded_sentinel_is_not_disjoint() {
        let a = ff(AuditField::Auid, CompareOp::Eq, "-1");
        let b = ff(AuditField::Auid, CompareOp::Eq, "4294967295");
        assert!(
            !disjoint(&a, &b),
            "auid=-1 and auid=4294967295 are the same value"
        );
    }

    #[test]
    fn disjoint_eq_eq_string_fields() {
        // A single event has one path; path=/a and path=/b cannot co-match.
        let a = ff(AuditField::Path, CompareOp::Eq, "/a");
        let b = ff(AuditField::Path, CompareOp::Eq, "/b");
        assert!(disjoint(&a, &b));
        let c = ff(AuditField::Path, CompareOp::Eq, "/a");
        assert!(!disjoint(&a, &c));
    }

    #[test]
    fn disjoint_opposite_relational_non_meeting() {
        let ge2000 = ff(AuditField::Auid, CompareOp::Ge, "2000");
        let lt1000 = ff(AuditField::Auid, CompareOp::Lt, "1000");
        assert!(
            disjoint(&ge2000, &lt1000),
            ">=2000 and <1000 cannot co-match"
        );
        // touching at the boundary is NOT disjoint.
        let ge2000b = ff(AuditField::Auid, CompareOp::Ge, "2000");
        let le2000 = ff(AuditField::Auid, CompareOp::Le, "2000");
        assert!(
            !disjoint(&ge2000b, &le2000),
            ">=2000 and <=2000 meet at 2000"
        );
        // overlapping ranges are not disjoint.
        let ge1000 = ff(AuditField::Auid, CompareOp::Ge, "1000");
        let lt2000 = ff(AuditField::Auid, CompareOp::Lt, "2000");
        assert!(!disjoint(&ge1000, &lt2000));
    }

    #[test]
    fn disjoint_eq_outside_relational() {
        let eq0 = ff(AuditField::Auid, CompareOp::Eq, "0");
        let ge1000 = ff(AuditField::Auid, CompareOp::Ge, "1000");
        assert!(disjoint(&eq0, &ge1000), "auid=0 is outside auid>=1000");
        let eq1500 = ff(AuditField::Auid, CompareOp::Eq, "1500");
        assert!(
            !disjoint(&eq1500, &ge1000),
            "auid=1500 is inside auid>=1000"
        );
    }

    #[test]
    fn disjoint_same_direction_is_not_disjoint() {
        let ge1000 = ff(AuditField::Auid, CompareOp::Ge, "1000");
        let ge2000 = ff(AuditField::Auid, CompareOp::Ge, "2000");
        assert!(!disjoint(&ge1000, &ge2000));
    }

    #[test]
    fn disjoint_conservative_on_ne_bitmask_sentinel_opaque() {
        // Ne stays conservative (overlap) even when arguably disjoint.
        let ne5 = ff(AuditField::Auid, CompareOp::Ne, "5");
        let eq5 = ff(AuditField::Auid, CompareOp::Eq, "5");
        assert!(
            !disjoint(&ne5, &eq5),
            "Ne is not interval-reasoned (conservative)"
        );
        // sentinel Eq vs relational -> can't prove disjoint -> overlap.
        let eq_unset = ff(AuditField::Auid, CompareOp::Eq, "unset");
        let ge1000 = ff(AuditField::Auid, CompareOp::Ge, "1000");
        assert!(!disjoint(&eq_unset, &ge1000));
        // bitmask -> overlap.
        let band4 = ff(AuditField::A0, CompareOp::BitAnd, "4");
        let band2 = ff(AuditField::A0, CompareOp::BitAnd, "2");
        assert!(!disjoint(&band4, &band2));
    }

    #[test]
    fn disjoint_requires_same_field() {
        let a = ff(AuditField::Auid, CompareOp::Eq, "0");
        let b = ff(AuditField::Uid, CompareOp::Eq, "1000");
        assert!(
            !disjoint(&a, &b),
            "different fields are independent, not disjoint"
        );
    }

    #[test]
    fn disjoint_signed_exit_ranges() {
        let ge0 = ff(AuditField::Exit, CompareOp::Ge, "0");
        let lt_m5 = ff(AuditField::Exit, CompareOp::Lt, "-5");
        assert!(
            disjoint(&ge0, &lt_m5),
            "exit>=0 and exit<-5 cannot co-match"
        );
    }

    #[test]
    fn disjoint_touching_boundary_is_not_disjoint() {
        // >=2000 and <=2000 share exactly the value 2000 -> NOT disjoint. Pins
        // the strict `<` (not `<=`) in the overlap check, both operand orders.
        let ge2000 = ff(AuditField::Auid, CompareOp::Ge, "2000");
        let le2000 = ff(AuditField::Auid, CompareOp::Le, "2000");
        assert!(
            !disjoint(&ge2000, &le2000),
            ">=2000 and <=2000 meet at 2000"
        );
        assert!(!disjoint(&le2000, &ge2000), "symmetric: meet at 2000");
    }

    #[test]
    fn disjoint_tight_lt_boundary() {
        // >=1000 and <1000 are adjacent with NO shared value -> disjoint. The
        // tight seam pins the `c - 1` upper bound of `<` (a wrong offset would
        // include 1000 in `<1000` and make the pair wrongly overlap).
        let ge1000 = ff(AuditField::Auid, CompareOp::Ge, "1000");
        let lt1000 = ff(AuditField::Auid, CompareOp::Lt, "1000");
        assert!(
            disjoint(&ge1000, &lt1000),
            ">=1000 and <1000 are disjoint at the 999/1000 seam"
        );
        // The overlapping neighbor <=1000 shares 1000, so NOT disjoint.
        let le1000 = ff(AuditField::Auid, CompareOp::Le, "1000");
        assert!(!disjoint(&ge1000, &le1000), ">=1000 and <=1000 share 1000");
    }

    #[test]
    fn disjoint_alias_bearing_eq_pairs_are_not_disjoint() {
        // Different spellings of the SAME kernel value on alias-bearing fields
        // must NOT be called disjoint, or au-W03 drops a real suppression warning.
        // msgtype=SYSCALL == 1300 (the codebase relies on this at ordering.rs).
        assert!(!disjoint(
            &ff(AuditField::MsgType, CompareOp::Eq, "SYSCALL"),
            &ff(AuditField::MsgType, CompareOp::Eq, "1300"),
        ));
        // uid=root resolves to uid 0; a static linter has no passwd db to disprove it.
        assert!(!disjoint(
            &ff(AuditField::Uid, CompareOp::Eq, "root"),
            &ff(AuditField::Uid, CompareOp::Eq, "0"),
        ));
        // arch=b64 selects the same syscall table as x86_64 on an x86 host.
        assert!(!disjoint(
            &ff(AuditField::Arch, CompareOp::Eq, "b64"),
            &ff(AuditField::Arch, CompareOp::Eq, "x86_64"),
        ));
    }

    #[test]
    fn disjoint_freeform_string_eq_pairs_are_disjoint() {
        // Free-form string fields (String / StringEqNe / Key) are exact kernel
        // matches with no symbolic aliases, so different spellings ARE provably
        // different. Pins each variant in the free-form set.
        assert!(disjoint(
            &ff(AuditField::Path, CompareOp::Eq, "/a"),
            &ff(AuditField::Path, CompareOp::Eq, "/b"),
        ));
        assert!(disjoint(
            &ff(AuditField::Exe, CompareOp::Eq, "/bin/sh"),
            &ff(AuditField::Exe, CompareOp::Eq, "/bin/bash"),
        ));
        assert!(disjoint(
            &ff(AuditField::Key, CompareOp::Eq, "a"),
            &ff(AuditField::Key, CompareOp::Eq, "b"),
        ));
    }
}
