//! Known attribute names + their permitted side (subject / object / either).
//!
//! The lists here are FLAVOR-AGNOSTIC: they record the most-permissive
//! classification (e.g. `dir`, `ftype`, `trust` are `Either` because
//! modern accepts them on either side). The legacy dialect is stricter,
//! and that stricter classification lives in
//! `parser::grammar::legacy_classify` (file-private). The legacy
//! positional split anchors on the parser-local `legacy_classify`, not
//! on the functions exported here.
//!
//! Used by:
//! * `lints::fapd-E01` - to flag unknown attribute names (via [`is_known`]).
//!
//! Source: R2-audit-grammar.md, derived from
//! `src/library/{subject,object}-attr.c` in upstream fapolicyd.
//!
//! For the per-flavor deltas (e.g. `gid`/`ppid` illegal on legacy
//! subject side; `trust`/`dir`/`ftype` object-only in legacy; `exe_dir`/
//! `exe_type` legal ONLY on the legacy subject side - see the note below)
//! see the truth table inline in `parser::grammar::legacy_classify`.
//! Session 3a intentionally kept that knowledge parser-internal because no
//! public consumer exists yet; a future session may expose a public
//! flavor-aware API when fapd-E02 / fapd-E03 lint codes give it a concrete
//! consumer.
//!
//! NOTE on removed names: `exe_dir` and `exe_type` were removed from
//! `SUBJECT_ONLY` on 2026-05-29. Runtime testing against fapolicyd
//! 1.3.2, 1.4.3, and 1.4.5 confirmed that both names are REJECTED with
//! "Field type (`exe_dir`) is unknown" in the MODERN (colon) grammar - they
//! do not appear in the man page and are not valid MODERN fapolicyd
//! attribute names. That removal from `SUBJECT_ONLY` (this module's
//! flavor-agnostic/modern baseline table) remains correct and is
//! unaffected by the note below.
//!
//! CORRECTION (ATL round 2 MISS 2, 2026-07-18, doc-truth-decay): the
//! rejection above is MODERN-ONLY. Upstream `subject-attr.c` table1 (the
//! LEGACY/ORIG-format subject table, distinct from the modern table2)
//! DOES list `EXE_DIR`/`EXE_TYPE`, and a legacy (no-colon) rule using them
//! LOADS cleanly on both fapolicyd 1.3.2 and 1.4.5 (live-verified
//! 2026-07-18: `allow exe_dir=/usr/bin/ trust=1` -> "Loaded 1 rules" on
//! both versions; the modern `allow exe_dir=/usr/bin/ : all` is REJECTED
//! on both, unaffected). `parser::grammar::legacy_classify` (not this
//! module) is the source of truth for that legacy-only legality - see its
//! `legacy_classify_exe_dir_and_exe_type_are_subject_anchors` test. Their
//! ORIGINAL 2026-05-29 removal from `fapd-E01`'s false-negative was a real
//! bug fix for the MODERN grammar; treating them as universally-unknown
//! (both flavors) was the doc-truth-decay this correction resolves.
//! The `dir=` value keywords `execdirs`/`systemdirs`/`untrusted` (handled
//! by fapd-W08) are distinct and were not affected by any of this.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttrSide {
    Subject,
    Object,
    Either,
}

pub const SUBJECT_ONLY: &[&str] = &[
    "auid",
    "uid",
    "gid",
    "sessionid",
    "pid",
    "ppid",
    "comm",
    "exe",
    // `pattern` is subject-only in fapolicyd: the C subject-attr.c tables
    // carry PATTERN, object-attr.c does not, and rules.5 lists it under
    // Subject only.
    "pattern",
];

pub const OBJECT_ONLY: &[&str] = &["path", "device", "filehash", "sha256hash", "mode"];

pub const BOTH_SIDES: &[&str] = &["all", "dir", "ftype", "trust"];

/// fapolicyd's value-TYPE category for an attribute, used by fapd-E07 to predict
/// load-time type rejection of a `%set` assigned to it.
///
/// Derived from the runtime behavior of fapolicyd 1.3.2 / 1.4.3 / 1.4.5 (cited
/// `fapolicyd --debug --permissive` output in
/// `.private-docs/fapd-e07-grounding.md`), cross-checked against the type columns
/// in upstream `src/library/{subject,object}-attr.c`. The CATEGORY here is
/// version-INVARIANT; only the per-set TYPE INFERENCE (which fapd-E07 computes
/// separately) diverges across versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttrTypeCategory {
    /// Unsigned integer (`uid`, `auid`, `sessionid` always; `pid`/`ppid` on
    /// rhel8; `gid` on rhel9+): accepts a numeric set, rejects a string set.
    Unsigned,
    /// Signed integer (`pid`, `ppid` on rhel9+/1.4.x): accepts ONLY a SIGNED set
    /// (all integers with at least one negative member, e.g. `-1` or `1,-2`). A
    /// positive-int set types UNSIGNED and a non-integer set types STRING, so both
    /// are rejected ("UNSIGNED/STRING ... SIGNED expected"). On rhel8 (1.3.2)
    /// pid/ppid are `Unsigned` (first-element typing, no SIGNED type).
    Signed,
    /// String (`comm`, `exe` subject; `dir`, `ftype`, `path`, `device`,
    /// `filehash`, `sha256hash` object/either): accepts a string set, rejects a
    /// numeric set.
    Str,
    /// Permissive (`gid` on rhel8/1.3.2): accepts group NAMES as well as numbers,
    /// so string, numeric, and mixed sets all load - fapd-E07 never flags it.
    /// On rhel9+ (1.4.x) `gid` is `Unsigned` (a string/mixed set IS flagged).
    Permissive,
    /// No set accepted (`pattern`, `trust`): a `%set` here is already an Error via
    /// fapd-E04 (macro in `pattern=`/`trust=`), so fapd-E07 DEFERS to fapd-E04
    /// rather than double-reporting the same defect.
    NoSet,
}

/// Attributes fapolicyd types as an unsigned integer.
const UNSIGNED_ATTRS: &[&str] = &["uid", "auid", "sessionid"];
/// Attributes fapolicyd types as a signed integer (the `pid`/`ppid` quirk).
const SIGNED_ATTRS: &[&str] = &["pid", "ppid"];
/// Attributes fapolicyd types as a string.
const STRING_ATTRS: &[&str] = &[
    "comm",
    "exe",
    "dir",
    "ftype",
    "path",
    "device",
    "filehash",
    "sha256hash",
    // fapolicyd types `mode` (FMODE) as a STRING attribute: a numeric `%set`
    // assigned to it errors "cannot assign SIGNED set ... to the STRING attribute"
    // on 1.3.2/1.4.3/1.4.5 (differential 2026-06-01).
    "mode",
];
/// Attributes that accept names as well as numbers (no type rejection).
const PERMISSIVE_ATTRS: &[&str] = &["gid"];
/// Attributes that accept no set at all (owned by fapd-E04).
const NO_SET_ATTRS: &[&str] = &["pattern", "trust"];

/// The fapolicyd value-type category for `name`, or `None` for an unknown
/// attribute (unknown names are fapd-E01's concern) or the special `all` token.
///
/// This is the version-INVARIANT baseline (it reflects the fapolicyd 1.4.x view
/// for `pid`/`ppid` = `Signed` and the 1.3.2 view for `gid` = `Permissive`).
/// `pid`/`ppid`/`gid` are actually version-DIVERGENT in category; callers that
/// must be version-correct (fapd-E07) use [`type_category_for`] instead. The
/// invariant attributes (`Unsigned`/`Str`/`NoSet`) are identical across both.
#[must_use]
pub fn type_category(name: &str) -> Option<AttrTypeCategory> {
    if UNSIGNED_ATTRS.contains(&name) {
        Some(AttrTypeCategory::Unsigned)
    } else if SIGNED_ATTRS.contains(&name) {
        Some(AttrTypeCategory::Signed)
    } else if STRING_ATTRS.contains(&name) {
        Some(AttrTypeCategory::Str)
    } else if PERMISSIVE_ATTRS.contains(&name) {
        Some(AttrTypeCategory::Permissive)
    } else if NO_SET_ATTRS.contains(&name) {
        Some(AttrTypeCategory::NoSet)
    } else {
        None
    }
}

/// The fapolicyd value-type category for `name` under a specific `version`.
///
/// Most attributes are version-invariant and delegate to [`type_category`].
/// `pid`/`ppid` and `gid` diverge across the 1.3.2 -> 1.4.x boundary, grounded
/// 2026-06-07 via `rpm -q fapolicyd` on fapolicyd8 (1.3.2-el8) and fapolicyd9
/// (1.4.5-el9_8), reproduced with `fapolicyd --debug --permissive` (see #163 and
/// `.private-docs/fapd-e07-grounding.md`):
///
/// - `pid`/`ppid`: `Unsigned` on rhel8 (1.3.2 accepts a positive-int set, rejects
///   a string set), `Signed` on rhel9/rhel10 (1.4.5 rejects EVERY set because a
///   positive-int set types UNSIGNED, not SIGNED).
/// - `gid`: `Permissive` on rhel8 (1.3.2 accepts group NAMES, so any set loads),
///   `Unsigned` on rhel9/rhel10 (1.4.5 accepts a numeric set but rejects a
///   string/mixed set as STRING != UNSIGNED).
#[must_use]
pub fn type_category_for(
    name: &str,
    version: crate::version::TargetVersion,
) -> Option<AttrTypeCategory> {
    use crate::version::TargetVersion;
    if SIGNED_ATTRS.contains(&name) {
        // pid/ppid: INT/UNSIGNED on 1.3.2, SIGNED on 1.4.x.
        return Some(match version {
            TargetVersion::Rhel8 => AttrTypeCategory::Unsigned,
            TargetVersion::Rhel9 | TargetVersion::Rhel10 => AttrTypeCategory::Signed,
        });
    }
    if PERMISSIVE_ATTRS.contains(&name) {
        // gid: PERMISSIVE on 1.3.2, UNSIGNED on 1.4.x.
        return Some(match version {
            TargetVersion::Rhel8 => AttrTypeCategory::Permissive,
            TargetVersion::Rhel9 | TargetVersion::Rhel10 => AttrTypeCategory::Unsigned,
        });
    }
    type_category(name)
}

#[must_use]
pub fn classify(name: &str) -> Option<AttrSide> {
    if SUBJECT_ONLY.contains(&name) {
        Some(AttrSide::Subject)
    } else if OBJECT_ONLY.contains(&name) {
        Some(AttrSide::Object)
    } else if BOTH_SIDES.contains(&name) {
        Some(AttrSide::Either)
    } else {
        None
    }
}

#[must_use]
pub fn is_known(name: &str) -> bool {
    classify(name).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_known_subject_only() {
        // Regression guard: real subject attrs must still classify correctly.
        assert_eq!(classify("uid"), Some(AttrSide::Subject));
        assert_eq!(classify("exe"), Some(AttrSide::Subject));
    }

    #[test]
    fn exe_dir_and_exe_type_are_not_known_attrs() {
        // Neither is a MODERN (colon-grammar) fapolicyd attribute -
        // fapolicyd 1.3.2/1.4.3/1.4.5 all reject them there ("Field type
        // (exe_dir) is unknown"). `classify`/`is_known` model the modern,
        // flavor-agnostic baseline table, so this assertion is unchanged and
        // still correct. Doc-truth-decay correction (ATL round 2 MISS 2,
        // 2026-07-18): they ARE legal LEGACY-format subject attrs
        // (`subject-attr.c` table1, live-verified on both versions) - that
        // legacy-only legality lives in `parser::grammar::legacy_classify`,
        // not here; do not read "unknown" here as "unknown in every
        // dialect".
        assert_eq!(classify("exe_dir"), None);
        assert_eq!(classify("exe_type"), None);
        assert!(!is_known("exe_dir"));
        assert!(!is_known("exe_type"));
    }

    #[test]
    fn classify_known_object_only() {
        assert_eq!(classify("path"), Some(AttrSide::Object));
        assert_eq!(classify("filehash"), Some(AttrSide::Object));
    }

    #[test]
    fn classify_mode_is_object_only() {
        // `mode` (FMODE) is a real OBJECT-only attribute: fapolicyd 1.3.2/1.4.3/1.4.5
        // all load `... : mode=0755` but REJECT it subject-side (differential
        // 2026-06-01, .private-docs/correctness-differential-grounding.md). Its
        // absence here made fapd-E01 false-positive on every valid `mode=` rule.
        assert_eq!(classify("mode"), Some(AttrSide::Object));
        assert!(is_known("mode"));
    }

    #[test]
    fn classify_both_sides() {
        assert_eq!(classify("dir"), Some(AttrSide::Either));
        assert_eq!(classify("trust"), Some(AttrSide::Either));
        assert_eq!(classify("all"), Some(AttrSide::Either));
    }

    #[test]
    fn classify_pattern_is_subject_only() {
        // pattern is subject-only: the C subject-attr.c tables contain PATTERN
        // while object-attr.c does not, and rules.5 lists pattern under Subject
        // only. It must NOT be Either.
        assert_eq!(classify("pattern"), Some(AttrSide::Subject));
    }

    #[test]
    fn classify_unknown_attr() {
        assert_eq!(classify("xyz"), None);
        assert_eq!(classify(""), None);
    }

    #[test]
    fn is_known_agrees_with_classify() {
        assert!(is_known("uid"));
        assert!(is_known("dir"));
        assert!(!is_known("xyz"));
    }

    #[test]
    fn type_category_maps_each_category() {
        // One representative per category, grounded in fapd-e07-grounding.md.
        assert_eq!(type_category("uid"), Some(AttrTypeCategory::Unsigned));
        assert_eq!(type_category("auid"), Some(AttrTypeCategory::Unsigned));
        assert_eq!(type_category("sessionid"), Some(AttrTypeCategory::Unsigned));
        assert_eq!(type_category("pid"), Some(AttrTypeCategory::Signed));
        assert_eq!(type_category("ppid"), Some(AttrTypeCategory::Signed));
        assert_eq!(type_category("exe"), Some(AttrTypeCategory::Str));
        assert_eq!(type_category("path"), Some(AttrTypeCategory::Str));
        assert_eq!(type_category("dir"), Some(AttrTypeCategory::Str));
        assert_eq!(type_category("filehash"), Some(AttrTypeCategory::Str));
    }

    #[test]
    fn type_category_mode_is_string() {
        // The daemon itself types `mode` as STRING: assigning a numeric `%set`
        // errors "cannot assign SIGNED set ... to the STRING attribute" on all three
        // versions, while a string set loads (differential 2026-06-01). So a numeric
        // set on mode= must be a fapd-E07 finding and a string set must not.
        assert_eq!(type_category("mode"), Some(AttrTypeCategory::Str));
    }

    #[test]
    fn type_category_gid_is_permissive_not_unsigned() {
        // Grounding contradiction #1: gid accepts group NAMES, so it is PERMISSIVE,
        // NOT a numeric attribute. A wrong map that types gid Unsigned would make
        // fapd-E07 fire on a valid `gid=%groupnames` set.
        assert_eq!(type_category("gid"), Some(AttrTypeCategory::Permissive));
    }

    #[test]
    fn type_category_pattern_and_trust_are_no_set() {
        assert_eq!(type_category("pattern"), Some(AttrTypeCategory::NoSet));
        assert_eq!(type_category("trust"), Some(AttrTypeCategory::NoSet));
    }

    #[test]
    fn type_category_unknown_and_all_are_none() {
        assert_eq!(type_category("xyz"), None);
        assert_eq!(type_category(""), None);
        // `all` is the bare Attr::All token, never a `key=value`, so it has no
        // value-type category.
        assert_eq!(type_category("all"), None);
    }

    #[test]
    fn every_known_kv_attr_has_a_type_category() {
        // Completeness invariant: every attribute that `classify` knows - except
        // the special `all` token - must have a value-type category, or fapd-E07
        // would silently skip a real attribute. Kills "forgot to add attr X".
        for &name in SUBJECT_ONLY
            .iter()
            .chain(OBJECT_ONLY.iter())
            .chain(BOTH_SIDES.iter())
        {
            if name == "all" {
                continue;
            }
            assert!(
                type_category(name).is_some(),
                "known attribute `{name}` has no fapd-E07 type category",
            );
        }
    }
}
