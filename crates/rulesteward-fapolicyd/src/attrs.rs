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
//! subject side; `trust`/`dir`/`ftype` object-only in legacy) see the
//! truth table inline in `parser::grammar::legacy_classify`. Session 3a
//! intentionally kept that knowledge parser-internal because no public
//! consumer exists yet; a future session may expose a public flavor-aware
//! API when fapd-E02 / fapd-E03 lint codes give it a concrete consumer.
//!
//! NOTE on removed names: `exe_dir` and `exe_type` were removed from
//! `SUBJECT_ONLY` on 2026-05-29. Runtime testing against fapolicyd
//! 1.3.2, 1.4.3, and 1.4.5 confirmed that both names are REJECTED with
//! "Field type (exe_dir) is unknown" - they do not appear in the man page
//! and are not valid fapolicyd attribute names. Their prior presence was a
//! false negative for fapd-E01 (RuleSteward accepted rules fapolicyd rejects).
//! The `dir=` value keywords `execdirs`/`systemdirs`/`untrusted` (handled
//! by fapd-W08) are distinct and were not affected.

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

pub const OBJECT_ONLY: &[&str] = &["path", "device", "filehash", "sha256hash"];

pub const BOTH_SIDES: &[&str] = &["all", "dir", "ftype", "trust"];

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
        // Neither is a real fapolicyd attribute - fapolicyd 1.3.2/1.4.3/1.4.5 all
        // reject them ("Field type (exe_dir) is unknown"). RuleSteward must flag
        // them via fapd-E01 (was a false negative).
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
}
