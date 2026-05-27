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
    "exe_dir",
    "exe_type",
];

pub const OBJECT_ONLY: &[&str] = &["path", "device", "filehash", "sha256hash"];

pub const BOTH_SIDES: &[&str] = &["all", "dir", "ftype", "trust", "pattern"];

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
        assert_eq!(classify("uid"), Some(AttrSide::Subject));
        assert_eq!(classify("exe_dir"), Some(AttrSide::Subject));
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
