//! Known attribute names + their permitted side (subject / object / either).
//!
//! Used in two places:
//! * `parser::legacy_rule` — to positionally split the flat attribute list
//!   into `(subject, object)` halves in the legacy (no-colon) syntax.
//! * `lints::E01` — to flag unknown attribute names.
//!
//! Source: R2-audit-grammar.md, derived from
//! `src/library/{subject,object}-attr.c` in upstream fapolicyd.
//!
//! KNOWN LIMITATION (deferred to Session 3): these lists are FLAVOR-AGNOSTIC. Per R2 §"Subject attributes (legacy ORIG format)"
//! the legacy dialect is stricter than modern in two ways:
//!
//!   * `ppid`, `gid`, `trust` are NOT legal on legacy subject side.
//!   * `dir`, `ftype`, `trust` appear ONLY on legacy object side (in modern
//!     they're either-side).
//!
//! Today, `classify("dir")` returns `Either`, which is correct for modern
//! but lets the legacy positional split reject some valid legacy rules
//! (those whose object side is purely `dir/ftype/trust` without an
//! `OBJECT_ONLY` anchor like `path=`). Per plan §7 this was explicitly
//! flagged as a "do not silently relax" decision — the fix needs a
//! flavor-aware classifier and per-flavor `is_known()` semantics.

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
