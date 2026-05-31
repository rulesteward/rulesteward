//! fapd-W01 rule shadowing detection.
//!
//! For each ordered pair of rules `(A, B)` where A appears before B in source
//! order, fapd-W01 fires on B iff A's predicates subsume B's predicates AND A's
//! decision is terminal. "A subsumes B" means every event B could match is also
//! matched by A; since fapolicyd evaluates rules top-down and stops at the first
//! terminal match, B is then unreachable.
//!
//! The subsume relation is built from four mechanisms, each grounded in
//! fapolicyd's actual matching semantics, designed for zero false-positive risk:
//!
//! 1. Decision-terminal assumption: fapolicyd treats every decision as
//!    terminal (a matched rule ends evaluation per `rules.c:eval_action`), so
//!    any earlier rule that subsumes B shadows it regardless of decision kind.
//!    `shadows` documents this inline; no per-decision gate is needed today.
//! 2. Perm subsume: A.perm covers B.perm.
//! 3. Predicate-list subsume per side (subject and object treated symmetrically):
//!    literal-equal subset, `Attr::All` shortcut, macro expansion.
//! 4. Cross-attribute `dir=` prefix hierarchy (`dir` covers `path`/`exe`).

use std::path::Path;

use rulesteward_core::{Diagnostic, Severity};

use crate::ast::Entry;
use crate::ast::Rule;

use super::anchored;
use super::subsume::{build_macro_map, shadows};

/// Run the fapd-W01 rule-shadowing pass over `entries` and return the
/// diagnostics. One fapd-W01 is emitted per later rule B that is shadowed by
/// any earlier terminal rule A.
pub(crate) fn walk(entries: &[Entry], file: &Path) -> Vec<Diagnostic> {
    let rules: Vec<&Rule> = entries
        .iter()
        .filter_map(|e| match e {
            Entry::Rule(r) => Some(r),
            _ => None,
        })
        .collect();

    let macro_map = build_macro_map(entries);

    let mut diags = Vec::new();
    // O(N^2) pairwise check. For each later rule B, search for any earlier
    // rule A that shadows it; emit at most one fapd-W01 per B (anchored to
    // the first shadowing A).
    for b_idx in 0..rules.len() {
        let b = rules[b_idx];
        for a in rules.iter().take(b_idx) {
            if shadows(a, b, &macro_map) {
                diags.push(anchored(
                    Severity::Warning,
                    "fapd-W01",
                    b.span.clone(),
                    format!(
                        "rule unreachable: shadowed by the broader rule on line {}",
                        a.line
                    ),
                    file,
                    b.line,
                ));
                break;
            }
        }
    }
    diags
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::{Attr, Decision, Perm};
    use crate::lints::testkit::{kv, kv_int, kv_ref, modern_rule, p, set_def};

    #[test]
    fn f1_identical_rules_b_shadowed() {
        // F1: `allow uid=0 : path=/bin/sh` twice -> line 2 shadowed.
        let entries = vec![
            modern_rule(
                1,
                Decision::Allow,
                None,
                vec![kv_int("uid", 0)],
                vec![kv("path", "/bin/sh")],
            ),
            modern_rule(
                2,
                Decision::Allow,
                None,
                vec![kv_int("uid", 0)],
                vec![kv("path", "/bin/sh")],
            ),
        ];
        let diags = walk(&entries, &p());
        assert_eq!(
            diags.len(),
            1,
            "expected one fapd-W01 on the duplicate: {diags:?}"
        );
        assert_eq!(diags[0].code.as_ref(), "fapd-W01");
        assert_eq!(diags[0].severity, Severity::Warning);
        assert_eq!(
            diags[0].line, 2,
            "fapd-W01 anchors on the later (shadowed) rule"
        );
        assert_eq!(diags[0].source_id, Some("/tmp/test.rules".to_string()));
    }

    #[test]
    fn f2_narrow_then_broad_not_shadowed() {
        // F2: narrow rule (perm=execute) first, broad rule second. The broad
        // rule is later so we never check "broad shadows narrow"; the narrow
        // rule's perm=execute means it does not subsume the broad rule anyway.
        let entries = vec![
            modern_rule(
                1,
                Decision::Allow,
                Some(Perm::Execute),
                vec![kv_int("uid", 0)],
                vec![kv("path", "/bin/sh")],
            ),
            modern_rule(
                2,
                Decision::Allow,
                None,
                vec![kv_int("uid", 0)],
                vec![Attr::All],
            ),
        ];
        let diags = walk(&entries, &p());
        assert!(
            diags.is_empty(),
            "narrow-then-broad must not fire fapd-W01: {diags:?}"
        );
    }

    #[test]
    fn f4_all_object_shadows_narrow_path() {
        // F4: `allow uid=0 : all` then `allow perm=execute uid=0 : path=/bin/sh`.
        // A's object is [Attr::All], which subsumes any concrete object.
        let entries = vec![
            modern_rule(
                1,
                Decision::Allow,
                None,
                vec![kv_int("uid", 0)],
                vec![Attr::All],
            ),
            modern_rule(
                2,
                Decision::Allow,
                Some(Perm::Execute),
                vec![kv_int("uid", 0)],
                vec![kv("path", "/bin/sh")],
            ),
        ];
        let diags = walk(&entries, &p());
        assert_eq!(
            diags.len(),
            1,
            "broad `all` object must shadow narrow path: {diags:?}"
        );
        assert_eq!(diags[0].line, 2);
    }

    #[test]
    fn f5_terminal_deny_all_shadows_later_allow() {
        // F5: `deny all : all` then `allow uid=0 : path=/bin/sh`. Deny is
        // terminal, and `all : all` subsumes any later rule. Exercises the
        // decision-terminal precondition with a non-Allow decision.
        let entries = vec![
            modern_rule(1, Decision::Deny, None, vec![Attr::All], vec![Attr::All]),
            modern_rule(
                2,
                Decision::Allow,
                None,
                vec![kv_int("uid", 0)],
                vec![kv("path", "/bin/sh")],
            ),
        ];
        let diags = walk(&entries, &p());
        assert_eq!(
            diags.len(),
            1,
            "terminal deny all:all must shadow the later allow: {diags:?}"
        );
        assert_eq!(diags[0].line, 2);
    }

    #[test]
    fn f6_macro_setref_shadows_literal_member() {
        // F6: `%admins=0,1000` ; `allow uid=%admins : all` ; `allow uid=0 : all`.
        // The earlier rule's `uid=%admins` ({0,1000}) covers the literal `0`.
        let entries = vec![
            set_def(1, "admins", &["0", "1000"]),
            modern_rule(
                2,
                Decision::Allow,
                None,
                vec![kv_ref("uid", "admins")],
                vec![Attr::All],
            ),
            modern_rule(
                3,
                Decision::Allow,
                None,
                vec![kv_int("uid", 0)],
                vec![Attr::All],
            ),
        ];
        let diags = walk(&entries, &p());
        assert_eq!(
            diags.len(),
            1,
            "macro set must shadow a literal member: {diags:?}"
        );
        assert_eq!(diags[0].line, 3, "the literal-uid rule is the shadowed one");
    }

    #[test]
    fn f7_dir_prefix_shadows_path_object_side() {
        // F7: `allow uid=0 : dir=/usr/bin/` then `allow uid=0 : path=/usr/bin/ls`.
        // The earlier rule's object `dir=/usr/bin/` is a byte-prefix of the
        // later rule's `path=/usr/bin/ls`.
        let entries = vec![
            modern_rule(
                1,
                Decision::Allow,
                None,
                vec![kv_int("uid", 0)],
                vec![kv("dir", "/usr/bin/")],
            ),
            modern_rule(
                2,
                Decision::Allow,
                None,
                vec![kv_int("uid", 0)],
                vec![kv("path", "/usr/bin/ls")],
            ),
        ];
        let diags = walk(&entries, &p());
        assert_eq!(
            diags.len(),
            1,
            "object-side dir prefix must shadow path: {diags:?}"
        );
        assert_eq!(diags[0].line, 2);
    }

    #[test]
    fn f7_dir_not_prefix_does_not_shadow() {
        // Same shape, but the dir is NOT a prefix of the path -> no shadow.
        let entries = vec![
            modern_rule(
                1,
                Decision::Allow,
                None,
                vec![kv_int("uid", 0)],
                vec![kv("dir", "/opt/")],
            ),
            modern_rule(
                2,
                Decision::Allow,
                None,
                vec![kv_int("uid", 0)],
                vec![kv("path", "/usr/bin/ls")],
            ),
        ];
        let diags = walk(&entries, &p());
        assert!(
            diags.is_empty(),
            "non-prefix dir must not shadow path: {diags:?}"
        );
    }

    #[test]
    fn f8_subject_dir_prefix_shadows_exe() {
        // F8: `allow dir=/usr/bin/ : all` then `allow exe=/usr/bin/python3 : all`.
        // The earlier rule's subject `dir=/usr/bin/` is a byte-prefix of the
        // later rule's subject `exe=/usr/bin/python3`.
        let entries = vec![
            modern_rule(
                1,
                Decision::Allow,
                None,
                vec![kv("dir", "/usr/bin/")],
                vec![Attr::All],
            ),
            modern_rule(
                2,
                Decision::Allow,
                None,
                vec![kv("exe", "/usr/bin/python3")],
                vec![Attr::All],
            ),
        ];
        let diags = walk(&entries, &p());
        assert_eq!(
            diags.len(),
            1,
            "subject-side dir prefix must shadow exe: {diags:?}"
        );
        assert_eq!(diags[0].line, 2);
    }

    #[test]
    fn f3_unrelated_paths_not_shadowed() {
        // F3: two rules with different object path literals -> no subsume.
        let entries = vec![
            modern_rule(
                1,
                Decision::Allow,
                None,
                vec![kv_int("uid", 0)],
                vec![kv("path", "/usr/bin/foo")],
            ),
            modern_rule(
                2,
                Decision::Allow,
                None,
                vec![kv_int("uid", 0)],
                vec![kv("path", "/usr/bin/bar")],
            ),
        ];
        let diags = walk(&entries, &p());
        assert!(
            diags.is_empty(),
            "unrelated paths must not fire fapd-W01: {diags:?}"
        );
    }
}
