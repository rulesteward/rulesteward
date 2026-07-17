//! fapd-W13: the merged `rules.d/` policy's LAST effective rule (in
//! fagenrules load order, across every file) is not a deny-all,
//! permit-by-exception default (DISA RHEL-08-040137 / RHEL-09-433016 /
//! RHEL-10-200602).
//!
//! Grounded in `/mnt/side-projects/9d-v0_8-wave2b/grounding/g1-g2-fapolicyd-denyall.md`
//! (G1.4 verdict): fagenrules concatenates `rules.d/*.rules` in `ls -1v` order
//! into one `compiled.rules` with NO per-file scope boundary and NO
//! byte-normalization (G1.2), so "the last effective rule" is a property of the
//! WHOLE merged stream, never a single file in isolation - a file that itself
//! ends in a clean deny-all can still be shadowed by a LATER-loading file that
//! appends something else. The predicate (G1.4): tokenize the candidate rule's
//! decision/perm/subject/object on RUNS OF SPACES (the daemon's own separator
//! tolerance; a tab is a daemon PARSE ERROR, never a rule); the rule satisfies
//! this check iff `decision` is one of `deny`, `deny_audit`, `deny_syslog`,
//! `deny_log` (the DECISION family, not just the bare literal - see G1.3/G1.4),
//! `perm` is EXACTLY `any` (STRICT - `perm=execute` is the shipped
//! `90-deny-execute.rules` default and is NOT a deny-all: it leaves `open`
//! wide open, which is exactly why stock fapolicyd appends
//! `allow perm=open all : all` after it), `subject` is exactly `all`, and
//! `object` is exactly `all` (after the `:` separator).
//!
//! `target: None` means the operator did not select a benchmark baseline, so
//! this check does not run at all (returns empty) - mirrors fapd-E06's
//! `RequiresTarget` gate. Under `Some(target)`, fires AT MOST once: a Warning
//! anchored at the LAST rule if it fails the predicate, or a file-level
//! finding (like fapd-C01/F02) anchored at the LAST FILE if the merged stream
//! contains no rules at all (nothing to be a deny-all).

use std::path::PathBuf;

use rulesteward_core::Diagnostic;

use crate::ast::Entry;
use crate::version::TargetVersion;

/// fapd-W13: the merged rules.d/ policy's last effective rule is not a
/// deny-all, permit-by-exception default. `files` must be in fagenrules load
/// order (the same convention `lint_cross_file`'s callers already use); a
/// single-file `--file` slice is just the degenerate one-file case of "the
/// merged stream" and must produce the identical verdict.
///
/// `target: None` -> always empty (this check requires an explicit
/// `--target`, matching fapd-E06's `Condition::RequiresTarget` gate - see
/// `lints::catalog`).
#[must_use]
pub fn w13(files: &[(PathBuf, Vec<Entry>)], target: Option<TargetVersion>) -> Vec<Diagnostic> {
    let _ = (files, target);
    todo!(
        "find the LAST Entry::Rule across the merged `files` stream (in the given order); \
         if none exists, emit ONE file-level fapd-W13 anchored at the LAST file; else emit \
         ONE fapd-W13 anchored at that rule's (file, line, span) iff it fails the G1.4 \
         deny-all predicate; attach lints::stig::control_refs(ControlFamily::DenyAll, target)"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rulesteward_core::Severity;

    use crate::ast::{Attr, Decision, Perm};
    use crate::lints::testkit::{kv, kv_int, modern_rule};

    // ---------------------------------------------------------------------
    // target = None: the check never runs, regardless of content.
    // ---------------------------------------------------------------------

    #[test]
    fn target_none_is_always_empty() {
        // Even an egregiously non-compliant merged stream (a bare `allow all :
        // all` as the only, and therefore last, rule) must not fire without an
        // explicit --target.
        let files = vec![(
            PathBuf::from("rules.d/95-allow.rules"),
            vec![modern_rule(
                1,
                Decision::Allow,
                Some(Perm::Any),
                vec![Attr::All],
                vec![Attr::All],
            )],
        )];
        assert!(
            w13(&files, None).is_empty(),
            "fapd-W13 requires an explicit --target and must be empty under None"
        );
    }

    // ---------------------------------------------------------------------
    // Clean (deny-all) last rules - the family match, not just the literal.
    // ---------------------------------------------------------------------

    #[test]
    fn deny_audit_perm_any_all_all_last_is_clean() {
        // `deny_audit` is a family member (G1.3/G1.4), not the bare `deny`
        // literal - this is the shipped-realistic "compliant but non-literal"
        // shape a DISA scanner would still flag but RuleSteward should not.
        let files = vec![(
            PathBuf::from("rules.d/95-final.rules"),
            vec![modern_rule(
                1,
                Decision::DenyAudit,
                Some(Perm::Any),
                vec![Attr::All],
                vec![Attr::All],
            )],
        )];
        let diags = w13(&files, Some(TargetVersion::Rhel9));
        assert!(
            diags.is_empty(),
            "deny_audit perm=any all : all is a compliant deny-all family match: {diags:?}"
        );
    }

    #[test]
    fn literal_deny_perm_any_all_all_last_is_clean() {
        let files = vec![(
            PathBuf::from("rules.d/95-final.rules"),
            vec![modern_rule(
                1,
                Decision::Deny,
                Some(Perm::Any),
                vec![Attr::All],
                vec![Attr::All],
            )],
        )];
        assert!(w13(&files, Some(TargetVersion::Rhel9)).is_empty());
    }

    // ---------------------------------------------------------------------
    // perm=execute is NOT perm=any - the wrong-impl killer named in the plan
    // (the shipped 90-deny-execute.rules rule).
    // ---------------------------------------------------------------------

    #[test]
    fn deny_perm_execute_all_all_last_fires() {
        // Byte-identical to the shipped `90-deny-execute.rules` rule
        // (`deny_audit perm=execute all : all`, G1.1): NOT a deny-all (opens
        // are still wide open) - a wrong impl that loosens `perm=any` to "any
        // perm" would wrongly call this clean.
        let files = vec![(
            PathBuf::from("rules.d/90-deny-execute.rules"),
            vec![modern_rule(
                1,
                Decision::DenyAudit,
                Some(Perm::Execute),
                vec![Attr::All],
                vec![Attr::All],
            )],
        )];
        let diags = w13(&files, Some(TargetVersion::Rhel9));
        assert_eq!(
            diags.len(),
            1,
            "perm=execute (not perm=any) must fire fapd-W13: {diags:?}"
        );
        assert_eq!(diags[0].code, "fapd-W13");
        assert_eq!(diags[0].severity, Severity::Warning);
    }

    // ---------------------------------------------------------------------
    // The shipped-default shape: last rule is `allow perm=open all : all`.
    // ---------------------------------------------------------------------

    #[test]
    fn shipped_default_shape_fires_anchored_at_last_rule_with_deny_all_controls() {
        // Mirrors G1.1's real shipped tail: the merged stream's last TWO
        // non-empty rules are `deny_audit perm=execute all : all` then
        // `allow perm=open all : all` - the LAST rule is the allow, which must
        // fire, anchored at ITS (file, line, span), carrying the DenyAll
        // family STIG control for the resolved target (G7/G8: RHEL-09-433016 /
        // V-270180 for rhel9).
        let files = vec![(
            PathBuf::from("rules.d/95-allow-open.rules"),
            vec![
                modern_rule(
                    1,
                    Decision::DenyAudit,
                    Some(Perm::Execute),
                    vec![Attr::All],
                    vec![Attr::All],
                ),
                modern_rule(
                    2,
                    Decision::Allow,
                    Some(Perm::Open),
                    vec![Attr::All],
                    vec![Attr::All],
                ),
            ],
        )];
        let diags = w13(&files, Some(TargetVersion::Rhel9));
        assert_eq!(diags.len(), 1, "exactly one fapd-W13: {diags:?}");
        let d = &diags[0];
        assert_eq!(d.code, "fapd-W13");
        assert_eq!(d.severity, Severity::Warning);
        assert_eq!(d.line, 2, "anchored at the LAST rule (line 2), not line 1");
        assert!(d.file.ends_with("95-allow-open.rules"));
        assert_eq!(
            d.controls.len(),
            1,
            "must carry exactly the DenyAll STIG control for rhel9: {d:?}"
        );
        assert_eq!(d.controls[0].id, "RHEL-09-433016");
        assert_eq!(d.controls[0].alias.as_deref(), Some("V-270180"));
    }

    // ---------------------------------------------------------------------
    // Multi-file: the MERGED stream's last rule, not any single file's.
    // ---------------------------------------------------------------------

    #[test]
    fn multi_file_fires_when_last_loading_files_final_rule_is_not_deny_all() {
        let files = vec![
            (
                PathBuf::from("rules.d/10-a.rules"),
                vec![modern_rule(
                    1,
                    Decision::Deny,
                    Some(Perm::Any),
                    vec![kv_int("uid", 0)],
                    vec![kv("path", "/x")],
                )],
            ),
            (
                PathBuf::from("rules.d/90-b.rules"),
                vec![modern_rule(
                    1,
                    Decision::Allow,
                    Some(Perm::Open),
                    vec![Attr::All],
                    vec![Attr::All],
                )],
            ),
        ];
        let diags = w13(&files, Some(TargetVersion::Rhel9));
        assert_eq!(diags.len(), 1, "{diags:?}");
        assert!(
            diags[0].file.ends_with("90-b.rules"),
            "anchored at the LAST-LOADING file: {:?}",
            diags[0].file
        );
    }

    #[test]
    fn multi_file_earlier_files_clean_deny_all_does_not_mask_a_later_allow() {
        // Adversarial pin named in the plan: an EARLIER-loading file ends with
        // a perfectly clean deny-all, but the fagenrules-order LAST file
        // appends an allow afterward. A wrong impl that checks "does ANY
        // file's own last rule satisfy the predicate" (or simply inspects the
        // FIRST file) would wrongly call this clean; the correct impl looks
        // only at the true merged-stream last rule (in the LAST file) and
        // must fire.
        let files = vec![
            (
                PathBuf::from("rules.d/10-a.rules"),
                vec![modern_rule(
                    1,
                    Decision::Deny,
                    Some(Perm::Any),
                    vec![Attr::All],
                    vec![Attr::All],
                )],
            ),
            (
                PathBuf::from("rules.d/90-b.rules"),
                vec![modern_rule(
                    1,
                    Decision::Allow,
                    None,
                    vec![kv_int("uid", 0)],
                    vec![kv("path", "/x")],
                )],
            ),
        ];
        let diags = w13(&files, Some(TargetVersion::Rhel10));
        assert_eq!(
            diags.len(),
            1,
            "an earlier file's clean deny-all must NOT mask a later-loading \
             file's trailing allow: {diags:?}"
        );
        assert!(
            diags[0].file.ends_with("90-b.rules"),
            "must anchor at the file that ACTUALLY loads last: {:?}",
            diags[0].file
        );
    }

    #[test]
    fn multi_file_clean_when_the_last_loading_files_final_rule_is_deny_all() {
        // Mirror-image regression guard: even though the FIRST file's last
        // rule is a narrow allow, the LAST-loading file's final rule is a
        // clean deny-all family match -> overall clean. Kills a wrong impl
        // that inspects the FIRST file instead of the last.
        let files = vec![
            (
                PathBuf::from("rules.d/10-a.rules"),
                vec![modern_rule(
                    1,
                    Decision::Allow,
                    None,
                    vec![kv_int("uid", 0)],
                    vec![kv("path", "/x")],
                )],
            ),
            (
                PathBuf::from("rules.d/90-b.rules"),
                vec![modern_rule(
                    1,
                    Decision::DenyAudit,
                    Some(Perm::Any),
                    vec![Attr::All],
                    vec![Attr::All],
                )],
            ),
        ];
        assert!(w13(&files, Some(TargetVersion::Rhel9)).is_empty());
    }

    #[test]
    fn single_file_slice_matches_the_equivalent_multi_file_merged_verdict() {
        // Collapsing `multi_file_earlier_files_clean_deny_all_does_not_mask_a_later_allow`'s
        // two files into ONE file, in the SAME load order, must produce the
        // IDENTICAL verdict: a single-file slice is just the degenerate
        // one-file case of "the merged stream".
        let files = vec![(
            PathBuf::from("rules.d/10-a.rules"),
            vec![
                modern_rule(
                    1,
                    Decision::Deny,
                    Some(Perm::Any),
                    vec![Attr::All],
                    vec![Attr::All],
                ),
                modern_rule(
                    2,
                    Decision::Allow,
                    None,
                    vec![kv_int("uid", 0)],
                    vec![kv("path", "/x")],
                ),
            ],
        )];
        let diags = w13(&files, Some(TargetVersion::Rhel10));
        assert_eq!(diags.len(), 1, "{diags:?}");
        assert_eq!(diags[0].line, 2, "anchored at the trailing allow, line 2");
    }

    // ---------------------------------------------------------------------
    // Zero rules anywhere: file-level finding at the LAST file.
    // ---------------------------------------------------------------------

    #[test]
    fn zero_rules_anywhere_fires_file_level_at_the_last_file() {
        let files = vec![
            (
                PathBuf::from("rules.d/10-a.rules"),
                vec![Entry::Comment {
                    text: "nothing here".to_string(),
                    line: 1,
                }],
            ),
            (
                PathBuf::from("rules.d/20-b.rules"),
                vec![Entry::Blank { line: 1 }],
            ),
        ];
        let diags = w13(&files, Some(TargetVersion::Rhel8));
        assert_eq!(
            diags.len(),
            1,
            "an empty merged ruleset must still fire (nothing IS a deny-all): {diags:?}"
        );
        let d = &diags[0];
        assert_eq!(d.code, "fapd-W13");
        assert!(
            d.file.ends_with("20-b.rules"),
            "file-level finding must anchor at the LAST file, got {:?}",
            d.file
        );
        assert_eq!(
            d.span.start, 0,
            "file-level finding has no source byte range"
        );
        assert_eq!(d.span.end, 0);
        assert!(
            d.source_id.is_none(),
            "file-level finding must not carry a source_id (mirrors fapd-C01/F02)"
        );
    }
}
