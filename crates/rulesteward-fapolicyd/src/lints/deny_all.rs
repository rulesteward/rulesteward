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

use rulesteward_core::{Diagnostic, Severity};

use crate::ast::{Attr, Decision, Entry, Perm, Rule};
use crate::lints::stig::ControlFamily;
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
    let Some(target) = target else {
        return Vec::new();
    };
    let controls = crate::lints::stig::control_refs(ControlFamily::DenyAll, target);

    // Scan the WHOLE merged stream, file by file (in the given fagenrules load
    // order) and, within each file, entry by entry: each Entry::Rule found
    // overwrites `last`, so after the scan `last` holds the merged stream's
    // TRUE final rule - a rule-free trailing file cannot mask an earlier
    // file's final rule (adversarial round 1, Finding 2).
    let mut last: Option<(&PathBuf, &Rule)> = None;
    for (path, entries) in files {
        for entry in entries {
            if let Entry::Rule(r) = entry {
                last = Some((path, r));
            }
        }
    }

    match last {
        None => {
            // No rule anywhere in the merged stream: a file-level finding
            // anchored at the LAST file (mirrors fapd-C01/F02's unanchored shape).
            let Some((last_path, _)) = files.last() else {
                return Vec::new();
            };
            vec![
                super::file_level(
                    Severity::Warning,
                    "fapd-W13",
                    "the merged rules.d/ policy contains no rules at all; a deny-all, \
                     permit-by-exception default is required",
                    last_path.clone(),
                )
                .with_controls(controls),
            ]
        }
        Some((path, rule)) => {
            if is_deny_all_family(rule) {
                Vec::new()
            } else {
                vec![
                    super::anchored(
                        Severity::Warning,
                        "fapd-W13",
                        rule.span.clone(),
                        "the merged rules.d/ policy's last effective rule is not a deny-all, \
                         permit-by-exception default (e.g. `deny perm=any all : all`)",
                        path,
                        rule.line,
                    )
                    .with_controls(controls),
                ]
            }
        }
    }
}

/// The G1.4 deny-all predicate over a STRUCTURED (already-parsed) rule:
/// decision in the deny family (`deny`/`deny_audit`/`deny_syslog`/`deny_log` -
/// not just the bare literal), `perm` EXACTLY `any` (STRICT - `perm=execute`
/// is the shipped `90-deny-execute.rules` default and is NOT a deny-all),
/// subject exactly `all`, and object exactly `all`.
fn is_deny_all_family(rule: &Rule) -> bool {
    matches!(
        rule.decision,
        Decision::Deny | Decision::DenyAudit | Decision::DenySyslog | Decision::DenyLog
    ) && rule.perm == Some(Perm::Any)
        && is_all_only(&rule.subject)
        && is_all_only(&rule.object)
}

/// Whether an attribute list is exactly the single `all` wildcard (`Attr::All`).
fn is_all_only(attrs: &[Attr]) -> bool {
    matches!(attrs, [Attr::All])
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

    #[test]
    fn deny_syslog_perm_any_all_all_last_is_clean() {
        // Adversarial round 1 (Finding 1): `deny_syslog` is the THIRD member
        // of the man-page DECISION deny family (G1.3, identical on 1.3.2 and
        // 1.4.5; "any rule with a deny in the keyword will deny access"). A
        // wrong impl accepting only {deny, deny_audit} passes every other
        // test yet wrongly fires on this compliant final rule.
        let files = vec![(
            PathBuf::from("rules.d/95-final.rules"),
            vec![modern_rule(
                1,
                Decision::DenySyslog,
                Some(Perm::Any),
                vec![Attr::All],
                vec![Attr::All],
            )],
        )];
        let diags = w13(&files, Some(TargetVersion::Rhel9));
        assert!(
            diags.is_empty(),
            "deny_syslog perm=any all : all is a compliant deny-all family match: {diags:?}"
        );
    }

    #[test]
    fn deny_log_perm_any_all_all_last_is_clean() {
        // Adversarial round 1 (Finding 1): `deny_log` is the FOURTH family
        // member (G1.3/G1.4) - same kill as deny_syslog above.
        let files = vec![(
            PathBuf::from("rules.d/95-final.rules"),
            vec![modern_rule(
                1,
                Decision::DenyLog,
                Some(Perm::Any),
                vec![Attr::All],
                vec![Attr::All],
            )],
        )];
        let diags = w13(&files, Some(TargetVersion::Rhel9));
        assert!(
            diags.is_empty(),
            "deny_log perm=any all : all is a compliant deny-all family match: {diags:?}"
        );
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
    // subject/object must be STRICTLY `all`, not just decision+perm family
    // match - mutation-kill for `is_all_only` (survivor 4: forced to `true`
    // unconditionally would bypass the subject/object strictness entirely).
    // ---------------------------------------------------------------------

    #[test]
    fn deny_perm_any_non_all_subject_last_fires() {
        // `deny perm=any uid=0 : all` (G1.4): decision is in the deny family
        // and perm is exactly `any`, but the SUBJECT is `uid=0`, not `all` -
        // this is NOT a deny-all (it only denies uid 0, not everyone), so
        // fapd-W13 must still fire. An `is_all_only` forced to always return
        // `true` would wrongly call this clean.
        let files = vec![(
            PathBuf::from("rules.d/95-final.rules"),
            vec![modern_rule(
                1,
                Decision::Deny,
                Some(Perm::Any),
                vec![kv_int("uid", 0)],
                vec![Attr::All],
            )],
        )];
        let diags = w13(&files, Some(TargetVersion::Rhel9));
        assert_eq!(
            diags.len(),
            1,
            "deny perm=any uid=0 : all has a non-`all` SUBJECT and must fire \
             fapd-W13: {diags:?}"
        );
        assert_eq!(diags[0].code, "fapd-W13");
    }

    #[test]
    fn deny_perm_any_non_all_object_last_fires() {
        // `deny perm=any all : /usr/bin/foo` (G1.4): decision and perm match,
        // subject is `all`, but the OBJECT is a single path, not `all` - this
        // denies access to one path only, not a deny-all default, so
        // fapd-W13 must still fire. Kills the same `is_all_only` forced-`true`
        // mutant from the object side (subject alone passing is not enough).
        let files = vec![(
            PathBuf::from("rules.d/95-final.rules"),
            vec![modern_rule(
                1,
                Decision::Deny,
                Some(Perm::Any),
                vec![Attr::All],
                vec![kv("path", "/usr/bin/foo")],
            )],
        )];
        let diags = w13(&files, Some(TargetVersion::Rhel9));
        assert_eq!(
            diags.len(),
            1,
            "deny perm=any all : /usr/bin/foo has a non-`all` OBJECT and must \
             fire fapd-W13: {diags:?}"
        );
        assert_eq!(diags[0].code, "fapd-W13");
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
    fn multi_file_rule_free_last_file_does_not_hide_an_earlier_clean_deny_all() {
        // Adversarial round 1 (Finding 2): the LAST-loading file contains NO
        // Entry::Rule at all - only Comment/Blank entries, realizable as a
        // trailing all-comment 99-*.rules - and the merged stream's TRUE last
        // rule (the EARLIER file's final rule) is a clean deny-all. A wrong
        // impl inspecting only `files.last()` (that file's own last rule, or
        // its zero-rules file-level branch) wrongly fires here; the correct
        // merged-stream impl is clean.
        let files = vec![
            (
                PathBuf::from("rules.d/90-deny.rules"),
                vec![modern_rule(
                    1,
                    Decision::Deny,
                    Some(Perm::Any),
                    vec![Attr::All],
                    vec![Attr::All],
                )],
            ),
            (
                PathBuf::from("rules.d/99-comments-only.rules"),
                vec![
                    Entry::Comment {
                        text: "site-local notes, no rules".to_string(),
                        line: 1,
                    },
                    Entry::Blank { line: 2 },
                ],
            ),
        ];
        let diags = w13(&files, Some(TargetVersion::Rhel9));
        assert!(
            diags.is_empty(),
            "a rule-free last-loading file must not hide the earlier file's \
             clean deny-all (the merged stream's true last rule): {diags:?}"
        );
    }

    #[test]
    fn multi_file_rule_free_last_file_anchors_at_the_earlier_files_last_rule() {
        // Mirror of the test above (adversarial round 1, Finding 2): the
        // last-loading file is rule-free, and the merged stream's true last
        // rule - the EARLIER file's final rule - is NOT a deny-all. Exactly
        // one fapd-W13 must fire, anchored at that EARLIER file's last rule
        // (file + line), never a file-level finding at the empty last file
        // and never at the earlier file's FIRST rule.
        let files = vec![
            (
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
                        3,
                        Decision::Allow,
                        Some(Perm::Open),
                        vec![Attr::All],
                        vec![Attr::All],
                    ),
                ],
            ),
            (
                PathBuf::from("rules.d/99-comments-only.rules"),
                vec![
                    Entry::Comment {
                        text: "site-local notes, no rules".to_string(),
                        line: 1,
                    },
                    Entry::Blank { line: 2 },
                ],
            ),
        ];
        let diags = w13(&files, Some(TargetVersion::Rhel9));
        assert_eq!(diags.len(), 1, "{diags:?}");
        let d = &diags[0];
        assert_eq!(d.code, "fapd-W13");
        assert_eq!(d.severity, Severity::Warning);
        assert!(
            d.file.ends_with("10-a.rules"),
            "must anchor at the EARLIER file holding the merged stream's true \
             last rule, not the rule-free last-loading file: {:?}",
            d.file
        );
        assert_eq!(
            d.line, 3,
            "anchored at the earlier file's LAST rule (line 3), not its first"
        );
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
