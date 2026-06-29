//! Tag-state-machine lint passes: sudo-W01 (NOPASSWD applies to an ALL command -
//! passwordless run-anything; #330) and sudo-W02 (a `Cmnd_Alias` transitively
//! expands to ALL while under NOPASSWD; #332).
//!
//! # Phase 0: STUBS
//! Both passes return `Vec::new()` today. They are filled by the #330 / #332
//! pipelines,
//! which walks each user-spec's [`Cmnd_Spec_List`](crate::ast::UserSpec::cmnd_specs)
//! left-to-right, applying the sudoers tag-inheritance rule (once a tag is set it
//! inherits to subsequent commands until the opposite tag overrides it; PASSWD
//! resets NOPASSWD). When NOPASSWD is in effect on a [`CmndItem::All`](crate::ast::CmndItem::All)
//! command, W01 fires; W02 additionally walks `Cmnd_Alias` expansions to ALL. The
//! AST records the EXPLICIT per-command tags (not inheritance-resolved), so the
//! state machine lives here and the pass only EMITS - it never re-parses.

use rulesteward_core::{Diagnostic, Severity};

use crate::ast::{CmndItem, LineKind, SudoersFile, Tag};
use crate::lints::{SudoersLintContext, anchored};

/// sudo-W01: NOPASSWD (after tag inheritance) applies to an `ALL` command.
///
/// A forward tag-state machine over each user-spec's `Cmnd_Spec_List`: the
/// `sudoers(5)` rule is "once a tag is set on a Cmnd, subsequent Cmnds in the same
/// list inherit it unless overridden by the opposite tag (PASSWD overrides
/// NOPASSWD)". So a line-level regex cannot model the PASSWD reset; we walk the list
/// left-to-right, folding each command's EXPLICIT tags (the AST records the written
/// tags, NOT inheritance-resolved) into the effective NOPASSWD state, then check the
/// command. When NOPASSWD is effective AND the command is the reserved `ALL`
/// ([`CmndItem::All`]), W01 fires: passwordless run-anything.
///
/// # Anchoring
///
/// The frozen AST carries no per-command span; a user-spec is exactly one logical
/// line, so the diagnostic anchors at that line's 1-based number and byte span (the
/// offending command's line). Severity is Warning.
///
/// # v1 false-negative (reserved for #332 / sudo-W02)
///
/// A `Cmnd_Alias` that transitively expands to `ALL` (e.g. `Cmnd_Alias X = ALL` then
/// `NOPASSWD: X`) is NOT a `CmndItem::All` here - it is a named `CmndItem::Cmnd`. W01
/// keys off the LITERAL reserved `ALL` only, so this case is a documented v1
/// false-negative handled by sudo-W02. W01 must never false-positive on the alias
/// name itself.
#[must_use]
pub fn w01(files: &[SudoersFile], _ctx: &SudoersLintContext) -> Vec<Diagnostic> {
    let mut diags = Vec::new();
    for file in files {
        for logical in &file.lines {
            let LineKind::UserSpec(spec) = &logical.kind else {
                continue;
            };
            // Forward tag-state: NOPASSWD effective until an explicit PASSWD resets
            // it. Inherits across the Cmnd_Spec_List in source order.
            let mut nopasswd = false;
            for cmnd_spec in &spec.cmnd_specs {
                // Fold THIS command's explicit tags into the state BEFORE evaluating
                // it: an explicit PASSWD on the very command being checked cancels
                // inheritance for that command (e.g. `NOPASSWD: /bin/ls, PASSWD: ALL`
                // -> the ALL is password-gated).
                for tag in &cmnd_spec.tags {
                    match tag {
                        Tag::NoPasswd => nopasswd = true,
                        Tag::Passwd => nopasswd = false,
                        _ => {}
                    }
                }
                if nopasswd && cmnd_spec.cmnd == CmndItem::All {
                    diags.push(anchored(
                        Severity::Warning,
                        "sudo-W01",
                        logical.span.clone(),
                        "NOPASSWD applies to the reserved ALL command: this grants \
                         passwordless authority to run any command"
                            .to_string(),
                        file.path.clone(),
                        logical.line,
                    ));
                }
            }
        }
    }
    diags
}

/// sudo-W02: a `Cmnd_Alias` transitively expands to `ALL` while under NOPASSWD.
/// STUB in Phase 0 (#332).
#[must_use]
pub fn w02(_files: &[SudoersFile], _ctx: &SudoersLintContext) -> Vec<Diagnostic> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::w01;
    use crate::lints::SudoersLintContext;
    use crate::parser::parse;
    use std::path::Path;

    /// Parse one source string into the single-element file slice the passes take.
    fn files(src: &str) -> Vec<crate::ast::SudoersFile> {
        vec![parse(src, Path::new("/etc/sudoers"))]
    }

    /// Run W01 over `src` and return the diagnostics.
    fn lint(src: &str) -> Vec<rulesteward_core::Diagnostic> {
        let f = files(src);
        w01(&f, &SudoersLintContext::default())
    }

    /// Count the `sudo-W01` diagnostics in a W01 run.
    fn w01_count(src: &str) -> usize {
        lint(src).iter().filter(|d| d.code == "sudo-W01").count()
    }

    // ---- the adversarial seeds (each fixture verified valid via `visudo -c`) ----

    #[test]
    fn nopasswd_inherits_forward_to_a_later_all_fires() {
        // `alice ALL = NOPASSWD: /bin/systemctl, ALL` (visudo -c rc 0): NOPASSWD set
        // on the first command inherits to the second (ALL), which carries no
        // explicit tag. Run-anything passwordless -> W01.
        assert_eq!(
            w01_count("alice ALL = NOPASSWD: /bin/systemctl, ALL\n"),
            1,
            "NOPASSWD must inherit forward to a later ALL"
        );
    }

    #[test]
    fn passwd_override_before_all_does_not_fire() {
        // `bob ALL = NOPASSWD: /bin/ls, PASSWD: ALL` (visudo -c rc 0): the second
        // command carries an explicit PASSWD which resets NOPASSWD before its own
        // ALL is evaluated. No passwordless run-anything -> NO W01.
        assert_eq!(
            w01_count("bob ALL = NOPASSWD: /bin/ls, PASSWD: ALL\n"),
            0,
            "an explicit PASSWD override on the ALL command cancels inheritance"
        );
    }

    #[test]
    fn continuation_joined_nopasswd_all_fires() {
        // `carol ALL = \<newline> NOPASSWD: ALL` (visudo -c rc 0): the parser joins
        // the physical lines into one user-spec; NOPASSWD applies to ALL -> W01.
        assert_eq!(
            w01_count("carol ALL = \\\n    NOPASSWD: ALL\n"),
            1,
            "a backslash-continued NOPASSWD: ALL is one user-spec and must fire"
        );
    }

    #[test]
    fn nopasswd_on_a_non_all_command_does_not_fire() {
        // `dave ALL = NOPASSWD: /bin/ls` (visudo -c rc 0): NOPASSWD but the command
        // is a specific binary, not ALL -> NO W01.
        assert_eq!(
            w01_count("dave ALL = NOPASSWD: /bin/ls\n"),
            0,
            "NOPASSWD on a specific command is not the run-anything hazard"
        );
    }

    #[test]
    fn uid_subject_user_spec_fires() {
        // `#1000 ALL = NOPASSWD: ALL` (visudo -c rc 0): `#1000` is a UID *subject*
        // of a user-spec, NOT a comment (the parser disambiguates this). NOPASSWD on
        // ALL -> W01.
        assert_eq!(
            w01_count("#1000 ALL = NOPASSWD: ALL\n"),
            1,
            "`#1000` is a UID user-spec subject, not a comment; W01 must fire"
        );
    }

    #[test]
    fn runas_spec_present_does_not_change_tag_logic_fires() {
        // `eve ALL = (root) NOPASSWD: ALL` (visudo -c rc 0): a Runas_Spec precedes
        // the tags; it does not affect tag inheritance. NOPASSWD on ALL -> W01.
        assert_eq!(
            w01_count("eve ALL = (root) NOPASSWD: ALL\n"),
            1,
            "a (root) Runas_Spec does not change the NOPASSWD-on-ALL hazard"
        );
    }

    #[test]
    fn a_defaults_line_is_not_a_user_spec_no_w01() {
        // `Defaults:eve !authenticate` (visudo -c rc 0): a Defaults entry, not a
        // user-spec. W01 walks only user-specs -> NO W01 (and it is not F01 either).
        let diags = lint("Defaults:eve !authenticate\n");
        assert_eq!(
            diags.iter().filter(|d| d.code == "sudo-W01").count(),
            0,
            "a Defaults line is never a W01 finding"
        );
    }

    #[test]
    fn alias_expanding_to_all_is_a_documented_v1_false_negative_no_w01() {
        // `Cmnd_Alias EVERYTHING = ALL` + `frank ALL = NOPASSWD: EVERYTHING`
        // (visudo -c rc 0): the command is the *named* alias `EVERYTHING`
        // (CmndItem::Cmnd), not the reserved `ALL` (CmndItem::All). W01 keys off the
        // literal reserved ALL, so this transitively-expands-to-ALL case is a
        // documented v1 false-negative reserved for #332 / sudo-W02. W01 must NOT
        // fire here, and must NOT false-positive on the alias NAME `EVERYTHING`.
        assert_eq!(
            w01_count("Cmnd_Alias EVERYTHING = ALL\nfrank ALL = NOPASSWD: EVERYTHING\n"),
            0,
            "an alias that expands to ALL is W02 territory; W01 must not fire (and \
             must not false-positive on the alias name)"
        );
    }

    // ---- obvious clean cases ----

    #[test]
    fn a_normal_specific_command_spec_is_clean() {
        // `user host = /bin/ls` (visudo -c rc 0): no NOPASSWD, not ALL -> clean.
        assert_eq!(
            w01_count("user host = /bin/ls\n"),
            0,
            "a plain specific-command user-spec is clean"
        );
    }

    #[test]
    fn all_command_without_nopasswd_is_clean() {
        // `root ALL=(ALL:ALL) ALL` (visudo -c rc 0): ALL but NO NOPASSWD in effect.
        // The hazard is specifically NOPASSWD-on-ALL; a password-gated ALL is fine.
        assert_eq!(
            w01_count("root ALL=(ALL:ALL) ALL\n"),
            0,
            "ALL without NOPASSWD in effect is not the W01 hazard"
        );
    }

    // ---- emission metadata: severity, anchoring, span ----

    #[test]
    fn fires_with_warning_severity_and_anchors_at_the_user_spec_line() {
        // The diagnostic anchors at the offending user-spec's logical line and span,
        // with the file source_id set (so ariadne can render the caret). The AST
        // carries no per-command span, so the user-spec line is the offending
        // command's line (a user-spec is one logical line).
        let diags = lint("alice ALL = NOPASSWD: /bin/systemctl, ALL\n");
        let w01s: Vec<_> = diags.iter().filter(|d| d.code == "sudo-W01").collect();
        assert_eq!(w01s.len(), 1);
        let d = w01s[0];
        assert_eq!(d.severity, rulesteward_core::Severity::Warning);
        assert_eq!(d.line, 1, "anchors at the user-spec's 1-based line");
        assert_eq!(
            d.span,
            0..41,
            "anchors at the user-spec's logical-line byte span"
        );
        assert!(
            d.source_id.is_some(),
            "an anchored W01 carries the file source_id for ariadne rendering"
        );
        assert_eq!(d.file, Path::new("/etc/sudoers"));
    }

    #[test]
    fn continuation_case_anchors_at_the_first_physical_line() {
        // The continuation user-spec's logical line starts at physical line 1; the
        // diagnostic anchors there.
        let diags = lint("carol ALL = \\\n    NOPASSWD: ALL\n");
        let d = diags
            .iter()
            .find(|d| d.code == "sudo-W01")
            .expect("W01 fires for carol");
        assert_eq!(
            d.line, 1,
            "anchors at the logical line's first physical line"
        );
    }

    // ---- forward-state edge cases the tag machine must get right ----

    #[test]
    fn nopasswd_then_all_then_explicit_passwd_all_only_first_all_fires() {
        // `g ALL = NOPASSWD: ALL, PASSWD: ALL`: the first ALL is under NOPASSWD
        // (fires); the second ALL carries explicit PASSWD, so it is password-gated
        // (does not fire). Exactly one W01.
        assert_eq!(
            w01_count("g ALL = NOPASSWD: ALL, PASSWD: ALL\n"),
            1,
            "only the ALL reached while NOPASSWD is effective fires"
        );
    }

    #[test]
    fn two_all_commands_both_under_inherited_nopasswd_fire_twice() {
        // `h ALL = NOPASSWD: ALL, ALL`: NOPASSWD set on the first ALL inherits to the
        // second (no overriding PASSWD). Both are passwordless run-anything -> two
        // W01 findings.
        assert_eq!(
            w01_count("h ALL = NOPASSWD: ALL, ALL\n"),
            2,
            "inherited NOPASSWD fires on every subsequent ALL until a PASSWD resets"
        );
    }

    #[test]
    fn passwd_then_nopasswd_re_enables_and_a_later_all_fires() {
        // `i ALL = PASSWD: /bin/ls, NOPASSWD: ALL`: PASSWD first, then NOPASSWD set
        // on the ALL command. NOPASSWD is effective on ALL -> W01.
        assert_eq!(
            w01_count("i ALL = PASSWD: /bin/ls, NOPASSWD: ALL\n"),
            1,
            "NOPASSWD set later re-enables the hazard on a subsequent ALL"
        );
    }

    #[test]
    fn no_user_specs_at_all_is_clean() {
        // A blank / comment-only file has no user-specs -> no W01.
        assert_eq!(
            w01_count("# just a comment\n\n"),
            0,
            "a file with no user-specs produces no W01"
        );
    }

    // ---- multiple tags on ONE command: last-written tag wins (within-spec fold) ----

    #[test]
    fn passwd_then_nopasswd_on_one_command_fires_last_tag_wins() {
        // `j ALL = PASSWD:NOPASSWD: ALL` (visudo -c rc 0): both tags are written on
        // the SAME command; the last one (NOPASSWD) wins. Ground truth: `visudo -x`
        // exports `"authenticate": false` for this command, i.e. passwordless. So
        // W01 must fire. This pins the within-spec tag-fold order (left-to-right,
        // last wins) the impl applies before checking the command.
        assert_eq!(
            w01_count("j ALL = PASSWD:NOPASSWD: ALL\n"),
            1,
            "PASSWD:NOPASSWD on one command resolves to NOPASSWD (last wins); fires"
        );
    }

    #[test]
    fn nopasswd_then_passwd_on_one_command_does_not_fire_last_tag_wins() {
        // `k ALL = NOPASSWD:PASSWD: ALL` (visudo -c rc 0): the reverse order; PASSWD
        // is last and wins. Ground truth: `visudo -x` exports `"authenticate": true`
        // (password required). W01 must NOT fire.
        assert_eq!(
            w01_count("k ALL = NOPASSWD:PASSWD: ALL\n"),
            0,
            "NOPASSWD:PASSWD on one command resolves to PASSWD (last wins); no fire"
        );
    }

    // ---- cross-user-spec isolation: NOPASSWD does not bleed between lines ----

    #[test]
    fn nopasswd_does_not_bleed_into_the_next_user_spec() {
        // Two adjacent user-specs (separate logical lines): the first sets NOPASSWD
        // on an ALL (fires), the second is a tagless ALL on its own line. The tag
        // state is per-user-spec, so it must NOT leak forward: exactly ONE W01.
        // Both lines are visudo-valid.
        assert_eq!(
            w01_count("a ALL = NOPASSWD: ALL\nb ALL = ALL\n"),
            1,
            "NOPASSWD state resets at each user-spec; it must not bleed across lines"
        );
    }

    // ---- documented Phase-0 limitation: multi-host `: Host = Cmnd` lines (#330) ----

    #[test]
    fn multi_host_continuation_is_a_documented_phase0_limitation() {
        // KNOWN LIMITATION (issue #330 v1, documented in parser.rs `classify_user_spec`):
        // the frozen Phase-0 parser does NOT split a user-spec on the multi-host
        // `: Host = Cmnd_Spec_List` boundary - the `: h2 = ...` tail is swallowed into
        // the last command token of the FIRST host group. So in
        //   `alice h1 = NOPASSWD: /bin/ls : h2 = /bin/id, ALL`  (visudo -c rc 0)
        // the parser yields cmnd_specs
        //   [ {NoPasswd, Cmnd("/bin/ls : h2 = /bin/id")}, {[], ALL} ]
        // and W01 fires ONCE on the trailing `, ALL`. In REAL sudo (`visudo -x`) each
        // `: Host = ...` group is a SEPARATE Cmnd_Spec_List, so NOPASSWD does NOT
        // cross the `:` boundary and that h2 ALL is password-REQUIRED - i.e. a real
        // sudo evaluator would NOT flag it. This is a FALSE POSITIVE inherent to the
        // frozen Phase-0 AST/parser flattening, NOT fixable in this W01 pass without
        // changing the frozen parser + UserSpec AST (surfaced to the orchestrator as
        // an out-of-scope question; see the W01 task report). This test PINS the
        // current behavior so any future parser fix that adds per-host-group
        // modelling deliberately revisits this assertion.
        assert_eq!(
            w01_count("alice h1 = NOPASSWD: /bin/ls : h2 = /bin/id, ALL\n"),
            1,
            "Phase-0 multi-host flattening: W01 fires once on the swallowed-tail ALL \
             (a known false positive vs real per-host-group sudo semantics)"
        );
    }
}
