//! Tag-state-machine lint passes: sudo-W01 (NOPASSWD applies to an ALL command -
//! passwordless run-anything; #330), sudo-W02 (a `Cmnd_Alias` transitively expands
//! to ALL while under NOPASSWD; #332), and sudo-W05 (NOPASSWD in effect on any
//! specific command; DISA STIG remove-all-NOPASSWD).
//!
//! All three walk each user-spec's [`Cmnd_Spec_List`](crate::ast::UserSpec::cmnd_specs)
//! left-to-right, applying the sudoers tag-inheritance rule (once a tag is set it
//! inherits to subsequent commands until the opposite tag overrides it; PASSWD
//! resets NOPASSWD), with the running state reset per host-group. The shared
//! forward-NOPASSWD walk + tag-fold is factored into `for_each_nopasswd_command`
//! (#404); each pass supplies only its fire predicate + message. When NOPASSWD is in
//! effect: W01 fires on a [`CmndItem::All`](crate::ast::CmndItem::All) command, W02
//! on a `Cmnd_Alias` that expands to ALL, and W05 on any non-ALL command. The AST
//! records the EXPLICIT per-command tags (not inheritance-resolved), so the state
//! machine lives here and the passes only EMIT - they never re-parse.

use rulesteward_core::{Diagnostic, Severity};

use crate::ast::{CmndItem, CmndSpec, LineKind, LogicalLine, SudoersFile, Tag};
use crate::lints::{SudoersLintContext, anchored};

/// Shared forward NOPASSWD/PASSWD tag-state walker for the W01/W02/W05 family
/// (#404 DRY extraction of the rule-of-three-identical nested walk).
///
/// Walks every file's user-specs; each `:`-separated host-group is an
/// INDEPENDENT `Cmnd_Spec_List` (#345), so the forward NOPASSWD/PASSWD state
/// starts fresh per group and never crosses the `:`. Within a group, each
/// command's EXPLICIT tags (the AST records what was WRITTEN, not
/// inheritance-resolved) fold into the running state BEFORE the command is
/// evaluated -- an explicit `PASSWD` on the very command being checked cancels
/// inheritance for it, and when two tags are written on ONE command the
/// last-written one wins (both folded in source order).
///
/// `on_command` runs once per command ONLY while NOPASSWD is currently
/// effective: W01, W02, and W05 are each a `nopasswd && <predicate>` gate, so
/// a nopasswd-false command is dead weight for all three callers and the
/// walker skips invoking the callback for it entirely.
fn for_each_nopasswd_command(
    files: &[SudoersFile],
    mut on_command: impl FnMut(&SudoersFile, &LogicalLine, &CmndSpec),
) {
    for file in files {
        for logical in &file.lines {
            let LineKind::UserSpec(spec) = &logical.kind else {
                continue;
            };
            // Each `:`-separated host-group is an INDEPENDENT Cmnd_Spec_List: the
            // forward NOPASSWD/PASSWD tag-state starts fresh per group and does NOT
            // cross the `:` (#345; grounded against cvtsudoers -f json, sudo 1.9.17p2).
            for host_group in &spec.host_groups {
                // Forward tag-state: NOPASSWD effective until an explicit PASSWD
                // resets it. Inherits across this group's Cmnd_Spec_List in source
                // order.
                let mut nopasswd = false;
                for cmnd_spec in &host_group.cmnd_specs {
                    // Fold THIS command's explicit tags into the state BEFORE
                    // evaluating it: an explicit PASSWD on the very command being
                    // checked cancels inheritance for it (e.g.
                    // `NOPASSWD: /bin/ls, PASSWD: ALL` -> the ALL is password-gated).
                    for tag in &cmnd_spec.tags {
                        match tag {
                            Tag::NoPasswd => nopasswd = true,
                            Tag::Passwd => nopasswd = false,
                            _ => {}
                        }
                    }
                    if nopasswd {
                        on_command(file, logical, cmnd_spec);
                    }
                }
            }
        }
    }
}

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
/// # Grounding
///
/// DISA STIG RHEL-08-010380 / RHEL-09-611085 (`ComplianceAsCode`
/// `sudo_remove_nopasswd`), re-grounded 2026-06-29 (#363) at `ComplianceAsCode`/
/// content commit `65ccea603ee2c305fdb4c6f54cb911449d969d55`. The finding message
/// cites these ids; the firing logic (the tag-state machine below) is unchanged by
/// the citation.
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
    for_each_nopasswd_command(files, |file, logical, cmnd_spec| {
        if cmnd_spec.cmnd == CmndItem::All {
            diags.push(anchored(
                Severity::Warning,
                "sudo-W01",
                logical.span.clone(),
                "NOPASSWD applies to the reserved ALL command: this grants \
                 passwordless authority to run any command \
                 (DISA STIG RHEL-08-010380 / RHEL-09-611085)"
                    .to_string(),
                file.path.clone(),
                logical.line,
            ));
        }
    });
    diags
}

/// sudo-W02: a `Cmnd_Alias` transitively expands to the reserved `ALL` while under
/// effective NOPASSWD (#332).
///
/// W02 is the alias-expansion companion to W01. W01 keys off the LITERAL reserved
/// `ALL` ([`CmndItem::All`]) and deliberately leaves `NOPASSWD: <alias-that-is-ALL>`
/// as a documented false-negative; W02 covers exactly that case.
///
/// # Algorithm
///
/// 1. Build the set of `Cmnd_Alias` names that TRANSITIVELY expand to `ALL` via
///    [`crate::lints::aliases::cmnd_aliases_expanding_to_all`] (reuses the #331
///    alias-table construction; cycle-safe fixpoint).
/// 2. Walk each user-spec's `Cmnd_Spec_List` with the SAME forward NOPASSWD/PASSWD
///    tag-state machine the #330 / W01 pass uses (`PASSWD` overrides `NOPASSWD`;
///    state inherits across the list in source order and is per-user-spec).
/// 3. When NOPASSWD is effective AND the command is a POSITIVE named `Cmnd_Alias`
///    reference (no leading `!` - a `!ALIAS` is a deny/subtraction, not a grant)
///    whose name is in the expand-to-ALL set, fire `sudo-W02` (Warning), anchored
///    at the user-spec's logical line and byte span.
///
/// The literal-`ALL` command is `CmndItem::All` (W01's domain), never a
/// `CmndItem::Cmnd`, so W02 and W01 are mutually exclusive by construction.
#[must_use]
pub fn w02(files: &[SudoersFile], _ctx: &SudoersLintContext) -> Vec<Diagnostic> {
    let expands_to_all = crate::lints::aliases::cmnd_aliases_expanding_to_all(files);
    let mut diags = Vec::new();
    for_each_nopasswd_command(files, |file, logical, cmnd_spec| {
        // The command must be a POSITIVE named alias (no leading `!`) whose name
        // transitively expands to ALL. `CmndItem::All` is the literal reserved ALL
        // (W01's case) and is excluded here.
        if let CmndItem::Cmnd(token) = &cmnd_spec.cmnd
            && !token.starts_with('!')
            && expands_to_all.contains(token)
        {
            diags.push(anchored(
                Severity::Warning,
                "sudo-W02",
                logical.span.clone(),
                format!(
                    "NOPASSWD applies to Cmnd_Alias \"{token}\", which expands to \
                     the reserved ALL command: this grants passwordless authority \
                     to run any command"
                ),
                file.path.clone(),
                logical.line,
            ));
        }
    });
    diags
}

/// sudo-W05: NOPASSWD grants passwordless sudo on a SPECIFIC (non-`ALL`) command
/// -- the STIG-strict broad any-NOPASSWD check (#370).
///
/// W05 is the same NOPASSWD family as W01/W02 (not a `Defaults`-baseline concept,
/// which is W04's domain). It walks each user-spec's `Cmnd_Spec_List` with the SAME
/// forward NOPASSWD/PASSWD tag-state machine W01 uses (per `sudoers(5)`: a tag
/// inherits to subsequent commands until the opposite tag overrides it; `PASSWD`
/// resets `NOPASSWD`; the state is fresh per `:`-separated host-group and per
/// user-spec, #345). When NOPASSWD is effective on a command, `sudo-W05` (Warning)
/// fires EXCEPT when the command is the reserved literal `ALL` ([`CmndItem::All`])
/// -- that is W01's exact domain, and excluding it IS the dedup-against-W01 (a
/// NOPASSWD-on-`ALL` line raises W01 and NOT W05). Fires per-command (like
/// W01/W02), anchored at the user-spec's logical line and byte span; Warning
/// severity.
///
/// The dedup is scoped to W01 only (the decided #370 contract). The W02
/// alias-expands-to-`ALL` case is deliberately NOT deduped here: a
/// `NOPASSWD: <alias-that-is-ALL>` line may raise both W02 and W05.
///
/// # Grounding
///
/// DISA STIG RHEL-08-010380 / RHEL-09-611085 / OL08-00-010380
/// (`ComplianceAsCode` `sudo_remove_nopasswd`, commit
/// `65ccea603ee2c305fdb4c6f54cb911449d969d55`) -- the SAME control W01 cites, with
/// the BROADER trigger: the rule's OVAL check
/// (`^(?!#).*[\s]+NOPASSWD[\s]*\:.*$`), OCIL (`grep -ri nopasswd`), and fixtext
/// ("Remove any occurrence of NOPASSWD") flag EVERY non-comment NOPASSWD usage,
/// not only the NOPASSWD-on-`ALL` case that W01 flags.
#[must_use]
pub fn w05(files: &[SudoersFile], _ctx: &SudoersLintContext) -> Vec<Diagnostic> {
    let mut diags = Vec::new();
    for_each_nopasswd_command(files, |file, logical, cmnd_spec| {
        // Exclude the reserved literal ALL: that is W01's domain, and excluding it
        // here IS the dedup-against-W01. Every other NOPASSWD-effective command
        // (including alias references) fires.
        if cmnd_spec.cmnd != CmndItem::All {
            diags.push(anchored(
                Severity::Warning,
                "sudo-W05",
                logical.span.clone(),
                "NOPASSWD is in effect on this command: DISA STIG requires \
                 removing all NOPASSWD usage from sudoers \
                 (DISA STIG RHEL-08-010380 / RHEL-09-611085)"
                    .to_string(),
                file.path.clone(),
                logical.line,
            ));
        }
    });
    diags
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

    // ---- multi-host `: Host = Cmnd_Spec_List` segment splitting (#345) ----

    #[test]
    fn nopasswd_does_not_cross_the_host_group_colon_no_false_positive() {
        // #345: a user-spec `User h1 = ... : h2 = ...` is several host-group segments;
        // each `: Host = Cmnd_Spec_List` is an INDEPENDENT Cmnd_Spec_List, so NOPASSWD
        // does NOT cross the `:`. Grounded against cvtsudoers -f json (sudo 1.9.17p2):
        //   `alice h1 = NOPASSWD: /bin/ls : h2 = /bin/id, ALL`   (visudo -c rc 0)
        // parses as two host-groups {h1 -> NOPASSWD /bin/ls} and {h2 -> /bin/id, ALL};
        // the h2 group carries NO `authenticate:false`, so the trailing ALL is
        // password-REQUIRED and W01 must NOT fire. (Pre-#345 the flattened parser made
        // ALL inherit h1's NOPASSWD - a false positive; pinned here so it stays fixed.)
        assert_eq!(
            w01_count("alice h1 = NOPASSWD: /bin/ls : h2 = /bin/id, ALL\n"),
            0,
            "the trailing ALL belongs to the password-required h2 segment; NOPASSWD \
             does not cross the `:`, so W01 must not fire"
        );
    }

    #[test]
    fn nopasswd_all_in_first_host_group_fires_once_not_swallowed() {
        // #345 false-NEGATIVE fix: `alice h1 = NOPASSWD: ALL : h2 = ALL`. h1's ALL is
        // genuinely passwordless and MUST fire W01; h2's ALL is a separate
        // password-required segment and must NOT. Exactly one finding. Pre-#345 the
        // `: h2 = ALL` tail was swallowed into a single command token
        // `Cmnd("ALL : h2 = ALL")`, so W01 saw no `CmndItem::All` and missed it.
        assert_eq!(
            w01_count("alice h1 = NOPASSWD: ALL : h2 = ALL\n"),
            1,
            "h1's passwordless ALL fires exactly once; h2's ALL is password-required"
        );
    }

    #[test]
    fn nopasswd_all_in_a_later_host_group_fires() {
        // The passwordless ALL is in the SECOND `:`-separated segment; the per-group
        // tag-state machine must still catch it, and the first group's plain /bin/ls
        // must not fire. `alice h1 = /bin/ls : h2 = NOPASSWD: ALL` (visudo -c rc 0).
        assert_eq!(
            w01_count("alice h1 = /bin/ls : h2 = NOPASSWD: ALL\n"),
            1,
            "h2's passwordless ALL fires; h1's /bin/ls does not"
        );
    }

    #[test]
    fn quoted_paren_in_command_does_not_hide_a_later_nopasswd_all() {
        // #345 adversarial-review fix: an unbalanced `(` in a double-quoted command
        // argument in the FIRST segment must not swallow the `: h2 = NOPASSWD: ALL`
        // segment. visudo -c rc 0; cvtsudoers shows h2 with authenticate:false + ALL, so
        // W01 must fire exactly once.
        assert_eq!(
            w01_count("alice h1 = /bin/sh -c \"a(b\" : h2 = NOPASSWD: ALL\n"),
            1,
            "the h2 passwordless ALL must not be hidden by a quoted `(` in h1's command"
        );
    }

    #[test]
    fn escaped_comma_tail_all_is_a_literal_arg_not_reserved_all_no_w01() {
        // `alice ALL = NOPASSWD: /bin/echo a\,ALL` (visudo -c -f rc 0, sudo 1.9.17p2):
        // the `\,` is an ESCAPED literal comma, so the whole token is ONE command,
        // `/bin/echo a,ALL`. cvtsudoers -f json reports exactly one command with
        // authenticate:false; the tail `ALL` is a literal command ARGUMENT, NOT the
        // reserved ALL built-in. So W01 must fire ZERO times.
        //
        // RED on the current shared parser: `parse_cmnd_spec_list` splits on a raw `,`
        // (escape-UNAWARE), so it sees a second token `ALL` and misclassifies it as
        // `CmndItem::All` -> a spurious W01 false positive. Same root cause as the W05
        // escaped-comma test; the fix makes the command split `\,`-aware (mirroring the
        // `\:` handling in split_top_level_segments). Tests only -- the implementer
        // fixes the parser.
        assert_eq!(
            w01_count("alice ALL = NOPASSWD: /bin/echo a\\,ALL\n"),
            0,
            "escaped-comma tail 'ALL' is a literal command arg, not reserved ALL"
        );
    }

    // ---- STIG citation (#363): the W01 NOPASSWD-on-ALL finding cites its control ----

    /// The W01 finding message carries the grounded DISA STIG citation
    /// RHEL-08-010380 / RHEL-09-611085 (`ComplianceAsCode` `sudo_remove_nopasswd`,
    /// re-grounded 2026-06-29 at commit
    /// `65ccea603ee2c305fdb4c6f54cb911449d969d55`). Only the message changes; the
    /// firing logic is unchanged.
    #[test]
    fn w01_message_cites_grounded_stig_control() {
        let diags = lint("alice ALL = NOPASSWD: ALL\n");
        let d = diags
            .iter()
            .find(|d| d.code == "sudo-W01")
            .expect("W01 fires for alice");
        assert!(
            d.message.contains("RHEL-08-010380"),
            "W01 message must cite RHEL-08-010380; got {:?}",
            d.message
        );
        assert!(
            d.message.contains("RHEL-09-611085"),
            "W01 message must cite RHEL-09-611085; got {:?}",
            d.message
        );
    }
}

#[cfg(test)]
mod w02_tests {
    use super::{w01, w02};
    use crate::lints::SudoersLintContext;
    use crate::parser::parse;
    use std::path::Path;

    /// Parse one source string into the single-element file slice the passes take.
    fn files(src: &str) -> Vec<crate::ast::SudoersFile> {
        vec![parse(src, Path::new("/etc/sudoers"))]
    }

    /// Run W02 over `src` and return the diagnostics.
    fn lint(src: &str) -> Vec<rulesteward_core::Diagnostic> {
        let f = files(src);
        w02(&f, &SudoersLintContext::default())
    }

    /// Count the `sudo-W02` diagnostics in a W02 run.
    fn w02_count(src: &str) -> usize {
        lint(src).iter().filter(|d| d.code == "sudo-W02").count()
    }

    /// Count the `sudo-W01` diagnostics over `src` (for the W01/W02 boundary tests).
    fn w01_count(src: &str) -> usize {
        let f = files(src);
        w01(&f, &SudoersLintContext::default())
            .iter()
            .filter(|d| d.code == "sudo-W01")
            .count()
    }

    // ---- the adversarial seeds (each fixture verified VALID via `visudo -c -f`,
    // sudo 1.9.17p2) ----

    #[test]
    fn headline_alias_directly_is_all_under_nopasswd_fires() {
        // `Cmnd_Alias EVERYTHING = ALL` + `frank ALL = NOPASSWD: EVERYTHING`
        // (visudo -c rc 0): the command is the named alias EVERYTHING, whose single
        // member is the reserved ALL. Under effective NOPASSWD this grants
        // passwordless run-anything via the alias -> W02 fires. This is the issue's
        // headline case and exactly the documented W01 false-negative (W01 keys off
        // the LITERAL ALL only; the command here is `CmndItem::Cmnd("EVERYTHING")`).
        assert_eq!(
            w02_count("Cmnd_Alias EVERYTHING = ALL\nfrank ALL = NOPASSWD: EVERYTHING\n"),
            1,
            "an alias whose member is ALL, under NOPASSWD, must fire W02"
        );
    }

    #[test]
    fn transitive_b_to_a_to_all_under_nopasswd_fires() {
        // `Cmnd_Alias A = ALL` + `Cmnd_Alias B = A, /bin/ls` + `bob ALL = NOPASSWD: B`
        // (visudo -c rc 0): B does not directly list ALL, but its member A is a
        // Cmnd_Alias that expands to ALL. Reachability B -> A -> ALL -> W02 fires.
        assert_eq!(
            w02_count("Cmnd_Alias A = ALL\nCmnd_Alias B = A, /bin/ls\nbob ALL = NOPASSWD: B\n"),
            1,
            "transitive expansion B -> A -> ALL must fire W02"
        );
    }

    #[test]
    fn alias_that_does_not_expand_to_all_does_not_fire() {
        // `Cmnd_Alias OPS = /bin/systemctl, /bin/journalctl`
        // + `carol ALL = NOPASSWD: OPS` (visudo -c rc 0): OPS is a bounded set of
        // specific binaries; it never reaches ALL -> NO W02.
        assert_eq!(
            w02_count(
                "Cmnd_Alias OPS = /bin/systemctl, /bin/journalctl\ncarol ALL = NOPASSWD: OPS\n"
            ),
            0,
            "an alias of specific commands does not expand to ALL: no W02"
        );
    }

    #[test]
    fn alias_expands_to_all_but_not_under_nopasswd_does_not_fire() {
        // `Cmnd_Alias EVERYTHING = ALL` + `dave ALL = PASSWD: EVERYTHING`
        // (visudo -c rc 0): the alias expands to ALL, but the command carries an
        // explicit PASSWD, so NOPASSWD is NOT effective. Password-gated run-anything
        // is not the W02 hazard -> NO W02.
        assert_eq!(
            w02_count("Cmnd_Alias EVERYTHING = ALL\ndave ALL = PASSWD: EVERYTHING\n"),
            0,
            "an alias-expands-to-ALL command under PASSWD (not NOPASSWD) does not fire"
        );
    }

    #[test]
    fn alias_expands_to_all_with_no_tag_at_all_does_not_fire() {
        // `Cmnd_Alias EVERYTHING = ALL` + `gus ALL = EVERYTHING` (visudo -c rc 0):
        // no NOPASSWD anywhere -> the default password-required policy applies -> NO
        // W02 (W02 is specifically the NOPASSWD-on-alias-that-is-ALL hazard).
        assert_eq!(
            w02_count("Cmnd_Alias EVERYTHING = ALL\ngus ALL = EVERYTHING\n"),
            0,
            "an alias-expands-to-ALL command with no NOPASSWD in effect does not fire"
        );
    }

    #[test]
    fn literal_all_under_nopasswd_is_w01_not_w02() {
        // `frank ALL = NOPASSWD: ALL` (visudo -c rc 0): the command is the LITERAL
        // reserved ALL (`CmndItem::All`), which is W01's domain. W02 covers ONLY the
        // alias-expansion case, so W02 must NOT fire here (and W01 must).
        assert_eq!(
            w02_count("frank ALL = NOPASSWD: ALL\n"),
            0,
            "literal ALL under NOPASSWD is W01 territory; W02 must not fire"
        );
        assert_eq!(
            w01_count("frank ALL = NOPASSWD: ALL\n"),
            1,
            "W01 still owns the literal-ALL case"
        );
    }

    #[test]
    fn nopasswd_inherits_forward_to_a_later_alias_that_is_all_fires() {
        // `Cmnd_Alias EVERYTHING = ALL` + `eve ALL = NOPASSWD: /bin/ls, EVERYTHING`
        // (visudo -c rc 0): NOPASSWD set on the first command (/bin/ls) inherits
        // forward to EVERYTHING (the alias carries no own tag). The inherited
        // NOPASSWD applies to an alias-that-is-ALL -> W02 fires on EVERYTHING.
        assert_eq!(
            w02_count("Cmnd_Alias EVERYTHING = ALL\neve ALL = NOPASSWD: /bin/ls, EVERYTHING\n"),
            1,
            "NOPASSWD inherits forward to a later alias-that-is-ALL: W02 fires"
        );
    }

    #[test]
    fn alias_cycle_with_no_all_terminates_and_does_not_fire() {
        // `Cmnd_Alias X = Y` + `Cmnd_Alias Y = X` + `u ALL = NOPASSWD: X`
        // (visudo -c rc 0): X and Y form a cycle that never reaches the reserved
        // ALL. The reachability walk MUST terminate (cycle guard) and NOT fire -> NO
        // W02, no hang.
        assert_eq!(
            w02_count("Cmnd_Alias X = Y\nCmnd_Alias Y = X\nu ALL = NOPASSWD: X\n"),
            0,
            "an alias cycle that never reaches ALL terminates and does not fire"
        );
    }

    // ---- W01/W02 boundary: each owns exactly its case ----

    #[test]
    fn w01_does_not_fire_on_the_alias_expansion_case() {
        // The headline W02 case must NOT trip W01: the command is the named alias,
        // not the literal ALL. (This is the SAME source the W01 module asserts is a
        // documented v1 false-negative; here we re-pin it from the W02 module's
        // perspective so the boundary is locked from both sides.)
        assert_eq!(
            w01_count("Cmnd_Alias EVERYTHING = ALL\nfrank ALL = NOPASSWD: EVERYTHING\n"),
            0,
            "W01 must not fire on an alias that expands to ALL (that is W02's case)"
        );
    }

    // ---- cross-user-spec isolation (NOPASSWD state is per-user-spec) ----

    #[test]
    fn nopasswd_does_not_bleed_across_user_specs_for_w02() {
        // `Cmnd_Alias EVERYTHING = ALL` + `a ALL = NOPASSWD: EVERYTHING`
        // + `b ALL = EVERYTHING` (visudo -c rc 0): the first user-spec is under
        // NOPASSWD (fires); the second is a tagless EVERYTHING on its own line. Tag
        // state is per-user-spec, so it must NOT leak forward -> exactly ONE W02.
        assert_eq!(
            w02_count(
                "Cmnd_Alias EVERYTHING = ALL\na ALL = NOPASSWD: EVERYTHING\nb ALL = EVERYTHING\n"
            ),
            1,
            "NOPASSWD state resets at each user-spec; it must not bleed across lines"
        );
    }

    // ---- within-spec tag fold: explicit PASSWD on the alias command cancels it ----

    #[test]
    fn explicit_passwd_on_the_alias_command_cancels_inheritance_no_fire() {
        // `Cmnd_Alias EVERYTHING = ALL`
        // + `u ALL = NOPASSWD: /bin/ls, PASSWD: EVERYTHING` (visudo -c rc 0): the
        // alias command carries an explicit PASSWD which resets the inherited
        // NOPASSWD before it is evaluated -> NO W02 (password-gated).
        assert_eq!(
            w02_count(
                "Cmnd_Alias EVERYTHING = ALL\nu ALL = NOPASSWD: /bin/ls, PASSWD: EVERYTHING\n"
            ),
            0,
            "an explicit PASSWD on the alias-that-is-ALL command cancels inheritance"
        );
    }

    // ---- diamond / self-cycle reachability (terminate + no double-count) ----

    #[test]
    fn diamond_reachability_to_all_fires_exactly_once() {
        // `A = ALL`, `B = A`, `C = A`, `D = B, C`, `e ALL = NOPASSWD: D`
        // (visudo -c rc 0): D reaches ALL via TWO paths (D->B->A->ALL and
        // D->C->A->ALL). The walk must visit A once (cycle/visited guard) and the
        // single command D must fire exactly ONE W02 (one finding per command, not
        // per path).
        assert_eq!(
            w02_count(
                "Cmnd_Alias A = ALL\nCmnd_Alias B = A\nCmnd_Alias C = A\nCmnd_Alias D = B, C\ne ALL = NOPASSWD: D\n"
            ),
            1,
            "a diamond that reaches ALL via two paths fires exactly one W02"
        );
    }

    #[test]
    fn self_cycle_containing_all_terminates_and_fires() {
        // `Cmnd_Alias Z = Z, ALL` + `u ALL = NOPASSWD: Z` (visudo -c rc 0; visudo
        // notes "cycle in Cmnd_Alias Z" but still accepts the file): Z references
        // itself AND lists the reserved ALL. The walk must terminate on the self
        // reference (visited guard) and still detect the ALL member -> W02 fires.
        assert_eq!(
            w02_count("Cmnd_Alias Z = Z, ALL\nu ALL = NOPASSWD: Z\n"),
            1,
            "a self-referential alias that also lists ALL terminates and fires"
        );
    }

    // ---- negation: a negated alias is a DENY/subtraction, not a run-anything grant ----

    #[test]
    fn negated_alias_command_does_not_fire() {
        // `Cmnd_Alias EVERYTHING = ALL` + `u ALL = NOPASSWD: !EVERYTHING`
        // (visudo -c rc 0): the command token is `!EVERYTHING`. visudo -x exports it
        // as `"cmndalias": "EVERYTHING", "negated": true` - a passwordless DENY of
        // everything, the OPPOSITE of run-anything. So W02 must NOT fire. (Mirrors
        // W01: a `!ALL` command is `CmndItem::Cmnd("!ALL")`, not `CmndItem::All`, so
        // W01 already does not fire on negated literal ALL.)
        assert_eq!(
            w02_count("Cmnd_Alias EVERYTHING = ALL\nu ALL = NOPASSWD: !EVERYTHING\n"),
            0,
            "a negated alias command (!EVERYTHING) is a deny, not a run-anything grant"
        );
    }

    #[test]
    fn negated_member_does_not_make_an_alias_expand_to_all() {
        // `Cmnd_Alias A = ALL` + `Cmnd_Alias B = !A, /bin/ls` + `u ALL = NOPASSWD: B`
        // (visudo -c rc 0): B's member `!A` is `"cmndalias": "A", "negated": true` -
        // a subtraction of everything A matches, leaving effectively just /bin/ls. B
        // does NOT grant run-anything -> NO W02. A POSITIVE member is required to
        // contribute the expand-to-ALL grant.
        assert_eq!(
            w02_count("Cmnd_Alias A = ALL\nCmnd_Alias B = !A, /bin/ls\nu ALL = NOPASSWD: B\n"),
            0,
            "a negated member (!A) subtracts; it must not make B expand-to-ALL"
        );
    }

    #[test]
    fn negated_alias_member_to_all_does_not_propagate_expansion() {
        // `Cmnd_Alias A = ALL` + `Cmnd_Alias B = !A` + `bob ALL = NOPASSWD: B`
        // (visudo -c rc 0): B's ONLY member is `!A`, a negation of the
        // alias-that-is-ALL. visudo -x exports it `"cmndalias": "A", "negated": true`
        // - B denies everything A matches, so B does NOT expand to ALL -> NO W02.
        // Pins the `!`-guard on the expansion edge: a `!A` member must not create an
        // ALL-propagating edge (it would if the bare `is_alias_ref` alone decided the
        // edge).
        assert_eq!(
            w02_count("Cmnd_Alias A = ALL\nCmnd_Alias B = !A\nbob ALL = NOPASSWD: B\n"),
            0,
            "a negated alias-to-ALL member (!A) must not propagate the expansion"
        );
    }

    #[test]
    fn negated_literal_all_member_does_not_expand_to_all() {
        // `Cmnd_Alias B = !ALL, /bin/ls` + `u ALL = NOPASSWD: B` (visudo -c rc 0):
        // B's member `!ALL` is a negated literal ALL (deny everything), plus
        // /bin/ls. B does not grant run-anything -> NO W02. A POSITIVE literal ALL
        // member is required.
        assert_eq!(
            w02_count("Cmnd_Alias B = !ALL, /bin/ls\nu ALL = NOPASSWD: B\n"),
            0,
            "a negated literal-ALL member (!ALL) must not make B expand-to-ALL"
        );
    }

    // ---- robustness: undefined alias members do not crash or hang ----

    #[test]
    fn undefined_alias_member_does_not_hang_and_does_not_fire() {
        // `Cmnd_Alias B = MISSING, /bin/ls` + `u ALL = NOPASSWD: B` (visudo -c rc 0;
        // visudo notes MISSING is referenced-but-not-defined, that is E01's concern).
        // The W02 walk reaches MISSING, finds no definition, and treats it as a
        // non-expanding leaf -> NO W02, no hang.
        assert_eq!(
            w02_count("Cmnd_Alias B = MISSING, /bin/ls\nu ALL = NOPASSWD: B\n"),
            0,
            "an undefined member is a non-expanding leaf; no hang, no W02"
        );
    }

    #[test]
    fn colon_separated_cmnd_alias_spec_w02_fires() {
        // #345: the sudoers(5) grammar allows MULTIPLE `Cmnd_Alias_Spec`s on one line,
        // separated by `:` - `Cmnd_Alias` Cmnd_Alias_Spec (`:` Cmnd_Alias_Spec)*. So
        //   `Cmnd_Alias A = ALL : B = /bin/ls`
        // defines TWO aliases (A=ALL, B=/bin/ls); cvtsudoers -f json (sudo 1.9.17p2)
        // shows both `Command_Aliases` A and B, and A expands to ALL. Therefore
        // `bob ALL = NOPASSWD: A` is a passwordless-run-anything finding and W02 MUST
        // fire. Pre-#345 the `: B = /bin/ls` tail was swallowed into A's single member
        // token, so A was never seen as expanding-to-ALL and W02 missed it.
        //
        // Fixture is `visudo -c -f` rc 0 (sudo 1.9.17p2).
        assert_eq!(
            w02_count("Cmnd_Alias A = ALL : B = /bin/ls\nbob ALL = NOPASSWD: A\n"),
            1,
            "the colon-form alias A => ALL must fire W02 under NOPASSWD"
        );
    }

    #[test]
    fn quoted_paren_in_command_does_not_hide_a_later_w02_alias() {
        // #345 adversarial-review fix (W02 analog of the W01 quoted-paren case): an
        // unbalanced `(` in a double-quoted command argument in h1 must not swallow the
        // `: h2 = NOPASSWD: EVERYTHING` segment where EVERYTHING => ALL. visudo -c rc 0.
        assert_eq!(
            w02_count(
                "Cmnd_Alias EVERYTHING = ALL\ndeploy h1 = /usr/bin/awk \"x(\" : h2 = NOPASSWD: EVERYTHING\n"
            ),
            1,
            "the h2 NOPASSWD alias-expanding-to-ALL must not be hidden by a quoted `(`"
        );
    }

    #[test]
    fn no_user_specs_at_all_is_clean_for_w02() {
        // A file with no user-specs (just an alias definition) has nothing to walk
        // for W02 -> no findings.
        assert_eq!(
            w02_count("Cmnd_Alias EVERYTHING = ALL\n"),
            0,
            "an alias definition with no user-spec referencing it produces no W02"
        );
    }

    // ---- emission metadata: severity, anchoring, span ----

    #[test]
    fn fires_with_warning_severity_and_anchors_at_the_user_spec_line() {
        // The W02 diagnostic anchors at the offending user-spec's logical line and
        // byte span, carries the file source_id (for ariadne), and is Warning
        // severity. The source string places the user-spec on physical line 2.
        let src = "Cmnd_Alias EVERYTHING = ALL\nfrank ALL = NOPASSWD: EVERYTHING\n";
        let diags = lint(src);
        let w02s: Vec<_> = diags.iter().filter(|d| d.code == "sudo-W02").collect();
        assert_eq!(w02s.len(), 1);
        let d = w02s[0];
        assert_eq!(d.severity, rulesteward_core::Severity::Warning);
        assert_eq!(d.line, 2, "anchors at the user-spec's 1-based line");
        // The user-spec is the second logical line: its byte span starts after the
        // 28-byte first line (`Cmnd_Alias EVERYTHING = ALL\n`).
        let spec_start = "Cmnd_Alias EVERYTHING = ALL\n".len();
        assert_eq!(
            d.span,
            spec_start..src.len() - 1,
            "anchors at the user-spec's logical-line byte span"
        );
        assert!(
            d.source_id.is_some(),
            "an anchored W02 carries the file source_id for ariadne rendering"
        );
        assert_eq!(d.file, Path::new("/etc/sudoers"));
    }

    #[test]
    fn message_names_the_alias_and_describes_the_hazard() {
        // The operator-facing message names the offending alias and conveys the
        // passwordless-run-anything-via-alias hazard.
        let diags = lint("Cmnd_Alias EVERYTHING = ALL\nfrank ALL = NOPASSWD: EVERYTHING\n");
        let d = diags
            .iter()
            .find(|d| d.code == "sudo-W02")
            .expect("W02 fires for frank");
        assert!(
            d.message.contains("EVERYTHING"),
            "the message names the offending Cmnd_Alias; got {:?}",
            d.message
        );
        assert!(
            d.message.to_ascii_uppercase().contains("ALL"),
            "the message mentions the ALL expansion; got {:?}",
            d.message
        );
    }
}

#[cfg(test)]
mod w05_tests {
    //! sudo-W05 (#370): the STIG-strict BROAD any-NOPASSWD check.
    //!
    //! W05 fires when NOPASSWD is effective (after the same forward tag-inheritance /
    //! PASSWD-reset / per-host-group state machine W01 uses) on a command that is NOT
    //! the reserved literal `ALL` -- excluding `CmndItem::All` IS the dedup against
    //! W01, which owns exactly the NOPASSWD-on-`ALL` case.
    //!
    //! Grounding: `ComplianceAsCode` `sudo_remove_nopasswd` (commit
    //! `65ccea603ee2c305fdb4c6f54cb911449d969d55`), OVAL pattern
    //! `^(?!#).*[\s]+NOPASSWD[\s]*\:.*$` flags EVERY non-comment NOPASSWD usage;
    //! DISA STIG RHEL-08-010380 / RHEL-09-611085 / OL08-00-010380. Every fixture is
    //! verified `visudo -c -f` rc 0 and (where tag inheritance matters) its per-command
    //! `authenticate` state confirmed via `cvtsudoers -f json` on sudo 1.9.17p2.

    use super::{w01, w05};
    use crate::lints::SudoersLintContext;
    use crate::parser::parse;
    use std::path::Path;

    /// Parse one source string into the single-element file slice the passes take.
    fn files(src: &str) -> Vec<crate::ast::SudoersFile> {
        vec![parse(src, Path::new("/etc/sudoers"))]
    }

    /// Run W05 over `src` and return the diagnostics.
    fn lint_w05(src: &str) -> Vec<rulesteward_core::Diagnostic> {
        w05(&files(src), &SudoersLintContext::default())
    }

    /// Count the `sudo-W05` diagnostics over `src`.
    fn w05_count(src: &str) -> usize {
        lint_w05(src)
            .iter()
            .filter(|d| d.code == "sudo-W05")
            .count()
    }

    /// Count the `sudo-W01` diagnostics over `src` (for the W05/W01 dedup boundary).
    fn w01_count(src: &str) -> usize {
        w01(&files(src), &SudoersLintContext::default())
            .iter()
            .filter(|d| d.code == "sudo-W01")
            .count()
    }

    // ---- POSITIVE: NOPASSWD on a specific command (the case W01 misses) ----

    /// `alice ALL=(root) NOPASSWD: /usr/bin/systemctl` (visudo -c -f rc 0, sudo
    /// 1.9.17p2): NOPASSWD on a SPECIFIC command, not the reserved `ALL`. W01 keys off
    /// the literal `ALL` only, so it does NOT catch this; the STIG-strict broad check
    /// (W05) MUST fire. Grounding: `sudo_remove_nopasswd` flags any non-comment
    /// NOPASSWD usage (DISA STIG RHEL-08-010380 / RHEL-09-611085).
    #[test]
    fn w05_fires_for_nopasswd_on_a_specific_command() {
        assert_eq!(
            w05_count("alice ALL=(root) NOPASSWD: /usr/bin/systemctl\n"),
            1,
            "W05 must fire for NOPASSWD on a specific (non-ALL) command"
        );
        // And W01 must NOT fire: this is not the literal-ALL run-anything hazard.
        assert_eq!(
            w01_count("alice ALL=(root) NOPASSWD: /usr/bin/systemctl\n"),
            0,
            "W01 must not fire on NOPASSWD applied to a specific command"
        );
    }

    // ---- #416: a visudo-VALID unbalanced quote / mid-command `(` used to MERGE two
    //      Cmnd_Specs (comma splitter) or two host-groups (colon splitter) in the parser,
    //      hiding the later `NOPASSWD:` grant -> a W05 FALSE NEGATIVE. After the parser
    //      fix W05 must fire exactly once on the hidden grant. Each config is `visudo -c`
    //      rc 0 and `cvtsudoers -f json` (sudo 1.9.17p2) yields TWO specs, the 2nd
    //      (`/bin/su`) passwordless -- so exactly one W05 (the 1st spec is password-required).

    #[test]
    fn w05_fires_past_an_unterminated_quote_hiding_a_grant() {
        // `alice ALL=(ALL) /bin/echo "x, NOPASSWD: /bin/su` (visudo -c rc 0). cvtsudoers
        // -f json: TWO commands, the 2nd (`/bin/su`) passwordless. The lone `"` must not
        // swallow the `,` and hide the NOPASSWD grant (#416).
        assert_eq!(
            w05_count("alice ALL=(ALL) /bin/echo \"x, NOPASSWD: /bin/su\n"),
            1,
            "W05 must fire on the NOPASSWD grant hidden past an unterminated quote (#416)"
        );
    }

    #[test]
    fn w05_fires_past_a_mid_command_paren_hiding_a_grant() {
        // `alice ALL=(ALL) /bin/echo a(b, NOPASSWD: /bin/su` (visudo -c rc 0). cvtsudoers
        // -f json: TWO commands, the 2nd (`/bin/su`) passwordless. A mid-command `(` must
        // not swallow the `,` and hide the NOPASSWD grant (#416).
        assert_eq!(
            w05_count("alice ALL=(ALL) /bin/echo a(b, NOPASSWD: /bin/su\n"),
            1,
            "W05 must fire on the NOPASSWD grant hidden past a mid-command `(` (#416)"
        );
    }

    #[test]
    fn w05_fires_past_an_unterminated_quote_hiding_a_host_group_grant() {
        // Colon-splitter analog: `alice localhost = /bin/echo "x : localhost = NOPASSWD:
        // /bin/su` (visudo -c rc 0). cvtsudoers -f json: TWO host-groups, the 2nd
        // (`/bin/su`) passwordless. The lone `"` must not swallow the top-level `:` (#416).
        assert_eq!(
            w05_count("alice localhost = /bin/echo \"x : localhost = NOPASSWD: /bin/su\n"),
            1,
            "W05 must fire on the grant hidden past an unterminated quote across `:` (#416)"
        );
    }

    #[test]
    fn w05_fires_past_a_mid_command_paren_hiding_a_host_group_grant() {
        // Colon-splitter analog: `alice localhost = /bin/echo a(b : localhost = NOPASSWD:
        // /bin/su` (visudo -c rc 0). cvtsudoers -f json: TWO host-groups, the 2nd
        // (`/bin/su`) passwordless. A mid-command `(` must not swallow the `:` (#416).
        assert_eq!(
            w05_count("alice localhost = /bin/echo a(b : localhost = NOPASSWD: /bin/su\n"),
            1,
            "W05 must fire on the grant hidden past a mid-command `(` across `:` (#416)"
        );
    }

    #[test]
    fn w05_fires_past_a_mid_command_eq_paren_hiding_a_host_group_grant() {
        // #416 round 2 (colon splitter): a command arg `X=(y` re-armed the runas position
        // at the `=`, so the `(` desynced `depth` and swallowed the top-level `:`, hiding
        // the second host-group's grant. `alice ALL = /bin/echo X=(y : ALL = NOPASSWD:
        // /bin/su` (visudo -c rc 0). cvtsudoers -f json: TWO host-groups, 2nd (`/bin/su`)
        // passwordless -> exactly one W05.
        assert_eq!(
            w05_count("alice ALL = /bin/echo X=(y : ALL = NOPASSWD: /bin/su\n"),
            1,
            "W05 must fire on the grant hidden past a mid-command `=(` across `:` (#416)"
        );
    }

    #[test]
    fn w05_fires_past_a_quoted_eq_paren_hiding_a_host_group_grant() {
        // Quoted twin of the above: `alice ALL = /bin/echo "a=(b" : ALL = NOPASSWD:
        // /bin/su` (visudo -c rc 0). cvtsudoers -f json: TWO host-groups, 2nd passwordless.
        assert_eq!(
            w05_count("alice ALL = /bin/echo \"a=(b\" : ALL = NOPASSWD: /bin/su\n"),
            1,
            "W05 must fire on the grant hidden past a quoted `=(` across `:` (#416)"
        );
    }

    // ---- DEDUP: a NOPASSWD-on-ALL line is W01's, never also W05 ----

    /// `alice ALL = NOPASSWD: ALL` (visudo -c -f rc 0): the literal reserved `ALL`
    /// under NOPASSWD is W01's exact domain. The broad W05 must NOT double-flag this
    /// line -- exactly one finding for this hazard, from W01 (dedup-against-W01, the
    /// decided #370 contract). Excluding `CmndItem::All` from W05 is the mechanism.
    #[test]
    fn w05_dedup_nopasswd_on_all_is_w01_only_not_w05() {
        assert_eq!(
            w01_count("alice ALL = NOPASSWD: ALL\n"),
            1,
            "W01 owns the literal NOPASSWD-on-ALL case (exactly one finding)"
        );
        assert_eq!(
            w05_count("alice ALL = NOPASSWD: ALL\n"),
            0,
            "W05 must NOT also fire on a NOPASSWD-on-ALL line already flagged by W01"
        );
    }

    // ---- NEGATIVE: no NOPASSWD anywhere -> password required -> no W05 ----

    /// `alice ALL = /usr/bin/systemctl` (visudo -c -f rc 0): a password-REQUIRED
    /// specific command; no NOPASSWD in effect anywhere -> no W05.
    #[test]
    fn w05_does_not_fire_without_nopasswd() {
        assert_eq!(
            w05_count("alice ALL = /usr/bin/systemctl\n"),
            0,
            "a password-required command (no NOPASSWD) must not fire W05"
        );
    }

    // ---- #424 (classifier-not-validator FALSE POSITIVE, opposite direction from
    // every other case in this module): an invalid EMPTY-COMMAND tag with no
    // command at all must not raise a spurious W05 ----

    /// `alice ALL = NOPASSWD:` -- a tag with NO command following it at all.
    /// `visudo -c -f` rc=1 (syntax error at EOL; the grammar requires a command
    /// token after the tag list). `RuleSteward`'s parser still folds this into a
    /// clean `UserSpec` with ONE `CmndSpec { tags: [NoPasswd], cmnd: Cmnd("") }`
    /// (`parse_cmnd_spec`'s remainder-is-the-command rule keeps the empty
    /// remainder verbatim), so `for_each_nopasswd_command` sees NOPASSWD in
    /// effect on a command that is NOT the reserved `ALL` and W05 fires a
    /// SPURIOUS warning -- there is no real NOPASSWD grant on this already-
    /// invalid line to warn about. RED today: W05 currently fires once here.
    ///
    /// In scope here is ONLY suppressing the spurious W05; whether `RuleSteward`
    /// should ALSO raise a Fatal for the empty command itself is a separate
    /// positive-detection decision (tracked alongside the sudo-F02 classifier-
    /// not-validator residuals in tokens.rs), not asserted by this test.
    #[test]
    fn w05_does_not_fire_on_invalid_empty_command_nopasswd_tag() {
        // Fixture: visudo -c -f rc=1, syntax error at end of line (no command
        // after `NOPASSWD:`). Verified locally: sudo/visudo 1.9.17p2, 2026-07-04.
        assert_eq!(
            w05_count("alice ALL = NOPASSWD:\n"),
            0,
            "`alice ALL = NOPASSWD:` has NO command at all (visudo rc=1) -- W05 \
             must NOT fire a spurious warning about a nonexistent grant"
        );
    }

    // ---- tag-state machine: forward inheritance, per-command emission ----

    /// `alice ALL = NOPASSWD: /bin/ls, /bin/cat` (visudo -c -f rc 0). `cvtsudoers -f
    /// json` (sudo 1.9.17p2) shows BOTH commands in ONE `authenticate:false` block:
    /// NOPASSWD inherits forward to `/bin/cat`, so both are passwordless. Neither is
    /// the literal `ALL` -> W05 fires on BOTH commands (per-command, like W01/W02). A
    /// naive "explicit-tag-only" impl would miss the inherited `/bin/cat` and report 1.
    #[test]
    fn w05_inherits_nopasswd_forward_and_fires_per_command() {
        assert_eq!(
            w05_count("alice ALL = NOPASSWD: /bin/ls, /bin/cat\n"),
            2,
            "inherited NOPASSWD makes both specific commands passwordless -> two W05"
        );
    }

    /// `alice ALL = NOPASSWD: /bin/ls, PASSWD: /bin/cat` (visudo -c -f rc 0).
    /// `cvtsudoers -f json` shows `/bin/ls` `authenticate:false` and `/bin/cat`
    /// `authenticate:true`: the explicit PASSWD resets NOPASSWD before `/bin/cat`. Only
    /// `/bin/ls` is passwordless -> W05 fires exactly ONCE.
    #[test]
    fn w05_explicit_passwd_override_cancels_inheritance() {
        assert_eq!(
            w05_count("alice ALL = NOPASSWD: /bin/ls, PASSWD: /bin/cat\n"),
            1,
            "an explicit PASSWD override password-gates the later command; one W05"
        );
    }

    /// `alice ALL = NOPASSWD: /bin/ls, ALL` (visudo -c -f rc 0). `cvtsudoers -f json`
    /// shows `/bin/ls` AND `ALL` under one `authenticate:false` block (both
    /// passwordless). The literal `ALL` is W01's (dedup, no W05); the specific
    /// `/bin/ls` is W05's. So exactly one W05 (on `/bin/ls`) and one W01 (on `ALL`):
    /// per-command dedup, with no double-flag of a single command.
    #[test]
    fn w05_mixed_specific_and_all_dedups_per_command() {
        assert_eq!(
            w05_count("alice ALL = NOPASSWD: /bin/ls, ALL\n"),
            1,
            "the specific /bin/ls fires W05; the literal ALL is W01's (excluded)"
        );
        assert_eq!(
            w01_count("alice ALL = NOPASSWD: /bin/ls, ALL\n"),
            1,
            "the literal ALL on the same line still fires exactly one W01"
        );
    }

    /// NOPASSWD state is per-user-spec and must not bleed across logical lines.
    /// `a ALL = NOPASSWD: /bin/ls` + `b ALL = /bin/cat` (visudo -c -f rc 0):
    /// `cvtsudoers -f json` shows only `a`'s `/bin/ls` `authenticate:false`; `b`'s
    /// `/bin/cat` is a separate password-required user-spec. So exactly ONE W05.
    #[test]
    fn w05_nopasswd_does_not_bleed_across_user_specs() {
        assert_eq!(
            w05_count("a ALL = NOPASSWD: /bin/ls\nb ALL = /bin/cat\n"),
            1,
            "NOPASSWD state resets at each user-spec; b's /bin/cat must not fire"
        );
    }

    // ---- escaped comma in a command: `\,` is a literal, not a Cmnd_Spec_List
    // separator (shared-parser regression, post-GREEN impl-aware review) ----

    /// `alice ALL = NOPASSWD: /bin/echo hi\,there` (visudo -c -f rc 0, sudo
    /// 1.9.17p2): the `\,` is an ESCAPED literal comma inside a single command, not a
    /// `Cmnd_Spec_List` separator. `cvtsudoers -f json` reports exactly ONE command,
    /// `/bin/echo hi,there`, `authenticate:false`. So W05 must fire EXACTLY ONCE.
    ///
    /// This is RED on the current shared parser: `parse_cmnd_spec_list` splits on a
    /// raw `,` (escape-UNAWARE), so it sees two commands (`/bin/echo hi` and `there`)
    /// and W05 fires twice. sudo escapes `\,` the same way the parser already escapes
    /// `\:` in `split_top_level_segments`; the fix makes the command split
    /// `\,`-aware. Tests only -- the implementer fixes the parser.
    #[test]
    fn w05_escaped_comma_is_one_command_fires_once() {
        assert_eq!(
            w05_count("alice ALL = NOPASSWD: /bin/echo hi\\,there\n"),
            1,
            "an escaped comma is one command; W05 fires once"
        );
    }

    // ---- comma inside a runas group `(root, operator)` is NOT a Cmnd_Spec_List
    // separator (shared-parser paren-depth regression, post-GREEN re-review) ----

    /// `alice ALL = (root, operator) NOPASSWD: /bin/ls` (visudo -c -f rc 0, sudo
    /// 1.9.17p2): the comma is INSIDE the runas group `(root, operator)`, not a
    /// `Cmnd_Spec_List` separator. `cvtsudoers -f json` reports ONE command `/bin/ls`
    /// with `runasusers` [root, operator] and `authenticate:false`, so NOPASSWD is in
    /// effect on the single command `/bin/ls` -> W05 must fire EXACTLY ONCE.
    ///
    /// RED on the current shared parser: `split_cmnd_specs` splits on `,` without
    /// PAREN-DEPTH awareness, so it breaks the runas group apart, the NOPASSWD tag is
    /// swallowed, and W05 fires ZERO times -- a security FALSE NEGATIVE (a passwordless
    /// grant goes unflagged). The fix makes the split paren-depth (and quote) aware,
    /// mirroring `split_top_level_segments`. Tests only -- the implementer fixes the
    /// parser.
    #[test]
    fn w05_runas_group_comma_is_one_command_fires_once() {
        assert_eq!(
            w05_count("alice ALL = (root, operator) NOPASSWD: /bin/ls\n"),
            1,
            "a comma-separated runas list is one command; W05 fires once"
        );
        // The single command is /bin/ls, not the reserved ALL -> no W01 (guard).
        assert_eq!(
            w01_count("alice ALL = (root, operator) NOPASSWD: /bin/ls\n"),
            0,
            "not on reserved ALL -> no W01"
        );
    }

    /// Over-suppression control for the upcoming paren-depth fix: a REAL top-level
    /// comma (no runas group involved) must STILL split the `Cmnd_Spec_List`.
    /// `alice ALL = NOPASSWD: /bin/ls, /bin/cat` (visudo -c -f rc 0): `cvtsudoers -f
    /// json` shows two commands, both `authenticate:false` -> W05 count 2. GREEN today;
    /// it must STAY green after the fix so the paren-depth split suppresses ONLY
    /// in-paren commas, never a genuine separator. (Mirrors
    /// `w05_inherits_nopasswd_forward_and_fires_per_command`, co-located here to lock
    /// the no-over-suppression direction alongside the paren-depth regression above.)
    #[test]
    fn w05_real_top_level_comma_still_splits_two_commands() {
        assert_eq!(
            w05_count("alice ALL = NOPASSWD: /bin/ls, /bin/cat\n"),
            2,
            "a real top-level comma still splits into two commands; W05 fires twice"
        );
    }

    /// Mutation-kill coverage for the paren-depth arithmetic in `split_cmnd_specs`
    /// (the `depth > 0` guard + `depth -= 1` on `)`): a runas GROUP `(root)` FOLLOWED
    /// BY a real top-level comma. `alice ALL = (root) NOPASSWD: /bin/ls, /bin/cat`
    /// (visudo -c -f rc 0, sudo 1.9.17p2): `cvtsudoers -f json` reports TWO commands
    /// `/bin/ls` and `/bin/cat`, both under runas [root] with `authenticate:false`
    /// -> W05 fires TWICE.
    ///
    /// On correct code the `(root)` group closes -- `)` drives `depth` back to 0 --
    /// so the following top-level comma DOES split, yielding two commands. If
    /// `depth -= 1` or the `depth > 0` close-guard is mutated, `depth` stays > 0 past
    /// the group, the top-level comma is wrongly treated as in-paren and does NOT
    /// split -> one command -> W05 once. So a depth-arithmetic mutation flips this from
    /// 2 to 1. This is the case no earlier test exercised (a group AND a later real
    /// separator), which is why the depth mutants survived.
    #[test]
    fn w05_runas_group_then_top_level_comma_splits_two() {
        assert_eq!(
            w05_count("alice ALL = (root) NOPASSWD: /bin/ls, /bin/cat\n"),
            2,
            "a runas group then a real top-level comma: two NOPASSWD commands both fire W05"
        );
    }

    // ---- emission metadata: severity, anchoring, span, source_id ----

    /// The W05 diagnostic is Warning severity, anchors at the user-spec's 1-based
    /// logical line and byte span (the AST carries no per-command span, so the
    /// user-spec line is the anchor, exactly as W01/W02), and carries the file
    /// `source_id` for ariadne rendering.
    #[test]
    fn w05_fires_with_warning_severity_and_anchors_at_the_user_spec_line() {
        let src = "alice ALL=(root) NOPASSWD: /usr/bin/systemctl\n";
        let diags = lint_w05(src);
        let w05s: Vec<_> = diags.iter().filter(|d| d.code == "sudo-W05").collect();
        assert_eq!(w05s.len(), 1);
        let d = w05s[0];
        assert_eq!(d.severity, rulesteward_core::Severity::Warning);
        assert_eq!(d.line, 1, "anchors at the user-spec's 1-based line");
        assert_eq!(
            d.span,
            0..src.len() - 1,
            "anchors at the user-spec's logical-line byte span"
        );
        assert!(
            d.source_id.is_some(),
            "an anchored W05 carries the file source_id for ariadne rendering"
        );
        assert_eq!(d.file, Path::new("/etc/sudoers"));
    }

    // ---- grounding: the finding cites its STIG control ----

    /// The W05 message names NOPASSWD and cites the grounded DISA STIG control
    /// RHEL-08-010380 / RHEL-09-611085 (`ComplianceAsCode` `sudo_remove_nopasswd`,
    /// commit `65ccea603ee2c305fdb4c6f54cb911449d969d55`) -- the same control W01
    /// cites, with the broader trigger.
    #[test]
    fn w05_message_cites_grounded_stig_control() {
        let diags = lint_w05("alice ALL=(root) NOPASSWD: /usr/bin/systemctl\n");
        let d = diags
            .iter()
            .find(|d| d.code == "sudo-W05")
            .expect("W05 fires for the specific-command NOPASSWD fixture");
        assert!(
            d.message.contains("NOPASSWD"),
            "the W05 message names NOPASSWD; got {:?}",
            d.message
        );
        assert!(
            d.message.contains("RHEL-08-010380"),
            "W05 message must cite RHEL-08-010380; got {:?}",
            d.message
        );
        assert!(
            d.message.contains("RHEL-09-611085"),
            "W05 message must cite RHEL-09-611085; got {:?}",
            d.message
        );
    }
}
