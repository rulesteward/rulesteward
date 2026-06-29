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
    }
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
    for file in files {
        for logical in &file.lines {
            let LineKind::UserSpec(spec) = &logical.kind else {
                continue;
            };
            // Per-host-group, same as W01: the NOPASSWD/PASSWD tag-state is fresh per
            // `:`-separated host-group and does not cross the `:` (#345).
            for host_group in &spec.host_groups {
                let mut nopasswd = false;
                for cmnd_spec in &host_group.cmnd_specs {
                    // Fold THIS command's explicit tags into the state BEFORE
                    // evaluating it (last-written tag wins; an explicit PASSWD on the
                    // very command being checked cancels inheritance for it).
                    for tag in &cmnd_spec.tags {
                        match tag {
                            Tag::NoPasswd => nopasswd = true,
                            Tag::Passwd => nopasswd = false,
                            _ => {}
                        }
                    }
                    // The command must be a POSITIVE named alias (no leading `!`)
                    // whose name transitively expands to ALL. `CmndItem::All` is the
                    // literal reserved ALL (W01's case) and is excluded here.
                    if nopasswd
                        && let CmndItem::Cmnd(token) = &cmnd_spec.cmnd
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
                }
            }
        }
    }
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
