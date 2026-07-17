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
//!
//! Also carries [`w06`] (#522, v0.8 Wave 2 lane 2d): the reserved literal `ALL`
//! user granted unrestricted `(ALL)`/`(ALL:ALL)` privilege elevation over `ALL`
//! commands. Unlike W01/W02/W05 this is NOT part of the NOPASSWD tag-state
//! family (it fires independent of any tag), but it is a `UserSpec`-shaped
//! "who is granted what" hazard like the rest of this module, so it lives here
//! rather than in `stig.rs` (which owns `Defaults`-entry findings only). `w06`
//! walks each user-spec directly (no tag-state machine involved) and fires at
//! most once per logical line; see `w06_tests` below for the frozen fire/
//! no-fire contract every fixture in this module was verified against
//! (`visudo -c -f` / `cvtsudoers -f json`, sudo 1.9.17p2).

use rulesteward_core::{Diagnostic, Framework, Severity};

use crate::ast::{CmndItem, CmndSpec, LineKind, LogicalLine, RunasSpec, SudoersFile, Tag};
use crate::lints::{SudoersLintContext, anchored};

/// The DISA STIG NOPASSWD control pair (RHEL-08-010380 + RHEL-09-611085) cited by
/// BOTH sudo-W01 and sudo-W05. Shared here so the two emit sites cannot drift;
/// mapped to typed `ControlRef`s via [`crate::lints::stig::controls`] (the same
/// single conversion point stig.rs's own emit sites use).
const NOPASSWD_STIG_CONTROLS: [(Framework, &str); 2] = [
    (Framework::Stig, "RHEL-08-010380"),
    (Framework::Stig, "RHEL-09-611085"),
];

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
            diags.push(
                anchored(
                    Severity::Warning,
                    "sudo-W01",
                    logical.span.clone(),
                    "NOPASSWD applies to the reserved ALL command: this grants \
                     passwordless authority to run any command \
                     (DISA STIG RHEL-08-010380 / RHEL-09-611085)"
                        .to_string(),
                    file.path.clone(),
                    logical.line,
                )
                .with_controls(crate::lints::stig::controls(&NOPASSWD_STIG_CONTROLS)),
            );
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
        // #424: a tag with NO command (`alice ALL = NOPASSWD:`) is visudo-rejected
        // (rc=1); RuleSteward's parser still folds it to a `CmndSpec` with an EMPTY
        // command token, so a spurious W05 would fire on a nonexistent grant.
        // Suppress it -- there is no real passwordless grant to warn about.
        let is_empty_command = matches!(&cmnd_spec.cmnd, CmndItem::Cmnd(token) if token.is_empty());
        // Exclude the reserved literal ALL: that is W01's domain, and excluding it
        // here IS the dedup-against-W01. Every other NOPASSWD-effective command
        // (including alias references) fires.
        if cmnd_spec.cmnd != CmndItem::All && !is_empty_command {
            diags.push(
                anchored(
                    Severity::Warning,
                    "sudo-W05",
                    logical.span.clone(),
                    "NOPASSWD is in effect on this command: DISA STIG requires \
                     removing all NOPASSWD usage from sudoers \
                     (DISA STIG RHEL-08-010380 / RHEL-09-611085)"
                        .to_string(),
                    file.path.clone(),
                    logical.line,
                )
                .with_controls(crate::lints::stig::controls(&NOPASSWD_STIG_CONTROLS)),
            );
        }
    });
    diags
}

/// sudo-W06 (#522, v0.8 Wave 2 lane 2d): a `UserSpec` grants the reserved
/// literal `ALL` user unrestricted sudo access to run the reserved `ALL`
/// command as `ALL` run-as users (and, optionally, `ALL` run-as groups).
///
/// # Grounding
///
/// DISA STIG RHEL-08-010382 / RHEL-09-432030 / RHEL-10-600520 ("RHEL must
/// restrict privilege elevation to authorized personnel"), pinned against the
/// same three DISA XCCDF revisions `tools/sshd-stig-update` and
/// `tools/auditd-stig-update` pin (RHEL 8 STIG V2R4 / RHEL 9 STIG V2R7 /
/// RHEL 10 STIG V1R1). Check-content (byte-identical fire condition across all
/// three revisions):
///
/// ```text
/// $ sudo grep -iwR 'ALL' /etc/sudoers /etc/sudoers.d/ | grep -v '#'
/// ```
///
/// "If either of the following entries are returned, this is a finding:
/// `ALL     ALL=(ALL) ALL` / `ALL     ALL=(ALL:ALL) ALL`" -- i.e. the subject
/// `User_List` is the reserved keyword `ALL` (not a specific user / group /
/// `User_Alias` reference), the `Host_List` is `ALL`, the command is the
/// reserved `ALL`, and the `Runas_Spec` is exactly `(ALL)`
/// (`RunasSpec { users: ["ALL"], groups: [] }`) or `(ALL:ALL)`
/// (`RunasSpec { users: ["ALL"], groups: ["ALL"] }`). Every literal in this
/// doc comment (`ALL` reserved-word case sensitivity, the two exact Runas
/// shapes) is verified against `visudo -c -f` + `cvtsudoers -f json`
/// (sudo 1.9.17p2) in `w06_tests` below.
///
/// # Scope boundary (documented, not a bug)
///
/// A `User_Alias` whose members transitively expand to `ALL` (e.g.
/// `User_Alias ADMINS = ALL` then `ADMINS ALL=(ALL) ALL`) is a documented
/// v1 false-negative: DISA's own check-content is a literal-string grep, not
/// an alias-aware walk, so this pass does not chase alias expansion either
/// (the same kind of scope boundary W01 documents for `Cmnd_Alias`-expands-
/// to-ALL, which W02 exists to cover separately).
///
/// # Algorithm
///
/// Unlike W01/W02/W05 this pass does not walk a NOPASSWD tag-state machine --
/// it fires independent of any tag. For each `UserSpec`: the subject
/// `User_List` must CONTAIN the reserved `ALL` (membership, not exact list
/// equality -- see `w06_fires_for_multi_subject_line_containing_all` in
/// `w06_tests`); then each `:`-separated host-group is checked for a
/// `Host_List` that CONTAINS the reserved `ALL` (membership, not exact list
/// equality -- `w06_fires_when_host_list_contains_all_among_others`) with at
/// least one `Cmnd_Spec` whose command is the reserved `ALL` and whose
/// EFFECTIVE `Runas_Spec` (see below) has a run-as `users` list that
/// CONTAINS `ALL` and a run-as `groups` list that is either empty or
/// CONTAINS `ALL` (`w06_fires_when_runas_user_list_contains_all_among_others`;
/// again membership, not exact equality). The diagnostic fires AT MOST ONCE
/// per user-spec logical line even when more than one host-group or
/// `Cmnd_Spec` on that line matches
/// (`w06_fires_once_when_only_one_host_group_matches`).
///
/// ## Forward `Runas_Spec` inheritance
///
/// `sudoers(5)` (sudo 1.9.17p2): "A `Runas_Spec` sets the default for the
/// commands that follow it" -- a `Cmnd_Spec` with no leading `(...)` group of
/// its own inherits the last EXPLICIT `Runas_Spec` written earlier in the
/// SAME host-group's `Cmnd_Spec_List` (e.g. `ALL ALL=(ALL) /bin/ls, ALL`: the
/// trailing bare `ALL` command inherits `(ALL)` from `/bin/ls`'s explicit
/// group). This mirrors the forward NOPASSWD/PASSWD tag-state machine
/// [`for_each_nopasswd_command`] already runs above: a simple explicit
/// forward walk, carrying the last-seen `Runas_Spec` as state that
/// resets per host-group (each `:`-separated segment is an INDEPENDENT
/// `Cmnd_Spec_List`; #345) and updates BEFORE the command is evaluated. A
/// command with no `Runas_Spec` anywhere before it in the group has no
/// effective runas at all (sudo defaults it to root at runtime, which is
/// narrower than either DISA literal) and cannot fire
/// (`w06_fires_when_runas_inherits_forward_to_all_command`,
/// `w06_fires_when_runas_all_all_inherits_forward_to_all_command`).
#[must_use]
pub fn w06(files: &[SudoersFile], _ctx: &SudoersLintContext) -> Vec<Diagnostic> {
    let mut diags = Vec::new();
    for file in files {
        for logical in &file.lines {
            let LineKind::UserSpec(spec) = &logical.kind else {
                continue;
            };
            // Membership, not exact list equality: DISA's check-content is an
            // unanchored whole-word grep, so a multi-subject line naming ALL
            // alongside another user still returns the hazardous line.
            if !spec.users.iter().any(|user| user == "ALL") {
                continue;
            }
            let hazard = spec.host_groups.iter().any(|host_group| {
                // Reserved-ALL Host_List membership: CONTAINS "ALL", not an
                // exact-equality check (see the doc comment above and
                // `w06_fires_when_host_list_contains_all_among_others`).
                if !host_group.hosts.iter().any(|host| host == "ALL") {
                    return false;
                }
                // Forward Runas_Spec inheritance state for this host-group's
                // Cmnd_Spec_List (see the "Forward Runas_Spec inheritance"
                // doc section above); resets fresh per host-group.
                let mut effective_runas: Option<&RunasSpec> = None;
                for cmnd_spec in &host_group.cmnd_specs {
                    if let Some(runas) = &cmnd_spec.runas {
                        effective_runas = Some(runas);
                    }
                    if is_unrestricted_privilege_elevation(&cmnd_spec.cmnd, effective_runas) {
                        return true;
                    }
                }
                false
            });
            if hazard {
                diags.push(
                    anchored(
                        Severity::Warning,
                        "sudo-W06",
                        logical.span.clone(),
                        "the reserved ALL user is granted unrestricted sudo access \
                         to run the reserved ALL command as ALL run-as users: DISA \
                         STIG requires restricting privilege elevation to \
                         authorized personnel (DISA STIG RHEL-08-010382 / \
                         RHEL-09-432030 / RHEL-10-600520)"
                            .to_string(),
                        file.path.clone(),
                        logical.line,
                    )
                    .with_controls(crate::lints::stig::controls(
                        &PRIVILEGE_ELEVATION_STIG_CONTROLS,
                    )),
                );
            }
        }
    }
    diags
}

/// The DISA STIG privilege-elevation control triple sudo-W06 cites, in
/// RHEL-08/09/10 order (mirrors the [`NOPASSWD_STIG_CONTROLS`] convention
/// above).
const PRIVILEGE_ELEVATION_STIG_CONTROLS: [(Framework, &str); 3] = [
    (Framework::Stig, "RHEL-08-010382"),
    (Framework::Stig, "RHEL-09-432030"),
    (Framework::Stig, "RHEL-10-600520"),
];

/// Whether a command and its EFFECTIVE `Runas_Spec` (after forward
/// inheritance is resolved by the caller; see the "Forward `Runas_Spec`
/// inheritance" doc section on [`w06`] above) match sudo-W06's DISA pattern:
/// the reserved `ALL` command with a run-as `users` list that CONTAINS `ALL`
/// and a run-as `groups` list that is either empty or CONTAINS `ALL`
/// (membership, not exact list equality -- a bare `(ALL)` grant has
/// `groups=[]`; `(ALL:ALL)` has `groups=[ALL]`; both are DISA-literal
/// patterns, but `(ALL, root)` and `(ALL:wheel)` also fire/don't-fire per the
/// membership rule -- see `w06_fires_when_runas_user_list_contains_all_
/// among_others` and `w06_does_not_fire_when_runas_group_is_not_all` in
/// `w06_tests`). `effective_runas` is `None` when no `Runas_Spec` has been
/// written anywhere before this command in its host-group's `Cmnd_Spec_List`.
fn is_unrestricted_privilege_elevation(
    cmnd: &CmndItem,
    effective_runas: Option<&RunasSpec>,
) -> bool {
    let Some(runas) = effective_runas else {
        return false;
    };
    *cmnd == CmndItem::All
        && runas.users.iter().any(|user| user == "ALL")
        && (runas.groups.is_empty() || runas.groups.iter().any(|group| group == "ALL"))
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

    // ---- Typed ControlRef backfill (#503, v0.7) ----

    /// The W01 NOPASSWD-on-ALL finding cites DISA STIG RHEL-08-010380 AND
    /// RHEL-09-611085 (tags.rs:119, the same dual-id citation
    /// `w01_message_cites_grounded_stig_control` pins in the message text).
    /// The dual per-distro-release id citation must become TWO typed
    /// `rulesteward_core::ControlRef`s, both `Framework::Stig`, in citation
    /// order (RHEL-08 first, then RHEL-09). The message stays byte-identical;
    /// only `Diagnostic::controls` gains the typed mapping.
    #[test]
    fn w01_finding_carries_stig_controls() {
        use rulesteward_core::Framework;

        let diags = lint("alice ALL = NOPASSWD: ALL\n");
        let d = diags
            .iter()
            .find(|d| d.code == "sudo-W01")
            .expect("W01 fires for alice");
        assert_eq!(
            d.controls.len(),
            2,
            "W01's dual RHEL-08/RHEL-09 citation must become two ControlRefs; \
             got {:?}",
            d.controls
        );
        assert_eq!(d.controls[0].framework, Framework::Stig);
        assert_eq!(d.controls[0].id, "RHEL-08-010380");
        assert_eq!(d.controls[1].framework, Framework::Stig);
        assert_eq!(d.controls[1].id, "RHEL-09-611085");
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

    // ---- Typed ControlRef backfill (#503, v0.7) ----

    /// The W05 broad-any-NOPASSWD finding cites the SAME control as W01: DISA
    /// STIG RHEL-08-010380 / RHEL-09-611085 (tags.rs:227, the W05 emit-site
    /// citation string; the same `sudo_remove_nopasswd` rule W01 cites with a
    /// broader trigger). The dual per-distro-release id citation must become
    /// TWO typed `rulesteward_core::ControlRef`s, both `Framework::Stig`, in
    /// citation order (RHEL-08 first, then RHEL-09). Uses a SPECIFIC-command
    /// NOPASSWD fixture so W05 (not W01) is the finding under test. The message
    /// stays byte-identical; only `Diagnostic::controls` gains the mapping.
    #[test]
    fn w05_finding_carries_stig_controls() {
        use rulesteward_core::Framework;

        // NOPASSWD on a specific command (not ALL) -> W05 fires, W01 does not.
        let diags = lint_w05("alice ALL=(root) NOPASSWD: /usr/bin/systemctl\n");
        let d = diags
            .iter()
            .find(|d| d.code == "sudo-W05")
            .expect("W05 fires for the specific-command NOPASSWD");
        assert_eq!(
            d.controls.len(),
            2,
            "W05's dual RHEL-08/RHEL-09 citation must become two ControlRefs; \
             got {:?}",
            d.controls
        );
        assert_eq!(d.controls[0].framework, Framework::Stig);
        assert_eq!(d.controls[0].id, "RHEL-08-010380");
        assert_eq!(d.controls[1].framework, Framework::Stig);
        assert_eq!(d.controls[1].id, "RHEL-09-611085");
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

#[cfg(test)]
mod w06_tests {
    //! sudo-W06 (#522, v0.8 Wave 2 lane 2d): the literal-`ALL`-user unrestricted
    //! privilege-elevation check.
    //!
    //! Grounding: DISA STIG RHEL-08-010382 / RHEL-09-432030 / RHEL-10-600520
    //! ("RHEL must restrict privilege elevation to authorized personnel"),
    //! pinned XCCDF revisions RHEL 8 STIG V2R4 / RHEL 9 STIG V2R7 / RHEL 10
    //! STIG V1R1 (`dl.dod.cyber.mil/wp-content/uploads/stigs/zip/`, fetched
    //! 2026-07-15 -- same revisions `tools/sshd-stig-update` and
    //! `tools/auditd-stig-update` pin). Check-content across all three
    //! revisions: `sudo grep -iwR 'ALL' /etc/sudoers /etc/sudoers.d/ | grep -v
    //! '#'`; a finding if either literal entry `ALL ALL=(ALL) ALL` or
    //! `ALL ALL=(ALL:ALL) ALL` is present.
    //!
    //! Every fixture below is verified `visudo -c -f` rc 0 (sudo 1.9.17p2,
    //! `sudo-1.9.17-8.p2.fc44`), and the `RunasSpec` / `UserSpec` shape each
    //! positive fixture is expected to parse into is cross-checked against
    //! `cvtsudoers -f json` on the same sudo build:
    //! * `ALL ALL=(ALL) ALL` -> `User_List=[ALL]`, `Host_List=[ALL]`,
    //!   `runasusers=[ALL]`, NO `runasgroups` key, `Commands=[ALL]`.
    //! * `ALL ALL=(ALL:ALL) ALL` -> as above plus `runasgroups=[ALL]`.
    //! * `ALL ALL=(root) ALL` -> `runasusers=[root]` (no `runasgroups`) -- a
    //!   narrower grant than either literal DISA pattern, so it must NOT fire.
    //!
    //! This crate's OWN parser is not re-verified against `cvtsudoers` line by
    //! line here (that grounding already lives in `ast.rs` / `parser.rs`'s own
    //! test suite, and `aliases.rs` already relies on the same "ALL" reserved-
    //! word literal-match semantics for its own checks); these fixtures instead
    //! pin the W06-specific fire/no-fire CONTRACT this module's future
    //! implementation must satisfy.

    use super::{w01, w06};
    use crate::lints::SudoersLintContext;
    use crate::parser::parse;
    use std::path::Path;

    /// Parse one source string into the single-element file slice the passes take.
    fn files(src: &str) -> Vec<crate::ast::SudoersFile> {
        vec![parse(src, Path::new("/etc/sudoers"))]
    }

    /// Parse several `(path, source)` pairs into a merged slice, in evaluation
    /// order -- the shape `resolve_target` produces for a main file plus its
    /// `@include`/`@includedir` drop-ins (mirrors `stig.rs::tests::parse_files`).
    fn parse_files(parts: &[(&str, &str)]) -> Vec<crate::ast::SudoersFile> {
        parts.iter().map(|(p, s)| parse(s, Path::new(p))).collect()
    }

    /// Run W06 over `src` and return the diagnostics.
    fn lint_w06(src: &str) -> Vec<rulesteward_core::Diagnostic> {
        w06(&files(src), &SudoersLintContext::default())
    }

    /// Count the `sudo-W06` diagnostics over `src`.
    fn w06_count(src: &str) -> usize {
        lint_w06(src)
            .iter()
            .filter(|d| d.code == "sudo-W06")
            .count()
    }

    // ---- POSITIVE: the two literal DISA-grounded patterns ----

    /// `ALL ALL=(ALL) ALL` (visudo -c -f rc 0): the subject is the reserved
    /// literal `ALL`, granted the reserved `ALL` command as run-as `ALL`. This
    /// is DISA's first literal example verbatim. Anchoring is also pinned here
    /// (line / span / file / `source_id`), matching the W01/W05 anchoring
    /// convention: a user-spec is exactly one logical line, so the diagnostic
    /// anchors at that line.
    #[test]
    fn w06_fires_for_all_all_paren_all_paren_all() {
        // A clean anchor line (`root ALL=(ALL:ALL) ALL`, the file's line 1)
        // precedes the hazard on line 2, so the anchoring assertions below pin
        // the OFFENDING line, not line 1.
        let src = "root ALL=(ALL:ALL) ALL\nALL ALL=(ALL) ALL\n";
        let diags = lint_w06(src);
        assert_eq!(
            diags.len(),
            1,
            "'ALL ALL=(ALL) ALL' is DISA's first literal finding pattern; got {diags:?}"
        );
        let d = &diags[0];
        assert_eq!(d.code, "sudo-W06");
        assert_eq!(d.severity, rulesteward_core::Severity::Warning);
        assert_eq!(
            d.line, 2,
            "the hazard sits on line 2, not the clean anchor line 1"
        );
        assert_eq!(d.file, Path::new("/etc/sudoers"));
        assert!(
            d.source_id.is_some(),
            "an anchored W06 carries the file source_id for ariadne rendering"
        );
        assert!(
            !d.span.is_empty(),
            "an anchored W06 carries a real (non-empty) byte span; got {d:?}"
        );
    }

    /// `ALL ALL=(ALL:ALL) ALL` (visudo -c -f rc 0): DISA's second literal
    /// pattern -- the run-as GROUP is also explicitly `ALL`.
    #[test]
    fn w06_fires_for_all_all_paren_all_colon_all_paren_all() {
        assert_eq!(
            w06_count("root ALL=(ALL:ALL) ALL\nALL ALL=(ALL:ALL) ALL\n"),
            1,
            "'ALL ALL=(ALL:ALL) ALL' is DISA's second literal finding pattern"
        );
    }

    /// `bob,ALL ALL=(ALL) ALL` (visudo -c -f rc 0; `cvtsudoers -f json` confirms
    /// `User_List=[{username:bob}, {username:ALL}]`, i.e. the reserved `ALL`
    /// principal is a MEMBER of a multi-element subject list, not the sole
    /// entry): grounds which of two candidate readings of the DISA
    /// check-content is faithful once the `User_List` is not exactly `[ALL]`
    /// (adversarial re-review finding, ground-and-pin micro-round).
    ///
    /// All three pinned check-contents share the same unanchored, whole-word
    /// grep. RHEL-08-010382 / RHEL-09-432030: `sudo grep -iwR 'ALL'
    /// /etc/sudoers /etc/sudoers.d/ | grep -v '#'`. RHEL-10-600520
    /// (functionally identical, flags reordered): `sudo grep -riw ALL
    /// /etc/sudoers /etc/sudoers.d/ | grep -v "#"`. `-w`/`--word-regexp`
    /// matches `ALL` as a whole WORD anywhere on the line -- NOT the whole
    /// line (that would be `-x`) -- and neither command anchors with `^`/`$`.
    /// Simulated against this fixture's exact text: `printf 'bob,ALL
    /// ALL=(ALL) ALL\n' | grep -iwR 'ALL' | grep -v '#'` returns the FULL
    /// line `bob,ALL ALL=(ALL) ALL` verbatim, rc 0 -- the grep does not
    /// strip the `bob,` prefix or require an exact match to the bare `ALL
    /// ALL=(ALL) ALL` string quoted in the check's finding text; that quoted
    /// string is itself only ONE candidate line the grep can surface, not a
    /// whole-line equality test. Since the reserved `ALL` token in a
    /// `User_List` already means "every user" regardless of what else shares
    /// the list, a multi-subject line naming `ALL` alongside `bob` grants the
    /// identical unrestricted-personnel hazard DISA's `VulnDiscussion`
    /// describes ("any user defined on the system can initiate privileged
    /// actions") -- MEMBERSHIP (`user_list.contains(&"ALL")`), not exact list
    /// equality (`user_list == ["ALL"]`), is therefore the DISA-faithful
    /// reading: an exact-match impl would silently miss a fixture that the
    /// check's own literal grep command surfaces as a returned candidate
    /// line. RED against the `Vec::new()` stub.
    ///
    /// The fixture is written WITHOUT a space after the comma
    /// (`bob,ALL ...`, not `bob, ALL ...`) for the same reason as
    /// `hash_digits_uid_subject_after_comma_is_not_a_comment` in
    /// `parser.rs`: `classify_user_spec`/`split_first_word` treats the
    /// first whitespace-run as the boundary of the whole `User_List`, a
    /// documented Phase-0 simplification. A comma followed by a space
    /// (`bob, ALL ALL=(ALL) ALL`) introduces a whitespace-run before the
    /// `=`, so the parser splits the `User_List` at that inner space and
    /// garbles the spec; keeping the user list one whitespace-word
    /// (`bob,ALL`) sidesteps that gap without touching the parser. The
    /// spaced form therefore remains a KNOWN false negative until a parser
    /// follow-up issue lands proper comma-aware `User_List` tokenization;
    /// this test only pins the membership-vs-exact-equality reading above,
    /// not the parser's tolerance for whitespace inside a comma list. The
    /// DISA grounding above (the unanchored `grep -iw` returns the line
    /// regardless of internal whitespace; membership semantics) is
    /// unchanged by this fixture adjustment.
    #[test]
    fn w06_fires_for_multi_subject_line_containing_all() {
        assert_eq!(
            w06_count("bob,ALL ALL=(ALL) ALL\n"),
            1,
            "the reserved ALL principal is a MEMBER of a multi-subject User_List; \
             membership (not exact list equality) is the DISA-faithful reading -- \
             see this test's doc comment for the grep simulation that grounds this"
        );
    }

    // ---- Typed ControlRef (mirrors the W04/W05 #503 backfill convention) ----

    /// The W06 finding cites all three DISA STIG revisions this control was
    /// pinned against, in RHEL-08 / RHEL-09 / RHEL-10 order.
    #[test]
    fn w06_finding_carries_three_stig_controls() {
        use rulesteward_core::Framework;

        let diags = lint_w06("ALL ALL=(ALL) ALL\n");
        let d = diags
            .iter()
            .find(|d| d.code == "sudo-W06")
            .expect("W06 fires for the literal ALL/ALL/(ALL)/ALL fixture");
        assert_eq!(
            d.controls.len(),
            3,
            "W06 must cite all three pinned RHEL-08/09/10 STIG ids; got {:?}",
            d.controls
        );
        assert_eq!(d.controls[0].framework, Framework::Stig);
        assert_eq!(d.controls[0].id, "RHEL-08-010382");
        assert_eq!(d.controls[1].framework, Framework::Stig);
        assert_eq!(d.controls[1].id, "RHEL-09-432030");
        assert_eq!(d.controls[2].framework, Framework::Stig);
        assert_eq!(d.controls[2].id, "RHEL-10-600520");
    }

    // ---- merged-slice / multi-host-group shape ----

    /// DISA's check-content greps BOTH `/etc/sudoers` AND `/etc/sudoers.d/`;
    /// W06 must fire on a hazard that lives in an included drop-in, not only
    /// the top-level file. Anchors to the drop-in's OWN path (not the parent),
    /// matching the sshd-W01 / sudo-W04 merged-config anchoring convention for
    /// a per-file (not per-tree) finding.
    #[test]
    fn w06_fires_in_a_sudoers_d_dropin_not_only_the_top_level_file() {
        let files = parse_files(&[
            (
                "/etc/sudoers",
                "root ALL=(ALL:ALL) ALL\n#includedir /etc/sudoers.d\n",
            ),
            ("/etc/sudoers.d/00-all", "ALL ALL=(ALL) ALL\n"),
        ]);
        let diags = w06(&files, &SudoersLintContext::default());
        assert_eq!(
            diags.len(),
            1,
            "the hazard in the drop-in must fire exactly once; got {diags:?}"
        );
        assert_eq!(
            diags[0].file,
            Path::new("/etc/sudoers.d/00-all"),
            "must anchor to the drop-in file that actually contains the hazard"
        );
        assert_eq!(diags[0].line, 1);
    }

    /// `ALL ALL=(ALL) ALL : host2 = /bin/ls` (visudo -c -f rc 0): TWO
    /// `:`-separated host-groups sharing one subject `ALL`. Only the FIRST
    /// host-group matches the literal DISA pattern (host `ALL`, cmnd `ALL`,
    /// runas `(ALL)`); the second grants a specific command to a specific
    /// host and must not itself count as a second finding. Exactly one W06.
    #[test]
    fn w06_fires_once_when_only_one_host_group_matches() {
        assert_eq!(
            w06_count("ALL ALL=(ALL) ALL : host2 = /bin/ls\n"),
            1,
            "only the first host-group matches the literal pattern; exactly one W06"
        );
    }

    /// `ALL ALL=(ALL) NOPASSWD: ALL` (visudo -c -f rc 0): the SAME line is
    /// simultaneously a W01 hazard (NOPASSWD on the reserved ALL command) and
    /// a W06 hazard (literal ALL user granted (ALL) ALL). These are TWO
    /// DISTINCT DISA controls (010380/611085/600560 vs 010382/432030/600520),
    /// so BOTH must fire -- this is NOT a W01/W06 dedup boundary (unlike the
    /// W01/W05 dedup, which exists because those two share ONE citation).
    #[test]
    fn w06_coexists_with_w01_when_nopasswd_also_applies() {
        let src = "ALL ALL=(ALL) NOPASSWD: ALL\n";
        assert_eq!(
            w06_count(src),
            1,
            "W06 must still fire alongside W01, not be deduped against it"
        );
        let w01_diags = w01(&files(src), &SudoersLintContext::default());
        assert_eq!(
            w01_diags.iter().filter(|d| d.code == "sudo-W01").count(),
            1,
            "W01 must ALSO fire: NOPASSWD is in effect on the reserved ALL command"
        );
    }

    // ---- ADVERSARIAL STRENGTHENING (#522, post-GREEN Adversarial Testing Loop):
    // forward Runas_Spec inheritance + list-membership misses the impl-aware
    // adversary found. All four fixtures below are re-verified `visudo -c -f`
    // rc 0 (sudo 1.9.17p2) and cross-checked against `cvtsudoers -f json`. ----

    /// `ALL ALL=(ALL) /bin/ls, ALL` (visudo -c -f rc 0; `cvtsudoers -f json`
    /// confirms ONE `Cmnd_Specs` group with `runasusers=[ALL]` covering BOTH
    /// `Commands=[/bin/ls, ALL]`): `sudoers(5)` (sudo 1.9.17p2) states "A
    /// `Runas_Spec` sets the default for the commands that follow it" -- the
    /// trailing `ALL` command carries no `(...)` group of its own, so it
    /// INHERITS the `(ALL)` `Runas_Spec` set by the preceding command in the
    /// same `Cmnd_Spec_List`. Every user may therefore run ANY command as
    /// ANY user via the trailing bare `ALL`. This is the same forward-
    /// inheritance shape `for_each_nopasswd_command` already models for tags
    /// (tags.rs:58-94: `NOPASSWD`/`PASSWD` inherit across a `Cmnd_Spec_List`
    /// until the opposite tag overrides); `Runas_Spec` inheritance is the
    /// analogous rule for the run-as clause.
    ///
    /// RED against the current impl: `is_unrestricted_privilege_elevation`
    /// early-returns `false` when `cmnd_spec.runas` is `None` (tags.rs:372-
    /// 374), and the parser only records an explicit LEADING `(...)` on the
    /// command it directly precedes (`CmndSpec::runas`, ast.rs:261: "The
    /// run-as spec, if a `(...)` group preceded THIS command") -- it does
    /// not forward-resolve `Runas_Spec` inheritance across the list. So the
    /// trailing `ALL`'s `CmndSpec.runas` is `None` here and `w06` misses
    /// this hazard entirely (adversarial-impl-reviewer finding, ATL round).
    #[test]
    fn w06_fires_when_runas_inherits_forward_to_all_command() {
        assert_eq!(
            w06_count("ALL ALL=(ALL) /bin/ls, ALL\n"),
            1,
            "the trailing ALL command inherits the (ALL) Runas_Spec set by the \
             preceding command in the same Cmnd_Spec_List; must fire"
        );
    }

    /// `ALL ALL=(ALL:ALL) /bin/ls, ALL` (visudo -c -f rc 0; `cvtsudoers -f
    /// json` confirms ONE `Cmnd_Specs` group with `runasusers=[ALL]`,
    /// `runasgroups=[ALL]` covering BOTH `Commands=[/bin/ls, ALL]`): the same
    /// forward `Runas_Spec` inheritance as
    /// `w06_fires_when_runas_inherits_forward_to_all_command` above, but for
    /// the `(ALL:ALL)` grant shape (W06's second DISA-literal pattern). Must
    /// also fire.
    #[test]
    fn w06_fires_when_runas_all_all_inherits_forward_to_all_command() {
        assert_eq!(
            w06_count("ALL ALL=(ALL:ALL) /bin/ls, ALL\n"),
            1,
            "the trailing ALL command inherits the (ALL:ALL) Runas_Spec set by \
             the preceding command in the same Cmnd_Spec_List; must fire"
        );
    }

    /// `ALL host1,ALL=(ALL) ALL` (visudo -c -f rc 0; `cvtsudoers -f json`
    /// confirms `Host_List=[host1, ALL]`): the reserved `ALL` host is a
    /// MEMBER of a multi-host list alongside a specific hostname. DISA's
    /// check-content is the SAME unanchored whole-word grep
    /// (`grep -iwR 'ALL' ...`) that `w06_fires_for_multi_subject_line_
    /// containing_all` above already grounds for the subject `User_List`;
    /// the reserved `ALL` host means "every host" regardless of what else
    /// shares the list, so membership (not exact list equality) is the
    /// DISA-faithful reading for `Host_List` too. RED against the current
    /// impl: `host_group.hosts == ["ALL"]` (tags.rs:328) is an EXACT-
    /// equality check, so a `[host1, ALL]` list misses (adversarial-impl-
    /// reviewer finding, ATL round).
    #[test]
    fn w06_fires_when_host_list_contains_all_among_others() {
        assert_eq!(
            w06_count("ALL host1,ALL=(ALL) ALL\n"),
            1,
            "the reserved ALL host is a MEMBER of a multi-host Host_List; \
             membership (not exact list equality) must fire, mirroring the \
             User_List membership reading above"
        );
    }

    /// `ALL ALL=(ALL, root) ALL` (visudo -c -f rc 0; `cvtsudoers -f json`
    /// confirms `runasusers=[ALL, root]`): the reserved `ALL` run-as user is
    /// a MEMBER of a multi-user `Runas_Spec` alongside the named user `root`.
    /// Same membership grounding as
    /// `w06_fires_when_host_list_contains_all_among_others` above -- the
    /// reserved `ALL` run-as user subsumes any co-members, so every subject
    /// may run as `root` (or literally any user). RED against the current
    /// impl: `is_unrestricted_privilege_elevation`'s `runas.users ==
    /// ["ALL"]` (tags.rs:376) is EXACT-equality, so a `[ALL, root]` list
    /// misses (adversarial-impl-reviewer finding, ATL round).
    #[test]
    fn w06_fires_when_runas_user_list_contains_all_among_others() {
        assert_eq!(
            w06_count("ALL ALL=(ALL, root) ALL\n"),
            1,
            "the reserved ALL run-as user is a MEMBER of a multi-user Runas_Spec; \
             membership (not exact list equality) must fire"
        );
    }

    // ---- NEGATIVE: discriminating fixtures that must NOT fire ----

    /// `root ALL=(ALL:ALL) ALL` alone (no second line): the single most common
    /// sudoers line in existence (present in EVERY default `/etc/sudoers`).
    /// The subject is the NAMED user `root`, not the reserved `ALL` -- an
    /// over-broad implementation that keys off the `(ALL:ALL) ALL` Runas/Cmnd
    /// shape alone (ignoring the subject) would false-positive on every
    /// unmodified RHEL install. Must NOT fire.
    #[test]
    fn w06_does_not_fire_for_the_default_root_line_alone() {
        assert_eq!(
            w06_count("root ALL=(ALL:ALL) ALL\n"),
            0,
            "the ubiquitous default root line's subject is 'root', not the \
             reserved literal ALL; must not fire"
        );
    }

    /// `%wheel ALL=(ALL) ALL` (visudo -c -f rc 0): the subject is the `wheel`
    /// GROUP (`%wheel`), a distinct raw token from the bare reserved word
    /// `ALL`. Must NOT fire -- this is the second half of `clean_file_
    /// produces_no_diagnostics` (lints/mod.rs), which must stay diagnostic-free.
    #[test]
    fn w06_does_not_fire_for_the_wheel_group_line() {
        assert_eq!(
            w06_count("%wheel ALL=(ALL) ALL\n"),
            0,
            "'%wheel' is a group token, not the literal reserved ALL; must not fire"
        );
    }

    /// `ALL ALL=(root) ALL` (visudo -c -f rc 0, `cvtsudoers -f json` confirms
    /// `runasusers=[root]`, no `runasgroups` key): the subject and command ARE
    /// the hazardous literals, but the `Runas_Spec` is narrower than either
    /// grounded pattern (`(ALL)` or `(ALL:ALL)`) -- every user can only run as
    /// root, not as ANY user. DISA's two literal patterns do not cover this
    /// string, so a compliant implementation must NOT fire on it (guards
    /// against an over-broad "any runas, any user" impl).
    #[test]
    fn w06_does_not_fire_when_runas_is_narrower_than_all() {
        assert_eq!(
            w06_count("ALL ALL=(root) ALL\n"),
            0,
            "runas (root) is narrower than the grounded (ALL)/(ALL:ALL) patterns; \
             must not fire"
        );
    }

    /// `ALL ALL=(ALL) /bin/ls` (visudo -c -f rc 0): subject and runas ARE the
    /// hazardous literals, but the command is a specific path, not the
    /// reserved `ALL`. Neither DISA literal pattern matches a non-ALL command;
    /// must NOT fire (guards against an impl that ignores the `Cmnd_Spec`).
    #[test]
    fn w06_does_not_fire_when_command_is_not_all() {
        assert_eq!(
            w06_count("ALL ALL=(ALL) /bin/ls\n"),
            0,
            "the command is a specific path, not the reserved ALL; must not fire"
        );
    }

    /// `ALL somehost=(ALL) ALL` (visudo -c -f rc 0; `cvtsudoers -f json`
    /// confirms `Host_List=[somehost]`, not `[ALL]`): subject, runas, and
    /// command are all the hazardous literals, but the HOST is a specific
    /// hostname, not the reserved `ALL`. Neither DISA literal pattern
    /// (`ALL ALL=(ALL) ALL` / `ALL ALL=(ALL:ALL) ALL`) matches a non-ALL
    /// host, so `grep`-equivalent matching would not return this line. Kills
    /// an impl that omits the `Host_List == [ALL]` check and keys only off
    /// subject/runas/command (adversarial-test-reviewer BLOCKER finding).
    #[test]
    fn w06_does_not_fire_when_host_is_not_all() {
        assert_eq!(
            w06_count("ALL somehost=(ALL) ALL\n"),
            0,
            "the host is a specific hostname, not the reserved ALL; must not fire"
        );
    }

    /// `ALL ALL=(ALL:wheel) ALL` (visudo -c -f rc 0; `cvtsudoers -f json`
    /// confirms `runasgroups=[wheel]`, not `[ALL]`): subject, host, and
    /// command are all the hazardous literals, and the runas USER is `ALL`,
    /// but the runas GROUP is the specific group `wheel`, not the reserved
    /// `ALL`. Neither grounded literal pattern's runas clause -- `(ALL)`
    /// (users=[ALL], no groups key) or `(ALL:ALL)` (users=[ALL],
    /// groups=[ALL]) -- matches `(ALL:wheel)`. Kills an impl that checks
    /// only `runasusers == [ALL]` (or a bare `.contains("ALL")` scan) while
    /// ignoring the runas GROUP (adversarial-test-reviewer CONCERN finding).
    #[test]
    fn w06_does_not_fire_when_runas_group_is_not_all() {
        assert_eq!(
            w06_count("ALL ALL=(ALL:wheel) ALL\n"),
            0,
            "the runas group is 'wheel', not the reserved ALL; must not fire"
        );
    }

    /// `ALL ALL=(ALL) /bin/ls : ALL = ALL` (visudo -c -f rc 0, sudo 1.9.17p2;
    /// `cvtsudoers -f json` confirms TWO separate `User_Specs` entries, one
    /// per `:`-separated host-group: the first has `runasusers=[ALL]` scoped
    /// to `/bin/ls` only; the second (`ALL = ALL`, no leading `(...)`) has NO
    /// `runasusers`/`runasgroups` key at all, i.e. it defaults to `root` at
    /// runtime -- narrower than either grounded DISA pattern -- so W06 must
    /// NOT fire on the second segment's bare `ALL` command. This pins the
    /// PER-SEGMENT reset the "Forward `Runas_Spec` inheritance" doc section on
    /// [`w06`] above already claims (each `:`-separated host-group is an
    /// INDEPENDENT `Cmnd_Spec_List`, #345): every existing forward-
    /// inheritance fixture above (`w06_fires_when_runas_inherits_forward_
    /// to_all_command` et al.) keeps its explicit `Runas_Spec` in the SAME
    /// `:`-segment as the `ALL` command it grants, so none of them would
    /// notice a wrong impl that hoists `effective_runas` out of the
    /// per-host-group closure (tags.rs: `let mut effective_runas` inside
    /// `spec.host_groups.iter().any(...)`) and lets it leak across `:`
    /// boundaries -- that wrong impl would carry the first segment's `(ALL)`
    /// into the second segment's bare `ALL` and false-positive-fire here
    /// (round-2 impl-aware adversary finding: the impl itself is already
    /// correct -- the reset is declared fresh inside the closure -- this test
    /// only locks that shape in).
    #[test]
    fn w06_does_not_fire_when_runas_does_not_cross_host_group_segments() {
        assert_eq!(
            w06_count("ALL ALL=(ALL) /bin/ls : ALL = ALL\n"),
            0,
            "the second :-segment's bare ALL command has no Runas_Spec of its \
             own and must NOT inherit (ALL) from the first segment's /bin/ls \
             grant; each :-separated host-group resets forward-inheritance \
             state independently"
        );
    }
}

#[cfg(test)]
mod w06_stig_drift_tests {
    //! Hermetic drift guard for the sudo-W06 STIG grounding (#522, v0.8 Wave 2
    //! lane 2d). ADDITIVE to `w06_tests` above: this module adds NOTHING to the
    //! frozen fire/no-fire RED contract (that contract stands as-is; see this
    //! crate's Wave 2 lane 2d history). It instead pins the SOURCE-GROUNDING
    //! text itself.
    //!
    //! # Tooling decision (locked 2026-07-15)
    //!
    //! Unlike the sshd / auditd baselines (`tools/sshd-stig-update`,
    //! `tools/auditd-stig-update`), there is no standalone `sudoers-stig-update`
    //! derive tool: a single-control family did not justify a whole derive-tool
    //! crate (no-speculative-abstraction). Instead this module pins the
    //! grounding INLINE, hermetically (no network at test time -- the DISA
    //! source was fetched once at test-authoring time; see Provenance below),
    //! with the SAME kind of "0 drift" guarantee the derive tools give their own
    //! backends, achieved two ways:
    //!
    //! 1. `w06_control_family_benchmark_pins_match_sshd_and_auditd`: `w06`'s doc
    //!    comment (above, in this file) claims this control family is pinned
    //!    against "the same three DISA XCCDF revisions `tools/sshd-stig-update`
    //!    and `tools/auditd-stig-update` pin". This test makes that claim
    //!    MECHANICAL: it reads both tools' real, independently-maintained
    //!    `stig-refs.toml` files via `include_str!` and asserts each pinned
    //!    `benchmark` string still contains this module's short revision label.
    //!    If a future sshd/auditd lane bumps a product's STIG revision (editing
    //!    ONLY that tool's `stig-refs.toml`) without a matching sudoers update,
    //!    THIS test fails -- the sudo-W06 grounding would otherwise silently go
    //!    stale relative to the shared revision the other two backends moved to.
    //! 2. `w06_grounding_fixtures_are_well_formed`: pins the actual DISA
    //!    check-content excerpt text (fetched once, see Provenance below) as a
    //!    committed fixture fragment, so a reviewer -- or a future re-fetch --
    //!    has real ground truth to diff against, not only the short prose in
    //!    `w06`'s doc comment.
    //!
    //! No separate `tests/fixtures/` directory or file is used: this crate has
    //! no existing `tests/` integration-test convention (every sudoers lint test
    //! is an inline `#[cfg(test)]` module), so the fixture fragments are
    //! committed as `&'static str` constants in this module instead of new
    //! files, keeping the drift guard co-located with the code it grounds.
    //!
    //! # Bump-time re-verify recipe
    //!
    //! When either `tools/sshd-stig-update/stig-refs.toml` or
    //! `tools/auditd-stig-update/stig-refs.toml` bumps a product's pinned `zip`
    //! / `benchmark` (e.g. RHEL 8 STIG V2R4 -> V2R5):
    //! 1. Update this module's `W06_GROUNDING` entry for that product's short
    //!    revision label to match (this test will otherwise fail immediately,
    //!    which is the intended signal to do so).
    //! 2. Re-fetch the DISA XCCDF for that product (the zip URL is
    //!    `stig-refs.toml`'s `base_url` + `/` + the pinned `zip`; DISA's own
    //!    `public.cyber.mil` is a JS SPA that cannot be curled, so use
    //!    `dl.dod.cyber.mil` per that file's own comment), locate the `<Rule>`
    //!    whose STIG-ID matches this control family (RHEL-08-010382 /
    //!    RHEL-09-432030 / RHEL-10-600520), and diff its `check-content` against
    //!    `W06_GROUNDING`'s `check_content_excerpt` for that product.
    //! 3. If the check-content text changed in a way that affects the fire
    //!    condition (not just cosmetic rewording), update the excerpt here.
    //! 4. If a control was RENUMBERED (not just reworded) or the fire condition
    //!    itself changed, that is a `[QUESTION FOR USER]` addressed to the
    //!    frozen contract's author, never a silent edit to `w06_tests` above or
    //!    to `w06`'s implementation once it lands.
    //!
    //! # Provenance
    //!
    //! Fetched 2026-07-15: the RHEL 8 (RHEL-08-010382) and RHEL 9
    //! (RHEL-09-432030) excerpts are cross-checked against TWO independent
    //! queries of `stigviewer.com`'s mirror of the DISA XCCDF; the RHEL 10
    //! (RHEL-10-600520) excerpt is from a single `stigaview.com` mirror query
    //! (no independent second source was found for RHEL 10 in-session). The raw
    //! DISA XCCDF zips for all three products are cached locally at
    //! `/home/runner/rulesteward-docs/grounding/auditd-stig/stig_research/`
    //! (`U_RHEL_8_V2R4_STIG.zip` / `U_RHEL_9_V2R7_STIG.zip` /
    //! `U_RHEL_10_V1R1_STIG.zip`); a bump-time re-verify should diff against
    //! those raw zips directly rather than re-fetching a mirror. The RHEL 10
    //! mirror's grep invocation differs
    //! cosmetically from RHEL 8/9's (`-riw` + double-quoted `'#'` vs `-iwR` +
    //! single-quoted `'#'`); this is recorded verbatim rather than silently
    //! normalized, since `w06`'s doc comment claims a "byte-identical fire
    //! condition" and this module's job is to surface exactly this kind of
    //! discrepancy, not paper over it.

    /// One control's pinned grounding.
    struct Grounding {
        /// The DISA STIG-ID this excerpt grounds.
        control_id: &'static str,
        /// `stig-refs.toml`'s `[products.<product>]` key.
        product: &'static str,
        /// The short revision label that must remain a SUBSTRING of
        /// `stig-refs.toml`'s `benchmark = "..."` value for `product`.
        short_benchmark: &'static str,
        /// A verbatim excerpt of the DISA check-content (see the module-level
        /// Provenance note). Kept as the full sentence rather than only the
        /// bare grant-pattern substring, so a future diff against the raw
        /// XCCDF has real prose to compare, not just two already-well-known
        /// literal strings.
        check_content_excerpt: &'static str,
    }

    const W06_GROUNDING: [Grounding; 3] = [
        Grounding {
            control_id: "RHEL-08-010382",
            product: "rhel8",
            short_benchmark: "RHEL 8 STIG V2R4",
            check_content_excerpt: "Verify the sudoers file restricts sudo access to \
                authorized personnel. $ sudo grep -iwR 'ALL' /etc/sudoers \
                /etc/sudoers.d/ | grep -v '#' If the either of the following entries \
                are returned, this is a finding: ALL ALL=(ALL) ALL ALL ALL=(ALL:ALL) ALL",
        },
        Grounding {
            control_id: "RHEL-09-432030",
            product: "rhel9",
            short_benchmark: "RHEL 9 STIG V2R7",
            check_content_excerpt: "Verify RHEL 9 restricts privilege elevation to \
                authorized personnel with the following command: $ sudo grep -iwR \
                'ALL' /etc/sudoers /etc/sudoers.d/ | grep -v '#' If the either of the \
                following entries are returned, this is a finding: ALL ALL=(ALL) ALL \
                ALL ALL=(ALL:ALL) ALL",
        },
        Grounding {
            control_id: "RHEL-10-600520",
            product: "rhel10",
            short_benchmark: "RHEL 10 STIG V1R1",
            check_content_excerpt: "Verify RHEL 10 restricts privilege elevation to \
                authorized personnel with the following command: $ sudo grep -riw \
                ALL /etc/sudoers /etc/sudoers.d/ | grep -v \"#\" -- this mirror \
                renders the grep invocation as -riw with a double-quoted '#' rather \
                than RHEL 8/9's -iwR with a single-quoted '#'; functionally \
                equivalent (same flags, same predicate), recorded verbatim per \
                source rather than silently normalized to match RHEL 8/9's wording. \
                If the either of the following entries is returned, this is a \
                finding: ALL ALL=(ALL) ALL ALL ALL=(ALL:ALL) ALL",
        },
    ];

    /// The sshd baseline's pinned STIG revisions -- the shared source `w06`'s
    /// doc comment claims this control family is ALSO pinned against.
    const SSHD_STIG_REFS: &str = include_str!("../../../../tools/sshd-stig-update/stig-refs.toml");
    /// The auditd baseline's pinned STIG revisions -- carries its own comment
    /// that it pins "the same three revisions tools/sshd-stig-update/
    /// stig-refs.toml pins"; `sshd_and_auditd_stig_refs_pin_the_same_three_
    /// benchmarks` below makes that cross-tool claim mechanical.
    const AUDITD_STIG_REFS: &str =
        include_str!("../../../../tools/auditd-stig-update/stig-refs.toml");

    /// Extract the `benchmark = "..."` value under a `[products.<product>]`
    /// section of a `stig-refs.toml`'s text. A minimal string search rather
    /// than a TOML parse: this crate carries no `toml` dependency, and a
    /// three-line section lookup does not need one.
    fn pinned_benchmark(refs_toml: &str, product: &str) -> String {
        let header = format!("[products.{product}]");
        let after = refs_toml
            .split_once(&header)
            .unwrap_or_else(|| panic!("no [products.{product}] section found in stig-refs.toml"))
            .1;
        let line = after
            .lines()
            .find(|l| l.trim_start().starts_with("benchmark"))
            .unwrap_or_else(|| panic!("no benchmark= line under [products.{product}]"));
        let (_, rest) = line
            .split_once('"')
            .unwrap_or_else(|| panic!("benchmark line has no opening quote: {line:?}"));
        let (value, _) = rest
            .split_once('"')
            .unwrap_or_else(|| panic!("benchmark line has no closing quote: {line:?}"));
        value.to_string()
    }

    #[test]
    fn sshd_and_auditd_stig_refs_pin_the_same_three_benchmarks() {
        // auditd-stig-update's own file comment claims it pins "the same
        // three revisions tools/sshd-stig-update/stig-refs.toml pins"; this
        // makes that cross-tool claim mechanical rather than only prose.
        for product in ["rhel8", "rhel9", "rhel10"] {
            let sshd = pinned_benchmark(SSHD_STIG_REFS, product);
            let auditd = pinned_benchmark(AUDITD_STIG_REFS, product);
            assert_eq!(
                sshd, auditd,
                "sshd-stig-update and auditd-stig-update must pin the SAME \
                 {product} benchmark; got sshd={sshd:?} auditd={auditd:?}"
            );
        }
    }

    #[test]
    fn w06_control_family_benchmark_pins_match_sshd_and_auditd() {
        // The actual drift guard: if a future sshd/auditd lane bumps a
        // product's pinned STIG revision without a matching sudoers update,
        // this fails -- the sudo-W06 grounding would otherwise silently be
        // pinned to a STALE revision relative to the shared source the other
        // two backends moved to.
        for g in &W06_GROUNDING {
            let live = pinned_benchmark(SSHD_STIG_REFS, g.product);
            assert!(
                live.contains(g.short_benchmark),
                "{}'s pinned benchmark in tools/sshd-stig-update/stig-refs.toml is \
                 {live:?}, which no longer contains the sudo-W06 grounding's short \
                 label {:?} -- re-verify per this module's bump-time recipe",
                g.product,
                g.short_benchmark
            );
        }
    }

    #[test]
    fn w06_grounding_fixtures_are_well_formed() {
        for g in &W06_GROUNDING {
            assert!(
                !g.check_content_excerpt.trim().is_empty(),
                "{}'s check-content excerpt must not be empty",
                g.control_id
            );
            assert!(
                g.check_content_excerpt.contains("ALL ALL=(ALL) ALL"),
                "{}'s check-content excerpt must carry the first DISA literal \
                 finding pattern; got {:?}",
                g.control_id,
                g.check_content_excerpt
            );
            assert!(
                g.check_content_excerpt.contains("ALL ALL=(ALL:ALL) ALL"),
                "{}'s check-content excerpt must carry the second DISA literal \
                 finding pattern; got {:?}",
                g.control_id,
                g.check_content_excerpt
            );
            assert!(
                g.control_id.starts_with("RHEL-"),
                "control id must be a RHEL-NN-NNNNNN STIG id; got {:?}",
                g.control_id
            );
        }
        // The three ids are exactly the ones the FROZEN
        // `w06_tests::w06_finding_carries_three_stig_controls` contract pins on
        // `Diagnostic::controls`, in the same RHEL-08/09/10 order. This is a
        // SECOND, independent listing (not an import of that test's literals),
        // so a reviewer sees two disagreeing sources rather than a single one
        // nobody re-checks.
        let ids: Vec<&str> = W06_GROUNDING.iter().map(|g| g.control_id).collect();
        assert_eq!(
            ids,
            ["RHEL-08-010382", "RHEL-09-432030", "RHEL-10-600520"],
            "the pinned control-id order must match the frozen w06_tests contract"
        );
    }
}
