//! sudo STIG-baseline Defaults lint pass (#333): sudo-W04 (a `Defaults` setting
//! weaker than the DISA sudo STIG baseline).
//!
//! # Grounding: DISA RHEL 8 / RHEL 9 sudo STIG
//!
//! Every check below is grounded in DISA STIG controls that appear in both the
//! RHEL 8 V2R1+ and RHEL 9 V1R1+ sudo-specific benchmarks. Exact rule IDs are
//! cited inline; those not confirmed from a local primary source are marked
//! `[VERIFY]` rather than fabricated.
//!
//! ## Weakening settings (fire on presence):
//!
//! - `!authenticate` -- bypasses per-invocation re-authentication.
//!   RHEL-08-010383 / RHEL-09-432025 [VERIFY exact IDs].
//! - `targetpw` / `rootpw` / `runaspw` -- prompts for the target/root/runas
//!   user's password rather than the invoking user's, breaking PAM/audit
//!   accountability.
//!   RHEL-08-010381 / RHEL-09-432015 [VERIFY exact IDs].
//! - `visiblepw` -- allows sudo to proceed when the password would be visible
//!   (e.g. when a tty is not associated with stdin).
//!   General CIS / STIG hardening; no dedicated single STIG ID confirmed [VERIFY].
//! - `!use_pty` (explicit negation of the pty requirement) -- deliberately
//!   disabling pseudo-terminal allocation is a present weakening.
//!   RHEL-08-010382 / RHEL-09-432020 [VERIFY exact IDs].
//!
//! ## Deferred: missing-required-hardening check
//!
//! The check for `use_pty` / `logfile` / `log_output` being absent from a file
//! is DEFERRED to a follow-up issue. It must run on the merged resolved config
//! set (all included files together), analogous to sshd-W01, to avoid
//! per-fragment false positives: each sudoers.d drop-in would be flagged for
//! missing use_pty even when the main /etc/sudoers sets it.
//!
//! # Scope design
//!
//! Weakening-present checks fire for EVERY `Defaults` scope (global, `@host`,
//! `:user`, `!cmnd`, `>runas`). A scoped weakening (`Defaults:someuser
//! !authenticate`) is still a finding: any user that matches the scope can
//! run sudo without re-authentication.
//!
//! # Version-agnostic
//!
//! These findings apply across all supported RHEL versions (no `--target` rail;
//! the context struct carries no target field).

// Setting names appear as plain string literals throughout this module.
// Wrapping them all in backticks in comments would bury the signal.
#![allow(clippy::doc_markdown)]

use rulesteward_core::{Diagnostic, Severity};

use crate::ast::{DefaultsScope, LineKind, SudoersFile};
use crate::lints::{SudoersLintContext, anchored};

// ---------------------------------------------------------------------------
// Weakening settings: fire when any of these appear (any scope).
// ---------------------------------------------------------------------------

/// Non-negated settings that weaken the sudo security posture below the STIG
/// baseline when present. Each tuple is `(name_as_written, human_explanation)`.
///
/// Note: `!authenticate` is NOT in this table because it is a NEGATED setting
/// (`DefaultSetting { negated: true, name: "authenticate" }`); it is handled
/// separately in `check_file`'s negated arm. This table covers settings that
/// are dangerous when present WITHOUT a `!` prefix.
const WEAKENING_PRESENT: &[(&str, &str)] = &[
    // targetpw: prompts for the target user's password rather than the invoking
    // user's -- breaks PAM accountability chain.
    // RHEL-08-010381 / RHEL-09-432015 [VERIFY].
    (
        "targetpw",
        "prompts for the target user's password instead of the invoking user's; \
         breaks PAM accountability (STIG: re-auth must use the user's own credentials)",
    ),
    // rootpw: prompts for root's password -- also breaks accountability.
    // RHEL-08-010381 / RHEL-09-432015 [VERIFY].
    (
        "rootpw",
        "prompts for the root password instead of the invoking user's; \
         breaks PAM accountability (STIG: re-auth must use the user's own credentials)",
    ),
    // runaspw: prompts for the run-as user's password.
    // RHEL-08-010381 / RHEL-09-432015 [VERIFY].
    (
        "runaspw",
        "prompts for the run-as user's password instead of the invoking user's; \
         breaks PAM accountability (STIG: re-auth must use the user's own credentials)",
    ),
    // visiblepw: allows sudo when the password would be echoed in plain text.
    // General STIG hardening [VERIFY exact ID].
    (
        "visiblepw",
        "allows sudo to proceed when the password would be visible on the terminal; \
         STIG baseline requires this to be disabled",
    ),
];

/// sudo-W04: a `Defaults` setting is weaker than the sudo STIG baseline.
///
/// # Checks
///
/// **Weakening present**: `!authenticate` (any scope), `targetpw`,
/// `rootpw`, `runaspw`, `visiblepw`, `!use_pty` -- fires at the offending
/// `Defaults` line.
///
/// The missing-required-hardening check (`use_pty` / I/O logging absent) is
/// DEFERRED to a follow-up issue; it must run on the merged resolved config
/// set (all included files together), analogous to sshd-W01, to avoid
/// per-fragment false positives.
///
/// See module-level doc for grounding and scope design.
#[must_use]
pub fn w04(files: &[SudoersFile], _ctx: &SudoersLintContext) -> Vec<Diagnostic> {
    let mut diags = Vec::new();
    for file in files {
        diags.extend(check_file(file));
    }
    diags
}

/// Run all W04 checks for one file.
fn check_file(file: &SudoersFile) -> Vec<Diagnostic> {
    let mut diags = Vec::new();

    for line in &file.lines {
        let LineKind::Defaults(defaults) = &line.kind else {
            continue;
        };

        for setting in &defaults.settings {
            let name = setting.name.as_str();

            // --- Negated checks ---
            if setting.negated {
                match name {
                    // `!authenticate`: disables per-invocation password re-authentication.
                    // RHEL-08-010383 / RHEL-09-432025 [VERIFY].
                    "authenticate" => {
                        diags.push(anchored(
                            Severity::Warning,
                            "sudo-W04",
                            line.span.clone(),
                            format!(
                                "Defaults setting '!authenticate' {} disables \
                                 per-invocation sudo re-authentication; \
                                 STIG requires authentication for every invocation \
                                 (RHEL-08-010383 / RHEL-09-432025 [VERIFY])",
                                scope_paren(&defaults.scope),
                            ),
                            &file.path,
                            line.line,
                        ));
                    }
                    // `!use_pty`: explicit negation of the pty requirement.
                    // RHEL-08-010382 / RHEL-09-432020 [VERIFY].
                    "use_pty" => {
                        diags.push(anchored(
                            Severity::Warning,
                            "sudo-W04",
                            line.span.clone(),
                            format!(
                                "Defaults setting '!use_pty' {} disables \
                                 pseudo-terminal allocation; STIG requires 'Defaults use_pty' \
                                 to prevent I/O redirection attacks \
                                 (RHEL-08-010382 / RHEL-09-432020 [VERIFY])",
                                scope_paren(&defaults.scope),
                            ),
                            &file.path,
                            line.line,
                        ));
                    }
                    _ => {}
                }
                continue; // done with this negated setting
            }

            // --- Non-negated checks ---

            // Fire for weakening non-negated settings (all entries in the table;
            // `!authenticate` is handled in the negated arm above).
            for &(weakening_name, explanation) in WEAKENING_PRESENT {
                if name == weakening_name {
                    diags.push(anchored(
                        Severity::Warning,
                        "sudo-W04",
                        line.span.clone(),
                        format!(
                            "Defaults setting '{name}' {} weakens sudo security: {explanation}",
                            scope_paren(&defaults.scope),
                        ),
                        &file.path,
                        line.line,
                    ));
                }
            }
        }
    }

    diags
}

/// Human-readable parenthetical naming the `Defaults` scope, used in diagnostic
/// messages. A global `Defaults` reads naturally as `(global scope)`; a scoped
/// `Defaults` names the binding, e.g. `(user:alice scope)` / `(host:web1 scope)`.
fn scope_paren(scope: &DefaultsScope) -> String {
    match scope {
        DefaultsScope::Global => "(global scope)".to_string(),
        DefaultsScope::Host(h) => format!("(host:{h} scope)"),
        DefaultsScope::User(u) => format!("(user:{u} scope)"),
        DefaultsScope::Cmnd(c) => format!("(cmnd:{c} scope)"),
        DefaultsScope::Runas(r) => format!("(runas:{r} scope)"),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lints::SudoersLintContext;
    use crate::parser::parse;
    use std::path::Path;

    const CTX: SudoersLintContext = SudoersLintContext {};
    const SUDOERS_PATH: &str = "/etc/sudoers";

    /// Parse a single sudoers source string into a one-element slice.
    fn parse_one(src: &str) -> Vec<SudoersFile> {
        vec![parse(src, Path::new(SUDOERS_PATH))]
    }

    /// Run w04 on a source string and return the diagnostics.
    fn lint_w04(src: &str) -> Vec<Diagnostic> {
        let files = parse_one(src);
        w04(&files, &CTX)
    }

    /// Extract only the W04 codes from a diagnostic list.
    fn w04_codes(diags: &[Diagnostic]) -> Vec<&str> {
        diags
            .iter()
            .filter(|d| d.code == "sudo-W04")
            .map(|d| d.code.as_ref())
            .collect()
    }

    // -----------------------------------------------------------------------
    // Weakening-present: !authenticate
    // -----------------------------------------------------------------------

    /// `Defaults !authenticate` fires W04.
    ///
    /// STIG grounding: RHEL-08-010383 / RHEL-09-432025 [VERIFY].
    /// Fixture verified valid by `visudo -c`.
    #[test]
    fn w04_fires_for_not_authenticate_global() {
        // Fixture: Defaults !authenticate (global scope).
        // visudo -c: "parsed OK"
        let diags = lint_w04("Defaults !authenticate\nroot ALL=(ALL:ALL) ALL\n");
        let w04_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-W04").collect();
        assert!(
            w04_diags
                .iter()
                .any(|d| d.message.contains("!authenticate")),
            "W04 must fire for 'Defaults !authenticate'; got {diags:?}"
        );
    }

    /// Scoped `Defaults:someuser !authenticate` still fires W04.
    /// A per-user weakening is still a finding.
    ///
    /// STIG grounding: RHEL-08-010383 / RHEL-09-432025 [VERIFY].
    /// Fixture verified valid by `visudo -c`.
    #[test]
    fn w04_fires_for_not_authenticate_user_scope() {
        // Fixture: Defaults:someuser !authenticate
        // visudo -c: "parsed OK"
        let diags = lint_w04("Defaults:someuser !authenticate\nroot ALL=(ALL:ALL) ALL\n");
        let w04_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-W04").collect();
        assert!(
            w04_diags
                .iter()
                .any(|d| d.message.contains("!authenticate")),
            "W04 must fire for scoped 'Defaults:someuser !authenticate'; got {diags:?}"
        );
        assert!(
            w04_diags
                .iter()
                .any(|d| d.message.contains("user:someuser")),
            "W04 message must name the scope 'user:someuser'; got {w04_diags:?}"
        );
    }

    /// The W04 `!authenticate` diagnostic anchors at the offending line (not line 0).
    #[test]
    fn w04_not_authenticate_anchors_at_defaults_line() {
        let diags = lint_w04("Defaults !authenticate\nroot ALL=(ALL:ALL) ALL\n");
        let w04_diags: Vec<_> = diags
            .iter()
            .filter(|d| d.code == "sudo-W04" && d.message.contains("!authenticate"))
            .collect();
        assert_eq!(
            w04_diags.len(),
            1,
            "exactly one W04 for !authenticate; got {w04_diags:?}"
        );
        assert_eq!(
            w04_diags[0].line, 1,
            "W04 must anchor at line 1 (the Defaults line)"
        );
    }

    // -----------------------------------------------------------------------
    // Weakening-present: targetpw / rootpw / runaspw
    // -----------------------------------------------------------------------

    /// `Defaults targetpw` fires W04.
    ///
    /// STIG grounding: RHEL-08-010381 / RHEL-09-432015 [VERIFY].
    /// Fixture verified valid by `visudo -c`.
    #[test]
    fn w04_fires_for_targetpw() {
        // Fixture: Defaults targetpw
        // visudo -c: "parsed OK"
        let diags = lint_w04("Defaults targetpw\nroot ALL=(ALL:ALL) ALL\n");
        let w04_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-W04").collect();
        assert!(
            w04_diags.iter().any(|d| d.message.contains("targetpw")),
            "W04 must fire for 'Defaults targetpw'; got {diags:?}"
        );
    }

    /// `Defaults rootpw` fires W04.
    ///
    /// STIG grounding: RHEL-08-010381 / RHEL-09-432015 [VERIFY].
    /// Fixture verified valid by `visudo -c`.
    #[test]
    fn w04_fires_for_rootpw() {
        // Fixture: Defaults rootpw
        // visudo -c: "parsed OK"
        let diags = lint_w04("Defaults rootpw\nroot ALL=(ALL:ALL) ALL\n");
        let w04_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-W04").collect();
        assert!(
            w04_diags.iter().any(|d| d.message.contains("rootpw")),
            "W04 must fire for 'Defaults rootpw'; got {diags:?}"
        );
    }

    /// `Defaults runaspw` fires W04.
    ///
    /// STIG grounding: RHEL-08-010381 / RHEL-09-432015 [VERIFY].
    /// Fixture verified valid by `visudo -c`.
    #[test]
    fn w04_fires_for_runaspw() {
        // Fixture: Defaults runaspw
        // visudo -c: "parsed OK"
        let diags = lint_w04("Defaults runaspw\nroot ALL=(ALL:ALL) ALL\n");
        let w04_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-W04").collect();
        assert!(
            w04_diags.iter().any(|d| d.message.contains("runaspw")),
            "W04 must fire for 'Defaults runaspw'; got {diags:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Weakening-present: visiblepw
    // -----------------------------------------------------------------------

    /// `Defaults visiblepw` fires W04.
    ///
    /// STIG grounding: general sudo hardening baseline [VERIFY exact ID].
    /// Fixture verified valid by `visudo -c`.
    #[test]
    fn w04_fires_for_visiblepw() {
        // Fixture: Defaults visiblepw
        // visudo -c: "parsed OK"
        let diags = lint_w04("Defaults visiblepw\nroot ALL=(ALL:ALL) ALL\n");
        let w04_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-W04").collect();
        assert!(
            w04_diags.iter().any(|d| d.message.contains("visiblepw")),
            "W04 must fire for 'Defaults visiblepw'; got {diags:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Weakening-present: !use_pty
    // -----------------------------------------------------------------------

    /// `Defaults !use_pty` fires W04 (explicit negation of the pty requirement).
    ///
    /// STIG grounding: RHEL-08-010382 / RHEL-09-432020 [VERIFY].
    /// Fixture verified valid by `visudo -c`.
    #[test]
    fn w04_fires_for_not_use_pty_explicit() {
        // Fixture: Defaults !use_pty (explicit negation)
        // visudo -c: "parsed OK"
        let diags = lint_w04("Defaults !use_pty\nroot ALL=(ALL:ALL) ALL\n");
        let w04_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-W04").collect();
        assert!(
            w04_diags
                .iter()
                .any(|d| d.message.contains("!use_pty") || d.message.contains("use_pty")),
            "W04 must fire for explicit '!use_pty'; got {diags:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Clean file: no W04 when no weakening Defaults present
    // -----------------------------------------------------------------------

    /// A file with no weakening Defaults fires NO W04.
    ///
    /// Fixture verified valid by `visudo -c`.
    #[test]
    fn w04_clean_when_no_weakening_defaults() {
        // Fixture: env_reset only; no weakening settings.
        // The missing-required-hardening check (use_pty / I/O logging absent) is
        // deferred, so this plain file emits no W04.
        // visudo -c: "parsed OK"
        let diags = lint_w04(
            "Defaults env_reset\n\
             root ALL=(ALL:ALL) ALL\n\
             %wheel ALL=(ALL) ALL\n",
        );
        let w04_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-W04").collect();
        assert!(
            w04_diags.is_empty(),
            "a file with no weakening Defaults must produce no W04; got {w04_diags:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Non-STIG Defaults: no false positives
    // -----------------------------------------------------------------------

    /// `Defaults env_reset` alone does NOT fire W04 (it is not a STIG finding).
    #[test]
    fn w04_env_reset_is_not_a_stig_finding() {
        // Fixture: only env_reset (no other Defaults).
        // visudo -c: "parsed OK"
        let diags = lint_w04("Defaults env_reset\nroot ALL=(ALL:ALL) ALL\n");
        // env_reset specifically must not appear in any W04 message
        let env_reset_diags: Vec<_> = diags
            .iter()
            .filter(|d| d.code == "sudo-W04" && d.message.contains("env_reset"))
            .collect();
        assert!(
            env_reset_diags.is_empty(),
            "'Defaults env_reset' must not trigger W04 as a weakening; got {env_reset_diags:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Scope label helper
    // -----------------------------------------------------------------------

    #[test]
    fn scope_paren_global_reads_global_scope() {
        // A global `Defaults` must read naturally as `(global scope)`, NOT the
        // awkward `(scope)` the old empty-prefix produced.
        assert_eq!(scope_paren(&DefaultsScope::Global), "(global scope)");
    }

    #[test]
    fn scope_paren_user_includes_username() {
        assert_eq!(
            scope_paren(&DefaultsScope::User("alice".into())),
            "(user:alice scope)"
        );
    }

    #[test]
    fn scope_paren_host_includes_hostname() {
        assert_eq!(
            scope_paren(&DefaultsScope::Host("myhost".into())),
            "(host:myhost scope)"
        );
    }

    // -----------------------------------------------------------------------
    // Diagnostic structural invariants
    // -----------------------------------------------------------------------

    #[test]
    fn w04_diagnostics_have_correct_code_and_severity() {
        let diags = lint_w04(
            "Defaults !authenticate\nDefaults use_pty\nDefaults logfile=/var/log/sudo.log\nroot ALL=(ALL:ALL) ALL\n",
        );
        for d in diags.iter().filter(|d| d.code == "sudo-W04") {
            assert_eq!(d.code.as_ref(), "sudo-W04");
            assert_eq!(
                d.severity,
                Severity::Warning,
                "sudo-W04 must always be Warning severity"
            );
            assert!(
                d.source_id.is_some(),
                "anchored diagnostics must have a source_id (ariadne key)"
            );
        }
    }

    #[test]
    fn w04_codes_helper_filters_correctly() {
        let diags = lint_w04(
            "Defaults !authenticate\nDefaults use_pty\nDefaults logfile=/var/log/sudo.log\nroot ALL=(ALL:ALL) ALL\n",
        );
        let codes = w04_codes(&diags);
        assert!(!codes.is_empty(), "should have at least one W04 code");
        assert!(codes.iter().all(|&c| c == "sudo-W04"));
    }
}
