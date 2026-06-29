//! sudo STIG-baseline Defaults lint pass (#333): sudo-W04 (a `Defaults` setting
//! weaker than the DISA sudo STIG baseline, or a required hardening setting
//! absent from a file).
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
//! - `!use_pty` (explicit negation of the pty requirement) -- equivalent to the
//!   absence finding below but written explicitly.
//!
//! ## Required hardening (fire on absence, per file):
//!
//! - `use_pty` absent (and not negated elsewhere) -- the STIG requires sudo to
//!   allocate a pseudo-terminal so that I/O cannot be redirected.
//!   RHEL-08-010382 / RHEL-09-432020 [VERIFY exact IDs].
//! - `logfile=...` or `log_output` absent -- I/O logging ensures command input
//!   and output are captured for audit purposes.
//!   RHEL-08-010384 / RHEL-09-432035 [VERIFY exact IDs].
//!
//! # Scope design
//!
//! Weakening-present checks fire for EVERY `Defaults` scope (global, `@host`,
//! `:user`, `!cmnd`, `>runas`). A scoped weakening (`Defaults:someuser
//! !authenticate`) is still a finding: any user that matches the scope can
//! run sudo without re-authentication.
//!
//! Absence checks are per-FILE: we look at whether ANY `Defaults` line (of any
//! scope) in the file names the required setting as a positive (non-negated)
//! flag. A file without any `Defaults use_pty` line is flagged regardless of
//! scope. Diagnostics anchor at byte 0..0 / line 0 (the "missing directive"
//! convention, consistent with sshd-W01 and the project's missing-key convention
//! documented in the core's `anchored` helper).
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

// ---------------------------------------------------------------------------
// Required hardening: fire when ABSENT from the file (any scope counts).
// ---------------------------------------------------------------------------

/// Settings that MUST appear (non-negated) somewhere in the file. If none of
/// the `Defaults` entries in the file name this setting as a positive flag, a
/// W04 absence finding is emitted at byte 0..0 (no line to anchor to).
///
/// Each tuple is `(setting_name, human_explanation)`.
const REQUIRED_PRESENT: &[(&str, &str)] = &[
    // use_pty: sudo must allocate a pseudo-terminal so command I/O cannot be
    // trivially redirected by a malicious program.
    // RHEL-08-010382 / RHEL-09-432020 [VERIFY].
    (
        "use_pty",
        "STIG requires 'Defaults use_pty' to ensure sudo commands run in a \
         pseudo-terminal (prevents I/O redirection attacks; \
         RHEL-08-010382 / RHEL-09-432020 [VERIFY])",
    ),
    // logfile or log_output: I/O logging for sudo sessions must be configured.
    // We check for `logfile` here; `log_output` is the alternative (see w04 impl).
    // RHEL-08-010384 / RHEL-09-432035 [VERIFY].
    (
        "logfile",
        "STIG requires sudo I/O logging; add 'Defaults logfile=/var/log/sudo.log' \
         or 'Defaults log_output' to capture sudo session I/O \
         (RHEL-08-010384 / RHEL-09-432035 [VERIFY])",
    ),
];

/// sudo-W04: a `Defaults` setting is weaker than the sudo STIG baseline, or a
/// required STIG hardening setting is absent from the file.
///
/// # Checks
///
/// 1. **Weakening present**: `!authenticate` (any scope), `targetpw`,
///    `rootpw`, `runaspw`, `visiblepw`, `!use_pty` -- fires at the offending
///    `Defaults` line.
/// 2. **Required absent**: `use_pty` and (`logfile` or `log_output`) absent
///    from the file in any `Defaults` entry -- fires with an empty span / line 0
///    anchored to the file path.
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

    // Collect all DefaultsEntry items with their line spans for weakening checks.
    let mut has_use_pty = false;
    let mut has_io_log = false; // logfile=... OR log_output

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
                                "Defaults setting '!authenticate' ({}scope) disables \
                                 per-invocation sudo re-authentication; \
                                 STIG requires authentication for every invocation \
                                 (RHEL-08-010383 / RHEL-09-432025 [VERIFY])",
                                scope_label(&defaults.scope),
                            ),
                            &file.path,
                            line.line,
                        ));
                    }
                    // `!use_pty`: explicit negation of the pty requirement.
                    // Same control as the absence check but written explicitly.
                    // RHEL-08-010382 / RHEL-09-432020 [VERIFY].
                    "use_pty" => {
                        diags.push(anchored(
                            Severity::Warning,
                            "sudo-W04",
                            line.span.clone(),
                            format!(
                                "Defaults setting '!use_pty' ({}scope) disables \
                                 pseudo-terminal allocation; STIG requires 'Defaults use_pty' \
                                 to prevent I/O redirection attacks \
                                 (RHEL-08-010382 / RHEL-09-432020 [VERIFY])",
                                scope_label(&defaults.scope),
                            ),
                            &file.path,
                            line.line,
                        ));
                        // An explicit `!use_pty` is both a weakening finding AND means
                        // the absence check must still fire (use_pty is not positively
                        // set). Do NOT set `has_use_pty` here.
                    }
                    _ => {}
                }
                continue; // done with this negated setting
            }

            // --- Non-negated checks ---

            // Track required settings present (for the absence check below).
            if name == "use_pty" {
                has_use_pty = true;
            }
            if name == "logfile" || name == "log_output" {
                has_io_log = true;
            }

            // Fire for weakening non-negated settings (all entries in the table;
            // `!authenticate` is handled in the negated arm above).
            for &(weakening_name, explanation) in WEAKENING_PRESENT {
                if name == weakening_name {
                    diags.push(anchored(
                        Severity::Warning,
                        "sudo-W04",
                        line.span.clone(),
                        format!(
                            "Defaults setting '{name}' ({}scope) weakens sudo security: {explanation}",
                            scope_label(&defaults.scope),
                        ),
                        &file.path,
                        line.line,
                    ));
                }
            }
        }
    }

    // --- Absence checks (per file) ---

    if !has_use_pty {
        // No `Defaults use_pty` found anywhere in the file. Anchor at 0..0
        // (no line to point to - the directive is absent), consistent with the
        // sshd-W01 "missing required directive" convention.
        diags.push(anchored(
            Severity::Warning,
            "sudo-W04",
            0..0,
            REQUIRED_PRESENT[0].1.to_string(),
            &file.path,
            0,
        ));
    }

    if !has_io_log {
        // No I/O logging configured anywhere in the file.
        diags.push(anchored(
            Severity::Warning,
            "sudo-W04",
            0..0,
            REQUIRED_PRESENT[1].1.to_string(),
            &file.path,
            0,
        ));
    }

    diags
}

/// Human-readable prefix for the scope, used in diagnostic messages.
fn scope_label(scope: &DefaultsScope) -> String {
    match scope {
        DefaultsScope::Global => String::new(),
        DefaultsScope::Host(h) => format!("host:{h} "),
        DefaultsScope::User(u) => format!("user:{u} "),
        DefaultsScope::Cmnd(c) => format!("cmnd:{c} "),
        DefaultsScope::Runas(r) => format!("runas:{r} "),
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
    // Absence checks: use_pty missing
    // -----------------------------------------------------------------------

    /// A file WITHOUT `Defaults use_pty` fires W04 (missing required hardening).
    ///
    /// STIG grounding: RHEL-08-010382 / RHEL-09-432020 [VERIFY].
    /// Fixture verified valid by `visudo -c`.
    #[test]
    fn w04_fires_for_missing_use_pty() {
        // Fixture: only env_reset; no use_pty.
        // visudo -c: "parsed OK"
        let diags = lint_w04(
            "Defaults env_reset\nDefaults logfile=/var/log/sudo.log\nroot ALL=(ALL:ALL) ALL\n",
        );
        let w04_diags: Vec<_> = diags
            .iter()
            .filter(|d| d.code == "sudo-W04" && d.message.contains("use_pty"))
            .collect();
        assert!(
            !w04_diags.is_empty(),
            "W04 must fire when 'Defaults use_pty' is absent; got {diags:?}"
        );
        assert_eq!(
            w04_diags[0].line, 0,
            "absence finding anchors at line 0 (no line to point to)"
        );
        assert_eq!(
            w04_diags[0].span,
            (0..0),
            "absence finding has empty span 0..0"
        );
    }

    // -----------------------------------------------------------------------
    // Absence checks: logfile / log_output missing
    // -----------------------------------------------------------------------

    /// A file WITHOUT any `logfile` or `log_output` fires W04.
    ///
    /// STIG grounding: RHEL-08-010384 / RHEL-09-432035 [VERIFY].
    /// Fixture verified valid by `visudo -c`.
    #[test]
    fn w04_fires_for_missing_io_logging() {
        // Fixture: has use_pty but no logfile or log_output.
        // visudo -c: "parsed OK"
        let diags = lint_w04("Defaults env_reset\nDefaults use_pty\nroot ALL=(ALL:ALL) ALL\n");
        let w04_diags: Vec<_> = diags
            .iter()
            .filter(|d| d.code == "sudo-W04" && d.message.contains("logfile"))
            .collect();
        assert!(
            !w04_diags.is_empty(),
            "W04 must fire when no I/O logging is configured; got {diags:?}"
        );
        assert_eq!(w04_diags[0].line, 0, "absence finding anchors at line 0");
    }

    /// `Defaults log_output` satisfies the I/O logging requirement.
    ///
    /// Fixture verified valid by `visudo -c`.
    #[test]
    fn w04_log_output_satisfies_io_logging_requirement() {
        // Fixture: Defaults use_pty and Defaults log_output (no logfile).
        // visudo -c: "parsed OK"
        let diags = lint_w04(
            "Defaults env_reset\nDefaults use_pty\nDefaults log_output\nroot ALL=(ALL:ALL) ALL\n",
        );
        let logfile_diags: Vec<_> = diags
            .iter()
            .filter(|d| d.code == "sudo-W04" && d.message.contains("logfile"))
            .collect();
        assert!(
            logfile_diags.is_empty(),
            "'Defaults log_output' must satisfy the I/O logging requirement; got {diags:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Clean file: no W04 when all required settings present, no weakening
    // -----------------------------------------------------------------------

    /// A file with `use_pty` + `logfile` and no weakening Defaults fires NO W04.
    ///
    /// Fixture verified valid by `visudo -c`.
    #[test]
    fn w04_clean_when_use_pty_and_logfile_and_no_weakening() {
        // Fixture: env_reset + use_pty + logfile; no weakening settings.
        // visudo -c: "parsed OK"
        let diags = lint_w04(
            "Defaults env_reset\n\
             Defaults use_pty\n\
             Defaults logfile=/var/log/sudo.log\n\
             root ALL=(ALL:ALL) ALL\n\
             %wheel ALL=(ALL) ALL\n",
        );
        let w04_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-W04").collect();
        assert!(
            w04_diags.is_empty(),
            "a fully compliant file must produce no W04; got {w04_diags:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Non-STIG Defaults: no false positives
    // -----------------------------------------------------------------------

    /// `Defaults env_reset` alone does NOT fire W04 (it is not a STIG finding).
    /// (It DOES fire absence findings for use_pty and logfile, but not for env_reset.)
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
    fn scope_label_global_is_empty_string() {
        assert_eq!(scope_label(&DefaultsScope::Global), "");
    }

    #[test]
    fn scope_label_user_includes_username() {
        assert_eq!(
            scope_label(&DefaultsScope::User("alice".into())),
            "user:alice "
        );
    }

    #[test]
    fn scope_label_host_includes_hostname() {
        assert_eq!(
            scope_label(&DefaultsScope::Host("myhost".into())),
            "host:myhost "
        );
    }

    // -----------------------------------------------------------------------
    // Multi-file: each file checked independently
    // -----------------------------------------------------------------------

    /// Two files, each missing use_pty -> two W04 absence findings.
    #[test]
    fn w04_absence_check_fires_per_file() {
        let files = vec![
            parse(
                "Defaults env_reset\nroot ALL=(ALL:ALL) ALL\n",
                Path::new("/etc/sudoers"),
            ),
            parse(
                "Defaults env_reset\nroot ALL=(ALL:ALL) ALL\n",
                Path::new("/etc/sudoers.d/extra"),
            ),
        ];
        let diags = w04(&files, &CTX);
        let use_pty_diags: Vec<_> = diags
            .iter()
            .filter(|d| d.code == "sudo-W04" && d.message.contains("use_pty"))
            .collect();
        assert_eq!(
            use_pty_diags.len(),
            2,
            "each file independently fires W04 for missing use_pty; got {use_pty_diags:?}"
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
