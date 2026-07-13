//! Map a finished lint result onto an exit code per spec §12.4.

use rulesteward_core::{Diagnostic, Severity};

/// Exit codes per spec §12.4.
pub const EXIT_CLEAN: i32 = 0;
pub const EXIT_WARNINGS: i32 = 1;
pub const EXIT_ERRORS: i32 = 2;
pub const EXIT_TOOL_FAILURE: i32 = 3;
/// LMDB / trust-DB engine error (could not open or read the trust DB).
pub const EXIT_LMDB_ERROR: i32 = 4;
pub const EXIT_RULE_PARSE_ERROR: i32 = 5;
/// Daemon IPC error. RESERVED: `RuleSteward` is a read-only linter with no daemon connection
/// today; defined so the code space matches spec section 12.4 and a future daemon-query mode
/// has a stable code. Not currently emitted.
#[allow(dead_code)]
pub const EXIT_DAEMON_IPC: i32 = 6;
/// Filesystem error (a path that exists but could not be read as expected).
#[allow(dead_code)]
pub const EXIT_FS_ERROR: i32 = 7;
/// Out-of-memory. RESERVED: no graceful OOM path in a read-only linter today.
#[allow(dead_code)]
pub const EXIT_OOM: i32 = 8;
pub const EXIT_NO_OP: i32 = 9;

/// Compute the exit code for a finished lint run.
///
/// Order matters:
/// 1. `tool_err == true` → [`EXIT_TOOL_FAILURE`] (3).
/// 2. Any parse-failure code (`fapd-F01` / `au-F01` / `sshd-F01` / `sysctld-F01` / `sudo-F01`) → [`EXIT_RULE_PARSE_ERROR`] (5).
/// 3. Any `Fatal` or `Error` → [`EXIT_ERRORS`] (2).
/// 4. Any `Warning` → [`EXIT_WARNINGS`] (1).
/// 5. Otherwise → [`EXIT_CLEAN`] (0).
#[must_use]
pub fn compute(diags: &[Diagnostic], tool_err: bool) -> i32 {
    if tool_err {
        return EXIT_TOOL_FAILURE;
    }
    // Each backend's parse-failure code maps to exit 5 (spec section 12.4 uses
    // one numbering across modules; D3, session 6a).
    if diags.iter().any(|d| is_parse_error_code(d.code.as_ref())) {
        return EXIT_RULE_PARSE_ERROR;
    }
    if diags
        .iter()
        .any(|d| matches!(d.severity, Severity::Fatal | Severity::Error))
    {
        return EXIT_ERRORS;
    }
    if diags.iter().any(|d| d.severity == Severity::Warning) {
        return EXIT_WARNINGS;
    }
    EXIT_CLEAN
}

/// True if `code` is a backend parse-failure code.
///
/// The set is `fapd-F01`, `au-F01`, `sshd-F01`, `sysctld-F01`, and `sudo-F01`.
/// These all map to [`EXIT_RULE_PARSE_ERROR`] (spec section 12.4 uses one
/// numbering across modules; D3, session 6a). This is the single source of truth
/// for the F01 set, shared by [`compute`] (the exit-code precedence) and
/// `crate::profile::apply_profile` (the `--profile` parse-error exemption: a file
/// that FAILED to parse was never checked, so its F01 must never be dropped as
/// "no matching control").
#[must_use]
pub fn is_parse_error_code(code: &str) -> bool {
    matches!(
        code,
        "fapd-F01" | "au-F01" | "sshd-F01" | "sysctld-F01" | "sudo-F01"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn diag(sev: Severity, code: &'static str) -> Diagnostic {
        Diagnostic::new(sev, code, 0..0, "msg", "/tmp/x", 1, 1)
    }

    #[test]
    fn empty_diags_clean_is_zero() {
        assert_eq!(compute(&[], false), EXIT_CLEAN);
    }

    #[test]
    fn warnings_only_returns_one() {
        assert_eq!(
            compute(&[diag(Severity::Warning, "fapd-W02")], false),
            EXIT_WARNINGS
        );
    }

    #[test]
    fn error_returns_two() {
        assert_eq!(
            compute(&[diag(Severity::Error, "fapd-E01")], false),
            EXIT_ERRORS
        );
    }

    #[test]
    fn fatal_non_f01_returns_two() {
        assert_eq!(
            compute(&[diag(Severity::Fatal, "fapd-F02")], false),
            EXIT_ERRORS
        );
    }

    #[test]
    fn f01_returns_five_even_with_other_errors() {
        let diags = [
            diag(Severity::Fatal, "fapd-F02"),
            diag(Severity::Fatal, "fapd-F01"),
        ];
        assert_eq!(compute(&diags, false), EXIT_RULE_PARSE_ERROR);
    }

    #[test]
    fn au_f01_returns_five() {
        // D3 (session 6a): the auditd backend's parse-failure code au-F01 maps
        // to the same EXIT_RULE_PARSE_ERROR as fapd-F01 (spec section 12.4:
        // "auditd uses the same numbering"). Without the mapping, au-F01 is
        // merely Fatal and would fall through to EXIT_ERRORS (2).
        assert_eq!(
            compute(&[diag(Severity::Fatal, "au-F01")], false),
            EXIT_RULE_PARSE_ERROR
        );
    }

    #[test]
    fn sysctld_f01_returns_five() {
        // The sysctld backend's parse-failure code sysctld-F01 maps to the same
        // EXIT_RULE_PARSE_ERROR as the other backends' F01 (issue #150); without
        // the mapping it would fall through to EXIT_ERRORS (2). exit_code.rs is
        // outside the mutation examine_globs, so this unit test is the guard that
        // pins the `| "sysctld-F01"` arm.
        assert_eq!(
            compute(&[diag(Severity::Fatal, "sysctld-F01")], false),
            EXIT_RULE_PARSE_ERROR
        );
    }

    #[test]
    fn sshd_f01_returns_five() {
        // The sshd backend's parse-failure code sshd-F01 maps to the same
        // EXIT_RULE_PARSE_ERROR as fapd-F01 / au-F01 (spec section 12.4 uses one
        // numbering across modules). Without the mapping, sshd-F01 is merely Fatal
        // and would fall through to EXIT_ERRORS (2).
        assert_eq!(
            compute(&[diag(Severity::Fatal, "sshd-F01")], false),
            EXIT_RULE_PARSE_ERROR
        );
    }

    #[test]
    fn sudo_f01_returns_five() {
        // The sudoers backend's parse-failure code sudo-F01 maps to the same
        // EXIT_RULE_PARSE_ERROR as the other backends' F01 (issue #329). exit_code.rs
        // is outside the mutation examine_globs, so this unit test is the guard that
        // pins the `| "sudo-F01"` arm; without it sudo-F01 is merely Fatal and would
        // fall through to EXIT_ERRORS (2).
        assert_eq!(
            compute(&[diag(Severity::Fatal, "sudo-F01")], false),
            EXIT_RULE_PARSE_ERROR
        );
    }

    #[test]
    fn au_w01_warning_returns_one() {
        // The au- warning tier rides the same severity fall-through as fapd-.
        assert_eq!(
            compute(&[diag(Severity::Warning, "au-W01")], false),
            EXIT_WARNINGS
        );
    }

    #[test]
    fn tool_err_overrides_everything() {
        let diags = [diag(Severity::Fatal, "fapd-F01")];
        assert_eq!(compute(&diags, true), EXIT_TOOL_FAILURE);
    }

    #[test]
    fn convention_only_is_clean() {
        // fapd-C01 is Convention: advisory, must NOT escalate the exit code.
        // Pins the Convention -> EXIT_CLEAN fall-through against a mutant that
        // re-tiers Convention as a Warning or Error.
        assert_eq!(
            compute(&[diag(Severity::Convention, "fapd-C01")], false),
            EXIT_CLEAN
        );
    }

    #[test]
    fn w04_warning_returns_one() {
        // fapd-W04 is Warning: must yield EXIT_WARNINGS (1), not be swallowed
        // as advisory.
        assert_eq!(
            compute(&[diag(Severity::Warning, "fapd-W04")], false),
            EXIT_WARNINGS
        );
    }
}
