//! Map a finished lint result onto an exit code per spec §9.4.

use rulesteward_core::{Diagnostic, Severity};

/// Exit codes per spec §9.4.
pub const EXIT_CLEAN: i32 = 0;
pub const EXIT_WARNINGS: i32 = 1;
pub const EXIT_ERRORS: i32 = 2;
pub const EXIT_TOOL_FAILURE: i32 = 3;
pub const EXIT_RULE_PARSE_ERROR: i32 = 5;
pub const EXIT_NO_OP: i32 = 9;

/// Compute the exit code for a finished lint run.
///
/// Order matters:
/// 1. `tool_err == true` → [`EXIT_TOOL_FAILURE`] (3).
/// 2. Any `F01` → [`EXIT_RULE_PARSE_ERROR`] (5).
/// 3. Any `Fatal` or `Error` → [`EXIT_ERRORS`] (2).
/// 4. Any `Warning` → [`EXIT_WARNINGS`] (1).
/// 5. Otherwise → [`EXIT_CLEAN`] (0).
#[must_use]
pub fn compute(diags: &[Diagnostic], tool_err: bool) -> i32 {
    if tool_err {
        return EXIT_TOOL_FAILURE;
    }
    if diags.iter().any(|d| d.code.as_ref() == "F01") {
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
            compute(&[diag(Severity::Warning, "W02")], false),
            EXIT_WARNINGS
        );
    }

    #[test]
    fn error_returns_two() {
        assert_eq!(compute(&[diag(Severity::Error, "E01")], false), EXIT_ERRORS);
    }

    #[test]
    fn fatal_non_f01_returns_two() {
        assert_eq!(compute(&[diag(Severity::Fatal, "F02")], false), EXIT_ERRORS);
    }

    #[test]
    fn f01_returns_five_even_with_other_errors() {
        let diags = [diag(Severity::Fatal, "F02"), diag(Severity::Fatal, "F01")];
        assert_eq!(compute(&diags, false), EXIT_RULE_PARSE_ERROR);
    }

    #[test]
    fn tool_err_overrides_everything() {
        let diags = [diag(Severity::Fatal, "F01")];
        assert_eq!(compute(&diags, true), EXIT_TOOL_FAILURE);
    }
}
