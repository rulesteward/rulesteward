//! The global `--profile <framework>` finding filter (issue #506, v0.7).
//!
//! `--profile stig|cis|pci|nist` keeps only findings that enforce a control in
//! the named [`Framework`], dropping the rest. When the filter turns a
//! PREVIOUSLY-NON-EMPTY finding set into an empty one, the caller returns
//! [`crate::exit_code::EXIT_NO_OP`] (9) instead of the clean 0, so CI can tell
//! "the profile matched nothing to check" from "checked and clean".
//!
//! The no-op decision lives HERE, not in [`crate::exit_code::compute`]: `compute`
//! sees only the already-filtered slice and returns 0 for an empty slice, so it
//! cannot distinguish a genuinely-clean scan from a filtered-empty one. Each lint
//! seam therefore calls [`apply_profile`] on its owned `Vec<Diagnostic>` right
//! before rendering, and maps a `true` return to `EXIT_NO_OP`.

use rulesteward_core::{Diagnostic, Framework};

/// Filter `diags` in place to only the findings that enforce a control in
/// `profile`'s framework, and report whether the filter emptied a non-empty set.
///
/// * `profile == None` -> no filter: `diags` is left untouched and the return is
///   `false` (the byte-identical no-flag path; the caller uses the normal
///   `exit_code::compute`).
/// * `profile == Some(fw)` -> keep only findings whose `controls` include a
///   [`Framework`] equal to `fw`; return `true` iff `diags` was non-empty before
///   the filter and is empty after (the no-op signal the caller maps to
///   [`crate::exit_code::EXIT_NO_OP`]).
///
/// A finding with no `controls` never matches any framework, so any `--profile`
/// drops it (e.g. every fapolicyd finding, which carries no control mapping).
pub fn apply_profile(diags: &mut Vec<Diagnostic>, profile: Option<Framework>) -> bool {
    let Some(fw) = profile else {
        return false;
    };
    let had = !diags.is_empty();
    // A parse-failure F01 is EXEMPT from the filter: a file that failed to parse
    // was never checked, so dropping its (control-less) F01 would vanish the error
    // and mis-signal a no-op. Keeping it also holds `parse_failed` true for the
    // fapolicyd SARIF pass-attestation suppression (#137 / lint.rs). The exemption
    // reuses `exit_code::is_parse_error_code` so the F01 set never drifts from the
    // exit-code mapping. This branch lives here (mutation-gated) on purpose.
    diags.retain(|d| {
        crate::exit_code::is_parse_error_code(d.code.as_ref())
            || d.controls.iter().any(|c| c.framework == fw)
    });
    had && diags.is_empty()
}

/// Map a completed lint run to its process exit code, honoring the `--profile`
/// no-op signal from [`apply_profile`].
///
/// * `no_op == true` (the filter emptied a previously-non-empty set) ->
///   [`crate::exit_code::EXIT_NO_OP`] (9).
/// * `no_op == false` -> the normal severity-based [`crate::exit_code::compute`]
///   over the (possibly filtered) `diags`.
///
/// Centralizes the identical post-render tail every lint seam runs, so the
/// no-op-vs-compute decision cannot drift between backends.
#[must_use]
pub fn resolve_exit_code(no_op: bool, diags: &[Diagnostic], tool_err: bool) -> i32 {
    if no_op {
        crate::exit_code::EXIT_NO_OP
    } else {
        crate::exit_code::compute(diags, tool_err)
    }
}

#[cfg(test)]
mod tests {
    use super::apply_profile;
    use rulesteward_core::{ControlRef, Diagnostic, Framework, Severity};

    /// A diagnostic tagged with the given controls (or none). The severity/code
    /// are irrelevant to the filter, which keys only on `controls`.
    fn diag(code: &'static str, controls: Vec<ControlRef>) -> Diagnostic {
        Diagnostic::new(Severity::Warning, code, 0..0, "msg", "/tmp/x", 1, 1)
            .with_controls(controls)
    }

    #[test]
    fn none_profile_retains_all_and_reports_not_a_no_op() {
        // No --profile -> the byte-identical path: nothing is dropped, and the
        // function reports `false` (never a no-op) even for a non-empty set.
        let mut diags = vec![
            diag("a-W01", vec![ControlRef::new(Framework::Stig, "RHEL-08-1")]),
            diag("b-W02", vec![]),
        ];
        let no_op = apply_profile(&mut diags, None);
        assert!(!no_op, "None must never signal a no-op");
        assert_eq!(diags.len(), 2, "None must retain every diagnostic");
    }

    #[test]
    fn some_stig_retains_only_stig_bearing_findings() {
        // A mixed set: one STIG finding, one CIS finding, one with no controls.
        // --profile stig keeps only the STIG one; the CIS and control-less ones go.
        let mut diags = vec![
            diag("a-W01", vec![ControlRef::new(Framework::Stig, "RHEL-08-1")]),
            diag("b-W02", vec![ControlRef::new(Framework::Cis, "1.3.2")]),
            diag("c-W03", vec![]),
        ];
        let no_op = apply_profile(&mut diags, Some(Framework::Stig));
        assert!(
            !no_op,
            "a set still holding a STIG finding after the filter is not a no-op"
        );
        assert_eq!(diags.len(), 1, "only the STIG-bearing finding survives");
        assert_eq!(diags[0].code.as_ref(), "a-W01");
    }

    #[test]
    fn parse_error_findings_are_exempt_from_the_filter() {
        use rulesteward_core::Severity;
        // A parse-failure F01 diagnostic (Fatal, no controls) MUST survive any
        // --profile: a file that FAILED to parse was never checked, so its F01 can
        // never be dropped as "no matching control" (that would vanish the error
        // and mis-signal a no-op). The uncontrolled Warning beside it is still
        // dropped, so this proves the exemption is CODE-specific, not blanket.
        let f01 = Diagnostic::new(
            Severity::Fatal,
            "sysctld-F01",
            0..0,
            "parse fail",
            "/tmp/x",
            1,
            1,
        );
        let mut diags = vec![f01, diag("a-W02", vec![])];
        let no_op = apply_profile(&mut diags, Some(Framework::Stig));
        assert!(
            !no_op,
            "a surviving F01 keeps the set non-empty -> not a no-op (compute returns 5, not 9)"
        );
        assert_eq!(
            diags.len(),
            1,
            "the F01 is retained; the uncontrolled warning is dropped"
        );
        assert_eq!(diags[0].code.as_ref(), "sysctld-F01");
    }

    #[test]
    fn multi_framework_finding_is_kept_by_any_matching_profile() {
        // A finding tagged BOTH Cis and Pci is retained by --profile cis AND by
        // --profile pci (the `any` over controls), and dropped by --profile stig.
        let both = || {
            vec![diag(
                "w04",
                vec![
                    ControlRef::new(Framework::Cis, "1.3.2"),
                    ControlRef::new(Framework::Pci, "Req-10.2.5"),
                ],
            )]
        };
        let mut cis = both();
        assert!(!apply_profile(&mut cis, Some(Framework::Cis)));
        assert_eq!(cis.len(), 1, "--profile cis keeps the Cis+Pci finding");

        let mut pci = both();
        assert!(!apply_profile(&mut pci, Some(Framework::Pci)));
        assert_eq!(pci.len(), 1, "--profile pci keeps the Cis+Pci finding");

        let mut stig = both();
        let no_op = apply_profile(&mut stig, Some(Framework::Stig));
        assert!(stig.is_empty(), "--profile stig drops the Cis+Pci finding");
        assert!(no_op, "emptying a non-empty set is a no-op");
    }

    #[test]
    fn emptying_a_nonempty_set_reports_a_no_op() {
        // A non-empty set whose findings all lack the requested framework is
        // emptied -> the function reports `true` (the EXIT_NO_OP signal).
        let mut diags = vec![
            diag("a-W01", vec![ControlRef::new(Framework::Cis, "1.3.2")]),
            diag("b-W02", vec![]),
        ];
        let no_op = apply_profile(&mut diags, Some(Framework::Stig));
        assert!(diags.is_empty(), "no STIG finding survives");
        assert!(no_op, "emptying a previously-non-empty set is a no-op");
    }

    #[test]
    fn resolve_exit_code_prefers_no_op_else_delegates_to_compute() {
        use crate::exit_code::{EXIT_CLEAN, EXIT_NO_OP, EXIT_TOOL_FAILURE, EXIT_WARNINGS};
        // no_op=true short-circuits to EXIT_NO_OP even though an empty slice would
        // otherwise compute EXIT_CLEAN.
        assert_eq!(super::resolve_exit_code(true, &[], false), EXIT_NO_OP);
        // no_op=false defers to compute: an empty clean slice -> EXIT_CLEAN.
        assert_eq!(super::resolve_exit_code(false, &[], false), EXIT_CLEAN);
        // no_op=false with a Warning -> EXIT_WARNINGS (proves it delegates to
        // compute, not a constant).
        let warn = diag("x-W01", vec![]);
        assert_eq!(
            super::resolve_exit_code(false, std::slice::from_ref(&warn), false),
            EXIT_WARNINGS
        );
        // tool_err flows through to compute -> EXIT_TOOL_FAILURE.
        assert_eq!(
            super::resolve_exit_code(false, &[], true),
            EXIT_TOOL_FAILURE
        );
    }

    #[test]
    fn already_empty_set_is_never_a_no_op() {
        // An ALREADY-clean scan + --profile stays clean: nothing was emptied, so
        // the caller keeps exit 0 (NOT 9). This is the CLEAN+PROFILE contract.
        let mut diags: Vec<Diagnostic> = Vec::new();
        let no_op = apply_profile(&mut diags, Some(Framework::Stig));
        assert!(
            !no_op,
            "an already-empty set was not emptied BY the filter, so not a no-op"
        );
    }
}
