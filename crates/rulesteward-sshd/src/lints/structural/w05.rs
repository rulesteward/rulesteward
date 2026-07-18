//! sshd-W05: `Match` block overrides a required global directive. See [`w05`].

use std::path::Path;

use rulesteward_core::{Diagnostic, Severity};

use crate::ast::Block;
use crate::lints::{SshdLintContext, anchored, is_unconditional_match_all};

use super::e04::e04_match_permitted;

/// sshd-W05: a `Match` block overrides a required global directive in a more
/// permissive direction (a STIG escape hatch).
///
/// Fires once per Match-body directive whose value fails the W02 STIG baseline
/// for the given target. Does NOT fire for the global block (that is W02's job).
///
/// Only directives the daemon actually HONORS inside a `Match` block are
/// evaluated (gated on [`e04_match_permitted`]). A STIG-controlled directive
/// that sshd rejects in a Match block (e.g. `StrictModes`, `PermitUserEnvironment`
/// -- `sshd -t` exits 255 with "not allowed within a Match block") is a sshd-E04
/// finding, not a W05 one: it never takes effect, so calling it "a more permissive
/// value" would be wrong. Skipping those here avoids a contradictory double-fire
/// alongside E04.
#[must_use]
pub fn w05(blocks: &[Block], file: &Path, ctx: &SshdLintContext) -> Vec<Diagnostic> {
    use crate::lints::stig::{BaselineCheck, baseline_check};

    let mut diags = Vec::new();
    for block in blocks {
        let Block::Match(match_block) = block else {
            continue;
        };
        if is_unconditional_match_all(match_block) {
            // `Match all` is global context, not a conditional override; a weak
            // value there is a global sshd-W02 finding, not a W05 escape hatch.
            // (issue #336)
            continue;
        }
        for directive in &match_block.body {
            let kw = directive.keyword_lower();
            // A Match-illegal directive never takes effect inside the block, so
            // it cannot be a "more permissive override"; that is E04's finding.
            if !e04_match_permitted(&kw, ctx.target) {
                continue;
            }
            if let BaselineCheck::Violation {
                requirement,
                displayed_value,
            } = baseline_check(&kw, &directive.args, ctx.target)
            {
                diags.push(anchored(
                    Severity::Warning,
                    "sshd-W05",
                    directive.span.clone(),
                    format!(
                        "Match block sets STIG-controlled directive '{}' to '{displayed_value}', \
                         a more permissive value; STIG baseline requires {requirement}",
                        directive.keyword,
                    ),
                    file,
                    directive.line,
                ));
            }
        }
    }
    diags
}

// ---------------------------------------------------------------------------
// sshd-W05 tests
// ---------------------------------------------------------------------------
//
// W05 fires when a Match block body directive has
// `baseline_check(keyword_lower, args, target) == BaselineCheck::Violation`.
// This is inherently W01-scoped: `baseline_check` returns `Violation` only for
// W02-controlled STIG directives, which are a subset of the required set.
//
// Firing rule (reading A, DECIDED): independent of whether the global block
// sets the directive -- a Match override that fails the baseline is the escape
// hatch and always fires W05.
//
// Non-STIG directives (e.g. PasswordAuthentication) return `NotControlled` from
// `baseline_check` and must NEVER trigger W05.
//
// Each test MUST be RED against the empty stub (`w05` returns `Vec::new()`).

#[cfg(test)]
mod w05_tests {
    //! sshd-W05: Match block overrides a STIG-required directive in a more
    //! permissive direction (STIG escape hatch).

    use super::w05;
    use crate::ast::Block;
    use crate::lints::{SshdLintContext, TargetVersion};
    use rulesteward_core::Diagnostic;
    use std::path::Path;

    fn parse(src: &str) -> Vec<Block> {
        crate::parser::parse_config_str_located(src, Path::new("/etc/ssh/sshd_config"))
            .expect("fixture parses")
    }

    fn run(src: &str) -> Vec<Diagnostic> {
        w05(
            &parse(src),
            Path::new("/etc/ssh/sshd_config"),
            &SshdLintContext::default(),
        )
    }

    fn run_with_target(src: &str, target: TargetVersion) -> Vec<Diagnostic> {
        w05(
            &parse(src),
            Path::new("/etc/ssh/sshd_config"),
            &SshdLintContext {
                target: Some(target),
                single_file: true,
            },
        )
    }

    // --- FIRES: ExactLower("no") baseline violation via PermitRootLogin yes ---
    //
    // PermitRootLogin must be "no" (W02 rule: ExactLower("no"), universal floor).
    // A Match block setting PermitRootLogin yes is a STIG escape hatch -> W05.
    // This is also the canonical example from the task spec.
    //
    // The stub returns Vec::new() -> "fires" assertion fails RED.
    #[test]
    fn fires_for_permitrootlogin_yes_in_match_rhel9() {
        // Line layout:
        //   1: PermitRootLogin no   (global, compliant -- W05 must NOT see this)
        //   2: Match Group admins
        //   3:     PermitRootLogin yes   (Match body, violates baseline -> W05)
        let src = "PermitRootLogin no\nMatch Group admins\n    PermitRootLogin yes\n";
        let diags = run_with_target(src, TargetVersion::Rhel9);
        assert_eq!(
            diags.len(),
            1,
            "exactly one W05 for a PermitRootLogin yes in a Match body; got {diags:?}"
        );
        assert_eq!(diags[0].code, "sshd-W05", "must carry code sshd-W05");
        assert_eq!(
            diags[0].line, 3,
            "diagnostic must anchor at the Match-body directive line (line 3)"
        );
        // Message must name the offending directive and the violating value.
        assert!(
            diags[0].message.contains("PermitRootLogin"),
            "message must name the directive; got: {}",
            diags[0].message
        );
        assert!(
            diags[0].message.contains("yes"),
            "message must name the violating value; got: {}",
            diags[0].message
        );
    }

    // --- issue #336: unconditional `Match all` is NOT a conditional override ---

    #[test]
    fn unconditional_match_all_is_not_a_w05_override() {
        // `Match all` is always-active global context, not a conditional override.
        // A weak STIG value there is a GLOBAL weakness (W02's job), never W05.
        let src = "PermitRootLogin no\nMatch all\n    PermitRootLogin yes\n";
        assert!(
            run_with_target(src, TargetVersion::Rhel9).is_empty(),
            "`Match all` is not a Match override; W05 must not fire"
        );
    }

    #[test]
    fn match_all_case_insensitive_is_not_a_w05_override() {
        // `Match All` (capitalized) is still the unconditional global block.
        let src = "PermitRootLogin no\nMatch All\n    PermitRootLogin yes\n";
        assert!(
            run_with_target(src, TargetVersion::Rhel9).is_empty(),
            "`Match All` is the unconditional global block; W05 must not fire"
        );
    }

    #[test]
    fn conditional_match_still_fires_w05_after_match_all_fix() {
        // Regression guard: a genuine conditional Match override still fires W05.
        let src = "PermitRootLogin no\nMatch Group admins\n    PermitRootLogin yes\n";
        let diags = run_with_target(src, TargetVersion::Rhel9);
        assert_eq!(diags.len(), 1, "conditional Match override still fires W05");
        assert_eq!(diags[0].code, "sshd-W05");
    }

    // --- FIRES: NumericCeiling(600) baseline violation via ClientAliveInterval ---
    //
    // ClientAliveInterval must be > 0 and <= 600 (universal floor).
    // A Match block setting ClientAliveInterval 900 exceeds the ceiling -> W05.
    //
    // The stub returns Vec::new() -> "fires" assertion fails RED.
    #[test]
    fn fires_for_clientaliveinterval_too_large_in_match() {
        // Line layout:
        //   1: ClientAliveInterval 300   (global, compliant)
        //   2: Match Group ops
        //   3:     ClientAliveInterval 900   (exceeds 600 ceiling -> Violation)
        let src = "ClientAliveInterval 300\nMatch Group ops\n    ClientAliveInterval 900\n";
        let diags = run(src);
        assert_eq!(
            diags.len(),
            1,
            "exactly one W05 for ClientAliveInterval 900 in a Match body; got {diags:?}"
        );
        assert_eq!(diags[0].code, "sshd-W05");
        assert_eq!(
            diags[0].line, 3,
            "diagnostic must anchor at the Match-body directive line"
        );
        assert!(
            diags[0].message.contains("ClientAliveInterval"),
            "message must name the directive; got: {}",
            diags[0].message
        );
        assert!(
            diags[0].message.contains("900"),
            "message must echo the violating value; got: {}",
            diags[0].message
        );
    }

    // --- FIRES: reading-A semantics -- no global block entry required ---
    //
    // Reading A: W05 fires regardless of whether the global block sets the
    // directive. This test has NO global PermitRootLogin; the Match body alone
    // triggers W05 because the override fails the baseline.
    //
    // The stub returns Vec::new() -> "fires" assertion fails RED.
    #[test]
    fn fires_even_when_global_block_does_not_set_the_directive() {
        // No global PermitRootLogin. Match body sets it to a violating value.
        let src = "Match User root\n    PermitRootLogin yes\n";
        let diags = run(src);
        assert_eq!(
            diags.len(),
            1,
            "W05 must fire on the Match body directive regardless of global absence; \
             got {diags:?}"
        );
        assert_eq!(diags[0].code, "sshd-W05");
        assert_eq!(diags[0].line, 2);
    }

    // --- FIRES: target=None (floor) for a universal STIG directive ---
    //
    // PermitRootLogin is controlled at the floor (RHEL8 required set, which
    // is the floor). W05 must fire even without --target.
    //
    // The stub returns Vec::new() -> "fires" assertion fails RED.
    #[test]
    fn fires_for_floor_target_none_universal_directive() {
        let src = "PermitRootLogin no\nMatch Group ops\n    PermitRootLogin yes\n";
        // target=None uses the conservative floor (RHEL8 required set)
        let diags = run(src);
        assert_eq!(
            diags.len(),
            1,
            "PermitRootLogin is in the floor required set; W05 must fire at target=None; \
             got {diags:?}"
        );
        assert_eq!(diags[0].code, "sshd-W05");
        assert_eq!(diags[0].line, 3);
    }

    // --- FIRES: multiple Match blocks, only the violating one fires ---
    //
    // First Match block: PermitRootLogin no (compliant, no W05).
    // Second Match block: PermitRootLogin yes (violating, fires W05).
    // Total: exactly one diagnostic on the second block's directive line.
    //
    // The stub returns Vec::new() -> "fires" assertion fails RED.
    #[test]
    fn fires_only_for_the_violating_match_block() {
        // Line layout:
        //   1: Match User alice
        //   2:     PermitRootLogin no        (compliant; no W05)
        //   3: Match Group admins
        //   4:     PermitRootLogin yes       (violating -> W05)
        let src = "Match User alice\n    PermitRootLogin no\nMatch Group admins\n    PermitRootLogin yes\n";
        let diags = run_with_target(src, TargetVersion::Rhel9);
        assert_eq!(
            diags.len(),
            1,
            "only the violating Match block (line 4) must fire; got {diags:?}"
        );
        assert_eq!(diags[0].code, "sshd-W05");
        assert_eq!(
            diags[0].line, 4,
            "diagnostic must anchor at line 4 (the violating block's directive)"
        );
    }

    // --- FIRES: one diagnostic per violating directive in the same Match block ---
    //
    // Two STIG-controlled directives in the same Match body both violate:
    // PermitRootLogin yes (must be "no") and X11Forwarding yes (must be "no").
    // Each violating directive produces its own W05 diagnostic.
    //
    // The stub returns Vec::new() -> "fires" assertion (len 2) fails RED.
    #[test]
    fn fires_once_per_violating_directive_in_a_single_match() {
        // Line layout:
        //   1: Match Group dev
        //   2:     PermitRootLogin yes    (Violation -> W05)
        //   3:     X11Forwarding yes      (Violation -> W05)
        let src = "Match Group dev\n    PermitRootLogin yes\n    X11Forwarding yes\n";
        let diags = run_with_target(src, TargetVersion::Rhel9);
        assert_eq!(
            diags.len(),
            2,
            "two violating directives in the same Match body yield two W05 diagnostics; \
             got {diags:?}"
        );
        let codes: Vec<&str> = diags.iter().map(|d| &d.code[..]).collect();
        assert!(
            codes.iter().all(|c| *c == "sshd-W05"),
            "all diagnostics must carry code sshd-W05; got {codes:?}"
        );
        let lines: Vec<usize> = diags.iter().map(|d| d.line).collect();
        assert!(
            lines.contains(&2),
            "PermitRootLogin yes must be flagged at line 2; lines = {lines:?}"
        );
        assert!(
            lines.contains(&3),
            "X11Forwarding yes must be flagged at line 3; lines = {lines:?}"
        );
    }

    // --- DOES NOT FIRE: compliant value in Match body (tightening / exact match) ---
    //
    // PermitRootLogin no inside a Match: this IS the required value.
    // baseline_check returns Ok -> no W05.
    #[test]
    fn does_not_fire_for_compliant_value_in_match() {
        let src = "Match Group sftp\n    PermitRootLogin no\n";
        let diags = run_with_target(src, TargetVersion::Rhel9);
        assert!(
            diags.is_empty(),
            "PermitRootLogin no is compliant; W05 must not fire; got {diags:?}"
        );
    }

    // --- DOES NOT FIRE: tightening a numeric (below ceiling) ---
    //
    // ClientAliveInterval 300 in a Match: the ceiling is 600 and 300 <= 600 -> Ok.
    // W05 must not fire for a value that satisfies the baseline.
    #[test]
    fn does_not_fire_for_numeric_tightening_in_match() {
        let src = "ClientAliveInterval 600\nMatch Group ops\n    ClientAliveInterval 300\n";
        let diags = run(src);
        assert!(
            diags.is_empty(),
            "ClientAliveInterval 300 satisfies the <=600 baseline; W05 must not fire; \
             got {diags:?}"
        );
    }

    // --- DOES NOT FIRE: non-STIG directive (PasswordAuthentication) ---
    //
    // #244's example: PasswordAuthentication is NOT in the W02 controlled set.
    // baseline_check("passwordauthentication", ...) returns NotControlled.
    // W05 must not fire even though the Match sets a looser value.
    //
    // This pins the W01-scoped decision: only W02-controlled directives are in scope.
    #[test]
    fn does_not_fire_for_non_stig_directive_in_match() {
        // PasswordAuthentication has no W02 rule; baseline_check -> NotControlled.
        let src = "Match Group sftp\n    PasswordAuthentication yes\n";
        let diags = run_with_target(src, TargetVersion::Rhel9);
        assert!(
            diags.is_empty(),
            "PasswordAuthentication is not a W02-controlled directive; \
             W05 must not fire (issue #244 example); got {diags:?}"
        );
    }

    // --- DOES NOT FIRE: global block directive (W02's responsibility, not W05) ---
    //
    // A violating directive in the GLOBAL block must produce NO W05 diagnostic.
    // (That is W02's job, tested elsewhere.) W05 is Match-only.
    //
    // This pins the non-double-fire property.
    #[test]
    fn does_not_fire_for_global_block_violation() {
        // Global PermitRootLogin yes is a W02 finding, not W05.
        // No Match blocks -> no Match body to inspect.
        let src = "PermitRootLogin yes\n";
        let diags = run_with_target(src, TargetVersion::Rhel9);
        assert!(
            diags.is_empty(),
            "a violating directive in the global block is a W02 finding, not W05; \
             W05 must return empty for a config with no Match blocks; got {diags:?}"
        );
    }

    // --- DOES NOT FIRE: global block has violating value BUT Match body is compliant ---
    //
    // The global block has PermitRootLogin yes (a W02 issue). The Match block sets
    // PermitRootLogin no (compliant). W05 must NOT fire for the Match body.
    #[test]
    fn does_not_fire_when_match_body_is_compliant_even_if_global_violates() {
        // Line layout:
        //   1: PermitRootLogin yes    (W02 concern, not W05)
        //   2: Match Group audit
        //   3:     PermitRootLogin no  (compliant in Match body -> no W05)
        let src = "PermitRootLogin yes\nMatch Group audit\n    PermitRootLogin no\n";
        let diags = run_with_target(src, TargetVersion::Rhel9);
        assert!(
            diags.is_empty(),
            "Match body sets the compliant value; W05 must not fire; got {diags:?}"
        );
    }

    // --- DOES NOT FIRE: Compression yes in Match under --target rhel10 ---
    //
    // #549 REFRESHED (2026-07-17): written when Compression was a RHEL8/9-only
    // W02 control (RHEL10 V1R1 had already dropped it). DISA RHEL 9 STIG V2R9
    // (confirmed via U_RHEL_9_V2R9_STIG.zip; lane3-tooling.md T1) subsequently
    // dropped Compression from RHEL9 too (V-258002/RHEL-09-255130 removed), so
    // Compression is now not a W02 control on ANY target -- but this test's
    // assertion (rhel10 specifically stays silent) remains true either way.
    // Under --target rhel10, baseline_check("compression", ...) returns
    // NotControlled, so a Match setting Compression yes must NOT fire W05.
    //
    // This pins the target-aware W02 rule propagation through baseline_check.
    #[test]
    fn does_not_fire_for_compression_in_match_under_rhel10() {
        let src = "Compression no\nMatch Group sftp\n    Compression yes\n";
        let diags = run_with_target(src, TargetVersion::Rhel10);
        assert!(
            diags.is_empty(),
            "Compression is not a RHEL10 STIG control (V1R1 dropped it); \
             W05 must not fire under --target rhel10; got {diags:?}"
        );
    }

    // --- Discriminating: trivial "always empty" impl fails the fires tests above.
    //     Trivial "fire on every Match directive" impl fails the no-fire tests above.
    //     Trivial "fire ignoring baseline" impl fails does_not_fire_for_compliant_value.
    //     This test pins an additional discriminating property: the ClientAliveCountMax
    //     exact-1 rule (NumericExact). Zero is NOT a valid value (not > 0); W05 fires.
    //
    //     The stub returns Vec::new() -> "fires" assertion fails RED.
    #[test]
    fn fires_for_clientalivecountmax_zero_in_match() {
        // ClientAliveCountMax must be exactly 1 (W02Rule::NumericExact(1)).
        // ClientAliveCountMax 0 fails: parse::<u64>() ok but != 1 -> Violation.
        let src = "ClientAliveCountMax 1\nMatch Group ops\n    ClientAliveCountMax 0\n";
        let diags = run(src);
        assert_eq!(
            diags.len(),
            1,
            "ClientAliveCountMax 0 violates the exact-1 STIG rule; W05 must fire; \
             got {diags:?}"
        );
        assert_eq!(diags[0].code, "sshd-W05");
        assert_eq!(diags[0].line, 3);
        assert!(
            diags[0].message.contains("ClientAliveCountMax"),
            "message must name the directive; got: {}",
            diags[0].message
        );
    }

    // --- DOES NOT FIRE: STIG-controlled but Match-ILLEGAL directive (StrictModes) ---
    //
    // StrictModes is a W02-controlled directive (must be "yes"), so a Match body
    // setting `StrictModes no` is a baseline FAILURE. But sshd does NOT honor
    // StrictModes inside a Match block: `sshd -t` rejects the config with
    // "StrictModes ... not allowed within a Match block" (rc 255, verified on
    // live rocky9 OpenSSH 9.9p1). The correct finding is sshd-E04 (which already
    // fires); W05 must NOT double-fire with a contradictory "more permissive
    // value" message. W05 only evaluates directives sshd actually honors in a
    // Match block (gated on e04_match_permitted).
    #[test]
    fn does_not_fire_for_match_illegal_strictmodes_floor() {
        // StrictModes no inside a Match: baseline-failing AND Match-illegal.
        let src = "Match Group sftp\n    StrictModes no\n";
        // target=None (floor): StrictModes is a universal W02 control, but it is
        // Match-illegal on every version, so W05 must not fire.
        let diags = run(src);
        assert!(
            diags.is_empty(),
            "StrictModes is Match-illegal (sshd-E04's job, not W05); \
             W05 must not fire at target=None; got {diags:?}"
        );
    }

    #[test]
    fn does_not_fire_for_match_illegal_strictmodes_rhel9() {
        let src = "Match Group sftp\n    StrictModes no\n";
        let diags = run_with_target(src, TargetVersion::Rhel9);
        assert!(
            diags.is_empty(),
            "StrictModes is Match-illegal (sshd-E04's job, not W05); \
             W05 must not fire under --target rhel9; got {diags:?}"
        );
    }

    // --- DOES NOT FIRE: STIG-controlled but Match-ILLEGAL (PermitUserEnvironment) ---
    //
    // PermitUserEnvironment is a W02-controlled directive (must be "no"), so a
    // Match body setting `PermitUserEnvironment yes` is a baseline FAILURE. But
    // sshd does NOT honor it inside a Match block (rejected by `sshd -t`, rc 255,
    // verified on live rocky9 OpenSSH 9.9p1). The correct finding is sshd-E04;
    // W05 must NOT double-fire.
    #[test]
    fn does_not_fire_for_match_illegal_permituserenvironment_floor() {
        let src = "Match User svc\n    PermitUserEnvironment yes\n";
        let diags = run(src);
        assert!(
            diags.is_empty(),
            "PermitUserEnvironment is Match-illegal (sshd-E04's job, not W05); \
             W05 must not fire at target=None; got {diags:?}"
        );
    }

    #[test]
    fn does_not_fire_for_match_illegal_permituserenvironment_rhel9() {
        let src = "Match User svc\n    PermitUserEnvironment yes\n";
        let diags = run_with_target(src, TargetVersion::Rhel9);
        assert!(
            diags.is_empty(),
            "PermitUserEnvironment is Match-illegal (sshd-E04's job, not W05); \
             W05 must not fire under --target rhel9; got {diags:?}"
        );
    }
}
