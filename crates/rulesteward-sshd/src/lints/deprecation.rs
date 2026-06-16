//! Deprecation lint: directives deprecated or removed in the target OpenSSH
//! version (`Protocol`, `RhostsRSAAuthentication`, `RSAAuthentication`,
//! `UseLogin`, ...). Consumes the per-OpenSSH-version deprecated-keyword table
//! from the Wave-B grounding task.

use std::path::Path;

use rulesteward_core::{Diagnostic, Severity};

use crate::ast::Block;
use crate::lints::{SshdLintContext, anchored};

/// Deprecated/removed `sshd_config` keywords for sshd-W04.
///
/// Grounding: `rulesteward-docs/sshd-stig-version-grounding.md` section 3,
/// backed by `[VM]` `sudo sshd -t -o "<Keyword>=yes"` on Rocky 8/9/10
/// (OpenSSH 8.0p1 / 9.9p1 / 9.9p1, 2026-06-15T02:23Z). The daemon accepts all
/// of these with `Deprecated option <X>` (sshd-t exit 0), so they are W04 (warn)
/// not E01 (error). `ChallengeResponseAuthentication` is additionally an alias
/// for `KbdInteractiveAuthentication` (renamed in OpenSSH 8.7, `release-8.7`).
///
/// The set is UNIFORM across the supported RHEL 8/9/10 targets (all three VMs
/// gave identical `Deprecated option` responses), so W04 fires under
/// `target=None` (no `--target` flag). Lowercased and sorted for
/// `binary_search`.
const DEPRECATED_KEYWORDS: &[&str] = &[
    "challengeresponseauthentication",
    "hostbasedacceptedkeytypes",
    "keyregenerationinterval",
    "protocol",
    "pubkeyacceptedkeytypes",
    "rhostsrsaauthentication",
    "rsaauthentication",
    "serverkeybits",
    "uselogin",
    "useprivilegeseparation",
];

/// sshd-W04: a directive deprecated or removed in the target OpenSSH version.
///
/// Fires once per occurrence (multiple uses of the same deprecated keyword each
/// produce their own diagnostic). The keyword match is case-insensitive
/// (matching the sshd daemon's own case-insensitive keyword table).
///
/// Scans every directive in the file: the global block AND all `Match` bodies,
/// because a deprecated keyword is wrong wherever it appears.
///
/// The deprecated set is version-uniform across RHEL 8/9/10 (all three VMs
/// answered `Deprecated option <X>` for each keyword), so W04 fires with
/// `target=None` (no `--target` flag required).
#[must_use]
pub fn w04(blocks: &[Block], file: &Path, _ctx: &SshdLintContext) -> Vec<Diagnostic> {
    let mut diags = Vec::new();
    for block in blocks {
        let directives = match block {
            Block::Global(directives) => directives,
            Block::Match(match_block) => &match_block.body,
        };
        for directive in directives {
            let keyword = directive.keyword_lower();
            if DEPRECATED_KEYWORDS.binary_search(&keyword.as_str()).is_ok() {
                let msg = if keyword == "challengeresponseauthentication" {
                    format!(
                        "'{}' is deprecated: it was renamed to KbdInteractiveAuthentication in OpenSSH 8.7; use the canonical spelling instead",
                        directive.keyword
                    )
                } else {
                    format!(
                        "'{}' is deprecated or removed in the target OpenSSH version",
                        directive.keyword
                    )
                };
                diags.push(anchored(
                    Severity::Warning,
                    "sshd-W04",
                    directive.span.clone(),
                    msg,
                    file,
                    directive.line,
                ));
            }
        }
    }
    diags
}

#[cfg(test)]
mod w04_tests {
    //! sshd-W04: deprecated / removed directive.
    //!
    //! # Grounding
    //! `rulesteward-docs/sshd-stig-version-grounding.md` section 3. Every keyword
    //! in the W04 set was probed via `[VM]` `sudo sshd -t -o "<Keyword>=yes"` on
    //! Rocky 8/9/10 and answered `Deprecated option <X>` (exit 0), confirming it
    //! is recognized-but-deprecated on EVERY currently-supported RHEL. The set is
    //! therefore version-uniform; W04 fires with `target=None`.
    //!
    //! # Key negative assertions (prevent over-fire)
    //! - Modern replacements (`KbdInteractiveAuthentication`, `PubkeyAuthentication`,
    //!   `UsePAM`, and other current keywords) MUST NOT fire W04.
    //! - A config of only-current keywords must yield ZERO W04 diagnostics.
    //! - A config with one deprecated keyword MUST fire W04 and MUST NOT fire E01
    //!   (deprecated keywords are recognized by sshd; they are NOT unknown).

    use super::w04;
    use crate::ast::Block;
    use crate::lints::{SshdLintContext, structural};
    use rulesteward_core::{Diagnostic, Severity};
    use std::path::Path;

    fn parse(src: &str) -> Vec<Block> {
        crate::parser::parse_config_str_located(src, Path::new("/etc/ssh/sshd_config"))
            .expect("fixture parses")
    }

    fn run(src: &str) -> Vec<Diagnostic> {
        w04(
            &parse(src),
            Path::new("/etc/ssh/sshd_config"),
            &SshdLintContext::default(),
        )
    }

    // --- positive: every keyword in the W04 set fires W04 ---

    #[test]
    fn uselogin_fires_w04() {
        // UseLogin: removed upstream 7.4 (`openssh.org/txt/release-7.4`).
        // `[VM]` rocky8/9/10: `Deprecated option UseLogin`.
        let diags = run("UseLogin no\n");
        assert_eq!(diags.len(), 1, "UseLogin must fire exactly one W04");
        assert_eq!(diags[0].code, "sshd-W04");
        assert_eq!(diags[0].severity, Severity::Warning);
        assert_eq!(diags[0].line, 1);
    }

    #[test]
    fn rhostsrsaauthentication_fires_w04() {
        // RhostsRSAAuthentication: protocol-1 deletion, upstream 7.6
        // (`openssh.org/txt/release-7.6`). `[VM]` rocky8/9/10: `Deprecated option`.
        let diags = run("RhostsRSAAuthentication no\n");
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code, "sshd-W04");
        assert_eq!(diags[0].line, 1);
    }

    #[test]
    fn rsaauthentication_fires_w04() {
        // RSAAuthentication: protocol-1 deletion, upstream 7.6.
        // `[VM]` rocky8/9/10: `Deprecated option`.
        let diags = run("RSAAuthentication yes\n");
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code, "sshd-W04");
        assert_eq!(diags[0].line, 1);
    }

    #[test]
    fn keyregenerationinterval_fires_w04() {
        // KeyRegenerationInterval: protocol-1-only, upstream 7.6.
        // `[VM]` rocky8/9/10: `Deprecated option`.
        let diags = run("KeyRegenerationInterval 3600\n");
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code, "sshd-W04");
        assert_eq!(diags[0].line, 1);
    }

    #[test]
    fn serverkeybits_fires_w04() {
        // ServerKeyBits: protocol-1-only, upstream 7.6.
        // `[VM]` rocky8/9/10: `Deprecated option`.
        let diags = run("ServerKeyBits 1024\n");
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code, "sshd-W04");
        assert_eq!(diags[0].line, 1);
    }

    #[test]
    fn useprivilegeseparation_fires_w04() {
        // UsePrivilegeSeparation: deprecated/mandatory since upstream 7.5
        // (`openssh.org/txt/release-7.5`). `[VM]` rocky8/9/10: `Deprecated option`.
        let diags = run("UsePrivilegeSeparation sandbox\n");
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code, "sshd-W04");
        assert_eq!(diags[0].line, 1);
    }

    #[test]
    fn protocol_fires_w04() {
        // Protocol: protocol-1 deletion, upstream 7.6. On RHEL the daemon accepts
        // it silently (no `Deprecated option` message), but it is upstream-deprecated
        // and a W04 policy finding. `[VM]` rocky8/9/10: clean parse, exit 0.
        let diags = run("Protocol 2\n");
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code, "sshd-W04");
        assert_eq!(diags[0].line, 1);
    }

    #[test]
    fn challengeresponseauthentication_fires_w04() {
        // ChallengeResponseAuthentication: renamed to KbdInteractiveAuthentication
        // in OpenSSH 8.7 (`openssh.org/txt/release-8.7`). On RHEL the old name is
        // kept as an accepted alias (daemon exits 0). Flagged as W04 to steer users
        // to the canonical spelling. `[VM]` rocky8/9/10: parses cleanly (alias).
        let diags = run("ChallengeResponseAuthentication yes\n");
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code, "sshd-W04");
        assert_eq!(diags[0].line, 1);
    }

    // --- keyword match is case-insensitive ---

    #[test]
    fn keyword_match_is_case_insensitive() {
        // sshd keyword matching is case-insensitive; the lint must mirror that.
        let cases = [
            "uselogin no\n",
            "UseLogin no\n",
            "USELOGIN no\n",
            "uSeLoGiN no\n",
        ];
        for src in cases {
            let diags = run(src);
            assert_eq!(diags.len(), 1, "case variant '{src}' must fire W04");
            assert_eq!(diags[0].code, "sshd-W04");
        }
    }

    // --- one W04 per occurrence ---

    #[test]
    fn each_occurrence_fires_a_separate_w04() {
        // Two uses of a deprecated keyword => two diagnostics, one per line.
        let diags = run("UseLogin no\nUseLogin yes\n");
        assert_eq!(diags.len(), 2, "one W04 per occurrence");
        let lines: Vec<usize> = diags.iter().map(|d| d.line).collect();
        assert_eq!(lines, vec![1, 2]);
    }

    #[test]
    fn two_different_deprecated_keywords_each_fire() {
        let diags = run("UseLogin no\nProtocol 2\n");
        assert_eq!(diags.len(), 2);
        let codes: Vec<&str> = diags.iter().map(|d| d.code.as_ref()).collect();
        assert!(codes.iter().all(|c| *c == "sshd-W04"));
        let lines: Vec<usize> = diags.iter().map(|d| d.line).collect();
        assert_eq!(lines, vec![1, 2]);
    }

    // --- deprecated keywords inside a Match block also fire ---

    #[test]
    fn deprecated_keyword_in_match_block_fires_w04() {
        // W04 scans all blocks, not just the global block, because a deprecated
        // keyword is wrong regardless of where it appears.
        let diags = run("Match User bob\n    UseLogin no\n");
        assert_eq!(
            diags.len(),
            1,
            "UseLogin inside a Match block must also fire W04"
        );
        assert_eq!(diags[0].code, "sshd-W04");
        assert_eq!(diags[0].line, 2);
    }

    // --- negative: modern replacements must NOT fire W04 ---

    #[test]
    fn kbdinteractiveauthentication_does_not_fire_w04() {
        // KbdInteractiveAuthentication is the MODERN canonical name (renamed from
        // ChallengeResponseAuthentication in 8.7). It must NOT be flagged.
        assert!(
            run("KbdInteractiveAuthentication yes\n").is_empty(),
            "modern canonical name must not fire W04"
        );
    }

    #[test]
    fn pubkeyauthentication_does_not_fire_w04() {
        // PubkeyAuthentication is a current directive; it must never fire W04.
        assert!(
            run("PubkeyAuthentication yes\n").is_empty(),
            "current keyword must not fire W04"
        );
    }

    #[test]
    fn usepam_does_not_fire_w04() {
        // UsePAM is a current directive; it must never fire W04.
        assert!(run("UsePAM yes\n").is_empty(), "UsePAM must not fire W04");
    }

    #[test]
    fn config_of_only_current_keywords_yields_zero_w04() {
        // A realistic STIG-compliant config with no deprecated keywords.
        let src = "\
PermitRootLogin no\n\
PermitEmptyPasswords no\n\
UsePAM yes\n\
PubkeyAuthentication yes\n\
KbdInteractiveAuthentication no\n\
X11Forwarding no\n\
LogLevel VERBOSE\n\
StrictModes yes\n\
PrintLastLog yes\n\
GSSAPIAuthentication no\n\
";
        let diags = run(src);
        assert!(
            diags.is_empty(),
            "config with only current keywords must yield zero W04; got {diags:?}"
        );
    }

    // --- separation from E01: deprecated != unknown ---

    #[test]
    fn deprecated_keyword_fires_w04_not_e01() {
        // A recognized-but-deprecated keyword is sshd-W04 (the daemon accepts it
        // with "Deprecated option"). It must NOT fire sshd-E01 (which is reserved
        // for truly-unknown keywords the daemon rejects with "Bad configuration
        // option"). This assertion enforces the E01/W04 boundary.
        let src = "UseLogin no\n";
        let blocks = parse(src);
        let file = Path::new("/etc/ssh/sshd_config");
        let ctx = SshdLintContext::default();

        let w04_diags = w04(&blocks, file, &ctx);
        let e01_diags = structural::e01(&blocks, file, &ctx);

        assert_eq!(w04_diags.len(), 1, "UseLogin must fire W04");
        assert_eq!(w04_diags[0].code, "sshd-W04");
        assert!(
            e01_diags.is_empty(),
            "UseLogin is recognized-but-deprecated: must NOT fire E01 (got {e01_diags:?})"
        );
    }

    #[test]
    fn challengeresponseauthentication_fires_w04_not_e01() {
        // ChallengeResponseAuthentication is a recognized alias (daemon accepts
        // it). It must fire W04 (deprecated alias) and NOT E01 (not unknown).
        let src = "ChallengeResponseAuthentication yes\n";
        let blocks = parse(src);
        let file = Path::new("/etc/ssh/sshd_config");
        let ctx = SshdLintContext::default();

        let w04_diags = w04(&blocks, file, &ctx);
        let e01_diags = structural::e01(&blocks, file, &ctx);

        assert_eq!(w04_diags.len(), 1, "must fire W04");
        assert!(
            e01_diags.is_empty(),
            "recognized alias must not fire E01 (got {e01_diags:?})"
        );
    }

    // --- OpenSSH 8.5 rename aliases (PubkeyAcceptedKeyTypes / HostbasedAcceptedKeyTypes) ---

    #[test]
    fn pubkeyacceptedkeytypes_fires_w04() {
        // PubkeyAcceptedKeyTypes was renamed to PubkeyAcceptedAlgorithms in
        // OpenSSH 8.5 (`openssh.org/txt/release-8.5`: "The previous name remains
        // available as an alias"). On Rocky 9/10 `sudo sshd -t -o
        // "PubkeyAcceptedKeyTypes=yes"` returns "Bad key types 'yes'" -- the keyword
        // is KNOWN (not "Bad configuration option"), so it is recognized-but-renamed.
        // Same deprecated-rename-alias class as ChallengeResponseAuthentication; must
        // fire exactly one sshd-W04 Warning.
        // Source: sshd-stig-version-grounding.md section 2.3, [VM] 2026-06-15T02:23Z.
        let diags = run("PubkeyAcceptedKeyTypes ssh-ed25519\n");
        assert_eq!(
            diags.len(),
            1,
            "PubkeyAcceptedKeyTypes (renamed alias) must fire exactly one sshd-W04; got {diags:?}"
        );
        assert_eq!(diags[0].code, "sshd-W04");
        assert_eq!(diags[0].severity, Severity::Warning);
        assert_eq!(diags[0].line, 1);
    }

    #[test]
    fn hostbasedacceptedkeytypes_fires_w04() {
        // HostbasedAcceptedKeyTypes was renamed to HostbasedAcceptedAlgorithms in
        // OpenSSH 8.5 (same release as PubkeyAcceptedKeyTypes, `release-8.5`: "The
        // previous name remains available as an alias"). On Rocky 9/10 the daemon
        // recognizes the old name (keyword known, value may be rejected on bad input).
        // Same deprecated-rename-alias class as ChallengeResponseAuthentication; must
        // fire exactly one sshd-W04 Warning.
        // Source: sshd-stig-version-grounding.md section 2.3, [VM] 2026-06-15T02:23Z.
        let diags = run("HostbasedAcceptedKeyTypes ssh-ed25519\n");
        assert_eq!(
            diags.len(),
            1,
            "HostbasedAcceptedKeyTypes (renamed alias) must fire exactly one sshd-W04; got {diags:?}"
        );
        assert_eq!(diags[0].code, "sshd-W04");
        assert_eq!(diags[0].severity, Severity::Warning);
        assert_eq!(diags[0].line, 1);
    }

    #[test]
    fn pubkeyacceptedkeytypes_fires_w04_not_e01() {
        // PubkeyAcceptedKeyTypes is a recognized alias (daemon knows the keyword).
        // It must fire W04 (deprecated alias) and NOT E01 (not unknown).
        // This pins the E01/W04 boundary for the 8.5 rename aliases.
        // Source: sshd-stig-version-grounding.md section 2.3 + section 2.6.
        let src = "PubkeyAcceptedKeyTypes ssh-ed25519\n";
        let blocks = parse(src);
        let file = Path::new("/etc/ssh/sshd_config");
        let ctx = SshdLintContext::default();

        let w04_diags = w04(&blocks, file, &ctx);
        let e01_diags = structural::e01(&blocks, file, &ctx);

        assert_eq!(w04_diags.len(), 1, "must fire W04");
        assert!(
            e01_diags.is_empty(),
            "recognized rename alias must not fire E01 (got {e01_diags:?})"
        );
    }

    #[test]
    fn hostbasedacceptedkeytypes_fires_w04_not_e01() {
        // HostbasedAcceptedKeyTypes is a recognized alias (daemon knows the keyword).
        // It must fire W04 (deprecated alias) and NOT E01 (not unknown).
        // Source: sshd-stig-version-grounding.md section 2.3 + section 2.6.
        let src = "HostbasedAcceptedKeyTypes ssh-ed25519\n";
        let blocks = parse(src);
        let file = Path::new("/etc/ssh/sshd_config");
        let ctx = SshdLintContext::default();

        let w04_diags = w04(&blocks, file, &ctx);
        let e01_diags = structural::e01(&blocks, file, &ctx);

        assert_eq!(w04_diags.len(), 1, "must fire W04");
        assert!(
            e01_diags.is_empty(),
            "recognized rename alias must not fire E01 (got {e01_diags:?})"
        );
    }

    // --- target=None fires (version-uniform set) ---

    #[test]
    fn w04_fires_without_target_flag() {
        // The deprecated set is uniform across RHEL 8/9/10 (measured on all three
        // VMs). W04 must therefore fire even when `--target` is unspecified.
        let diags = run("Protocol 2\n");
        assert_eq!(
            diags.len(),
            1,
            "W04 fires with target=None (version-uniform set)"
        );
    }

    // --- diagnostic metadata ---

    #[test]
    fn w04_diagnostic_has_correct_severity_and_code() {
        let diags = run("UseLogin no\n");
        assert_eq!(diags.len(), 1);
        let d = &diags[0];
        assert_eq!(d.severity, Severity::Warning, "W04 is a Warning");
        assert_eq!(d.code, "sshd-W04");
        // The message must mention the directive keyword so the operator knows
        // what to replace.
        assert!(
            d.message.contains("UseLogin") || d.message.to_ascii_lowercase().contains("uselogin"),
            "diagnostic message must reference the keyword; got: {:?}",
            d.message
        );
    }

    #[test]
    fn w04_diagnostic_line_matches_source() {
        // Span anchoring: the diagnostic must point to the exact source line.
        let src = "# comment\nPermitRootLogin no\nRSAAuthentication yes\nX11Forwarding no\n";
        let diags = run(src);
        assert_eq!(diags.len(), 1);
        assert_eq!(
            diags[0].line, 3,
            "diagnostic must be at line 3 (the RSAAuthentication line)"
        );
    }

    #[test]
    fn w04_special_message_for_challengeresponseauthentication() {
        // ChallengeResponseAuthentication has a special rename message (not the
        // generic "deprecated or removed" message) because it was renamed to
        // KbdInteractiveAuthentication in OpenSSH 8.7. The message must mention
        // the canonical spelling.
        let diags = run("ChallengeResponseAuthentication yes\n");
        assert_eq!(diags.len(), 1);
        let msg = &diags[0].message;
        assert!(
            msg.to_ascii_lowercase().contains("renamed"),
            "W04 for ChallengeResponseAuthentication must mention 'renamed'; got: {msg:?}"
        );
        assert!(
            msg.contains("KbdInteractiveAuthentication"),
            "W04 must mention the canonical KbdInteractiveAuthentication; got: {msg:?}"
        );
    }

    #[test]
    fn w04_generic_message_for_other_deprecated() {
        // Other deprecated keywords get the generic "deprecated or removed"
        // message (not the rename-specific message).
        let diags = run("Protocol 2\n");
        assert_eq!(diags.len(), 1);
        let msg = &diags[0].message;
        assert!(
            msg.to_ascii_lowercase().contains("deprecated"),
            "W04 message must contain 'deprecated'; got: {msg:?}"
        );
        assert!(
            !msg.to_ascii_lowercase().contains("renamed"),
            "W04 for non-rename deprecated keywords must not say 'renamed'; got: {msg:?}"
        );
    }
}
