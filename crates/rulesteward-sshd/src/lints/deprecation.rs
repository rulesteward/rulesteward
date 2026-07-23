//! Deprecation lint: directives deprecated or removed in the target OpenSSH
//! version (`Protocol`, `RhostsRSAAuthentication`, `RSAAuthentication`,
//! `UseLogin`, ...). Consumes the per-OpenSSH-version deprecated-keyword table
//! from the Wave-B grounding task.

use std::path::Path;

use rulesteward_core::{Diagnostic, Severity};

use crate::ast::Block;
use crate::lints::{SshdLintContext, TargetVersion, anchored};

/// Deprecated/removed `sshd_config` keywords for sshd-W04. Most of the set is
/// confirmed recognized-but-deprecated on every supported RHEL 8/9/10 target
/// via the daemon's own `Deprecated option <X>` diagnostic; four entries lack
/// that literal message: three are recognized RENAME ALIASES
/// (`challengeresponseauthentication`, `pubkeyacceptedkeytypes`,
/// `hostbasedacceptedkeytypes`) the daemon accepts silently or rejects only on
/// a bad value, and `protocol` is a REMOVED protocol-1 option the daemon
/// accepts silently. All four are still upstream-deprecated, and W04 flags
/// them as a policy finding steering users to the canonical spelling.
///
/// Grounding: `rulesteward-docs/sshd-stig-version-grounding.md` sections 2.3
/// and 3 + depth-sshd-sets.md FINDING 2, backed by `[VM]` `sudo sshd -t -o
/// "<Keyword>=yes"` on Rocky 8/9/10 (OpenSSH 8.0p1 / 9.9p1 / 9.9p1,
/// 2026-06-15 + 2026-06-17). All of these are recognized by the daemon (not
/// unknown), so they are W04 (warn) not E01 (error). `ChallengeResponseAuthentication`
/// is additionally an alias for `KbdInteractiveAuthentication` (renamed in
/// OpenSSH 8.7, `release-8.7`).
///
/// This set is UNIFORM across RHEL 8/9/10 (each keyword's behavior - whether
/// the literal `Deprecated option` message or the rename-alias handling
/// above - matched on all three VMs), so it fires under `target=None`. The
/// version-SPLIT keyword `skeyauthentication` (deprecated on 8.0p1 but a
/// recognized non-deprecated legacy keyword on 9.9p1) is NOT here; it is gated on
/// the target in [`w04`]. Lowercased and sorted for `binary_search`.
///
/// #372 (2026-07-07): a FULL-registry `sshd-probe-update` probe (vs FINDING 2's
/// 31-keyword boundary probe) found three more version-uniform `Deprecated option`
/// keywords the set missed: `authorizedkeysfile2`, `checkmail`,
/// `pamauthenticationviakbdint`. (`authorizedkeysfile2` is also Match-honored, so it
/// is likewise in the E04 permitted set.)
const DEPRECATED_KEYWORDS: &[&str] = &[
    "authorizedkeysfile2",
    "challengeresponseauthentication",
    "checkmail",
    "hostbasedacceptedkeytypes",
    "keyregenerationinterval",
    "pamauthenticationviakbdint",
    "protocol",
    "pubkeyacceptedkeytypes",
    "reversemappingcheck",
    "rhostsauthentication",
    "rhostsrsaauthentication",
    "rsaauthentication",
    "serverkeybits",
    "uselogin",
    "useprivilegeseparation",
    "verifyreversemapping",
];

/// Whether `skeyauthentication` should fire sshd-W04 for `target`. It is
/// `Deprecated option` on OpenSSH 8.0p1 (RHEL 8) but an ACCEPTED recognized
/// legacy keyword on 9.9p1 (RHEL 9/10), so the warning is version-split.
///
/// OWNER DECISION (LOCKED): fire when the target is `None` (no `--target` =
/// conservative over-warn) or `Rhel8`; do NOT fire under `--target rhel9/rhel10`.
/// Source: depth-sshd-sets.md FINDING 2 (DEPRECATED rocky8; ACCEPTED rocky9/10).
fn skey_is_deprecated(target: Option<TargetVersion>) -> bool {
    !matches!(target, Some(TargetVersion::Rhel9 | TargetVersion::Rhel10))
}

/// The full set of deprecated `sshd_config` keywords sshd-W04 fires for `target`,
/// enumerated for the out-of-tree `sshd-probe-update` drift tool. The
/// version-uniform [`DEPRECATED_KEYWORDS`] plus `skeyauthentication` when it is
/// deprecated for `target` (see [`skey_is_deprecated`]): 17 on rhel8, 16 on
/// rhel9/rhel10. Order is unspecified.
#[must_use]
pub fn deprecated_keywords(target: TargetVersion) -> Vec<&'static str> {
    let mut out: Vec<&'static str> = DEPRECATED_KEYWORDS.to_vec();
    if skey_is_deprecated(Some(target)) {
        out.push("skeyauthentication");
    }
    out
}

/// sshd-W04: a directive deprecated or removed in the target OpenSSH version.
///
/// Fires once per occurrence (multiple uses of the same deprecated keyword each
/// produce their own diagnostic). The keyword match is case-insensitive
/// (matching the sshd daemon's own case-insensitive keyword table).
///
/// Scans every directive in the file: the global block AND all `Match` bodies,
/// because a deprecated keyword is wrong wherever it appears.
///
/// Most of the deprecated set is version-uniform across RHEL 8/9/10 (all three
/// VMs answered `Deprecated option <X>`), so W04 fires with `target=None`. The
/// one version-split keyword, `skeyauthentication`, is gated on `ctx.target` via
/// [`skey_is_deprecated`] (deprecated on 8.0p1, accepted on 9.9p1).
#[must_use]
pub fn w04(blocks: &[Block], file: &Path, ctx: &SshdLintContext) -> Vec<Diagnostic> {
    let mut diags = Vec::new();
    for block in blocks {
        let directives = match block {
            Block::Global(directives) => directives,
            Block::Match(match_block) => &match_block.body,
        };
        for directive in directives {
            let keyword = directive.keyword_lower();
            let is_deprecated = DEPRECATED_KEYWORDS.binary_search(&keyword.as_str()).is_ok()
                || (keyword == "skeyauthentication" && skey_is_deprecated(ctx.target));
            if is_deprecated {
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
    //! `rulesteward-docs/sshd-stig-version-grounding.md` sections 2.3 and 3. Most
    //! of the W04 set was probed via `[VM]` `sudo sshd -t -o "<Keyword>=yes"` on
    //! Rocky 8/9/10 and answered `Deprecated option <X>` (exit 0), confirming it
    //! is recognized-but-deprecated on every currently-supported RHEL. Four
    //! entries lack that literal message: three rename aliases
    //! (`challengeresponseauthentication`, `pubkeyacceptedkeytypes`,
    //! `hostbasedacceptedkeytypes`) plus `protocol`, a removed protocol-1
    //! option accepted silently (see the per-test comments below); W04 still
    //! flags them as a policy finding. The set is version-uniform; W04 fires
    //! with `target=None`.
    //!
    //! # Key negative assertions (prevent over-fire)
    //! - Modern replacements (`KbdInteractiveAuthentication`, `PubkeyAuthentication`,
    //!   `UsePAM`, and other current keywords) MUST NOT fire W04.
    //! - A config of only-current keywords must yield ZERO W04 diagnostics.
    //! - A config with one deprecated keyword MUST fire W04 and MUST NOT fire E01
    //!   (deprecated keywords are recognized by sshd; they are NOT unknown).

    use super::w04;
    use crate::ast::Block;
    use crate::lints::{SshdLintContext, TargetVersion, structural};
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

    fn run_with_target(src: &str, target: TargetVersion) -> Vec<Diagnostic> {
        w04(
            &parse(src),
            Path::new("/etc/ssh/sshd_config"),
            &SshdLintContext {
                target: Some(target),
                single_file: true,
            },
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

    // --- #372: 3 more missed deprecated keywords (full-registry probe) ---
    //
    // sshd-probe-update capture 2026-07-07 (oracle: `sshd -t -o "<kw>=yes"` on Rocky
    // 8/9/10, "Deprecated option <X>"): a FULL-registry probe (vs the earlier
    // 31-keyword boundary probe of FINDING 2) found three more recognized-but-
    // deprecated keywords the W04 set missed. All three are in RHEL8_BASE (registry-
    // known on every version) and version-uniform, so W04 must warn on every target.
    //   - checkmail                  DEPRECATED on rhel8/9/10
    //   - authorizedkeysfile2        DEPRECATED on rhel8/9/10 (also E04-honored-in-Match)
    //   - pamauthenticationviakbdint DEPRECATED on rhel8/9/10

    #[test]
    fn checkmail_fires_w04_on_every_target() {
        let contexts = [
            None,
            Some(TargetVersion::Rhel8),
            Some(TargetVersion::Rhel9),
            Some(TargetVersion::Rhel10),
        ];
        for target in contexts {
            let diags = match target {
                Some(t) => run_with_target("CheckMail yes\n", t),
                None => run("CheckMail yes\n"),
            };
            assert_eq!(
                diags.len(),
                1,
                "CheckMail is deprecated on all versions -> one W04 for target {target:?}; \
                 got {diags:?}"
            );
            assert_eq!(diags[0].code, "sshd-W04");
            assert_eq!(diags[0].severity, Severity::Warning);
        }
    }

    #[test]
    fn authorizedkeysfile2_fires_w04_on_every_target() {
        let contexts = [
            None,
            Some(TargetVersion::Rhel8),
            Some(TargetVersion::Rhel9),
            Some(TargetVersion::Rhel10),
        ];
        for target in contexts {
            let diags = match target {
                Some(t) => run_with_target("AuthorizedKeysFile2 yes\n", t),
                None => run("AuthorizedKeysFile2 yes\n"),
            };
            assert_eq!(
                diags.len(),
                1,
                "AuthorizedKeysFile2 is deprecated on all versions -> one W04 for target \
                 {target:?}; got {diags:?}"
            );
            assert_eq!(diags[0].code, "sshd-W04");
            assert_eq!(diags[0].severity, Severity::Warning);
        }
    }

    #[test]
    fn pamauthenticationviakbdint_fires_w04_on_every_target() {
        let contexts = [
            None,
            Some(TargetVersion::Rhel8),
            Some(TargetVersion::Rhel9),
            Some(TargetVersion::Rhel10),
        ];
        for target in contexts {
            let diags = match target {
                Some(t) => run_with_target("PAMAuthenticationViaKBDInt yes\n", t),
                None => run("PAMAuthenticationViaKBDInt yes\n"),
            };
            assert_eq!(
                diags.len(),
                1,
                "PAMAuthenticationViaKBDInt is deprecated on all versions -> one W04 for \
                 target {target:?}; got {diags:?}"
            );
            assert_eq!(diags[0].code, "sshd-W04");
            assert_eq!(diags[0].severity, Severity::Warning);
        }
    }

    // --- #267 / FINDING 2: 4 missed deprecated keywords ---
    //
    // depth-sshd-sets.md FINDING 2 (oracle: `sudo sshd -t -o "<kw>=yes"` on Rocky
    // 8/9/10, 2026-06-17, "Deprecated option <X>" classification): the daemon
    // answers "Deprecated option" for four keywords the W04 set currently misses.
    // All four are in RHEL8_BASE (registry-known on every version), so they are NOT
    // E01; W04 must warn on them.
    //   - reversemappingcheck   DEPRECATED on rhel8/9/10  (all targets)
    //   - rhostsauthentication  DEPRECATED on rhel8/9/10  (all targets)
    //   - verifyreversemapping  DEPRECATED on rhel8/9/10  (all targets)
    //   - skeyauthentication    DEPRECATED on rhel8 (8.0p1) ONLY; ACCEPTED on 9/10
    //                           (version-split: fire under --target rhel8, not 9/10)

    #[test]
    fn reversemappingcheck_fires_w04_on_every_target() {
        // "Deprecated option ReverseMappingCheck" on rocky8/9/10.
        let contexts = [
            None,
            Some(TargetVersion::Rhel8),
            Some(TargetVersion::Rhel9),
            Some(TargetVersion::Rhel10),
        ];
        for target in contexts {
            let diags = match target {
                Some(t) => run_with_target("ReverseMappingCheck yes\n", t),
                None => run("ReverseMappingCheck yes\n"),
            };
            assert_eq!(
                diags.len(),
                1,
                "ReverseMappingCheck is deprecated on all versions -> one W04 for \
                 target {target:?}; got {diags:?}"
            );
            assert_eq!(diags[0].code, "sshd-W04");
            assert_eq!(diags[0].severity, Severity::Warning);
        }
    }

    #[test]
    fn rhostsauthentication_fires_w04_on_every_target() {
        // "Deprecated option RhostsAuthentication" on rocky8/9/10. Distinct from
        // RhostsRSAAuthentication (already in the W04 set).
        let contexts = [
            None,
            Some(TargetVersion::Rhel8),
            Some(TargetVersion::Rhel9),
            Some(TargetVersion::Rhel10),
        ];
        for target in contexts {
            let diags = match target {
                Some(t) => run_with_target("RhostsAuthentication yes\n", t),
                None => run("RhostsAuthentication yes\n"),
            };
            assert_eq!(
                diags.len(),
                1,
                "RhostsAuthentication is deprecated on all versions -> one W04 for \
                 target {target:?}; got {diags:?}"
            );
            assert_eq!(diags[0].code, "sshd-W04");
        }
    }

    #[test]
    fn verifyreversemapping_fires_w04_on_every_target() {
        // "Deprecated option VerifyReverseMapping" on rocky8/9/10.
        let contexts = [
            None,
            Some(TargetVersion::Rhel8),
            Some(TargetVersion::Rhel9),
            Some(TargetVersion::Rhel10),
        ];
        for target in contexts {
            let diags = match target {
                Some(t) => run_with_target("VerifyReverseMapping yes\n", t),
                None => run("VerifyReverseMapping yes\n"),
            };
            assert_eq!(
                diags.len(),
                1,
                "VerifyReverseMapping is deprecated on all versions -> one W04 for \
                 target {target:?}; got {diags:?}"
            );
            assert_eq!(diags[0].code, "sshd-W04");
        }
    }

    #[test]
    fn three_all_version_deprecated_additions_are_not_e01() {
        // Boundary guard: the three all-version additions are RHEL8_BASE keywords
        // (daemon recognizes them as "Deprecated option", not "Bad configuration
        // option"), so they fire W04 and must NOT fire E01 on any target.
        let file = Path::new("/etc/ssh/sshd_config");
        for kw in [
            "ReverseMappingCheck",
            "RhostsAuthentication",
            "VerifyReverseMapping",
        ] {
            let src = format!("{kw} yes\n");
            let blocks = parse(&src);
            for ctx in [
                SshdLintContext::default(),
                SshdLintContext {
                    target: Some(TargetVersion::Rhel8),
                    single_file: true,
                },
                SshdLintContext {
                    target: Some(TargetVersion::Rhel9),
                    single_file: true,
                },
                SshdLintContext {
                    target: Some(TargetVersion::Rhel10),
                    single_file: true,
                },
            ] {
                let w04_diags = w04(&blocks, file, &ctx);
                let e01_diags = structural::e01(&blocks, file, &ctx);
                assert_eq!(w04_diags.len(), 1, "{kw} must fire W04 ({ctx:?})");
                assert!(
                    e01_diags.is_empty(),
                    "{kw} is recognized-but-deprecated: must NOT fire E01 ({ctx:?}); \
                     got {e01_diags:?}"
                );
            }
        }
    }

    #[test]
    fn skeyauthentication_fires_w04_at_no_target_and_rhel8_but_not_rhel9_rhel10() {
        // VERSION-SPLIT: skeyauthentication is "Deprecated option" on rocky8 (8.0p1)
        // but ACCEPTED (a recognized, non-deprecated legacy keyword) on rocky9/10.
        //   Source: FINDING 2 (DEPRECATED rocky8; ACCEPTED rocky9/rocky10).
        //
        // Full W04 matrix (OWNER DECISION, LOCKED): fire when the target is
        // {no-target/None, Rhel8} (no-target = conservative over-warn = FIRE); do NOT
        // fire under --target rhel9 / rhel10. Implement/assert as: skeyauthentication
        // is W04-deprecated UNLESS the target is explicitly Rhel9 or Rhel10.
        //
        // The mechanism exists: deprecation.rs `w04` receives `&SshdLintContext`
        // (the `_ctx` param, dispatched with `ctx` at mod.rs:131); the impl gates
        // skeyauthentication on `ctx.target`. A naive uniform-add (ignoring target)
        // would over-fire on rhel9/rhel10; a target-gated add that forgets the
        // None=>FIRE direction would under-fire at no-target. This pins both.

        // FIRE: no-target (None) - conservative over-warn.
        let diags_none = run("SKeyAuthentication yes\n");
        assert_eq!(
            diags_none.len(),
            1,
            "SKeyAuthentication must fire W04 at no-target (conservative over-warn = \
             FIRE unless target is explicitly Rhel9/Rhel10); got {diags_none:?}"
        );
        assert_eq!(diags_none[0].code, "sshd-W04");
        assert_eq!(diags_none[0].severity, Severity::Warning);

        // FIRE: --target rhel8 (8.0p1, "Deprecated option").
        let diags8 = run_with_target("SKeyAuthentication yes\n", TargetVersion::Rhel8);
        assert_eq!(
            diags8.len(),
            1,
            "SKeyAuthentication is deprecated on 8.0p1 -> one W04 under --target rhel8; \
             got {diags8:?}"
        );
        assert_eq!(diags8[0].code, "sshd-W04");
        assert_eq!(diags8[0].severity, Severity::Warning);

        // DO NOT FIRE: --target rhel9 / rhel10 (ACCEPTED, recognized non-deprecated).
        for target in [TargetVersion::Rhel9, TargetVersion::Rhel10] {
            let diags = run_with_target("SKeyAuthentication yes\n", target);
            assert!(
                diags.is_empty(),
                "SKeyAuthentication is ACCEPTED (not deprecated) on 9.9p1 -> no W04 \
                 under --target {target:?}; got {diags:?}"
            );
        }
    }

    #[test]
    fn skeyauthentication_is_not_e01_on_any_target() {
        // skeyauthentication is in RHEL8_BASE (known on every version), so even where
        // it is NOT W04 (rhel9/rhel10) it must never fire E01 - it is a recognized
        // legacy keyword, not an unknown directive.
        let file = Path::new("/etc/ssh/sshd_config");
        let blocks = parse("SKeyAuthentication yes\n");
        for ctx in [
            SshdLintContext::default(),
            SshdLintContext {
                target: Some(TargetVersion::Rhel8),
                single_file: true,
            },
            SshdLintContext {
                target: Some(TargetVersion::Rhel9),
                single_file: true,
            },
            SshdLintContext {
                target: Some(TargetVersion::Rhel10),
                single_file: true,
            },
        ] {
            assert!(
                structural::e01(&blocks, file, &ctx).is_empty(),
                "SKeyAuthentication is a recognized legacy keyword -> must NOT fire \
                 E01 ({ctx:?})"
            );
        }
    }
}

#[cfg(test)]
mod projection_tests {
    use super::{DEPRECATED_KEYWORDS, deprecated_keywords};
    use crate::lints::TargetVersion;

    #[test]
    fn deprecated_keyword_sizes_and_skey_version_split() {
        assert_eq!(deprecated_keywords(TargetVersion::Rhel8).len(), 17);
        assert_eq!(deprecated_keywords(TargetVersion::Rhel9).len(), 16);
        assert_eq!(deprecated_keywords(TargetVersion::Rhel10).len(), 16);
        assert!(
            deprecated_keywords(TargetVersion::Rhel8).contains(&"skeyauthentication"),
            "skeyauthentication is deprecated on rhel8"
        );
        assert!(
            !deprecated_keywords(TargetVersion::Rhel9).contains(&"skeyauthentication"),
            "skeyauthentication is accepted (not deprecated) on rhel9"
        );
    }

    #[test]
    fn deprecated_keywords_superset_of_uniform_table() {
        for target in [
            TargetVersion::Rhel8,
            TargetVersion::Rhel9,
            TargetVersion::Rhel10,
        ] {
            let set = deprecated_keywords(target);
            for kw in DEPRECATED_KEYWORDS {
                assert!(
                    set.contains(kw),
                    "{kw} missing from deprecated_keywords({target:?})"
                );
            }
        }
    }
}
