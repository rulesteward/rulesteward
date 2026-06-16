//! STIG-baseline lints: required-directive presence (sshd-W01) and
//! value-vs-baseline comparison (sshd-W02).
//!
//! Tables are keyed by `TargetVersion` and built from the DISA XCCDF official
//! check-content for RHEL 8 V2R4 (02 Jul 2025), RHEL 9 V2R7 (05 Jan 2026), and
//! RHEL 10 V1R1 (26 Feb 2026). Every claim is primary-source grounded; see
//! `sshd-stig-version-grounding.md` section 4 and 5.
//!
//! # target=None floor
//!
//! When `--target` is unspecified the conservative FLOOR is used: the 14-directive
//! RHEL 8 required set (the intersection of all supported versions). A floor
//! directive is required by every supported target, so no false positives.
//!
//! # `MaxAuthTries` / `LoginGraceTime` are NOT in scope
//!
//! Those are CIS / general-hardening controls, absent from every DISA STIG XCCDF
//! SSH directive set. W01/W02 must never fire for them.
//!
//! # Cross-file scope guard (W02)
//!
//! W02 evaluates the single-file value only. Cross-file drop-in precedence is
//! future sshd-F02 (Wave C), not W02.
// Directive keyword names appear as plain identifiers in prose throughout this
// module (e.g. `PermitRootLogin`, `ClientAliveInterval`). Wrapping every one
// in backticks would bury the signal; we allow doc_markdown here to keep the
// comments readable.  The frozen test file carries the same allow.
#![allow(clippy::doc_markdown)]

use std::path::Path;

use rulesteward_core::{Diagnostic, Severity};

use crate::ast::Block;
use crate::lints::{SshdLintContext, TargetVersion, anchored};

// ---------------------------------------------------------------------------
// W01 required-directive tables (per target)
// Each entry is the directive keyword in LOWERCASE.
// The RHEL 9 set is the "spine"; RHEL 8 and RHEL 10 sets are derived from it.
// ---------------------------------------------------------------------------

/// RHEL 9 V2R7 required directives (20 total, V-257981..V-258011 SSH set).
///
/// Grounded in DISA XCCDF `U_RHEL_9_V2R7_STIG.zip`, benchmark 05 Jan 2026.
/// STIG-IDs: RHEL-09-255025..255175.
const RHEL9_REQUIRED: &[&str] = &[
    "banner",                  // RHEL-09-255025 V-257981
    "clientalivecountmax",     // RHEL-09-255095 V-257995
    "clientaliveinterval",     // RHEL-09-255100 V-257996
    "compression",             // RHEL-09-255130 V-258002
    "gssapiauthentication",    // RHEL-09-255135 V-258003
    "hostbasedauthentication", // RHEL-09-255080 V-257992
    "ignorerhosts",            // RHEL-09-255145 V-258005
    "ignoreuserknownhosts",    // RHEL-09-255150 V-258006
    "kerberosauthentication",  // RHEL-09-255140 V-258004
    "loglevel",                // RHEL-09-255030 V-257982
    "permitemptypasswords",    // RHEL-09-255040 V-257984
    "permitrootlogin",         // RHEL-09-255045 V-257985
    "permituserenvironment",   // RHEL-09-255085 V-257993
    "printlastlog",            // RHEL-09-255165 V-258009
    "pubkeyauthentication",    // RHEL-09-255035 V-257983
    "rekeylimit",              // RHEL-09-255090 V-257994
    "strictmodes",             // RHEL-09-255160 V-258008
    "usepam",                  // RHEL-09-255050 V-257986
    "x11forwarding",           // RHEL-09-255155 V-258007
    "x11uselocalhost",         // RHEL-09-255175 V-258011
];

/// RHEL 8 V2R4 required directives (14 total).
///
/// Absent vs RHEL9: LogLevel, PubkeyAuthentication, UsePAM, IgnoreRhosts,
/// HostbasedAuthentication, Compression. (RHEL 8 has no sshd_config controls
/// for those six; grounded in DISA XCCDF `U_RHEL_8_V2R4_STIG.zip`, 02 Jul 2025.)
///
/// STIG-IDs: V-230225 Banner, V-230244 ClientAliveCountMax, V-244525
/// ClientAliveInterval, V-230288 StrictModes, V-230290 IgnoreUserKnownHosts,
/// V-230291 KerberosAuthentication, V-244528 GSSAPIAuthentication, V-230296
/// PermitRootLogin, V-230330 PermitUserEnvironment, V-230380 PermitEmptyPasswords,
/// V-230382 PrintLastLog, V-230527 RekeyLimit, V-230555 X11Forwarding, V-230556
/// X11UseLocalhost.
const RHEL8_REQUIRED: &[&str] = &[
    "banner",                 // V-230225
    "clientalivecountmax",    // V-230244
    "clientaliveinterval",    // V-244525
    "gssapiauthentication",   // V-244528
    "ignoreuserknownhosts",   // V-230290
    "kerberosauthentication", // V-230291
    "permitemptypasswords",   // V-230380
    "permitrootlogin",        // V-230296
    "permituserenvironment",  // V-230330
    "printlastlog",           // V-230382
    "rekeylimit",             // V-230527
    "strictmodes",            // V-230288
    "x11forwarding",          // V-230555
    "x11uselocalhost",        // V-230556
];

/// RHEL 10 V1R1 required directives (19 total, the RHEL9 set minus Compression).
///
/// Compression was dropped from the RHEL 10 V1R1 STIG (not a controlled
/// directive in `U_RHEL_10_V1R1_STIG.zip`, benchmark 26 Feb 2026).
///
/// STIG-IDs: V-281115 LogLevel, V-281216 UsePAM, V-281224 Banner,
/// V-281254 GSSAPIAuthentication, V-281255 KerberosAuthentication,
/// V-281256 IgnoreRhosts, V-281257 IgnoreUserKnownHosts, V-281258 X11Forwarding,
/// V-281259 StrictModes, V-281260 PrintLastLog, V-281261 X11UseLocalhost,
/// V-281263 PubkeyAuthentication, V-281264 PermitEmptyPasswords,
/// V-281265 PermitRootLogin, V-281266 HostbasedAuthentication,
/// V-281267 PermitUserEnvironment, V-281268 RekeyLimit,
/// V-281269 ClientAliveCountMax, V-281296 ClientAliveInterval.
const RHEL10_REQUIRED: &[&str] = &[
    "banner",                  // V-281224
    "clientalivecountmax",     // V-281269
    "clientaliveinterval",     // V-281296
    "gssapiauthentication",    // V-281254
    "hostbasedauthentication", // V-281266
    "ignorerhosts",            // V-281256
    "ignoreuserknownhosts",    // V-281257
    "kerberosauthentication",  // V-281255
    "loglevel",                // V-281115
    "permitemptypasswords",    // V-281264
    "permitrootlogin",         // V-281265
    "permituserenvironment",   // V-281267
    "printlastlog",            // V-281260
    "pubkeyauthentication",    // V-281263
    "rekeylimit",              // V-281268
    "strictmodes",             // V-281259
    "usepam",                  // V-281216
    "x11forwarding",           // V-281258
    "x11uselocalhost",         // V-281261
];

/// The conservative floor: the intersection of all supported versions' required
/// sets. Equals RHEL 8 V2R4 (14 directives) since every RHEL8 directive is also
/// required by RHEL9 and RHEL10. Used when target=None to avoid false positives.
const FLOOR_REQUIRED: &[&str] = RHEL8_REQUIRED;

/// Return the required directive set for a given target (or the floor when None).
fn required_set(target: Option<TargetVersion>) -> &'static [&'static str] {
    match target {
        Some(TargetVersion::Rhel8) => RHEL8_REQUIRED,
        Some(TargetVersion::Rhel9) => RHEL9_REQUIRED,
        Some(TargetVersion::Rhel10) => RHEL10_REQUIRED,
        None => FLOOR_REQUIRED,
    }
}

// ---------------------------------------------------------------------------
// W02 value comparison helpers
// ---------------------------------------------------------------------------

/// Comparison kind for a STIG-required directive's value.
enum W02Rule {
    /// Exact case-insensitive literal match.
    ExactLower(&'static str),
    /// Exact two-token match: first arg and second arg must both match exactly
    /// (case-insensitive). Used for `RekeyLimit 1G 1h`.
    TwoTokenExact(&'static str, &'static str),
    /// Accept any of the listed lowercase values (for Compression: "delayed" or "no").
    AnyOf(&'static [&'static str]),
    /// Numeric ceiling: value must parse as u64 and be <= the ceiling.
    NumericCeiling(u64),
    /// Numeric exact: must parse as u64 and equal the required value exactly.
    NumericExact(u64),
}

/// Return the W02 comparison rule for `keyword_lower`, or `None` when the
/// directive is not a W02-controlled value check for the given target.
///
/// Banner is a presence-only check (W01); it has no W02 rule.
/// Compression is RHEL8/9 only (V1R1 dropped it).
/// LogLevel is RHEL9/10 only.
/// Several yes/no directives are RHEL9/10 only.
fn w02_rule(keyword: &str, target: Option<TargetVersion>) -> Option<W02Rule> {
    let is_rhel9_or_10 = matches!(target, Some(TargetVersion::Rhel9 | TargetVersion::Rhel10));
    let is_rhel8_or_9 = matches!(target, Some(TargetVersion::Rhel8 | TargetVersion::Rhel9));
    // target=None behaves as the conservative floor = RHEL8 set.
    let target_is_none = target.is_none();

    match keyword {
        // ---- universal (all targets, floor included) ----
        "clientaliveinterval" => Some(W02Rule::NumericCeiling(600)),
        "clientalivecountmax" => Some(W02Rule::NumericExact(1)),
        "rekeylimit" => Some(W02Rule::TwoTokenExact("1g", "1h")),
        // Directives that must be exactly "no":
        "permitrootlogin"
        | "permitemptypasswords"
        | "gssapiauthentication"
        | "kerberosauthentication"
        | "x11forwarding"
        | "permituserenvironment" => Some(W02Rule::ExactLower("no")),
        // Directives that must be exactly "yes":
        "ignoreuserknownhosts" | "strictmodes" | "printlastlog" | "x11uselocalhost" => {
            Some(W02Rule::ExactLower("yes"))
        }

        // ---- RHEL9/10 only (not in RHEL8 required set or floor) ----
        "loglevel" if is_rhel9_or_10 => Some(W02Rule::ExactLower("verbose")),
        // RHEL9/10 "yes" controls:
        "pubkeyauthentication" | "usepam" | "ignorerhosts" if is_rhel9_or_10 => {
            Some(W02Rule::ExactLower("yes"))
        }
        // RHEL9/10 "no" controls:
        "hostbasedauthentication" if is_rhel9_or_10 => Some(W02Rule::ExactLower("no")),

        // ---- Compression: RHEL8/9 only; RHEL10 V1R1 dropped this control ----
        // target=None uses the floor (RHEL8), so Compression is controlled there too.
        "compression" if is_rhel8_or_9 || target_is_none => {
            Some(W02Rule::AnyOf(&["delayed", "no"]))
        }

        // ---- Banner: presence-only (W01); not a W02 value check ----
        // ---- Everything else: not a W02 concern for this target ----
        _ => None,
    }
}

/// Extract the directives from the global block only.
///
/// W01 and W02 check the global (pre-Match) block: STIG baselines govern the
/// daemon-level effective configuration, not Match overrides. (Match overrides
/// are a future sshd-W05 concern.)
fn global_directives(blocks: &[Block]) -> &[crate::ast::Directive] {
    match blocks.first() {
        Some(Block::Global(directives)) => directives,
        _ => &[],
    }
}

// ---------------------------------------------------------------------------
// sshd-W01
// ---------------------------------------------------------------------------

/// sshd-W01: a STIG-required directive is missing from the configuration.
///
/// Fires one diagnostic per missing required directive. The required set depends
/// on the `--target` RHEL version; `target=None` uses the conservative floor (the
/// 14-directive RHEL 8 V2R4 intersection).
///
/// # Per-target required sets (grounded in official DISA XCCDF, 2026-06-14)
///
/// - RHEL 8 V2R4 (`U_RHEL_8_V2R4_STIG.zip`, 02 Jul 2025): 14 directives.
/// - RHEL 9 V2R7 (`U_RHEL_9_V2R7_STIG.zip`, 05 Jan 2026): 20 directives.
/// - RHEL 10 V1R1 (`U_RHEL_10_V1R1_STIG.zip`, 26 Feb 2026): 19 directives
///   (RHEL9 minus Compression, which V1R1 dropped).
///
/// # Not in scope
///
/// `MaxAuthTries` and `LoginGraceTime` are CIS / general-hardening controls,
/// absent from all three DISA STIG XCCDF SSH directive sets. W01 must never fire
/// for their absence.
///
/// # Lookup is case-insensitive
///
/// Keywords in `sshd_config` are case-insensitive (`Directive::keyword_lower()`
/// is the canonical comparison key).
#[must_use]
pub fn w01(blocks: &[Block], file: &Path, ctx: &SshdLintContext) -> Vec<Diagnostic> {
    let directives = global_directives(blocks);
    let required = required_set(ctx.target);

    // Build the set of present keyword lowercases.
    let present: std::collections::HashSet<String> = directives
        .iter()
        .map(crate::ast::Directive::keyword_lower)
        .collect();

    let mut diags = Vec::new();
    for &req in required {
        if !present.contains(req) {
            // Emit at byte offset 0 with an empty span: there is no line to anchor
            // to (the directive is absent). The file path is still reported.
            diags.push(anchored(
                Severity::Warning,
                "sshd-W01",
                0..0,
                format!("STIG-required directive '{req}' is missing from the configuration"),
                file,
                0,
            ));
        }
    }
    diags
}

// ---------------------------------------------------------------------------
// sshd-W02
// ---------------------------------------------------------------------------

/// sshd-W02: a present directive's value is weaker than the STIG baseline.
///
/// Fires for each present directive whose value fails the per-directive comparison
/// rule for the target. W02 never fires for an absent directive (that is W01's
/// job); `w02` only checks directives that ARE present in the global block.
///
/// # Per-target value semantics (grounded in DISA XCCDF)
///
/// - `ClientAliveInterval`: `<= 600` numeric ceiling (RHEL-09-255100 V-257996 /
///   V-244525 / V-281296).
/// - `ClientAliveCountMax`: exact `1` (BOTH 0 AND > 1 are findings).
///   Grounded in RHEL-09-255095 V-257995 / V-230244 / V-281269 check-text
///   requiring the literal value `1`.
/// - `RekeyLimit`: exact two-token `1G 1h` (V-257994 / V-230527 / V-281268).
/// - `PermitRootLogin`: exact `no`; `prohibit-password` IS a finding
///   (V-257985 / V-230296 / V-281265).
/// - yes/no controls: exact literal match.
/// - `Compression`: `delayed` or `no` are OK; `yes` is a finding (RHEL 8/9 only;
///   RHEL 10 V1R1 dropped this control, so W02 must NOT fire for it under Rhel10).
/// - `LogLevel`: exact `VERBOSE` (RHEL9/10 only; not a RHEL8 or floor control).
///
/// # Scope guard
///
/// W02 evaluates the single-file value only. Cross-file / drop-in precedence
/// (first-value-wins across `sshd_config.d/`) is sshd-F02 / Wave C.
///
/// # Banner is not a W02 concern
///
/// Banner is a presence-only check (W01). The banner value is a path, not a
/// strict literal, so W02 must not fire for any Banner value.
#[must_use]
pub fn w02(blocks: &[Block], file: &Path, ctx: &SshdLintContext) -> Vec<Diagnostic> {
    let directives = global_directives(blocks);
    let mut diags = Vec::new();

    for directive in directives {
        let keyword = directive.keyword_lower();
        let Some(rule) = w02_rule(&keyword, ctx.target) else {
            continue;
        };

        let violation_msg: Option<String> = match rule {
            W02Rule::ExactLower(expected) => {
                let actual = directive.args.first().map_or("", String::as_str);
                (actual.to_ascii_lowercase() != expected).then(|| {
                    format!(
                        "directive '{}' has value '{actual}'; STIG baseline requires '{expected}'",
                        directive.keyword,
                    )
                })
            }
            W02Rule::TwoTokenExact(tok0, tok1) => {
                let actual0 = directive
                    .args
                    .first()
                    .map_or_else(String::new, |s| s.to_ascii_lowercase());
                let actual1 = directive
                    .args
                    .get(1)
                    .map_or_else(String::new, |s| s.to_ascii_lowercase());
                (actual0 != tok0 || actual1 != tok1).then(|| {
                    let displayed = directive.args.join(" ");
                    format!(
                        "directive '{}' has value '{displayed}'; STIG baseline requires '{tok0} {tok1}'",
                        directive.keyword,
                    )
                })
            }
            W02Rule::AnyOf(accepted) => {
                let actual = directive.args.first().map_or("", String::as_str);
                let actual_lower = actual.to_ascii_lowercase();
                (!accepted.contains(&actual_lower.as_str())).then(|| {
                    format!(
                        "directive '{}' has value '{actual}'; STIG baseline requires one of: {}",
                        directive.keyword,
                        accepted.join(", "),
                    )
                })
            }
            W02Rule::NumericCeiling(ceiling) => {
                let actual = directive.args.first().map_or("", String::as_str);
                match actual.parse::<u64>() {
                    Ok(n) if n > 0 && n <= ceiling => None,
                    _ => Some(format!(
                        "directive '{}' has value '{actual}'; STIG baseline requires a value > 0 and <= {ceiling}",
                        directive.keyword,
                    )),
                }
            }
            W02Rule::NumericExact(required) => {
                let actual = directive.args.first().map_or("", String::as_str);
                match actual.parse::<u64>() {
                    Ok(n) if n == required => None,
                    _ => Some(format!(
                        "directive '{}' has value '{actual}'; STIG baseline requires exactly {required}",
                        directive.keyword,
                    )),
                }
            }
        };

        if let Some(msg) = violation_msg {
            diags.push(anchored(
                Severity::Warning,
                "sshd-W02",
                directive.span.clone(),
                msg,
                file,
                directive.line,
            ));
        }
    }

    diags
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lints::TargetVersion;
    use std::path::Path;

    fn parse(src: &str) -> Vec<Block> {
        crate::parser::parse_config_str_located(src, Path::new("/etc/ssh/sshd_config"))
            .expect("fixture parses")
    }

    #[test]
    fn required_set_sizes_match_spec() {
        assert_eq!(
            RHEL8_REQUIRED.len(),
            14,
            "RHEL8 must have 14 required directives"
        );
        assert_eq!(
            RHEL9_REQUIRED.len(),
            20,
            "RHEL9 must have 20 required directives"
        );
        assert_eq!(
            RHEL10_REQUIRED.len(),
            19,
            "RHEL10 must have 19 required directives"
        );
        assert_eq!(FLOOR_REQUIRED.len(), 14, "floor must have 14 directives");
    }

    #[test]
    fn floor_is_subset_of_all_versions() {
        for &kw in FLOOR_REQUIRED {
            assert!(
                RHEL8_REQUIRED.contains(&kw),
                "floor directive '{kw}' must be in RHEL8",
            );
            assert!(
                RHEL9_REQUIRED.contains(&kw),
                "floor directive '{kw}' must be in RHEL9",
            );
            assert!(
                RHEL10_REQUIRED.contains(&kw),
                "floor directive '{kw}' must be in RHEL10",
            );
        }
    }

    #[test]
    fn rhel8_is_subset_of_rhel9() {
        for &kw in RHEL8_REQUIRED {
            assert!(
                RHEL9_REQUIRED.contains(&kw),
                "RHEL8 directive '{kw}' must also be in RHEL9",
            );
        }
    }

    #[test]
    fn compression_in_rhel9_only_among_floors() {
        assert!(
            !RHEL10_REQUIRED.contains(&"compression"),
            "Compression was dropped from RHEL10 V1R1"
        );
        assert!(
            !RHEL8_REQUIRED.contains(&"compression"),
            "Compression was never in RHEL8 V2R4 (no such STIG control)"
        );
        assert!(
            RHEL9_REQUIRED.contains(&"compression"),
            "Compression is in RHEL9 V2R7 (V-258002)"
        );
    }

    #[test]
    fn w02_does_not_fire_for_absent_directive() {
        // Empty config: W02 must return empty (W01 handles absence).
        let ctx = SshdLintContext {
            target: Some(TargetVersion::Rhel9),
            single_file: true,
        };
        let blocks = parse("");
        let diags = w02(&blocks, Path::new("/etc/ssh/sshd_config"), &ctx);
        assert!(
            diags.is_empty(),
            "W02 must not fire for absent directives; got {diags:?}"
        );
    }

    #[test]
    fn w02_compression_not_checked_for_rhel10() {
        let ctx = SshdLintContext {
            target: Some(TargetVersion::Rhel10),
            single_file: true,
        };
        let blocks = parse("Compression yes\n");
        let diags = w02(&blocks, Path::new("/etc/ssh/sshd_config"), &ctx);
        assert!(
            !diags.iter().any(|d| d.code == "sshd-W02"),
            "Compression is not a RHEL10 STIG control; W02 must not fire"
        );
    }
}
