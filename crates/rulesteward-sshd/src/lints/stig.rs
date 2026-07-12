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
///
/// `pub(crate)` so the cross-file (sshd-F02) and Match-override (sshd-W05) lints
/// share the exact same STIG-required set as W01 (Phase-0 shared surface, #149
/// Wave C). The keywords are lowercase.
pub(crate) fn required_set(target: Option<TargetVersion>) -> &'static [&'static str] {
    match target {
        Some(TargetVersion::Rhel8) => RHEL8_REQUIRED,
        Some(TargetVersion::Rhel9) => RHEL9_REQUIRED,
        Some(TargetVersion::Rhel10) => RHEL10_REQUIRED,
        None => FLOOR_REQUIRED,
    }
}

/// Outcome of checking one directive's value against its STIG W02 baseline.
///
/// Shared by W02 (global block), sshd-W05 (Match-block override), and sshd-F02
/// (drop-in override) so all three apply the IDENTICAL per-directive comparison
/// (Phase-0 shared surface, #149 Wave C). Each call site phrases its own
/// diagnostic from `requirement` + `displayed_value`.
pub(crate) enum BaselineCheck {
    /// The directive is not a W02-controlled value check for this target.
    NotControlled,
    /// The value satisfies the baseline.
    Ok,
    /// The value fails the baseline. `requirement` is the human clause naming
    /// what STIG requires (e.g. `'no'`, `'1g 1h'`, `one of: delayed, no`,
    /// `a value > 0 and <= 600`, `exactly 1`); `displayed_value` is the value as
    /// the operator wrote it (single token, or the full two-token form).
    Violation {
        requirement: String,
        displayed_value: String,
    },
}

/// Check a directive's value against the W02 STIG baseline for `target`.
///
/// Returns `NotControlled` when the directive has no W02 value rule for this
/// target (so W01 presence-only directives like Banner, and out-of-target
/// directives, are never value-checked here).
pub(crate) fn baseline_check(
    keyword_lower: &str,
    args: &[String],
    target: Option<TargetVersion>,
) -> BaselineCheck {
    let Some(rule) = w02_rule(keyword_lower, target) else {
        return BaselineCheck::NotControlled;
    };

    // The displayed value: the full two-token form for RekeyLimit, else the
    // first token (or empty). Matches the prior inline W02 message formatting
    // byte-for-byte.
    let displayed_value = match rule {
        W02Rule::TwoTokenExact(..) => args.join(" "),
        _ => args.first().map_or_else(String::new, String::clone),
    };

    let requirement: Option<String> = match rule {
        W02Rule::ExactLower(expected) => {
            let actual = args.first().map_or("", String::as_str);
            (actual.to_ascii_lowercase() != expected).then(|| format!("'{expected}'"))
        }
        W02Rule::TwoTokenExact(tok0, tok1) => {
            let actual0 = args
                .first()
                .map_or_else(String::new, |s| s.to_ascii_lowercase());
            let actual1 = args
                .get(1)
                .map_or_else(String::new, |s| s.to_ascii_lowercase());
            (actual0 != tok0 || actual1 != tok1).then(|| format!("'{tok0} {tok1}'"))
        }
        W02Rule::AnyOf(accepted) => {
            let actual = args.first().map_or("", String::as_str);
            let actual_lower = actual.to_ascii_lowercase();
            (!accepted.contains(&actual_lower.as_str()))
                .then(|| format!("one of: {}", accepted.join(", ")))
        }
        W02Rule::NumericCeiling(ceiling) => {
            let actual = args.first().map_or("", String::as_str);
            match actual.parse::<u64>() {
                Ok(n) if n > 0 && n <= ceiling => None,
                _ => Some(format!("a value > 0 and <= {ceiling}")),
            }
        }
        W02Rule::NumericExact(required) => {
            let actual = args.first().map_or("", String::as_str);
            match actual.parse::<u64>() {
                Ok(n) if n == required => None,
                _ => Some(format!("exactly {required}")),
            }
        }
    };

    match requirement {
        Some(requirement) => BaselineCheck::Violation {
            requirement,
            displayed_value,
        },
        None => BaselineCheck::Ok,
    }
}

// ---------------------------------------------------------------------------
// W02 value comparison helpers
// ---------------------------------------------------------------------------

/// Comparison kind for a STIG-required directive's value.
#[derive(Clone, Copy)]
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

// ---------------------------------------------------------------------------
// #444 drift-tool projection
//
// A machine-comparable view of the shipped W01 required set + W02 value rule +
// the V-number provenance, so the `sshd-stig-update` tool (issue #444) can derive
// the same shape from the DISA XCCDF and drift-check it against these tables.
//
// This is ADDITIVE: the frozen `RHEL{8,9,10}_REQUIRED` arrays and `w02_rule` stay
// the lint interface untouched. The only datum not already machine-readable is the
// V-number (it lives in `//` comments on the required arrays); the per-target
// `(keyword, v_number)` provenance maps below carry it as data. A consistency test
// (`provenance_covers_required_set_exactly`) binds each map's keyword set to
// `required_set`, so the parallel map cannot silently drift from the required set.
// ---------------------------------------------------------------------------

/// A STIG value assertion, projected for the #444 drift tool. Public mirror of the
/// private [`W02Rule`], plus `PresenceOnly` for the one W01 presence-only control
/// (Banner) that has no W02 value rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StigValueRule {
    /// Presence-only (W01): the directive must be set, but no specific value is
    /// asserted (Banner - the value is a site-specific path).
    PresenceOnly,
    /// Exact case-insensitive literal (e.g. PermitRootLogin `no`, LogLevel `verbose`).
    ExactLower(&'static str),
    /// Exact two-token match (RekeyLimit `1g 1h`).
    TwoTokenExact(&'static str, &'static str),
    /// Any of the listed lowercase values (Compression: `delayed` or `no`).
    AnyOf(&'static [&'static str]),
    /// Numeric ceiling: value must be `> 0` and `<= N` (ClientAliveInterval `<= 600`).
    NumericCeiling(u64),
    /// Numeric exact: value must equal N exactly (ClientAliveCountMax `1`).
    NumericExact(u64),
}

/// One STIG-controlled sshd directive, projected for the #444 drift tool: the
/// lowercase keyword, its DISA V-number for the target, and the value assertion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StigControl {
    /// Directive keyword, lowercase (matches [`required_set`]).
    pub keyword: &'static str,
    /// DISA V-number for this target (e.g. `V-257985`), from `<Group id>`.
    pub v_number: &'static str,
    /// The W02 value assertion, or `PresenceOnly` (W01) for Banner.
    pub value_rule: StigValueRule,
}

/// Per-target `(keyword, V-number)` provenance. Mirrors the `//` V-number comments
/// on the `RHEL{8,9,10}_REQUIRED` arrays as data. The keyword set MUST equal
/// `required_set(Some(target))` (asserted by `provenance_covers_required_set_exactly`).
const RHEL8_VNUM: &[(&str, &str)] = &[
    ("banner", "V-230225"),
    ("clientalivecountmax", "V-230244"),
    ("clientaliveinterval", "V-244525"),
    ("gssapiauthentication", "V-244528"),
    ("ignoreuserknownhosts", "V-230290"),
    ("kerberosauthentication", "V-230291"),
    ("permitemptypasswords", "V-230380"),
    ("permitrootlogin", "V-230296"),
    ("permituserenvironment", "V-230330"),
    ("printlastlog", "V-230382"),
    ("rekeylimit", "V-230527"),
    ("strictmodes", "V-230288"),
    ("x11forwarding", "V-230555"),
    ("x11uselocalhost", "V-230556"),
];

const RHEL9_VNUM: &[(&str, &str)] = &[
    ("banner", "V-257981"),
    ("clientalivecountmax", "V-257995"),
    ("clientaliveinterval", "V-257996"),
    ("compression", "V-258002"),
    ("gssapiauthentication", "V-258003"),
    ("hostbasedauthentication", "V-257992"),
    ("ignorerhosts", "V-258005"),
    ("ignoreuserknownhosts", "V-258006"),
    ("kerberosauthentication", "V-258004"),
    ("loglevel", "V-257982"),
    ("permitemptypasswords", "V-257984"),
    ("permitrootlogin", "V-257985"),
    ("permituserenvironment", "V-257993"),
    ("printlastlog", "V-258009"),
    ("pubkeyauthentication", "V-257983"),
    ("rekeylimit", "V-257994"),
    ("strictmodes", "V-258008"),
    ("usepam", "V-257986"),
    ("x11forwarding", "V-258007"),
    ("x11uselocalhost", "V-258011"),
];

const RHEL10_VNUM: &[(&str, &str)] = &[
    ("banner", "V-281224"),
    ("clientalivecountmax", "V-281269"),
    ("clientaliveinterval", "V-281296"),
    ("gssapiauthentication", "V-281254"),
    ("hostbasedauthentication", "V-281266"),
    ("ignorerhosts", "V-281256"),
    ("ignoreuserknownhosts", "V-281257"),
    ("kerberosauthentication", "V-281255"),
    ("loglevel", "V-281115"),
    ("permitemptypasswords", "V-281264"),
    ("permitrootlogin", "V-281265"),
    ("permituserenvironment", "V-281267"),
    ("printlastlog", "V-281260"),
    ("pubkeyauthentication", "V-281263"),
    ("rekeylimit", "V-281268"),
    ("strictmodes", "V-281259"),
    ("usepam", "V-281216"),
    ("x11forwarding", "V-281258"),
    ("x11uselocalhost", "V-281261"),
];

/// The `(keyword, V-number)` provenance map for a concrete target.
fn provenance_map(target: TargetVersion) -> &'static [(&'static str, &'static str)] {
    match target {
        TargetVersion::Rhel8 => RHEL8_VNUM,
        TargetVersion::Rhel9 => RHEL9_VNUM,
        TargetVersion::Rhel10 => RHEL10_VNUM,
    }
}

/// Widen the private [`W02Rule`] into the public [`StigValueRule`]; `None`
/// (no W02 value rule) becomes `PresenceOnly`.
fn value_rule_of(rule: Option<W02Rule>) -> StigValueRule {
    match rule {
        None => StigValueRule::PresenceOnly,
        Some(W02Rule::ExactLower(s)) => StigValueRule::ExactLower(s),
        Some(W02Rule::TwoTokenExact(a, b)) => StigValueRule::TwoTokenExact(a, b),
        Some(W02Rule::AnyOf(v)) => StigValueRule::AnyOf(v),
        Some(W02Rule::NumericCeiling(n)) => StigValueRule::NumericCeiling(n),
        Some(W02Rule::NumericExact(n)) => StigValueRule::NumericExact(n),
    }
}

/// The full STIG baseline projection for `target`: one [`StigControl`] per required
/// directive (keyword + V-number + value rule), for the #444 drift tool to compare
/// against its DISA-XCCDF-derived table.
///
/// Driven by [`provenance_map`] (so it never has a "missing V-number" case); the
/// keyword coverage is cross-checked against [`required_set`] by a test. The value
/// rule comes from the shipped [`w02_rule`], so this stays a pure projection of the
/// existing tables - no second source of truth for the values.
#[must_use]
pub fn stig_baseline(target: TargetVersion) -> Vec<StigControl> {
    provenance_map(target)
        .iter()
        .map(|&(keyword, v_number)| StigControl {
            keyword,
            v_number,
            value_rule: value_rule_of(w02_rule(keyword, Some(target))),
        })
        .collect()
}

/// The directives that make up the EFFECTIVE global configuration: the leading
/// global (pre-Match) block, followed by the bodies of every unconditional
/// `Match all` block.
///
/// `Match all` is always active (verified rocky9 `sshd -T`), so sshd treats its
/// body as global context, not a per-connection override. W01 (required-present)
/// and W02 (value-vs-baseline) therefore must see those directives too; reading
/// only the leading global block makes a directive placed under `Match all`
/// invisible -- a false `sshd-W01` "missing" and a dropped `sshd-W02`. Conditional
/// `Match User/Group/...` bodies are deliberately EXCLUDED: a weak value there is
/// `sshd-W05`'s concern, not a global finding.
///
/// Single-file scope note (issue #336, owner-confirmed Option A): this is the
/// "as-written" view -- every present value is evaluated, NOT a first-`Match all`-
/// wins effective-value dedup. If the global section sets a weak value that a later
/// `Match all` overrides to a compliant one, W02 still reports the global line.
/// That is intentional: effective-value precedence is the dir-mode / sshd-F02
/// path's job ([`crate::lints::drop_in`]'s `build_merged`); do NOT "fix" it into a
/// dedup here.
fn effective_global_directives(blocks: &[Block]) -> Vec<&crate::ast::Directive> {
    let mut directives = Vec::new();
    for block in blocks {
        match block {
            Block::Global(global) => directives.extend(global.iter()),
            Block::Match(match_block) if super::is_unconditional_match_all(match_block) => {
                directives.extend(match_block.body.iter());
            }
            Block::Match(_) => {}
        }
    }
    directives
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
    let directives = effective_global_directives(blocks);
    let required = required_set(ctx.target);

    // Build the set of present keyword lowercases.
    let present: std::collections::HashSet<String> =
        directives.iter().map(|d| d.keyword_lower()).collect();

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
    let directives = effective_global_directives(blocks);
    let mut diags = Vec::new();

    for directive in directives {
        let keyword = directive.keyword_lower();
        if let BaselineCheck::Violation {
            requirement,
            displayed_value,
        } = baseline_check(&keyword, &directive.args, ctx.target)
        {
            diags.push(anchored(
                Severity::Warning,
                "sshd-W02",
                directive.span.clone(),
                format!(
                    "directive '{}' has value '{displayed_value}'; STIG baseline requires {requirement}",
                    directive.keyword,
                ),
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

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn baseline_check_contract_for_shared_callers() {
        // NotControlled: a directive with no W02 value rule for the target.
        assert!(matches!(
            baseline_check("banner", &args(&["/etc/issue"]), None),
            BaselineCheck::NotControlled
        ));
        // Ok: a compliant value passes.
        assert!(matches!(
            baseline_check("permitrootlogin", &args(&["no"]), None),
            BaselineCheck::Ok
        ));
        // Violation: a non-compliant value carries the requirement + the value
        // as written (this is the shared surface W05/F02 phrase their own
        // diagnostics from).
        match baseline_check("permitrootlogin", &args(&["yes"]), None) {
            BaselineCheck::Violation {
                requirement,
                displayed_value,
            } => {
                assert_eq!(requirement, "'no'");
                assert_eq!(displayed_value, "yes");
            }
            other => panic!(
                "expected Violation, got NotControlled/Ok: {}",
                matches!(other, BaselineCheck::Ok)
            ),
        }
        // Two-token RekeyLimit displays the full form.
        match baseline_check("rekeylimit", &args(&["2G", "2h"]), None) {
            BaselineCheck::Violation {
                requirement,
                displayed_value,
            } => {
                assert_eq!(requirement, "'1g 1h'");
                assert_eq!(displayed_value, "2G 2h");
            }
            _ => panic!("expected RekeyLimit Violation"),
        }
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

    // --- issue #336: unconditional `Match all` folds into the effective global ---

    #[test]
    fn w02_evaluates_unconditional_match_all_as_global() {
        // `Match all` is always-active global context: a weak STIG value there is a
        // W02 finding. Previously dropped (W02 read only the leading global block).
        let ctx = SshdLintContext {
            target: Some(TargetVersion::Rhel9),
            single_file: true,
        };
        let blocks = parse("Match all\n    PermitRootLogin yes\n");
        let diags = w02(&blocks, Path::new("/etc/ssh/sshd_config"), &ctx);
        assert_eq!(
            diags.len(),
            1,
            "a weak STIG value under `Match all` is a W02 finding; got {diags:?}"
        );
        assert_eq!(diags[0].code, "sshd-W02");
        assert_eq!(
            diags[0].line, 2,
            "W02 anchors at the real Match-body directive line (line 2)"
        );
    }

    #[test]
    fn w02_compliant_value_under_match_all_is_clean() {
        let ctx = SshdLintContext {
            target: Some(TargetVersion::Rhel9),
            single_file: true,
        };
        let blocks = parse("Match all\n    PermitRootLogin no\n");
        let diags = w02(&blocks, Path::new("/etc/ssh/sshd_config"), &ctx);
        assert!(
            diags.is_empty(),
            "a compliant value under `Match all` must not fire W02; got {diags:?}"
        );
    }

    #[test]
    fn w02_does_not_fold_a_conditional_match() {
        // A weak value in a CONDITIONAL Match is W05's domain, not W02's: W02 must
        // fold only the UNCONDITIONAL `Match all`, never a conditional Match.
        let ctx = SshdLintContext {
            target: Some(TargetVersion::Rhel9),
            single_file: true,
        };
        let blocks = parse("PermitRootLogin no\nMatch Group admins\n    PermitRootLogin yes\n");
        let diags = w02(&blocks, Path::new("/etc/ssh/sshd_config"), &ctx);
        assert!(
            diags.is_empty(),
            "a conditional Match is not global context; W02 must not fire; got {diags:?}"
        );
    }

    #[test]
    fn w01_counts_required_directive_present_only_in_match_all() {
        // A required directive present ONLY inside `Match all` is effectively set
        // (always active), so W01 must NOT report it missing (issue #336).
        let ctx = SshdLintContext {
            target: Some(TargetVersion::Rhel9),
            single_file: true,
        };
        let blocks = parse("PermitRootLogin no\nMatch all\n    Banner /etc/issue.net\n");
        let diags = w01(&blocks, Path::new("/etc/ssh/sshd_config"), &ctx);
        assert!(
            !diags.iter().any(|d| d.message.contains("'banner'")),
            "banner present inside `Match all` must not be reported missing; got {diags:?}"
        );
    }

    // --- #444 drift-tool projection ---------------------------------------

    /// The parallel `(keyword, V-number)` provenance map for each target must cover
    /// EXACTLY `required_set` - no orphan V-number entry, no required directive
    /// missing a V-number. This is the guard that lets the parallel map stay a
    /// separate const without silently drifting from the frozen required arrays.
    #[test]
    fn provenance_covers_required_set_exactly() {
        for target in [
            TargetVersion::Rhel8,
            TargetVersion::Rhel9,
            TargetVersion::Rhel10,
        ] {
            let required: std::collections::BTreeSet<&str> =
                required_set(Some(target)).iter().copied().collect();
            let provenance: std::collections::BTreeSet<&str> =
                provenance_map(target).iter().map(|&(k, _)| k).collect();
            assert_eq!(
                provenance, required,
                "provenance keyword set must equal required_set for {target:?}"
            );
            // No duplicate keyword rows (would make stig_baseline emit two controls
            // for one directive).
            assert_eq!(
                provenance_map(target).len(),
                provenance.len(),
                "provenance_map has a duplicate keyword row for {target:?}"
            );
        }
    }

    /// V-numbers must be well-formed (`V-<digits>`) and unique within a target.
    #[test]
    fn v_numbers_are_well_formed_and_unique() {
        for target in [
            TargetVersion::Rhel8,
            TargetVersion::Rhel9,
            TargetVersion::Rhel10,
        ] {
            let controls = stig_baseline(target);
            let mut seen = std::collections::BTreeSet::new();
            for c in &controls {
                assert!(
                    c.v_number.starts_with("V-")
                        && c.v_number[2..].chars().all(|ch| ch.is_ascii_digit()),
                    "malformed V-number {:?} for {} on {target:?}",
                    c.v_number,
                    c.keyword
                );
                assert!(
                    seen.insert(c.v_number),
                    "duplicate V-number {:?} on {target:?}",
                    c.v_number
                );
            }
        }
    }

    /// `stig_baseline` must have one control per required directive (14/20/19).
    #[test]
    fn stig_baseline_sizes_match_required_sets() {
        assert_eq!(stig_baseline(TargetVersion::Rhel8).len(), 14);
        assert_eq!(stig_baseline(TargetVersion::Rhel9).len(), 20);
        assert_eq!(stig_baseline(TargetVersion::Rhel10).len(), 19);
    }

    /// Anti-tautology spot-checks: the projection must reproduce the exact
    /// (V-number, value rule) tuples for one directive of every `StigValueRule`
    /// kind, hard-coded from the DISA XCCDF grounding. A drift in either the
    /// provenance map or `w02_rule` breaks this.
    #[test]
    fn stig_baseline_projects_known_rhel9_controls() {
        let by_kw: std::collections::BTreeMap<&str, StigControl> =
            stig_baseline(TargetVersion::Rhel9)
                .into_iter()
                .map(|c| (c.keyword, c))
                .collect();
        let get = |kw: &str| *by_kw.get(kw).unwrap_or_else(|| panic!("missing {kw}"));

        // PresenceOnly (Banner, path value).
        let banner = get("banner");
        assert_eq!(banner.v_number, "V-257981");
        assert_eq!(banner.value_rule, StigValueRule::PresenceOnly);
        // ExactLower "no".
        let prl = get("permitrootlogin");
        assert_eq!(prl.v_number, "V-257985");
        assert_eq!(prl.value_rule, StigValueRule::ExactLower("no"));
        // ExactLower "verbose".
        assert_eq!(
            get("loglevel").value_rule,
            StigValueRule::ExactLower("verbose")
        );
        // ExactLower "yes".
        assert_eq!(
            get("ignoreuserknownhosts").value_rule,
            StigValueRule::ExactLower("yes")
        );
        // NumericCeiling 600.
        let cai = get("clientaliveinterval");
        assert_eq!(cai.v_number, "V-257996");
        assert_eq!(cai.value_rule, StigValueRule::NumericCeiling(600));
        // NumericExact 1.
        assert_eq!(
            get("clientalivecountmax").value_rule,
            StigValueRule::NumericExact(1)
        );
        // TwoTokenExact 1g 1h.
        assert_eq!(
            get("rekeylimit").value_rule,
            StigValueRule::TwoTokenExact("1g", "1h")
        );
        // AnyOf delayed/no.
        assert_eq!(
            get("compression").value_rule,
            StigValueRule::AnyOf(&["delayed", "no"])
        );
    }

    /// Compression is dropped from RHEL10, so its projection must NOT include it,
    /// and RHEL8 (floor) also excludes it (matches the required-set tables).
    #[test]
    fn stig_baseline_compression_only_rhel9() {
        assert!(
            stig_baseline(TargetVersion::Rhel9)
                .iter()
                .any(|c| c.keyword == "compression")
        );
        assert!(
            !stig_baseline(TargetVersion::Rhel10)
                .iter()
                .any(|c| c.keyword == "compression"),
            "Compression dropped from RHEL10 V1R1"
        );
        assert!(
            !stig_baseline(TargetVersion::Rhel8)
                .iter()
                .any(|c| c.keyword == "compression"),
            "Compression not a RHEL8 V2R4 control"
        );
    }

    // --- #501 v0.7 typed control-ID backfill --------------------------------
    // sshd-W01/W02 findings must carry a typed STIG `ControlRef` whose canonical
    // `id` is the STIG Rule id (RHEL-09-######) and whose `alias` is the DISA
    // V-number, alongside the byte-identical human message. Grounded in the data
    // already in THIS file: the Rule id lives in the `//` comment on the
    // `RHEL9_REQUIRED` array; the V-number lives in the `RHEL9_VNUM` table.

    #[test]
    fn w01_missing_findings_carry_typed_stig_control() {
        // Representative: `banner` on target=Rhel9.
        //   Rule id  RHEL-09-255025 -- RHEL9_REQUIRED comment:
        //            `"banner", // RHEL-09-255025 V-257981` (this file).
        //   V-number V-257981       -- RHEL9_VNUM entry `("banner", "V-257981")`.
        use rulesteward_core::Framework;
        let ctx = SshdLintContext {
            target: Some(TargetVersion::Rhel9),
            single_file: true,
        };
        // An empty config makes every required directive (incl. Banner) missing.
        let blocks = parse("");
        let diags = w01(&blocks, Path::new("/etc/ssh/sshd_config"), &ctx);
        let banner = diags
            .iter()
            .find(|d| d.message.contains("'banner'"))
            .expect("banner reported missing on an empty config");

        // Message stays byte-identical (the implementer must not alter it).
        assert_eq!(
            banner.message,
            "STIG-required directive 'banner' is missing from the configuration"
        );

        // RED anchor: length first, so RED is a clean `0 != 1`, not an index panic.
        assert_eq!(
            banner.controls.len(),
            1,
            "W01 finding must carry exactly one STIG control"
        );
        assert_eq!(banner.controls[0].framework, Framework::Stig);
        assert_eq!(banner.controls[0].id, "RHEL-09-255025");
        assert_eq!(banner.controls[0].alias, Some("V-257981".to_string()));
    }

    #[test]
    fn w02_weak_value_findings_carry_typed_stig_control() {
        // Representative: `PermitRootLogin yes` on target=Rhel9 (STIG requires `no`).
        //   Rule id  RHEL-09-255045 -- RHEL9_REQUIRED comment:
        //            `"permitrootlogin", // RHEL-09-255045 V-257985` (this file).
        //   V-number V-257985       -- RHEL9_VNUM entry `("permitrootlogin", "V-257985")`.
        use rulesteward_core::Framework;
        let ctx = SshdLintContext {
            target: Some(TargetVersion::Rhel9),
            single_file: true,
        };
        let blocks = parse("PermitRootLogin yes\n");
        let diags = w02(&blocks, Path::new("/etc/ssh/sshd_config"), &ctx);
        assert_eq!(
            diags.len(),
            1,
            "one W02 finding for the weak PermitRootLogin; got {diags:?}"
        );
        let prl = &diags[0];
        assert_eq!(prl.code, "sshd-W02");

        // Message stays byte-identical (the implementer must not alter it).
        assert_eq!(
            prl.message,
            "directive 'PermitRootLogin' has value 'yes'; STIG baseline requires 'no'"
        );

        // RED anchor: length first.
        assert_eq!(
            prl.controls.len(),
            1,
            "W02 finding must carry exactly one STIG control"
        );
        assert_eq!(prl.controls[0].framework, Framework::Stig);
        assert_eq!(prl.controls[0].id, "RHEL-09-255045");
        assert_eq!(prl.controls[0].alias, Some("V-257985".to_string()));
    }

    #[test]
    fn non_stig_findings_carry_no_controls() {
        // Empty-controls guard: the backfill is scoped to the STIG passes (W01/W02).
        // A finding from a non-STIG structural pass (here sshd-E02, a duplicate
        // directive) must keep `controls` empty -- the implementer must not
        // over-attach. `MaxSessions` is neither STIG-required nor W02-controlled.
        let ctx = SshdLintContext::default();
        let blocks = parse("MaxSessions 10\nMaxSessions 5\n");
        let diags = crate::lints::structural::e02(&blocks, Path::new("/etc/ssh/sshd_config"), &ctx);
        let dup = diags
            .iter()
            .find(|d| d.code == "sshd-E02")
            .expect("duplicate MaxSessions fires sshd-E02");
        assert!(
            dup.controls.is_empty(),
            "a non-STIG (sshd-E02) finding must carry no controls; got {:?}",
            dup.controls
        );
    }

    // --- #501 backfill: RHEL8 + RHEL10 targets (scope expansion) -------------
    // Same shape as the RHEL9 W01/W02 tests above, on the other two targets, so
    // the emit path must key the ControlRef on BOTH target AND keyword: a
    // constant-control impl fails because per target `banner` (W01) and
    // `permitrootlogin` (W02) pin DISTINCT ids/aliases, and each keyword's
    // expected control also differs across targets. RHEL8/RHEL10 Rule ids come
    // from the DISA XCCDF grounding (RHEL8 V2R4 / RHEL10 V1R1); each V-number
    // alias is cross-validated against this file's shipped RHEL8_VNUM/RHEL10_VNUM.

    /// Shared W01 assertion: an empty config makes `banner` missing on `target`;
    /// the finding must carry exactly one STIG `ControlRef` (`id` = Rule id,
    /// `alias` = V-number) and keep its message byte-identical.
    fn assert_w01_banner_control(target: TargetVersion, expect_id: &str, expect_vnum: &str) {
        use rulesteward_core::Framework;
        let ctx = SshdLintContext {
            target: Some(target),
            single_file: true,
        };
        let blocks = parse("");
        let diags = w01(&blocks, Path::new("/etc/ssh/sshd_config"), &ctx);
        let banner = diags
            .iter()
            .find(|d| d.message.contains("'banner'"))
            .expect("banner reported missing on an empty config");
        assert_eq!(
            banner.message,
            "STIG-required directive 'banner' is missing from the configuration"
        );
        assert_eq!(
            banner.controls.len(),
            1,
            "W01 finding must carry exactly one STIG control ({target:?})"
        );
        assert_eq!(banner.controls[0].framework, Framework::Stig);
        assert_eq!(banner.controls[0].id, expect_id);
        assert_eq!(banner.controls[0].alias, Some(expect_vnum.to_string()));
    }

    /// Shared W02 assertion: `PermitRootLogin yes` on `target` is a weak-value
    /// finding (STIG requires `no`) that must carry exactly one STIG `ControlRef`
    /// (`id` = Rule id, `alias` = V-number) and keep its message byte-identical.
    fn assert_w02_permitrootlogin_control(
        target: TargetVersion,
        expect_id: &str,
        expect_vnum: &str,
    ) {
        use rulesteward_core::Framework;
        let ctx = SshdLintContext {
            target: Some(target),
            single_file: true,
        };
        let blocks = parse("PermitRootLogin yes\n");
        let diags = w02(&blocks, Path::new("/etc/ssh/sshd_config"), &ctx);
        assert_eq!(
            diags.len(),
            1,
            "one W02 finding for the weak PermitRootLogin ({target:?}); got {diags:?}"
        );
        let prl = &diags[0];
        assert_eq!(prl.code, "sshd-W02");
        assert_eq!(
            prl.message,
            "directive 'PermitRootLogin' has value 'yes'; STIG baseline requires 'no'"
        );
        assert_eq!(
            prl.controls.len(),
            1,
            "W02 finding must carry exactly one STIG control ({target:?})"
        );
        assert_eq!(prl.controls[0].framework, Framework::Stig);
        assert_eq!(prl.controls[0].id, expect_id);
        assert_eq!(prl.controls[0].alias, Some(expect_vnum.to_string()));
    }

    #[test]
    fn w01_missing_findings_carry_typed_stig_control_rhel8() {
        // banner on Rhel8: Rule id RHEL-08-010040 (DISA XCCDF RHEL8 V2R4),
        // V-number V-230225 (this file's RHEL8_VNUM `("banner", "V-230225")`).
        assert_w01_banner_control(TargetVersion::Rhel8, "RHEL-08-010040", "V-230225");
    }

    #[test]
    fn w02_weak_value_findings_carry_typed_stig_control_rhel8() {
        // PermitRootLogin on Rhel8: Rule id RHEL-08-010550 (DISA XCCDF RHEL8 V2R4),
        // V-number V-230296 (this file's RHEL8_VNUM `("permitrootlogin", "V-230296")`).
        assert_w02_permitrootlogin_control(TargetVersion::Rhel8, "RHEL-08-010550", "V-230296");
    }

    #[test]
    fn w01_missing_findings_carry_typed_stig_control_rhel10() {
        // banner on Rhel10: Rule id RHEL-10-700010 (DISA XCCDF RHEL10 V1R1),
        // V-number V-281224 (this file's RHEL10_VNUM `("banner", "V-281224")`).
        assert_w01_banner_control(TargetVersion::Rhel10, "RHEL-10-700010", "V-281224");
    }

    #[test]
    fn w02_weak_value_findings_carry_typed_stig_control_rhel10() {
        // PermitRootLogin on Rhel10: Rule id RHEL-10-700620 (DISA XCCDF RHEL10 V1R1),
        // V-number V-281265 (this file's RHEL10_VNUM `("permitrootlogin", "V-281265")`).
        assert_w02_permitrootlogin_control(TargetVersion::Rhel10, "RHEL-10-700620", "V-281265");
    }
}
