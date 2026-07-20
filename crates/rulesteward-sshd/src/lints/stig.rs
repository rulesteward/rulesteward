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

use rulesteward_core::{ControlRef, Diagnostic, Framework, Severity};

use crate::ast::Block;
use crate::lints::cis;
use crate::lints::{SshdLintContext, TargetVersion, anchored};

// ---------------------------------------------------------------------------
// W01 required-directive tables (per target)
// Each entry is the directive keyword in LOWERCASE.
// The RHEL 9 set is the "spine"; RHEL 8 and RHEL 10 sets are derived from it.
// ---------------------------------------------------------------------------

/// RHEL 9 V2R9 required directives (19 total, V-257981..V-258011 SSH set
/// minus Compression, dropped in V2R9).
///
/// Grounded in DISA XCCDF `U_RHEL_9_V2R9_STIG.zip`, confirmed 2026-07-17
/// (#549, session 9e-wave2c pipeline P2). Compression (V-258002 /
/// RHEL-09-255130) was REMOVED from the STIG in V2R9 (was present in V2R7).
/// STIG-IDs: RHEL-09-255025..255175 (minus 255130).
const RHEL9_REQUIRED: &[&str] = &[
    "banner",                  // RHEL-09-255025 V-257981
    "clientalivecountmax",     // RHEL-09-255095 V-257995
    "clientaliveinterval",     // RHEL-09-255100 V-257996
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
/// Absent vs RHEL9 (V2R9): LogLevel, PubkeyAuthentication, UsePAM,
/// IgnoreRhosts, HostbasedAuthentication. (RHEL 8 has no sshd_config controls
/// for those five; grounded in DISA XCCDF `U_RHEL_8_V2R4_STIG.zip`, 02 Jul 2025.
/// #549: Compression, formerly the sixth absent-vs-RHEL9 directive, was
/// dropped from RHEL9 too in V2R9, so it is no longer part of this
/// comparison at all.)
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

/// RHEL 10 V1R1 required directives (19 total, the same set as RHEL9 V2R9).
///
/// Compression was dropped from the RHEL 10 V1R1 STIG (not a controlled
/// directive in `U_RHEL_10_V1R1_STIG.zip`, benchmark 26 Feb 2026) -- RHEL9
/// V2R9 subsequently dropped it too (#549), so RHEL9 and RHEL10 now require
/// the identical 19-directive set.
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
    /// Numeric ceiling: value must parse as u64 and be <= the ceiling.
    NumericCeiling(u64),
    /// Numeric exact: must parse as u64 and equal the required value exactly.
    NumericExact(u64),
}

/// Return the W02 comparison rule for `keyword_lower`, or `None` when the
/// directive is not a W02-controlled value check for the given target.
///
/// Banner is a presence-only check (W01); it has no W02 rule.
/// Compression is not a W02 value check on any target as of RHEL9 V2R9 (#549:
/// DISA dropped the control entirely; it was never RHEL10-controlled either).
/// LogLevel is RHEL9/10 only.
/// Several yes/no directives are RHEL9/10 only.
fn w02_rule(keyword: &str, target: Option<TargetVersion>) -> Option<W02Rule> {
    let is_rhel9_or_10 = matches!(target, Some(TargetVersion::Rhel9 | TargetVersion::Rhel10));

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

        // ---- Compression: #549, DISA RHEL 9 STIG V2R9 dropped this control
        // (V-258002/RHEL-09-255130 removed); no target value-checks it.
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

// ---------------------------------------------------------------------------
// #501 typed control-ID backfill: per-target `(keyword, STIG Rule id)` maps.
//
// The Rule id (the DISA XCCDF `<version>`) is the canonical `ControlRef::id`;
// paired with the DISA V-number from `provenance_map` it builds the typed STIG
// control attached to every sshd-W01/W02 finding. This is a SECOND parallel map
// (not an extension of `RHEL*_VNUM`) so `provenance_map` keeps its `(keyword,
// v_number)` 2-tuple shape and the V-number stays single-sourced in `RHEL*_VNUM`.
//
// RHEL9 ids mirror the `//` comments on `RHEL9_REQUIRED`; RHEL8/RHEL10 ids are
// grounded in the DISA XCCDF (RHEL 8 V2R4 / RHEL 10 V1R1), cross-validated
// 0-drift against the shipped V-numbers. Each map's keyword set matches
// `required_set` for the target, so the W01 emit path (which iterates the
// required set) always resolves a control.
// ---------------------------------------------------------------------------

const RHEL8_RULE_ID: &[(&str, &str)] = &[
    ("banner", "RHEL-08-010040"),
    ("clientalivecountmax", "RHEL-08-010200"),
    ("clientaliveinterval", "RHEL-08-010201"),
    ("gssapiauthentication", "RHEL-08-010522"),
    ("ignoreuserknownhosts", "RHEL-08-010520"),
    ("kerberosauthentication", "RHEL-08-010521"),
    ("permitemptypasswords", "RHEL-08-020330"),
    ("permitrootlogin", "RHEL-08-010550"),
    ("permituserenvironment", "RHEL-08-010830"),
    ("printlastlog", "RHEL-08-020350"),
    ("rekeylimit", "RHEL-08-040161"),
    ("strictmodes", "RHEL-08-010500"),
    ("x11forwarding", "RHEL-08-040340"),
    ("x11uselocalhost", "RHEL-08-040341"),
];

const RHEL9_RULE_ID: &[(&str, &str)] = &[
    ("banner", "RHEL-09-255025"),
    ("clientalivecountmax", "RHEL-09-255095"),
    ("clientaliveinterval", "RHEL-09-255100"),
    ("gssapiauthentication", "RHEL-09-255135"),
    ("hostbasedauthentication", "RHEL-09-255080"),
    ("ignorerhosts", "RHEL-09-255145"),
    ("ignoreuserknownhosts", "RHEL-09-255150"),
    ("kerberosauthentication", "RHEL-09-255140"),
    ("loglevel", "RHEL-09-255030"),
    ("permitemptypasswords", "RHEL-09-255040"),
    ("permitrootlogin", "RHEL-09-255045"),
    ("permituserenvironment", "RHEL-09-255085"),
    ("printlastlog", "RHEL-09-255165"),
    ("pubkeyauthentication", "RHEL-09-255035"),
    ("rekeylimit", "RHEL-09-255090"),
    ("strictmodes", "RHEL-09-255160"),
    ("usepam", "RHEL-09-255050"),
    ("x11forwarding", "RHEL-09-255155"),
    ("x11uselocalhost", "RHEL-09-255175"),
];

const RHEL10_RULE_ID: &[(&str, &str)] = &[
    ("banner", "RHEL-10-700010"),
    ("clientalivecountmax", "RHEL-10-700660"),
    ("clientaliveinterval", "RHEL-10-700930"),
    ("gssapiauthentication", "RHEL-10-700510"),
    ("hostbasedauthentication", "RHEL-10-700630"),
    ("ignorerhosts", "RHEL-10-700530"),
    ("ignoreuserknownhosts", "RHEL-10-700540"),
    ("kerberosauthentication", "RHEL-10-700520"),
    ("loglevel", "RHEL-10-500215"),
    ("permitemptypasswords", "RHEL-10-700610"),
    ("permitrootlogin", "RHEL-10-700620"),
    ("permituserenvironment", "RHEL-10-700640"),
    ("printlastlog", "RHEL-10-700570"),
    ("pubkeyauthentication", "RHEL-10-700600"),
    ("rekeylimit", "RHEL-10-700650"),
    ("strictmodes", "RHEL-10-700560"),
    ("usepam", "RHEL-10-600640"),
    ("x11forwarding", "RHEL-10-700550"),
    ("x11uselocalhost", "RHEL-10-700580"),
];

/// The `(keyword, STIG Rule id)` map for a concrete target.
fn rule_id_map(target: TargetVersion) -> &'static [(&'static str, &'static str)] {
    match target {
        TargetVersion::Rhel8 => RHEL8_RULE_ID,
        TargetVersion::Rhel9 => RHEL9_RULE_ID,
        TargetVersion::Rhel10 => RHEL10_RULE_ID,
    }
}

/// Look up the value paired with `key` in a `(keyword, value)` table.
fn lookup(table: &[(&'static str, &'static str)], key: &str) -> Option<&'static str> {
    table.iter().find_map(|&(k, v)| (k == key).then_some(v))
}

/// Build the typed STIG [`ControlRef`] for `keyword_lower` on `target`: canonical
/// `id` = STIG Rule id, `alias` = DISA V-number.
///
/// `target=None` uses the conservative floor (RHEL 8), matching [`required_set`].
/// Returns `None` when the keyword has no STIG Rule id for the target, so the
/// emit sites attach a control only for a genuinely STIG-controlled directive and
/// never fabricate one. (The W01 emit path iterates `required_set`, so every W01
/// keyword resolves. #549: every W02-checked keyword is also within
/// `required_set` for the target it is checked under, so W02 resolves too --
/// Compression, the sole prior out-of-required-set W02 control, is no longer
/// checked at all as of RHEL9 V2R9.)
fn stig_control_ref(keyword_lower: &str, target: Option<TargetVersion>) -> Option<ControlRef> {
    let concrete = target.unwrap_or(TargetVersion::Rhel8);
    let rule_id = lookup(rule_id_map(concrete), keyword_lower)?;
    let v_number = lookup(provenance_map(concrete), keyword_lower)?;
    Some(ControlRef::new(Framework::Stig, rule_id).with_alias(v_number))
}

/// Build the combined control list for a W01/W02 finding: the existing STIG
/// [`ControlRef`] (never dropped) plus, for the ten STIG/CIS overlap keywords
/// (issue #525, v0.8 Wave 3), the [`Framework::Cis`] ref from [`cis::cis_control_ref`].
///
/// `Diagnostic::with_controls` REPLACES the `controls` Vec, so this builds the
/// COMBINED vec once here rather than each emit site calling `with_controls`
/// twice (which would drop the first ref).
fn combined_controls(keyword_lower: &str, target: Option<TargetVersion>) -> Vec<ControlRef> {
    let mut controls: Vec<ControlRef> = stig_control_ref(keyword_lower, target)
        .into_iter()
        .collect();
    controls.extend(cis::cis_control_ref(keyword_lower, target));
    controls
}

/// Look up the STIG Rule id (the DISA XCCDF `<Rule><version>`) for `keyword_lower`
/// on a concrete `target`, or `None` if the keyword has no Rule id for that target.
///
/// Read-only accessor over [`rule_id_map`], added for the `sshd-stig-update` drift
/// tool (issue #507): the tool's offline XCCDF parser derives the Rule id per
/// keyword and needs this to compare against the shipped `RHEL*_RULE_ID` maps,
/// closing the drift-protection gap those maps had after #501 (hand-authored from
/// the DISA XCCDF with no automated cross-check). ADDITIVE only: does not touch
/// [`StigControl`] or [`stig_baseline`]'s shape.
#[must_use]
pub fn rule_id_for(keyword_lower: &str, target: TargetVersion) -> Option<&'static str> {
    lookup(rule_id_map(target), keyword_lower)
}

/// Widen the private [`W02Rule`] into the public [`StigValueRule`]; `None`
/// (no W02 value rule) becomes `PresenceOnly`.
fn value_rule_of(rule: Option<W02Rule>) -> StigValueRule {
    match rule {
        None => StigValueRule::PresenceOnly,
        Some(W02Rule::ExactLower(s)) => StigValueRule::ExactLower(s),
        Some(W02Rule::TwoTokenExact(a, b)) => StigValueRule::TwoTokenExact(a, b),
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
/// # Per-target required sets (grounded in official DISA XCCDF, 2026-06-14;
/// RHEL9 count REFRESHED 2026-07-17 for issue #549, session 9e-wave2c
/// pipeline P2 -- `RHEL9_REQUIRED` below dropped Compression)
///
/// - RHEL 8 V2R4 (`U_RHEL_8_V2R4_STIG.zip`, 02 Jul 2025): 14 directives.
/// - RHEL 9 V2R9 (`U_RHEL_9_V2R9_STIG.zip`, confirmed 2026-07-17): 19
///   directives (was 20 under V2R7; DISA dropped Compression,
///   V-258002/RHEL-09-255130 removed -- lane3-tooling.md T1).
/// - RHEL 10 V1R1 (`U_RHEL_10_V1R1_STIG.zip`, 26 Feb 2026): 19 directives
///   (same set as RHEL9 V2R9; RHEL10 also never had Compression).
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
            diags.push(
                anchored(
                    Severity::Warning,
                    "sshd-W01",
                    0..0,
                    format!("STIG-required directive '{req}' is missing from the configuration"),
                    file,
                    0,
                )
                .with_controls(combined_controls(req, ctx.target)),
            );
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
            diags.push(
                anchored(
                    Severity::Warning,
                    "sshd-W02",
                    directive.span.clone(),
                    format!(
                        "directive '{}' has value '{displayed_value}'; STIG baseline requires {requirement}",
                        directive.keyword,
                    ),
                    file,
                    directive.line,
                )
                .with_controls(combined_controls(&keyword, ctx.target)),
            );
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
        // #549 RE-GROUNDED: was 20 (DISA RHEL 9 STIG V2R7). DISA RHEL 9 STIG
        // V2R9 (confirmed 2026-07-17 via U_RHEL_9_V2R9_STIG.zip;
        // lane3-tooling.md T1) dropped the Compression control (V-258002 /
        // RHEL-09-255130), leaving 19.
        assert_eq!(
            RHEL9_REQUIRED.len(),
            19,
            "RHEL9 V2R9 must have 19 required directives (Compression dropped)"
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
    fn compression_dropped_from_all_rhel_targets_v2r9() {
        // #549 RE-GROUNDED (was `compression_in_rhel9_only_among_floors`,
        // which asserted Compression WAS RHEL9-required). DISA RHEL 9 STIG
        // V2R9 (confirmed 2026-07-17 via U_RHEL_9_V2R9_STIG.zip) drops the
        // Compression control (V-258002 / RHEL-09-255130): the V2R9 XCCDF has
        // zero matches for "V-258002", and the sole case-insensitive
        // "compression" hit is an unrelated gzip fix-text example in a
        // different control (lane3-tooling.md T1 + its "Sanity check on the
        // 'compression removed' read" section). Cross-checked against the OLD
        // V2R7 pinned zip, which DOES show `compression // V-258002`,
        // confirming the control existed in V2R7 and is genuinely gone in
        // V2R9. Compression is no longer STIG-required on ANY target.
        assert!(
            !RHEL10_REQUIRED.contains(&"compression"),
            "Compression was dropped from RHEL10 V1R1"
        );
        assert!(
            !RHEL8_REQUIRED.contains(&"compression"),
            "Compression was never in RHEL8 V2R4 (no such STIG control)"
        );
        assert!(
            !RHEL9_REQUIRED.contains(&"compression"),
            "Compression was dropped from RHEL9 V2R9 (V-258002/RHEL-09-255130 removed)"
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
        // #549 RE-GROUNDED: RHEL9 was 20 (V2R7); V2R9 drops Compression,
        // leaving 19 (same size as RHEL10, which dropped it in V1R1).
        assert_eq!(stig_baseline(TargetVersion::Rhel8).len(), 14);
        assert_eq!(stig_baseline(TargetVersion::Rhel9).len(), 19);
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
        // #549 RE-GROUNDED: the AnyOf(delayed/no) spot-check previously lived
        // here as `get("compression").value_rule`. DISA RHEL 9 STIG V2R9
        // drops Compression (V-258002/RHEL-09-255130 removed; see
        // `compression_dropped_from_all_rhel_targets_v2r9`), so `compression`
        // is no longer a key in `by_kw` at all -- `get("compression")` would
        // now panic (its `unwrap_or_else` fires "missing compression").
        // `AnyOf` was Compression's only consumer in `w02_rule`; no other
        // required directive uses it, so there is currently no other AnyOf
        // representative to substitute here.
        //
        // #549 (adversarial-review finding 5, no-speculative-abstraction
        // project rule): `W02Rule::AnyOf` and `StigValueRule::AnyOf` (plus
        // its `value_rule_of` mapping arm) were DELETED, not kept "for
        // future use", once the `"compression"` arm was removed from
        // `w02_rule` -- compression was their only constructor, and no
        // other STIG control in any current target uses a
        // multi-value-accepted rule. If one is added later, re-add the
        // variant then, grounded in that control's real check-content.
    }

    /// Compression is dropped from RHEL10, so its projection must NOT include it,
    /// and RHEL8 (floor) also excludes it (matches the required-set tables).
    #[test]
    fn stig_baseline_compression_absent_from_all_targets_v2r9() {
        // #549 RE-GROUNDED (was `stig_baseline_compression_only_rhel9`, which
        // asserted RHEL9's projection DID include Compression). DISA RHEL 9
        // STIG V2R9 drops the control (see
        // `compression_dropped_from_all_rhel_targets_v2r9`), so the
        // projection must now omit Compression from ALL three targets.
        assert!(
            !stig_baseline(TargetVersion::Rhel9)
                .iter()
                .any(|c| c.keyword == "compression"),
            "Compression dropped from RHEL9 V2R9 (V-258002/RHEL-09-255130 removed)"
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
        //   CIS id   5.1.8 -- `derive-rhel9-sshd.txt`
        //            (`5.1.8 ... sshd_enable_warning_banner_net ... "Ensure sshd
        //            Banner is configured (Automated)"`); issue #525 (v0.8 Wave 3).
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

        // RED anchor: length first, so RED is a clean `0 != 2`, not an index panic.
        // #525: banner is a STIG/CIS overlap keyword on every target, so the
        // finding must carry BOTH -- the existing Stig ref is never dropped, and
        // exactly one new Cis ref is added (no duplicate).
        assert_eq!(
            banner.controls.len(),
            2,
            "W01 finding must carry the STIG control AND a CIS control (#525); got {:?}",
            banner.controls
        );
        let stig = banner
            .controls
            .iter()
            .find(|c| c.framework == Framework::Stig)
            .expect("existing Stig control must not be dropped");
        assert_eq!(stig.id, "RHEL-09-255025");
        assert_eq!(stig.alias, Some("V-257981".to_string()));
        let cis = banner
            .controls
            .iter()
            .find(|c| c.framework == Framework::Cis)
            .expect("a Cis control must be attached");
        assert_eq!(cis.id, "5.1.8");
        assert_eq!(
            cis.name,
            Some("Ensure sshd Banner is configured (Automated)".to_string()),
            "the CaC title must surface via ControlRef::name"
        );
    }

    #[test]
    fn w02_weak_value_findings_carry_typed_stig_control() {
        // Representative: `PermitRootLogin yes` on target=Rhel9 (STIG requires `no`).
        //   Rule id  RHEL-09-255045 -- RHEL9_REQUIRED comment:
        //            `"permitrootlogin", // RHEL-09-255045 V-257985` (this file).
        //   V-number V-257985       -- RHEL9_VNUM entry `("permitrootlogin", "V-257985")`.
        //   CIS id   5.1.20 -- `derive-rhel9-sshd.txt`
        //            (`5.1.20 ... sshd_disable_root_login ... "Ensure sshd
        //            PermitRootLogin is disabled (Automated)"`); issue #525.
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

        // RED anchor: length first. #525: permitrootlogin is a STIG/CIS overlap
        // keyword on every target -- both refs must be present, never a dropped
        // Stig ref or a duplicated Cis ref.
        assert_eq!(
            prl.controls.len(),
            2,
            "W02 finding must carry the STIG control AND a CIS control (#525); got {:?}",
            prl.controls
        );
        let stig = prl
            .controls
            .iter()
            .find(|c| c.framework == Framework::Stig)
            .expect("existing Stig control must not be dropped");
        assert_eq!(stig.id, "RHEL-09-255045");
        assert_eq!(stig.alias, Some("V-257985".to_string()));
        let cis = prl
            .controls
            .iter()
            .find(|c| c.framework == Framework::Cis)
            .expect("a Cis control must be attached");
        assert_eq!(cis.id, "5.1.20");
        assert_eq!(
            cis.name,
            Some("Ensure sshd PermitRootLogin is disabled (Automated)".to_string()),
            "the CaC title must surface via ControlRef::name"
        );
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
    /// the finding must carry the STIG `ControlRef` (`id` = Rule id, `alias` =
    /// V-number) AND a CIS `ControlRef` (`id` = CIS control id, `name` = CaC
    /// title) -- banner is a STIG/CIS overlap keyword on EVERY target (#525) --
    /// and keep its message byte-identical.
    fn assert_w01_banner_control(
        target: TargetVersion,
        expect_id: &str,
        expect_vnum: &str,
        expect_cis_id: &str,
    ) {
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
            2,
            "W01 finding must carry the STIG control AND a CIS control ({target:?}, #525); got {:?}",
            banner.controls
        );
        let stig = banner
            .controls
            .iter()
            .find(|c| c.framework == Framework::Stig)
            .expect("existing Stig control must not be dropped");
        assert_eq!(stig.id, expect_id);
        assert_eq!(stig.alias, Some(expect_vnum.to_string()));
        let cis = banner
            .controls
            .iter()
            .find(|c| c.framework == Framework::Cis)
            .expect("a Cis control must be attached");
        assert_eq!(cis.id, expect_cis_id, "CIS control id ({target:?})");
        assert_eq!(
            cis.name,
            Some("Ensure sshd Banner is configured (Automated)".to_string()),
            "the CaC title must surface via ControlRef::name ({target:?})"
        );
    }

    /// Shared W02 assertion: `PermitRootLogin yes` on `target` is a weak-value
    /// finding (STIG requires `no`) that must carry the STIG `ControlRef` (`id` =
    /// Rule id, `alias` = V-number) AND a CIS `ControlRef` (`id` = CIS control
    /// id, `name` = CaC title) -- permitrootlogin is a STIG/CIS overlap keyword on
    /// EVERY target (#525) -- and keep its message byte-identical.
    fn assert_w02_permitrootlogin_control(
        target: TargetVersion,
        expect_id: &str,
        expect_vnum: &str,
        expect_cis_id: &str,
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
            2,
            "W02 finding must carry the STIG control AND a CIS control ({target:?}, #525); got {:?}",
            prl.controls
        );
        let stig = prl
            .controls
            .iter()
            .find(|c| c.framework == Framework::Stig)
            .expect("existing Stig control must not be dropped");
        assert_eq!(stig.id, expect_id);
        assert_eq!(stig.alias, Some(expect_vnum.to_string()));
        let cis = prl
            .controls
            .iter()
            .find(|c| c.framework == Framework::Cis)
            .expect("a Cis control must be attached");
        assert_eq!(cis.id, expect_cis_id, "CIS control id ({target:?})");
        assert_eq!(
            cis.name,
            Some("Ensure sshd PermitRootLogin is disabled (Automated)".to_string()),
            "the CaC title must surface via ControlRef::name ({target:?})"
        );
    }

    #[test]
    fn w01_missing_findings_carry_typed_stig_control_rhel8() {
        // banner on Rhel8: Rule id RHEL-08-010040 (DISA XCCDF RHEL8 V2R4),
        // V-number V-230225 (this file's RHEL8_VNUM `("banner", "V-230225")`).
        // CIS id 5.1.7 (derive-rhel8-sshd.txt, #525).
        assert_w01_banner_control(TargetVersion::Rhel8, "RHEL-08-010040", "V-230225", "5.1.7");
    }

    #[test]
    fn w02_weak_value_findings_carry_typed_stig_control_rhel8() {
        // PermitRootLogin on Rhel8: Rule id RHEL-08-010550 (DISA XCCDF RHEL8 V2R4),
        // V-number V-230296 (this file's RHEL8_VNUM `("permitrootlogin", "V-230296")`).
        // CIS id 5.1.22 (derive-rhel8-sshd.txt, #525).
        assert_w02_permitrootlogin_control(
            TargetVersion::Rhel8,
            "RHEL-08-010550",
            "V-230296",
            "5.1.22",
        );
    }

    #[test]
    fn w01_missing_findings_carry_typed_stig_control_rhel10() {
        // banner on Rhel10: Rule id RHEL-10-700010 (DISA XCCDF RHEL10 V1R1),
        // V-number V-281224 (this file's RHEL10_VNUM `("banner", "V-281224")`).
        // CIS id 5.1.5 (derive-rhel10-sshd.txt, #525).
        assert_w01_banner_control(TargetVersion::Rhel10, "RHEL-10-700010", "V-281224", "5.1.5");
    }

    #[test]
    fn w02_weak_value_findings_carry_typed_stig_control_rhel10() {
        // PermitRootLogin on Rhel10: Rule id RHEL-10-700620 (DISA XCCDF RHEL10 V1R1),
        // V-number V-281265 (this file's RHEL10_VNUM `("permitrootlogin", "V-281265")`).
        // CIS id 5.1.20 (derive-rhel10-sshd.txt, #525).
        assert_w02_permitrootlogin_control(
            TargetVersion::Rhel10,
            "RHEL-10-700620",
            "V-281265",
            "5.1.20",
        );
    }

    // --- #501 backfill: full-coverage completeness (locks the user's decision to
    //     source ALL three targets, so a two-keyword-hardcoded impl is wrong) ---
    // Feed a config missing EVERY required directive for the target: W01 fires once
    // per required directive, and each finding must carry a Stig control whose id
    // uses that target's Rule-id prefix. This forces the emit path to attach a
    // control to ALL required keywords, not just the `banner`/`permitrootlogin`
    // pair pinned by value above. We do not pin each exact id here (the by-value
    // tests do that for the representatives); count + non-empty + framework + prefix
    // is what rules out a partial impl.

    /// Shared completeness assertion (see the block comment above).
    ///
    /// #525 extension: every W01 finding must still carry exactly one STIG
    /// control (never dropped), but exactly `expect_cis_overlap` of them ALSO
    /// carry exactly one CIS control (never duplicated) -- the STIG/CIS overlap
    /// keywords for `target` (banner, clientaliveinterval, clientalivecountmax,
    /// gssapiauthentication, permitemptypasswords, permitrootlogin,
    /// permituserenvironment on every target; plus ignorerhosts, loglevel, usepam
    /// on RHEL9/RHEL10 only). Every other required directive
    /// (ignoreuserknownhosts, kerberosauthentication, printlastlog, rekeylimit,
    /// strictmodes, x11forwarding, x11uselocalhost, hostbasedauthentication,
    /// pubkeyauthentication) has no CIS control in the sshd table and must carry
    /// no Cis ref at all.
    fn assert_w01_completeness(target: TargetVersion, id_prefix: &str, expect_cis_overlap: usize) {
        use rulesteward_core::Framework;
        let ctx = SshdLintContext {
            target: Some(target),
            single_file: true,
        };
        // An empty config makes every required directive for this target missing.
        let blocks = parse("");
        let diags = w01(&blocks, Path::new("/etc/ssh/sshd_config"), &ctx);

        let expected = required_set(Some(target)).len();
        assert!(
            expected > 2,
            "sanity: the completeness check must span more than the 2 value-pinned \
             keywords ({target:?})"
        );
        assert_eq!(
            diags.len(),
            expected,
            "W01 must fire once per required directive on an empty config ({target:?})"
        );
        let mut cis_count = 0usize;
        for d in &diags {
            assert_eq!(d.code, "sshd-W01");
            let stig_controls: Vec<_> = d
                .controls
                .iter()
                .filter(|c| c.framework == Framework::Stig)
                .collect();
            assert_eq!(
                stig_controls.len(),
                1,
                "every W01 finding must carry exactly one STIG control ({target:?}); \
                 offender: {}",
                d.message
            );
            assert!(
                stig_controls[0].id.starts_with(id_prefix),
                "W01 control id {:?} must start with {id_prefix:?} ({target:?})",
                stig_controls[0].id
            );
            let cis_controls: Vec<_> = d
                .controls
                .iter()
                .filter(|c| c.framework == Framework::Cis)
                .collect();
            assert!(
                cis_controls.len() <= 1,
                "no duplicate CIS ref ({target:?}); offender: {}",
                d.message
            );
            if let [cis] = cis_controls[..] {
                cis_count += 1;
                assert!(!cis.id.is_empty(), "CIS control id must be non-empty");
                assert!(
                    cis.name.as_deref().is_some_and(|n| !n.is_empty()),
                    "CIS ref must carry a title via with_name; offender: {}",
                    d.message
                );
            }
            assert_eq!(
                d.controls.len(),
                stig_controls.len() + cis_controls.len(),
                "no controls beyond Stig+Cis ({target:?}); offender: {}",
                d.message
            );
        }
        assert_eq!(
            cis_count, expect_cis_overlap,
            "exactly the STIG/CIS overlap keywords must gain a Cis ref ({target:?})"
        );
    }

    #[test]
    fn w01_completeness_all_required_carry_stig_control_rhel8() {
        // RHEL8 V2R4: 14 required directives, every id under the `RHEL-08-` prefix.
        // #525: 7 of them overlap a CIS control (banner, clientaliveinterval,
        // clientalivecountmax, gssapiauthentication, permitemptypasswords,
        // permitrootlogin, permituserenvironment) -- ignorerhosts/loglevel/usepam
        // are not RHEL8-required by STIG, so RHEL8 has no attach site for them.
        assert_w01_completeness(TargetVersion::Rhel8, "RHEL-08-", 7);
    }

    #[test]
    fn w01_completeness_all_required_carry_stig_control_rhel9() {
        // #549 REFRESHED: RHEL9 V2R9: 19 required directives (was 20 under
        // V2R7; Compression dropped), every id under the `RHEL-09-` prefix.
        // This assertion itself is unaffected either way (it reads
        // `required_set(Some(target)).len()` dynamically, not a hardcoded
        // count) -- only the comment was stale.
        // #525: 10 overlap a CIS control (the RHEL8 7 plus ignorerhosts, loglevel,
        // usepam, which STIG requires starting at RHEL9).
        assert_w01_completeness(TargetVersion::Rhel9, "RHEL-09-", 10);
    }

    #[test]
    fn w01_completeness_all_required_carry_stig_control_rhel10() {
        // RHEL10 V1R1: 19 required directives, every id under the `RHEL-10-` prefix.
        // #525: 10 overlap a CIS control (same set as RHEL9).
        assert_w01_completeness(TargetVersion::Rhel10, "RHEL-10-", 10);
    }

    // --- #507 drift-tool `rule_id_for` accessor ------------------------------
    // The `sshd-stig-update` tool needs a read-only way to project the Rule id
    // (the DISA XCCDF `<version>`) per keyword+target, so it can compare it
    // against the XCCDF-derived value and guard the RHEL*_RULE_ID maps that #501
    // hand-authored with zero drift protection. This is a thin lookup over the
    // existing `rule_id_map`, spot-checked here across all three targets plus
    // the not-found case.

    #[test]
    fn rule_id_for_matches_shipped_rule_id_map() {
        assert_eq!(
            rule_id_for("banner", TargetVersion::Rhel9),
            Some("RHEL-09-255025")
        );
        assert_eq!(
            rule_id_for("banner", TargetVersion::Rhel8),
            Some("RHEL-08-010040")
        );
        assert_eq!(
            rule_id_for("banner", TargetVersion::Rhel10),
            Some("RHEL-10-700010")
        );
    }

    #[test]
    fn rule_id_for_none_for_unknown_keyword() {
        assert_eq!(
            rule_id_for("not_a_real_directive", TargetVersion::Rhel9),
            None
        );
    }
}
