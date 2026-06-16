//! sshd-W01 and sshd-W02 integration tests.
// The module-level doc lists many sshd_config keyword names (PubkeyAuthentication,
// IgnoreRhosts, etc.) as plain prose; allowing doc_markdown here avoids cluttering
// the doc with backticks on every keyword name.
#![allow(clippy::doc_markdown)]
//!
//! # Grounding (DISA XCCDF, fetched 2026-06-14; live VMs 2026-06-15)
//!
//! sshd-W01: a STIG-required directive is absent from the global block.
//!   - RHEL 9 V2R7: 20 required directives (V-257981..V-258011 SSH set).
//!   - RHEL 8 V2R4: 14 required directives (the 20 minus LogLevel, PubkeyAuthentication,
//!     UsePAM, IgnoreRhosts, HostbasedAuthentication, Compression).
//!   - RHEL 10 V1R1: 19 required directives (the 20 minus Compression).
//!   - target=None fires on the CONSERVATIVE FLOOR = the intersection of all
//!     supported versions = the 14 from the RHEL 8 set. Every floor directive is
//!     required by every supported version, so zero false positives.
//!   - MaxAuthTries and LoginGraceTime are CIS / general-hardening controls, NOT in
//!     any DISA STIG XCCDF SSH directive set. W01 MUST NOT fire for their absence.
//!
//! sshd-W02: a present directive's value is weaker than the STIG baseline.
//!   - ClientAliveInterval: `<= 600` (numeric ceiling; value > 600 is a finding).
//!   - ClientAliveCountMax: exact `1` (BOTH 0 AND > 1 are findings - not a range).
//!   - RekeyLimit: exact two-token `1G 1h`.
//!   - PermitRootLogin: exact `no` (`prohibit-password` IS a finding).
//!   - yes/no controls (PermitEmptyPasswords, UsePAM, HostbasedAuthentication,
//!     IgnoreRhosts, X11Forwarding, StrictModes, GSSAPIAuthentication,
//!     KerberosAuthentication, PubkeyAuthentication, IgnoreUserKnownHosts,
//!     PrintLastLog, X11UseLocalhost): exact literal match.
//!   - Compression: `delayed` or `no` are OK; anything else is a finding (RHEL 8/9
//!     only - RHEL 10 dropped this control).
//!   - LogLevel: exact `VERBOSE` (RHEL 9/10 only).
//!   - SCOPE GUARD: W02 evaluates the single-file value only. Cross-file / drop-in
//!     precedence (first-value-wins across sshd_config.d/) is F02/Wave C.

use std::path::Path;

use rulesteward_core::Diagnostic;
use rulesteward_sshd::lints::stig::{w01, w02};
use rulesteward_sshd::lints::{SshdLintContext, TargetVersion};
use rulesteward_sshd::parser::parse_config_str_located;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const FAKE_FILE: &str = "/etc/ssh/sshd_config";

fn parse(src: &str) -> Vec<rulesteward_sshd::ast::Block> {
    parse_config_str_located(src, Path::new(FAKE_FILE)).expect("fixture parses")
}

fn ctx(target: Option<TargetVersion>) -> SshdLintContext {
    SshdLintContext {
        target,
        single_file: true,
    }
}

fn run_w01(src: &str, target: Option<TargetVersion>) -> Vec<Diagnostic> {
    w01(&parse(src), Path::new(FAKE_FILE), &ctx(target))
}

fn run_w02(src: &str, target: Option<TargetVersion>) -> Vec<Diagnostic> {
    w02(&parse(src), Path::new(FAKE_FILE), &ctx(target))
}

fn codes(diags: &[Diagnostic]) -> Vec<&str> {
    diags.iter().map(|d| d.code.as_ref()).collect()
}

// ---------------------------------------------------------------------------
// W01: a config containing ALL required directives => zero findings
// ---------------------------------------------------------------------------

/// RHEL 9 V2R7 complete set (20 directives) - one finding per MISSING required
/// directive means supplying ALL of them must yield zero findings.
const RHEL9_FULL: &str = "\
Banner /etc/issue\n\
LogLevel VERBOSE\n\
PubkeyAuthentication yes\n\
PermitEmptyPasswords no\n\
PermitRootLogin no\n\
UsePAM yes\n\
HostbasedAuthentication no\n\
PermitUserEnvironment no\n\
RekeyLimit 1G 1h\n\
ClientAliveCountMax 1\n\
ClientAliveInterval 300\n\
Compression delayed\n\
GSSAPIAuthentication no\n\
KerberosAuthentication no\n\
IgnoreRhosts yes\n\
IgnoreUserKnownHosts yes\n\
X11Forwarding no\n\
StrictModes yes\n\
PrintLastLog yes\n\
X11UseLocalhost yes\n";

/// RHEL 8 V2R4 complete set (14 directives).
const RHEL8_FULL: &str = "\
Banner /etc/issue\n\
PermitEmptyPasswords no\n\
PermitRootLogin no\n\
PermitUserEnvironment no\n\
RekeyLimit 1G 1h\n\
ClientAliveCountMax 1\n\
ClientAliveInterval 300\n\
KerberosAuthentication no\n\
GSSAPIAuthentication no\n\
StrictModes yes\n\
IgnoreUserKnownHosts yes\n\
PrintLastLog yes\n\
X11Forwarding no\n\
X11UseLocalhost yes\n";

/// RHEL 10 V1R1 complete set (19 directives = RHEL9 minus Compression).
const RHEL10_FULL: &str = "\
Banner /etc/issue\n\
LogLevel VERBOSE\n\
PubkeyAuthentication yes\n\
PermitEmptyPasswords no\n\
PermitRootLogin no\n\
UsePAM yes\n\
HostbasedAuthentication no\n\
PermitUserEnvironment no\n\
RekeyLimit 1G 1h\n\
ClientAliveCountMax 1\n\
ClientAliveInterval 300\n\
GSSAPIAuthentication no\n\
KerberosAuthentication no\n\
IgnoreRhosts yes\n\
IgnoreUserKnownHosts yes\n\
X11Forwarding no\n\
StrictModes yes\n\
PrintLastLog yes\n\
X11UseLocalhost yes\n";

#[test]
fn w01_rhel9_all_required_directives_present_is_clean() {
    let diags = run_w01(RHEL9_FULL, Some(TargetVersion::Rhel9));
    assert!(
        diags.iter().all(|d| d.code != "sshd-W01"),
        "all RHEL9 required directives present => no W01 findings; got {diags:?}"
    );
}

#[test]
fn w01_rhel8_all_required_directives_present_is_clean() {
    let diags = run_w01(RHEL8_FULL, Some(TargetVersion::Rhel8));
    assert!(
        diags.iter().all(|d| d.code != "sshd-W01"),
        "all RHEL8 required directives present => no W01 findings; got {diags:?}"
    );
}

#[test]
fn w01_rhel10_all_required_directives_present_is_clean() {
    let diags = run_w01(RHEL10_FULL, Some(TargetVersion::Rhel10));
    assert!(
        diags.iter().all(|d| d.code != "sshd-W01"),
        "all RHEL10 required directives present => no W01 findings; got {diags:?}"
    );
}

// ---------------------------------------------------------------------------
// W01: missing a floor directive fires regardless of target
// ---------------------------------------------------------------------------

/// Banner is in the RHEL8 floor set (V-230225). Missing it MUST fire at every
/// target including None.
#[test]
fn w01_banner_missing_fires_at_every_target() {
    // A config with all 20 RHEL9 directives EXCEPT Banner.
    let src = RHEL9_FULL.replace("Banner /etc/issue\n", "");
    for target in [
        Some(TargetVersion::Rhel8),
        Some(TargetVersion::Rhel9),
        Some(TargetVersion::Rhel10),
        None,
    ] {
        let diags = run_w01(&src, target);
        let w01_diags: Vec<_> = diags.iter().filter(|d| d.code == "sshd-W01").collect();
        assert!(
            !w01_diags.is_empty(),
            "Banner is floor-required; missing it must fire W01 for {target:?}"
        );
    }
}

/// PermitRootLogin is in the floor set (V-230296 / V-257985 / V-281265).
#[test]
fn w01_permitrootlogin_missing_fires_at_every_target() {
    let src = RHEL9_FULL.replace("PermitRootLogin no\n", "");
    for target in [
        Some(TargetVersion::Rhel8),
        Some(TargetVersion::Rhel9),
        Some(TargetVersion::Rhel10),
        None,
    ] {
        let diags = run_w01(&src, target);
        let w01_diags: Vec<_> = diags.iter().filter(|d| d.code == "sshd-W01").collect();
        assert!(
            !w01_diags.is_empty(),
            "PermitRootLogin is floor-required; missing it must fire W01 for {target:?}"
        );
    }
}

/// ClientAliveCountMax is in the floor set (V-230244 / V-257995 / V-281269).
#[test]
fn w01_clientalivecountmax_missing_fires_at_every_target() {
    let src = RHEL9_FULL.replace("ClientAliveCountMax 1\n", "");
    for target in [
        Some(TargetVersion::Rhel8),
        Some(TargetVersion::Rhel9),
        Some(TargetVersion::Rhel10),
        None,
    ] {
        let diags = run_w01(&src, target);
        let w01_diags: Vec<_> = diags.iter().filter(|d| d.code == "sshd-W01").collect();
        assert!(
            !w01_diags.is_empty(),
            "ClientAliveCountMax is floor-required; missing it must fire W01 for {target:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// W01: RHEL9-only directive: fires for Rhel9 but NOT for None
// ---------------------------------------------------------------------------

/// LogLevel is a RHEL9 V2R7 required directive (V-257982) but is absent from the
/// RHEL8 V2R4 set. target=None uses the conservative floor (RHEL8 set), so a
/// missing LogLevel must NOT produce a W01 finding under None.
#[test]
fn w01_loglevel_fires_for_rhel9_not_for_none() {
    // config has all RHEL9 directives except LogLevel
    let src = RHEL9_FULL.replace("LogLevel VERBOSE\n", "");

    // Must fire for Rhel9 (it is in the RHEL9 required set)
    let rhel9_diags = run_w01(&src, Some(TargetVersion::Rhel9));
    let rhel9_w01: Vec<_> = rhel9_diags
        .iter()
        .filter(|d| d.code == "sshd-W01")
        .collect();
    assert!(
        !rhel9_w01.is_empty(),
        "LogLevel is RHEL9-required (V-257982); missing it must fire W01 for Rhel9"
    );

    // Must NOT fire for None (floor is RHEL8 set, which does not require LogLevel)
    let none_diags = run_w01(&src, None);
    let none_w01: Vec<_> = none_diags.iter().filter(|d| d.code == "sshd-W01").collect();
    assert!(
        none_w01.is_empty(),
        "LogLevel is NOT in the RHEL8 floor set; missing it must NOT fire W01 for target=None; got {none_w01:?}"
    );
}

/// PubkeyAuthentication is RHEL9/10 required (V-257983/V-281263) but NOT RHEL8.
#[test]
fn w01_pubkeyauthentication_fires_for_rhel9_not_for_none() {
    let src = RHEL9_FULL.replace("PubkeyAuthentication yes\n", "");

    let rhel9_diags = run_w01(&src, Some(TargetVersion::Rhel9));
    let rhel9_w01: Vec<_> = rhel9_diags
        .iter()
        .filter(|d| d.code == "sshd-W01")
        .collect();
    assert!(
        !rhel9_w01.is_empty(),
        "PubkeyAuthentication is RHEL9-required (V-257983); must fire W01"
    );

    let none_diags = run_w01(&src, None);
    let none_w01: Vec<_> = none_diags.iter().filter(|d| d.code == "sshd-W01").collect();
    assert!(
        none_w01.is_empty(),
        "PubkeyAuthentication is NOT in the RHEL8 floor set; must NOT fire W01 for target=None; got {none_w01:?}"
    );
}

/// UsePAM is RHEL9/10 required (V-257986/V-281216) but NOT RHEL8.
#[test]
fn w01_usepam_fires_for_rhel9_not_for_none() {
    let src = RHEL9_FULL.replace("UsePAM yes\n", "");

    let rhel9_diags = run_w01(&src, Some(TargetVersion::Rhel9));
    assert!(
        rhel9_diags.iter().any(|d| d.code == "sshd-W01"),
        "UsePAM is RHEL9-required (V-257986); missing it must fire W01"
    );

    let none_diags = run_w01(&src, None);
    assert!(
        !none_diags.iter().any(|d| d.code == "sshd-W01"),
        "UsePAM is NOT in the RHEL8 floor set; must NOT fire W01 for target=None"
    );
}

/// Compression is RHEL9 required (V-258002) but NOT RHEL8 and NOT RHEL10.
#[test]
fn w01_compression_fires_for_rhel9_not_for_rhel8_or_none() {
    let src = RHEL9_FULL.replace("Compression delayed\n", "");

    // Must fire for Rhel9
    let rhel9_diags = run_w01(&src, Some(TargetVersion::Rhel9));
    assert!(
        rhel9_diags.iter().any(|d| d.code == "sshd-W01"),
        "Compression is RHEL9-required (V-258002); missing it must fire W01"
    );

    // Must NOT fire for Rhel8 (not in RHEL8 required set)
    let rhel8_diags = run_w01(&src, Some(TargetVersion::Rhel8));
    assert!(
        !rhel8_diags.iter().any(|d| d.code == "sshd-W01"),
        "Compression is NOT RHEL8-required; must NOT fire W01 for Rhel8"
    );

    // Must NOT fire for Rhel10 (V1R1 dropped this control)
    let rhel10_diags = run_w01(&src, Some(TargetVersion::Rhel10));
    assert!(
        !rhel10_diags.iter().any(|d| d.code == "sshd-W01"),
        "Compression was DROPPED from RHEL10 V1R1; must NOT fire W01 for Rhel10"
    );

    // Must NOT fire for None (not in floor set)
    let none_diags = run_w01(&src, None);
    assert!(
        !none_diags.iter().any(|d| d.code == "sshd-W01"),
        "Compression is NOT in the RHEL8 floor set; must NOT fire W01 for target=None"
    );
}

// ---------------------------------------------------------------------------
// W01: one finding per missing required directive (count check)
// ---------------------------------------------------------------------------

/// An empty config must fire one W01 per required directive for the target.
/// RHEL9 requires 20 directives; an empty file should produce exactly 20 W01.
#[test]
fn w01_rhel9_empty_config_fires_20_findings() {
    let diags = run_w01("", Some(TargetVersion::Rhel9));
    let count = diags.iter().filter(|d| d.code == "sshd-W01").count();
    assert_eq!(
        count, 20,
        "RHEL9 requires 20 directives; an empty config must produce exactly 20 W01 findings; got {count}"
    );
}

/// RHEL8 requires 14 directives.
#[test]
fn w01_rhel8_empty_config_fires_14_findings() {
    let diags = run_w01("", Some(TargetVersion::Rhel8));
    let count = diags.iter().filter(|d| d.code == "sshd-W01").count();
    assert_eq!(
        count, 14,
        "RHEL8 requires 14 directives; an empty config must produce exactly 14 W01 findings; got {count}"
    );
}

/// RHEL10 requires 19 directives (RHEL9 minus Compression).
#[test]
fn w01_rhel10_empty_config_fires_19_findings() {
    let diags = run_w01("", Some(TargetVersion::Rhel10));
    let count = diags.iter().filter(|d| d.code == "sshd-W01").count();
    assert_eq!(
        count, 19,
        "RHEL10 requires 19 directives; an empty config must produce exactly 19 W01 findings; got {count}"
    );
}

/// target=None uses the floor (14 directives from the RHEL8 set).
#[test]
fn w01_target_none_empty_config_fires_14_findings() {
    let diags = run_w01("", None);
    let count = diags.iter().filter(|d| d.code == "sshd-W01").count();
    assert_eq!(
        count, 14,
        "target=None uses the 14-directive RHEL8 floor; an empty config must produce exactly 14 W01 findings; got {count}"
    );
}

// ---------------------------------------------------------------------------
// W01: CRITICAL NEGATIVE ASSERTIONS - MaxAuthTries and LoginGraceTime
// These are CIS / general-hardening, NOT DISA STIG - W01 must NEVER flag their absence.
// ---------------------------------------------------------------------------

/// MaxAuthTries is a CIS control, NOT a DISA STIG RHEL sshd_config control
/// (absent from RHEL 8 V2R4 / 9 V2R7 / 10 V1R1 XCCDF SSH directive sets).
/// W01 MUST NEVER fire for its absence at any target.
#[test]
fn w01_never_fires_for_missing_maxauthtries_at_any_target() {
    // A config with ALL RHEL9 required directives but no MaxAuthTries.
    // (MaxAuthTries is deliberately absent; the full required set is present.)
    let src = RHEL9_FULL; // MaxAuthTries never in RHEL9_FULL
    for target in [
        Some(TargetVersion::Rhel8),
        Some(TargetVersion::Rhel9),
        Some(TargetVersion::Rhel10),
        None,
    ] {
        let diags = run_w01(src, target);
        let firing_for_maxauthtries = diags.iter().any(|d| {
            d.code == "sshd-W01" && d.message.to_ascii_lowercase().contains("maxauthtries")
        });
        assert!(
            !firing_for_maxauthtries,
            "MaxAuthTries is CIS, NOT DISA STIG; W01 must NEVER flag its absence for {target:?}"
        );
    }
}

/// LoginGraceTime is a CIS control, NOT a DISA STIG RHEL sshd_config control.
#[test]
fn w01_never_fires_for_missing_logingracetime_at_any_target() {
    let src = RHEL9_FULL; // LoginGraceTime never in RHEL9_FULL
    for target in [
        Some(TargetVersion::Rhel8),
        Some(TargetVersion::Rhel9),
        Some(TargetVersion::Rhel10),
        None,
    ] {
        let diags = run_w01(src, target);
        let firing_for_logingracetime = diags.iter().any(|d| {
            d.code == "sshd-W01" && d.message.to_ascii_lowercase().contains("logingracetime")
        });
        assert!(
            !firing_for_logingracetime,
            "LoginGraceTime is CIS, NOT DISA STIG; W01 must NEVER flag its absence for {target:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// W01: diagnostics carry severity Warning and code sshd-W01
// ---------------------------------------------------------------------------

#[test]
fn w01_diagnostic_fields_are_correct() {
    // Missing Banner - simplest floor directive to trigger.
    let diags = run_w01("", Some(TargetVersion::Rhel9));
    let w01_diags: Vec<_> = diags.iter().filter(|d| d.code == "sshd-W01").collect();
    assert!(!w01_diags.is_empty(), "W01 must fire for an empty config");
    for d in &w01_diags {
        assert_eq!(
            d.severity,
            rulesteward_core::Severity::Warning,
            "W01 must have Warning severity"
        );
        assert_eq!(d.code, "sshd-W01");
        // The message must name the directive that is missing.
        assert!(
            !d.message.is_empty(),
            "W01 diagnostic must include a message naming the missing directive"
        );
    }
}

// ---------------------------------------------------------------------------
// W02: ClientAliveInterval
// ---------------------------------------------------------------------------

/// Value 600 is the STIG ceiling (exactly at the limit) -> clean.
#[test]
fn w02_clientaliveinterval_600_is_clean() {
    assert!(
        run_w02("ClientAliveInterval 600\n", Some(TargetVersion::Rhel9)).is_empty(),
        "ClientAliveInterval 600 is exactly the STIG ceiling: no W02"
    );
}

/// Value <= 600 is clean for all targets.
#[test]
fn w02_clientaliveinterval_300_is_clean() {
    for target in [
        Some(TargetVersion::Rhel8),
        Some(TargetVersion::Rhel9),
        Some(TargetVersion::Rhel10),
        None,
    ] {
        assert!(
            run_w02("ClientAliveInterval 300\n", target).is_empty(),
            "ClientAliveInterval 300 is within the <= 600 ceiling: no W02 for {target:?}"
        );
    }
}

/// Value > 600 is a finding (sshd-W02).
#[test]
fn w02_clientaliveinterval_601_fires() {
    let diags = run_w02("ClientAliveInterval 601\n", Some(TargetVersion::Rhel9));
    assert!(
        diags.iter().any(|d| d.code == "sshd-W02"),
        "ClientAliveInterval 601 exceeds the <= 600 STIG ceiling; must fire W02"
    );
}

/// Value 900 (a common admin default) is a finding.
#[test]
fn w02_clientaliveinterval_900_fires() {
    let diags = run_w02("ClientAliveInterval 900\n", Some(TargetVersion::Rhel8));
    assert!(
        diags.iter().any(|d| d.code == "sshd-W02"),
        "ClientAliveInterval 900 is weaker than the <= 600 STIG ceiling"
    );
}

/// Value 0 disables keepalive entirely (sshd_config(5): "The default is 0,
/// indicating that these messages will not be sent to the client"), which means
/// no session timeout enforcement. This is WEAKER than the STIG <=600-and-nonzero
/// baseline, so it MUST fire sshd-W02.
///
/// Grounded in:
/// - sshd_config(5) man.openbsd.org: value 0 = keepalive messages disabled.
/// - grounding doc section 5: "ClientAliveInterval -> the only true `<= N` numeric
///   ceiling (`<= 600`, and not 0)." (verbatim from sshd-stig-version-grounding.md).
/// - DISA XCCDF RHEL-09-255100 (V-257996): operational fix requires a positive
///   value; the OpenSCAP `sshd_set_keepalive` rule treats a positive value as
///   required.
///
/// Adversarial note: the miss-case for a naive `NumericCeiling(600)` impl is
/// exactly this input. `0 <= 600` is true, so the ceiling arm returns clean -- but
/// the correct contract is a POSITIVE value <= 600.
#[test]
fn w02_clientaliveinterval_0_fires() {
    // Must fire for every supported target because ClientAliveInterval is a
    // floor-level control (present in all of RHEL8/9/10 and the None floor).
    for target in [
        Some(TargetVersion::Rhel8),
        Some(TargetVersion::Rhel9),
        Some(TargetVersion::Rhel10),
        None,
    ] {
        let diags = run_w02("ClientAliveInterval 0\n", target);
        assert!(
            diags.iter().any(|d| d.code == "sshd-W02"),
            "ClientAliveInterval 0 disables keepalive entirely (sshd_config(5)); \
             it is weaker than the STIG <=600-and-nonzero baseline and MUST fire \
             sshd-W02 for {target:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// W02: ClientAliveCountMax - EXACT = 1; BOTH 0 AND > 1 are findings
// This is the dual-bound case: a naive `<= 1` impl passes 0; a naive `>= 1`
// passes 999. Only exact equality catches both.
// ---------------------------------------------------------------------------

/// Value 1 is exactly the STIG requirement -> clean.
#[test]
fn w02_clientalivecountmax_1_is_clean() {
    for target in [
        Some(TargetVersion::Rhel8),
        Some(TargetVersion::Rhel9),
        Some(TargetVersion::Rhel10),
        None,
    ] {
        assert!(
            run_w02("ClientAliveCountMax 1\n", target).is_empty(),
            "ClientAliveCountMax 1 is the exact STIG value: no W02 for {target:?}"
        );
    }
}

/// Value 0 is a finding. (`0` disables keepalive entirely, which means no timeout
/// enforcement; ALL three STIGs require exact 1.)
/// Grounded in: DISA XCCDF RHEL-09-255095 (V-257995) check-text "value 1" (exact).
#[test]
fn w02_clientalivecountmax_0_fires() {
    for target in [
        Some(TargetVersion::Rhel8),
        Some(TargetVersion::Rhel9),
        Some(TargetVersion::Rhel10),
        None,
    ] {
        let diags = run_w02("ClientAliveCountMax 0\n", target);
        assert!(
            diags.iter().any(|d| d.code == "sshd-W02"),
            "ClientAliveCountMax 0 is NOT the required exact value 1; must fire W02 for {target:?}"
        );
    }
}

/// Value 2 (> 1) is also a finding - the STIG requires EXACT 1.
#[test]
fn w02_clientalivecountmax_2_fires() {
    for target in [
        Some(TargetVersion::Rhel8),
        Some(TargetVersion::Rhel9),
        Some(TargetVersion::Rhel10),
        None,
    ] {
        let diags = run_w02("ClientAliveCountMax 2\n", target);
        assert!(
            diags.iter().any(|d| d.code == "sshd-W02"),
            "ClientAliveCountMax 2 is NOT the required exact value 1; must fire W02 for {target:?}"
        );
    }
}

/// Value 5 (a common admin default) fires too.
#[test]
fn w02_clientalivecountmax_5_fires() {
    let diags = run_w02("ClientAliveCountMax 5\n", Some(TargetVersion::Rhel9));
    assert!(
        diags.iter().any(|d| d.code == "sshd-W02"),
        "ClientAliveCountMax 5 must fire W02 (required exact 1)"
    );
}

// ---------------------------------------------------------------------------
// W02: RekeyLimit - exact two-token "1G 1h"
// ---------------------------------------------------------------------------

/// Exact "1G 1h" is the STIG requirement -> clean.
#[test]
fn w02_rekeylimit_1g_1h_is_clean() {
    for target in [
        Some(TargetVersion::Rhel8),
        Some(TargetVersion::Rhel9),
        Some(TargetVersion::Rhel10),
        None,
    ] {
        assert!(
            run_w02("RekeyLimit 1G 1h\n", target).is_empty(),
            "RekeyLimit 1G 1h is the exact STIG value: no W02 for {target:?}"
        );
    }
}

/// A weaker limit (2G amount) is a finding.
#[test]
fn w02_rekeylimit_2g_1h_fires() {
    let diags = run_w02("RekeyLimit 2G 1h\n", Some(TargetVersion::Rhel9));
    assert!(
        diags.iter().any(|d| d.code == "sshd-W02"),
        "RekeyLimit 2G 1h exceeds the 1G amount limit; must fire W02"
    );
}

/// Larger time token (2h) is a finding.
#[test]
fn w02_rekeylimit_1g_2h_fires() {
    let diags = run_w02("RekeyLimit 1G 2h\n", Some(TargetVersion::Rhel9));
    assert!(
        diags.iter().any(|d| d.code == "sshd-W02"),
        "RekeyLimit 1G 2h exceeds the 1h time limit; must fire W02"
    );
}

/// Only the data amount (omitting the time token) is not the full required value.
#[test]
fn w02_rekeylimit_1g_none_fires() {
    let diags = run_w02("RekeyLimit 1G\n", Some(TargetVersion::Rhel9));
    assert!(
        diags.iter().any(|d| d.code == "sshd-W02"),
        "RekeyLimit 1G (no time token) is not the exact '1G 1h' required; must fire W02"
    );
}

/// The default "none" value is a finding.
#[test]
fn w02_rekeylimit_default_fires() {
    let diags = run_w02("RekeyLimit none\n", Some(TargetVersion::Rhel9));
    assert!(
        diags.iter().any(|d| d.code == "sshd-W02"),
        "RekeyLimit none (default, no rekeying) is weaker than '1G 1h'; must fire W02"
    );
}

// ---------------------------------------------------------------------------
// W02: PermitRootLogin - exact "no"; "prohibit-password" IS a finding
// This is the tricky case: `prohibit-password` is often seen as "secure enough"
// but DISA STIG V-257985 / V-230296 / V-281265 require the literal `no`.
// ---------------------------------------------------------------------------

/// Exact "no" is the STIG requirement -> clean.
#[test]
fn w02_permitrootlogin_no_is_clean() {
    for target in [
        Some(TargetVersion::Rhel8),
        Some(TargetVersion::Rhel9),
        Some(TargetVersion::Rhel10),
        None,
    ] {
        assert!(
            run_w02("PermitRootLogin no\n", target).is_empty(),
            "PermitRootLogin no is the exact STIG value: no W02 for {target:?}"
        );
    }
}

/// "yes" is obviously a finding.
#[test]
fn w02_permitrootlogin_yes_fires() {
    for target in [
        Some(TargetVersion::Rhel8),
        Some(TargetVersion::Rhel9),
        Some(TargetVersion::Rhel10),
        None,
    ] {
        let diags = run_w02("PermitRootLogin yes\n", target);
        assert!(
            diags.iter().any(|d| d.code == "sshd-W02"),
            "PermitRootLogin yes is weaker than the required 'no'; must fire W02 for {target:?}"
        );
    }
}

/// "prohibit-password" is a finding - this is the adversarial case that a naive
/// `>= no` or "any non-yes" implementation would miss.
/// Grounded in DISA XCCDF check-text requiring the exact string "no".
#[test]
fn w02_permitrootlogin_prohibit_password_fires() {
    for target in [
        Some(TargetVersion::Rhel8),
        Some(TargetVersion::Rhel9),
        Some(TargetVersion::Rhel10),
        None,
    ] {
        let diags = run_w02("PermitRootLogin prohibit-password\n", target);
        assert!(
            diags.iter().any(|d| d.code == "sshd-W02"),
            "PermitRootLogin prohibit-password is NOT the required exact 'no'; must fire W02 for {target:?}"
        );
    }
}

/// "forced-commands-only" is also not exactly "no" -> finding.
#[test]
fn w02_permitrootlogin_forced_commands_only_fires() {
    let diags = run_w02(
        "PermitRootLogin forced-commands-only\n",
        Some(TargetVersion::Rhel9),
    );
    assert!(
        diags.iter().any(|d| d.code == "sshd-W02"),
        "PermitRootLogin forced-commands-only is not the required 'no'; must fire W02"
    );
}

// ---------------------------------------------------------------------------
// W02: yes/no controls - exact literal match
// ---------------------------------------------------------------------------

/// PermitEmptyPasswords must be exact "no".
#[test]
fn w02_permitemptypasswords_yes_fires() {
    let diags = run_w02("PermitEmptyPasswords yes\n", Some(TargetVersion::Rhel9));
    assert!(
        diags.iter().any(|d| d.code == "sshd-W02"),
        "PermitEmptyPasswords yes violates the STIG 'no' requirement (V-257984)"
    );
}

#[test]
fn w02_permitemptypasswords_no_is_clean() {
    assert!(
        run_w02("PermitEmptyPasswords no\n", Some(TargetVersion::Rhel9)).is_empty(),
        "PermitEmptyPasswords no is the exact STIG value: no W02"
    );
}

/// GSSAPIAuthentication must be "no".
#[test]
fn w02_gssapiauthentication_yes_fires() {
    let diags = run_w02("GSSAPIAuthentication yes\n", Some(TargetVersion::Rhel9));
    assert!(
        diags.iter().any(|d| d.code == "sshd-W02"),
        "GSSAPIAuthentication yes violates the STIG 'no' requirement (V-258003)"
    );
}

#[test]
fn w02_gssapiauthentication_no_is_clean() {
    assert!(
        run_w02("GSSAPIAuthentication no\n", Some(TargetVersion::Rhel9)).is_empty(),
        "GSSAPIAuthentication no is the exact STIG value: no W02"
    );
}

/// KerberosAuthentication must be "no".
#[test]
fn w02_kerberosauthentication_yes_fires() {
    let diags = run_w02("KerberosAuthentication yes\n", Some(TargetVersion::Rhel9));
    assert!(
        diags.iter().any(|d| d.code == "sshd-W02"),
        "KerberosAuthentication yes violates the STIG 'no' requirement (V-258004)"
    );
}

/// X11Forwarding must be "no".
#[test]
fn w02_x11forwarding_yes_fires() {
    let diags = run_w02("X11Forwarding yes\n", Some(TargetVersion::Rhel9));
    assert!(
        diags.iter().any(|d| d.code == "sshd-W02"),
        "X11Forwarding yes violates the STIG 'no' requirement (V-258007)"
    );
}

/// StrictModes must be "yes".
#[test]
fn w02_strictmodes_no_fires() {
    let diags = run_w02("StrictModes no\n", Some(TargetVersion::Rhel9));
    assert!(
        diags.iter().any(|d| d.code == "sshd-W02"),
        "StrictModes no violates the STIG 'yes' requirement (V-258008)"
    );
}

#[test]
fn w02_strictmodes_yes_is_clean() {
    assert!(
        run_w02("StrictModes yes\n", Some(TargetVersion::Rhel9)).is_empty(),
        "StrictModes yes is the exact STIG value: no W02"
    );
}

/// HostbasedAuthentication must be "no" (RHEL9/10 only in required set).
#[test]
fn w02_hostbasedauthentication_yes_fires_for_rhel9() {
    let diags = run_w02("HostbasedAuthentication yes\n", Some(TargetVersion::Rhel9));
    assert!(
        diags.iter().any(|d| d.code == "sshd-W02"),
        "HostbasedAuthentication yes violates the STIG 'no' requirement (V-257992)"
    );
}

/// IgnoreRhosts must be "yes" (RHEL9/10 only).
#[test]
fn w02_ignorerhosts_no_fires_for_rhel9() {
    let diags = run_w02("IgnoreRhosts no\n", Some(TargetVersion::Rhel9));
    assert!(
        diags.iter().any(|d| d.code == "sshd-W02"),
        "IgnoreRhosts no violates the STIG 'yes' requirement (V-258005)"
    );
}

/// PubkeyAuthentication must be "yes" (RHEL9/10 required).
#[test]
fn w02_pubkeyauthentication_no_fires_for_rhel9() {
    let diags = run_w02("PubkeyAuthentication no\n", Some(TargetVersion::Rhel9));
    assert!(
        diags.iter().any(|d| d.code == "sshd-W02"),
        "PubkeyAuthentication no violates the STIG 'yes' requirement (V-257983)"
    );
}

/// IgnoreUserKnownHosts must be "yes".
#[test]
fn w02_ignoreuserknowhosts_no_fires() {
    let diags = run_w02("IgnoreUserKnownHosts no\n", Some(TargetVersion::Rhel9));
    assert!(
        diags.iter().any(|d| d.code == "sshd-W02"),
        "IgnoreUserKnownHosts no violates the STIG 'yes' requirement (V-258006)"
    );
}

/// PrintLastLog must be "yes".
#[test]
fn w02_printlastlog_no_fires() {
    let diags = run_w02("PrintLastLog no\n", Some(TargetVersion::Rhel9));
    assert!(
        diags.iter().any(|d| d.code == "sshd-W02"),
        "PrintLastLog no violates the STIG 'yes' requirement (V-258009)"
    );
}

/// X11UseLocalhost must be "yes".
#[test]
fn w02_x11uselocalhost_no_fires() {
    let diags = run_w02("X11UseLocalhost no\n", Some(TargetVersion::Rhel9));
    assert!(
        diags.iter().any(|d| d.code == "sshd-W02"),
        "X11UseLocalhost no violates the STIG 'yes' requirement (V-258011)"
    );
}

/// PermitUserEnvironment must be "no".
#[test]
fn w02_permituserenvironment_yes_fires() {
    let diags = run_w02("PermitUserEnvironment yes\n", Some(TargetVersion::Rhel9));
    assert!(
        diags.iter().any(|d| d.code == "sshd-W02"),
        "PermitUserEnvironment yes violates the STIG 'no' requirement (V-257993)"
    );
}

/// UsePAM must be "yes" (RHEL9/10 required).
#[test]
fn w02_usepam_no_fires_for_rhel9() {
    let diags = run_w02("UsePAM no\n", Some(TargetVersion::Rhel9));
    assert!(
        diags.iter().any(|d| d.code == "sshd-W02"),
        "UsePAM no violates the STIG 'yes' requirement (V-257986)"
    );
}

/// PubkeyAuthentication is RHEL9/10 only: must NOT fire for RHEL8 target.
#[test]
fn w02_pubkeyauthentication_no_does_not_fire_for_rhel8() {
    let diags = run_w02("PubkeyAuthentication no\n", Some(TargetVersion::Rhel8));
    assert!(
        !diags.iter().any(|d| d.code == "sshd-W02"),
        "PubkeyAuthentication is not a W02 control in RHEL8 (only in RHEL9/10)"
    );
}

/// UsePAM is RHEL9/10 only: must NOT fire for target=None (floor).
#[test]
fn w02_usepam_no_does_not_fire_for_none() {
    let diags = run_w02("UsePAM no\n", None);
    assert!(
        !diags.iter().any(|d| d.code == "sshd-W02"),
        "UsePAM is not a W02 control in the floor (target=None; RHEL8 set)"
    );
}

/// IgnoreRhosts is RHEL9/10 only: must NOT fire for RHEL8 target.
#[test]
fn w02_ignorerhosts_no_does_not_fire_for_rhel8() {
    let diags = run_w02("IgnoreRhosts no\n", Some(TargetVersion::Rhel8));
    assert!(
        !diags.iter().any(|d| d.code == "sshd-W02"),
        "IgnoreRhosts is not a W02 control in RHEL8 (only in RHEL9/10)"
    );
}

/// HostbasedAuthentication is RHEL9/10 only: must NOT fire for None target.
#[test]
fn w02_hostbasedauthentication_yes_does_not_fire_for_none() {
    let diags = run_w02("HostbasedAuthentication yes\n", None);
    assert!(
        !diags.iter().any(|d| d.code == "sshd-W02"),
        "HostbasedAuthentication is not a W02 control in the floor (target=None; RHEL8 set)"
    );
}

// ---------------------------------------------------------------------------
// W02: Compression - "delayed" and "no" OK; "yes" is a finding (RHEL8/9 only)
// ---------------------------------------------------------------------------

/// "delayed" is an accepted value per RHEL 9 V2R7 / RHEL 8 V2R4.
#[test]
fn w02_compression_delayed_is_clean_for_rhel9() {
    assert!(
        run_w02("Compression delayed\n", Some(TargetVersion::Rhel9)).is_empty(),
        "Compression delayed is an accepted STIG value for RHEL9 (V-258002)"
    );
}

/// "no" is also an accepted value.
#[test]
fn w02_compression_no_is_clean_for_rhel9() {
    assert!(
        run_w02("Compression no\n", Some(TargetVersion::Rhel9)).is_empty(),
        "Compression no is an accepted STIG value for RHEL9"
    );
}

/// "yes" is a finding for RHEL8 and RHEL9.
#[test]
fn w02_compression_yes_fires_for_rhel9() {
    let diags = run_w02("Compression yes\n", Some(TargetVersion::Rhel9));
    assert!(
        diags.iter().any(|d| d.code == "sshd-W02"),
        "Compression yes violates the STIG requirement (V-258002): must be 'delayed' or 'no'"
    );
}

#[test]
fn w02_compression_yes_fires_for_rhel8() {
    let diags = run_w02("Compression yes\n", Some(TargetVersion::Rhel8));
    assert!(
        diags.iter().any(|d| d.code == "sshd-W02"),
        "Compression yes violates the STIG requirement for RHEL8"
    );
}

/// Compression is NOT a controlled directive for RHEL10 (V1R1 dropped it).
/// W02 must NOT fire for Compression with any value under Rhel10.
#[test]
fn w02_compression_yes_does_not_fire_for_rhel10() {
    let diags = run_w02("Compression yes\n", Some(TargetVersion::Rhel10));
    assert!(
        !diags.iter().any(|d| d.code == "sshd-W02"),
        "Compression was dropped from RHEL10 V1R1; W02 must NOT fire for it under Rhel10"
    );
}

// ---------------------------------------------------------------------------
// W02: LogLevel - exact "VERBOSE" (RHEL9/10 only)
// ---------------------------------------------------------------------------

/// "VERBOSE" is the exact required value -> clean for RHEL9 and RHEL10.
#[test]
fn w02_loglevel_verbose_is_clean_for_rhel9() {
    assert!(
        run_w02("LogLevel VERBOSE\n", Some(TargetVersion::Rhel9)).is_empty(),
        "LogLevel VERBOSE is the exact STIG requirement for RHEL9 (V-257982)"
    );
}

#[test]
fn w02_loglevel_verbose_is_clean_for_rhel10() {
    assert!(
        run_w02("LogLevel VERBOSE\n", Some(TargetVersion::Rhel10)).is_empty(),
        "LogLevel VERBOSE is the exact STIG requirement for RHEL10 (V-281115)"
    );
}

/// "INFO" (common default) is a finding for RHEL9.
#[test]
fn w02_loglevel_info_fires_for_rhel9() {
    let diags = run_w02("LogLevel INFO\n", Some(TargetVersion::Rhel9));
    assert!(
        diags.iter().any(|d| d.code == "sshd-W02"),
        "LogLevel INFO is weaker than the required VERBOSE (V-257982); must fire W02 for RHEL9"
    );
}

/// "QUIET" is also a finding.
#[test]
fn w02_loglevel_quiet_fires_for_rhel9() {
    let diags = run_w02("LogLevel QUIET\n", Some(TargetVersion::Rhel9));
    assert!(
        diags.iter().any(|d| d.code == "sshd-W02"),
        "LogLevel QUIET is weaker than the required VERBOSE; must fire W02 for RHEL9"
    );
}

/// LogLevel is NOT a controlled directive for RHEL8 (absent from V2R4 set).
/// W02 must NOT fire for LogLevel under Rhel8 or target=None.
#[test]
fn w02_loglevel_info_does_not_fire_for_rhel8() {
    let diags = run_w02("LogLevel INFO\n", Some(TargetVersion::Rhel8));
    assert!(
        !diags.iter().any(|d| d.code == "sshd-W02"),
        "LogLevel is NOT a RHEL8 STIG control; W02 must NOT fire for Rhel8"
    );
}

#[test]
fn w02_loglevel_info_does_not_fire_for_target_none() {
    let diags = run_w02("LogLevel INFO\n", None);
    assert!(
        !diags.iter().any(|d| d.code == "sshd-W02"),
        "LogLevel is not in the RHEL8 floor set; W02 must NOT fire for target=None"
    );
}

// ---------------------------------------------------------------------------
// W02: SCOPE GUARD - cross-file precedence is out of scope
// W02 evaluates ONLY the single-file value. If the value is correct in this
// file, W02 is clean regardless of what another file might say.
// ---------------------------------------------------------------------------

/// If PermitRootLogin is "no" in this file, W02 is satisfied - the fact that
/// another drop-in might override it is not W02's concern (that is F02/Wave C).
#[test]
fn w02_scope_guard_single_file_only() {
    // PermitRootLogin no in the file being linted: W02 must be clean here.
    assert!(
        run_w02("PermitRootLogin no\n", Some(TargetVersion::Rhel9)).is_empty(),
        "W02 is single-file only; a correct value in this file is clean regardless of drop-ins"
    );
}

// ---------------------------------------------------------------------------
// W02: Banner is NOT a value-checked directive (W01 checks presence only)
// ---------------------------------------------------------------------------

/// Banner is a presence-only check (W01). The value is a path, not a strict
/// literal, so W02 must NOT fire for any Banner value (that is an out-of-scope
/// file-content check).
#[test]
fn w02_banner_any_path_is_not_a_w02_finding() {
    for src in [
        "Banner /etc/issue\n",
        "Banner /etc/issue.net\n",
        "Banner /custom/banner.txt\n",
    ] {
        let diags = run_w02(src, Some(TargetVersion::Rhel9));
        assert!(
            !diags.iter().any(|d| d.code == "sshd-W02"),
            "Banner value is not a W02 concern (presence only); got W02 for: {src}"
        );
    }
}

// ---------------------------------------------------------------------------
// W02: diagnostic fields
// ---------------------------------------------------------------------------

#[test]
fn w02_diagnostic_severity_is_warning() {
    let diags = run_w02("ClientAliveInterval 900\n", Some(TargetVersion::Rhel9));
    let w02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sshd-W02").collect();
    assert!(!w02_diags.is_empty(), "must fire W02");
    for d in &w02_diags {
        assert_eq!(
            d.severity,
            rulesteward_core::Severity::Warning,
            "W02 must have Warning severity"
        );
    }
}

// ---------------------------------------------------------------------------
// W02: a fully STIG-compliant config is entirely clean
// ---------------------------------------------------------------------------

/// All 20 RHEL9 directives at their required values produce zero W02 findings.
#[test]
fn w02_rhel9_full_compliant_config_is_clean() {
    let diags = run_w02(RHEL9_FULL, Some(TargetVersion::Rhel9));
    let w02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sshd-W02").collect();
    assert!(
        w02_diags.is_empty(),
        "a fully STIG-compliant RHEL9 config must produce zero W02 findings; got {w02_diags:?}"
    );
}

/// All 14 RHEL8 directives at their required values produce zero W02 findings.
#[test]
fn w02_rhel8_full_compliant_config_is_clean() {
    let diags = run_w02(RHEL8_FULL, Some(TargetVersion::Rhel8));
    let w02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sshd-W02").collect();
    assert!(
        w02_diags.is_empty(),
        "a fully STIG-compliant RHEL8 config must produce zero W02 findings; got {w02_diags:?}"
    );
}

// ---------------------------------------------------------------------------
// W01 + W02 separation: W02 never fires for an ABSENT directive
// (W01 handles absence; W02 handles a present-but-wrong value)
// ---------------------------------------------------------------------------

/// An empty config produces W01 (missing) findings, NOT W02 (wrong value).
#[test]
fn w01_handles_absence_w02_does_not_fire_for_absent_directives() {
    // Empty config: all required directives are absent.
    let w01_diags = run_w01("", Some(TargetVersion::Rhel9));
    let w02_diags = run_w02("", Some(TargetVersion::Rhel9));

    assert!(
        w01_diags.iter().any(|d| d.code == "sshd-W01"),
        "empty config must produce W01 (missing directives)"
    );
    assert!(
        !w02_diags.iter().any(|d| d.code == "sshd-W02"),
        "W02 must NOT fire for absent directives (that is W01's job); got: {w02_diags:?}"
    );
}

// ---------------------------------------------------------------------------
// Trap corpus fixtures: add .conf files under tests/corpus/traps/sshd-W01/
// and tests/corpus/traps/sshd-W02/ for the trap_corpus.rs driver.
// (These are simple smoke files; the richer semantics are in the tests above.)
// ---------------------------------------------------------------------------

// NOTE: trap corpus fixtures are .conf files; they do not need Rust test fns.
// The trap_corpus.rs driver picks them up automatically.

// Verify the trap_corpus directory paths are consistent with this module.
#[test]
fn w01_trap_corpus_fires_through_dispatcher() {
    // A minimal config missing the required Banner directive (floor).
    // Simulates what the trap corpus fixture would do: run through the full
    // lints::lint() dispatcher with default context and assert sshd-W01 fires.
    use rulesteward_sshd::lints;
    let src = "PermitRootLogin no\n"; // missing Banner and others
    let blocks = parse_config_str_located(src, Path::new(FAKE_FILE)).unwrap();
    let diags = lints::lint(&blocks, Path::new(FAKE_FILE), &SshdLintContext::default());
    assert!(
        diags.iter().any(|d| d.code == "sshd-W01"),
        "sshd-W01 must fire through the full dispatcher when required directives are absent"
    );
}

#[test]
fn w02_trap_corpus_fires_through_dispatcher() {
    // ClientAliveInterval value above the ceiling, run through the full dispatcher.
    use rulesteward_sshd::lints;
    let src = "ClientAliveInterval 900\n";
    let blocks = parse_config_str_located(src, Path::new(FAKE_FILE)).unwrap();
    let diags = lints::lint(&blocks, Path::new(FAKE_FILE), &SshdLintContext::default());
    assert!(
        diags.iter().any(|d| d.code == "sshd-W02"),
        "sshd-W02 must fire through the full dispatcher for a weaker-than-baseline value"
    );
}

// ---------------------------------------------------------------------------
// Additional adversarial cases: ensure correct sshd-W0x codes are emitted
// ---------------------------------------------------------------------------

/// Ensure the diagnostic code is exactly "sshd-W01" (not "W01" or "sshd-w01").
#[test]
fn w01_diagnostic_code_is_exact() {
    let diags = run_w01("", Some(TargetVersion::Rhel9));
    let codes_list: Vec<_> = codes(&diags);
    assert!(
        codes_list.contains(&"sshd-W01"),
        "diagnostic code must be exactly 'sshd-W01'"
    );
    assert!(
        !codes_list.contains(&"W01"),
        "short code 'W01' must not appear"
    );
}

/// Ensure the diagnostic code is exactly "sshd-W02".
#[test]
fn w02_diagnostic_code_is_exact() {
    let diags = run_w02("ClientAliveInterval 900\n", Some(TargetVersion::Rhel9));
    let codes_list: Vec<_> = codes(&diags);
    assert!(
        codes_list.contains(&"sshd-W02"),
        "diagnostic code must be exactly 'sshd-W02'"
    );
}

/// Keyword lookup is case-insensitive: "clientaliveinterval 900" (all lowercase)
/// must still fire W02 for the ceiling violation.
#[test]
fn w02_keyword_match_is_case_insensitive() {
    let diags = run_w02("clientaliveinterval 900\n", Some(TargetVersion::Rhel9));
    assert!(
        diags.iter().any(|d| d.code == "sshd-W02"),
        "W02 keyword matching must be case-insensitive"
    );
}

// ---------------------------------------------------------------------------
// W01: each finding NAMES the specific missing directive in its message
// (positive assertion - closes the generic-message wrong-impl gap)
// ---------------------------------------------------------------------------

/// A W01 finding for a missing Banner directive must name "banner" (case-insensitive)
/// in its message.  A generic message ("missing required STIG directive") that does
/// not identify WHICH directive was omitted makes the finding un-actionable and would
/// allow a trivially-wrong impl (emit one finding with a static message for any missing
/// set member) to pass the structural/count tests above while hiding its defect.
#[test]
fn w01_finding_names_the_missing_directive_in_message() {
    // Config has every RHEL9 directive EXCEPT Banner - the floor item we know will fire.
    let src = RHEL9_FULL.replace("Banner /etc/issue\n", "");
    let diags = run_w01(&src, None); // target=None: Banner is floor-required
    let banner_finding = diags
        .iter()
        .find(|d| d.code == "sshd-W01" && d.message.to_ascii_lowercase().contains("banner"));
    assert!(
        banner_finding.is_some(),
        "a W01 finding for a missing Banner directive must include 'banner' \
         (case-insensitive) in its message so the operator knows which directive is absent; \
         W01 findings were: {diags:?}"
    );
}

/// Similarly, a missing PermitRootLogin finding must name "permitrootlogin"
/// in its message.  Verifies the naming requirement is not Banner-specific.
#[test]
fn w01_finding_names_the_missing_directive_for_permitrootlogin() {
    // Config has every RHEL9 directive EXCEPT PermitRootLogin.
    let src = RHEL9_FULL.replace("PermitRootLogin no\n", "");
    let diags = run_w01(&src, None); // target=None: PermitRootLogin is floor-required
    let finding = diags.iter().find(|d| {
        d.code == "sshd-W01" && d.message.to_ascii_lowercase().contains("permitrootlogin")
    });
    assert!(
        finding.is_some(),
        "a W01 finding for a missing PermitRootLogin directive must include \
         'permitrootlogin' (case-insensitive) in its message; got: {diags:?}"
    );
}

/// Keyword lookup is case-insensitive for W01 too.
#[test]
fn w01_keyword_match_is_case_insensitive() {
    // A config with all required directives supplied in various cases.
    // If W01 is case-sensitive it would fire falsely here.
    let src = "\
BANNER /etc/issue\n\
loglevel VERBOSE\n\
pubkeyauthentication yes\n\
PermitEmptyPasswords no\n\
PERMITROOTLOGIN no\n\
UsePAM yes\n\
HostbasedAuthentication no\n\
PermitUserEnvironment no\n\
RekeyLimit 1G 1h\n\
ClientAliveCountMax 1\n\
ClientAliveInterval 300\n\
Compression delayed\n\
GSSAPIAuthentication no\n\
KerberosAuthentication no\n\
IgnoreRhosts yes\n\
IgnoreUserKnownHosts yes\n\
X11Forwarding no\n\
StrictModes yes\n\
PrintLastLog yes\n\
X11UseLocalhost yes\n";

    let diags = run_w01(src, Some(TargetVersion::Rhel9));
    assert!(
        !diags.iter().any(|d| d.code == "sshd-W01"),
        "W01 keyword lookup must be case-insensitive; no W01 for mixed-case directives; got {diags:?}"
    );
}
