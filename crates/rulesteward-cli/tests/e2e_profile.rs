//! End-to-end proof for the global `--profile <framework>` finding filter (#506,
//! v0.7 headline feature). Exercises the real binary: clap parse -> command
//! dispatch -> lint -> `apply_profile` filter -> render -> exit code.
//!
//! Contract (locked):
//!  * `--profile {stig,cis,pci,nist}` keeps only findings enforcing a control in
//!    that framework.
//!  * When the filter empties a PREVIOUSLY-NON-EMPTY finding set -> exit 9
//!    (`EXIT_NO_OP`), so CI can tell "nothing matched the profile" from "clean".
//!  * An already-clean scan + `--profile` stays exit 0 (never 9).
//!  * `--profile` absent = no filter = byte-identical to omitting the flag.
//!
//! The framework tags these fixtures rely on are grounded in the lint crates:
//!  * `sysctld-W02` (STIG baseline) attaches `Framework::Stig`
//!    (`rulesteward-sysctld/src/lints/baseline.rs`).
//!  * `sysctld-W04` (CIS baseline, #527) attaches `Framework::Cis`
//!    (`rulesteward-sysctld/src/lints/cis.rs`).
//!  * `sysctld-W01` (last-wins) attaches NO controls -> dropped by any profile.
//!  * `sudo-W04` missing-`use_pty` / missing-I/O-log attach `Framework::Cis`
//!    (5.2.2 / 5.2.3) + `Framework::Pci` (`rulesteward-sudoers/src/lints/stig.rs`).
//!  * fapolicyd findings attach NO controls -> any profile empties them.
//!  * `Framework::Nist` is attached by NO lint today -> `--profile nist` empties
//!    any non-empty finding set.

use std::io::Write;

use assert_cmd::Command;
use serde_json::Value;

fn bin() -> Command {
    Command::cargo_bin("rulesteward").expect("binary built")
}

/// Write `body` to a temp file and return the handle (kept alive by the caller).
fn tmp_file(body: &str) -> tempfile::NamedTempFile {
    let mut f = tempfile::NamedTempFile::new().expect("temp file");
    f.write_all(body.as_bytes()).expect("write body");
    f.flush().expect("flush");
    f
}

// ---------------------------------------------------------------------------
// EXIT 9: fapolicyd carries no controls, so any --profile empties its findings.
// This is the cleanest no-op demonstration.
// ---------------------------------------------------------------------------

/// Baseline: the fapolicyd fixture DOES yield a finding without `--profile`
/// (`allow uid=0 : all # bad comment` -> fapd-W03, Warning -> exit 1). Guards the
/// exit-9 test below from being vacuous (a fixture that was already clean would
/// exit 0 with OR without the flag).
#[test]
fn fapolicyd_lint_without_profile_reports_the_finding_exit_one() {
    let f = tmp_file("allow uid=0 : all # bad comment\n");
    let out = bin()
        .args(["fapolicyd", "lint", "--file", f.path().to_str().unwrap()])
        .output()
        .expect("binary ran");
    assert_eq!(
        out.status.code(),
        Some(1),
        "the fixture yields fapd-W03 (Warning) -> exit 1 without --profile; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).expect("utf8");
    assert!(
        stdout.contains("fapd-W03"),
        "no-profile baseline must report the finding; stdout: {stdout}"
    );
}

/// `--profile stig` on that same fapolicyd fixture: the finding carries no STIG
/// control (fapolicyd emits no controls at all), so the filter empties a
/// previously-non-empty set -> exit 9 with EMPTY stdout (nothing to render).
#[test]
fn fapolicyd_lint_profile_stig_empties_and_exits_nine() {
    let f = tmp_file("allow uid=0 : all # bad comment\n");
    let out = bin()
        .args([
            "fapolicyd",
            "lint",
            "--file",
            f.path().to_str().unwrap(),
            "--profile",
            "stig",
        ])
        .output()
        .expect("binary ran");
    assert_eq!(
        out.status.code(),
        Some(9),
        "emptying a non-empty finding set via --profile exits 9 (EXIT_NO_OP); stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).expect("utf8");
    assert!(
        stdout.trim().is_empty(),
        "the filtered-empty set renders nothing; stdout was: {stdout}"
    );
    assert!(
        !stdout.contains("fapd-W03"),
        "the dropped finding must not appear; stdout was: {stdout}"
    );
}

// ---------------------------------------------------------------------------
// RETAIN + byte-identical None path: an all-STIG finding set under --profile stig
// is byte-for-byte identical to the no-flag run (nothing is filtered).
// ---------------------------------------------------------------------------

/// An `sshd lint --target rhel9` run on a minimal config: every finding is an
/// `sshd-W01` STIG-baseline miss, and ALL of them carry a `Framework::Stig` ref
/// (the CIS-overlap keywords carry an ADDITIONAL `Framework::Cis` ref, which does
/// not affect `stig` retention). `--profile stig` retains every one, so BOTH the
/// exit code and the stdout are byte-identical to the no-`--profile` baseline.
/// This pins (a) STIG retention and (b) that the filter is a no-op when
/// everything matches. (Pre-Wave-3 this property was pinned via sysctl, but
/// `sysctld-W04` CIS findings now fire alongside `sysctld-W02` under `--target`,
/// so sysctl baselines are no longer all-STIG by design -- see
/// `sysctl_profile_stig_keeps_w02_and_drops_w04` below.)
#[test]
fn sshd_profile_stig_retains_all_and_is_byte_identical_to_baseline() {
    let cfg = tmp_file("Port 22\n");
    let path = cfg.path().to_str().unwrap();

    let baseline = bin()
        .args(["sshd", "lint", path, "--target", "rhel9"])
        .output()
        .expect("baseline ran");
    let profiled = bin()
        .args([
            "sshd",
            "lint",
            path,
            "--target",
            "rhel9",
            "--profile",
            "stig",
        ])
        .output()
        .expect("profiled ran");

    // Baseline sanity: the fixture yields STIG W01 findings (exit 1), else the
    // identity below would be a vacuous 0==0 / empty==empty.
    assert_eq!(
        baseline.status.code(),
        Some(1),
        "minimal config under --target rhel9 warns (exit 1); stderr: {}",
        String::from_utf8_lossy(&baseline.stderr)
    );
    let baseline_stdout = String::from_utf8(baseline.stdout).expect("utf8");
    assert!(
        baseline_stdout.contains("sshd-W01"),
        "baseline must carry the STIG W01 findings; stdout: {baseline_stdout}"
    );

    // Retention + byte-identity: an all-STIG set is unchanged by --profile stig.
    assert_eq!(
        profiled.status.code(),
        baseline.status.code(),
        "an all-STIG set retained by --profile stig keeps the baseline exit code"
    );
    let profiled_stdout = String::from_utf8(profiled.stdout).expect("utf8");
    assert_eq!(
        profiled_stdout, baseline_stdout,
        "an all-STIG set retained by --profile stig is byte-identical to the baseline"
    );
}

/// `sysctl lint --target rhel9` now yields BOTH `sysctld-W02` (STIG-tagged) and
/// `sysctld-W04` (CIS-tagged) findings for an unhardened config (#527).
/// `--profile stig` keeps every W02 and drops every W04; `--profile cis` does
/// the inverse. This replaced the pre-Wave-3 sysctl byte-identity test: with
/// W04 in the baseline, a single-framework profile is never a no-op for sysctl
/// by design.
#[test]
fn sysctl_profile_stig_keeps_w02_and_drops_w04() {
    let cfg = tmp_file("# nothing hardened here\nkernel.sysrq = 0\n");
    let path = cfg.path().to_str().unwrap();

    let baseline = bin()
        .args(["sysctl", "lint", path, "--target", "rhel9"])
        .output()
        .expect("baseline ran");
    assert_eq!(
        baseline.status.code(),
        Some(1),
        "unhardened config under --target rhel9 warns (exit 1); stderr: {}",
        String::from_utf8_lossy(&baseline.stderr)
    );
    let baseline_stdout = String::from_utf8(baseline.stdout).expect("utf8");
    assert!(
        baseline_stdout.contains("sysctld-W02") && baseline_stdout.contains("sysctld-W04"),
        "baseline must carry BOTH the STIG W02 and CIS W04 findings; stdout: {baseline_stdout}"
    );

    let stig = bin()
        .args([
            "sysctl",
            "lint",
            path,
            "--target",
            "rhel9",
            "--profile",
            "stig",
        ])
        .output()
        .expect("stig-profiled ran");
    assert_eq!(stig.status.code(), Some(1), "W02 findings remain (exit 1)");
    let stig_stdout = String::from_utf8(stig.stdout).expect("utf8");
    assert!(
        stig_stdout.contains("sysctld-W02") && !stig_stdout.contains("sysctld-W04"),
        "--profile stig keeps W02 and drops W04; stdout: {stig_stdout}"
    );

    let cis = bin()
        .args([
            "sysctl",
            "lint",
            path,
            "--target",
            "rhel9",
            "--profile",
            "cis",
        ])
        .output()
        .expect("cis-profiled ran");
    assert_eq!(cis.status.code(), Some(1), "W04 findings remain (exit 1)");
    let cis_stdout = String::from_utf8(cis.stdout).expect("utf8");
    assert!(
        cis_stdout.contains("sysctld-W04") && !cis_stdout.contains("sysctld-W02"),
        "--profile cis keeps W04 and drops W02; stdout: {cis_stdout}"
    );
}

/// Mixed set: a `sysctld-W01` last-wins conflict (NO controls) AND a `sysctld-W02`
/// STIG finding under `--target rhel9`. `--profile stig` KEEPS the W02 and DROPS
/// the W01 -- proving the filter actually removes non-matching findings (not just
/// passes everything through). Exit stays 1 (W02 is a Warning).
#[test]
fn sysctl_profile_stig_drops_uncontrolled_findings_keeps_stig() {
    // kernel.sysrq assigned twice -> sysctld-W01 (last-wins, no controls).
    // kernel.dmesg_restrict = 0 under rhel9 -> sysctld-W02 (STIG, needs 1).
    let cfg = tmp_file("kernel.dmesg_restrict = 0\nkernel.sysrq = 1\nkernel.sysrq = 0\n");
    let path = cfg.path().to_str().unwrap();

    // Baseline: both codes present.
    let baseline = bin()
        .args(["sysctl", "lint", path, "--target", "rhel9"])
        .output()
        .expect("baseline ran");
    let baseline_stdout = String::from_utf8(baseline.stdout).expect("utf8");
    assert!(
        baseline_stdout.contains("sysctld-W01") && baseline_stdout.contains("sysctld-W02"),
        "baseline must contain BOTH W01 (uncontrolled) and W02 (STIG); stdout: {baseline_stdout}"
    );

    let profiled = bin()
        .args([
            "sysctl",
            "lint",
            path,
            "--target",
            "rhel9",
            "--profile",
            "stig",
        ])
        .output()
        .expect("profiled ran");
    assert_eq!(
        profiled.status.code(),
        Some(1),
        "the retained STIG W02 is a Warning -> exit 1; stderr: {}",
        String::from_utf8_lossy(&profiled.stderr)
    );
    let profiled_stdout = String::from_utf8(profiled.stdout).expect("utf8");
    assert!(
        profiled_stdout.contains("sysctld-W02"),
        "--profile stig must KEEP the STIG W02; stdout: {profiled_stdout}"
    );
    assert!(
        !profiled_stdout.contains("sysctld-W01"),
        "--profile stig must DROP the uncontrolled W01; stdout: {profiled_stdout}"
    );
}

// ---------------------------------------------------------------------------
// CIS: a sudoers fixture whose findings carry Framework::Cis (use_pty / I/O-log
// merged-absence). --profile cis retains them; --profile nist (attached by no
// lint) empties the set -> exit 9.
// ---------------------------------------------------------------------------

/// A sudoers file that SETS `timestamp_timeout` (so no STIG timestamp W04 fires)
/// but omits `use_pty` and I/O logging -> the only findings are the two CIS
/// `sudo-W04` merged-absence warnings (CIS 5.2.2 / 5.2.3, + PCI). Grounded in
/// `rulesteward-sudoers/src/lints/stig.rs` `USE_PTY_CONTROLS` / `IO_LOG_CONTROLS`.
/// Verified `visudo -c`-shaped (valid Defaults + one user-spec).
const CIS_ONLY_SUDOERS: &str = "\
Defaults env_reset
Defaults timestamp_timeout=5
root ALL=(ALL:ALL) ALL
";

/// `--profile cis` retains the CIS-tagged `sudo-W04` findings: exit 1 (Warning)
/// and the finding is still reported. Proves CIS filtering is REAL, not stubbed.
/// The retained set is byte-identical to the no-profile baseline (every finding
/// is CIS-tagged, so nothing is dropped).
#[test]
fn sudoers_profile_cis_retains_cis_findings() {
    let cfg = tmp_file(CIS_ONLY_SUDOERS);
    let path = cfg.path().to_str().unwrap();

    let baseline = bin()
        .args(["sudoers", "lint", path])
        .output()
        .expect("baseline ran");
    assert_eq!(
        baseline.status.code(),
        Some(1),
        "the CIS-only sudoers fixture warns (sudo-W04) -> exit 1; stderr: {}",
        String::from_utf8_lossy(&baseline.stderr)
    );
    let baseline_stdout = String::from_utf8(baseline.stdout).expect("utf8");
    assert!(
        baseline_stdout.contains("sudo-W04"),
        "baseline must report the CIS sudo-W04 findings; stdout: {baseline_stdout}"
    );

    let profiled = bin()
        .args(["sudoers", "lint", path, "--profile", "cis"])
        .output()
        .expect("profiled ran");
    assert_eq!(
        profiled.status.code(),
        Some(1),
        "--profile cis retains the CIS findings -> exit 1; stderr: {}",
        String::from_utf8_lossy(&profiled.stderr)
    );
    let profiled_stdout = String::from_utf8(profiled.stdout).expect("utf8");
    assert!(
        profiled_stdout.contains("sudo-W04"),
        "--profile cis must KEEP the CIS sudo-W04 findings; stdout: {profiled_stdout}"
    );
    assert_eq!(
        profiled_stdout, baseline_stdout,
        "an all-CIS set retained by --profile cis is byte-identical to the baseline"
    );
}

/// `--profile nist` on the same CIS-only fixture: no finding carries a NIST
/// control (NIST is attached by no lint today), so the filter empties a
/// non-empty set -> exit 9 with empty stdout. Proves a non-matching profile
/// drops CIS-tagged findings too (the filter is framework-specific).
#[test]
fn sudoers_profile_nist_empties_and_exits_nine() {
    let cfg = tmp_file(CIS_ONLY_SUDOERS);
    let out = bin()
        .args([
            "sudoers",
            "lint",
            cfg.path().to_str().unwrap(),
            "--profile",
            "nist",
        ])
        .output()
        .expect("binary ran");
    assert_eq!(
        out.status.code(),
        Some(9),
        "no finding carries a NIST control, so --profile nist empties the set -> exit 9; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).expect("utf8");
    assert!(
        stdout.trim().is_empty(),
        "the filtered-empty set renders nothing; stdout: {stdout}"
    );
}

// ---------------------------------------------------------------------------
// CLEAN + PROFILE: an already-clean scan + --profile stays exit 0, NOT 9. The
// no-op fires only when the filter EMPTIES a non-empty set.
// ---------------------------------------------------------------------------

/// A clean sysctl config (no findings) with `--profile stig`: the set was already
/// empty, so the filter did not empty a non-empty set -> exit 0, not 9.
#[test]
fn clean_scan_with_profile_stays_zero_not_nine() {
    let cfg = tmp_file("# clean\nkernel.randomize_va_space = 2\n");
    let out = bin()
        .args([
            "sysctl",
            "lint",
            cfg.path().to_str().unwrap(),
            "--profile",
            "stig",
        ])
        .output()
        .expect("binary ran");
    assert_eq!(
        out.status.code(),
        Some(0),
        "an already-clean scan + --profile stays exit 0 (NOT the no-op 9); stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).expect("utf8");
    assert!(
        stdout.trim().is_empty(),
        "a clean scan prints no findings; stdout: {stdout}"
    );
}

/// `--profile` is a GLOBAL flag but INERT on a non-lint verb: `auditd cost` has no
/// `Vec<Diagnostic>` seam, so `--profile stig` is accepted (not a parse error) and
/// does not alter the cost output or return 9.
#[test]
fn profile_is_accepted_but_inert_on_non_lint_verb() {
    let rules = tmp_file("-w /etc/passwd -p wa -k identity\n");
    let out = bin()
        .args([
            "auditd",
            "cost",
            "--rules",
            rules.path().to_str().unwrap(),
            "--profile",
            "stig",
        ])
        .output()
        .expect("binary ran");
    assert_eq!(
        out.status.code(),
        Some(0),
        "--profile is accepted on a non-lint verb and never returns 9; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).expect("utf8");
    assert!(
        stdout.contains("auditd cost estimate"),
        "the cost output is unaffected by the inert --profile; stdout: {stdout}"
    );
}

// ---------------------------------------------------------------------------
// PARSE-ERROR EXEMPTION (#506 defect fix): a file that FAILED to parse was never
// checked, so its F01 must NOT be filtered by --profile. Exit stays 5 (F01
// outranks all severities per exit_code.rs), the F01 renders (does not vanish),
// and the SARIF coverage attestation stays suppressed. F01 carries no controls,
// so a naive controls-only filter would drop it -> exit 9 / empty output.
// ---------------------------------------------------------------------------

/// A sysctl config that fails to parse (a bare key with no `=` -> sysctld-F01)
/// under `--profile stig`: the F01 must SURVIVE the filter. Exit 5 (parse
/// failure), NOT the no-op 9, and the F01 still renders (never a silent empty).
#[test]
fn sysctl_parse_error_under_profile_exits_five_and_renders_f01() {
    let cfg = tmp_file("kernel.dmesg_restrict\n");
    let out = bin()
        .args([
            "sysctl",
            "lint",
            cfg.path().to_str().unwrap(),
            "--profile",
            "stig",
        ])
        .output()
        .expect("binary ran");
    assert_eq!(
        out.status.code(),
        Some(5),
        "a parse failure under --profile must exit 5 (F01 outranks severity), \
         never the no-op 9 or a swallowed 0; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).expect("utf8");
    assert!(
        stdout.contains("sysctld-F01"),
        "the parse error must still render under --profile (must not vanish); stdout: {stdout}"
    );
}

/// Same exemption for the fapolicyd backend: a garbage `.rules` file (fapd-F01)
/// under `--profile stig` exits 5 and renders the F01, not exit 9 with empty
/// output. Covers a SECOND backend so the fix is not sysctl-specific.
#[test]
fn fapolicyd_parse_error_under_profile_exits_five_and_renders_f01() {
    let f = tmp_file("!!!garbage line\n");
    let out = bin()
        .args([
            "fapolicyd",
            "lint",
            "--file",
            f.path().to_str().unwrap(),
            "--profile",
            "stig",
        ])
        .output()
        .expect("binary ran");
    assert_eq!(
        out.status.code(),
        Some(5),
        "a fapolicyd parse failure under --profile must exit 5, not the no-op 9; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).expect("utf8");
    assert!(
        stdout.contains("fapd-F01"),
        "the fapd-F01 parse error must still render under --profile; stdout: {stdout}"
    );
}

/// #137 attestation guard must NOT be defeated by the profile filter: a rules.d
/// with one VALID and one UN-PARSEABLE file, under
/// `--format sarif --sarif-include-pass --profile stig`, must emit ZERO
/// `kind:"pass"` results. If F01 were filtered out BEFORE the parse-failure check
/// (`lint.rs` `sarif_pass_info`), the surviving-clean set would falsely attest
/// full coverage. The retained F01 keeps `parse_failed` true -> attestation gone.
#[test]
fn fapolicyd_sarif_pass_attestation_suppressed_by_parse_failure_under_profile() {
    let dir = tempfile::tempdir().expect("tempdir");
    let rules_d = dir.path().join("rules.d");
    std::fs::create_dir_all(&rules_d).expect("create rules.d");
    std::fs::write(rules_d.join("10-ok.rules"), "allow uid=0 : all\n").expect("write ok");
    std::fs::write(rules_d.join("20-broken.rules"), "!!!garbage\n").expect("write broken");

    let out = bin()
        .args([
            "fapolicyd",
            "lint",
            rules_d.to_str().unwrap(),
            "--format",
            "sarif",
            "--sarif-include-pass",
            "--profile",
            "stig",
        ])
        .output()
        .expect("binary ran");

    let stdout = String::from_utf8(out.stdout).expect("utf8");
    let v: Value = serde_json::from_str(&stdout).expect("SARIF output must be valid JSON");

    // Zero kind:"pass" results (the coverage attestation must stay suppressed).
    let pass_results: Vec<&Value> = v
        .pointer("/runs/0/results")
        .and_then(Value::as_array)
        .map(|rs| {
            rs.iter()
                .filter(|r| r.get("kind").and_then(Value::as_str) == Some("pass"))
                .collect()
        })
        .unwrap_or_default();
    assert!(
        pass_results.is_empty(),
        "a surviving parse failure must suppress every kind:\"pass\" result even under \
         --profile; got {} pass results:\n{stdout}",
        pass_results.len()
    );

    // The tool.driver.rules[] coverage list must likewise be empty/absent.
    let rules_len = v
        .pointer("/runs/0/tool/driver/rules")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    assert_eq!(
        rules_len, 0,
        "a surviving parse failure must suppress the rules[] coverage attestation; stdout:\n{stdout}"
    );

    // The F01 itself must still be reported as a finding (it did not vanish).
    let finding_ids: Vec<String> = v
        .pointer("/runs/0/results")
        .and_then(Value::as_array)
        .map(|rs| {
            rs.iter()
                .filter_map(|r| r.get("ruleId").and_then(Value::as_str).map(String::from))
                .collect()
        })
        .unwrap_or_default();
    assert!(
        finding_ids.contains(&"fapd-F01".to_string()),
        "the parse failure must still be reported as fapd-F01 under --profile; got {finding_ids:?}"
    );
}

/// The profile filter must NOT turn a check that ACTUALLY FIRED into a false
/// pass. A VALID ruleset whose only finding is fapd-W03 (a fired Warning that
/// carries no control), under `--format sarif --sarif-include-pass --profile
/// stig`, must emit ZERO `kind:"pass"` results. fapolicyd carries no controls, so
/// `--profile` empties the finding set (`no_op`) - and the coverage attestation
/// must be suppressed, else the filtered-out fapd-W03 gets re-listed as passed:
/// the exact coverage overstatement #137 forbids. Distinct from the F01 case
/// above (a parse failure); here the file parsed fine and a real check fired.
#[test]
fn fapolicyd_sarif_pass_attestation_suppressed_when_profile_filters_a_fired_check() {
    let f = tmp_file("allow uid=0 : all # bad comment\n");
    let out = bin()
        .args([
            "fapolicyd",
            "lint",
            "--file",
            f.path().to_str().unwrap(),
            "--format",
            "sarif",
            "--sarif-include-pass",
            "--profile",
            "stig",
        ])
        .output()
        .expect("binary ran");

    // fapolicyd control-less findings are all filtered -> no_op -> exit 9.
    assert_eq!(
        out.status.code(),
        Some(9),
        "--profile empties fapolicyd's control-less findings -> exit 9; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).expect("utf8");
    let v: Value = serde_json::from_str(&stdout).expect("SARIF output must be valid JSON");

    let pass_ids: Vec<String> = v
        .pointer("/runs/0/results")
        .and_then(Value::as_array)
        .map(|rs| {
            rs.iter()
                .filter(|r| r.get("kind").and_then(Value::as_str) == Some("pass"))
                .filter_map(|r| r.get("ruleId").and_then(Value::as_str).map(String::from))
                .collect()
        })
        .unwrap_or_default();
    assert!(
        pass_ids.is_empty(),
        "a profile-filtered fired check must NOT be re-listed as kind:\"pass\"; \
         got passes {pass_ids:?}\n{stdout}"
    );
    // Specifically: the fired code must never be attested as passed.
    assert!(
        !pass_ids.contains(&"fapd-W03".to_string()),
        "the fired fapd-W03 must not be attested as passed; got {pass_ids:?}"
    );
    // The tool.driver.rules[] coverage list must likewise be suppressed.
    let rules_len = v
        .pointer("/runs/0/tool/driver/rules")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    assert_eq!(
        rules_len, 0,
        "the coverage attestation (rules[]) must be suppressed under the no_op filter; \
         stdout:\n{stdout}"
    );
}
