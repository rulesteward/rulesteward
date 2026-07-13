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
//!  * `sysctld-W01` (last-wins) attaches NO controls -> dropped by any profile.
//!  * `sudo-W04` missing-`use_pty` / missing-I/O-log attach `Framework::Cis`
//!    (1.3.2 / 1.3.3) + `Framework::Pci` (`rulesteward-sudoers/src/lints/stig.rs`).
//!  * fapolicyd findings attach NO controls -> any profile empties them.
//!  * `Framework::Nist` is attached by NO lint today -> `--profile nist` empties
//!    any non-empty finding set.

use std::io::Write;

use assert_cmd::Command;

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

/// A `sysctl lint --target rhel9` run whose only findings are `sysctld-W02` (all
/// STIG-tagged). `--profile stig` retains every one, so BOTH the exit code and the
/// stdout are byte-identical to the no-`--profile` baseline. This pins (a) STIG
/// retention and (b) that the filter is a no-op when everything matches.
#[test]
fn sysctl_profile_stig_retains_all_and_is_byte_identical_to_baseline() {
    let cfg = tmp_file("# nothing hardened here\nkernel.sysrq = 0\n");
    let path = cfg.path().to_str().unwrap();

    let baseline = bin()
        .args(["sysctl", "lint", path, "--target", "rhel9"])
        .output()
        .expect("baseline ran");
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

    // Baseline sanity: the fixture yields STIG W02 findings (exit 1), else the
    // identity below would be a vacuous 0==0 / empty==empty.
    assert_eq!(
        baseline.status.code(),
        Some(1),
        "unhardened config under --target rhel9 warns (exit 1); stderr: {}",
        String::from_utf8_lossy(&baseline.stderr)
    );
    let baseline_stdout = String::from_utf8(baseline.stdout).expect("utf8");
    assert!(
        baseline_stdout.contains("sysctld-W02"),
        "baseline must carry the STIG W02 findings; stdout: {baseline_stdout}"
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
/// `sudo-W04` merged-absence warnings (CIS 1.3.2 / 1.3.3, + PCI). Grounded in
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
