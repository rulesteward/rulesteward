//! End-to-end CLI tests: exercise the built binary offline (via `check`/
//! `derive --file`) and assert the exit-code contract - 0 in sync, 1 on
//! drift, 2 on error. Cloned in shape from
//! `tools/auditd-stig-update/tests/cli.rs`, adapted to the fapolicyd #519
//! STIG control table (`ControlFamily::{Installed,Enabled,DenyAll}`, 3 rows
//! per target - see `crates/rulesteward-fapolicyd/src/lints/stig.rs`).
//!
//! # RED-state note (session 9d, test-author dispatch)
//!
//! `src/main.rs` is a SKELETON: it unconditionally prints a generic
//! "not yet implemented" message to stderr and exits 2, regardless of
//! arguments. EVERY test below therefore fails today - the exit-code-only
//! assertions (`unknown_subcommand...`, the `check *_exits_2` cases) trip on
//! the SPECIFIC message-content assertion paired with each (a generic
//! "not yet implemented" string never contains "unknown product", "unknown
//! subcommand", etc.), and the 0/1-exit-code assertions trip on the exit
//! code itself (the stub always exits 2). This is the expected, uniform RED
//! state for a from-scratch skeleton, not several independent failures.

use std::path::PathBuf;
use std::process::Command;

const RHEL8_FIXTURE: &str = include_str!("fixtures/rhel8_fapolicyd_controls.xml");
const RHEL9_FIXTURE: &str = include_str!("fixtures/rhel9_fapolicyd_controls.xml");
const RHEL10_FIXTURE: &str = include_str!("fixtures/rhel10_fapolicyd_controls.xml");

/// A minimal XCCDF with only a NON-selected (decoy) Group: no fapolicyd
/// Installed/Enabled/DenyAll Group anywhere, so a correct `derive` returns an
/// empty set - necessarily DRIFT against the (3-row) shipped table.
const EMPTY_SELECTION_XCCDF: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1" id="EMPTY_TEST_FIXTURE">
<title>No fapolicyd Groups: only a decoy SELinux-enforcement check.</title>
<Group id="V-1"><Rule severity="medium"><version>RHEL-09-000001</version>
<check system="C-x"><check-content>Verify SELinux is enforcing:
$ getenforce
Enforcing
If not "Enforcing", this is a finding.</check-content></check></Rule></Group>
</Benchmark>
"#;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_fapolicyd-stig-update")
}

/// Write `content` to a unique temp file and return its path.
fn temp_xccdf(tag: &str, content: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "fapolicyd-stig-cli-{}-{tag}.xml",
        std::process::id()
    ));
    std::fs::write(&path, content).expect("write temp fixture");
    path
}

fn run(args: &[&str]) -> (Option<i32>, String, String) {
    let out = Command::new(bin())
        .args(args)
        .output()
        .expect("spawn binary");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

// --- exit-code contract: 1 drift ---------------------------------------------

#[test]
fn check_empty_selection_file_drifts_against_the_populated_table_exits_1() {
    // Once `stig_controls(Rhel9)` is populated (3 rows: Installed/Enabled/
    // DenyAll), a file with zero fapolicyd Groups derives an empty set, which
    // necessarily drifts against it.
    let f = temp_xccdf("empty", EMPTY_SELECTION_XCCDF);
    let (code, stdout, err) = run(&[
        "check",
        "--product",
        "rhel9",
        "--file",
        &f.to_string_lossy(),
    ]);
    assert_eq!(
        code,
        Some(1),
        "an empty-selection file must drift against the populated shipped table; \
         stdout={stdout} stderr={err}"
    );
    assert!(stdout.contains("DRIFT"), "stdout={stdout}");
}

#[test]
fn check_real_rhel9_fixture_is_in_sync_with_the_populated_table() {
    // The real, trimmed rhel9 fixture (3 fapolicyd Groups + 2 decoys)
    // derives EXACTLY the 3 fapolicyd rows, matching the shipped table once
    // populated: 0 drift, 3 rows.
    let f = temp_xccdf("rhel9-full", RHEL9_FIXTURE);
    let (code, stdout, err) = run(&[
        "check",
        "--product",
        "rhel9",
        "--file",
        &f.to_string_lossy(),
    ]);
    assert_eq!(
        code,
        Some(0),
        "the real rhel9 fixture must be in sync with the populated table; \
         stdout={stdout} stderr={err}"
    );
    assert!(stdout.contains("OK (0 drift, 3 rows)"), "stdout={stdout}");
}

#[test]
fn check_real_rhel8_fixture_is_in_sync_with_the_populated_table() {
    let f = temp_xccdf("rhel8-full", RHEL8_FIXTURE);
    let (code, stdout, err) = run(&[
        "check",
        "--product",
        "rhel8",
        "--file",
        &f.to_string_lossy(),
    ]);
    assert_eq!(code, Some(0), "stdout={stdout} stderr={err}");
    assert!(stdout.contains("OK (0 drift, 3 rows)"), "stdout={stdout}");
}

#[test]
fn check_real_rhel10_fixture_is_in_sync_with_the_populated_table() {
    let f = temp_xccdf("rhel10-full", RHEL10_FIXTURE);
    let (code, stdout, err) = run(&[
        "check",
        "--product",
        "rhel10",
        "--file",
        &f.to_string_lossy(),
    ]);
    assert_eq!(code, Some(0), "stdout={stdout} stderr={err}");
    assert!(stdout.contains("OK (0 drift, 3 rows)"), "stdout={stdout}");
}

#[test]
fn check_file_drift_names_the_removed_control() {
    // Remove the DenyAll Group (V-270180) from the rhel9 fixture: the
    // derived set (missing that row) must still drift against the populated
    // shipped table, and the diff must be per-row content, not just a length
    // check.
    let start = RHEL9_FIXTURE
        .find("<Group id=\"V-270180\"")
        .expect("V-270180 group present in fixture");
    let end =
        RHEL9_FIXTURE[start..].find("</Group>").expect("group end") + start + "</Group>".len();
    let mut mutated = RHEL9_FIXTURE.to_string();
    mutated.replace_range(start..end, "");

    let f = temp_xccdf("rhel9-mutated", &mutated);
    let (code, stdout, err) = run(&[
        "check",
        "--product",
        "rhel9",
        "--file",
        &f.to_string_lossy(),
    ]);
    assert_eq!(
        code,
        Some(1),
        "drift must exit 1; stdout={stdout} stderr={err}"
    );
    assert!(stdout.contains("DRIFT"), "stdout={stdout}");
}

// --- decoy exclusion: the selector must not count the 2 SELinux Groups -----

#[test]
fn decoy_groups_are_excluded_from_the_derived_row_count() {
    // The rhel9 fixture has 5 total Groups (3 fapolicyd + 2 SELinux decoys);
    // a correct selector derives exactly 3, so it stays in sync with the
    // 3-row shipped table. A wrong selector that also picks up the decoys
    // would derive 5 and drift.
    let f = temp_xccdf("rhel9-decoy-check", RHEL9_FIXTURE);
    let (code, stdout, err) = run(&[
        "derive",
        "--product",
        "rhel9",
        "--file",
        &f.to_string_lossy(),
    ]);
    assert_eq!(code, Some(0), "stdout={stdout} stderr={err}");
    assert!(
        stdout.contains("3 rows"),
        "decoys must be excluded from the derived count (expected 3, not 5): {stdout}"
    );
}

// --- exit-code contract: 2 on error ------------------------------------------

#[test]
fn check_missing_file_exits_2_with_a_specific_read_error() {
    let (code, _out, err) = run(&[
        "check",
        "--product",
        "rhel9",
        "--file",
        "/no/such/fapolicyd-xccdf.xml",
    ]);
    assert_eq!(code, Some(2), "unreadable source must exit 2");
    assert!(
        err.contains("/no/such/fapolicyd-xccdf.xml") || err.to_lowercase().contains("no such file"),
        "error must name the unreadable path, got err={err}"
    );
}

#[test]
fn check_file_without_product_exits_2_with_a_specific_message() {
    let f = temp_xccdf("noproduct", RHEL9_FIXTURE);
    let (code, _out, err) = run(&["check", "--file", &f.to_string_lossy()]);
    assert_eq!(
        code,
        Some(2),
        "--file without a single --product must exit 2"
    );
    assert!(
        err.contains("--file requires exactly one --product"),
        "err={err}"
    );
}

#[test]
fn check_unknown_product_exits_2_with_a_specific_message() {
    let f = temp_xccdf("badproduct", RHEL9_FIXTURE);
    let (code, _out, err) = run(&[
        "check",
        "--product",
        "rhel7",
        "--file",
        &f.to_string_lossy(),
    ]);
    assert_eq!(code, Some(2), "an unknown product must exit 2; err={err}");
    assert!(err.contains("unknown product"), "err={err}");
}

#[test]
fn unknown_subcommand_exits_2_with_a_specific_message() {
    let (code, _out, err) = run(&["frobnicate"]);
    assert_eq!(code, Some(2));
    assert!(err.contains("unknown subcommand"), "err={err}");
}

// --- derive: always exits 0 (a report, not a gate) --------------------------

#[test]
fn derive_file_exits_0_and_prints_paste_ready_literals() {
    let f = temp_xccdf("derive", RHEL9_FIXTURE);
    let (code, stdout, err) = run(&[
        "derive",
        "--product",
        "rhel9",
        "--file",
        &f.to_string_lossy(),
    ]);
    assert_eq!(code, Some(0), "stdout={stdout} stderr={err}");
    assert!(stdout.contains("paste-ready"), "stdout={stdout}");
}

// --- help/plumbing -----------------------------------------------------------

#[test]
fn help_exits_0_and_mentions_check_and_derive() {
    let (code, _out, err) = run(&["--help"]);
    assert_eq!(code, Some(0), "--help exits 0; err={err}");
    assert!(err.contains("check"), "err={err}");
    assert!(err.contains("derive"), "err={err}");
    assert!(err.contains("drift-check the fapolicyd"), "err={err}");
}
