//! End-to-end CLI tests: exercise the built binary offline (via `check`/`derive
//! --file`) and assert the exit-code contract - 0 in sync, 1 on drift, 2 on
//! error. Mirrors `tools/sshd-stig-update/tests/cli.rs` exactly for the
//! contract shape.
//!
//! # RED-state note (session 7c-v0_6-wave3 P2, test-author dispatch)
//!
//! `src/xccdf.rs::parse_requirements`'s body is a single `todo!()` (the
//! extraction algorithm is the implementer's job; see that module's doc
//! comment for the full grounded spec). EVERY test below that reaches
//! `parse_requirements` (i.e. every `check`/`derive` invocation with a
//! readable file and a known product) therefore PANICS today (Rust default
//! panic exit code 101), not the specific 0/1/2 code each test asserts - this
//! is the expected, uniform RED state, not several independent failures. The
//! tests that do NOT reach `parse_requirements` (a missing/unreadable file, an
//! unknown product/subcommand, `--file` without `--product`, `--help`) are
//! GREEN already: they exercise only `source`/`config`, both fully
//! implemented (not stubs).

use std::path::PathBuf;
use std::process::Command;

const RHEL9_FIXTURE: &str = include_str!("fixtures/rhel9_auditd_controls.xml");

/// A minimal XCCDF with only a NON-selected (decoy) Group: no `-a`/`-A`/`-w`
/// line anywhere, so a correct `parse_requirements` returns `Ok(vec![])` -
/// which equals the (currently empty) shipped table, i.e. genuinely IN SYNC.
const EMPTY_SELECTION_XCCDF: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1" id="EMPTY_TEST_FIXTURE">
<title>No audit-rule Groups: only a decoy service check.</title>
<Group id="V-1"><Rule severity="medium"><version>RHEL-09-000001</version>
<check system="C-x"><check-content>Verify the audit service is enabled:
$ sudo systemctl is-enabled auditd
If not "enabled", this is a finding.</check-content></check>
</Rule></Group>
</Benchmark>
"#;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_auditd-stig-update")
}

/// Write `content` to a unique temp file and return its path.
fn temp_xccdf(tag: &str, content: &str) -> PathBuf {
    let path =
        std::env::temp_dir().join(format!("auditd-stig-cli-{}-{tag}.xml", std::process::id()));
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

// --- exit-code contract: 0 in sync -------------------------------------------

#[test]
fn check_empty_selection_file_drifts_against_the_populated_table_exits_1() {
    // The shipped RHEL9_REQUIRED table is now populated (issue #474): a file
    // with no audit-rule Groups derives an empty set, which necessarily
    // drifts against the (now 67-row) shipped table - this keeps coverage of
    // the zero-selection -> drift -> exit-1 path (the mirror-image case of
    // the "both sides empty" wiring pin this test used to be, before
    // population inverted its premise).
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
    assert!(stdout.contains("DRIFT (67 change(s))"), "stdout={stdout}");
}

// --- exit-code contract: 1 drift ---------------------------------------------

#[test]
fn check_real_rhel9_fixture_is_in_sync_with_the_populated_table() {
    // The shipped RHEL9_REQUIRED table is now populated from this same
    // fixture's derived output (issue #474), so the real, non-empty rhel9
    // fixture matches it exactly: 0 drift, 67 rules - mirrors
    // `xccdf.rs`'s `rhel9_fixture_reproduces_code_table_exactly` through the
    // CLI's `check` subcommand.
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
    assert!(stdout.contains("OK (0 drift, 67 rules)"), "stdout={stdout}");
}

#[test]
fn check_file_drift_names_the_removed_v_number() {
    // String-surgery mutation (mirrors sshd's cli.rs `check_file_drift_exits_1`):
    // remove the identity/sudoers watch Group (V-258217) from the fixture, so
    // once xccdf.rs is real, the derived set (missing V-258217) still drifts
    // against the empty shipped table just like the full fixture does - this
    // test additionally proves the diff messages are per-row content, not just
    // a length check. RED today via the todo!() panic.
    let start = RHEL9_FIXTURE
        .find("<Group id=\"V-258217\"")
        .expect("V-258217 group present in fixture");
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

// --- exit-code contract: 2 on error (these are GREEN today: no xccdf::parse
// involved) --------------------------------------------------------------

#[test]
fn check_missing_file_exits_2() {
    let (code, _out, err) = run(&[
        "check",
        "--product",
        "rhel9",
        "--file",
        "/no/such/xccdf.xml",
    ]);
    assert_eq!(code, Some(2), "unreadable source must exit 2");
    assert!(err.contains("auditd-stig-update:"), "err={err}");
}

#[test]
fn check_file_without_product_exits_2() {
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
fn check_unknown_product_exits_2() {
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
fn unknown_subcommand_exits_2() {
    let (code, _out, err) = run(&["frobnicate"]);
    assert_eq!(code, Some(2));
    assert!(err.contains("unknown subcommand"), "err={err}");
}

// --- derive: always exits 0 (a report, not a gate); GREEN-adjacent but still
// reaches parse_requirements, so RED today via the todo!() panic ------------

#[test]
fn derive_file_exits_0() {
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

// --- help/plumbing (GREEN today) --------------------------------------------

#[test]
fn help_exits_0() {
    let (code, _out, err) = run(&["--help"]);
    assert_eq!(code, Some(0), "--help exits 0");
    assert!(
        err.contains("drift-check the auditd au-W06 STIG baselines"),
        "err={err}"
    );
}
