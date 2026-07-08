//! End-to-end CLI tests: exercise the built binary OFFLINE (via `check`/`derive
//! --transcript`) against the committed probe fixtures and assert the exit-code
//! contract - 0 in sync, 1 on drift, 2 on error. The docker LIVE path is not
//! exercised here (no docker in CI); the offline transcript path is the core.

use std::path::PathBuf;
use std::process::Command;

const RHEL9_FIXTURE: &str = include_str!("fixtures/rhel9_probe.jsonl");

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_sshd-probe-update")
}

/// Absolute path to a committed fixture (robust regardless of the test cwd).
fn fixture(name: &str) -> String {
    format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))
}

/// Write `content` to a unique temp file and return its path.
fn temp_jsonl(tag: &str, content: &str) -> PathBuf {
    let path =
        std::env::temp_dir().join(format!("sshd-probe-cli-{}-{tag}.jsonl", std::process::id()));
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

#[test]
fn check_rhel9_transcript_in_sync_exits_0() {
    let (code, stdout, err) = run(&[
        "check",
        "--product",
        "rhel9",
        "--transcript",
        &fixture("rhel9_probe.jsonl"),
    ]);
    assert_eq!(
        code,
        Some(0),
        "in-sync must exit 0; stdout={stdout} err={err}"
    );
    assert!(stdout.contains("OK (0 drift)"), "stdout={stdout}");
}

#[test]
fn check_rhel8_transcript_in_sync_exits_0() {
    let (code, stdout, _e) = run(&[
        "check",
        "--product",
        "rhel8",
        "--transcript",
        &fixture("rhel8_probe.jsonl"),
    ]);
    assert_eq!(code, Some(0), "rhel8 in-sync must exit 0; stdout={stdout}");
    assert!(stdout.contains("OK (0 drift)"), "stdout={stdout}");
}

#[test]
fn check_rhel10_transcript_in_sync_exits_0() {
    let (code, stdout, _e) = run(&[
        "check",
        "--product",
        "rhel10",
        "--transcript",
        &fixture("rhel10_probe.jsonl"),
    ]);
    assert_eq!(code, Some(0), "rhel10 in-sync must exit 0; stdout={stdout}");
    assert!(stdout.contains("OK (0 drift)"), "stdout={stdout}");
}

/// The `--file` alias must behave identically to `--transcript`.
#[test]
fn check_file_alias_works() {
    let (code, stdout, _e) = run(&[
        "check",
        "--product",
        "rhel9",
        "--file",
        &fixture("rhel9_probe.jsonl"),
    ]);
    assert_eq!(code, Some(0), "stdout={stdout}");
    assert!(stdout.contains("OK (0 drift)"));
}

/// Flipping a known keyword's `opt` stderr to `Bad configuration option` makes
/// the probe no longer confirm the table's entry -> E01 drift, exit 1, keyword named.
#[test]
fn check_synthesized_drift_exits_1_and_names_keyword() {
    let mutated = RHEL9_FIXTURE.replacen(
        "{\"kw\": \"acceptenv\", \"probe\": \"opt\", \"rc\": 0, \"stderr\": \"\"}",
        "{\"kw\": \"acceptenv\", \"probe\": \"opt\", \"rc\": 255, \"stderr\": \"command-line line 0: Bad configuration option: acceptenv\"}",
        1,
    );
    assert_ne!(mutated, RHEL9_FIXTURE, "the acceptenv opt line must exist");
    let f = temp_jsonl("drift", &mutated);
    let (code, stdout, _e) = run(&[
        "check",
        "--product",
        "rhel9",
        "--transcript",
        &f.to_string_lossy(),
    ]);
    assert_eq!(code, Some(1), "drift must exit 1; stdout={stdout}");
    assert!(stdout.contains("DRIFT"), "stdout={stdout}");
    assert!(
        stdout.contains("acceptenv"),
        "the drift must name acceptenv; stdout={stdout}"
    );
}

#[test]
fn check_missing_transcript_exits_2() {
    let (code, _out, err) = run(&[
        "check",
        "--product",
        "rhel9",
        "--transcript",
        "/no/such/probe.jsonl",
    ]);
    assert_eq!(code, Some(2), "unreadable transcript must exit 2");
    assert!(err.contains("sshd-probe-update:"), "err={err}");
}

#[test]
fn check_transcript_without_single_product_exits_2() {
    let (code, _out, err) = run(&["check", "--transcript", &fixture("rhel9_probe.jsonl")]);
    assert_eq!(
        code,
        Some(2),
        "--transcript without a single --product must exit 2"
    );
    assert!(
        err.contains("--transcript requires exactly one --product"),
        "err={err}"
    );
}

#[test]
fn unknown_subcommand_exits_2() {
    let (code, _out, err) = run(&["frobnicate"]);
    assert_eq!(code, Some(2));
    assert!(err.contains("unknown subcommand"), "err={err}");
}

#[test]
fn help_exits_0() {
    let (code, _out, err) = run(&["--help"]);
    assert_eq!(code, Some(0));
    assert!(
        err.contains("drift-check the sshd E01/E04/W04 tables"),
        "err={err}"
    );
}

#[test]
fn derive_transcript_exits_0_and_reproduces_rows() {
    let (code, stdout, _e) = run(&[
        "derive",
        "--product",
        "rhel9",
        "--transcript",
        &fixture("rhel9_probe.jsonl"),
    ]);
    assert_eq!(code, Some(0), "stdout={stdout}");
    assert!(
        stdout.contains("no drift vs the shipped tables"),
        "stdout={stdout}"
    );
    // The paste-ready E01 block must reproduce a real derived keyword row.
    assert!(
        stdout.contains("\"acceptenv\","),
        "expected a quoted acceptenv row; stdout={stdout}"
    );
    // And a probe-derived deprecated keyword row.
    assert!(
        stdout.contains("\"rsaauthentication\","),
        "expected a deprecated keyword row; stdout={stdout}"
    );
}
