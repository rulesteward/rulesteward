//! End-to-end graceful-degradation tests for `rulesteward selinux doctor`
//! (#520). Mirrors `e2e_doctor.rs`'s fapolicyd pattern, adapted to the 5
//! selinux checks.

use assert_cmd::Command;
use predicates::prelude::*;

fn bin() -> Command {
    Command::cargo_bin("rulesteward").expect("rulesteward binary")
}

/// `selinux doctor --format json` on this host must:
///   - Not panic (exit code != 101).
///   - Emit stdout that parses as a JSON object (not an error message).
///   - Carry `kind: "selinux-doctor-report"` and `schemaVersion: 1`.
///   - Carry a `checks` array with exactly 5 entries.
///   - Carry a `summary` object.
///   - End with a trailing newline (machine-readable output contract).
///   - Exit with 0, 1, or 2 (never 3, which would indicate a tool-level crash).
#[test]
fn selinux_doctor_json_graceful_degradation() {
    let output = bin()
        .args(["selinux", "doctor", "--format", "json"])
        .output()
        .expect("binary ran");

    assert_ne!(
        output.status.code(),
        Some(101),
        "selinux doctor must not panic; got exit 101"
    );

    let code = output.status.code().expect("process exited normally");
    assert!(
        code == 0 || code == 1 || code == 2,
        "exit code must be 0, 1, or 2; got {code}"
    );

    let stdout = String::from_utf8(output.stdout.clone()).expect("stdout is UTF-8");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("stdout must be valid JSON");

    assert_eq!(
        v["kind"].as_str(),
        Some("selinux-doctor-report"),
        "kind must be selinux-doctor-report; got: {stdout}"
    );
    assert_eq!(
        v["schemaVersion"].as_u64(),
        Some(1),
        "schemaVersion must be 1; got: {stdout}"
    );

    let checks = v["checks"].as_array().expect("checks must be a JSON array");
    assert_eq!(
        checks.len(),
        5,
        "selinux doctor must produce exactly 5 checks; got {}",
        checks.len()
    );

    assert!(
        v["summary"].is_object(),
        "summary must be a JSON object; got: {stdout}"
    );

    assert!(
        stdout.ends_with('\n'),
        "JSON output must end with a trailing newline"
    );

    for bad in &[
        "<source>",
        "<unknown>",
        "<placeholder>",
        "TODO",
        "panic",
        "dbg!",
    ] {
        assert!(
            !stdout.contains(bad),
            "stdout must not contain debug token {bad:?}; got: {stdout}"
        );
    }
}

/// `selinux doctor` (human format, the default) must not panic and must emit
/// a non-empty human-readable scorecard to stdout.
#[test]
fn selinux_doctor_human_format_does_not_panic() {
    bin()
        .args(["selinux", "doctor"])
        .assert()
        .code(predicate::in_iter([0i32, 1, 2]))
        .stdout(predicate::str::contains("selinux doctor report"))
        .stdout(predicate::str::contains("Summary:"));
}

/// `selinux --help` must mention the `doctor` verb.
#[test]
fn selinux_help_mentions_doctor_verb() {
    bin()
        .args(["selinux", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("doctor"));
}

/// `selinux doctor --help` must render and include key flags.
#[test]
fn selinux_doctor_help_renders_expected_flags() {
    bin()
        .args(["selinux", "doctor", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--format"))
        .stdout(predicate::str::contains("--target"));
}
