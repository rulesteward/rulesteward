//! End-to-end graceful-degradation tests for `rulesteward fapolicyd
//! container-check`.
//!
//! These exercise the real `LiveContainerProbe` against whatever host the test
//! runs on (a bare CI box, a dev box with podman, etc.). The host's exact
//! verdict is not asserted -- only that the command degrades gracefully (never
//! panics), emits a valid envelope, and returns a documented exit code. The
//! per-verdict classification logic is covered by the `FakeProbe` unit tests in
//! `commands::container_check::checks`.

use assert_cmd::Command;

fn bin() -> Command {
    Command::cargo_bin("rulesteward").expect("binary built")
}

/// `container-check --format json` emits a valid `container-check` envelope and
/// exits with a documented code (0/1/2/3), never panicking (101).
#[test]
fn container_check_json_is_valid_and_exits_documented_code() {
    let output = bin()
        .args(["fapolicyd", "container-check", "--format", "json"])
        .output()
        .expect("binary ran");

    let code = output.status.code().expect("process exited normally");
    assert!(
        [0, 1, 2, 3].contains(&code),
        "exit code must be one of 0/1/2/3, got {code}"
    );

    let stdout = String::from_utf8(output.stdout).expect("UTF-8 stdout");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON envelope");
    assert_eq!(v["kind"], "container-check");
    assert_eq!(v["schemaVersion"], 1);
    assert!(v["runtimes"].is_array(), "runtimes array present");
    assert!(v["findings"].is_array(), "findings array present");
    // No placeholder text must leak into operator-facing output.
    assert!(
        !stdout.contains("paid-product-url") && !stdout.contains("<TODO>"),
        "no placeholder leakage in container-check output"
    );
}

/// The human renderer runs end-to-end without panicking and prints the header.
#[test]
fn container_check_human_renders() {
    let output = bin()
        .args(["fapolicyd", "container-check"])
        .output()
        .expect("binary ran");
    let code = output.status.code().expect("process exited normally");
    assert!([0, 1, 2, 3].contains(&code), "documented exit, got {code}");
    let stdout = String::from_utf8(output.stdout).expect("UTF-8");
    assert!(
        stdout.contains("fapolicyd container-check"),
        "header present"
    );
}

/// `--deep` without root degrades gracefully: the daemon reads simply return no
/// evidence rather than crashing. Still a documented exit code.
#[test]
fn container_check_deep_degrades_without_root() {
    let output = bin()
        .args(["fapolicyd", "container-check", "--deep", "--format", "json"])
        .output()
        .expect("binary ran");
    let code = output.status.code().expect("process exited normally");
    assert!([0, 1, 2, 3].contains(&code), "documented exit, got {code}");
    let stdout = String::from_utf8(output.stdout).expect("UTF-8");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    // --deep attaches the evidence object even when the daemon reads come back empty.
    assert!(
        v.get("deep").is_some(),
        "deep evidence object present under --deep"
    );
}
