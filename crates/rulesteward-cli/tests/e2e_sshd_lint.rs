//! End-to-end tests for `rulesteward sshd lint` exercising the Wave-A structural
//! lints (sshd-E02/E03/E04, #239) through the real binary: clap parse -> command
//! dispatch -> lint -> human/JSON output -> exit code.
//!
//! Exit-code scheme (shared): 0 clean, 1 warnings, 2 errors. All three codes are
//! Errors, so a triggering config exits 2.

use std::io::Write;

use assert_cmd::Command;

fn bin() -> Command {
    Command::cargo_bin("rulesteward").expect("binary built")
}

/// Write `body` to a temp file and return the handle (kept alive by the caller).
fn config_file(body: &str) -> tempfile::NamedTempFile {
    let mut f = tempfile::NamedTempFile::new().expect("temp file");
    f.write_all(body.as_bytes()).expect("write config");
    f.flush().expect("flush");
    f
}

fn run_lint(path: &std::path::Path, extra: &[&str]) -> std::process::Output {
    let mut args = vec!["sshd", "lint", path.to_str().unwrap()];
    args.extend_from_slice(extra);
    bin().args(args).output().expect("binary ran")
}

#[test]
fn fires_e02_with_exit_two_and_code_in_stdout() {
    let cfg = config_file("PermitRootLogin no\nPermitRootLogin yes\n");
    let out = run_lint(cfg.path(), &[]);
    assert_eq!(out.status.code(), Some(2), "errors exit 2");
    let stdout = String::from_utf8(out.stdout).expect("utf8");
    assert!(
        stdout.contains("sshd-E02"),
        "stdout names the code: {stdout}"
    );
}

#[test]
fn fires_e04_with_exit_two() {
    let cfg = config_file("Match User restricted\n    Ciphers aes256-ctr\n");
    let out = run_lint(cfg.path(), &[]);
    assert_eq!(out.status.code(), Some(2));
    let stdout = String::from_utf8(out.stdout).expect("utf8");
    assert!(stdout.contains("sshd-E04"), "stdout: {stdout}");
}

#[test]
fn fires_e03_with_exit_two() {
    let cfg = config_file("Include /nonexistent-rulesteward-e03-e2e/missing.conf\n");
    let out = run_lint(cfg.path(), &[]);
    assert_eq!(out.status.code(), Some(2));
    let stdout = String::from_utf8(out.stdout).expect("utf8");
    assert!(stdout.contains("sshd-E03"), "stdout: {stdout}");
}

#[test]
fn json_envelope_is_valid_and_carries_the_diagnostic() {
    let cfg = config_file("PermitRootLogin no\nPermitRootLogin yes\n");
    let out = run_lint(cfg.path(), &["--format", "json"]);
    assert_eq!(out.status.code(), Some(2));
    let stdout = String::from_utf8(out.stdout).expect("utf8");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON envelope");
    assert_eq!(v["kind"], "sshd-lint");
    assert_eq!(v["schemaVersion"], 1);
    let diags = v["diagnostics"].as_array().expect("diagnostics array");
    assert!(
        diags.iter().any(|d| d["code"] == "sshd-E02"),
        "envelope carries sshd-E02: {stdout}"
    );
    // Machine-readable output ends with a trailing newline (shell-pipeline safe).
    assert!(stdout.ends_with('\n'), "JSON output ends with a newline");
    // No internal placeholder leakage.
    assert!(
        !stdout.contains("<source>") && !stdout.contains("<TODO>"),
        "no placeholder leakage"
    );
}

#[test]
fn clean_config_exits_zero() {
    let cfg = config_file("PermitRootLogin no\nMaxAuthTries 4\nX11Forwarding no\n");
    let out = run_lint(cfg.path(), &[]);
    assert_eq!(out.status.code(), Some(0), "a clean config exits 0");
    let stdout = String::from_utf8(out.stdout).expect("utf8");
    assert!(
        !stdout.contains("sshd-E0"),
        "no error codes for a clean config"
    );
}
