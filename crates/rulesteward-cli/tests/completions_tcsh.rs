//! Structural end-to-end tests for `rulesteward completions tcsh`.
//!
//! These tests assert the shape of a correct tcsh completion script without
//! pinning every byte of output, so they remain stable across minor generator
//! changes. They are authored RED: the stub generator in completions.rs emits
//! an empty string, so all assertions about non-empty output and required
//! keywords will fail until a real tcsh generator is implemented.

use assert_cmd::Command;

/// `rulesteward completions tcsh` must exit 0 and produce non-empty output.
/// RED with the stub (empty output).
#[test]
fn tcsh_completions_exit_zero_and_non_empty() {
    let out = Command::cargo_bin("rulesteward")
        .expect("binary")
        .args(["completions", "tcsh"])
        .output()
        .expect("run");
    assert!(
        out.status.success(),
        "exit code must be 0; got: {:?}",
        out.status.code()
    );
    assert!(
        !out.stdout.is_empty(),
        "stdout must not be empty; stub emits nothing"
    );
}

/// The output must contain a tcsh `complete` directive.
/// tcsh completion scripts begin with `complete <name> ...`.
/// RED with the stub (no output at all).
#[test]
fn tcsh_completions_contains_complete_directive() {
    let out = Command::cargo_bin("rulesteward")
        .expect("binary")
        .args(["completions", "tcsh"])
        .output()
        .expect("run");
    assert!(out.status.success(), "exit code: {:?}", out.status.code());
    let s = std::str::from_utf8(&out.stdout).expect("utf8");
    assert!(
        s.contains("complete"),
        "tcsh completion script must contain a `complete` directive; got: {s}"
    );
}

/// The output must reference the binary name `rulesteward` in the `complete` line.
/// A tcsh script starts with `complete rulesteward ...`.
/// RED with the stub.
#[test]
fn tcsh_completions_references_binary_name() {
    let out = Command::cargo_bin("rulesteward")
        .expect("binary")
        .args(["completions", "tcsh"])
        .output()
        .expect("run");
    assert!(out.status.success(), "exit code: {:?}", out.status.code());
    let s = std::str::from_utf8(&out.stdout).expect("utf8");
    assert!(
        s.contains("rulesteward"),
        "tcsh completion script must reference the binary name `rulesteward`; got: {s}"
    );
}

/// The output must list the real top-level subcommand `fapolicyd` so completions
/// are actually useful.
/// RED with the stub.
#[test]
fn tcsh_completions_references_fapolicyd_subcommand() {
    let out = Command::cargo_bin("rulesteward")
        .expect("binary")
        .args(["completions", "tcsh"])
        .output()
        .expect("run");
    assert!(out.status.success(), "exit code: {:?}", out.status.code());
    let s = std::str::from_utf8(&out.stdout).expect("utf8");
    assert!(
        s.contains("fapolicyd"),
        "tcsh completion script must reference the `fapolicyd` subcommand; got: {s}"
    );
}

/// The output must list the `completions` subcommand so that shell-completion
/// of the completions subcommand itself works.
/// RED with the stub.
#[test]
fn tcsh_completions_references_completions_subcommand() {
    let out = Command::cargo_bin("rulesteward")
        .expect("binary")
        .args(["completions", "tcsh"])
        .output()
        .expect("run");
    assert!(out.status.success(), "exit code: {:?}", out.status.code());
    let s = std::str::from_utf8(&out.stdout).expect("utf8");
    assert!(
        s.contains("completions"),
        "tcsh completion script must reference the `completions` subcommand; got: {s}"
    );
}

/// Pipe to `head -1` must not panic or return a non-zero exit code
/// (`BrokenPipe` must be swallowed by `EpipeSwallowingWriter`).
///
/// This test verifies the `EpipeSwallowingWriter` path is exercised for tcsh.
/// With the stub the output is empty so head exits immediately; the real
/// generator will produce enough bytes to trigger a genuine pipe-close.
/// The test is still worth authoring: it must stay green through both phases.
#[test]
fn tcsh_completions_pipe_to_head_does_not_panic() {
    use std::process::{Command as StdCommand, Stdio};

    let mut completions = StdCommand::new(assert_cmd::cargo::cargo_bin("rulesteward"))
        .args(["completions", "tcsh"])
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn rulesteward");

    let head_status = StdCommand::new("head")
        .arg("-1")
        .stdin(completions.stdout.take().expect("piped stdout"))
        .status()
        .expect("spawn head");

    let status = completions.wait().expect("wait rulesteward");
    assert!(
        head_status.success(),
        "head must exit 0; got: {:?}",
        head_status.code()
    );
    assert!(
        status.success(),
        "rulesteward must exit 0 even after pipe close; got: {:?}",
        status.code()
    );
}
