//! End-to-end tests for `rulesteward selinux` subcommands.
//!
//! Only the input-validation path is testable in the frozen state: the render
//! path hits `todo!()` inside `triage.rs` / `te_emit.rs` (P3/P4 fill those).
//! Tests that would invoke a renderer are intentionally absent.

use assert_cmd::Command;
use predicates::prelude::*;

/// `selinux triage` with neither `--record` nor `--audit-log` must print the
/// required-argument error to stderr and exit 2 (`EXIT_ERRORS`).
///
/// TDD note: before the frozen arm replaced the `todo!()`, this test failed
/// because the `todo!()` panicked (exit 101) instead of printing the message
/// and exiting 2.
#[test]
fn triage_no_input_flag_errors_with_message() {
    Command::cargo_bin("rulesteward")
        .expect("binary built")
        .args(["selinux", "triage"])
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains(
            "one of --record or --audit-log is required",
        ));
}

/// `selinux triage --help` still renders (the frozen `--help` test from P0.3
/// must continue to pass).
#[test]
fn triage_help_still_renders() {
    Command::cargo_bin("rulesteward")
        .expect("binary built")
        .args(["selinux", "triage", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--emit-te"))
        .stdout(predicate::str::contains("--format"));
}
