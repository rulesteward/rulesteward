//! End-to-end tests for `rulesteward selinux` subcommands.
//!
//! These end-to-end tests cover the `selinux triage` input-validation path only
//! (missing-flag errors and `--help`). The renderers are implemented; their
//! output is covered by the selinux crate's `triage_render_human.rs`,
//! `te_emit_unit.rs`, and `known_answer_categorize.rs`.

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
