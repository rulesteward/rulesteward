//! End-to-end CLI tests via `assert_cmd`. These exercise the whole pipeline:
//! argv → clap parse → command dispatch → `lint_file` → render → exit code.
//!
//! One test per exit-code path. The temp files are minimal - they exercise
//! the path through the code, not the full lint surface (the parser and
//! lint walker have their own dedicated test suites in
//! `rulesteward-fapolicyd`).

use assert_cmd::Command;
use predicates::prelude::*;
use std::io::Write;

fn write_tmp(contents: &str) -> tempfile::NamedTempFile {
    let mut f = tempfile::NamedTempFile::new().expect("tempfile");
    write!(f, "{contents}").expect("write");
    f
}

#[test]
fn lint_clean_file_exits_zero() {
    let f = write_tmp("allow uid=0 : all\n");
    Command::cargo_bin("rulesteward")
        .expect("binary")
        .args(["fapolicyd", "lint", "--file"])
        .arg(f.path())
        .assert()
        .code(0);
}

#[test]
fn lint_file_with_warning_exits_one() {
    // Inline-trailing-# triggers W03 (Warning).
    let f = write_tmp("allow uid=0 : all # bad comment\n");
    Command::cargo_bin("rulesteward")
        .expect("binary")
        .args(["fapolicyd", "lint", "--file"])
        .arg(f.path())
        .assert()
        .code(1)
        .stdout(predicate::str::contains("[W03]"));
}

#[test]
fn lint_file_with_syntax_error_exits_five() {
    let f = write_tmp("!!!garbage line\n");
    let path_str = f.path().to_str().expect("utf8 path");
    Command::cargo_bin("rulesteward")
        .expect("binary")
        .args(["fapolicyd", "lint", "--file"])
        .arg(f.path())
        .assert()
        .code(5)
        .stdout(predicate::str::contains("[F01]"))
        .stdout(predicate::str::contains(path_str));
}

#[test]
fn lint_json_format_emits_array() {
    let f = write_tmp("allow uid=0 : all # bad\n");
    Command::cargo_bin("rulesteward")
        .expect("binary")
        .args(["fapolicyd", "lint", "--format", "json", "--file"])
        .arg(f.path())
        .assert()
        .code(1)
        .stdout(predicate::str::contains("\"W03\""))
        .stdout(predicate::str::starts_with("["));
}

#[test]
fn lint_sarif_format_exits_three_with_not_implemented_error() {
    let f = write_tmp("allow uid=0 : all\n");
    Command::cargo_bin("rulesteward")
        .expect("binary")
        .args(["fapolicyd", "lint", "--format", "sarif", "--file"])
        .arg(f.path())
        .assert()
        .code(3)
        .stdout(predicate::str::contains("sarif format not yet implemented"));
}

#[test]
fn against_trustdb_stub_exits_nine() {
    let f = write_tmp("allow uid=0 : all\n");
    Command::cargo_bin("rulesteward")
        .expect("binary")
        .args([
            "fapolicyd",
            "lint",
            "--against-trustdb",
            "/var/lib/fapolicyd/data.mdb",
            "--file",
        ])
        .arg(f.path())
        .assert()
        .code(9)
        .stderr(predicate::str::contains("not yet implemented"));
}

#[test]
fn selinux_triage_stub_exits_nine() {
    Command::cargo_bin("rulesteward")
        .expect("binary")
        .args(["selinux", "triage"])
        .assert()
        .code(9);
}

#[test]
fn auditd_cost_stub_exits_nine() {
    Command::cargo_bin("rulesteward")
        .expect("binary")
        .args(["auditd", "cost"])
        .assert()
        .code(9);
}

#[test]
fn unknown_subcommand_exits_three_not_two() {
    Command::cargo_bin("rulesteward")
        .expect("binary")
        .args(["nonsense"])
        .assert()
        .code(3);
}
