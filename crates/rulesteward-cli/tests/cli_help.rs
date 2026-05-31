//! `--help` smoke tests - verify that clap renders the full subcommand
//! tree (fapolicyd / selinux / auditd) and that `fapolicyd lint --help`
//! exposes the `--file`, `--format`, and `--against-trustdb` flags.

use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn root_help_renders_and_exits_zero() {
    Command::cargo_bin("rulesteward")
        .expect("binary built")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("fapolicyd"))
        .stdout(predicate::str::contains("selinux"))
        .stdout(predicate::str::contains("auditd"));
}

#[test]
fn fapolicyd_lint_help_lists_format_flag() {
    Command::cargo_bin("rulesteward")
        .expect("binary built")
        .args(["fapolicyd", "lint", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--format"))
        .stdout(predicate::str::contains("--file"))
        .stdout(predicate::str::contains("--against-trustdb"));
}

#[test]
fn root_help_lists_completions_subcommand() {
    Command::cargo_bin("rulesteward")
        .expect("binary built")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("completions"));
}

#[test]
fn completions_help_lists_supported_shells() {
    Command::cargo_bin("rulesteward")
        .expect("binary built")
        .args(["completions", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("bash"))
        .stdout(predicate::str::contains("zsh"))
        .stdout(predicate::str::contains("fish"))
        .stdout(predicate::str::contains("elvish"))
        .stdout(predicate::str::contains("power-shell"))
        .stdout(predicate::str::contains("tcsh"));
}
