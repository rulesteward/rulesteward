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
fn all_fapolicyd_subcommands_visible_in_help() {
    // No hidden no-op stubs remain: migrate shipped in #187, so every fapolicyd
    // subcommand is visible in --help. explain/triage/cost (v0.2 round 1),
    // simulate/report (round 2), doctor (#76/#77/#78), container-check (#175),
    // migrate (#187).
    let bin = || Command::cargo_bin("rulesteward").expect("binary built");

    bin()
        .args(["fapolicyd", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("lint"))
        .stdout(predicate::str::contains("trustdb"))
        .stdout(predicate::str::contains("explain")) // now visible
        .stdout(predicate::str::contains("simulate")) // now visible (round 2)
        .stdout(predicate::str::contains("report")) // now visible (round 2)
        .stdout(predicate::str::contains("doctor")) // now visible (#76/#77/#78)
        .stdout(predicate::str::contains("container-check")) // now visible (#175)
        .stdout(predicate::str::contains("migrate")); // now visible (#187)

    bin()
        .args(["selinux", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("triage")); // now visible

    bin()
        .args(["auditd", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("cost")); // now visible
}

#[test]
fn fapolicyd_simulate_help_lists_flags() {
    Command::cargo_bin("rulesteward")
        .expect("binary built")
        .args(["fapolicyd", "simulate", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--rules"))
        .stdout(predicate::str::contains("--workload"))
        .stdout(predicate::str::contains("--format"));
}

#[test]
fn fapolicyd_report_help_lists_flags() {
    Command::cargo_bin("rulesteward")
        .expect("binary built")
        .args(["fapolicyd", "report", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--diff-against"))
        .stdout(predicate::str::contains("--fail-on-drift"))
        .stdout(predicate::str::contains("--format"));
}

#[test]
fn fapolicyd_explain_help_lists_flags() {
    Command::cargo_bin("rulesteward")
        .expect("binary built")
        .args(["fapolicyd", "explain", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--record"))
        .stdout(predicate::str::contains("--ruleset"))
        .stdout(predicate::str::contains("--format"));
}

#[test]
fn auditd_cost_help_lists_flags() {
    Command::cargo_bin("rulesteward")
        .expect("binary built")
        .args(["auditd", "cost", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--rules"))
        .stdout(predicate::str::contains("--price-per-gb"))
        .stdout(predicate::str::contains("--format"));
}

#[test]
fn selinux_triage_help_lists_flags() {
    Command::cargo_bin("rulesteward")
        .expect("binary built")
        .args(["selinux", "triage", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--emit-te"))
        .stdout(predicate::str::contains("--format"));
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
