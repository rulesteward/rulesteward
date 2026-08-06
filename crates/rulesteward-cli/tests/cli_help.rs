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
    // Every fapolicyd subcommand is visible in --help; no hidden no-op stubs
    // remain.
    let bin = || Command::cargo_bin("rulesteward").expect("binary built");

    bin()
        .args(["fapolicyd", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("lint"))
        .stdout(predicate::str::contains("trustdb"))
        .stdout(predicate::str::contains("explain"))
        .stdout(predicate::str::contains("simulate"))
        .stdout(predicate::str::contains("report"))
        .stdout(predicate::str::contains("doctor"))
        .stdout(predicate::str::contains("container-check"))
        .stdout(predicate::str::contains("migrate"));

    bin()
        .args(["selinux", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("triage"));

    bin()
        .args(["auditd", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("cost"));
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
fn auditd_cost_help_documents_measured_byte_size() {
    // #307: --from-log measures the per-event SIZE (real on-disk bytes) in
    // addition to the per-key event RATE, so --help must say the size is measured
    // and must not carry an "under-counts" bias caveat.
    Command::cargo_bin("rulesteward")
        .expect("binary built")
        .args(["auditd", "cost", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("per-event on-disk bytes"))
        .stdout(predicate::str::contains("under-counts").not());
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

#[test]
fn sudoers_lint_help_cites_renumbered_cis_ids() {
    // #526: the sudo-W04 CIS ids are "5.2.2" (use_pty) / "5.2.3" (I/O
    // logging); "1.3.2" / "1.3.3" are an older CIS benchmark generation's
    // numbering. `rulesteward-sudoers::lints::cis` / `lints::stig` emit the
    // renumbered ids in every live sudo-W04 `Diagnostic` (verified by running
    // `rulesteward sudoers lint` on a `Defaults !use_pty` fixture: the
    // findings say "CIS Benchmark 5.2.2" / "CIS Benchmark 5.2.3", never
    // "1.3.2"/"1.3.3"). The operator-facing `sudoers lint --help` must match
    // the tool's own output instead of contradicting it.
    Command::cargo_bin("rulesteward")
        .expect("binary built")
        .args(["sudoers", "lint", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("CIS Benchmark 5.2.2"))
        .stdout(predicate::str::contains("5.2.3"))
        .stdout(predicate::str::contains("1.3.2").not())
        .stdout(predicate::str::contains("1.3.3").not());
}

#[test]
fn sysctl_lint_help_system_enumeration_includes_w04() {
    // #576: `--system` mode's merged-set rerun covers the sysctld-W04 CIS
    // baseline (`rulesteward_sysctld::system::lint_system` reruns
    // F01/W01/W02/W04), so the operator-facing `sysctl lint --help` must name
    // W04 in BOTH places it enumerates the passes: the `Lint` subcommand's
    // long doc comment (cli/mod.rs) and the `--system` flag's own help
    // (cli/args/sysctl.rs). Help enumerating only F01/W01/W02 tells an
    // operator that `--system` is W02-only.
    //
    // The negative assertions target the longer phrase (not just
    // "F01/W01/W02"), because the correct text "F01/W01/W02/W04" contains
    // "F01/W01/W02" as a substring -- a naive negative assertion on the short
    // form would be unsatisfiable.
    Command::cargo_bin("rulesteward")
        .expect("binary built")
        .args(["sysctl", "lint", "--help"])
        .assert()
        .success()
        // cli/mod.rs long-about site: "reruns F01/W01/W02/W04 over the merged
        // set", never the W04-less form.
        .stdout(predicate::str::contains("F01/W01/W02/W04"))
        .stdout(predicate::str::contains("reruns F01/W01/W02 over").not())
        // cli/args/sysctl.rs `--system` flag-help site: "pass to
        // F01/W01/W02/W04.", never the W04-less form.
        .stdout(predicate::str::contains("pass to F01/W01/W02/W04."))
        .stdout(predicate::str::contains("pass to F01/W01/W02.").not());
}

#[test]
fn sshd_lint_help_lists_all_codes_including_w07() {
    // #414: the help must state the real sshd- code count and list every
    // catalog code, W07 (#302) included. Guards against a new sshd- code
    // landing without updating the operator-facing `sshd lint --help`.
    Command::cargo_bin("rulesteward")
        .expect("binary built")
        .args(["sshd", "lint", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("13 sshd-"))
        .stdout(predicate::str::contains("sshd-W07"));
}

#[test]
fn sysctl_lint_help_target_names_both_baselines_not_just_stig() {
    // #576: `--target` gates BOTH the STIG baseline W02 and the CIS baseline
    // W04, in all three modes, so the flag help must not describe only the
    // STIG baseline ("Target RHEL release for the STIG hardening baseline ...
    // Enables the version-aware `sysctld-W02` check ... With no `--target`,
    // W02 does not run ... only sysctld-F01 / sysctld-W01") - that understates
    // what an operator gives up by omitting the flag.
    //
    // clap HARD-WRAPS help text at the terminal width, so this normalises runs
    // of whitespace to single spaces before matching. A phrase assertion
    // against raw stdout would pass or fail depending on where the wrap landed,
    // which is a flake waiting to happen rather than a real invariant.
    let out = Command::cargo_bin("rulesteward")
        .expect("binary built")
        .args(["sysctl", "lint", "--help"])
        .output()
        .expect("`sysctl lint --help` runs");
    assert!(out.status.success(), "--help must exit 0");
    let help = String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");

    assert!(
        help.contains("neither W02 nor W04 runs"),
        "--target help must state that BOTH baselines are gated by --target; got:\n{help}"
    );
    assert!(
        !help.contains("W02 does not run"),
        "stale --target help: says only W02 is gated, but --target also gates W04"
    );
    assert!(
        !help.contains("Target RHEL release for the STIG hardening baseline"),
        "stale --target help: names only STIG, but --target also selects the CIS baseline"
    );
}
