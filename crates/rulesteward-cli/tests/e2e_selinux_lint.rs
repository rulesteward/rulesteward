//! End-to-end tests for `rulesteward selinux lint` (#520).
//!
//! `e2e_selinux.rs` (the pre-existing triage suite) is untouched; this is a
//! NEW file for the new `lint` verb.

use assert_cmd::Command;
use predicates::prelude::*;
use std::io::Write as _;

fn bin() -> Command {
    Command::cargo_bin("rulesteward").expect("rulesteward binary")
}

/// Write `contents` to a temp file and return the guard (keeps the file alive
/// for the duration of the test).
fn write_config(contents: &str) -> tempfile::NamedTempFile {
    let mut f = tempfile::NamedTempFile::new().expect("create temp selinux config");
    f.write_all(contents.as_bytes())
        .expect("write selinux config contents");
    f.flush().expect("flush selinux config file");
    f
}

#[test]
fn lint_target_rhel9_permissive_fires_se_w01_with_control_suffix_and_exits_1() {
    let f = write_config("SELINUX=permissive\nSELINUXTYPE=targeted\n");
    bin()
        .args(["selinux", "lint"])
        .arg(f.path())
        .args(["--target", "rhel9"])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("se-W01"))
        .stdout(predicate::str::contains("(STIG RHEL-09-431010/V-258078)"));
}

#[test]
fn lint_target_rhel9_enforcing_is_clean_exit_0() {
    let f = write_config("SELINUX=enforcing\nSELINUXTYPE=targeted\n");
    bin()
        .args(["selinux", "lint"])
        .arg(f.path())
        .args(["--target", "rhel9"])
        .assert()
        .code(0);
}

#[test]
fn lint_target_rhel8_selinuxtype_mls_fires_se_w02_with_control_suffix() {
    let f = write_config("SELINUX=enforcing\nSELINUXTYPE=mls\n");
    bin()
        .args(["selinux", "lint"])
        .arg(f.path())
        .args(["--target", "rhel8"])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("se-W02"))
        .stdout(predicate::str::contains("(STIG RHEL-08-010450/V-230282)"));
}

#[test]
fn lint_without_target_is_version_agnostic_and_clean() {
    // A misconfigured file with NO --target must be clean: the whole lint is
    // gated on a resolved target (mirrors sysctld-W02).
    let f = write_config("SELINUX=permissive\nSELINUXTYPE=mls\n");
    bin()
        .args(["selinux", "lint"])
        .arg(f.path())
        .assert()
        .code(0);
}

#[test]
fn lint_json_kind_and_schema_version_are_pinned() {
    let f = write_config("SELINUX=enforcing\nSELINUXTYPE=targeted\n");
    let output = bin()
        .args(["selinux", "lint"])
        .arg(f.path())
        .args(["--format", "json"])
        .output()
        .expect("binary ran");
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid json");
    assert_eq!(v["kind"].as_str(), Some("selinux-lint"));
    assert_eq!(v["schemaVersion"].as_u64(), Some(1));
}

#[test]
fn lint_profile_stig_passthrough_is_non_empty_for_a_controls_bearing_finding() {
    let f = write_config("SELINUX=permissive\nSELINUXTYPE=targeted\n");
    bin()
        .args(["selinux", "lint"])
        .arg(f.path())
        .args(["--target", "rhel9", "--profile", "stig"])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("se-W01"));
}

#[test]
fn lint_help_mentions_the_verb_and_target_flag() {
    bin()
        .args(["selinux", "lint", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--target"))
        .stdout(predicate::str::contains("--format"));
}

/// True when this host's `/etc/os-release` identifies an EL-family distro the
/// live probe would RESOLVE for `--target auto` (same family signals as
/// `commands::target_probe`: family `ID`, an `ID_LIKE` containing `rhel`, or
/// `PLATFORM_ID=platform:elN`). Used only to self-skip the degrade test on
/// hosts (e.g. the Rocky distro-CI containers) where auto resolves instead of
/// degrading.
fn host_is_el_family() -> bool {
    let text = std::fs::read_to_string("/etc/os-release").unwrap_or_default();
    text.lines().map(str::trim).any(|line| {
        let Some((key, value)) = line.split_once('=') else {
            return false;
        };
        let value = value.trim_matches(|c| c == '"' || c == '\'');
        match key {
            "ID" => matches!(value, "rhel" | "rocky" | "almalinux" | "centos"),
            "ID_LIKE" => value.split_whitespace().any(|token| token == "rhel"),
            "PLATFORM_ID" => value.starts_with("platform:el"),
            _ => false,
        }
    })
}

/// `--target auto` on a host that maps to no supported RHEL target degrades to
/// the version-agnostic dialect: the shared `resolve_target` warning reaches
/// stderr (with this verb's `selinux lint:` prefix) and a clean config still
/// exits 0. This is the stderr half of the unit test
/// `commands::selinux::lint::tests::target_auto_degrade_lints_clean_and_does_not_error`,
/// which cannot capture `eprintln!` output in-process. Self-skips on EL-family
/// hosts, where auto RESOLVES and no warning is printed.
#[test]
fn lint_target_auto_degrade_warns_on_stderr_and_exits_0() {
    if host_is_el_family() {
        eprintln!("skipping: EL-family host resolves --target auto instead of degrading");
        return;
    }
    let f = write_config("SELINUX=enforcing\nSELINUXTYPE=targeted\n");
    bin()
        .args(["selinux", "lint"])
        .arg(f.path())
        .args(["--target", "auto"])
        .assert()
        .code(0)
        // Both degrade arms (unmappable host / unreadable os-release) share
        // the "--target auto: ...; linting version-agnostic" wording pinned in
        // commands/target_probe.rs; the verb prefixes it with "selinux lint:".
        .stderr(predicate::str::contains("selinux lint: --target auto:"))
        .stderr(predicate::str::contains("linting version-agnostic"));
}
