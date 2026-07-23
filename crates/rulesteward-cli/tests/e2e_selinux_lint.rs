//! End-to-end tests for `rulesteward selinux lint` (#520).
//!
//! `e2e_selinux.rs` (the pre-existing triage suite) is untouched; this is a
//! NEW file for the new `lint` verb.

use assert_cmd::Command;
use boon::{Compiler, Schemas};
use predicates::prelude::*;
use serde_json::Value;
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

// ---------------------------------------------------------------------------
// #511 (v0.8 Wave 4): SARIF output for the 5 `HumanJsonFormat` lint verbs
// (findings-only). RED today: `SelinuxLintArgs.format` is `HumanJsonFormat`
// (human|json only), so clap rejects `--format sarif` at parse time. The
// planned impl switches `SelinuxLintArgs.format` to `OutputFormat` and routes
// the new Sarif arm through `output::emit_lint`.
// ---------------------------------------------------------------------------

/// Validate a SARIF JSON string against the bundled OASIS SARIF 2.1.0 schema.
/// Duplicated per-file (see the identical helper in `e2e_sshd_lint.rs` for why
/// -- no shared test-support module exists in this crate).
fn assert_valid_sarif(rendered: &str) {
    let instance: Value = serde_json::from_str(rendered).expect("SARIF stdout must parse as JSON");
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/sarif-2.1.0.schema.json"
    );
    let schema: Value = serde_json::from_slice(&std::fs::read(path).expect("read schema fixture"))
        .expect("schema fixture parses");
    let schema_id = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json";
    let mut compiler = Compiler::new();
    compiler
        .add_resource(schema_id, schema)
        .expect("add SARIF schema");
    let mut schemas = Schemas::new();
    let idx = compiler
        .compile(schema_id, &mut schemas)
        .expect("compile SARIF schema");
    if let Err(e) = schemas.validate(&instance, idx) {
        panic!("SARIF failed schema validation:\n{e}\n--- instance ---\n{rendered}");
    }
}

/// A permissive-at-boot config under `--target rhel9` fires `se-W01`
/// (Warning, STIG RHEL-09-431010/V-258078). SARIF output is schema-valid,
/// carries `ruleId: "se-W01"` at `level: "warning"`, ends with a trailing
/// newline, and exits 1 (Warning tier, matching
/// `lint_target_rhel9_permissive_fires_se_w01_with_control_suffix_and_exits_1`
/// above).
#[test]
fn sarif_format_fires_se_w01_with_ruleid_warning_level_and_trailing_newline() {
    let f = write_config("SELINUX=permissive\nSELINUXTYPE=targeted\n");
    let out = bin()
        .args(["selinux", "lint"])
        .arg(f.path())
        .args(["--target", "rhel9", "--format", "sarif"])
        .output()
        .expect("binary ran");
    assert_eq!(
        out.status.code(),
        Some(1),
        "se-W01 (Warning) must exit 1 under --format sarif; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).expect("utf8");
    assert_valid_sarif(&stdout);
    let v: Value = serde_json::from_str(&stdout).expect("SARIF stdout parses as JSON");
    let results = v
        .pointer("/runs/0/results")
        .and_then(Value::as_array)
        .expect("results array present");
    assert!(
        results.iter().any(
            |r| r.get("ruleId").and_then(Value::as_str) == Some("se-W01")
                && r.get("level").and_then(Value::as_str) == Some("warning")
        ),
        "a result must carry ruleId \"se-W01\" with level \"warning\"; got: {stdout}"
    );
    assert!(
        stdout.ends_with('\n'),
        "SARIF stdout must end with a newline"
    );
}

/// An enforcing-at-boot, targeted-type config under `--target rhel9` emits a
/// schema-valid SARIF document with zero results and exits 0.
#[test]
fn sarif_format_clean_config_is_schema_valid_with_zero_results() {
    let f = write_config("SELINUX=enforcing\nSELINUXTYPE=targeted\n");
    let out = bin()
        .args(["selinux", "lint"])
        .arg(f.path())
        .args(["--target", "rhel9", "--format", "sarif"])
        .output()
        .expect("binary ran");
    assert_eq!(
        out.status.code(),
        Some(0),
        "a clean config must exit 0 under --format sarif; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).expect("utf8");
    assert_valid_sarif(&stdout);
    let v: Value = serde_json::from_str(&stdout).expect("SARIF stdout parses as JSON");
    let results = v
        .pointer("/runs/0/results")
        .and_then(Value::as_array)
        .expect("results array present");
    assert!(
        results.is_empty(),
        "a clean config must produce zero SARIF results; got: {stdout}"
    );
}

/// `--sarif-include-pass` must stay fapolicyd-ONLY (locked scope): clap must
/// still reject it as an unrecognized flag on `selinux lint`. GREEN today
/// (clap already rejects the unknown flag) and must stay green after the
/// impl.
#[test]
fn sarif_include_pass_is_rejected_for_selinux_lint() {
    let f = write_config("SELINUX=enforcing\nSELINUXTYPE=targeted\n");
    let out = bin()
        .args(["selinux", "lint"])
        .arg(f.path())
        .args(["--sarif-include-pass"])
        .output()
        .expect("binary ran");
    assert_eq!(
        out.status.code(),
        Some(3),
        "an unrecognized flag is a clap parse error (mapped to EXIT_TOOL_FAILURE); stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8(out.stderr).expect("utf8");
    assert!(
        stderr.contains("--sarif-include-pass"),
        "clap's error must name the rejected flag; got: {stderr}"
    );
}
