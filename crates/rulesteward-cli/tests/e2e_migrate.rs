//! e2e: `rulesteward fapolicyd migrate` via the real binary (#187 + #211/#212).
//!
//! Exercises the clap wiring (`--from`/`--to`/`--apply`/`--report`) and the
//! human/JSON stdout the unit tests cannot observe (they call `run`/`run_with_probe`
//! directly; stdout is not captured).
//!
//! #211 e2e: on a host without `fagenrules` (which is true on CI and the dev
//! machine), the binary must exit 0 and mention that verification was unavailable
//! or skipped. This is the CI-exercised graceful-degrade path.
//!
//! #212 e2e: `--report <PATH>` writes a markdown file; dry-run report documents
//! the plan; absent `--report` writes no file.

use assert_cmd::Command;
use predicates::prelude::*;

fn write(dir: &std::path::Path, rel: &str, content: &str) {
    let p = dir.join(rel);
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(p, content).unwrap();
}

fn migrate_args(dir: &std::path::Path) -> Vec<String> {
    vec![
        "fapolicyd".into(),
        "migrate".into(),
        "--from".into(),
        "rhel8".into(),
        "--to".into(),
        "rhel9".into(),
        "--rules-dir".into(),
        dir.to_str().unwrap().into(),
    ]
}

#[test]
fn migrate_dry_run_prints_plan_and_writes_nothing() {
    let d = tempfile::tempdir().unwrap();
    write(
        d.path(),
        "fapolicyd.rules",
        "allow perm=execute exe=/x : sha256hash=ab\n",
    );
    Command::cargo_bin("rulesteward")
        .unwrap()
        .args(migrate_args(d.path()))
        .assert()
        .success()
        .stdout(predicate::str::contains("dry-run"))
        .stdout(predicate::str::contains("rhel8 -> rhel9"))
        .stdout(predicate::str::contains("99-migrated.rules"));
    assert!(
        !d.path().join("rules.d").join("99-migrated.rules").exists(),
        "dry-run must write nothing"
    );
    assert!(
        d.path().join("fapolicyd.rules").exists(),
        "dry-run must not move the legacy file"
    );
}

#[test]
fn migrate_apply_moves_file_and_reports_applied() {
    let d = tempfile::tempdir().unwrap();
    write(
        d.path(),
        "fapolicyd.rules",
        "allow perm=execute exe=/x : sha256hash=ab\n",
    );
    let mut argv = migrate_args(d.path());
    argv.push("--apply".into());
    Command::cargo_bin("rulesteward")
        .unwrap()
        .args(argv)
        .assert()
        .success()
        .stdout(predicate::str::contains("Migration applied"));
    let target = d.path().join("rules.d").join("99-migrated.rules");
    assert!(
        std::fs::read_to_string(&target)
            .unwrap()
            .contains("filehash=ab"),
        "apply rewrites sha256hash -> filehash"
    );
    assert!(
        !d.path().join("fapolicyd.rules").exists(),
        "apply moves (removes) the legacy file"
    );
}

#[test]
fn migrate_modern_only_reports_already_migrated() {
    let d = tempfile::tempdir().unwrap();
    write(d.path(), "rules.d/10-x.rules", "allow perm=any all : all\n");
    Command::cargo_bin("rulesteward")
        .unwrap()
        .args(migrate_args(d.path()))
        .assert()
        .success()
        .stdout(predicate::str::contains("Already migrated"));
}

#[test]
fn migrate_coexistence_trap_without_delete_legacy_exits_two() {
    let d = tempfile::tempdir().unwrap();
    write(d.path(), "fapolicyd.rules", "allow perm=any all : all\n");
    write(d.path(), "rules.d/10-x.rules", "deny perm=any all : all\n");
    let mut argv = migrate_args(d.path());
    argv.push("--apply".into());
    Command::cargo_bin("rulesteward")
        .unwrap()
        .args(argv)
        .assert()
        .code(2)
        .stderr(predicate::str::contains("coexistence trap"));
    assert!(
        d.path().join("fapolicyd.rules").exists(),
        "refused: untouched"
    );
}

#[test]
fn migrate_both_apply_json_reports_coexistence_trap() {
    let d = tempfile::tempdir().unwrap();
    write(d.path(), "fapolicyd.rules", "allow perm=any all : all\n");
    write(d.path(), "rules.d/10-x.rules", "deny perm=any all : all\n");
    let mut argv = migrate_args(d.path());
    argv.push("--apply".into());
    argv.push("--delete-legacy".into());
    argv.push("--format".into());
    argv.push("json".into());
    let assert = Command::cargo_bin("rulesteward")
        .unwrap()
        .args(argv)
        .assert()
        .success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("json envelope");
    assert_eq!(v["kind"], serde_json::json!("migrate"));
    assert_eq!(v["coexistenceTrap"], serde_json::json!(true), "{stdout}");
    assert_eq!(v["legacyDeleted"], serde_json::json!(true), "{stdout}");
    assert!(
        !d.path().join("fapolicyd.rules").exists(),
        "legacy moved on apply"
    );
}

// ---------------------------------------------------------------------------
// #211 e2e: graceful degradation when the verification binary is absent
// ---------------------------------------------------------------------------

/// Helper: create an empty temporary directory suitable for use as a PATH
/// that contains no executables.  Running `fapolicyd-cli` with this PATH
/// causes `Command::new("fapolicyd-cli")` to return `ErrorKind::NotFound`,
/// which the live probe must map to `Ok(None)` (graceful degrade).
///
/// Using a controlled PATH is deterministic: it forces the "absent" path
/// regardless of whether `fapolicyd-cli` is installed on the host.
fn empty_path_dir() -> tempfile::TempDir {
    tempfile::tempdir().expect("create empty PATH dir")
}

/// On a host where `fapolicyd-cli` is unreachable (forced via a PATH that
/// contains only an empty directory), `--apply` must succeed (exit 0) and
/// the human output must mention that verification was unavailable or skipped.
///
/// RED until #211 is implemented: the current binary exits 0 but the human
/// output contains no verification line at all, so the `contains` assertion
/// fails.
#[test]
fn migrate_apply_without_fagenrules_degrades_gracefully() {
    let d = tempfile::tempdir().unwrap();
    write(
        d.path(),
        "fapolicyd.rules",
        "allow perm=execute exe=/usr/bin/cat : sha256hash=ab\n",
    );
    let mut argv = migrate_args(d.path());
    argv.push("--apply".into());
    // Force PATH to an empty dir so fapolicyd-cli is unreachable on any host.
    let empty_path = empty_path_dir();
    Command::cargo_bin("rulesteward")
        .unwrap()
        .args(&argv)
        .env("PATH", empty_path.path())
        .assert()
        .success()
        // RED: the current binary emits no verification line.
        // After #211: must contain "unavailable" or "skipped" or "verification".
        .stdout(
            predicate::str::contains("unavailable")
                .or(predicate::str::contains("skipped"))
                .or(predicate::str::contains("verification")),
        );
    // The migration itself must still have applied.
    assert!(
        d.path().join("rules.d").join("99-migrated.rules").exists(),
        "target file must be written even when verification is unavailable"
    );
    assert!(
        !d.path().join("fapolicyd.rules").exists(),
        "legacy file must be moved even when verification is unavailable"
    );
}

/// JSON output after apply (fapolicyd-cli unreachable via empty PATH):
/// `fagenrulesCheck.status` must be `"unavailable"` (not null, not absent)
/// per #211 D7 graceful-degrade spec.
///
/// RED until #211 is implemented: the current binary emits `fagenrulesCheck: null`.
#[test]
fn migrate_apply_json_fagenrules_check_unavailable_when_binary_absent() {
    let d = tempfile::tempdir().unwrap();
    write(
        d.path(),
        "fapolicyd.rules",
        "allow perm=execute exe=/x : sha256hash=ff\n",
    );
    let mut argv = migrate_args(d.path());
    argv.push("--apply".into());
    argv.push("--format".into());
    argv.push("json".into());
    // Force PATH to an empty dir so fapolicyd-cli is unreachable on any host.
    let empty_path = empty_path_dir();
    let assert = Command::cargo_bin("rulesteward")
        .unwrap()
        .args(argv)
        .env("PATH", empty_path.path())
        .assert()
        .success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("json must parse");
    // RED: current binary has fagenrulesCheck: null; after #211 it must be
    // {"status": "unavailable", ...}.
    let check = &v["fagenrulesCheck"];
    assert!(
        !check.is_null(),
        "fagenrulesCheck must not be null after apply (must be an object with status): {stdout}"
    );
    assert_eq!(
        check["status"],
        serde_json::json!("unavailable"),
        "fagenrulesCheck.status must be 'unavailable' when binary absent: {stdout}"
    );
    // D7: applied must still be true.
    assert_eq!(
        v["applied"],
        serde_json::json!(true),
        "applied must be true even when verification is unavailable: {stdout}"
    );
}

// ---------------------------------------------------------------------------
// #212 e2e: --report flag writes a markdown file
// ---------------------------------------------------------------------------

/// `--report <PATH>` in apply mode writes a markdown file containing the
/// migration details.
///
/// RED until #212 is implemented: the current binary ignores `--report` and
/// writes nothing, so the file-exists assertion fails.
#[test]
fn migrate_apply_report_flag_writes_markdown_file() {
    let d = tempfile::tempdir().unwrap();
    write(
        d.path(),
        "fapolicyd.rules",
        "allow perm=execute exe=/x : sha256hash=ab\ndeny perm=any all : all\n",
    );
    let report_path = d.path().join("migration-report.md");
    let mut argv = migrate_args(d.path());
    argv.push("--apply".into());
    argv.push("--report".into());
    argv.push(report_path.to_str().unwrap().into());
    Command::cargo_bin("rulesteward")
        .unwrap()
        .args(argv)
        .assert()
        .success();
    // RED: no report written yet.
    assert!(
        report_path.exists(),
        "migration report must be written at the --report path"
    );
    let md = std::fs::read_to_string(&report_path).unwrap();
    // Must mention the legacy file and target.
    assert!(
        md.contains("fapolicyd.rules"),
        "report must mention the legacy file: {md}"
    );
    assert!(
        md.contains("99-migrated.rules"),
        "report must mention the target file: {md}"
    );
    // Must mention the rewrite (sha256hash -> filehash).
    assert!(
        md.contains("sha256hash") || md.contains("filehash"),
        "report must document the hash rewrite: {md}"
    );
    // Must NOT contain a timestamp (D1).
    assert!(
        !(md.contains("2026") || md.contains("2025") || md.contains("T0")),
        "report must not contain a timestamp (D1): {md}"
    );
}

/// `--report <PATH>` in dry-run mode writes a markdown report documenting
/// the PLAN (what WOULD happen), without applying anything.
///
/// RED until #212 is implemented.
#[test]
fn migrate_dry_run_report_flag_writes_plan_markdown() {
    let d = tempfile::tempdir().unwrap();
    write(d.path(), "fapolicyd.rules", "allow perm=any all : all\n");
    let report_path = d.path().join("plan-report.md");
    let mut argv = migrate_args(d.path());
    // No --apply: this is dry-run.
    argv.push("--report".into());
    argv.push(report_path.to_str().unwrap().into());
    Command::cargo_bin("rulesteward")
        .unwrap()
        .args(argv)
        .assert()
        .success();
    // RED: no report written yet.
    assert!(
        report_path.exists(),
        "dry-run report must be written at the --report path"
    );
    // The legacy file must be untouched (dry-run).
    assert!(
        d.path().join("fapolicyd.rules").exists(),
        "dry-run must not move the legacy file"
    );
    assert!(
        !d.path().join("rules.d").join("99-migrated.rules").exists(),
        "dry-run must not write the target file"
    );
}

/// Absent `--report` flag -> no report file written anywhere.
///
/// This test is VACUOUSLY GREEN in the skeleton (no report is ever written),
/// but it pins the contract: the implementer must not write a default report
/// path when `--report` is absent.
#[test]
fn migrate_absent_report_flag_writes_no_extra_files() {
    let d = tempfile::tempdir().unwrap();
    write(d.path(), "fapolicyd.rules", "allow perm=any all : all\n");
    let mut argv = migrate_args(d.path());
    argv.push("--apply".into());
    // No --report.
    Command::cargo_bin("rulesteward")
        .unwrap()
        .args(argv)
        .assert()
        .success();
    // Only rules.d/99-migrated.rules and (absence of legacy) are expected.
    // No .md file or other extra artifact.
    let all_entries: Vec<_> = std::fs::read_dir(d.path())
        .unwrap()
        .filter_map(std::result::Result::ok)
        .filter(|e| {
            let name = e.file_name();
            let s = name.to_string_lossy();
            s.ends_with(".md") || s.ends_with(".txt") || s.ends_with(".log")
        })
        .collect();
    assert!(
        all_entries.is_empty(),
        "no report files must be written when --report is absent: {:?}",
        all_entries
            .iter()
            .map(std::fs::DirEntry::path)
            .collect::<Vec<_>>()
    );
}
