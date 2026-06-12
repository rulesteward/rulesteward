//! e2e: `rulesteward fapolicyd migrate` via the real binary (#187).
//!
//! Exercises the clap wiring (`--from`/`--to`/`--apply`) and the human stdout the
//! unit tests cannot observe (they call `run` directly; stdout is not captured).

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
