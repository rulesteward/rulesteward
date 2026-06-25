//! e2e: `rulesteward auditd lint` via the real binary (#193, session 6a).
//!
//! These freeze the output contract end to end: envelope shape, exit codes, and
//! human render across the live P1/P2/P3 semantic passes. (They were landed
//! `#[ignore]`d during Phase 0 while the pass bodies were `todo!()` stubs; the
//! integration gate enabled them once all passes merged.)

use assert_cmd::Command;
use predicates::prelude::*;

fn write(dir: &std::path::Path, rel: &str, content: &str) {
    let p = dir.join(rel);
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(p, content).unwrap();
}

fn lint_cmd() -> Command {
    Command::cargo_bin("rulesteward").expect("binary builds")
}

// ---------------------------------------------------------------------------
// Live from Phase 0: paths that never reach the semantic-pass stubs.
// ---------------------------------------------------------------------------

#[test]
fn lint_missing_path_exits_three_with_message() {
    lint_cmd()
        .args(["auditd", "lint", "/nonexistent/6a/nothing"])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("does not exist"));
}

#[test]
fn lint_unparseable_rules_exits_five_with_au_f01_json() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "10-bad.rules", "-Z bogus\n");
    let assert = lint_cmd()
        .args(["auditd", "lint"])
        .arg(dir.path())
        .args(["--format", "json"])
        .assert()
        .code(5);
    let out = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let v: serde_json::Value = serde_json::from_str(&out).expect("stdout must be JSON");
    assert_eq!(v["kind"], serde_json::json!("auditd-lint"));
    assert_eq!(v["schemaVersion"], serde_json::json!(1));
    let diags = v["diagnostics"].as_array().expect("diagnostics array");
    assert!(
        diags
            .iter()
            .any(|d| d["code"] == serde_json::json!("au-F01")),
        "an unparseable line must yield au-F01: {out}"
    );
}

#[test]
fn lint_unparseable_rules_human_names_file_and_flag() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "10-bad.rules", "-Z bogus\n");
    lint_cmd()
        .args(["auditd", "lint"])
        .arg(dir.path())
        .assert()
        .code(5)
        .stdout(predicate::str::contains("au-F01"))
        .stdout(predicate::str::contains("10-bad.rules"))
        .stdout(predicate::str::contains("unknown flag"));
}

// ---------------------------------------------------------------------------
// Full semantic dispatcher (all P1/P2/P3 passes live).
// ---------------------------------------------------------------------------

#[test]
fn lint_clean_ruleset_exits_zero_with_empty_diagnostics_json() {
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        "10-base.rules",
        "-D\n-b 8192\n-a always,exit -S execve -F auid>=1000 -k exec\n-e 2\n",
    );
    let assert = lint_cmd()
        .args(["auditd", "lint"])
        .arg(dir.path())
        .args(["--format", "json"])
        .assert()
        .code(0);
    let out = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(out.ends_with('\n'), "JSON output must end with a newline");
    let v: serde_json::Value = serde_json::from_str(&out).expect("stdout must be JSON");
    assert_eq!(v["kind"], serde_json::json!("auditd-lint"));
    assert_eq!(v["schemaVersion"], serde_json::json!(1));
    assert_eq!(
        v["diagnostics"],
        serde_json::json!([]),
        "a clean ruleset has an EMPTY diagnostics array: {out}"
    );
}

#[test]
fn lint_clean_ruleset_human_prints_nothing() {
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        "10-base.rules",
        "-w /etc/passwd -p wa -k identity\n",
    );
    lint_cmd()
        .args(["auditd", "lint"])
        .arg(dir.path())
        .assert()
        .code(0)
        .stdout(predicate::str::is_empty());
}

#[test]
fn lint_reordered_duplicate_warning_exits_one() {
    // A normalized-equal-but-FIELD-REORDERED duplicate is au-W01 (Warning) ->
    // exit 1: the kernel compares `-F` field predicates POSITIONALLY, so a
    // field-order swap is a DIFFERENT rule to the kernel and does NOT EEXIST --
    // the second rule loads, making it redundant waste, not a load-abort.
    // Contrast: a SYSCALL-order swap IS a load-abort (commutative bitmask) and
    // the watch perm-swap in lint_load_aborting_duplicate_exits_two -> au-E03.
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        "10-a.rules",
        "-a always,exit -S execve -F auid>=1000 -F uid=0 -k io\n",
    );
    write(
        dir.path(),
        "50-b.rules",
        "-a always,exit -S execve -F uid=0 -F auid>=1000 -k io\n",
    );
    lint_cmd()
        .args(["auditd", "lint"])
        .arg(dir.path())
        .assert()
        .code(1)
        .stdout(predicate::str::contains("au-W01"));
}

#[test]
fn lint_load_aborting_duplicate_exits_two() {
    // An AST-structurally-identical duplicate is au-E03 (Error) -> exit 2: the
    // two watches resolve to the SAME path + perm bitmask + key, so the second
    // `auditctl -R` rule is rejected with EEXIST and the load ABORTS, silently
    // dropping every later rule (auditctl.c). `-p wa` and `-p aw` are the same
    // mask, so they are this load-aborting class, NOT mere reorder-waste.
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        "10-a.rules",
        "-w /etc/passwd -p wa -k identity\n",
    );
    write(
        dir.path(),
        "50-b.rules",
        "-w /etc/passwd -p aw -k identity\n",
    );
    lint_cmd()
        .args(["auditd", "lint"])
        .arg(dir.path())
        .assert()
        .code(2)
        .stdout(predicate::str::contains("au-E03"));
}

#[test]
fn lint_post_lock_rule_exits_two() {
    // A rule after `-e 2` -> au-E01 (Error) -> exit 2.
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        "10-a.rules",
        "-e 2\n-w /etc/passwd -p wa -k identity\n",
    );
    lint_cmd()
        .args(["auditd", "lint"])
        .arg(dir.path())
        .assert()
        .code(2)
        .stdout(predicate::str::contains("au-E01"));
}

#[test]
fn lint_exact_duplicate_pair_yields_exactly_one_finding() {
    // The D2 cross-pipeline boundary, testable only with ALL passes live: an
    // exact-canonical-equal pair is au-W01 (P1) ONLY - P2's subsumption pass
    // must skip it, so the pair yields exactly ONE diagnostic, never two.
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        "10-a.rules",
        "-a always,exit -S execve -F auid>=1000 -F uid=0 -k x\n",
    );
    write(
        dir.path(),
        "50-b.rules",
        "-a always,exit -F uid=0 -F auid>=1000 -S execve -k x\n",
    );
    let assert = lint_cmd()
        .args(["auditd", "lint"])
        .arg(dir.path())
        .args(["--format", "json"])
        .assert()
        .code(1);
    let out = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let v: serde_json::Value = serde_json::from_str(&out).expect("stdout must be JSON");
    let diags = v["diagnostics"].as_array().expect("diagnostics array");
    assert_eq!(
        diags.len(),
        1,
        "an exact-equal pair is ONE au-W01, not an additional au-W02: {out}"
    );
    assert_eq!(diags[0]["code"], serde_json::json!("au-W01"));
}

// ---------------------------------------------------------------------------
// T11 (#230): --apparmor flag enables AppArmor msgtype folding end-to-end.
// ---------------------------------------------------------------------------

#[test]
fn t11_apparmor_flag_folds_msgtype_names() {
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        "10-a.rules",
        "-a always,exclude -F msgtype=APPARMOR_DENIED\n",
    );
    write(
        dir.path(),
        "50-b.rules",
        "-a always,exclude -F msgtype=1503\n",
    );

    // Without --apparmor: the two rules are distinct, no au-W01.
    lint_cmd()
        .args(["auditd", "lint"])
        .arg(dir.path())
        .assert()
        .code(0)
        .stdout(predicates::prelude::predicate::str::is_empty());

    // With --apparmor: APPARMOR_DENIED folds to 1503, so au-W01 fires.
    lint_cmd()
        .args(["auditd", "lint", "--apparmor"])
        .arg(dir.path())
        .assert()
        .code(1)
        .stdout(predicates::prelude::predicate::str::contains("au-W01"));
}
