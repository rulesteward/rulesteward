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

/// An EXISTING file the process cannot read is a distinct arm from the
/// missing-path case above: `resolve_lint_target` succeeds (the file exists),
/// but the per-file `std::fs::read_to_string` inside the staging loop fails.
/// Relies on chmod 0000 reliably denying read for the non-root user this
/// suite runs as (both locally and in CI).
#[test]
fn lint_unreadable_existing_file_exits_three() {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("10-unreadable.rules");
    std::fs::write(&f, "-w /etc/passwd -p wa -k identity\n").unwrap();
    std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o000)).unwrap();

    // Root (RHEL-family distro CI) bypasses DAC, so 0o000 stays readable and the
    // "cannot read" arm is structurally unreachable. Probe and skip rather than
    // false-fail; the assertion stays fully live on every non-root run.
    if std::fs::File::open(&f).is_ok() {
        let _ = std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o644));
        eprintln!(
            "SKIP lint_unreadable_existing_file_exits_three: 0o000 is readable here \
             (running as root / CAP_DAC_OVERRIDE); cannot exercise the deny arm"
        );
        return;
    }

    let rc = lint_cmd().args(["auditd", "lint"]).arg(&f).assert();

    // Restore permissions unconditionally so the tempdir's own Drop cleanup
    // can still remove the file.
    let _ = std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o644));

    rc.code(3)
        .stderr(predicate::str::contains("auditd lint: cannot read"));
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

// ---------------------------------------------------------------------------
// issue #474: --target wiring for the version-aware au-W06 STIG baseline.
// The shipped RHEL*_REQUIRED tables are empty placeholders (test-author
// state; the implementer populates them via `tools/auditd-stig-update
// derive`), so these tests pin the FLAG WIRING (exit code, no crash, no
// au-W06 leaking without --target) rather than a real "au-W06 fires" case -
// that content-level proof lives in
// crates/rulesteward-auditd/tests/test_lints_stig_required.rs, which
// exercises the real matcher against a test-local injected baseline.
// ---------------------------------------------------------------------------

#[test]
fn help_lists_the_target_flag() {
    lint_cmd()
        .args(["auditd", "lint", "--help"])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("--target"));
}

#[test]
fn target_rhel9_flag_accepted_and_warns_against_the_populated_table() {
    // The shipped RHEL9_REQUIRED table is now populated (issue #474): this
    // fixture satisfies only one of its required lines
    // (`-w /etc/passwd -p wa -k identity`, RHEL-09-654240), so --target rhel9
    // surfaces every other one as au-W06 warnings (exit 1) - the same
    // FLAG-WIRING proof as before (the flag reaches the real matcher), just
    // with the outcome the populated table actually produces.
    //
    // UPDATED (#523, session 9b-v0_8-wave2 lane 2e): the shipped table grows
    // from 67 to 69 rows (two new Control-shaped deepening entries, neither
    // satisfied by this fixture), so 68 (not 66) of the 69 required lines are
    // now missing. RED today.
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        "10-a.rules",
        "-w /etc/passwd -p wa -k identity\n",
    );
    let assert = lint_cmd()
        .args(["auditd", "lint"])
        .arg(dir.path())
        .args(["--target", "rhel9", "--format", "json"])
        .assert()
        .code(1);
    let out = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let v: serde_json::Value = serde_json::from_str(&out).expect("stdout must be JSON");
    let diags = v["diagnostics"].as_array().expect("diagnostics array");
    assert_eq!(
        diags.len(),
        68,
        "68 of the 69 required lines are missing (RHEL-09-654240 is satisfied): {out}"
    );
    assert!(
        diags
            .iter()
            .all(|d| d["code"] == serde_json::json!("au-W06")),
        "every finding must be au-W06: {out}"
    );
    assert!(
        !diags.iter().any(|d| d["message"]
            .as_str()
            .unwrap_or_default()
            .contains("RHEL-09-654240")),
        "the satisfied requirement must not be reported missing: {out}"
    );
}

#[test]
fn no_target_emits_no_au_w06() {
    // Without --target, au-W06 never runs (version-agnostic contract) - a
    // wildly non-compliant ruleset (no watches, no syscall rules at all)
    // still shows no au-W06.
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "10-a.rules", "-D\n-b 8192\n");
    lint_cmd()
        .args(["auditd", "lint"])
        .arg(dir.path())
        .assert()
        .code(0)
        .stdout(predicate::str::contains("au-W06").not());
}
