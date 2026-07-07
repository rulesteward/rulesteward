//! End-to-end tests for `rulesteward selinux` subcommands.
//!
//! These end-to-end tests cover the `selinux triage` input-validation path
//! (missing-flag errors and `--help`), plus a handful of FLOOR-only (no
//! `--policy`) command-wiring arms in `commands/selinux.rs` that the
//! feature-gated `e2e_selinux_authoritative.rs` suite does not reach (it
//! always supplies `--policy`): the parse-error arm, a full successful
//! no-`--policy` run (including the reclassification hint), `--emit-te`, and
//! `-o <file>` output. The renderers' own content is covered by the selinux
//! crate's `triage_render_human.rs`, `te_emit_unit.rs`, and
//! `known_answer_categorize.rs`; these tests are wiring-level (#440).

use assert_cmd::Command;
use predicates::prelude::*;

/// Write `contents` to a temp file and return the guard (keeps the file alive
/// for the duration of the test). Mirrors `e2e_selinux_authoritative.rs`'s
/// `write_record` helper.
fn write_record(contents: &str) -> tempfile::NamedTempFile {
    use std::io::Write as _;
    let mut f = tempfile::NamedTempFile::new().expect("create temp AVC record file");
    f.write_all(contents.as_bytes())
        .expect("write AVC record contents");
    f.flush().expect("flush AVC record file");
    f
}

/// A real `type=AVC` record whose FLOOR (record-only, no `--policy`)
/// classification is `RoleSuspected`: source and target contexts share the
/// same MLS level but differ in role, and the target role is not
/// `object_r`. Reused verbatim from
/// `e2e_selinux_authoritative.rs::AVC_ROLE_CONSTRAINT` (see that file for the
/// authoritative-vs-floor divergence grounding; here only the FLOOR
/// classification matters).
const AVC_ROLE_CONSTRAINT: &str = r#"type=AVC msg=audit(1700000000.003:1003): avc:  denied  { dyntransition } for  pid=1003 comm="probe" scontext=u1:r_a:src_t:s0:c0.c1 tcontext=u1:r_b:src_t:s0:c0.c1 tclass=process permissive=0"#;

/// `selinux triage` with neither `--record` nor `--audit-log` must print the
/// required-argument error to stderr and exit 2 (`EXIT_ERRORS`).
///
/// TDD note: before the frozen arm replaced the `todo!()`, this test failed
/// because the `todo!()` panicked (exit 101) instead of printing the message
/// and exiting 2.
#[test]
fn triage_no_input_flag_errors_with_message() {
    Command::cargo_bin("rulesteward")
        .expect("binary built")
        .args(["selinux", "triage"])
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains(
            "one of --record or --audit-log is required",
        ));
}

/// `selinux triage --help` still renders (the frozen `--help` test from P0.3
/// must continue to pass).
#[test]
fn triage_help_still_renders() {
    Command::cargo_bin("rulesteward")
        .expect("binary built")
        .args(["selinux", "triage", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--emit-te"))
        .stdout(predicate::str::contains("--format"));
}

/// A `--record` file with no recognizable `type=AVC` line hits `parse_avc`'s
/// error arm: exit 2 (`EXIT_ERRORS`), same code as the missing-flag case above
/// but a distinct message and code path (`commands/selinux.rs` lines 67-73).
#[test]
fn triage_unparseable_record_exits_errors() {
    let record = write_record("not an avc record at all\n");
    Command::cargo_bin("rulesteward")
        .expect("binary built")
        .args(["selinux", "triage", "--record"])
        .arg(record.path())
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("selinux triage: parsing"));
}

/// A full successful `triage --record <file>` run with NO `--policy` exercises
/// the FLOOR-only path end to end (`apply_authoritative_categorizer`'s
/// `policy_path.is_none()` early return) and, because the chosen record floors
/// to `RoleSuspected`, also the `--policy`-reclassification hint printed to
/// stderr. `e2e_selinux_authoritative.rs` never runs a full triage without
/// `--policy`, so this arm is otherwise untested.
#[test]
fn triage_without_policy_runs_floor_only_and_prints_reclassification_hint() {
    let record = write_record(AVC_ROLE_CONSTRAINT);
    Command::cargo_bin("rulesteward")
        .expect("binary built")
        .args(["selinux", "triage", "--record"])
        .arg(record.path())
        .assert()
        .success()
        .code(0)
        .stdout(predicate::str::contains("RBAC role constraint"))
        .stderr(predicate::str::contains(
            "hint: 1 group classified as a suspected MLS/role denial",
        ));
}

/// `--emit-te` routes to the `.te` emitter instead of the triage renderer.
/// This record's group is a role-constraint DECLINE (not TE-representable),
/// so the emitted output documents that rather than an `allow` rule - the
/// point of this test is that the `--emit-te` arm is reached at all, not the
/// emitter's own content (covered by the selinux crate's `te_emit_unit.rs`).
#[test]
fn triage_emit_te_routes_to_te_emitter() {
    let record = write_record(AVC_ROLE_CONSTRAINT);
    Command::cargo_bin("rulesteward")
        .expect("binary built")
        .args(["selinux", "triage", "--record"])
        .arg(record.path())
        .args(["--emit-te", "--module-name", "mymod"])
        .assert()
        .success()
        .stdout(predicate::str::contains("rulesteward:"));
}

/// `-o <file>` writes the rendered report to a file instead of stdout.
#[test]
fn triage_output_flag_writes_to_file_not_stdout() {
    let record = write_record(AVC_ROLE_CONSTRAINT);
    let out_dir = tempfile::tempdir().expect("tempdir");
    let out_path = out_dir.path().join("triage-out.txt");

    Command::cargo_bin("rulesteward")
        .expect("binary built")
        .args(["selinux", "triage", "--record"])
        .arg(record.path())
        .args(["-o"])
        .arg(&out_path)
        .assert()
        .success()
        .stdout(predicate::str::is_empty());

    let contents = std::fs::read_to_string(&out_path).expect("read -o output file");
    assert!(
        contents.contains("RBAC role constraint"),
        "the rendered report must land in the -o file, got: {contents}"
    );
}
