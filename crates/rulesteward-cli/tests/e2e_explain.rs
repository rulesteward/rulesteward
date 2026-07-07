//! End-to-end tests for `rulesteward fapolicyd explain` (issues #72/#73/#74).
//!
//! `commands/explain.rs::run` was at 0% line coverage (#440): a whole
//! subcommand with no test exercising it. These tests drive every reachable
//! branch: read record -> parse FANOTIFY event -> ruleset-is-dir check ->
//! `read_dir` -> read+parse each `.rules` file -> `explain_event` -> render
//! Human/Json.
//!
//! ## Happy-path fixture strategy
//!
//! `tests/corpus/explain/fanotify/{rocky9,rocky10}/ausearch.txt` are REAL
//! FANOTIFY denial records captured from live Rocky 9.8 / 10.2 VMs (see the
//! per-scenario README.md for provenance). Both records carry
//! `fan_type=1 fan_info=D` (hex `D` = decimal 13): an Era2 record that
//! `explain_event` resolves via a direct 1-based rule-index lookup, with NO
//! dependency on companion SYSCALL/PATH facts (exe/path/perm/pid/auid are all
//! `None` for a bare FANOTIFY line). So the "matching ruleset" this brief asks
//! for is simply a `rules.d/` with >= 13 rules; rule 13 is asserted directly,
//! not content-matched. `ruleset_13_dir()` below builds exactly that (12
//! filler `allow` rules + a `deny_audit` rule at position 13), which also
//! mirrors the real deny rule name from the VM capture (`90-deny-execute.rules`
//! in a stock fapolicyd ruleset).
//!
//! `tests/corpus/explain/fanotify/rocky8/ausearch.txt` has NO usable record at
//! all (Rocky 8.10's kernel/audit combination never emits a FANOTIFY audit
//! event); it is comment-only prose, so feeding it to `parse_audit_event`
//! exercises the unparseable-record error arm for free.
//!
//! Every assertion below was confirmed against the real binary's actual
//! output before being written (not guessed from reading the source).

use assert_cmd::Command;
use predicates::prelude::*;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn bin() -> Command {
    Command::cargo_bin("rulesteward").expect("binary built")
}

/// Path to a staged real FANOTIFY corpus record (`rocky8` | `rocky9` | `rocky10`).
fn corpus_record(scenario: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("corpus")
        .join("explain")
        .join("fanotify")
        .join(scenario)
        .join("ausearch.txt")
}

/// Build a `rules.d/`-shaped tempdir with exactly 13 rules: 12 filler `allow`
/// rules followed by a `deny_audit` rule at position 13, matching the
/// `fan_info=D` (0xD = 13 decimal) 1-based rule index in the staged records.
///
/// A leading `%set` definition is mixed in on purpose: `explain.rs` filters
/// `all_entries` down to `Entry::Rule` items only (a `%set` line parses to a
/// non-`Rule` `Entry`), so this also exercises that filter's `None` arm
/// without disturbing the 1-based rule numbering (only `Entry::Rule` items
/// count towards it).
fn ruleset_13_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut contents = String::from("%langs=text/x-perl,text/x-python\n");
    contents.push_str(&"allow uid=0 : all\n".repeat(12));
    contents.push_str("deny_audit perm=execute all : all\n");
    std::fs::write(dir.path().join("10-explain.rules"), contents).expect("write rules file");
    dir
}

/// Run `explain --record R --ruleset S --format F` and return
/// `(exit_code, stdout)`.
fn run_explain(record: &Path, ruleset: &Path, fmt: &str) -> (i32, String) {
    let out = bin()
        .args(["fapolicyd", "explain", "--record"])
        .arg(record)
        .args(["--ruleset"])
        .arg(ruleset)
        .args(["--format", fmt])
        .output()
        .expect("run");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

/// RAII guard: restores a chmod-0000 fixture to 0o755 on drop (even if the
/// assertion panics mid-test) so `tempfile`'s own cleanup can still remove it.
struct RestorePerms(PathBuf);

impl Drop for RestorePerms {
    fn drop(&mut self) {
        let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o755));
    }
}

// ---------------------------------------------------------------------------
// Happy path
// ---------------------------------------------------------------------------

/// `--format human` on a real Era2 record + a matching 13-rule ruleset exits
/// 0 (`EXIT_CLEAN`) and renders the DENIED explanation citing rule 13.
#[test]
fn explain_human_happy_path_exits_zero_and_explains_the_denial() {
    let ruleset = ruleset_13_dir();
    let (code, stdout) = run_explain(&corpus_record("rocky9"), ruleset.path(), "human");
    assert_eq!(
        code, 0,
        "happy path must exit 0 (EXIT_CLEAN), stdout: {stdout}"
    );
    assert!(
        stdout.contains("DENIED: <unknown>"),
        "stdout must render the DENIED explanation (no exe/path in a bare FANOTIFY record), got: {stdout}"
    );
    assert!(
        stdout.contains("Matched rule 13:"),
        "stdout must cite the 1-based rule number decoded from fan_info=D (0xD = 13 decimal), got: {stdout}"
    );
    assert!(
        stdout.contains("\"deny_audit perm=execute all : all\""),
        "stdout must quote the matched rule's exact text, got: {stdout}"
    );
    assert!(
        stdout.contains("subject trust=unknown, object trust=no"),
        "stdout must report subj_trust=2->unknown and obj_trust=0->no, got: {stdout}"
    );
}

/// `--format json` on the rocky10 record emits a valid `explain` envelope
/// (schemaVersion 1) with the rule-number match fields, trailing newline.
#[test]
fn explain_json_happy_path_has_correct_envelope() {
    let ruleset = ruleset_13_dir();
    let (code, stdout) = run_explain(&corpus_record("rocky10"), ruleset.path(), "json");
    assert_eq!(
        code, 0,
        "happy path must exit 0 (EXIT_CLEAN), stdout: {stdout}"
    );
    assert!(
        stdout.ends_with('\n'),
        "JSON output must end with a trailing newline"
    );
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON envelope");
    assert_eq!(v["kind"], "explain");
    assert_eq!(v["schemaVersion"], 1);
    assert_eq!(v["rule_number"], 13);
    assert_eq!(v["rule_text"], "deny_audit perm=execute all : all");
    assert_eq!(v["matched_by"], "rule_number");
    assert_eq!(v["decision"], "deny_audit");
    assert_eq!(v["subj_trust"], "unknown");
    assert_eq!(v["obj_trust"], "no");
}

// ---------------------------------------------------------------------------
// Error arms
// ---------------------------------------------------------------------------

/// The `rocky8` fixture has no real `type=FANOTIFY` record (Rocky 8.10's
/// kernel/audit combination never emits one; see its README.md) - only prose
/// mentioning the string. `parse_audit_event` fails to extract required
/// fields from it, exercising the unparseable-record arm: exit 2
/// (`EXIT_ERRORS`), not exit 5 (that code is reserved for an unparseable RULES
/// file, not a denial record; f1 section 4.2 / issue #114).
#[test]
fn explain_unparseable_record_exits_errors() {
    let ruleset = ruleset_13_dir();
    bin()
        .args(["fapolicyd", "explain", "--record"])
        .arg(corpus_record("rocky8"))
        .args(["--ruleset"])
        .arg(ruleset.path())
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("parsing FANOTIFY record"));
}

/// A `--ruleset` that points at a file (not a directory) exits 3
/// (`EXIT_TOOL_FAILURE`).
#[test]
fn explain_ruleset_path_is_a_file_exits_tool_failure() {
    let record = corpus_record("rocky9");
    bin()
        .args(["fapolicyd", "explain", "--record"])
        .arg(&record)
        .args(["--ruleset"])
        .arg(&record) // a file, not a directory
        .assert()
        .failure()
        .code(3)
        .stderr(predicate::str::contains("is not a directory"));
}

/// A `.rules` file inside the ruleset directory that fails to parse exits 3
/// (`EXIT_TOOL_FAILURE`) - distinct from the record-parse-error arm above.
#[test]
fn explain_rule_file_parse_error_exits_tool_failure() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        dir.path().join("10-bad.rules"),
        "allow uid=0 : all\n!!!garbage\n",
    )
    .expect("write bad rules file");
    bin()
        .args(["fapolicyd", "explain", "--record"])
        .arg(corpus_record("rocky9"))
        .args(["--ruleset"])
        .arg(dir.path())
        .assert()
        .failure()
        .code(3)
        .stderr(predicate::str::contains("parsing rule file"));
}

/// A record whose Era2 rule index (13) exceeds the supplied ruleset's length
/// (5) hits `explain_event`'s `RuleOutOfRange` error arm: exit 2
/// (`EXIT_ERRORS`), not a tool failure - the inputs were readable and
/// individually valid, they just don't agree with each other.
#[test]
fn explain_rule_out_of_range_exits_errors() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        dir.path().join("10-small.rules"),
        "allow uid=0 : all\n".repeat(5),
    )
    .expect("write small rules file");
    bin()
        .args(["fapolicyd", "explain", "--record"])
        .arg(corpus_record("rocky10"))
        .args(["--ruleset"])
        .arg(dir.path())
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains(
            "record references rule 13, ruleset has 5",
        ));
}

// ---------------------------------------------------------------------------
// Filesystem-error arms (chmod 0000; verified reliable for the non-root
// `runner` user this suite runs as both locally and in CI)
// ---------------------------------------------------------------------------

/// An unreadable record file exits 3 (`EXIT_TOOL_FAILURE`) at the very first
/// `std::fs::read_to_string(&args.record)` call.
#[test]
fn explain_record_file_unreadable_exits_tool_failure() {
    let dir = tempfile::tempdir().expect("tempdir");
    let record_path = dir.path().join("unreadable-record.txt");
    std::fs::copy(corpus_record("rocky9"), &record_path).expect("copy record");
    std::fs::set_permissions(&record_path, std::fs::Permissions::from_mode(0o000))
        .expect("chmod 0000");
    let _restore = RestorePerms(record_path.clone());

    // Root (RHEL-family distro CI) bypasses DAC: 0o000 stays readable, so the
    // "reading record file" arm is unreachable. Skip rather than false-fail (the
    // `_restore` guard restores perms on return); assertion stays live non-root.
    if std::fs::File::open(&record_path).is_ok() {
        eprintln!(
            "SKIP explain_record_file_unreadable_exits_tool_failure: 0o000 is readable here \
             (running as root / CAP_DAC_OVERRIDE); cannot exercise the deny arm"
        );
        return;
    }

    let ruleset = ruleset_13_dir();
    bin()
        .args(["fapolicyd", "explain", "--record"])
        .arg(&record_path)
        .args(["--ruleset"])
        .arg(ruleset.path())
        .assert()
        .failure()
        .code(3)
        .stderr(predicate::str::contains("reading record file"));
}

/// An unreadable ruleset directory still passes the `is_dir()` check (stat
/// only needs search permission on ancestors, not the target itself) but
/// fails `std::fs::read_dir`, exiting 3 (`EXIT_TOOL_FAILURE`).
#[test]
fn explain_ruleset_dir_unreadable_exits_tool_failure() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("10-explain.rules"), "allow uid=0 : all\n").expect("write");
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o000))
        .expect("chmod 0000");
    let _restore = RestorePerms(dir.path().to_path_buf());

    // Root bypasses DAC: read_dir on a 0o000 directory still succeeds, so the
    // "reading ruleset directory" arm is unreachable. Skip rather than
    // false-fail (the `_restore` guard restores perms on return).
    if std::fs::read_dir(dir.path()).is_ok() {
        eprintln!(
            "SKIP explain_ruleset_dir_unreadable_exits_tool_failure: 0o000 dir is readable here \
             (running as root / CAP_DAC_OVERRIDE); cannot exercise the deny arm"
        );
        return;
    }

    bin()
        .args(["fapolicyd", "explain", "--record"])
        .arg(corpus_record("rocky9"))
        .args(["--ruleset"])
        .arg(dir.path())
        .assert()
        .failure()
        .code(3)
        .stderr(predicate::str::contains("reading ruleset directory"));
}

/// A `.rules` file that `read_dir` can list (the directory itself is
/// readable) but cannot be read individually exits 3 (`EXIT_TOOL_FAILURE`) -
/// distinct from the whole-directory-unreadable arm above.
#[test]
fn explain_rule_file_unreadable_exits_tool_failure() {
    let dir = tempfile::tempdir().expect("tempdir");
    let rule_file = dir.path().join("10-explain.rules");
    std::fs::write(&rule_file, "allow uid=0 : all\n").expect("write");
    std::fs::set_permissions(&rule_file, std::fs::Permissions::from_mode(0o000))
        .expect("chmod 0000");
    let _restore = RestorePerms(rule_file.clone());

    // Root bypasses DAC: File::open on the 0o000 rule file still succeeds, so
    // the "reading rule file" arm is unreachable. Skip rather than false-fail
    // (the `_restore` guard restores perms on return).
    if std::fs::File::open(&rule_file).is_ok() {
        eprintln!(
            "SKIP explain_rule_file_unreadable_exits_tool_failure: 0o000 file is readable here \
             (running as root / CAP_DAC_OVERRIDE); cannot exercise the deny arm"
        );
        return;
    }

    bin()
        .args(["fapolicyd", "explain", "--record"])
        .arg(corpus_record("rocky9"))
        .args(["--ruleset"])
        .arg(dir.path())
        .assert()
        .failure()
        .code(3)
        .stderr(predicate::str::contains("reading rule file"));
}
