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
use std::time::Duration;

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

// ---------------------------------------------------------------------------
// Special-file (FIFO) arm - #583 half A
// ---------------------------------------------------------------------------

/// Create a FIFO at `dir/name` via the `mkfifo(1)` coreutil. No writer is ever
/// opened on it -- reading it in blocking mode is exactly the #560/#583 hang
/// trigger (opening a read-only FIFO blocks until a writer appears, fifo(7)).
/// Mirrors `path_error_fifo.rs`'s `make_fifo` helper (test files are separate
/// binaries and cannot share it directly).
fn make_fifo(dir: &Path, name: &str) -> PathBuf {
    let fifo = dir.join(name);
    let status = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .expect("mkfifo(1) available on the Linux distribution target");
    assert!(
        status.success(),
        "mkfifo must succeed for {}",
        fifo.display()
    );
    fifo
}

/// `explain --record <fifo>` must fail FAST, never hang: `run`'s very first
/// read (`commands/explain.rs:23`, raw `std::fs::read_to_string(&args.record)`)
/// has no special-file guard today. Bounded by a 15s `assert_cmd` timeout so a
/// wrong (hanging) implementation fails this ONE test instead of wedging the
/// suite; `status.code().is_some()` is the hang signal (`assert_cmd`'s
/// `.timeout()` kills the child on expiry, which `.output()` still reports as
/// `Ok(Output)` with `status.code() == None`, never an `Err`).
///
/// NOTE: unlike this call site, the SECOND read in `explain.rs` (the
/// ruleset-directory loop at `commands/explain.rs:72`) is reached only for
/// entries that pass `p.is_file()` in the loop's own collection filter
/// (`commands/explain.rs:58`), which already excludes a FIFO before the read
/// -- so a bare `*.rules` FIFO placed in `--ruleset` cannot reach that second
/// call site at all, and no hang test is written for it here (a test that
/// cannot fail regardless of the implementation would be a vacuous positive
/// control, not a regression pin).
#[test]
fn explain_record_file_fifo_fails_fast_not_hang() {
    let dir = tempfile::tempdir().expect("tempdir");
    let fifo = make_fifo(dir.path(), "record.fifo");
    let ruleset = ruleset_13_dir();

    let out = bin()
        .args(["fapolicyd", "explain", "--record"])
        .arg(&fifo)
        .args(["--ruleset"])
        .arg(ruleset.path())
        .timeout(Duration::from_secs(15))
        .output()
        .unwrap_or_else(|e| panic!("command failed to run (spawn/IO error, not a timeout): {e}"));

    assert!(
        out.status.code().is_some(),
        "hang: child killed by 15s timeout (status.code() is None, meaning the \
         process was killed by a signal rather than exiting normally) -- this IS \
         the #583 gap: explain::run's raw std::fs::read_to_string(&args.record) \
         has no special-file guard, so a FIFO with no writer hangs forever; \
         stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        out.status.code(),
        Some(3),
        "a FIFO --record must be a tool failure (EXIT_TOOL_FAILURE=3), not a hang \
         or a different exit code; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains(&fifo.display().to_string()),
        "the diagnostic must name the offending FIFO path; stderr: {stderr}"
    );
    assert!(
        stderr.contains("refusing to read non-regular file"),
        "the rejection must route through the shared rulesteward_core::fsread \
         guard specifically (not a hand-rolled is_file()/is_fifo() precheck \
         that still does a raw, TOCTOU-vulnerable read afterwards); stderr: {stderr}"
    );
}

/// #583 adversarial-review follow-up (blocker 2): a FIFO-only special-file
/// guard is not enough. `/dev/null` (a character device) never hangs under a
/// raw `std::fs::read_to_string` - it reads back an instant empty string -
/// so TODAY `explain --record /dev/null` silently succeeds past the read and
/// hits the UNRELATED "no FANOTIFY record found" parse-error arm
/// (`EXIT_ERRORS`=2, measured live 2026-07-24), not a crash. A
/// `if is_fifo(path) { reject } else { raw read }` implementation passes
/// every FIFO test above yet still lets this character-device case through
/// to the wrong error arm. After the fix (routing through the shared
/// `rulesteward_core::fsread::read_to_string`, which rejects ANY
/// non-regular file), `/dev/null` must be a tool failure BEFORE parsing is
/// ever attempted.
#[test]
fn explain_record_dev_null_is_a_tool_failure_not_a_parse_error() {
    let ruleset = ruleset_13_dir();
    let out = bin()
        .args(["fapolicyd", "explain", "--record", "/dev/null"])
        .args(["--ruleset"])
        .arg(ruleset.path())
        .timeout(Duration::from_secs(10))
        .output()
        .unwrap_or_else(|e| panic!("command failed to run (spawn/IO error): {e}"));

    assert_eq!(
        out.status.code(),
        Some(3),
        "/dev/null must be rejected as a non-regular file (EXIT_TOOL_FAILURE=3), \
         not read as an empty record and hit the unrelated parse-error arm \
         (EXIT_ERRORS=2, today's behavior); stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("refusing to read non-regular file"),
        "the rejection must route through the shared rulesteward_core::fsread \
         guard (not a FIFO-only special case); stderr: {stderr}"
    );
}

// ---------------------------------------------------------------------------
// Adversarial-review miss 1 (session 9j lane 3): restored stream support.
// `read_to_string` rejects EVERY FIFO, even one with a live writer -- but
// `--record` is a stream-shaped input operators legitimately pipe in
// (`--record <(cat ausearch.raw.txt)`). `read_stream_to_string` accepts a
// FIFO with a live writer; these tests pin that a pipe round-trips
// byte-identically to the same fixture read from a regular file.
// ---------------------------------------------------------------------------

/// Spawn a background thread that opens `fifo` for writing, writes `content`,
/// then drops the file (closing the write end so the reader sees EOF). Not
/// joined: by the time the reading child process exits (what `.output()`
/// below awaits), the writer must already have completed its blocking write +
/// close -- that IS what produces the EOF the reader is waiting for -- so
/// there is nothing left to wait for; the OS thread is reclaimed when the
/// test binary exits.
fn spawn_fifo_writer(fifo: PathBuf, content: Vec<u8>) {
    use std::io::Write as _;
    std::thread::spawn(move || {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .open(&fifo)
            .expect("open fifo for write");
        f.write_all(&content)
            .expect("write fixture content to fifo");
    });
}

/// `explain --record <fifo-with-a-live-writer>` must be accepted, not
/// rejected: reading the SAME real corpus record through a pipe must produce
/// BYTE-IDENTICAL output to reading it from a regular file. An exit-0-only
/// assertion would also pass a silently truncated 64KB read; comparing full
/// stdout catches that.
#[test]
fn explain_record_fifo_with_live_writer_round_trips_byte_identical() {
    let ruleset = ruleset_13_dir();
    let regular = corpus_record("rocky9");
    let content = std::fs::read(&regular).expect("read corpus fixture");

    let (baseline_code, baseline_stdout) = run_explain(&regular, ruleset.path(), "json");
    assert_eq!(
        baseline_code, 0,
        "baseline regular-file run must succeed, stdout: {baseline_stdout}"
    );

    let dir = tempfile::tempdir().expect("tempdir");
    let fifo = make_fifo(dir.path(), "record.fifo");
    spawn_fifo_writer(fifo.clone(), content);

    let out = bin()
        .args(["fapolicyd", "explain", "--record"])
        .arg(&fifo)
        .args(["--ruleset"])
        .arg(ruleset.path())
        .args(["--format", "json"])
        .timeout(Duration::from_secs(15))
        .output()
        .unwrap_or_else(|e| panic!("command failed to run (spawn/IO error, not a timeout): {e}"));

    assert_eq!(
        out.status.code(),
        Some(0),
        "a FIFO --record with a live writer must round-trip successfully, not \
         be rejected like a writerless FIFO; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).expect("utf8 stdout");
    assert_eq!(
        stdout, baseline_stdout,
        "a readable pipe --record must produce BYTE-IDENTICAL output to the \
         same fixture read from a regular file"
    );
}
