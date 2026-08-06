//! End-to-end tests for `rulesteward fapolicyd report --format human` and
//! `--format csv`.
//!
//! The JSON oracle tests in `report_oracle.rs` exercise the full corpus but
//! always use `--format json`. These tests cover the human TABLE renderer
//! (`render_human_register`) and the CSV renderer (`render_csv_register`)
//! so the mutation survivors in those renderers are killed.
//!
//! ## Mutation survivors killed by this file
//!
//! **output/register.rs (human + csv renderers + helpers)**
//! - `render_human_register` lines 213, 237:35 (`==` -> `!=`) - killed by
//!   summary-line assertions checking `hash_pinned` and `trust_scoped` counts.
//! - `truncate` line 253 / 253:26 (`<=` -> `>`) - killed by the
//!   `report_human_truncates_long_subject` test (39-char subject truncated to 38).
//! - `hash_origin_str` line 261 - killed by CSV/human assertions that check the
//!   exact string "rule-filehash" vs "none" in the output.
//! - `render_csv_register` line 176 - killed by CSV header + data-row assertions.
//!
//! **rulesteward-fapolicyd/src/register.rs (`compute_scope`)**
//! - Line 326 delete `"pattern"` arm in `obj_key_scope` - killed by
//!   `report_json_scope_pattern_object` which verifies scope="pattern" when
//!   pattern= is the only OBJECT-side key.
//!
//! ## Equivalent mutants (documented, NOT killed by tests)
//!
//! Lines 348 and 357 in `compute_scope`: `<` -> `<=` in the filter closures.
//!
//! Both closures use a strict `<` comparison to find the NARROWEST constraint:
//! `filter(|(p, _)| *p < best_pri)`. The priorities are chosen so that no two
//! keys on the SAME side share a priority number, and the object-side priority
//! numbers (1-6) and subject-side priority numbers (50, 60, 70) are also
//! fully disjoint. Therefore:
//!
//! - In the object loop (line 348): two object keys can never share a priority
//!   (each maps to a unique value 1-6), so a tie is impossible. `<` and `<=`
//!   produce identical results for all inputs.
//! - In the subject loop (line 357): subject keys map to 50, 60, or 70. The
//!   `best_pri` at the start of the subject loop is either 255 (no object key
//!   set a scope) or one of 1-6 (an object key set a scope). Neither 50, 60,
//!   nor 70 can equal any of {1, 2, 3, 4, 5, 6, 255}, so a tie is impossible.
//!   `<` and `<=` produce identical results.
//!
//! Both are genuine equivalent mutants. They are documented in `.cargo/mutants.toml`
//! `exclude_re` so the mutation gate accepts them without a confounding survivor.

use assert_cmd::Command;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn corpus_dir() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("corpus")
        .join("report")
}

fn scenario_rules_d(category: &str, id: &str) -> std::path::PathBuf {
    corpus_dir().join(category).join(id).join("rules.d")
}

/// Build a temporary rules.d with a single `.rules` file.
fn make_rules_dir(filename: &str, content: &str) -> TempDir {
    let tmp = tempfile::tempdir().expect("tempdir for rules.d fixture");
    let rules_d = tmp.path().join("rules.d");
    fs::create_dir_all(&rules_d).expect("create rules.d");
    fs::write(rules_d.join(filename), content).expect("write rules file");
    tmp
}

/// Run `rulesteward fapolicyd report <rules_d> --format human` and return
/// the stdout string. Panics if the command fails or the binary cannot be found.
fn run_report_human(rules_d: &Path) -> String {
    let output = Command::cargo_bin("rulesteward")
        .expect("rulesteward binary")
        .args(["fapolicyd", "report"])
        .arg(rules_d)
        .args(["--format", "human"])
        .output()
        .expect("run rulesteward");
    assert_eq!(
        output.status.code().unwrap_or(-1),
        0,
        "expected exit 0 from human report; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// Run `rulesteward fapolicyd report <rules_d> --format csv` and return
/// the stdout string. Panics if the command fails.
fn run_report_csv(rules_d: &Path) -> String {
    let output = Command::cargo_bin("rulesteward")
        .expect("rulesteward binary")
        .args(["fapolicyd", "report"])
        .arg(rules_d)
        .args(["--format", "csv"])
        .output()
        .expect("run rulesteward");
    assert_eq!(
        output.status.code().unwrap_or(-1),
        0,
        "expected exit 0 from csv report; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

// ---------------------------------------------------------------------------
// Human renderer tests (kills render_human_register mutations)
// ---------------------------------------------------------------------------

/// The human renderer produces the column values and summary line for a
/// representative multi-grant ruleset drawn from the corpus.
///
/// Uses `cardinality/card-multi-many-mixed` which has 8 grants spanning
/// all scope/origin variants.
///
/// Kills:
/// - `render_human_register` lines 213 and 237:35 `==` -> `!=`: the summary
///   line's hash-pinned count (1) and trust-scoped count (1) both assert
///   specific values that only the correct comparison produces.
/// - `hash_origin_str` line 261: asserts both "rule-filehash" and "none" appear.
#[test]
fn report_human_multi_grant_content_and_summary() {
    let rules_d = scenario_rules_d("cardinality", "card-multi-many-mixed");
    let out = run_report_human(&rules_d);

    // --- column content checks ---

    // The `allow` + `execute` + `all`(subject) + `trust=1`(object) grant (line 1)
    assert!(
        out.contains("allow"),
        "human output must contain 'allow' decision: {out}"
    );
    assert!(
        out.contains("execute"),
        "human output must contain 'execute' perm: {out}"
    );

    // The `allow_open` + `exe=/usr/bin/rpm` grant (line 2)
    assert!(
        out.contains("exe=/usr/bin/rpm"),
        "human output must contain subject exe=/usr/bin/rpm: {out}"
    );

    // hash_origin_str: the filehash grant (line 7) must render "rule-filehash"
    assert!(
        out.contains("rule-filehash"),
        "human output must contain 'rule-filehash' for the filehash grant: {out}"
    );

    // hash_origin_str: non-hash grants must render "none"
    assert!(
        out.contains("none"),
        "human output must contain 'none' for non-hash grants: {out}"
    );

    // Source file and line appear in the output
    assert!(
        out.contains("25-many.rules"),
        "human output must contain source filename: {out}"
    );

    // --- summary line ---
    // The corpus has 8 allow-grants, 1 with HashOrigin::RuleFilehash (the SHA256
    // filehash on line 7), and 1 with Scope::Trust (the trust=1 on line 1).
    assert!(
        out.contains("8 allow-grants"),
        "summary line must report 8 allow-grants: {out}"
    );
    assert!(
        out.contains("1 hash-pinned"),
        "summary line must report 1 hash-pinned: {out}"
    );
    assert!(
        out.contains("1 trust-scoped"),
        "summary line must report 1 trust-scoped: {out}"
    );
}

/// Zero-grants ruleset: summary line says "0 allow-grants (0 hash-pinned, 0 trust-scoped)".
///
/// This is a complementary check that the summary counts are not hard-coded.
#[test]
fn report_human_zero_grants_summary() {
    let rules_d = scenario_rules_d("cardinality", "card-empty-no-grants");
    let out = run_report_human(&rules_d);
    assert!(
        out.contains("0 allow-grants"),
        "empty register summary must say 0 allow-grants: {out}"
    );
    assert!(
        out.contains("0 hash-pinned"),
        "empty register summary must say 0 hash-pinned: {out}"
    );
    assert!(
        out.contains("0 trust-scoped"),
        "empty register summary must say 0 trust-scoped: {out}"
    );
}

/// `truncate` boundary: a subject that is longer than 38 chars must be truncated
/// to exactly 38 chars in the human column output.
///
/// Kills `truncate` mutation `<=` -> `>` at line 253: the mutant inverts the
/// condition, so strings LONGER than `max_len` are returned un-truncated (the if
/// and else branches swap). The test uses a subject that ends with a distinctive
/// sentinel character that only appears if truncation is skipped.
#[test]
fn report_human_truncates_long_subject() {
    // Build a 39-char subject: 38 uniform chars + a distinctive sentinel '!'.
    // With correct truncation: the '!' at position 38 is dropped (count=39 > 38).
    // With the mutant (`>` instead of `<=`): the if-branch returns s.to_owned()
    // for count > max_len, so the full 39-char string (including '!') appears.
    let base = "a".repeat(38); // 38 'a' chars
    let subject = format!("exe=/{base}!"); // "exe=/" (5) + 38 a's + '!' = 44 chars total

    // With truncation at 38: output is "exe=/" + 33 a's (38 chars), '!' is dropped.
    // With NO truncation (mutant): full 44-char string appears including '!'.
    let sentinel = "!"; // only present if truncation is skipped

    let rule = format!("allow perm=open {subject} : all\n");
    let tmp = make_rules_dir("10-test.rules", &rule);
    let rules_d = tmp.path().join("rules.d");
    let out = run_report_human(&rules_d);

    // The sentinel must NOT appear in the rendered subject column.
    // If truncation is working correctly, the 44-char subject is cut to 38
    // chars and '!' at position 43 is never rendered.
    assert!(
        !out.contains(sentinel),
        "human output must NOT contain the sentinel '!' beyond the truncation point \
         (subject was 44 chars, truncated to 38; '!' is at position 43): {out}"
    );
}

/// A single hash-pinned grant produces the correct human summary:
/// "1 allow-grants (1 hash-pinned, 0 trust-scoped)".
///
/// Also verifies the hash value is printed on the continuation line.
#[test]
fn report_human_single_hash_pinned_grant() {
    let sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let rule = format!("allow perm=open all : filehash={sha256}\n");
    let tmp = make_rules_dir("62-sha256.rules", &rule);
    let rules_d = tmp.path().join("rules.d");
    let out = run_report_human(&rules_d);

    assert!(
        out.contains("1 allow-grants"),
        "summary must say 1 allow-grants: {out}"
    );
    assert!(
        out.contains("1 hash-pinned"),
        "summary must say 1 hash-pinned: {out}"
    );
    assert!(
        out.contains("0 trust-scoped"),
        "summary must say 0 trust-scoped: {out}"
    );
    // hash_origin_str for RuleFilehash
    assert!(
        out.contains("rule-filehash"),
        "human output must show 'rule-filehash' for this grant: {out}"
    );
    // Continuation line with the actual hash value
    assert!(
        out.contains(&format!("hash={sha256}")),
        "human output must contain 'hash=<sha256>' on the continuation line: {out}"
    );
}

// ---------------------------------------------------------------------------
// CSV renderer tests (kills render_csv_register mutation)
// ---------------------------------------------------------------------------

/// The CSV renderer emits the correct header row + at least one data row.
///
/// Kills `render_csv_register` line 176 stub (which would produce no output
/// or a structurally wrong CSV), by asserting the exact header and a specific
/// data-row field match.
#[test]
fn report_csv_header_and_data_row() {
    let sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let rule = format!("allow perm=execute exe=/usr/bin/python3 : filehash={sha256}\n");
    let tmp = make_rules_dir("C5-exehash.rules", &rule);
    let rules_d = tmp.path().join("rules.d");
    let out = run_report_csv(&rules_d);

    let lines: Vec<&str> = out.lines().collect();
    assert!(
        lines.len() >= 2,
        "CSV must have at least a header row + one data row; got {lines:?}"
    );

    // Header row: exact column names in order
    let header = lines[0];
    assert_eq!(
        header,
        "decision,perm,subject,object,hash,hashOrigin,scope,sourceFile,sourceLine,loadIndex",
        "CSV header row must match the expected column names"
    );

    // Data row: verify key fields
    let data = lines[1];
    assert!(
        data.contains("allow"),
        "CSV data row must contain 'allow' decision: {data}"
    );
    assert!(
        data.contains("execute"),
        "CSV data row must contain 'execute' perm: {data}"
    );
    assert!(
        data.contains("exe=/usr/bin/python3"),
        "CSV data row must contain the subject: {data}"
    );
    assert!(
        data.contains(sha256),
        "CSV data row must contain the hash digest: {data}"
    );
    assert!(
        data.contains("rule-filehash"),
        "CSV data row must contain 'rule-filehash' for hashOrigin: {data}"
    );
    assert!(
        data.contains("hash"),
        "CSV data row must contain 'hash' for scope: {data}"
    );
}

/// CSV with multiple grants: verifies the scope column uses the explicit
/// `scope_str` mapping (not `format!("{:?}", scope).to_lowercase()`).
///
/// The variants tested span several Scope discriminants to pin the full
/// mapping independently of the Debug impl.
#[test]
fn report_csv_scope_column_variants() {
    // Rules that produce different scopes:
    // - `all` (no object constraint)
    // - `path` (path= on object)
    // - `ftype` (ftype= on object)
    // - `trust` (trust=1 on object)
    // - `hash` (filehash= on object)
    let sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let rules = format!(
        "allow perm=open all : all\n\
         allow perm=open all : path=/etc/hosts\n\
         allow perm=open all : ftype=text/plain\n\
         allow perm=execute all : trust=1\n\
         allow perm=open all : filehash={sha256}\n"
    );
    let tmp = make_rules_dir("10-scopes.rules", &rules);
    let rules_d = tmp.path().join("rules.d");
    let out = run_report_csv(&rules_d);

    // Each scope token must appear in the scope column of at least one row.
    // A mutation that flips scope_str("all") to "ALL" or drops a variant would fail.
    assert!(out.contains(",all,"), "CSV must have scope=all row: {out}");
    assert!(
        out.contains(",path,"),
        "CSV must have scope=path row: {out}"
    );
    assert!(
        out.contains(",ftype,"),
        "CSV must have scope=ftype row: {out}"
    );
    assert!(
        out.contains(",trust,"),
        "CSV must have scope=trust row: {out}"
    );
    assert!(
        out.contains(",hash,"),
        "CSV must have scope=hash row: {out}"
    );
}

// ---------------------------------------------------------------------------
// compute_scope pattern-on-object arm (kills line 326 delete `pattern` arm)
// ---------------------------------------------------------------------------

/// A grant whose ONLY object-side constraint is `pattern=ld_so` must produce
/// `scope="pattern"` in the JSON output.
///
/// Kills the line-326 deletion mutant in `obj_key_scope`: if the `"pattern"`
/// arm is deleted, `pattern=` on the object side returns `None` and the scope
/// falls back to `Scope::All` ("all"), making this assertion fail.
///
/// Note: `pattern=` may appear on the object side in fapolicyd rules just as
/// it appears on the subject side. The scope is still "pattern" in both cases,
/// but the mechanism is different (`obj_key_scope` for object-side vs
/// `subj_key_scope` for subject-side). The existing oracle tests only cover
/// subject-side pattern via `scope-pattern-subject`; this test covers the
/// object-side path.
#[test]
fn report_json_scope_pattern_object() {
    use assert_cmd::Command;

    // `pattern=ld_so` on the OBJECT side; subject is `all`.
    let rule = "allow perm=any all : pattern=ld_so\n";
    let tmp = make_rules_dir("56-obj-pattern.rules", rule);
    let rules_d = tmp.path().join("rules.d");

    let output = Command::cargo_bin("rulesteward")
        .expect("rulesteward binary")
        .args(["fapolicyd", "report"])
        .arg(&rules_d)
        .args(["--format", "json"])
        .output()
        .expect("run rulesteward");

    let exit_code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(stdout.as_ref()).unwrap_or_else(|e| {
        panic!("report output not valid JSON (exit {exit_code}): {e}\nstdout: {stdout}")
    });

    assert_eq!(exit_code, 0, "expected exit 0");

    let grants = parsed["grants"].as_array().expect("grants array");
    assert_eq!(grants.len(), 1, "expected exactly 1 grant");

    let scope = grants[0]["scope"].as_str().expect("scope field");
    assert_eq!(
        scope, "pattern",
        "a rule with `pattern=ld_so` on the OBJECT side must produce scope=pattern, not {scope:?}"
    );
}

// ---------------------------------------------------------------------------
// scope_str exhaustive pin (kills scope_str variant deletions)
// ---------------------------------------------------------------------------

/// The `scope_str` helper must map every `Scope` variant to its exact lowercase
/// wire token, independent of the `Debug` impl.
///
/// This mirrors the `tier_str` pattern documented in the spec. Tested here
/// via the CSV renderer's scope column, since `scope_str` is called from
/// `render_csv_register`.
#[test]
fn report_csv_scope_str_all_variants_pinned() {
    // dir= on object -> "dir"; pattern= on subject -> "pattern"
    let rules = "allow perm=open all : dir=/var/tmp/\n\
                 allow perm=any pattern=ld_so : all\n";
    let tmp = make_rules_dir("10-dir-pat.rules", rules);
    let rules_d = tmp.path().join("rules.d");
    let out = run_report_csv(&rules_d);

    // "dir" scope
    assert!(out.contains(",dir,"), "CSV must have scope=dir row: {out}");
    // "pattern" scope (from subject-side pattern key)
    assert!(
        out.contains(",pattern,"),
        "CSV must have scope=pattern row: {out}"
    );
}

// ---------------------------------------------------------------------------
// resolve_targets + against-trustdb wiring arms (#440 coverage top-up)
// ---------------------------------------------------------------------------
//
// None of `report_oracle.rs`'s 73 golden scenarios or the renderer tests above
// exercise `--file` (single-file mode), a non-directory positional PATH, a
// fapd-F01 parse error, or an `--against-trustdb` path that fails to resolve -
// every one of those tests passes a plain, already-valid `rules.d/` directory.

/// `--file <single-file>` is single-file mode (`resolve_targets` returns a
/// one-element `Vec` without ever consulting `read_dir`), distinct from the
/// positional-directory mode every other test in this file uses.
#[test]
fn report_file_flag_single_file_mode() {
    let tmp = make_rules_dir("10-x.rules", "deny_audit perm=open all : all\n");
    let single_file = tmp.path().join("rules.d").join("10-x.rules");

    Command::cargo_bin("rulesteward")
        .expect("rulesteward binary")
        .args(["fapolicyd", "report", "--file"])
        .arg(&single_file)
        .args(["--format", "json"])
        .assert()
        .success()
        .code(0)
        .stdout(predicates::str::contains(
            "\"kind\": \"exception-register\"",
        ));
}

/// A positional PATH that is not a directory (and `--file` was not used) hits
/// `resolve_targets`'s `dir.is_dir()` guard: a tool failure, not a parse error.
#[test]
fn report_positional_path_not_a_directory_is_a_tool_failure() {
    let tmp = make_rules_dir("10-x.rules", "allow perm=open all : all\n");
    let not_a_dir = tmp.path().join("rules.d").join("10-x.rules");

    Command::cargo_bin("rulesteward")
        .expect("rulesteward binary")
        .arg("fapolicyd")
        .arg("report")
        .arg(&not_a_dir)
        .assert()
        .failure()
        .code(3)
        .stderr(predicates::str::contains("not a directory"));
}

/// A `rules.d/` containing a fapd-F01 parse error exits `EXIT_RULE_PARSE_ERROR`
/// = 5 with the diagnostic printed to stderr - the parse-error arm inside
/// `run`'s per-file loop, distinct from `resolve_targets`'s own errors above.
#[test]
fn report_rules_parse_error_exits_five() {
    let tmp = make_rules_dir("10-bad.rules", "allow uid=0 : all\n!!!garbage\n");
    let rules_d = tmp.path().join("rules.d");

    Command::cargo_bin("rulesteward")
        .expect("rulesteward binary")
        .args(["fapolicyd", "report"])
        .arg(&rules_d)
        .assert()
        .failure()
        .code(5)
        .stderr(predicates::str::contains("fapd-F01"));
}

/// `--against-trustdb <path>` that is not a directory hits the trust-DB
/// enrichment block's own directory guard: exit `EXIT_LMDB_ERROR` = 4.
#[test]
fn report_against_trustdb_not_a_directory_exits_lmdb_error() {
    let tmp = make_rules_dir("10-x.rules", "allow perm=open all : all\n");
    let rules_d = tmp.path().join("rules.d");
    let not_a_dir = rules_d.join("10-x.rules");

    Command::cargo_bin("rulesteward")
        .expect("rulesteward binary")
        .args(["fapolicyd", "report"])
        .arg(&rules_d)
        .args(["--against-trustdb"])
        .arg(&not_a_dir)
        .assert()
        .failure()
        .code(4)
        .stderr(predicates::str::contains("not a directory"));
}

/// `--against-trustdb <dir>` that IS a directory but is not a valid LMDB
/// environment (no `data.mdb`/`lock.mdb`) hits `open_trustdb_readonly`'s error
/// arm - distinct from the not-a-directory guard above.
#[test]
fn report_against_trustdb_invalid_env_exits_lmdb_error() {
    let tmp = make_rules_dir("10-x.rules", "allow perm=open all : all\n");
    let rules_d = tmp.path().join("rules.d");
    let empty_dir = tempfile::tempdir().expect("tempdir for empty (non-LMDB) trust DB");

    Command::cargo_bin("rulesteward")
        .expect("rulesteward binary")
        .args(["fapolicyd", "report"])
        .arg(&rules_d)
        .args(["--against-trustdb"])
        .arg(empty_dir.path())
        .assert()
        .failure()
        .code(4)
        .stderr(predicates::str::contains("opening trust DB"));
}

// ---------------------------------------------------------------------------
// Special-file (FIFO) arms - #583 half A
// ---------------------------------------------------------------------------

/// Create a FIFO at `dir/name` via the `mkfifo(1)` coreutil. No writer is ever
/// opened on it -- reading it in blocking mode is exactly the #560/#583 hang
/// trigger (opening a read-only FIFO blocks until a writer appears, fifo(7)).
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

/// `report --file <fifo>` must fail FAST, never hang: `resolve_targets`'
/// single-file branch (`commands/report.rs:246-248`) returns the path
/// unconditionally with no `is_file()` gate, so the read loop's raw
/// `std::fs::read_to_string(path)` (`commands/report.rs:56`) is the actual
/// #560/#583 hang mechanism on a FIFO with no writer. Bounded by a 15s
/// `assert_cmd` timeout so a wrong (hanging) implementation fails this ONE
/// test instead of wedging the suite; `status.code().is_some()` is the hang
/// signal (a killed child still yields `Ok(Output)` from `.output()`, with
/// `status.code() == None`).
///
/// NOTE: the sibling DIRECTORY-mode loop (`--path <dir>`, `commands/report.rs`
/// `resolve_targets`' `read_dir` branch) filters entries through `p.is_file()`
/// (`commands/report.rs:261`) before ever reading them, so a bare `*.rules`
/// FIFO placed in a `--path` directory cannot reach that read at all - only
/// the gate-free `--file` single-file mode is exercised here.
#[test]
fn report_file_fifo_fails_fast_not_hang() {
    let dir = tempfile::tempdir().expect("tempdir");
    let fifo = make_fifo(dir.path(), "policy.rules");

    let out = Command::cargo_bin("rulesteward")
        .expect("rulesteward binary")
        .args(["fapolicyd", "report", "--file"])
        .arg(&fifo)
        .timeout(Duration::from_secs(15))
        .output()
        .unwrap_or_else(|e| panic!("command failed to run (spawn/IO error, not a timeout): {e}"));

    assert!(
        out.status.code().is_some(),
        "hang: child killed by 15s timeout (status.code() is None) -- this IS the \
         #583 gap: report's target-file read loop has no special-file guard; \
         stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        out.status.code(),
        Some(3),
        "a FIFO --file target must be a tool failure (EXIT_TOOL_FAILURE=3), not a \
         hang or a different exit code; stderr: {}",
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

/// `report --file <valid> --diff-against <fifo>` must fail FAST, never hang:
/// the drift-comparison read (`commands/report.rs:197`,
/// `std::fs::read_to_string(snapshot_path)`) has no special-file guard and no
/// upstream `is_file()` gate on `--diff-against` at all, so this is reached
/// unconditionally once the primary register build succeeds.
#[test]
fn report_diff_against_fifo_fails_fast_not_hang() {
    let rules_dir = tempfile::tempdir().expect("tempdir for a valid single rules file");
    let rules_file = rules_dir.path().join("10-x.rules");
    fs::write(&rules_file, "allow uid=0 : all\n").expect("write valid rules file");

    let fifo_dir = tempfile::tempdir().expect("tempdir for the snapshot fifo");
    let fifo = make_fifo(fifo_dir.path(), "snapshot.json");

    let out = Command::cargo_bin("rulesteward")
        .expect("rulesteward binary")
        .args(["fapolicyd", "report", "--file"])
        .arg(&rules_file)
        .args(["--diff-against"])
        .arg(&fifo)
        .timeout(Duration::from_secs(15))
        .output()
        .unwrap_or_else(|e| panic!("command failed to run (spawn/IO error, not a timeout): {e}"));

    assert!(
        out.status.code().is_some(),
        "hang: child killed by 15s timeout (status.code() is None) -- this IS the \
         #583 gap: report's --diff-against snapshot read has no special-file \
         guard; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        out.status.code(),
        Some(3),
        "a FIFO --diff-against target must be a tool failure (EXIT_TOOL_FAILURE=3), \
         not a hang or a different exit code; stderr: {}",
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

// ---------------------------------------------------------------------------
// #583 (blocker 2): a FIFO-only special-file
// guard is not enough. `/dev/null` (a character device) never hangs under a
// raw `std::fs::read_to_string` - it reads back an instant empty string - so
// it defeats any guard that only special-cases FIFOs, and on `report` this is
// worse than a hang: it produces a CONFIDENT, FABRICATED clean report.
// ---------------------------------------------------------------------------

/// An unguarded `report --file /dev/null` silently succeeds and prints a
/// fabricated "0 allow-grants" CLEAN report (measured live, 2026-07-24: exit
/// 0, stdout "0 allow-grants (0 hash-pinned, 0 trust-scoped)") - a wrong,
/// confident answer, not a crash or a hang. A `if is_fifo(path) { reject }
/// else { raw read }` implementation passes every FIFO test in this file yet
/// still lets this exact silent-wrong-answer case through, and per #560's own
/// title ("`fapolicyd lint --file /dev/zero` hangs") a device node is squarely
/// in scope, not just FIFOs. Routing through the SAME
/// `rulesteward_core::fsread::read_to_string` every other special-file guard
/// uses, which rejects ANY non-regular file, makes `/dev/null` a tool
/// failure instead.
#[test]
fn report_file_dev_null_is_a_tool_failure_not_a_fabricated_clean_report() {
    let out = Command::cargo_bin("rulesteward")
        .expect("rulesteward binary")
        .args(["fapolicyd", "report", "--file", "/dev/null"])
        .timeout(Duration::from_secs(10))
        .output()
        .unwrap_or_else(|e| panic!("command failed to run (spawn/IO error): {e}"));

    assert_eq!(
        out.status.code(),
        Some(3),
        "/dev/null must be rejected as a non-regular file (EXIT_TOOL_FAILURE=3), \
         not silently read as an empty ruleset yielding a fabricated \"0 \
         allow-grants\" clean report; stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("refusing to read non-regular file"),
        "the rejection must route through the shared rulesteward_core::fsread \
         guard (not a FIFO-only special case), naming the non-regular-file \
         condition; stderr: {stderr}"
    );
}

/// `report --file <dir>` is ALREADY a tool failure TODAY - raw
/// `std::fs::read_to_string` on a directory fails with EISDIR - so this pins
/// the EXIT-CODE invariant across the coming fsread conversion WITHOUT
/// hard-pinning today's raw OS wording ("Is a directory (os error 21)"),
/// which fsread's synthetic "refusing to read non-regular file (found
/// directory)" message legitimately replaces. Only the "reading {path}"
/// prefix `report.rs`'s own `with_context` adds is asserted, since that part
/// survives the conversion unchanged.
#[test]
fn report_file_is_a_directory_stays_a_tool_failure_across_the_fsread_conversion() {
    let dir = tempfile::tempdir().expect("tempdir");

    let out = Command::cargo_bin("rulesteward")
        .expect("rulesteward binary")
        .args(["fapolicyd", "report", "--file"])
        .arg(dir.path())
        .timeout(Duration::from_secs(10))
        .output()
        .unwrap_or_else(|e| panic!("command failed to run (spawn/IO error): {e}"));

    assert_eq!(
        out.status.code(),
        Some(3),
        "a directory --file target is a tool failure both before and after \
         the fsread conversion; stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains(&format!("reading {}", dir.path().display())),
        "the diagnostic must keep naming the offending path under the \
         'reading <path>' prefix report's own with_context adds, regardless \
         of which error wording follows it; stderr: {stderr}"
    );
}

// ---------------------------------------------------------------------------
// Stream support.
// `read_to_string` rejects EVERY FIFO, even one with a live writer -- but
// `--file` and `--diff-against` are stream-shaped inputs operators
// legitimately pipe in. `read_stream_to_string` accepts a FIFO with a live
// writer; these tests pin that a pipe round-trips byte-identically to the
// same fixture read from a regular file.
// ---------------------------------------------------------------------------

/// Spawn a background thread that opens `fifo` for writing, writes `content`,
/// then drops the file (closing the write end so the reader sees EOF). Not
/// joined: by the time the reading child process exits (what `.output()`
/// below awaits), the writer must already have completed its blocking write +
/// close -- that IS what produces the EOF the reader is waiting for -- so
/// there is nothing left to wait for; the OS thread is reclaimed when the
/// test binary exits. Mirrors `e2e_explain.rs`'s identical helper (test files
/// are separate binaries and cannot share it directly).
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

/// `report --file <fifo-with-a-live-writer>` must be accepted, not rejected:
/// reading the same rules file through a pipe must produce BYTE-IDENTICAL
/// output to reading it from a regular file. An exit-0-only assertion would
/// also pass a silently truncated 64KB read; comparing full stdout catches
/// that.
#[test]
fn report_file_fifo_with_live_writer_round_trips_byte_identical() {
    const CONTENT: &str = "allow uid=0 : all\n";
    let tmp = make_rules_dir("10-x.rules", CONTENT);
    let regular_file = tmp.path().join("rules.d").join("10-x.rules");

    let baseline = Command::cargo_bin("rulesteward")
        .expect("rulesteward binary")
        .args(["fapolicyd", "report", "--file"])
        .arg(&regular_file)
        .args(["--format", "json"])
        .output()
        .expect("baseline regular-file run");
    assert_eq!(
        baseline.status.code(),
        Some(0),
        "baseline regular-file run must succeed; stderr: {}",
        String::from_utf8_lossy(&baseline.stderr)
    );

    // Same basename as the regular-file fixture above ("10-x.rules"), NOT an
    // arbitrary name: `report`'s register embeds the source path's
    // `file_name()` into each grant's `source.file` JSON field, so a
    // differently-named FIFO would make the two runs' JSON differ in that
    // field alone -- a false positive for THIS test, not a real behavioral
    // difference.
    let fifo_dir = tempfile::tempdir().expect("tempdir for the fifo");
    let fifo = make_fifo(fifo_dir.path(), "10-x.rules");
    spawn_fifo_writer(fifo.clone(), CONTENT.as_bytes().to_vec());

    let out = Command::cargo_bin("rulesteward")
        .expect("rulesteward binary")
        .args(["fapolicyd", "report", "--file"])
        .arg(&fifo)
        .args(["--format", "json"])
        .timeout(Duration::from_secs(15))
        .output()
        .unwrap_or_else(|e| panic!("command failed to run (spawn/IO error, not a timeout): {e}"));

    assert_eq!(
        out.status.code(),
        Some(0),
        "a FIFO --file with a live writer must round-trip successfully, not \
         be rejected like a writerless FIFO; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        out.stdout, baseline.stdout,
        "a readable pipe --file must produce BYTE-IDENTICAL output to the \
         same fixture read from a regular file"
    );
}

/// `report --file <valid> --diff-against <fifo-with-a-live-writer>` must be
/// accepted: the drift-comparison read must produce a result BYTE-IDENTICAL
/// to the same snapshot read from a regular file.
#[test]
fn report_diff_against_fifo_with_live_writer_round_trips_byte_identical() {
    const SNAPSHOT: &str = r#"{"grants": []}"#;

    let rules_dir = tempfile::tempdir().expect("tempdir for a valid single rules file");
    let rules_file = rules_dir.path().join("10-x.rules");
    fs::write(&rules_file, "allow uid=0 : all\n").expect("write valid rules file");

    let snapshot_dir = tempfile::tempdir().expect("tempdir for the regular snapshot");
    let snapshot_regular = snapshot_dir.path().join("snapshot.json");
    fs::write(&snapshot_regular, SNAPSHOT).expect("write snapshot");

    let baseline = Command::cargo_bin("rulesteward")
        .expect("rulesteward binary")
        .args(["fapolicyd", "report", "--file"])
        .arg(&rules_file)
        .args(["--diff-against"])
        .arg(&snapshot_regular)
        .args(["--format", "json"])
        .output()
        .expect("baseline regular-file run");
    assert_eq!(
        baseline.status.code(),
        Some(0),
        "baseline regular-file run must succeed; stderr: {}",
        String::from_utf8_lossy(&baseline.stderr)
    );

    let fifo_dir = tempfile::tempdir().expect("tempdir for the snapshot fifo");
    let fifo = make_fifo(fifo_dir.path(), "snapshot.json");
    spawn_fifo_writer(fifo.clone(), SNAPSHOT.as_bytes().to_vec());

    let out = Command::cargo_bin("rulesteward")
        .expect("rulesteward binary")
        .args(["fapolicyd", "report", "--file"])
        .arg(&rules_file)
        .args(["--diff-against"])
        .arg(&fifo)
        .args(["--format", "json"])
        .timeout(Duration::from_secs(15))
        .output()
        .unwrap_or_else(|e| panic!("command failed to run (spawn/IO error, not a timeout): {e}"));

    assert_eq!(
        out.status.code(),
        Some(0),
        "a FIFO --diff-against with a live writer must round-trip \
         successfully, not be rejected like a writerless FIFO; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        out.stdout, baseline.stdout,
        "a readable pipe --diff-against must produce BYTE-IDENTICAL output to \
         the same snapshot read from a regular file"
    );
}
