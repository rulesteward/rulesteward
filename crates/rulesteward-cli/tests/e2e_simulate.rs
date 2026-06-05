//! End-to-end CLI tests for `rulesteward fapolicyd simulate`.
//!
//! Exercises the whole pipeline: argv -> clap parse -> `simulate::run()` ->
//! render -> exit code. Tests are black-box via `assert_cmd`.
//!
//! ## TDD state: RED
//!
//! `simulate::run()` is a `todo!()` stub (panics at runtime, exit 101).
//! Every test below WILL FAIL until the implementer fills the body.
//!
//! ## JSON schema frozen here
//!
//! `--format json` output must match this envelope (see also `simulate_oracle.rs`):
//!
//! ```json
//! {
//!   "schemaVersion": 1,
//!   "kind": "simulate",
//!   "results": [
//!     {
//!       "verdict": "Decisive" | "Possible" | "NoMatch",
//!       "decision": "allow" | "deny",
//!       "matchedRule": <integer> | null,
//!       "source": "rule" | "fallthrough",
//!       "confidenceNote": "<string>"
//!     }
//!   ],
//!   "summary": { "total": <u>, "decisive": <u>, "possible": <u>, "noMatch": <u> }
//! }
//! ```
//!
//! Output MUST end with a trailing newline (shell-pipeline safety).
//! No placeholder strings (`<source>`, `TODO`, `panic`, `dbg!`) may appear.

use assert_cmd::Command;
use predicates::prelude::*;
use std::io::Write as _;
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn corpus_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("corpus")
        .join("simulate")
}

/// Write a temporary file with `contents` and return it (keeps the file alive).
fn write_tmp(contents: &str) -> tempfile::NamedTempFile {
    let mut f = tempfile::NamedTempFile::new().expect("tempfile");
    write!(f, "{contents}").expect("write");
    f
}

/// Write a temporary `rules.d` directory containing a single `.rules` file.
/// Returns `(dir_guard, rules_dir PathBuf)`. The `dir_guard` must be kept alive.
fn write_rules_dir(rules_content: &str) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let rules_path = dir.path().join("10-test.rules");
    std::fs::write(&rules_path, rules_content).expect("write rules file");
    let rules_dir = dir.path().to_path_buf();
    (dir, rules_dir)
}

/// Parse JSON from a byte slice, panicking with context on error.
fn parse_json(label: &str, bytes: &[u8]) -> serde_json::Value {
    let s = String::from_utf8_lossy(bytes);
    serde_json::from_str(&s)
        .unwrap_or_else(|e| panic!("{label}: output is not valid JSON: {e}\nstdout: {s}"))
}

// ---------------------------------------------------------------------------
// Workload form 1: canonical JSON {exe, path, perm}
// ---------------------------------------------------------------------------

/// JSON workload: `deny perm=open all : all` -> decision=deny via rule 1.
#[test]
fn json_workload_single_object_decisive_deny() {
    let (_rules_dir, rules_path) = write_rules_dir("deny_audit perm=open all : all\n");
    let workload = write_tmp(r#"{"exe":"/usr/bin/cat","path":"/etc/hostname","perm":"open"}"#);

    let out = Command::cargo_bin("rulesteward")
        .expect("binary")
        .args([
            "fapolicyd",
            "simulate",
            "--rules",
            rules_path.to_str().unwrap(),
            "--workload",
            workload.path().to_str().unwrap(),
            "--format",
            "json",
        ])
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();

    let json = parse_json("json_workload_single_object_decisive_deny", &out);
    assert_eq!(json["kind"], "simulate", "kind must be 'simulate'");
    assert_eq!(json["schemaVersion"], 1, "schemaVersion must be 1");

    let result = &json["results"][0];
    assert_eq!(result["decision"], "deny");
    assert_eq!(result["verdict"], "Decisive");
    assert_eq!(result["matchedRule"], 1);
    assert_eq!(result["source"], "rule");
}

/// JSON workload: `allow perm=open all : all` -> decision=allow via rule 1.
#[test]
fn json_workload_single_object_decisive_allow() {
    let (_rules_dir, rules_path) = write_rules_dir("allow perm=open all : all\n");
    let workload = write_tmp(r#"{"exe":"/usr/bin/ls","path":"/tmp/out","perm":"open"}"#);

    let out = Command::cargo_bin("rulesteward")
        .expect("binary")
        .args([
            "fapolicyd",
            "simulate",
            "--rules",
            rules_path.to_str().unwrap(),
            "--workload",
            workload.path().to_str().unwrap(),
            "--format",
            "json",
        ])
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();

    let json = parse_json("json_workload_single_object_decisive_allow", &out);
    let result = &json["results"][0];
    assert_eq!(result["decision"], "allow");
    assert_eq!(result["verdict"], "Decisive");
    assert_eq!(result["matchedRule"], 1);
}

/// JSON workload array: `[{...}, {...}]` - two queries, each gets its own result.
#[test]
fn json_workload_array_two_queries() {
    let (_rules_dir, rules_path) = write_rules_dir("deny_audit perm=open all : all\n");
    let workload = write_tmp(
        r#"[
            {"exe":"/usr/bin/cat","path":"/etc/hostname","perm":"open"},
            {"exe":"/usr/bin/ls","path":"/tmp/x","perm":"open"}
        ]"#,
    );

    let out = Command::cargo_bin("rulesteward")
        .expect("binary")
        .args([
            "fapolicyd",
            "simulate",
            "--rules",
            rules_path.to_str().unwrap(),
            "--workload",
            workload.path().to_str().unwrap(),
            "--format",
            "json",
        ])
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();

    let json = parse_json("json_workload_array_two_queries", &out);
    let results = json["results"].as_array().expect("results must be array");
    assert_eq!(results.len(), 2, "two queries must produce two results");
    assert_eq!(results[0]["decision"], "deny");
    assert_eq!(results[1]["decision"], "deny");
    assert_eq!(json["summary"]["total"], 2, "summary.total must be 2");
}

// ---------------------------------------------------------------------------
// Workload form 2: terse line form `perm exe -> path`
// ---------------------------------------------------------------------------

/// Terse line workload from a file: `execute /usr/bin/curl -> /tmp/payload`.
/// The binary must parse this format and produce a result.
#[test]
fn terse_workload_from_file_execute_perm() {
    let (_rules_dir, rules_path) =
        write_rules_dir("deny_audit perm=execute all : all\nallow perm=open all : all\n");
    let workload = write_tmp("execute /usr/bin/curl -> /tmp/payload\n");

    let out = Command::cargo_bin("rulesteward")
        .expect("binary")
        .args([
            "fapolicyd",
            "simulate",
            "--rules",
            rules_path.to_str().unwrap(),
            "--workload",
            workload.path().to_str().unwrap(),
            "--format",
            "json",
        ])
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();

    let json = parse_json("terse_workload_from_file_execute_perm", &out);
    let result = &json["results"][0];
    // execute access hits `deny_audit perm=execute all : all` (rule 1)
    assert_eq!(
        result["decision"], "deny",
        "execute access must be denied by rule 1"
    );
    assert_eq!(result["matchedRule"], 1);
    assert_eq!(result["source"], "rule");
}

/// Terse line workload: `open` perm.
#[test]
fn terse_workload_open_perm() {
    let (_rules_dir, rules_path) =
        write_rules_dir("deny_audit perm=execute all : all\nallow perm=open all : all\n");
    let workload = write_tmp("open /usr/bin/cat -> /etc/hostname\n");

    let out = Command::cargo_bin("rulesteward")
        .expect("binary")
        .args([
            "fapolicyd",
            "simulate",
            "--rules",
            rules_path.to_str().unwrap(),
            "--workload",
            workload.path().to_str().unwrap(),
            "--format",
            "json",
        ])
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();

    let json = parse_json("terse_workload_open_perm", &out);
    let result = &json["results"][0];
    // open access hits `allow perm=open all : all` (rule 2)
    assert_eq!(
        result["decision"], "allow",
        "open access must be allowed by rule 2"
    );
    assert_eq!(result["matchedRule"], 2);
}

/// Multiple terse lines in one workload file: each line is one query.
#[test]
fn terse_workload_multiple_lines() {
    let (_rules_dir, rules_path) =
        write_rules_dir("deny_audit perm=execute all : all\nallow perm=open all : all\n");
    let workload =
        write_tmp("execute /usr/bin/curl -> /tmp/payload\nopen /usr/bin/cat -> /etc/hostname\n");

    let out = Command::cargo_bin("rulesteward")
        .expect("binary")
        .args([
            "fapolicyd",
            "simulate",
            "--rules",
            rules_path.to_str().unwrap(),
            "--workload",
            workload.path().to_str().unwrap(),
            "--format",
            "json",
        ])
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();

    let json = parse_json("terse_workload_multiple_lines", &out);
    let results = json["results"].as_array().expect("results array");
    assert_eq!(results.len(), 2, "two terse lines must produce two results");
    assert_eq!(results[0]["decision"], "deny", "execute line must deny");
    assert_eq!(results[1]["decision"], "allow", "open line must allow");
    assert_eq!(json["summary"]["total"], 2);
}

// ---------------------------------------------------------------------------
// Stdin workload: `--workload -`
// ---------------------------------------------------------------------------

/// `--workload -` reads a JSON workload from stdin.
#[test]
fn workload_dash_reads_from_stdin_json() {
    let (_rules_dir, rules_path) = write_rules_dir("deny_audit perm=open all : all\n");

    let out = Command::cargo_bin("rulesteward")
        .expect("binary")
        .args([
            "fapolicyd",
            "simulate",
            "--rules",
            rules_path.to_str().unwrap(),
            "--workload",
            "-",
            "--format",
            "json",
        ])
        .write_stdin(r#"{"exe":"/usr/bin/cat","path":"/etc/hostname","perm":"open"}"#)
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();

    let json = parse_json("workload_dash_reads_from_stdin_json", &out);
    assert_eq!(json["kind"], "simulate");
    let result = &json["results"][0];
    assert_eq!(result["decision"], "deny");
}

/// `--workload -` reads a terse line workload from stdin.
#[test]
fn workload_dash_reads_from_stdin_terse() {
    let (_rules_dir, rules_path) = write_rules_dir("deny_audit perm=execute all : all\n");

    let out = Command::cargo_bin("rulesteward")
        .expect("binary")
        .args([
            "fapolicyd",
            "simulate",
            "--rules",
            rules_path.to_str().unwrap(),
            "--workload",
            "-",
            "--format",
            "json",
        ])
        .write_stdin("execute /usr/bin/curl -> /tmp/payload\n")
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();

    let json = parse_json("workload_dash_reads_from_stdin_terse", &out);
    assert_eq!(json["results"][0]["decision"], "deny");
}

// ---------------------------------------------------------------------------
// Exit codes
// ---------------------------------------------------------------------------

/// A clean decisive run (no errors) exits 0.
#[test]
fn clean_decisive_run_exits_zero() {
    let (_rules_dir, rules_path) = write_rules_dir("allow perm=open all : all\n");
    let workload = write_tmp(r#"{"exe":"/usr/bin/cat","path":"/etc/hostname","perm":"open"}"#);

    Command::cargo_bin("rulesteward")
        .expect("binary")
        .args([
            "fapolicyd",
            "simulate",
            "--rules",
            rules_path.to_str().unwrap(),
            "--workload",
            workload.path().to_str().unwrap(),
        ])
        .assert()
        .code(0);
}

/// A rules dir containing a fapd-F01 parse error exits `EXIT_RULE_PARSE_ERROR` = 5.
/// This mirrors the lint exit-code contract (`exit_code.rs`).
#[test]
fn rules_parse_error_exits_five() {
    let (_rules_dir, rules_path) = write_rules_dir("!!!garbage line that cannot parse\n");
    let workload = write_tmp(r#"{"exe":"/usr/bin/cat","path":"/etc/hostname","perm":"open"}"#);

    Command::cargo_bin("rulesteward")
        .expect("binary")
        .args([
            "fapolicyd",
            "simulate",
            "--rules",
            rules_path.to_str().unwrap(),
            "--workload",
            workload.path().to_str().unwrap(),
        ])
        .assert()
        .code(5); // EXIT_RULE_PARSE_ERROR
}

// ---------------------------------------------------------------------------
// JSON output contract
// ---------------------------------------------------------------------------

/// `--format json` output is under the shared envelope
/// `{ "schemaVersion": 1, "kind": "simulate", ... }`.
#[test]
fn json_format_emits_versioned_envelope() {
    let (_rules_dir, rules_path) = write_rules_dir("allow perm=open all : all\n");
    let workload = write_tmp(r#"{"exe":"/usr/bin/cat","path":"/etc/hostname","perm":"open"}"#);

    Command::cargo_bin("rulesteward")
        .expect("binary")
        .args([
            "fapolicyd",
            "simulate",
            "--rules",
            rules_path.to_str().unwrap(),
            "--workload",
            workload.path().to_str().unwrap(),
            "--format",
            "json",
        ])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("\"schemaVersion\": 1"))
        .stdout(predicate::str::contains("\"kind\": \"simulate\""))
        .stdout(predicate::str::contains("\"results\""))
        .stdout(predicate::str::contains("\"summary\""));
}

/// JSON output ends with a trailing newline (machine-readable shell-pipeline safety).
#[test]
fn json_output_ends_with_trailing_newline() {
    let (_rules_dir, rules_path) = write_rules_dir("allow perm=open all : all\n");
    let workload = write_tmp(r#"{"exe":"/usr/bin/cat","path":"/etc/hostname","perm":"open"}"#);

    let out = Command::cargo_bin("rulesteward")
        .expect("binary")
        .args([
            "fapolicyd",
            "simulate",
            "--rules",
            rules_path.to_str().unwrap(),
            "--workload",
            workload.path().to_str().unwrap(),
            "--format",
            "json",
        ])
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();

    let s = String::from_utf8_lossy(&out);
    assert!(
        s.ends_with('\n'),
        "JSON output must end with a trailing newline, got: {s:?}"
    );
}

/// JSON results array has the required stable keys for each entry.
#[test]
fn json_result_has_stable_schema_keys() {
    let (_rules_dir, rules_path) = write_rules_dir("allow perm=open all : all\n");
    let workload = write_tmp(r#"{"exe":"/usr/bin/cat","path":"/etc/hostname","perm":"open"}"#);

    let out = Command::cargo_bin("rulesteward")
        .expect("binary")
        .args([
            "fapolicyd",
            "simulate",
            "--rules",
            rules_path.to_str().unwrap(),
            "--workload",
            workload.path().to_str().unwrap(),
            "--format",
            "json",
        ])
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();

    let json = parse_json("json_result_has_stable_schema_keys", &out);
    let result = &json["results"][0];

    // These keys are frozen by this test file; the implementer must use these exact names.
    assert!(
        result.get("verdict").is_some(),
        "result must have 'verdict' key"
    );
    assert!(
        result.get("decision").is_some(),
        "result must have 'decision' key"
    );
    assert!(
        result.get("matchedRule").is_some(),
        "result must have 'matchedRule' key (camelCase)"
    );
    assert!(
        result.get("source").is_some(),
        "result must have 'source' key"
    );
    assert!(
        result.get("confidenceNote").is_some(),
        "result must have 'confidenceNote' key (camelCase)"
    );

    // Summary schema
    let summary = json["summary"].as_object().expect("summary must be object");
    assert!(summary.contains_key("total"), "summary must have 'total'");
    assert!(
        summary.contains_key("decisive"),
        "summary must have 'decisive'"
    );
    assert!(
        summary.contains_key("possible"),
        "summary must have 'possible'"
    );
    assert!(
        summary.contains_key("noMatch"),
        "summary must have 'noMatch' (camelCase)"
    );
}

/// verdict values must be exactly one of `"Decisive"`, `"Possible"`, `"NoMatch"`.
#[test]
fn json_verdict_values_are_closed_set() {
    let valid_verdicts = ["Decisive", "Possible", "NoMatch"];

    // Decisive: normal rule match
    let (_rules_dir, rules_path) = write_rules_dir("allow perm=open all : all\n");
    let workload = write_tmp(r#"{"exe":"/usr/bin/cat","path":"/etc/hostname","perm":"open"}"#);
    let out = Command::cargo_bin("rulesteward")
        .expect("binary")
        .args([
            "fapolicyd",
            "simulate",
            "--rules",
            rules_path.to_str().unwrap(),
            "--workload",
            workload.path().to_str().unwrap(),
            "--format",
            "json",
        ])
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();
    let json = parse_json("json_verdict_values_closed_set", &out);
    let verdict = json["results"][0]["verdict"].as_str().unwrap_or("MISSING");
    assert!(
        valid_verdicts.contains(&verdict),
        "verdict must be one of {valid_verdicts:?}, got: {verdict:?}"
    );
}

/// Fallthrough (empty ruleset) produces verdict="NoMatch" and matchedRule=null.
#[test]
fn json_fallthrough_produces_nomatch_verdict() {
    // Empty rules.d: every access falls through to ALLOW
    let dir = tempfile::TempDir::new().expect("tempdir");
    let rules_path = dir.path().to_path_buf();
    // Write a comment-only file so parse succeeds with 0 rules
    std::fs::write(rules_path.join("10-empty.rules"), "# no rules\n")
        .expect("write comment-only rules");

    let workload = write_tmp(r#"{"exe":"/usr/bin/cat","path":"/etc/hostname","perm":"open"}"#);

    let out = Command::cargo_bin("rulesteward")
        .expect("binary")
        .args([
            "fapolicyd",
            "simulate",
            "--rules",
            rules_path.to_str().unwrap(),
            "--workload",
            workload.path().to_str().unwrap(),
            "--format",
            "json",
        ])
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();

    let json = parse_json("json_fallthrough_produces_nomatch_verdict", &out);
    let result = &json["results"][0];
    assert_eq!(
        result["verdict"], "NoMatch",
        "fallthrough must produce NoMatch verdict"
    );
    assert_eq!(
        result["decision"], "allow",
        "fallthrough decision must be allow"
    );
    assert!(
        result["matchedRule"].is_null(),
        "fallthrough matchedRule must be null"
    );
    assert_eq!(result["source"], "fallthrough");
}

/// A pattern= rule above the decisive match produces verdict="Possible".
#[test]
fn json_pattern_rule_above_match_produces_possible_verdict() {
    // Rule 1: pattern= (not statically evaluable); Rule 2: allow all : all (decisive)
    let (_rules_dir, rules_path) = write_rules_dir(
        "deny_audit perm=execute pattern=ld_so : all\nallow perm=execute all : all\n",
    );
    let workload = write_tmp(
        r#"{"exe":"/usr/local/bin/myexe","path":"/usr/local/bin/mychild","perm":"execute"}"#,
    );

    let out = Command::cargo_bin("rulesteward")
        .expect("binary")
        .args([
            "fapolicyd",
            "simulate",
            "--rules",
            rules_path.to_str().unwrap(),
            "--workload",
            workload.path().to_str().unwrap(),
            "--format",
            "json",
        ])
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();

    let json = parse_json(
        "json_pattern_rule_above_match_produces_possible_verdict",
        &out,
    );
    let result = &json["results"][0];
    assert_eq!(
        result["verdict"], "Possible",
        "pattern= above match must produce Possible verdict, not Decisive"
    );
    assert_eq!(result["decision"], "allow");
    assert_eq!(result["matchedRule"], 2);
}

// ---------------------------------------------------------------------------
// Leakage / content hygiene
// ---------------------------------------------------------------------------

/// Placeholder strings must not leak into JSON output.
/// Catches: `<source>`, `TODO`, `panic`, `dbg!` leaking from stub or impl.
#[test]
fn json_output_has_no_placeholder_leakage() {
    let (_rules_dir, rules_path) = write_rules_dir("allow perm=open all : all\n");
    let workload = write_tmp(r#"{"exe":"/usr/bin/cat","path":"/etc/hostname","perm":"open"}"#);

    Command::cargo_bin("rulesteward")
        .expect("binary")
        .args([
            "fapolicyd",
            "simulate",
            "--rules",
            rules_path.to_str().unwrap(),
            "--workload",
            workload.path().to_str().unwrap(),
            "--format",
            "json",
        ])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("<source>").not())
        .stdout(predicate::str::contains("<unknown>").not())
        .stdout(predicate::str::contains("<placeholder>").not())
        .stdout(predicate::str::contains("<TODO>").not())
        .stdout(predicate::str::is_match(r"\bTODO\b").unwrap().not())
        .stdout(predicate::str::contains("panic").not())
        .stdout(predicate::str::contains("dbg!").not());
}

/// Human output (no `--format json`) must also be free of placeholder leakage.
#[test]
fn human_output_has_no_placeholder_leakage() {
    let (_rules_dir, rules_path) = write_rules_dir("allow perm=open all : all\n");
    let workload = write_tmp(r#"{"exe":"/usr/bin/cat","path":"/etc/hostname","perm":"open"}"#);

    Command::cargo_bin("rulesteward")
        .expect("binary")
        .args([
            "fapolicyd",
            "simulate",
            "--rules",
            rules_path.to_str().unwrap(),
            "--workload",
            workload.path().to_str().unwrap(),
        ])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("<source>").not())
        .stdout(predicate::str::contains("TODO").not())
        .stdout(predicate::str::contains("panic").not());
}

// ---------------------------------------------------------------------------
// Summary counts correctness
// ---------------------------------------------------------------------------

/// Summary counts must account for every query in the workload.
/// Two decisive results: summary={total:2, decisive:2, possible:0, noMatch:0}.
#[test]
fn summary_counts_two_decisive_queries() {
    let (_rules_dir, rules_path) = write_rules_dir("deny_audit perm=open all : all\n");
    let workload = write_tmp(
        r#"[
            {"exe":"/usr/bin/cat","path":"/etc/hostname","perm":"open"},
            {"exe":"/usr/bin/ls","path":"/tmp/x","perm":"open"}
        ]"#,
    );

    let out = Command::cargo_bin("rulesteward")
        .expect("binary")
        .args([
            "fapolicyd",
            "simulate",
            "--rules",
            rules_path.to_str().unwrap(),
            "--workload",
            workload.path().to_str().unwrap(),
            "--format",
            "json",
        ])
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();

    let json = parse_json("summary_counts_two_decisive_queries", &out);
    let summary = &json["summary"];
    assert_eq!(summary["total"], 2, "total must be 2");
    assert_eq!(summary["decisive"], 2, "decisive must be 2");
    assert_eq!(summary["possible"], 0, "possible must be 0");
    assert_eq!(summary["noMatch"], 0, "noMatch must be 0");
}

/// Summary counts include a Possible result from a pattern= rule.
#[test]
fn summary_counts_includes_possible() {
    // Rule 1: pattern= (Possible); Rule 2: allow all:all (decisive for perm=open)
    let (_rules_dir, rules_path) =
        write_rules_dir("deny_audit perm=execute pattern=ld_so : all\nallow perm=open all : all\n");
    let workload = write_tmp(
        r#"[
            {"exe":"/usr/bin/cat","path":"/etc/hostname","perm":"open"},
            {"exe":"/usr/local/bin/myexe","path":"/usr/local/bin/mychild","perm":"execute"}
        ]"#,
    );

    let out = Command::cargo_bin("rulesteward")
        .expect("binary")
        .args([
            "fapolicyd",
            "simulate",
            "--rules",
            rules_path.to_str().unwrap(),
            "--workload",
            workload.path().to_str().unwrap(),
            "--format",
            "json",
        ])
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();

    let json = parse_json("summary_counts_includes_possible", &out);
    let summary = &json["summary"];
    assert_eq!(summary["total"], 2);
    // Query 1 (open, no pattern above it in open path): Decisive
    // Query 2 (execute, pattern= above it): Possible
    assert_eq!(summary["possible"], 1, "one Possible result expected");
}

// ---------------------------------------------------------------------------
// Corpus-driven spot-check with --format human (default)
// ---------------------------------------------------------------------------

/// Human output for a decisive deny includes the matched rule number.
#[test]
fn human_output_decisive_deny_mentions_rule_number() {
    let corpus = corpus_root();
    let rules_dir = corpus
        .join("happy-path")
        .join("all-subject-all-object-matches-everything")
        .join("rules.d");
    let workload = corpus
        .join("happy-path")
        .join("all-subject-all-object-matches-everything")
        .join("workload.json");

    Command::cargo_bin("rulesteward")
        .expect("binary")
        .args([
            "fapolicyd",
            "simulate",
            "--rules",
            rules_dir.to_str().unwrap(),
            "--workload",
            workload.to_str().unwrap(),
        ])
        .assert()
        .code(0)
        // Human output must mention "rule 1" or "Rule 1" or "rule=1" for the matched rule
        .stdout(predicate::str::is_match(r"[Rr]ule.?1").unwrap())
        .stdout(predicate::str::contains("deny"));
}

/// Human output for a fallthrough mentions "fallthrough" or "no match" or "no rule".
#[test]
fn human_output_fallthrough_mentions_fallthrough() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    std::fs::write(dir.path().join("10-empty.rules"), "# no rules\n").expect("write");
    let workload = write_tmp(r#"{"exe":"/usr/bin/cat","path":"/etc/hostname","perm":"open"}"#);

    Command::cargo_bin("rulesteward")
        .expect("binary")
        .args([
            "fapolicyd",
            "simulate",
            "--rules",
            dir.path().to_str().unwrap(),
            "--workload",
            workload.path().to_str().unwrap(),
        ])
        .assert()
        .code(0)
        .stdout(predicate::str::is_match(r"(?i)(fallthrough|no.match|no rule)").unwrap());
}

// ---------------------------------------------------------------------------
// Mutation-killing tests (survivors from the post-impl mutation gate)
// ---------------------------------------------------------------------------

// --- Kills survivors 1-4: render_human label branches + summary-line counts ---
//
// Survivor 1 (simulate.rs:445:23): `res.source == "rule"` in render_human.
//   Mutant flips `==` to `!=`: a rule-matched access takes the fallthrough branch
//   and prints "allow (fallthrough - no rule matched)" even for a decisive deny.
//   Kill: assert that the human verdict line for a rule-matched deny contains
//   the decision and rule number IN THE VERDICT line, not just anywhere in output.
//
// Survivors 2-4 (simulate.rs:465:31, :469:31, :473:31): the three verdict-class
//   filter predicates in render_human's summary computation.
//   Mutant flips one `==` to `!=`: that class gets the wrong count (counts all
//   OTHER classes instead of its own).
//   Kill: assert the exact per-class counts in the human summary line.
//
// One comprehensive test covers all four survivors.

/// Human output verdict line for a decisive deny must say "DECISIVE deny (rule N)".
/// The verdict line format is `"  verdict: DECISIVE deny (rule 1)"` - the decision
/// and rule number appear in the verdict line, not just the note line.
/// Kills: simulate.rs:445:23 (source == "rule" -> source != "rule").
#[test]
fn human_render_decisive_deny_verdict_line_contains_rule_and_decision() {
    // Single deny rule - one query produces a Decisive deny via rule 1.
    let (_rules_dir, rules_path) = write_rules_dir("deny perm=open all : all\n");
    let workload = write_tmp(r#"{"exe":"/usr/bin/cat","path":"/etc/hostname","perm":"open"}"#);

    Command::cargo_bin("rulesteward")
        .expect("binary")
        .args([
            "fapolicyd",
            "simulate",
            "--rules",
            rules_path.to_str().unwrap(),
            "--workload",
            workload.path().to_str().unwrap(),
        ])
        .assert()
        .code(0)
        // The verdict line must say "DECISIVE deny (rule 1)" - all three tokens on
        // the same line. With the mutant (source != "rule" is true for source=="rule"),
        // the else branch fires and prints "DECISIVE allow (fallthrough - no rule
        // matched)" instead, so neither "deny" nor "rule 1" appear in the verdict line.
        .stdout(predicate::str::is_match(r"verdict:.*DECISIVE.*deny.*rule").unwrap());
}

/// Human output verdict line for a decisive allow must say "DECISIVE allow (rule N)".
/// Kills: simulate.rs:445:23 (source == "rule" -> source != "rule").
#[test]
fn human_render_decisive_allow_verdict_line_contains_rule_and_decision() {
    let (_rules_dir, rules_path) = write_rules_dir("allow perm=open all : all\n");
    let workload = write_tmp(r#"{"exe":"/usr/bin/cat","path":"/etc/hostname","perm":"open"}"#);

    Command::cargo_bin("rulesteward")
        .expect("binary")
        .args([
            "fapolicyd",
            "simulate",
            "--rules",
            rules_path.to_str().unwrap(),
            "--workload",
            workload.path().to_str().unwrap(),
        ])
        .assert()
        .code(0)
        // Verdict line: "  verdict: DECISIVE allow (rule 1)"
        // With the mutant (source != "rule" true when source=="rule"), the else branch
        // fires: "verdict: DECISIVE allow (fallthrough - no rule matched)" - no "rule 1".
        .stdout(predicate::str::is_match(r"verdict:.*DECISIVE.*allow.*rule").unwrap());
}

/// Human summary line for a mixed workload reports exact per-class counts.
///
/// Workload: 2 decisive + 1 possible + 2 no-match queries.
/// Expected summary line: `"5 queries, 2 decisive, 1 possible, 2 no-match"`
///
/// Kills simulate.rs:465:31, :469:31, :473:31: flipping any of the three
/// verdict-class filter predicates (`== -> !=`) in `render_human` produces the
/// wrong count for that class.
#[test]
fn human_summary_line_exact_per_class_counts() {
    // Rules:
    //   Rule 1: deny perm=open all : path=/etc/hostname  (decisive only for that exact path)
    //   Rule 2: deny perm=execute pattern=ld_so : all    (unevaluable, contributes Possible)
    //   Rule 3: allow perm=execute all : all              (decisive execute, Possible due to rule 2)
    // Queries with perm=open and path != /etc/hostname have no matching rule -> NoMatch.
    let (_rules_dir, rules_path) = write_rules_dir(
        "deny perm=open all : path=/etc/hostname\n\
         deny perm=execute pattern=ld_so : all\n\
         allow perm=execute all : all\n",
    );
    let workload = write_tmp(
        r#"[
            {"exe":"/usr/bin/cat","path":"/etc/hostname","perm":"open"},
            {"exe":"/usr/bin/ls","path":"/etc/hostname","perm":"open"},
            {"exe":"/usr/local/bin/myexe","path":"/usr/local/bin/mychild","perm":"execute"},
            {"exe":"/usr/bin/cat","path":"/nonexistent/path","perm":"open"},
            {"exe":"/usr/bin/cat","path":"/other/path","perm":"open"}
        ]"#,
    );

    Command::cargo_bin("rulesteward")
        .expect("binary")
        .args([
            "fapolicyd",
            "simulate",
            "--rules",
            rules_path.to_str().unwrap(),
            "--workload",
            workload.path().to_str().unwrap(),
        ])
        .assert()
        .code(0)
        // Exact summary line. Any mutant flipping one verdict-class filter (== -> !=)
        // produces the wrong count for that class.
        .stdout(predicate::str::contains(
            "5 queries, 2 decisive, 1 possible, 2 no-match",
        ));
}

// --- Kills survivor 5: evaluate_query confidence_note branch (simulate.rs:398:30) ---
//
// Line 398: `verdict.source == Source::Fallthrough` in the confidence_note arm.
// Mutant flips `==` to `!=`: when source IS Fallthrough the else branch fires
// (formats "decisive: rule 0 allow" instead of the fallthrough note), and when
// source is NOT Fallthrough the Fallthrough branch fires (produces the fallthrough
// note instead of "decisive: rule N decision").
//
// Kill: assert the exact confidenceNote text for a fallthrough case (must contain
// "fallthrough" or "no rule"), and separately for a decisive rule-matched case
// (must contain "decisive" and the rule number).

/// For a fallthrough query the JSON `confidenceNote` must contain "fallthrough".
///
/// Kills simulate.rs:398:30 (`== Source::Fallthrough` -> `!= Source::Fallthrough`).
/// With the mutant, the else branch fires for a fallthrough: note becomes
/// `"decisive: rule 0 allow"` which does NOT contain "fallthrough".
#[test]
fn json_confidence_note_fallthrough_contains_fallthrough() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    std::fs::write(dir.path().join("10-empty.rules"), "# no rules\n").expect("write");
    let workload = write_tmp(r#"{"exe":"/usr/bin/cat","path":"/etc/hostname","perm":"open"}"#);

    let out = Command::cargo_bin("rulesteward")
        .expect("binary")
        .args([
            "fapolicyd",
            "simulate",
            "--rules",
            dir.path().to_str().unwrap(),
            "--workload",
            workload.path().to_str().unwrap(),
            "--format",
            "json",
        ])
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();

    let json = parse_json(
        "json_confidence_note_fallthrough_contains_fallthrough",
        &out,
    );
    let note = json["results"][0]["confidenceNote"]
        .as_str()
        .expect("confidenceNote must be a string");
    assert!(
        note.contains("fallthrough") || note.contains("no rule"),
        "fallthrough confidenceNote must mention 'fallthrough' or 'no rule', got: {note:?}"
    );
}

/// For a decisive rule-matched query the JSON confidenceNote must contain "decisive"
/// and the rule number.
/// Kills: simulate.rs:398:30 (`== Source::Fallthrough` -> `!= Source::Fallthrough`).
/// With the mutant, the Fallthrough branch fires for a rule-matched case: note becomes
/// "no rule matched; implicit allow (fallthrough)" - no "decisive" or rule number.
#[test]
fn json_confidence_note_decisive_contains_rule_number() {
    let (_rules_dir, rules_path) = write_rules_dir("deny perm=open all : all\n");
    let workload = write_tmp(r#"{"exe":"/usr/bin/cat","path":"/etc/hostname","perm":"open"}"#);

    let out = Command::cargo_bin("rulesteward")
        .expect("binary")
        .args([
            "fapolicyd",
            "simulate",
            "--rules",
            rules_path.to_str().unwrap(),
            "--workload",
            workload.path().to_str().unwrap(),
            "--format",
            "json",
        ])
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();

    let json = parse_json("json_confidence_note_decisive_contains_rule_number", &out);
    let note = json["results"][0]["confidenceNote"]
        .as_str()
        .expect("confidenceNote must be a string");
    assert!(
        note.contains("decisive"),
        "decisive confidenceNote must contain 'decisive', got: {note:?}"
    );
    assert!(
        note.contains('1'),
        "decisive confidenceNote must contain the rule number (1), got: {note:?}"
    );
}

// --- Kills survivor 6: load_ruleset file-extension filter (simulate.rs:316:17) ---
//
// Line 316: `p.extension()... == Some("rules")` joined with `&&` to `p.is_file()`.
// Mutant replaces `&&` with `||`: the filter becomes
//   `p.is_file() || extension == Some("rules") || ...`
// With `||`, any regular file passes the filter regardless of extension, so a
// non-`.rules` file (e.g., a README with invalid rule content) gets included and
// causes a parse error -> exit 5.
//
// Kill: place a non-`.rules` file with invalid content alongside a valid `.rules`
// file and assert the run succeeds (exit 0). With `&&`, the non-.rules file is
// skipped. With `||`, it is included and parse fails.

/// A rules directory containing a non-`.rules` file (e.g., README) must succeed.
/// The non-`.rules` file is ignored by the `&&` filter (extension check gates inclusion).
/// Kills: simulate.rs:316:17 (`&&` -> `||`): with `||`, any file is included, the
/// README content fails to parse, and the run exits 5 instead of 0.
#[test]
fn load_ruleset_ignores_non_rules_extension_files() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    // A valid rules file that allows everything.
    std::fs::write(
        dir.path().join("10-allow.rules"),
        "allow perm=open all : all\n",
    )
    .expect("write rules");
    // A non-.rules file with content that would fail to parse if accidentally loaded.
    std::fs::write(
        dir.path().join("README.txt"),
        "This is NOT a rules file and should not be loaded.\n",
    )
    .expect("write README");
    let workload = write_tmp(r#"{"exe":"/usr/bin/cat","path":"/etc/hostname","perm":"open"}"#);

    Command::cargo_bin("rulesteward")
        .expect("binary")
        .args([
            "fapolicyd",
            "simulate",
            "--rules",
            dir.path().to_str().unwrap(),
            "--workload",
            workload.path().to_str().unwrap(),
            "--format",
            "json",
        ])
        .assert()
        // With correct `&&` filter, README.txt is skipped; 10-allow.rules parses fine;
        // exit 0. With `||` mutant, README.txt is included; parse fails; exit 5.
        .code(0);
}

// --- Kills survivor 7: summary.no_match += 1 (simulate.rs:551:51) ---
//
// Line 551: `summary.no_match += 1` mutated to `summary.no_match *= 1`.
// With `*= 1`, no_match remains 0 (initial value 0 multiplied by 1 each time = 0).
// Kill: run a workload with >= 2 NoMatch queries and assert noMatch == 2.
// With `+= 1`: noMatch = 2. With `*= 1`: noMatch = 0.
//
// A NoMatch result requires a fallthrough (no rule matched for this query's perm).
// Use perm=any queries against a ruleset that only has perm=open and perm=execute
// rules - a perm=any query matches perm=any or perm=all rules only; those absent
// means fallthrough.

/// Two fallthrough (no-match) queries must produce `summary.noMatch == 2`.
///
/// Kills simulate.rs:551:51: `+= 1` mutated to `*= 1` leaves `no_match` at 0
/// because `0 * 1 = 0` for every iteration.
#[test]
fn summary_no_match_count_multiple_fallthrough_queries() {
    // Path-specific rule: only queries for /etc/hostname match; other paths fall through.
    let (_rules_dir, rules_path) = write_rules_dir("deny perm=open all : path=/etc/hostname\n");
    // 3 queries: 1 decisive (matched path), 2 no-match (unmatched paths)
    let workload = write_tmp(
        r#"[
            {"exe":"/usr/bin/cat","path":"/etc/hostname","perm":"open"},
            {"exe":"/usr/bin/cat","path":"/nonexistent/path-a","perm":"open"},
            {"exe":"/usr/bin/cat","path":"/nonexistent/path-b","perm":"open"}
        ]"#,
    );

    let out = Command::cargo_bin("rulesteward")
        .expect("binary")
        .args([
            "fapolicyd",
            "simulate",
            "--rules",
            rules_path.to_str().unwrap(),
            "--workload",
            workload.path().to_str().unwrap(),
            "--format",
            "json",
        ])
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();

    let json = parse_json("summary_no_match_count_multiple_fallthrough_queries", &out);
    let summary = &json["summary"];
    assert_eq!(summary["total"], 3, "total must be 3");
    assert_eq!(summary["decisive"], 1, "decisive must be 1");
    assert_eq!(summary["possible"], 0, "possible must be 0");
    // Key assertion: += 1 twice gives 2; *= 1 twice gives 0.
    assert_eq!(
        summary["noMatch"], 2,
        "noMatch must be 2 (kills the *= mutant)"
    );
}
