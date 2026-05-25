//! End-to-end CLI tests via `assert_cmd`. These exercise the whole pipeline:
//! argv → clap parse → command dispatch → `lint_file` → render → exit code.
//!
//! One test per exit-code path. The temp files are minimal - they exercise
//! the path through the code, not the full lint surface (the parser and
//! lint walker have their own dedicated test suites in
//! `rulesteward-fapolicyd`).

use assert_cmd::Command;
use predicates::prelude::*;
use std::io::Write;

fn write_tmp(contents: &str) -> tempfile::NamedTempFile {
    let mut f = tempfile::NamedTempFile::new().expect("tempfile");
    write!(f, "{contents}").expect("write");
    f
}

#[test]
fn lint_clean_file_exits_zero() {
    let f = write_tmp("allow uid=0 : all\n");
    Command::cargo_bin("rulesteward")
        .expect("binary")
        .args(["fapolicyd", "lint", "--file"])
        .arg(f.path())
        .assert()
        .code(0);
}

#[test]
fn lint_file_with_warning_exits_one() {
    // Inline-trailing-# triggers W03 (Warning).
    let f = write_tmp("allow uid=0 : all # bad comment\n");
    Command::cargo_bin("rulesteward")
        .expect("binary")
        .args(["fapolicyd", "lint", "--file"])
        .arg(f.path())
        .assert()
        .code(1)
        .stdout(predicate::str::contains("[W03]"));
}

#[test]
fn lint_file_with_syntax_error_exits_five() {
    let f = write_tmp("!!!garbage line\n");
    let path_str = f.path().to_str().expect("utf8 path");
    Command::cargo_bin("rulesteward")
        .expect("binary")
        .args(["fapolicyd", "lint", "--file"])
        .arg(f.path())
        .assert()
        .code(5)
        .stdout(predicate::str::contains("[F01]"))
        .stdout(predicate::str::contains(path_str));
}

#[test]
fn lint_json_format_emits_array() {
    let f = write_tmp("allow uid=0 : all # bad\n");
    Command::cargo_bin("rulesteward")
        .expect("binary")
        .args(["fapolicyd", "lint", "--format", "json", "--file"])
        .arg(f.path())
        .assert()
        .code(1)
        .stdout(predicate::str::contains("\"W03\""))
        .stdout(predicate::str::starts_with("["));
}

#[test]
fn lint_sarif_format_exits_three_with_not_implemented_error() {
    let f = write_tmp("allow uid=0 : all\n");
    Command::cargo_bin("rulesteward")
        .expect("binary")
        .args(["fapolicyd", "lint", "--format", "sarif", "--file"])
        .arg(f.path())
        .assert()
        .code(3)
        .stdout(predicate::str::contains("sarif format not yet implemented"));
}

#[test]
fn against_trustdb_stub_exits_nine() {
    let f = write_tmp("allow uid=0 : all\n");
    Command::cargo_bin("rulesteward")
        .expect("binary")
        .args([
            "fapolicyd",
            "lint",
            "--against-trustdb",
            "/var/lib/fapolicyd/data.mdb",
            "--file",
        ])
        .arg(f.path())
        .assert()
        .code(9)
        .stderr(predicate::str::contains("not yet implemented"));
}

#[test]
fn selinux_triage_stub_exits_nine() {
    Command::cargo_bin("rulesteward")
        .expect("binary")
        .args(["selinux", "triage"])
        .assert()
        .code(9);
}

#[test]
fn auditd_cost_stub_exits_nine() {
    Command::cargo_bin("rulesteward")
        .expect("binary")
        .args(["auditd", "cost"])
        .assert()
        .code(9);
}

#[test]
fn unknown_subcommand_exits_three_not_two() {
    Command::cargo_bin("rulesteward")
        .expect("binary")
        .args(["nonsense"])
        .assert()
        .code(3);
}

// --- ariadne renderer tests (Task 4) ---

/// When a diagnostic has `source_id` set (E01 from AST lints), the human
/// renderer should produce ariadne-style rich output containing the source
/// line text AND a caret (`^`) underline, plus the `[E01]` code header.
#[test]
fn lint_human_output_renders_ariadne_snippet_when_span_present() {
    // unknown-xyz.rules: "allow xyz=0 : all\n" -> triggers E01 with span set.
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../rulesteward-fapolicyd/tests/corpus/traps/E01/unknown-xyz.rules");
    Command::cargo_bin("rulesteward")
        .expect("binary")
        .args(["fapolicyd", "lint", "--file"])
        .arg(&fixture)
        .assert()
        .code(2) // error-level exit
        .stdout(predicate::str::contains("[E01]"))
        .stdout(predicate::str::contains("xyz")) // source line appears in snippet
        // ariadne 0.6 uses box-drawing underlines (─ or ╭) rather than ASCII ^.
        // We check for the source line box bracket open which ariadne always emits.
        .stdout(predicate::str::contains('\u{2500}')); // U+2500 BOX DRAWINGS LIGHT HORIZONTAL (─)
}

/// When a diagnostic does NOT have `source_id` set (F02 layout fatal, which
/// has no per-byte span), the human renderer falls back to the plain
/// `file:line:col [F02] fatal: ...` format and must NOT produce a caret line.
#[test]
fn lint_human_output_falls_back_to_plain_when_source_id_absent() {
    // The F02 "canonical-both-present" fixture: a directory that has BOTH
    // fapolicyd.rules and rules.d/. The CLI must receive this as a directory
    // path (not --file), so the layout check fires and emits F02 with no
    // source_id. We pass the rules.d/ subdirectory as the --path arg.
    let rules_d = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../rulesteward-fapolicyd/tests/corpus/traps/F02/canonical-both-present/rules.d");
    Command::cargo_bin("rulesteward")
        .expect("binary")
        .args(["fapolicyd", "lint"])
        .arg(&rules_d)
        .assert()
        // F02 is Fatal (non-F01) -> exit 2 per exit_code::compute.
        .code(2)
        .stdout(predicate::str::contains("[F02]"))
        .stdout(predicate::str::is_match(r"\[F02\] fatal:").expect("valid regex"))
        // Must NOT contain ariadne box-drawing underlines - no span to point at.
        .stdout(predicate::str::contains('\u{2500}').not()); // U+2500 ─
}

/// Switching to JSON output must not be affected by the ariadne renderer path.
/// JSON output should still be a JSON array with the expected code.
#[test]
fn lint_json_output_unchanged_by_ariadne_renderer() {
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../rulesteward-fapolicyd/tests/corpus/traps/E01/unknown-xyz.rules");
    Command::cargo_bin("rulesteward")
        .expect("binary")
        .args(["fapolicyd", "lint", "--format", "json", "--file"])
        .arg(&fixture)
        .assert()
        .code(2)
        .stdout(predicate::str::contains("\"E01\""))
        .stdout(predicate::str::starts_with("["));
}
