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
/// line text AND a box-drawing underline (`-`, U+2500). The earlier draft of
/// this test asserted a caret `^`, but ariadne 0.6 uses Unicode box-drawing
/// chars, not ASCII carets.
///
/// Also asserts that the ariadne bracket line shows the real source file path
/// (e.g. `..../E01/unknown-xyz.rules`) rather than the placeholder `<unknown>`
/// that ariadne emits when the span type carries no source identity.
#[test]
fn lint_human_output_renders_ariadne_snippet_when_span_present() {
    // unknown-xyz.rules: "allow xyz=0 : all\n" -> triggers E01 with span set.
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../rulesteward-fapolicyd/tests/corpus/traps/E01/unknown-xyz.rules");
    let fixture_str = fixture.to_str().expect("valid utf-8 fixture path");
    Command::cargo_bin("rulesteward")
        .expect("binary")
        .args(["fapolicyd", "lint", "--file"])
        .arg(&fixture)
        .assert()
        .code(2) // error-level exit
        .stdout(predicate::str::contains("[E01]"))
        .stdout(predicate::str::contains("xyz")) // source line appears in snippet
        // ariadne 0.6 uses box-drawing underlines (- or ╭) rather than ASCII ^.
        // We check for the source line box bracket open which ariadne always emits.
        .stdout(predicate::str::contains('\u{2500}')) // U+2500 BOX DRAWINGS LIGHT HORIZONTAL (-)
        // The ariadne bracket line must show the real source path, not <unknown>.
        .stdout(predicate::str::contains("unknown-xyz.rules"))
        .stdout(predicate::str::contains(fixture_str))
        .stdout(predicate::str::contains("<unknown>").not());
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

/// When stdout is captured by `assert_cmd` (a pipe, not a TTY), ariadne must
/// disable ANSI color escape sequences. Box-drawing characters (e.g. U+2500
/// which ariadne uses for structural underlines) remain - they are part of
/// structural rendering, not color rendering.
#[test]
fn lint_human_output_strips_ansi_when_stdout_is_not_a_tty() {
    // assert_cmd captures stdout via a pipe, so the binary should detect
    // non-TTY and disable ANSI color codes.
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../rulesteward-fapolicyd/tests/corpus/traps/E01/unknown-xyz.rules");
    let output = Command::cargo_bin("rulesteward")
        .expect("binary exists")
        .args(["fapolicyd", "lint", "--file"])
        .arg(&fixture)
        .env_remove("NO_COLOR")
        .output()
        .expect("command runs");
    let stdout = String::from_utf8(output.stdout).expect("utf-8 stdout");
    assert!(
        !stdout.contains('\u{001b}'),
        "stdout must not contain ANSI escape codes when piped, got: {stdout:?}"
    );
    // Sanity: box-drawing structural chars still present (not color rendering).
    assert!(
        stdout.contains('\u{2500}'),
        "box-drawing chars should remain on pipe, got: {stdout:?}"
    );
}

/// Even when `NO_COLOR=1` is set, ANSI codes must be suppressed.
/// (`assert_cmd` is already non-TTY so this also documents the `NO_COLOR` contract.)
#[test]
fn lint_human_output_strips_ansi_when_no_color_set() {
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../rulesteward-fapolicyd/tests/corpus/traps/E01/unknown-xyz.rules");
    let output = Command::cargo_bin("rulesteward")
        .expect("binary exists")
        .args(["fapolicyd", "lint", "--file"])
        .arg(&fixture)
        .env("NO_COLOR", "1")
        .output()
        .expect("command runs");
    let stdout = String::from_utf8(output.stdout).expect("utf-8 stdout");
    assert!(
        !stdout.contains('\u{001b}'),
        "NO_COLOR=1 must suppress ANSI codes, got: {stdout:?}"
    );
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

// --- per-code CLI exit-code tests for E02/E03/E04/E05/W07 ---
//
// Each test exercises the whole binary pipeline (clap parse -> commands::
// fapolicyd::run_lint -> parse_rules_file -> lints::lint -> output::human ->
// exit_code::compute) on a minimal hardcoded source that fires the target
// code in isolation. Pins the exit-code mapping (Error -> 2, Warning -> 1)
// that `exit_code::compute` implements generically over severity. A future
// refactor that changes the severity of any of these codes would flip the
// exit code and surface here.

#[test]
fn lint_fires_e02_with_exit_two_and_code_in_stdout() {
    // `filehash=abc` -> 3 chars, not 64. E02 fires; no other code applies.
    let f = write_tmp("allow filehash=abc : exe=/foo\n");
    Command::cargo_bin("rulesteward")
        .expect("binary")
        .args(["fapolicyd", "lint", "--file"])
        .arg(f.path())
        .assert()
        .code(2)
        .stdout(predicate::str::contains("[E02]"));
}

#[test]
fn lint_fires_e03_with_exit_two_and_code_in_stdout() {
    // `exe=%undef` references an undefined macro. E03 fires; E04 does not
    // (key is `exe`, not `trust`/`pattern`).
    let f = write_tmp("allow uid=0 : exe=%undef\n");
    Command::cargo_bin("rulesteward")
        .expect("binary")
        .args(["fapolicyd", "lint", "--file"])
        .arg(f.path())
        .assert()
        .code(2)
        .stdout(predicate::str::contains("[E03]"));
}

#[test]
fn lint_fires_e04_with_exit_two_and_code_in_stdout() {
    // `%mymacro` defined before reference; `trust=%mymacro` fires E04 (macro
    // in trust=) but NOT E03 (macro IS defined). Single-value all-string
    // set definition, so E05 stays silent too.
    let f = write_tmp("%mymacro=foo\nallow uid=0 : trust=%mymacro\n");
    Command::cargo_bin("rulesteward")
        .expect("binary")
        .args(["fapolicyd", "lint", "--file"])
        .arg(f.path())
        .assert()
        .code(2)
        .stdout(predicate::str::contains("[E04]"));
}

#[test]
fn lint_fires_e05_with_exit_two_and_code_in_stdout() {
    // `%mymacro=1,2,foo` mixes numeric (`1`, `2`) and string (`foo`) values.
    // E05 fires; no rule, so nothing else applies.
    let f = write_tmp("%mymacro=1,2,foo\n");
    Command::cargo_bin("rulesteward")
        .expect("binary")
        .args(["fapolicyd", "lint", "--file"])
        .arg(f.path())
        .assert()
        .code(2)
        .stdout(predicate::str::contains("[E05]"));
}

#[test]
fn lint_fires_w07_with_exit_one_and_code_in_stdout() {
    // `sha256hash=<64-hex>` is the deprecated spelling but the value is a
    // valid 64-hex digest, so E02 stays silent. Only W07 fires -> exit 1.
    let f = write_tmp(
        "allow uid=0 : sha256hash=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n",
    );
    Command::cargo_bin("rulesteward")
        .expect("binary")
        .args(["fapolicyd", "lint", "--file"])
        .arg(f.path())
        .assert()
        .code(1)
        .stdout(predicate::str::contains("[W07]"));
}
