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
    // Inline-trailing-# triggers fapd-W03 (Warning).
    let f = write_tmp("allow uid=0 : all # bad comment\n");
    Command::cargo_bin("rulesteward")
        .expect("binary")
        .args(["fapolicyd", "lint", "--file"])
        .arg(f.path())
        .assert()
        .code(1)
        .stdout(predicate::str::contains("[fapd-W03]"));
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
        .stdout(predicate::str::contains("[fapd-F01]"))
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
        .stdout(predicate::str::contains("\"fapd-W03\""))
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

#[test]
fn lint_nonexistent_dir_emits_error_prefix_on_stderr() {
    // Phase B locks the "error: " stderr prefix that main.rs's report()
    // helper attaches when an anyhow::Error bubbles out of a command body.
    // Pre-Phase B this would fail: the bare eprintln!() in run_lint
    // wrote the message without any prefix.
    Command::cargo_bin("rulesteward")
        .expect("binary")
        .args(["fapolicyd", "lint", "/definitely/not/a/real/dir/zzz"])
        .assert()
        .code(3)
        .stderr(predicate::str::starts_with("error: "))
        .stderr(predicate::str::contains("not a directory"));
}

// --- ariadne renderer tests (Task 4) ---

/// When a diagnostic has `source_id` set (fapd-E01 from AST lints), the human
/// renderer should produce ariadne-style rich output containing the source
/// line text AND a box-drawing underline (`-`, U+2500). The earlier draft of
/// this test asserted a caret `^`, but ariadne 0.6 uses Unicode box-drawing
/// chars, not ASCII carets.
///
/// Also asserts that the ariadne bracket line shows the real source file path
/// (e.g. `..../fapd-E01/unknown-xyz.rules`) rather than the placeholder
/// `<unknown>` that ariadne emits when the span type carries no source identity.
#[test]
fn lint_human_output_renders_ariadne_snippet_when_span_present() {
    // unknown-xyz.rules: "allow xyz=0 : all\n" -> triggers fapd-E01 with span set.
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../rulesteward-fapolicyd/tests/corpus/traps/fapd-E01/unknown-xyz.rules");
    let fixture_str = fixture.to_str().expect("valid utf-8 fixture path");
    Command::cargo_bin("rulesteward")
        .expect("binary")
        .args(["fapolicyd", "lint", "--file"])
        .arg(&fixture)
        .assert()
        .code(2) // error-level exit
        .stdout(predicate::str::contains("[fapd-E01]"))
        .stdout(predicate::str::contains("xyz")) // source line appears in snippet
        // ariadne 0.6 uses box-drawing underlines (- or ╭) rather than ASCII ^.
        // We check for the source line box bracket open which ariadne always emits.
        .stdout(predicate::str::contains('\u{2500}')) // U+2500 BOX DRAWINGS LIGHT HORIZONTAL (-)
        // The ariadne bracket line must show the real source path, not <unknown>.
        .stdout(predicate::str::contains("unknown-xyz.rules"))
        .stdout(predicate::str::contains(fixture_str))
        .stdout(predicate::str::contains("<unknown>").not());
}

/// When a diagnostic does NOT have `source_id` set (fapd-F02 layout fatal,
/// which has no per-byte span), the human renderer falls back to the plain
/// `file:line:col [fapd-F02] fatal: ...` format and must NOT produce a caret
/// line.
#[test]
fn lint_human_output_falls_back_to_plain_when_source_id_absent() {
    // The fapd-F02 "canonical-both-present" fixture: a directory that has BOTH
    // fapolicyd.rules and rules.d/. The CLI must receive this as a directory
    // path (not --file), so the layout check fires and emits fapd-F02 with no
    // source_id. We pass the rules.d/ subdirectory as the --path arg.
    let rules_d = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(
        "../rulesteward-fapolicyd/tests/corpus/traps/fapd-F02/canonical-both-present/rules.d",
    );
    Command::cargo_bin("rulesteward")
        .expect("binary")
        .args(["fapolicyd", "lint"])
        .arg(&rules_d)
        .assert()
        // fapd-F02 is Fatal (non-fapd-F01) -> exit 2 per exit_code::compute.
        .code(2)
        .stdout(predicate::str::contains("[fapd-F02]"))
        .stdout(predicate::str::is_match(r"\[fapd-F02\] fatal:").expect("valid regex"))
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
        .join("../rulesteward-fapolicyd/tests/corpus/traps/fapd-E01/unknown-xyz.rules");
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
        .join("../rulesteward-fapolicyd/tests/corpus/traps/fapd-E01/unknown-xyz.rules");
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
        .join("../rulesteward-fapolicyd/tests/corpus/traps/fapd-E01/unknown-xyz.rules");
    Command::cargo_bin("rulesteward")
        .expect("binary")
        .args(["fapolicyd", "lint", "--format", "json", "--file"])
        .arg(&fixture)
        .assert()
        .code(2)
        .stdout(predicate::str::contains("\"fapd-E01\""))
        .stdout(predicate::str::starts_with("["));
}

// --- per-code CLI exit-code tests for fapd-E02/fapd-E03/fapd-E04/fapd-E05/fapd-W07 ---
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
    // `filehash=abc` -> 3 chars, not 64. fapd-E02 fires; no other code applies.
    let f = write_tmp("allow filehash=abc : exe=/foo\n");
    Command::cargo_bin("rulesteward")
        .expect("binary")
        .args(["fapolicyd", "lint", "--file"])
        .arg(f.path())
        .assert()
        .code(2)
        .stdout(predicate::str::contains("[fapd-E02]"));
}

#[test]
fn lint_fires_e03_with_exit_two_and_code_in_stdout() {
    // `exe=%undef` references an undefined macro. fapd-E03 fires; fapd-E04
    // does not (key is `exe`, not `trust`/`pattern`).
    let f = write_tmp("allow uid=0 : exe=%undef\n");
    Command::cargo_bin("rulesteward")
        .expect("binary")
        .args(["fapolicyd", "lint", "--file"])
        .arg(f.path())
        .assert()
        .code(2)
        .stdout(predicate::str::contains("[fapd-E03]"));
}

#[test]
fn lint_fires_e04_with_exit_two_and_code_in_stdout() {
    // `%mymacro` defined before reference; `trust=%mymacro` fires fapd-E04
    // (macro in trust=) but NOT fapd-E03 (macro IS defined). Single-value
    // all-string set definition, so fapd-E05 stays silent too.
    let f = write_tmp("%mymacro=foo\nallow uid=0 : trust=%mymacro\n");
    Command::cargo_bin("rulesteward")
        .expect("binary")
        .args(["fapolicyd", "lint", "--file"])
        .arg(f.path())
        .assert()
        .code(2)
        .stdout(predicate::str::contains("[fapd-E04]"));
}

#[test]
fn lint_fires_e05_with_exit_two_and_code_in_stdout() {
    // `%mymacro=123,99999999999999999999` is an integer-typed set (first value
    // numeric) whose second value exceeds i64 - a non-portable integer fapolicyd
    // 1.3.2/1.4.5 reject. fapd-E05 (overflow-only policy) fires; no rule, so
    // nothing else applies. (Type-mix sets like `1,2,foo` no longer fire E05 -
    // see the overflow-only redesign.)
    let f = write_tmp("%mymacro=123,99999999999999999999\n");
    Command::cargo_bin("rulesteward")
        .expect("binary")
        .args(["fapolicyd", "lint", "--file"])
        .arg(f.path())
        .assert()
        .code(2)
        .stdout(predicate::str::contains("[fapd-E05]"));
}

#[test]
fn lint_fires_w07_with_exit_one_and_code_in_stdout() {
    // `sha256hash=<64-hex>` is the deprecated spelling but the value is a
    // valid 64-hex digest, so fapd-E02 stays silent. Only fapd-W07 fires
    // -> exit 1.
    let f = write_tmp(
        "allow uid=0 : sha256hash=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n",
    );
    Command::cargo_bin("rulesteward")
        .expect("binary")
        .args(["fapolicyd", "lint", "--file"])
        .arg(f.path())
        .assert()
        .code(1)
        .stdout(predicate::str::contains("[fapd-W07]"));
}

#[test]
fn lint_fires_w01_with_exit_one_and_code_in_stdout() {
    // Two identical rules: the second is unreachable (shadowed by the first).
    // fapd-W01 is a Warning, so exit code is 1.
    // TDD RED proof: with a NON-shadowing input (e.g. two rules whose object
    // paths are unrelated, `path=/usr/bin/foo` vs `path=/usr/bin/bar`), no
    // fapd-W01 fires, the exit code is 0, and this test fails - confirming
    // it actually exercises the shadowing path rather than passing vacuously.
    let f = write_tmp("allow uid=0 : all\nallow uid=0 : all\n");
    Command::cargo_bin("rulesteward")
        .expect("binary")
        .args(["fapolicyd", "lint", "--file"])
        .arg(f.path())
        .assert()
        .code(1)
        .stdout(predicate::str::contains("[fapd-W01]"));
}

#[test]
fn lint_fires_s02_with_exit_zero_and_code_in_stdout() {
    // A rule followed by a macro definition: the macro is defined after the
    // first rule, firing fapd-S02 (Style). Style severity falls through
    // exit_code::compute to EXIT_CLEAN (0) - only Fatal/Error -> 2 and
    // Warning -> 1; Style/Convention/Extra do not raise the exit code.
    // The macro value is a single all-string path (no fapd-E05) and the macro
    // is unreferenced (no fapd-E03), so fapd-S02 fires in isolation.
    //
    // TDD RED proof: with a macro-at-top input
    // ("%trusted=/usr/bin/foo\nallow uid=0 : all\n") the macro precedes the
    // rule, no fapd-S02 fires, and the `contains("[fapd-S02]")` assertion
    // fails - confirming the test exercises the post-rule-macro path rather
    // than passing vacuously.
    let f = write_tmp("allow uid=0 : all\n%trusted=/usr/bin/foo\n");
    Command::cargo_bin("rulesteward")
        .expect("binary")
        .args(["fapolicyd", "lint", "--file"])
        .arg(f.path())
        .assert()
        .code(0)
        .stdout(predicate::str::contains("[fapd-S02]"));
}

#[test]
fn lint_directory_cross_file_w04_exits_one() {
    // Cross-rules.d ordering: `deny all : all` in the earlier-loading file
    // (10-) shadows the allow in the later file (50-), firing fapd-W04
    // (Warning -> exit 1). This only happens once the cross-file pass runs
    // in directory mode (positional path, no --file).
    let dir = tempfile::tempdir().expect("tempdir");
    let rules_d = dir.path().join("rules.d");
    std::fs::create_dir(&rules_d).expect("mkdir");
    std::fs::write(rules_d.join("10-deny.rules"), "deny all : all\n").expect("write");
    std::fs::write(rules_d.join("50-allow.rules"), "allow uid=0 : path=/x\n").expect("write");
    Command::cargo_bin("rulesteward")
        .expect("binary")
        .args(["fapolicyd", "lint"])
        .arg(&rules_d)
        .assert()
        .code(1)
        .stdout(predicate::str::contains("[fapd-W04]"));
}

#[test]
fn lint_directory_cross_file_c01_is_advisory_exits_zero() {
    // A rules.d filename lacking the NN- prefix fires fapd-C01 (Convention).
    // Convention does not escalate the exit code (lone C01 -> exit 0) but the
    // finding is still rendered to stdout.
    let dir = tempfile::tempdir().expect("tempdir");
    let rules_d = dir.path().join("rules.d");
    std::fs::create_dir(&rules_d).expect("mkdir");
    std::fs::write(rules_d.join("badname.rules"), "allow uid=0 : all\n").expect("write");
    Command::cargo_bin("rulesteward")
        .expect("binary")
        .args(["fapolicyd", "lint"])
        .arg(&rules_d)
        .assert()
        .code(0)
        .stdout(predicate::str::contains("[fapd-C01]"));
}

#[test]
fn lint_single_file_mode_skips_cross_file_c01() {
    // In --file mode there are no cross-file relationships, so lint_cross_file
    // (which includes the C01 filename-convention check) must NOT run - even
    // though the random tempfile name lacks the NN- prefix. Pins the
    // `args.file.is_none()` gate: exit 0 and NO fapd-C01 in output.
    let f = write_tmp("allow uid=0 : all\n");
    Command::cargo_bin("rulesteward")
        .expect("binary")
        .args(["fapolicyd", "lint", "--file"])
        .arg(f.path())
        .assert()
        .code(0)
        .stdout(predicate::str::contains("[fapd-C01]").not());
}
