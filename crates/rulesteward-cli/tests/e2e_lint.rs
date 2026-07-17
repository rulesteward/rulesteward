//! End-to-end CLI tests via `assert_cmd`. These exercise the whole pipeline:
//! argv → clap parse → command dispatch → `lint_file` → render → exit code.
//!
//! One test per exit-code path. The temp files are minimal - they exercise
//! the path through the code, not the full lint surface (the parser and
//! lint walker have their own dedicated test suites in
//! `rulesteward-fapolicyd`).

use assert_cmd::Command;
use boon::{Compiler, Schemas};
use predicates::prelude::*;
use serde_json::Value;
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
fn lint_json_format_emits_versioned_envelope() {
    // v0.1.0 freezes the JSON contract as a versioned envelope object
    // `{ "schemaVersion": 1, "diagnostics": [...] }`, not the old bare array.
    let f = write_tmp("allow uid=0 : all # bad\n");
    Command::cargo_bin("rulesteward")
        .expect("binary")
        .args(["fapolicyd", "lint", "--format", "json", "--file"])
        .arg(f.path())
        .assert()
        .code(1)
        .stdout(predicate::str::contains("\"fapd-W03\""))
        .stdout(predicate::str::starts_with("{"))
        .stdout(predicate::str::contains("\"schemaVersion\": 1"))
        .stdout(predicate::str::contains("\"diagnostics\""));
}

/// Feature 3e: SARIF rendering now SUCCEEDS. A clean file linted with
/// `--format sarif` must exit 0 and emit a SARIF 2.1.0 log on stdout that
/// parses as JSON and declares `"version": "2.1.0"`. No internal placeholder
/// strings may leak into the output.
///
/// RED state: the stub still returns `Err(SarifNotImplemented)`, which the CLI
/// maps to exit 3 (and prints "sarif format not yet implemented"), so the
/// `.code(0)` and `"version": "2.1.0"` assertions fail until the renderer lands.
/// The retired `lint_sarif_format_exits_three_with_not_implemented_error` test
/// (which pinned the OLD stub behavior) is intentionally removed by this change.
#[test]
fn lint_sarif_format_clean_file_exits_zero_with_sarif_json() {
    let f = write_tmp("allow uid=0 : all\n");
    let output = Command::cargo_bin("rulesteward")
        .expect("binary")
        .args(["fapolicyd", "lint", "--format", "sarif", "--file"])
        .arg(f.path())
        .assert()
        .code(0)
        .stdout(predicate::str::contains("\"version\": \"2.1.0\""))
        .get_output()
        .stdout
        .clone();

    let stdout = String::from_utf8(output).expect("utf-8 stdout");

    // stdout must be valid JSON.
    let _: serde_json::Value =
        serde_json::from_str(&stdout).expect("SARIF stdout must parse as JSON");

    // No internal placeholder strings may leak into shipped output.
    for needle in ["<source>", "<unknown>", "TODO"] {
        assert!(
            !stdout.contains(needle),
            "SARIF stdout leaked placeholder {needle:?}:\n{stdout}"
        );
    }
}

/// Feature 3e: result-level SARIF rendering through the full CLI pipeline.
/// The clean-file SARIF test above pins only the top-level log shape (empty
/// `results`); this one fires a KNOWN code so a wrong impl that emits SARIF
/// with no per-result `ruleId`/`level` (or the wrong level mapping) fails.
///
/// `"allow uid=0 : all # bad comment\n"` triggers `fapd-W03` (Warning), whose
/// mapped SARIF level is `"warning"` (exit 1). RED state: the stub returns
/// `Err(SarifNotImplemented)`, so the `.code(1)` + `"ruleId"`/`"warning"`
/// assertions fail until the renderer lands. The structural unit test in
/// `tests/sarif_render.rs` carries the full six-arm level discrimination; this
/// e2e check confirms one mapped result survives the real argv -> render path.
#[test]
fn lint_sarif_format_warning_file_carries_ruleid_and_level() {
    let f = write_tmp("allow uid=0 : all # bad comment\n");
    let output = Command::cargo_bin("rulesteward")
        .expect("binary")
        .args(["fapolicyd", "lint", "--format", "sarif", "--file"])
        .arg(f.path())
        .assert()
        .code(1)
        .stdout(predicate::str::contains("\"ruleId\": \"fapd-W03\""))
        .stdout(predicate::str::contains("\"level\": \"warning\""))
        .get_output()
        .stdout
        .clone();

    let stdout = String::from_utf8(output).expect("utf-8 stdout");

    // stdout must still be valid SARIF JSON declaring version 2.1.0.
    let v: serde_json::Value =
        serde_json::from_str(&stdout).expect("SARIF stdout must parse as JSON");
    assert_eq!(
        v.get("version").and_then(serde_json::Value::as_str),
        Some("2.1.0"),
        "SARIF stdout must declare version 2.1.0"
    );
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
/// JSON output is the versioned envelope object with the expected code.
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
        .stdout(predicate::str::starts_with("{"))
        .stdout(predicate::str::contains("\"schemaVersion\": 1"));
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
    // Within-file forward reference: `exe=%fwd` on line 1, `%fwd=foo` defined
    // on line 2. The macro IS defined in this file, just below the reference,
    // so this is a certain violation regardless of mode. fapd-E03 fires (not
    // fapd-W09), exit code is 2. fapd-E04 does not fire (key is `exe`, not
    // `trust`/`pattern`).
    //
    // RETARGETED (B.4.3): previously used `allow uid=0 : exe=%undef\n` with no
    // local definition, which in single-file `--file` mode will correctly become
    // fapd-W09 (exit 1) after the implement phase. The within-file forward-ref
    // fixture stays fapd-E03 in all modes because the definition is visible.
    let f = write_tmp("allow uid=0 : exe=%fwd\n%fwd=foo\n");
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
fn lint_directory_dotfile_never_emits_phantom_c01() {
    // A rules.d with a visible `10-real.rules` plus a hidden `.50-hidden.rules`.
    // fagenrules enumerates with `ls -1v | grep '\.rules$'` (no -a), so the
    // dotfile is never compiled. RuleSteward must NOT lint it and must NOT emit a
    // phantom fapd-C01 referencing `.50-hidden.rules`.
    let dir = tempfile::tempdir().expect("tempdir");
    let rules_d = dir.path().join("rules.d");
    std::fs::create_dir(&rules_d).expect("mkdir");
    std::fs::write(rules_d.join("10-real.rules"), "allow uid=0 : all\n").expect("write");
    std::fs::write(rules_d.join(".50-hidden.rules"), "allow uid=0 : all\n").expect("write");
    Command::cargo_bin("rulesteward")
        .expect("binary")
        .args(["fapolicyd", "lint"])
        .arg(&rules_d)
        .assert()
        .code(0)
        // The hidden dotfile must not appear in any diagnostic output.
        .stdout(predicate::str::contains(".50-hidden.rules").not())
        // Specifically, no phantom fapd-C01 must be emitted for the dotfile.
        .stdout(predicate::str::contains("[fapd-C01]").not());
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

// --- trustdb e2e tests (Tasks 6+7: --against-trustdb and --report-orphans) ---
//
// These tests are intentionally RED until the production wiring lands.
// RED mode: the current stub in run_lint() returns EXIT_NO_OP (9) for any
// --against-trustdb invocation; these tests assert the CORRECT exit codes
// and output that the real impl must produce.

/// Build a real LMDB trust.db fixture in `dir` containing `keys` as path entries.
///
/// # Safety (scoped allow)
/// Opens a fresh tempdir LMDB env RW to build an e2e fixture; no other process
/// touches it. heed's open is unsafe (mmap aliasing contract). This fixture
/// helper is the ONLY unsafe in the cli crate's test code; it mirrors the
/// `write_fixture` helper in rulesteward-fapolicyd which is `#[cfg(test)]`
/// and `pub(crate)` (not accessible from here).
#[allow(unsafe_code)]
fn write_trustdb_fixture(dir: &std::path::Path, keys: &[&str]) {
    // SAFETY: opens a freshly-created tempdir LMDB env RW to build an e2e
    // fixture; no other process touches it. heed's open is unsafe (mmap).
    let env = unsafe {
        heed::EnvOpenOptions::new()
            .max_dbs(1)
            .open(dir)
            .expect("write_trustdb_fixture: open LMDB env")
    };
    let mut wtxn = env.write_txn().expect("write_trustdb_fixture: write_txn");
    let db: heed::Database<heed::types::Bytes, heed::types::Bytes> = env
        .create_database(&mut wtxn, Some("trust.db"))
        .expect("write_trustdb_fixture: create_database");
    for k in keys {
        db.put(&mut wtxn, k.as_bytes(), b"1 100 deadbeef")
            .expect("write_trustdb_fixture: put");
    }
    wtxn.commit().expect("write_trustdb_fixture: commit");
    // env is dropped here - LMDB file is flushed and closed.
}

/// Build a trust.db fixture with one `(key, raw-value)` row, letting the caller
/// control the exact `"<src> <size> <hexdigest>"` value bytes (so a weak MD5/SHA1
/// digest length can be exercised). Mirrors `write_trustdb_fixture`.
#[allow(unsafe_code)]
fn write_trustdb_fixture_val(dir: &std::path::Path, key: &str, value: &[u8]) {
    // SAFETY: fresh tempdir LMDB env, RW, no other process touches it.
    let env = unsafe {
        heed::EnvOpenOptions::new()
            .max_dbs(1)
            .open(dir)
            .expect("write_trustdb_fixture_val: open LMDB env")
    };
    let mut wtxn = env
        .write_txn()
        .expect("write_trustdb_fixture_val: write_txn");
    let db: heed::Database<heed::types::Bytes, heed::types::Bytes> = env
        .create_database(&mut wtxn, Some("trust.db"))
        .expect("write_trustdb_fixture_val: create_database");
    db.put(&mut wtxn, key.as_bytes(), value)
        .expect("write_trustdb_fixture_val: put");
    wtxn.commit().expect("write_trustdb_fixture_val: commit");
}

/// fapd-W11 fires on the `--against-trustdb` lint path when the trust DB holds a
/// weak (MD5 32-hex) digest. The rule references the DB key so W06 stays clean;
/// the only diagnostic is the W11 weak-hash summary -> exit 1 (Warning).
#[test]
fn against_trustdb_w11_fires_for_weak_digest() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_dir = dir.path().join("trustdb");
    std::fs::create_dir_all(&db_dir).expect("create db_dir");
    // "1 100 <32-hex>" -> a valid-length but weak (MD5) digest for /usr/bin/ls.
    let md5 = "a".repeat(32);
    write_trustdb_fixture_val(&db_dir, "/usr/bin/ls", format!("1 100 {md5}").as_bytes());

    // path=/usr/bin/ls IS a DB key -> W06 clean; only W11 should fire.
    let rules_d = write_rules_d(
        dir.path(),
        "10-ok.rules",
        "allow perm=open all : path=/usr/bin/ls\n",
    );

    Command::cargo_bin("rulesteward")
        .expect("binary")
        .args(["fapolicyd", "lint", "--against-trustdb"])
        .arg(&db_dir)
        .arg(&rules_d)
        .assert()
        .code(1)
        .stdout(predicate::str::contains("[fapd-W11]"))
        .stdout(predicate::str::contains("weak hash algorithm"));
}

/// A strong (SHA256 64-hex) trust DB produces NO fapd-W11 on the lint path.
/// Same clean rule; exit 0, no W11.
#[test]
fn against_trustdb_no_w11_for_strong_digest() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_dir = dir.path().join("trustdb");
    std::fs::create_dir_all(&db_dir).expect("create db_dir");
    let sha256 = "b".repeat(64);
    write_trustdb_fixture_val(&db_dir, "/usr/bin/ls", format!("1 100 {sha256}").as_bytes());

    let rules_d = write_rules_d(
        dir.path(),
        "10-ok.rules",
        "allow perm=open all : path=/usr/bin/ls\n",
    );

    Command::cargo_bin("rulesteward")
        .expect("binary")
        .args(["fapolicyd", "lint", "--against-trustdb"])
        .arg(&db_dir)
        .arg(&rules_d)
        .assert()
        .code(0)
        .stdout(predicate::str::contains("[fapd-W11]").not());
}

/// Helper: create a minimal rules.d/ directory with a single rules file.
fn write_rules_d(parent: &std::path::Path, filename: &str, content: &str) -> std::path::PathBuf {
    let rules_d = parent.join("rules.d");
    std::fs::create_dir_all(&rules_d).expect("create rules.d");
    std::fs::write(rules_d.join(filename), content).expect("write rules file");
    rules_d
}

// --- #137: --sarif-include-pass per-check coverage attestation -------------

/// Validate a SARIF JSON string against the bundled official OASIS SARIF 2.1.0
/// schema (same fixture + boon harness as `sarif_render.rs`). Panics on a
/// schema violation so a malformed pass-augmented log fails the test loudly.
fn assert_valid_sarif(rendered: &str) {
    let instance: Value = serde_json::from_str(rendered).expect("SARIF stdout must parse as JSON");
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/sarif-2.1.0.schema.json"
    );
    let schema: Value = serde_json::from_slice(&std::fs::read(path).expect("read schema fixture"))
        .expect("schema fixture parses");
    let schema_id = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json";
    let mut compiler = Compiler::new();
    compiler
        .add_resource(schema_id, schema)
        .expect("add SARIF schema");
    let mut schemas = Schemas::new();
    let idx = compiler
        .compile(schema_id, &mut schemas)
        .expect("compile SARIF schema");
    if let Err(e) = schemas.validate(&instance, idx) {
        panic!("pass-augmented SARIF failed schema validation:\n{e}\n--- instance ---\n{rendered}");
    }
}

/// The `ruleId`s declared in `runs[0].tool.driver.rules[]` (the evaluated-check
/// catalog). Empty when the key is absent.
fn sarif_rule_ids(v: &Value) -> Vec<String> {
    v.pointer("/runs/0/tool/driver/rules")
        .and_then(Value::as_array)
        .map(|rules| {
            rules
                .iter()
                .filter_map(|r| r.get("id").and_then(Value::as_str).map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

/// The `ruleId`s of results with `kind == "pass"`.
fn sarif_pass_result_ids(v: &Value) -> Vec<String> {
    v.pointer("/runs/0/results")
        .and_then(Value::as_array)
        .map(|results| {
            results
                .iter()
                .filter(|r| r.get("kind").and_then(Value::as_str) == Some("pass"))
                .filter_map(|r| r.get("ruleId").and_then(Value::as_str).map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

/// Run `fapolicyd lint --format sarif [extra args] <rules_d>` and return parsed
/// stdout JSON plus the raw stdout string and stderr.
fn run_sarif_lint(rules_d: &std::path::Path, extra: &[&str]) -> (Value, String, String) {
    let mut args = vec!["fapolicyd", "lint", "--format", "sarif"];
    args.extend_from_slice(extra);
    let out = Command::cargo_bin("rulesteward")
        .expect("binary")
        .args(&args)
        .arg(rules_d)
        .assert()
        .get_output()
        .clone();
    let stdout = String::from_utf8(out.stdout).expect("utf8 stdout");
    let stderr = String::from_utf8(out.stderr).expect("utf8 stderr");
    let v: Value = serde_json::from_str(&stdout).expect("SARIF stdout parses as JSON");
    (v, stdout, stderr)
}

/// Flag-OFF guard: without `--sarif-include-pass`, SARIF output carries NO
/// `tool.driver.rules[]` and NO `kind:"pass"` results, and there is no stderr
/// note. This pins byte-shape compatibility with the pre-#137 output.
#[test]
fn sarif_without_pass_flag_has_no_rules_or_pass_results() {
    let dir = tempfile::tempdir().expect("tempdir");
    let rules_d = write_rules_d(dir.path(), "10-clean.rules", "allow uid=0 : all\n");
    let (v, _stdout, stderr) = run_sarif_lint(&rules_d, &[]);

    assert!(
        sarif_rule_ids(&v).is_empty(),
        "without the flag, tool.driver.rules[] must be absent/empty"
    );
    assert!(
        sarif_pass_result_ids(&v).is_empty(),
        "without the flag, there must be no kind:\"pass\" results"
    );
    assert!(
        !stderr.contains("--sarif-include-pass"),
        "no reserved-flag note must appear (the flag now has an effect); got: {stderr}"
    );
}

/// Flag-ON: on a clean rules.d, `--sarif-include-pass` emits a non-empty
/// `tool.driver.rules[]` and `kind:"pass"` results for evaluated-clean checks,
/// the log stays schema-valid, exit code is 0, and pass results carry NO
/// `locations` (per-check coverage attestation is analysis-wide).
#[test]
fn sarif_with_pass_flag_emits_rules_and_pass_results_valid_schema() {
    let dir = tempfile::tempdir().expect("tempdir");
    let rules_d = write_rules_d(dir.path(), "10-clean.rules", "allow uid=0 : all\n");

    Command::cargo_bin("rulesteward")
        .expect("binary")
        .args([
            "fapolicyd",
            "lint",
            "--format",
            "sarif",
            "--sarif-include-pass",
        ])
        .arg(&rules_d)
        .assert()
        .code(0);

    let (v, stdout, _stderr) = run_sarif_lint(&rules_d, &["--sarif-include-pass"]);
    assert_valid_sarif(&stdout);

    let rule_ids = sarif_rule_ids(&v);
    assert!(
        !rule_ids.is_empty(),
        "flag-on must populate tool.driver.rules[] with the evaluated checks"
    );
    let pass_ids = sarif_pass_result_ids(&v);
    assert!(
        !pass_ids.is_empty(),
        "a clean rules.d must yield kind:\"pass\" coverage results, got none"
    );
    // Pass results are analysis-wide coverage: they must NOT carry a location.
    let results = v
        .pointer("/runs/0/results")
        .and_then(Value::as_array)
        .expect("results array");
    for r in results {
        if r.get("kind").and_then(Value::as_str) == Some("pass") {
            assert!(
                r.get("locations").is_none(),
                "pass results must omit locations (analysis-wide attestation): {r}"
            );
            assert_eq!(
                r.get("level").and_then(Value::as_str),
                Some("none"),
                "pass results must have level \"none\": {r}"
            );
        }
    }
}

/// False-attestation guard (the correctness core): a conditional check must
/// appear in `tool.driver.rules[]` ONLY when its gate is on. Uses the
/// `--target` gate (fapd-E06) - subprocess-free and deterministic, unlike the
/// `--check-identities`/getent gate. A naive "all codes minus fired" would
/// attest E06 coverage even when `--target` is absent and the check never ran.
#[test]
fn sarif_pass_coverage_respects_target_gate() {
    let dir = tempfile::tempdir().expect("tempdir");
    let rules_d = write_rules_d(dir.path(), "10-clean.rules", "allow uid=0 : all\n");

    let (without, _o1, _e1) = run_sarif_lint(&rules_d, &["--sarif-include-pass"]);
    assert!(
        !sarif_rule_ids(&without).contains(&"fapd-E06".to_string()),
        "fapd-E06 must NOT be attested without --target (the version-divergence check never ran)"
    );

    let (with, _o2, _e2) = run_sarif_lint(&rules_d, &["--sarif-include-pass", "--target", "rhel9"]);
    assert!(
        sarif_rule_ids(&with).contains(&"fapd-E06".to_string()),
        "fapd-E06 must be attested (in rules[]) once --target runs it"
    );
}

/// A code that FIRED is excluded from the pass set; a clean evaluated code
/// still appears as a pass. Fixture fires fapd-E01 (unknown attribute); W08 is
/// clean and evaluated.
#[test]
fn sarif_pass_excludes_fired_codes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let rules_d = write_rules_d(
        dir.path(),
        "10-mixed.rules",
        "allow uid=0 bogusattr=x : all\n",
    );
    let (v, _stdout, _stderr) = run_sarif_lint(&rules_d, &["--sarif-include-pass"]);

    let pass_ids = sarif_pass_result_ids(&v);
    assert!(
        !pass_ids.contains(&"fapd-E01".to_string()),
        "fapd-E01 fired, so it must NOT also be attested as a pass; passes={pass_ids:?}"
    );
    // The fired code must still be present as a finding (not silently dropped).
    let finding_ids: Vec<String> = v
        .pointer("/runs/0/results")
        .and_then(Value::as_array)
        .expect("results")
        .iter()
        .filter(|r| r.get("kind").and_then(Value::as_str) != Some("pass"))
        .filter_map(|r| r.get("ruleId").and_then(Value::as_str).map(String::from))
        .collect();
    assert!(
        finding_ids.contains(&"fapd-E01".to_string()),
        "fapd-E01 must appear as a finding result; findings={finding_ids:?}"
    );
    assert!(
        pass_ids.contains(&"fapd-W08".to_string()),
        "fapd-W08 is clean + evaluated, so it must be attested as a pass; passes={pass_ids:?}"
    );
}

/// Regression (getent stdout leak): `--check-identities` shells out to
/// `getent`, whose matched-line stdout must NOT leak into rulesteward's own
/// stdout - it would corrupt machine-readable `--format json`/`sarif`. Before
/// the fix, `getent passwd 0` printed `root:x:0:0:...` ahead of the SARIF JSON
/// (identity.rs used `.status()`, which inherits the child's stdout). stdout
/// must be pure, parseable SARIF.
#[test]
fn check_identities_does_not_leak_getent_output_to_stdout() {
    let dir = tempfile::tempdir().expect("tempdir");
    let rules_d = write_rules_d(dir.path(), "10-id.rules", "allow uid=0 : all\n");
    let out = Command::cargo_bin("rulesteward")
        .expect("binary")
        .args([
            "fapolicyd",
            "lint",
            "--format",
            "sarif",
            "--check-identities",
        ])
        .arg(&rules_d)
        .assert()
        .get_output()
        .clone();
    let stdout = String::from_utf8(out.stdout).expect("utf8 stdout");
    assert!(
        !stdout.contains("root:x:"),
        "getent output must not leak into stdout; got:\n{stdout}"
    );
    let v: Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!(
            "stdout must be valid SARIF JSON (no leading getent line), parse error {e}:\n{stdout}"
        )
    });
    assert_eq!(v.get("version").and_then(Value::as_str), Some("2.1.0"));
}

/// #137 + getent (the canonical issue example): with the getent leak fixed,
/// `--check-identities` makes fapd-W05 an evaluated check, so it appears in
/// `tool.driver.rules[]`; without it, it does not. The `--target` test pins the
/// same plumbing subprocess-free; this exercises the W05/getent path end to end.
#[test]
fn sarif_pass_coverage_includes_w05_only_with_check_identities() {
    let dir = tempfile::tempdir().expect("tempdir");
    let rules_d = write_rules_d(dir.path(), "10-clean.rules", "allow uid=0 : all\n");

    let (without, _o, _e) = run_sarif_lint(&rules_d, &["--sarif-include-pass"]);
    assert!(
        !sarif_rule_ids(&without).contains(&"fapd-W05".to_string()),
        "fapd-W05 must NOT be attested without --check-identities"
    );

    let (with, _o2, _e2) =
        run_sarif_lint(&rules_d, &["--sarif-include-pass", "--check-identities"]);
    assert!(
        sarif_rule_ids(&with).contains(&"fapd-W05".to_string()),
        "fapd-W05 must be attested in rules[] with --check-identities"
    );
}

/// Coverage attestation must be SUPPRESSED on a parse failure: a rules.d with a
/// file that does not parse (fapd-F01) means the policy was never fully read, so
/// claiming the always-on checks "passed" would overstate coverage. The F01
/// finding is still present; rules[] and pass results are not.
#[test]
fn sarif_pass_suppressed_on_parse_failure() {
    let dir = tempfile::tempdir().expect("tempdir");
    let rules_d = write_rules_d(dir.path(), "10-broken.rules", "!!!garbage line\n");
    let (v, _stdout, _stderr) = run_sarif_lint(&rules_d, &["--sarif-include-pass"]);

    assert!(
        sarif_rule_ids(&v).is_empty(),
        "parse failure must suppress tool.driver.rules[] coverage attestation"
    );
    assert!(
        sarif_pass_result_ids(&v).is_empty(),
        "parse failure must suppress kind:\"pass\" results"
    );
    // The parse failure itself is still reported as a finding.
    let finding_ids: Vec<String> = v
        .pointer("/runs/0/results")
        .and_then(Value::as_array)
        .expect("results")
        .iter()
        .filter_map(|r| r.get("ruleId").and_then(Value::as_str).map(String::from))
        .collect();
    assert!(
        finding_ids.contains(&"fapd-F01".to_string()),
        "the parse failure must still be reported as fapd-F01; got {finding_ids:?}"
    );
}

/// Coverage attestation must be SUPPRESSED on an EMPTY rules.d (no rule files):
/// no policy content was analyzed, so attesting "checks passed" is meaningless.
#[test]
fn sarif_pass_suppressed_on_empty_rules_d() {
    let dir = tempfile::tempdir().expect("tempdir");
    let rules_d = dir.path().join("rules.d");
    std::fs::create_dir_all(&rules_d).expect("create empty rules.d");
    let (v, _stdout, _stderr) = run_sarif_lint(&rules_d, &["--sarif-include-pass"]);

    assert!(
        sarif_rule_ids(&v).is_empty(),
        "empty rules.d must suppress tool.driver.rules[] (no content analyzed)"
    );
    assert!(
        sarif_pass_result_ids(&v).is_empty(),
        "empty rules.d must suppress kind:\"pass\" results"
    );
}

/// Coverage attestation must be SUPPRESSED when the input has no rule content
/// (only comments/blanks parse): the checks had nothing to validate.
#[test]
fn sarif_pass_suppressed_when_only_comments() {
    let dir = tempfile::tempdir().expect("tempdir");
    let rules_d = write_rules_d(dir.path(), "10-comments.rules", "# just a comment\n\n");
    let (v, _stdout, _stderr) = run_sarif_lint(&rules_d, &["--sarif-include-pass"]);

    assert!(
        sarif_rule_ids(&v).is_empty(),
        "comment-only input must suppress rules[] (no rule content analyzed)"
    );
    assert!(
        sarif_pass_result_ids(&v).is_empty(),
        "comment-only input must suppress kind:\"pass\" results"
    );
}

/// Compliance-safe semantic: a parse failure in ONE file suppresses coverage
/// for the WHOLE run even when sibling files parse cleanly - you cannot attest
/// a policy you could not fully read. The clean file's content is analyzed, but
/// the F01 in the broken file means coverage is incomplete, so no passes.
#[test]
fn sarif_pass_suppressed_when_any_file_fails_to_parse() {
    let dir = tempfile::tempdir().expect("tempdir");
    let rules_d = dir.path().join("rules.d");
    std::fs::create_dir_all(&rules_d).expect("create rules.d");
    std::fs::write(rules_d.join("10-ok.rules"), "allow uid=0 : all\n").expect("write ok");
    std::fs::write(rules_d.join("20-broken.rules"), "!!!garbage\n").expect("write broken");
    let (v, _stdout, _stderr) = run_sarif_lint(&rules_d, &["--sarif-include-pass"]);

    assert!(
        sarif_rule_ids(&v).is_empty() && sarif_pass_result_ids(&v).is_empty(),
        "any parse failure must suppress coverage for the whole run (incomplete read)"
    );
}

/// Passing a nonexistent directory as --against-trustdb must fail with exit 3
/// (`EXIT_TOOL_FAILURE`). The stub currently exits 9; this test is RED.
#[test]
fn against_trustdb_missing_db_exits_tool_failure() {
    let dir = tempfile::tempdir().expect("tempdir");
    let rules_d = write_rules_d(dir.path(), "10-clean.rules", "allow uid=0 : all\n");
    Command::cargo_bin("rulesteward")
        .expect("binary")
        .args([
            "fapolicyd",
            "lint",
            "--against-trustdb",
            "/nonexistent/trustdb/dir/zzz9999",
        ])
        .arg(&rules_d)
        .assert()
        // EXIT_TOOL_FAILURE = 3. The stub exits 9 -> RED.
        .code(3);
}

/// W06 fires when a rule's path= value is NOT a key in the trust DB.
/// The fixture DB does not contain /nonexistent/rs-trap/x, so fapd-W06 must
/// appear in stdout, and exit must be 1 (Warning). The stub exits 9 -> RED.
#[test]
fn against_trustdb_w06_fires_for_unlisted_path() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_dir = dir.path().join("trustdb");
    std::fs::create_dir_all(&db_dir).expect("create db_dir");
    // DB contains /usr/bin/ls but NOT /nonexistent/rs-trap/x.
    write_trustdb_fixture(&db_dir, &["/usr/bin/ls"]);

    let rules_d = write_rules_d(
        dir.path(),
        "10-trap.rules",
        "allow perm=open all : path=/nonexistent/rs-trap/x\n",
    );

    Command::cargo_bin("rulesteward")
        .expect("binary")
        .args(["fapolicyd", "lint", "--against-trustdb"])
        .arg(&db_dir)
        .arg(&rules_d)
        .assert()
        // EXIT_WARNINGS = 1, fapd-W06 present. Stub exits 9 -> RED.
        .code(1)
        .stdout(predicate::str::contains("[fapd-W06]"));
}

/// W06 is CLEAN when the rule's path= value IS a key in the trust DB.
/// A rule pointing at /usr/bin/ls, a DB containing /usr/bin/ls -> no fapd-W06.
/// Exit must be 0 and stdout must NOT contain [fapd-W06]. Stub exits 9 -> RED.
#[test]
fn against_trustdb_w06_clean_for_listed_path() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_dir = dir.path().join("trustdb");
    std::fs::create_dir_all(&db_dir).expect("create db_dir");
    // DB contains exactly the path the rule references.
    write_trustdb_fixture(&db_dir, &["/usr/bin/ls"]);

    let rules_d = write_rules_d(
        dir.path(),
        "10-ok.rules",
        // path=/usr/bin/ls is a DB key -> W06 must NOT fire.
        "allow perm=open all : path=/usr/bin/ls\n",
    );

    Command::cargo_bin("rulesteward")
        .expect("binary")
        .args(["fapolicyd", "lint", "--against-trustdb"])
        .arg(&db_dir)
        .arg(&rules_d)
        .assert()
        // Exit 0 (no warnings) and absolutely no fapd-W06. Stub exits 9 -> RED.
        .code(0)
        .stdout(predicate::str::contains("[fapd-W06]").not());
}

/// X01 fires (as Extra / advisory) when --report-orphans is passed and the DB
/// contains keys that no rule references. Exit must be 0 (Extra does NOT raise
/// the exit code). Stub exits 9 and the --report-orphans flag does not exist
/// yet -> RED at compile time for the flag + runtime wrong exit.
#[test]
fn report_orphans_x01_fires_and_exit_is_zero() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_dir = dir.path().join("trustdb");
    std::fs::create_dir_all(&db_dir).expect("create db_dir");
    // DB keys are unreferenced by any rule in the rules.d below.
    write_trustdb_fixture(
        &db_dir,
        &["/usr/bin/unreferenced-a", "/usr/bin/unreferenced-b"],
    );

    // The rule uses `all` as the object (no path= attr) so neither DB key is referenced.
    let rules_d = write_rules_d(dir.path(), "10-norefs.rules", "allow uid=0 : all\n");

    Command::cargo_bin("rulesteward")
        .expect("binary")
        .args(["fapolicyd", "lint", "--against-trustdb"])
        .arg(&db_dir)
        // --report-orphans does not exist yet (field not added) -> compile/parse error -> RED.
        .arg("--report-orphans")
        .arg(&rules_d)
        .assert()
        // EXIT_CLEAN = 0 (Extra severity never raises exit code).
        // Stub exits 9. Also --report-orphans is an unknown flag -> RED.
        .code(0)
        .stdout(predicate::str::contains("[fapd-X01]"));
}

/// --report-orphans WITHOUT --against-trustdb must not crash and must not
/// exit with an error code that differs from a plain lint result. The CLI
/// should warn on stderr that the flag has no effect, then behave as a plain
/// lint. A clean rules.d -> exit 0.
///
/// This test is RED because --report-orphans does not exist yet (unknown flag
/// -> clap exits 3, not 0). After the flag is added and the warning is wired,
/// the exit will be 0 for a clean input.
#[test]
fn report_orphans_without_against_trustdb_warns_and_does_not_crash() {
    let dir = tempfile::tempdir().expect("tempdir");
    let rules_d = write_rules_d(dir.path(), "10-clean.rules", "allow uid=0 : all\n");

    Command::cargo_bin("rulesteward")
        .expect("binary")
        // --report-orphans present but no --against-trustdb.
        .args(["fapolicyd", "lint", "--report-orphans"])
        .arg(&rules_d)
        .assert()
        // Plain lint of a clean file -> exit 0.
        // Currently RED: --report-orphans is unknown -> clap exits 3.
        .code(0);
}

// --- B.4 - Cross-file E03 and single-file W09 e2e tests ---
//
// These tests are RED until the CLI two-phase loop and single-file-mode
// downgrade land in the implement phase.

/// B.4.1 - Directory mode with a backward cross-file macro reference must NOT
/// fire fapd-E03 and must NOT fire fapd-W09.
///
/// Fixture: `10-languages.rules` defines `%languages`; `70-trusted-lang.rules`
/// references it. In directory mode with the two-phase loop, the definition
/// from `10-` is in scope for `70-` via the `earlier_macros` accumulator.
///
/// RED now: the CLI does not yet run the two-phase loop, so `70-trusted-lang.rules`
/// sees an empty earlier set and fires fapd-E03.
#[test]
fn lint_directory_cross_file_macro_no_e03() {
    let dir = tempfile::tempdir().expect("tempdir");
    let rules_d = dir.path().join("rules.d");
    std::fs::create_dir(&rules_d).expect("mkdir rules.d");
    std::fs::write(
        rules_d.join("10-languages.rules"),
        "%languages=text/x-ruby,text/x-perl\n",
    )
    .expect("write 10-languages.rules");
    std::fs::write(
        rules_d.join("70-trusted-lang.rules"),
        "allow perm=open all : ftype=%languages\n",
    )
    .expect("write 70-trusted-lang.rules");

    Command::cargo_bin("rulesteward")
        .expect("binary")
        .args(["fapolicyd", "lint"])
        .arg(&rules_d)
        .assert()
        // A backward cross-file macro reference must be clean: no fapd-E03 and
        // no fapd-W09. Exit 0.
        // RED until two-phase CLI loop lands.
        .code(0)
        .stdout(predicate::str::contains("[fapd-E03]").not())
        .stdout(predicate::str::contains("[fapd-W09]").not());
}

/// B.4.2 - Single-file `--file` mode with a macro reference to an undefined
/// macro must emit fapd-W09 (Warning, exit 1), NOT fapd-E03.
///
/// RED now: the CLI passes `single_file=false` (the default) for both directory
/// and single-file mode; after the implement phase, `--file` sets `single_file=true`
/// and `e03` emits fapd-W09 instead of fapd-E03 for the undefined case.
#[test]
fn lint_single_file_undefined_macro_is_w09_exit_one() {
    let f = write_tmp("allow uid=0 : exe=%missingmacro\n");
    Command::cargo_bin("rulesteward")
        .expect("binary")
        .args(["fapolicyd", "lint", "--file"])
        .arg(f.path())
        .assert()
        // exit 1: Warning severity (fapd-W09), not Error (fapd-E03).
        // RED until the single-file mode downgrade lands.
        .code(1)
        .stdout(predicate::str::contains("[fapd-W09]"))
        .stdout(predicate::str::contains("[fapd-E03]").not());
}

// --- B.4.4 - GAP 3 (adversarial-reviewer finding): directory mode with a macro
// undefined in EVERY file must be a hard fapd-E03 (Error, exit 2), NOT
// downgraded to fapd-W09. Kills a wrong CLI that passes single_file=true in
// directory mode, which would produce W09 (exit 1) instead of E03 (exit 2).
//
// This test is GREEN against the current frozen foundation (which always emits
// fapd-E03 regardless of mode). It is a regression pin: the implement phase
// must keep it green. A wrong impl that sets single_file=true in directory mode
// would downgrade to W09 and break this test.

#[test]
fn lint_directory_undefined_macro_is_e03_exit_two() {
    let dir = tempfile::tempdir().expect("tempdir");
    let rules_d = dir.path().join("rules.d");
    std::fs::create_dir(&rules_d).expect("mkdir");
    std::fs::write(rules_d.join("10-x.rules"), "allow uid=0 : exe=%nowhere\n").expect("write");
    Command::cargo_bin("rulesteward")
        .expect("binary")
        .args(["fapolicyd", "lint"])
        .arg(&rules_d)
        .assert()
        .code(2)
        .stdout(predicate::str::contains("[fapd-E03]"))
        .stdout(predicate::str::contains("[fapd-W09]").not());
}

// --- CLEAN-4c: exit-code 4 for LMDB/trust-DB open error vs exit-code 3 for
// not-a-directory (CLEAN-4c barrier tests). ---
//
// Background: `run_lint` passes `--against-trustdb <PATH>` directly to
// `open_trustdb_readonly`. Post-CLEAN-4c the implementer will add a `is_dir()`
// pre-check: if PATH is not a directory -> exit 3 (stays EXIT_TOOL_FAILURE);
// if PATH IS a directory but heed/LMDB fails to open it -> exit 4
// (new EXIT_LMDB_ERROR). Today BOTH arms still exit 3, so:
//   - `against_trustdb_lmdb_open_error_exits_4` is RED (expects 4, gets 3).
//   - `against_trustdb_not_a_directory_exits_3` is GREEN today (expects 3,
//     gets 3 via the heed error path); it becomes a preservation guard after
//     impl adds the is_dir() check that separates the two arms.

/// CLEAN-4c RED test: `--against-trustdb` pointing at an EXISTING DIRECTORY
/// that contains no valid LMDB env (empty temp dir, no `data.mdb`) triggers a
/// genuine heed/LMDB open error. Post-CLEAN-4c this must exit 4
/// (`EXIT_LMDB_ERROR`). Currently exits 3 (`EXIT_TOOL_FAILURE`) because the
/// two failure arms are not yet distinguished.
///
/// Fixture grounding: `open_trustdb_readonly` on an empty dir returns
/// `Err(TrustDbError::Open(_) | TrustDbError::Missing(_))` (confirmed by the
/// `missing_db_is_error_not_panic` test in trustdb.rs). An empty directory is
/// the canonical fixture for a heed-error arm because `is_dir()` returns true
/// (so the future `is_dir()` check passes) but LMDB has nothing to open.
///
/// Asserts the literal value 4, not a not-yet-existing `EXIT_LMDB_ERROR`
/// constant, so the test compiles today.
#[test]
fn against_trustdb_lmdb_open_error_exits_4() {
    let dir = tempfile::tempdir().expect("tempdir");
    // Empty sub-directory: is_dir() = true, no data.mdb -> heed returns Err.
    let empty_db_dir = dir.path().join("empty_lmdb_dir");
    std::fs::create_dir(&empty_db_dir).expect("create empty lmdb dir");
    let rules_d = write_rules_d(dir.path(), "10-clean.rules", "allow uid=0 : all\n");
    Command::cargo_bin("rulesteward")
        .expect("binary")
        .args(["fapolicyd", "lint", "--against-trustdb"])
        .arg(&empty_db_dir)
        .arg(&rules_d)
        .assert()
        // EXIT_LMDB_ERROR = 4 (post-CLEAN-4c). Currently exits 3 -> RED.
        .code(4);
}

/// CLEAN-4c preservation guard: `--against-trustdb` pointing at a REGULAR FILE
/// (not a directory) must continue to exit 3 (`EXIT_TOOL_FAILURE`) after
/// CLEAN-4c wires the `is_dir()` pre-check. A regular file fails `is_dir()` -> the
/// "not a directory" arm fires -> exit 3.
///
/// This test is GREEN today (currently exits 3 via the heed error path because
/// no `is_dir()` check exists yet). After the implementer adds the `is_dir()` check
/// it will remain GREEN via the new `is_dir()` -> exit 3 arm. Documents the
/// preservation contract: "not a directory" stays 3, not 4.
#[test]
fn against_trustdb_not_a_directory_exits_3() {
    let dir = tempfile::tempdir().expect("tempdir");
    // A real file: is_dir() = false -> "not a directory" arm -> exit 3.
    let regular_file = dir.path().join("not_a_dir.txt");
    std::fs::write(&regular_file, b"I am a file, not a directory").expect("write file");
    let rules_d = write_rules_d(dir.path(), "10-clean.rules", "allow uid=0 : all\n");
    Command::cargo_bin("rulesteward")
        .expect("binary")
        .args(["fapolicyd", "lint", "--against-trustdb"])
        .arg(&regular_file)
        .arg(&rules_d)
        .assert()
        // EXIT_TOOL_FAILURE = 3. GREEN today (heed error path); preserved after
        // is_dir() check lands as the "not a directory" arm.
        .code(3);
}

// --- #519: fapd-W13 (merged deny-all) + fapd-W14 (--conf permissive) -------

/// `--target rhel9` on a rules.d/ whose fagenrules-order LAST rule is not a
/// deny-all must fire `[fapd-W13]` (exit 1); the mirror-image clean ruleset
/// (last rule IS a deny-all family match) must stay exit 0 with no
/// `[fapd-W13]`. Combined into one test (the firing case runs first) so a
/// not-yet-wired `run_lint_resolved` (w13 is never called today) fails
/// immediately rather than the clean half passing vacuously on its own.
#[test]
fn lint_target_rhel9_w13_fires_on_trailing_allow_clean_on_trailing_deny_all() {
    let dir = tempfile::tempdir().expect("tempdir");
    let rules_d = dir.path().join("rules.d");
    std::fs::create_dir(&rules_d).expect("mkdir");
    std::fs::write(rules_d.join("10-deny.rules"), "deny perm=any all : all\n").expect("write");
    std::fs::write(
        rules_d.join("90-allow.rules"),
        "allow perm=open all : all\n",
    )
    .expect("write");
    Command::cargo_bin("rulesteward")
        .expect("binary")
        .args(["fapolicyd", "lint", "--target", "rhel9"])
        .arg(&rules_d)
        .assert()
        .code(1)
        .stdout(predicate::str::contains("[fapd-W13]"));

    let clean_dir = tempfile::tempdir().expect("tempdir");
    let clean_rules_d = clean_dir.path().join("rules.d");
    std::fs::create_dir(&clean_rules_d).expect("mkdir");
    std::fs::write(clean_rules_d.join("10-allow.rules"), "allow uid=0 : all\n").expect("write");
    std::fs::write(
        clean_rules_d.join("90-deny.rules"),
        "deny_audit perm=any all : all\n",
    )
    .expect("write");
    Command::cargo_bin("rulesteward")
        .expect("binary")
        .args(["fapolicyd", "lint", "--target", "rhel9"])
        .arg(&clean_rules_d)
        .assert()
        .code(0)
        .stdout(predicate::str::contains("[fapd-W13]").not());

    // fapd-W13 requires an explicit --target: the SAME non-compliant ruleset
    // as the firing case above must NOT fire it when --target is omitted.
    // Bundled into this test (rather than standalone) because on its own it
    // is indistinguishable from the pre-#519 (nothing ever fires fapd-W13)
    // behavior and would pass vacuously.
    let no_target_dir = tempfile::tempdir().expect("tempdir");
    let no_target_rules_d = no_target_dir.path().join("rules.d");
    std::fs::create_dir(&no_target_rules_d).expect("mkdir");
    std::fs::write(
        no_target_rules_d.join("90-allow.rules"),
        "allow perm=open all : all\n",
    )
    .expect("write");
    Command::cargo_bin("rulesteward")
        .expect("binary")
        .args(["fapolicyd", "lint"])
        .arg(&no_target_rules_d)
        .assert()
        .stdout(predicate::str::contains("[fapd-W13]").not());
}

/// `--conf <path>` pointing at a `permissive=1` fapolicyd.conf must fire
/// `[fapd-W14]` and exit 1; without `--conf`, no fapd-W14 finding is ever
/// produced (the check is entirely opt-in).
#[test]
fn lint_conf_permissive_one_fires_w14_exits_one_absent_conf_never_fires_it() {
    let f = write_tmp("allow uid=0 : all\n");
    let conf = tempfile::NamedTempFile::new().expect("conf tempfile");
    std::fs::write(conf.path(), "permissive = 1\n").expect("write conf");
    Command::cargo_bin("rulesteward")
        .expect("binary")
        .args(["fapolicyd", "lint", "--file"])
        .arg(f.path())
        .arg("--conf")
        .arg(conf.path())
        .assert()
        .code(1)
        .stdout(predicate::str::contains("[fapd-W14]"));

    // Without --conf on the same fixture: never fires. Bundled into this test
    // (rather than standalone) because on its own it is indistinguishable
    // from the pre-#519 (--conf does nothing) behavior and would pass
    // vacuously.
    Command::cargo_bin("rulesteward")
        .expect("binary")
        .args(["fapolicyd", "lint", "--file"])
        .arg(f.path())
        .assert()
        .stdout(predicate::str::contains("[fapd-W14]").not());
}

/// `--profile stig` on a ruleset that fires fapd-W13 (STIG-controlled, #519)
/// must NOT empty the finding set: unlike every other today's fapolicyd
/// finding (which carries no controls and is always dropped by any
/// `--profile`), a W13 finding under `--target rhel9` carries the `DenyAll`
/// STIG control and must survive the filter with non-empty output.
#[test]
fn lint_profile_stig_on_w13_firing_ruleset_is_non_empty() {
    let dir = tempfile::tempdir().expect("tempdir");
    let rules_d = dir.path().join("rules.d");
    std::fs::create_dir(&rules_d).expect("mkdir");
    std::fs::write(
        rules_d.join("90-allow.rules"),
        "allow perm=open all : all\n",
    )
    .expect("write");
    let out = Command::cargo_bin("rulesteward")
        .expect("binary")
        .args([
            "fapolicyd",
            "lint",
            "--target",
            "rhel9",
            "--profile",
            "stig",
        ])
        .arg(&rules_d)
        .output()
        .expect("binary ran");
    let stdout = String::from_utf8(out.stdout).expect("utf8");
    assert!(
        !stdout.trim().is_empty(),
        "a STIG-controlled fapd-W13 finding must survive --profile stig \
         (non-empty output), got exit={:?} stdout={stdout:?}",
        out.status.code()
    );
    assert!(
        stdout.contains("fapd-W13"),
        "the surviving finding must be fapd-W13: {stdout}"
    );
}
