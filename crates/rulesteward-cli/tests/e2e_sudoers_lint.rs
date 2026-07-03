//! End-to-end tests for `rulesteward sudoers lint`'s ariadne snippet rendering
//! (#401): a trailing broken `@include` marker (empty synthetic source, same
//! path as the real file) must NOT overwrite the real staged source for that
//! path in the CLI's source map, or every anchored diagnostic for that file
//! blanks its snippet.
//!
//! Exercises the whole pipeline: argv -> clap parse -> command dispatch ->
//! resolve -> lint -> human render -> exit code, through the real binary.

use std::io::Write;

use assert_cmd::Command;
use predicates::prelude::*;

fn bin() -> Command {
    Command::cargo_bin("rulesteward").expect("binary built")
}

/// Write `body` to a temp file and return the handle (kept alive by the caller).
fn config_file(body: &str) -> tempfile::NamedTempFile {
    let mut f = tempfile::NamedTempFile::new().expect("temp file");
    f.write_all(body.as_bytes()).expect("write config");
    f.flush().expect("flush");
    f
}

fn run_lint(path: &std::path::Path) -> std::process::Output {
    bin()
        .args(["sudoers", "lint"])
        .arg(path)
        .env("NO_COLOR", "1")
        .output()
        .expect("binary ran")
}

/// #401: a malformed line ("garbage line") sits BEFORE a trailing `@include`
/// directive whose target does not exist. Both lines resolve to sudo-F01: the
/// malformed line anchors to the file's real source (it is genuine source
/// text with a non-empty span); the missing-include target is a synthetic
/// marker with the SAME path but an EMPTY source (`resolve::malformed_marker`).
///
/// The CLI's source-staging loop (`commands/sudoers.rs`) keys both segments'
/// sources by the same display path in a `BTreeMap`. Before the fix,
/// `BTreeMap::insert` is last-write-wins: the marker's empty source (staged
/// after the real one, since it is spliced at the include directive's later
/// position) overwrites the real source, so the anchored "garbage line"
/// diagnostic loses its backing text and ariadne cannot render a real
/// snippet. This must NOT happen: the real source text must still appear in
/// the rendered output.
#[test]
fn trailing_broken_include_does_not_blank_the_real_sources_snippet() {
    let cfg = config_file("garbage line\n@include /does/not/exist\n");
    let out = run_lint(cfg.path());
    assert_eq!(
        out.status.code(),
        Some(5),
        "sudo-F01 (Fatal, unparseable config) exits 5"
    );
    let stdout = String::from_utf8(out.stdout).expect("utf8");
    assert!(
        stdout.contains("sudo-F01"),
        "stdout names the code: {stdout}"
    );
    // The real source line must appear in the rendered snippet - NOT be
    // blanked out by the later empty-source marker for the same path.
    assert!(
        stdout.contains("garbage line"),
        "the real source text 'garbage line' must appear in the rendered \
         snippet, not be blanked by the trailing broken-include marker; \
         got: {stdout}"
    );
    // A real ariadne snippet (not the plain fallback) uses box-drawing
    // underlines (U+2500 and family), confirming the anchor render path ran.
    assert!(
        stdout.contains('\u{2500}'),
        "expected an ariadne box-drawing snippet for the anchored malformed \
         line, got: {stdout}"
    );
}

/// Regression guard: a NORMAL malformed-line file with no broken include at
/// all must still render its real ariadne snippet (the fix must not disturb
/// the ordinary single-segment-per-path case).
#[test]
fn malformed_line_with_no_include_still_renders_real_snippet() {
    let cfg = config_file("frobnicate\n");
    let out = run_lint(cfg.path());
    assert_eq!(out.status.code(), Some(5));
    let stdout = String::from_utf8(out.stdout).expect("utf8");
    assert!(stdout.contains("sudo-F01"), "stdout: {stdout}");
    assert!(
        stdout.contains("frobnicate"),
        "the real source text must appear: {stdout}"
    );
    assert!(
        stdout.contains('\u{2500}'),
        "expected an ariadne box-drawing snippet, got: {stdout}"
    );
}

/// Regression guard: a broken `@include` with NO preceding real content on
/// that path (the marker is the file's ONLY segment) has no real source to
/// anchor to and correctly stays UNANCHORED, rendering the plain
/// `file:line:col [sudo-F01] fatal: ...` fallback line (not a box). This
/// pins that the fix (which now special-cases empty-source staging) does
/// NOT start fabricating a snippet where no real source exists.
#[test]
fn broken_include_with_no_preceding_real_line_stays_plain() {
    let cfg = config_file("@include /does/not/exist\n");
    let out = run_lint(cfg.path());
    assert_eq!(out.status.code(), Some(5));
    let stdout = String::from_utf8(out.stdout).expect("utf8");
    assert!(
        stdout.contains("does not exist"),
        "the missing-include message must appear: {stdout}"
    );
    // The plain fallback format is `file:line:col [CODE] severity: message`;
    // the missing-include marker sits on line 1 of the single-line fixture.
    assert!(
        predicate::str::is_match(r":1:1 \[sudo-F01\] fatal:")
            .expect("valid regex")
            .eval(&stdout),
        "the missing-include sudo-F01 must render via the plain (unanchored) \
         fallback since it has no real backing source; got: {stdout}"
    );
}
