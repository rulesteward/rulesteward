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
use boon::{Compiler, Schemas};
use predicates::prelude::*;
use serde_json::Value;

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

/// #401 order-symmetry: the MARKER-BEFORE-REAL (reverse) order. The broken
/// `@include` sits on line 1 (its empty-source marker is staged for the path
/// FIRST), then the genuine malformed "garbage line" follows on line 2 (its
/// real, non-empty source is staged for the SAME path AFTERWARD). The fix must
/// let the later non-empty source win over the already-staged empty one, so
/// "garbage line" still renders its real anchored snippet. A naive fix that
/// assumed the real segment always comes first would blank this case;
/// asserting it proves order symmetry.
#[test]
fn marker_before_real_order_still_renders_the_real_snippet() {
    let cfg = config_file("@include /does/not/exist\ngarbage line\n");
    let out = run_lint(cfg.path());
    assert_eq!(out.status.code(), Some(5), "sudo-F01 exits 5");
    let stdout = String::from_utf8(out.stdout).expect("utf8");
    assert!(stdout.contains("sudo-F01"), "stdout: {stdout}");
    assert!(
        stdout.contains("garbage line"),
        "the real source text 'garbage line' (staged AFTER the empty marker \
         for the same path) must still render its snippet; got: {stdout}"
    );
    assert!(
        stdout.contains('\u{2500}'),
        "expected an ariadne box-drawing snippet for the anchored line, \
         got: {stdout}"
    );
}

/// #401 order-symmetry: the REAL / MARKER / REAL sandwich. Two genuine
/// malformed lines ("realgarbage1" on line 1, "realgarbage2" on line 3)
/// bracket a broken `@include` on line 2. All three segments key on the same
/// display path; the empty include marker is spliced BETWEEN the two real
/// content segments. Neither real snippet may be blanked - BOTH real source
/// lines must render. This is the strongest order proof: the empty marker is
/// neither strictly-first nor strictly-last among the same-path segments.
#[test]
fn real_marker_real_sandwich_renders_both_real_snippets() {
    let cfg = config_file("realgarbage1\n@include /does/not/exist\nrealgarbage2\n");
    let out = run_lint(cfg.path());
    assert_eq!(out.status.code(), Some(5), "sudo-F01 exits 5");
    let stdout = String::from_utf8(out.stdout).expect("utf8");
    assert!(stdout.contains("sudo-F01"), "stdout: {stdout}");
    // "realgarbage2" is on line 3, so it can appear ONLY in its own anchored
    // snippet (it cannot leak in via a 0..0-spanned W04 box, which always
    // points at line 1); asserting it appears proves the second real segment's
    // source survived staging past the spliced empty marker.
    assert!(
        stdout.contains("realgarbage1"),
        "the first real malformed line's snippet must render; got: {stdout}"
    );
    assert!(
        stdout.contains("realgarbage2"),
        "the second real malformed line's snippet (staged after the empty \
         marker was spliced between the two real segments) must render, not be \
         blanked; got: {stdout}"
    );
    assert!(
        stdout.contains('\u{2500}'),
        "expected ariadne box-drawing snippets for the anchored lines, \
         got: {stdout}"
    );
}

/// Regression guard: a broken `@include` with NO preceding real content on
/// that path (the marker is the file's ONLY segment) renders the plain
/// `file:line:col [sudo-F01] fatal: ...` fallback line (not a box). The reason
/// is that the missing-include marker's sudo-F01 is UNANCHORED - `lints::f01`
/// leaves its `source_id` as `None` for a synthetic marker with an empty span
/// (see `lints/mod.rs`), so `human::render` takes the plain fallback path
/// regardless of what is (or is not) staged in the sources map. This pins that
/// the source-staging fix does NOT start fabricating a snippet where the
/// diagnostic was never anchored to begin with.
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

// ---------------------------------------------------------------------------
// #511 (v0.8 Wave 4): SARIF output for the 5 `HumanJsonFormat` lint verbs
// (findings-only). RED today: `SudoersLintArgs.format` is `HumanJsonFormat`
// (human|json only), so clap rejects `--format sarif` at parse time. The
// planned impl switches `SudoersLintArgs.format` to `OutputFormat` and routes
// the new Sarif arm through `output::emit_lint`.
// ---------------------------------------------------------------------------

/// Validate a SARIF JSON string against the bundled OASIS SARIF 2.1.0 schema.
/// Duplicated per-file (see the identical helper in `e2e_sshd_lint.rs` for why
/// -- no shared test-support module exists in this crate).
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
        panic!("SARIF failed schema validation:\n{e}\n--- instance ---\n{rendered}");
    }
}

/// A STIG-clean sudoers file: `env_reset` + `use_pty` + `logfile` +
/// `timestamp_timeout` Defaults (satisfying sudo-W04's merged-required
/// checks), plus root/%wheel grants with no NOPASSWD, no undefined or dead
/// aliases. Deliberately omits `#includedir /etc/sudoers.d` (present in the
/// domain-crate unit fixture `clean_file_produces_no_diagnostics`) so this
/// e2e fixture has no dependency on real filesystem state outside the temp
/// file.
const CLEAN_SUDOERS: &str = "\
Defaults env_reset
Defaults use_pty
Defaults logfile=/var/log/sudo.log
Defaults timestamp_timeout=5
root ALL=(ALL:ALL) ALL
%wheel ALL=(ALL) ALL
";

/// `alice ALL = NOPASSWD: ALL` fires `sudo-W01` (Warning, passwordless
/// run-anything; carries STIG controls RHEL-08-010380/RHEL-09-611085). SARIF
/// output is schema-valid, carries `ruleId: "sudo-W01"` at `level:
/// "warning"`, ends with a trailing newline, and exits 1 (Warning tier;
/// verified live: this fixture also fires 3 sudo-W04 findings since it
/// carries no Defaults at all, all Warning severity, so `EXIT_WARNINGS` still
/// applies).
#[test]
fn sarif_format_fires_w01_with_ruleid_warning_level_and_trailing_newline() {
    let cfg = config_file("alice ALL = NOPASSWD: ALL\n");
    let out = bin()
        .args(["sudoers", "lint"])
        .arg(cfg.path())
        .args(["--format", "sarif"])
        .output()
        .expect("binary ran");
    assert_eq!(
        out.status.code(),
        Some(1),
        "sudo-W01 (Warning) must exit 1 under --format sarif; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).expect("utf8");
    assert_valid_sarif(&stdout);
    let v: Value = serde_json::from_str(&stdout).expect("SARIF stdout parses as JSON");
    let results = v
        .pointer("/runs/0/results")
        .and_then(Value::as_array)
        .expect("results array present");
    assert!(
        results.iter().any(
            |r| r.get("ruleId").and_then(Value::as_str) == Some("sudo-W01")
                && r.get("level").and_then(Value::as_str) == Some("warning")
        ),
        "a result must carry ruleId \"sudo-W01\" with level \"warning\"; got: {stdout}"
    );
    assert!(
        stdout.ends_with('\n'),
        "SARIF stdout must end with a newline"
    );
}

/// [`CLEAN_SUDOERS`] emits a schema-valid SARIF document with zero results
/// and exits 0.
#[test]
fn sarif_format_clean_file_is_schema_valid_with_zero_results() {
    let cfg = config_file(CLEAN_SUDOERS);
    let out = bin()
        .args(["sudoers", "lint"])
        .arg(cfg.path())
        .args(["--format", "sarif"])
        .output()
        .expect("binary ran");
    assert_eq!(
        out.status.code(),
        Some(0),
        "a clean file must exit 0 under --format sarif; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).expect("utf8");
    assert_valid_sarif(&stdout);
    let v: Value = serde_json::from_str(&stdout).expect("SARIF stdout parses as JSON");
    let results = v
        .pointer("/runs/0/results")
        .and_then(Value::as_array)
        .expect("results array present");
    assert!(
        results.is_empty(),
        "a clean file must produce zero SARIF results; got: {stdout}"
    );
}

/// `--sarif-include-pass` must stay fapolicyd-ONLY (locked scope): clap must
/// still reject it as an unrecognized flag on `sudoers lint`. GREEN today
/// (clap already rejects the unknown flag) and must stay green after the
/// impl.
#[test]
fn sarif_include_pass_is_rejected_for_sudoers_lint() {
    let cfg = config_file(CLEAN_SUDOERS);
    let out = bin()
        .args(["sudoers", "lint"])
        .arg(cfg.path())
        .args(["--sarif-include-pass"])
        .output()
        .expect("binary ran");
    assert_eq!(
        out.status.code(),
        Some(3),
        "an unrecognized flag is a clap parse error (mapped to EXIT_TOOL_FAILURE); stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8(out.stderr).expect("utf8");
    assert!(
        stderr.contains("--sarif-include-pass"),
        "clap's error must name the rejected flag; got: {stderr}"
    );
}
