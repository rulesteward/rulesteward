//! End-to-end Phase-0 wiring proof for `rulesteward sysctl lint` (#150).
//!
//! Exercises the subcommand through the real binary: clap parse -> command
//! dispatch -> lint -> human/JSON output -> exit code. The F01/W01 lint passes are
//! still empty Phase-0 stubs, so ANY input currently yields a clean result; this
//! test only proves the `sysctl lint` verb is wired and runs end to end. The
//! pass-FIRES cases land with the F01/W01 impl (test-author barrier + impl
//! pipeline).

use std::io::Write;

use assert_cmd::Command;
use boon::{Compiler, Schemas};
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

#[test]
fn clean_file_exits_zero_with_no_findings() {
    // A plain sysctl.conf-shaped file. With the F01/W01 passes stubbed empty the
    // run is clean: exit 0 and no diagnostic output (the human "no findings"
    // state - the renderer emits an empty string for zero diagnostics).
    let cfg = config_file("# kernel hardening\nkernel.randomize_va_space = 2\n");
    let out = bin()
        .args(["sysctl", "lint", cfg.path().to_str().unwrap()])
        .output()
        .expect("binary ran");
    assert_eq!(
        out.status.code(),
        Some(0),
        "a clean file exits 0 (stderr: {})",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).expect("utf8");
    assert!(
        stdout.trim().is_empty(),
        "stubbed lints produce no findings; stdout was: {stdout}"
    );
    assert!(
        !stdout.contains("sysctld-"),
        "no lint codes for a stubbed clean run: {stdout}"
    );
}

#[test]
fn json_format_emits_the_sysctl_lint_envelope() {
    // The JSON surface is wired through the shared versioned envelope: kind
    // `sysctl-lint`, schemaVersion 1, an (empty for now) diagnostics array, and a
    // trailing newline (shell-pipeline safe).
    let cfg = config_file("net.ipv4.ip_forward = 0\n");
    let out = bin()
        .args([
            "sysctl",
            "lint",
            cfg.path().to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .expect("binary ran");
    assert_eq!(
        out.status.code(),
        Some(0),
        "a clean file exits 0 (stderr: {})",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).expect("utf8");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON envelope");
    assert_eq!(v["kind"], "sysctl-lint");
    assert_eq!(v["schemaVersion"], 1);
    assert!(
        v["diagnostics"].as_array().is_some(),
        "envelope carries a diagnostics array: {stdout}"
    );
    assert!(stdout.ends_with('\n'), "JSON output ends with a newline");
}

// ---------------------------------------------------------------------------
// v1 lint tests (issue #150), authored at the test-author barrier BEFORE the
// F01/W01 impl. RED against the Phase-0 stub: the lint passes return nothing and
// the dir handler treats a directory target as a tool failure, so these fail for
// the RIGHT reason (missing finding / wrong exit code), not a compile error.
// ---------------------------------------------------------------------------

/// Write `name` containing `body` into `dir`.
fn write_in(dir: &std::path::Path, name: &str, body: &str) {
    std::fs::write(dir.join(name), body).expect("write drop-in");
}

#[test]
fn w01_fires_across_dropins_in_lexicographic_order() {
    // The drop-in last-wins case: files apply in lexicographic filename order, so
    // `90-b.conf`'s `=0` wins over `10-a.conf`'s `=1` for the SAME key. The `=1` is
    // dead -> sysctld-W01. Exit code reflects a warning (1).
    //
    // PINS: `sysctl lint <dir>` enumerates the directory's *.conf files in
    // lexicographic order and runs W01 across them. The Phase-0 handler rejects a
    // directory target as a tool failure (exit 3) and the W01 pass is stubbed, so
    // this is RED today; the impl adds dir enumeration + the cross-file W01 pass.
    let dir = tempfile::tempdir().expect("temp dir");
    write_in(dir.path(), "10-a.conf", "net.ipv4.ip_forward=1\n");
    write_in(dir.path(), "90-b.conf", "net.ipv4.ip_forward=0\n");

    let out = bin()
        .args(["sysctl", "lint", dir.path().to_str().unwrap()])
        .output()
        .expect("binary ran");

    let stdout = String::from_utf8(out.stdout).expect("utf8");
    assert!(
        stdout.contains("sysctld-W01"),
        "a cross-drop-in last-wins conflict emits sysctld-W01; stdout was: {stdout} \
         (stderr: {})",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("net.ipv4.ip_forward"),
        "the W01 finding names the conflicting key; stdout was: {stdout}"
    );
    assert_eq!(
        out.status.code(),
        Some(1),
        "a warning-only run exits 1 (EXIT_WARNINGS); stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn malformed_file_exits_with_the_parse_error_code() {
    // A malformed line is sysctld-F01 (Fatal, parse failure). Per
    // exit_code::compute, every backend's parse-failure code (`fapd-F01` / `au-F01`
    // / `sshd-F01`) maps to EXIT_RULE_PARSE_ERROR (5); the impl must add
    // `sysctld-F01` to that match. Today the lint stub emits nothing -> exit 0, so
    // this is RED for the right reason (wrong exit code).
    //
    // `kernel.dmesg_restrict` is a bare key with no `=`: malformed -> F01.
    let cfg = config_file("kernel.dmesg_restrict\n");
    let out = bin()
        .args(["sysctl", "lint", cfg.path().to_str().unwrap()])
        .output()
        .expect("binary ran");

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("sysctld-F01"),
        "a malformed line emits sysctld-F01; stdout was: {stdout} (stderr: {})",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        out.status.code(),
        Some(5),
        "sysctld-F01 (parse failure) maps to EXIT_RULE_PARSE_ERROR (5), not the \
         generic Fatal exit 2; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn human_file_mode_reports_the_real_line_not_line_one() {
    // Integration-gate regression (senior fresh-context review): in FILE mode the
    // human renderer must report the diagnostic's REAL line, not line 1.
    //
    // Post-#337 the F01/W01 diagnostics carry a REAL byte span and the CLI stages the
    // source, so the human renderer takes the ariadne path and derives the snippet
    // header `file:line:col` from the byte span -- which now points at the real line.
    // (Before #337 the span was a degenerate `0..0`; the v1 fix avoided the mis-anchor
    // by NOT staging the source and falling back to plain `file:line:col`. Either way
    // this regression pins the same invariant: the finding references the real line,
    // never line 1.)
    //
    // Layout: the DEAD (overridden) assignment is on line 4. The later assignment
    // (line 5) wins; W01 anchors at line 4. The human output must reference `:4:`
    // and must NOT place this finding at `:1:`.
    let body = "\
# kernel hardening
kernel.sysrq = 0
net.ipv4.ip_forward = 0
kernel.kptr_restrict = 2
kernel.kptr_restrict = 1
";
    let cfg = config_file(body);
    let out = bin()
        // NO_COLOR keeps the snippet header free of ANSI escapes so the `:4:`
        // substring match is robust.
        .env("NO_COLOR", "1")
        .args(["sysctl", "lint", cfg.path().to_str().unwrap()])
        .output()
        .expect("binary ran");

    let stdout = String::from_utf8(out.stdout).expect("utf8");
    assert!(
        stdout.contains("sysctld-W01"),
        "the last-wins conflict emits sysctld-W01; stdout was: {stdout} (stderr: {})",
        String::from_utf8_lossy(&out.stderr)
    );
    // The dead assignment is on line 4: the human output must reference :4:.
    assert!(
        stdout.contains(":4:"),
        "human file-mode output must reference the real line 4 of the dead \
         assignment; stdout was: {stdout}"
    );
    // ...and must NOT report this finding at line 1 (the comment), which is what
    // the degenerate-byte-span ariadne path did.
    assert!(
        !stdout.contains(":1:"),
        "human file-mode output must NOT mis-anchor the finding at line 1; \
         stdout was: {stdout}"
    );
    assert_eq!(
        out.status.code(),
        Some(1),
        "a warning-only run exits 1 (EXIT_WARNINGS); stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// ---------------------------------------------------------------------------
// issue #337: with real byte spans + staged source, the human renderer takes the
// ariadne path and shows a source snippet (box-drawing underline) anchored at the
// real offending line, matching auditd/sshd. RED before the fix: the diagnostics
// carried a 0..0 span, so the CLI staged no source and the PLAIN renderer (no
// box-drawing) was used in both file and dir mode. The `\u{2500}` (-) box-drawing
// char proves the snippet path; the literal `key = value` source-line text proves
// the SNIPPET (the F01/W01 messages never contain that exact literal).
// ---------------------------------------------------------------------------

#[test]
fn human_file_mode_renders_ariadne_snippet_at_the_real_line() {
    // The dead (overridden) assignment is on line 4; the line-5 assignment wins, so
    // W01 anchors at line 4. The snippet must underline line 4 and show its source.
    let body = "\
# kernel hardening
kernel.sysrq = 0
net.ipv4.ip_forward = 0
kernel.kptr_restrict = 2
kernel.kptr_restrict = 1
";
    let cfg = config_file(body);
    let out = bin()
        // NO_COLOR strips ANSI so the substring matches are robust.
        .env("NO_COLOR", "1")
        .args(["sysctl", "lint", cfg.path().to_str().unwrap()])
        .output()
        .expect("binary ran");

    let stdout = String::from_utf8(out.stdout).expect("utf8");
    assert!(
        stdout.contains("sysctld-W01"),
        "the last-wins conflict emits sysctld-W01; stdout: {stdout} (stderr: {})",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains('\u{2500}'),
        "file-mode human output must render an ariadne snippet (box-drawing underline); \
         stdout: {stdout}"
    );
    assert!(
        stdout.contains("kernel.kptr_restrict = 2"),
        "the snippet must include the real dead source line text; stdout: {stdout}"
    );
    assert!(
        stdout.contains(":4:"),
        "the snippet header must anchor at the real line 4; stdout: {stdout}"
    );
    assert_eq!(
        out.status.code(),
        Some(1),
        "a warning-only run exits 1; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn human_dir_mode_renders_ariadne_snippet_for_cross_file_conflict() {
    // dir-mode stages each `*.conf` it reads, so a cross-file last-wins W01 renders a
    // snippet anchored in the drop-in that holds the DEAD line. The dead assignment is
    // on line 2 of `10-a.conf` (line 1 is a comment), so the header reads `:2:`.
    let dir = tempfile::tempdir().expect("temp dir");
    write_in(
        dir.path(),
        "10-a.conf",
        "# earlier drop-in\nnet.ipv4.ip_forward = 1\n",
    );
    write_in(dir.path(), "90-b.conf", "net.ipv4.ip_forward = 0\n");

    let out = bin()
        .env("NO_COLOR", "1")
        .args(["sysctl", "lint", dir.path().to_str().unwrap()])
        .output()
        .expect("binary ran");

    let stdout = String::from_utf8(out.stdout).expect("utf8");
    assert!(
        stdout.contains("sysctld-W01"),
        "the cross-file conflict emits sysctld-W01; stdout: {stdout} (stderr: {})",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains('\u{2500}'),
        "dir-mode human output must render an ariadne snippet; stdout: {stdout}"
    );
    assert!(
        stdout.contains("net.ipv4.ip_forward = 1"),
        "the snippet must include the dead drop-in's real source line; stdout: {stdout}"
    );
    assert!(
        stdout.contains(":2:"),
        "the snippet header must anchor at the dead line 2 of 10-a.conf; stdout: {stdout}"
    );
    assert_eq!(
        out.status.code(),
        Some(1),
        "a warning-only run exits 1; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn human_file_mode_renders_ariadne_snippet_for_a_malformed_line() {
    // A malformed line on line 3 must render an F01 snippet anchored at `:3:` and show
    // the malformed source text (the F01 message never contains that literal).
    let body = "\
# header
kernel.sysrq = 0
kernel.dmesg_restrict
";
    let cfg = config_file(body);
    let out = bin()
        .env("NO_COLOR", "1")
        .args(["sysctl", "lint", cfg.path().to_str().unwrap()])
        .output()
        .expect("binary ran");

    let stdout = String::from_utf8(out.stdout).expect("utf8");
    assert!(
        stdout.contains("sysctld-F01"),
        "the malformed line emits sysctld-F01; stdout: {stdout} (stderr: {})",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains('\u{2500}'),
        "the F01 must render an ariadne snippet; stdout: {stdout}"
    );
    assert!(
        stdout.contains("kernel.dmesg_restrict"),
        "the snippet must include the malformed source line; stdout: {stdout}"
    );
    assert!(
        stdout.contains(":3:"),
        "the snippet header must anchor at the malformed line 3; stdout: {stdout}"
    );
    assert_eq!(
        out.status.code(),
        Some(5),
        "sysctld-F01 maps to EXIT_RULE_PARSE_ERROR (5); stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn human_file_mode_snippet_anchors_correctly_with_multibyte_before_the_finding() {
    // issue #337 (strengthening, per the spec + idiomatic reviewers): a multibyte UTF-8
    // char on a line BEFORE the finding exercises the byte-span -> char-span conversion
    // the renderer does (human.rs `byte_span_to_char_span`). The parser emits a BYTE
    // span; the renderer converts it to a char offset for ariadne. A byte/char mismatch
    // anywhere in that chain would mis-anchor the header. The dead assignment is on line
    // 2; the `\u{e9}` (2 bytes / 1 char) on line 1 must not shift the snippet off line 2.
    let body = "\
# caf\u{e9} notes
kernel.kptr_restrict = 2
kernel.kptr_restrict = 1
";
    let cfg = config_file(body);
    let out = bin()
        .env("NO_COLOR", "1")
        .args(["sysctl", "lint", cfg.path().to_str().unwrap()])
        .output()
        .expect("binary ran");

    let stdout = String::from_utf8(out.stdout).expect("utf8");
    assert!(
        stdout.contains("sysctld-W01"),
        "the last-wins conflict emits sysctld-W01; stdout: {stdout} (stderr: {})",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains('\u{2500}'),
        "the snippet must render even with a multibyte char before the finding; stdout: {stdout}"
    );
    assert!(
        stdout.contains("kernel.kptr_restrict = 2"),
        "the snippet must underline the real dead source line; stdout: {stdout}"
    );
    assert!(
        stdout.contains(":2:"),
        "the snippet header must anchor at line 2 despite the multibyte line 1; stdout: {stdout}"
    );
    assert_eq!(
        out.status.code(),
        Some(1),
        "a warning-only run exits 1; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// ---------------------------------------------------------------------------
// issue #335: the version-aware sysctld-W02 STIG baseline, gated on --target.
// RED before the impl: --target is unknown to clap (or W02 is the empty stub), so
// these fail for the right reason (no W02 emitted / wrong exit code).
// ---------------------------------------------------------------------------

#[test]
fn target_rhel9_flags_unset_baseline_keys() {
    // A config that sets no STIG-required key leaves them all unset; --target rhel9
    // runs the W02 baseline and reports them as warnings (exit 1).
    let cfg = config_file("# nothing hardened here\nkernel.sysrq = 0\n");
    let out = bin()
        .args([
            "sysctl",
            "lint",
            cfg.path().to_str().unwrap(),
            "--target",
            "rhel9",
        ])
        .output()
        .expect("binary ran");

    let stdout = String::from_utf8(out.stdout).expect("utf8");
    assert!(
        stdout.contains("sysctld-W02"),
        "an unhardened config under --target rhel9 emits sysctld-W02; stdout: {stdout} \
         (stderr: {})",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("kernel.dmesg_restrict"),
        "a W02 names a concrete unset STIG key; stdout: {stdout}"
    );
    assert_eq!(
        out.status.code(),
        Some(1),
        "a warning-only W02 run exits 1 (EXIT_WARNINGS); stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn no_target_emits_no_w02() {
    // Without --target the STIG baseline does not run: the same unhardened config
    // is clean (exit 0, no sysctld-W02).
    let cfg = config_file("kernel.sysrq = 0\n");
    let out = bin()
        .args(["sysctl", "lint", cfg.path().to_str().unwrap()])
        .output()
        .expect("binary ran");

    let stdout = String::from_utf8(out.stdout).expect("utf8");
    assert!(
        !stdout.contains("sysctld-W02"),
        "no --target means no W02; stdout: {stdout}"
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "no findings without a target -> exit 0; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn target_rhel9_present_insecure_renders_key_and_snippet() {
    // A present-but-insecure key (dmesg_restrict=0, requires 1) renders an ariadne
    // snippet anchored at its real line, naming the key. Functional-smoke for the
    // human surface.
    let cfg = config_file("kernel.dmesg_restrict = 0\n");
    let out = bin()
        .env("NO_COLOR", "1")
        .args([
            "sysctl",
            "lint",
            cfg.path().to_str().unwrap(),
            "--target",
            "rhel9",
        ])
        .output()
        .expect("binary ran");

    let stdout = String::from_utf8(out.stdout).expect("utf8");
    assert!(
        stdout.contains("sysctld-W02") && stdout.contains("kernel.dmesg_restrict"),
        "the insecure value is reported as a W02 naming the key; stdout: {stdout}"
    );
    assert!(
        stdout.contains('\u{2500}'),
        "a present-but-insecure W02 renders an ariadne snippet (box-drawing); stdout: {stdout}"
    );
    assert!(
        stdout.contains(":1:"),
        "the snippet anchors at the real assignment line 1; stdout: {stdout}"
    );
    assert_eq!(
        out.status.code(),
        Some(1),
        "a warning-only W02 run exits 1; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn json_envelope_carries_w02_under_target() {
    let cfg = config_file("kernel.sysrq = 0\n");
    let out = bin()
        .args([
            "sysctl",
            "lint",
            cfg.path().to_str().unwrap(),
            "--target",
            "rhel9",
            "--format",
            "json",
        ])
        .output()
        .expect("binary ran");

    let stdout = String::from_utf8(out.stdout).expect("utf8");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON envelope");
    let diags = v["diagnostics"].as_array().expect("diagnostics array");
    assert!(
        diags.iter().any(|d| d["code"] == "sysctld-W02"),
        "the JSON envelope carries at least one sysctld-W02 diagnostic; stdout: {stdout}"
    );
}

#[test]
fn help_lists_the_target_flag() {
    let out = bin()
        .args(["sysctl", "lint", "--help"])
        .output()
        .expect("binary ran");
    assert_eq!(out.status.code(), Some(0), "--help exits 0");
    let stdout = String::from_utf8(out.stdout).expect("utf8");
    assert!(
        stdout.contains("--target"),
        "sysctl lint --help advertises the --target flag; stdout: {stdout}"
    );
}

// ---------------------------------------------------------------------------
// #511 (v0.8 Wave 4): SARIF output for the 5 `HumanJsonFormat` lint verbs
// (findings-only). RED today: `SysctlLintArgs.format` is `HumanJsonFormat`
// (human|json only), so clap rejects `--format sarif` at parse time. The
// planned impl switches `SysctlLintArgs.format` to `OutputFormat` and routes
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

/// A malformed line fires the parse-failure code `sysctld-F01` (Fatal, NO
/// controls attached). SARIF output is schema-valid, carries `ruleId:
/// "sysctld-F01"` at `level: "error"`, ends with a trailing newline, exits 5
/// (`EXIT_RULE_PARSE_ERROR`, matching
/// `malformed_file_exits_with_the_parse_error_code` above) -- and, because
/// F01 carries no `controls`, the run has NO `taxonomies` key and the result
/// has NO `taxa` key. This is sarif.rs's generic, backend-agnostic
/// `sarif_no_controls_omits_taxonomy_keys` unit pin, exercised here end to
/// end through the real CLI for a non-fapolicyd backend.
#[test]
fn sarif_format_fires_f01_with_ruleid_error_level_and_no_taxonomy_keys() {
    let cfg = config_file("kernel.dmesg_restrict\n");
    let out = bin()
        .args([
            "sysctl",
            "lint",
            cfg.path().to_str().unwrap(),
            "--format",
            "sarif",
        ])
        .output()
        .expect("binary ran");
    assert_eq!(
        out.status.code(),
        Some(5),
        "sysctld-F01 maps to EXIT_RULE_PARSE_ERROR (5) under SARIF too; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).expect("utf8");
    assert_valid_sarif(&stdout);
    let v: Value = serde_json::from_str(&stdout).expect("SARIF stdout parses as JSON");
    let results = v
        .pointer("/runs/0/results")
        .and_then(Value::as_array)
        .expect("results array present");
    let f01 = results
        .iter()
        .find(|r| r.get("ruleId").and_then(Value::as_str) == Some("sysctld-F01"))
        .unwrap_or_else(|| panic!("no sysctld-F01 result found: {stdout}"));
    assert_eq!(
        f01.get("level").and_then(Value::as_str),
        Some("error"),
        "Fatal severity maps to SARIF level \"error\"; got: {stdout}"
    );
    assert!(
        stdout.ends_with('\n'),
        "SARIF stdout must end with a newline"
    );
    assert!(
        v.pointer("/runs/0/taxonomies").is_none(),
        "sysctld-F01 carries no controls; the run must have NO taxonomies key: {stdout}"
    );
    assert!(
        f01.get("taxa").is_none(),
        "sysctld-F01 carries no controls; its result must have NO taxa key: {stdout}"
    );
}

/// A clean file (no `--target`) emits a schema-valid SARIF document with zero
/// results and exits 0.
#[test]
fn sarif_format_clean_file_is_schema_valid_with_zero_results() {
    let cfg = config_file("kernel.sysrq = 0\n");
    let out = bin()
        .args([
            "sysctl",
            "lint",
            cfg.path().to_str().unwrap(),
            "--format",
            "sarif",
        ])
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

/// A STIG-mapped finding (`sysctld-W02` under `--target rhel9`) produces a
/// `runs[0].taxonomies[]` entry named "STIG" (`Framework::Stig::name()`) and
/// at least one `sysctld-W02` result whose `taxa[]` is non-empty. Exercises
/// the generic, backend-agnostic taxonomy plumbing (sarif.rs
/// `collect_taxonomy_groups` / `diagnostic_to_result`) end to end for a
/// non-fapolicyd backend.
#[test]
fn sarif_format_target_rhel9_w02_carries_stig_taxonomy_and_taxa() {
    let cfg = config_file("# nothing hardened here\nkernel.sysrq = 0\n");
    let out = bin()
        .args([
            "sysctl",
            "lint",
            cfg.path().to_str().unwrap(),
            "--target",
            "rhel9",
            "--format",
            "sarif",
        ])
        .output()
        .expect("binary ran");
    assert_eq!(
        out.status.code(),
        Some(1),
        "sysctld-W02 (Warning) exits 1 under SARIF too; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).expect("utf8");
    assert_valid_sarif(&stdout);
    let v: Value = serde_json::from_str(&stdout).expect("SARIF stdout parses as JSON");

    let taxonomies = v
        .pointer("/runs/0/taxonomies")
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("no taxonomies array present: {stdout}"));
    assert!(
        taxonomies
            .iter()
            .any(|t| t.get("name").and_then(Value::as_str) == Some("STIG")),
        "a taxonomies entry named \"STIG\" must be present: {stdout}"
    );

    let results = v
        .pointer("/runs/0/results")
        .and_then(Value::as_array)
        .expect("results array present");
    assert!(
        results.iter().any(|r| {
            r.get("ruleId").and_then(Value::as_str) == Some("sysctld-W02")
                && r.get("taxa")
                    .and_then(Value::as_array)
                    .is_some_and(|taxa| !taxa.is_empty())
        }),
        "a sysctld-W02 result must carry a non-empty taxa[] array: {stdout}"
    );
}

/// `--sarif-include-pass` must stay fapolicyd-ONLY (locked scope): clap must
/// still reject it as an unrecognized flag on `sysctl lint`. GREEN today
/// (clap already rejects the unknown flag) and must stay green after the
/// impl.
#[test]
fn sarif_include_pass_is_rejected_for_sysctl_lint() {
    let cfg = config_file("kernel.sysrq = 0\n");
    let out = bin()
        .args([
            "sysctl",
            "lint",
            cfg.path().to_str().unwrap(),
            "--sarif-include-pass",
        ])
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
