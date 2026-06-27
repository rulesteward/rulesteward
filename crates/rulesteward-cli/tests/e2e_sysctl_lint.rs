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
