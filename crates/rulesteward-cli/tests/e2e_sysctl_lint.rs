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
