//! End-to-end tests for `rulesteward sshd lint` exercising the Wave-A structural
//! lints (sshd-E02/E03/E04, #239) through the real binary: clap parse -> command
//! dispatch -> lint -> human/JSON output -> exit code.
//!
//! Exit-code scheme (shared): 0 clean, 1 warnings, 2 errors. All three codes are
//! Errors, so a triggering config exits 2.

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

fn run_lint(path: &std::path::Path, extra: &[&str]) -> std::process::Output {
    let mut args = vec!["sshd", "lint", path.to_str().unwrap()];
    args.extend_from_slice(extra);
    bin().args(args).output().expect("binary ran")
}

/// A fully STIG-compliant config: all RHEL9-required directives present with
/// baseline-correct values, no weak crypto, no deprecated keywords, no structural
/// issues. Lint-clean under both target=None (the RHEL8 floor) and --target rhel9.
/// Wave B made the W01/W02 passes real, so a minimal config is no longer "clean".
const CLEAN_CONFIG: &str = "\
Banner /etc/issue.net
LogLevel VERBOSE
PubkeyAuthentication yes
PermitEmptyPasswords no
PermitRootLogin no
UsePAM yes
HostbasedAuthentication no
PermitUserEnvironment no
RekeyLimit 1G 1h
ClientAliveCountMax 1
ClientAliveInterval 300
Compression no
GSSAPIAuthentication no
KerberosAuthentication no
IgnoreRhosts yes
IgnoreUserKnownHosts yes
X11Forwarding no
StrictModes yes
PrintLastLog yes
X11UseLocalhost yes
";

#[test]
fn fires_e02_with_exit_two_and_code_in_stdout() {
    let cfg = config_file("PermitRootLogin no\nPermitRootLogin yes\n");
    let out = run_lint(cfg.path(), &[]);
    assert_eq!(out.status.code(), Some(2), "errors exit 2");
    let stdout = String::from_utf8(out.stdout).expect("utf8");
    assert!(
        stdout.contains("sshd-E02"),
        "stdout names the code: {stdout}"
    );
}

#[test]
fn fires_e04_with_exit_two() {
    let cfg = config_file("Match User restricted\n    Ciphers aes256-ctr\n");
    let out = run_lint(cfg.path(), &[]);
    assert_eq!(out.status.code(), Some(2));
    let stdout = String::from_utf8(out.stdout).expect("utf8");
    assert!(stdout.contains("sshd-E04"), "stdout: {stdout}");
}

#[test]
fn fires_e03_with_exit_two() {
    let cfg = config_file("Include /nonexistent-rulesteward-e03-e2e/missing.conf\n");
    let out = run_lint(cfg.path(), &[]);
    assert_eq!(out.status.code(), Some(2));
    let stdout = String::from_utf8(out.stdout).expect("utf8");
    assert!(stdout.contains("sshd-E03"), "stdout: {stdout}");
}

#[test]
fn json_envelope_is_valid_and_carries_the_diagnostic() {
    let cfg = config_file("PermitRootLogin no\nPermitRootLogin yes\n");
    let out = run_lint(cfg.path(), &["--format", "json"]);
    assert_eq!(out.status.code(), Some(2));
    let stdout = String::from_utf8(out.stdout).expect("utf8");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON envelope");
    assert_eq!(v["kind"], "sshd-lint");
    assert_eq!(v["schemaVersion"], 1);
    let diags = v["diagnostics"].as_array().expect("diagnostics array");
    assert!(
        diags.iter().any(|d| d["code"] == "sshd-E02"),
        "envelope carries sshd-E02: {stdout}"
    );
    // Machine-readable output ends with a trailing newline (shell-pipeline safe).
    assert!(stdout.ends_with('\n'), "JSON output ends with a newline");
    // No internal placeholder leakage.
    assert!(
        !stdout.contains("<source>") && !stdout.contains("<TODO>"),
        "no placeholder leakage"
    );
}

#[test]
fn clean_config_exits_zero() {
    let cfg = config_file(CLEAN_CONFIG);
    let out = run_lint(cfg.path(), &[]);
    assert_eq!(out.status.code(), Some(0), "a clean config exits 0");
    let stdout = String::from_utf8(out.stdout).expect("utf8");
    assert!(
        !stdout.contains("sshd-E0"),
        "no error codes for a clean config"
    );
}

// ---------------------------------------------------------------------------
// sshd-F02: cross-file drop-in override (directory target, #149 Wave C).
// A directory target now routes to the F02 check instead of erroring.
// ---------------------------------------------------------------------------

/// Build an /etc/ssh-layout directory under a fresh tempdir: a main `sshd_config`
/// (with `{DIR}` replaced by the tempdir's `sshd_config.d/*.conf` include glob)
/// plus one `<name> -> <body>` drop-in per entry. Returns the tempdir handle
/// (kept alive by the caller).
fn etc_ssh_layout(main: &str, dropins: &[(&str, &str)]) -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    let dropin_dir = dir.path().join("sshd_config.d");
    std::fs::create_dir_all(&dropin_dir).expect("mkdir sshd_config.d");
    let include_glob = dropin_dir.join("*.conf").display().to_string();
    let main_resolved = main.replace("{DIR}", &include_glob);
    std::fs::write(dir.path().join("sshd_config"), &main_resolved).expect("write main");
    for (name, body) in dropins {
        std::fs::write(dropin_dir.join(name), body).expect("write drop-in");
    }
    dir
}

#[test]
fn fires_f02_for_dropin_override_with_exit_two_and_code_in_stdout() {
    // Scenario A (verified rocky9 / OpenSSH 9.9p1): the main file Includes the
    // drop-in dir FIRST, then sets `PermitRootLogin no`; a drop-in sets
    // `PermitRootLogin yes`, which WINS by first-value-wins and FAILS baseline.
    // F02 is Fatal -> exit 2. The directory target is accepted (no longer a tool
    // failure).
    let dir = etc_ssh_layout(
        "Include {DIR}\nPermitRootLogin no\n",
        &[("50-x.conf", "PermitRootLogin yes\n")],
    );
    let out = run_lint(dir.path(), &[]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "a Fatal sshd-F02 exits 2 (stderr: {})",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).expect("utf8");
    assert!(
        stdout.contains("sshd-F02"),
        "stdout names the code: {stdout}"
    );
}

#[test]
fn directory_with_clean_dropins_exits_zero() {
    // A directory target is accepted; a drop-in that does NOT weaken the hardened
    // main file produces no F02 finding -> exit 0. (GREEN against the empty stub
    // today; pins that the directory mode does not error.)
    let dir = etc_ssh_layout(
        "Include {DIR}\nPermitRootLogin no\n",
        &[("50-clean.conf", "PermitRootLogin no\n")],
    );
    let out = run_lint(dir.path(), &[]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "a directory with clean drop-ins exits 0 (stderr: {})",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn fires_f02_when_dropin_match_all_overrides_global_set_before_include() {
    // PRECEDENCE (verified rocky9 `sudo sshd -T -f`): an active `Match all` block
    // overrides the global section regardless of textual position. The main file
    // sets `PermitRootLogin no` BEFORE the Include, then a drop-in's `Match all`
    // sets `yes` -> real sshd effective = `yes` (Match-all wins), which FAILS
    // baseline. F02 is Fatal -> exit 2. (A flat first-value-wins model would miss
    // this; this e2e mirrors the unit-level false-negative killing test.)
    let dir = etc_ssh_layout(
        "PermitRootLogin no\nInclude {DIR}\n",
        &[("50-x.conf", "Match all\nPermitRootLogin yes\n")],
    );
    let out = run_lint(dir.path(), &[]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "an active `Match all` drop-in overriding the earlier global `no` exits 2 \
         (stderr: {})",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).expect("utf8");
    assert!(
        stdout.contains("sshd-F02"),
        "stdout names the code: {stdout}"
    );
}

#[test]
fn fires_f02_when_include_sits_inside_a_match_all_block() {
    // PRECEDENCE (verified rocky9 `sudo sshd -T -f`): an `Include` placed INSIDE an
    // unconditional `Match all` block is unconditionally active, so the drop-in's
    // directives are effective within it. main sets `PermitRootLogin no` then opens
    // `Match all` and Includes the drop-in dir; the drop-in sets `PermitRootLogin
    // yes` -> real sshd effective = `yes`, FAILS baseline. F02 is Fatal -> exit 2.
    // (An impl that only expands top-level Includes misses this; this e2e mirrors
    // the unit-level round-3 killing test.)
    let dir = etc_ssh_layout(
        "PermitRootLogin no\nMatch all\nInclude {DIR}\n",
        &[("50-x.conf", "PermitRootLogin yes\n")],
    );
    let out = run_lint(dir.path(), &[]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "an Include inside a `Match all` block folding a baseline-failing drop-in \
         exits 2 (stderr: {})",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).expect("utf8");
    assert!(
        stdout.contains("sshd-F02"),
        "stdout names the code: {stdout}"
    );
}
