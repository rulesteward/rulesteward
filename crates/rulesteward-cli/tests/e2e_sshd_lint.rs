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
    // main file produces no finding -> exit 0.
    //
    // #324 CHANGED dir-mode semantics: directory mode now runs the single-file lint
    // suite (sshd-E01/W01..W06) over the MERGED EFFECTIVE config in addition to F02.
    // So "clean drop-ins exit 0" now requires the MERGED VIEW to be STIG-complete and
    // compliant, not just F02-clean. The base is the fully STIG-complete CLEAN_CONFIG
    // (every RHEL9-required directive present + compliant) plus an Include; the drop-in
    // re-asserts a compliant value (PermitRootLogin no) which agrees with the base, so
    // F02 does not fire and the merged view is still STIG-complete. Pins that a genuinely
    // clean /etc/ssh layout exits 0 under the new merged-suite behavior. (--target rhel9
    // pins the version-aware required set the merged view is checked against.)
    let dir = etc_ssh_layout(
        &format!("{CLEAN_CONFIG}Include {{DIR}}\n"),
        &[("50-clean.conf", "PermitRootLogin no\n")],
    );
    let out = run_lint(dir.path(), &["--target", "rhel9"]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "a directory whose MERGED view is STIG-complete + compliant exits 0 \
         (stdout: {}; stderr: {})",
        String::from_utf8_lossy(&out.stdout),
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

// ===========================================================================
// #324: directory mode runs the single-file lint suite (sshd-E01/W01..W06)
// over the MERGED EFFECTIVE config, not just F02.
//
// Today the `path.is_dir()` branch in commands/sshd.rs runs ONLY
// `lints::drop_in::lint_drop_in` (F02) and returns, so a weak algorithm or a
// missing/weak STIG directive that only manifests in the MERGED view (base
// sshd_config + sshd_config.d/*.conf drop-ins) is never reported in dir mode.
// The fix: also run the relevant single-file passes (E01, W01, W02, W03, W04,
// W06) over a synthetic merged Block, REMAPPING each diagnostic's (file, line)
// back to the real winning source file (a drop-in, not the base). E02/E03/W05
// and F02 are NOT part of the merged run (F02 stays the separate cross-file
// pass; Include is already resolved away in the merged view).
//
// All tests below are RED against the current F02-only dir behavior.
// ===========================================================================

/// Parse the `--format json` envelope and return its `diagnostics` array.
/// Fails the test (with the raw stdout) if the output is not a valid envelope.
fn diagnostics_json(out: &std::process::Output) -> Vec<serde_json::Value> {
    let stdout = String::from_utf8(out.stdout.clone()).expect("utf8 stdout");
    let v: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("stdout is a valid JSON envelope ({e}); got: {stdout}"));
    v["diagnostics"]
        .as_array()
        .unwrap_or_else(|| panic!("envelope has a diagnostics array; got: {stdout}"))
        .clone()
}

#[test]
fn dir_mode_w03_weak_algo_in_dropin_anchors_to_the_dropin() {
    // PROVENANCE / anchoring-fidelity (the key #324 test). The base sshd_config is
    // otherwise fine (fully STIG-complete CLEAN_CONFIG); a drop-in `50-weak.conf`
    // sets a weak CBC cipher that sshd-W03 flags. Because W03 runs over the MERGED
    // view, dir mode must emit sshd-W03, and the diagnostic must be anchored to the
    // DROP-IN file (`50-weak.conf`) -- the file the operator must edit -- NOT to the
    // base `sshd_config`, because the weak directive physically lives in the drop-in.
    //
    // (Today dir mode never runs W03 -> diagnostics array is empty -> RED on both
    // the code-presence and the anchoring assertion.)
    let dir = etc_ssh_layout(
        &format!("{CLEAN_CONFIG}Include {{DIR}}\n"),
        &[("50-weak.conf", "Ciphers aes256-cbc\n")],
    );
    let out = run_lint(dir.path(), &["--target", "rhel9", "--format", "json"]);
    let diags = diagnostics_json(&out);

    let w03: Vec<&serde_json::Value> = diags.iter().filter(|d| d["code"] == "sshd-W03").collect();
    assert_eq!(
        w03.len(),
        1,
        "dir mode runs W03 over the merged view: exactly one sshd-W03 for the weak \
         drop-in cipher; got diagnostics: {diags:?}"
    );
    let d = w03[0];
    // ANCHORING ASSERTION (load-bearing): the diagnostic's `file` is the DROP-IN that
    // actually contains the weak cipher, not the base sshd_config. The merged passes
    // run over a synthetic Block whose directives come from many files; the fix must
    // remap each finding back to its true source file.
    let file = d["file"].as_str().expect("file is a string");
    assert!(
        file.ends_with("50-weak.conf"),
        "sshd-W03 must anchor to the drop-in that holds the weak cipher (50-weak.conf), \
         not the base sshd_config; got file = {file:?}"
    );
    assert!(
        !file.ends_with("/sshd_config"),
        "sshd-W03 must NOT anchor to the base sshd_config; got file = {file:?}"
    );
    // The weak cipher's line within the drop-in is line 1 (it is the drop-in's only
    // directive), proving line provenance is preserved through the remap.
    assert_eq!(
        d["line"].as_u64(),
        Some(1),
        "sshd-W03 line must be the directive's line within the drop-in (1); got: {d:?}"
    );
    assert_eq!(
        d["source_id"].as_str(),
        Some(file),
        "source_id is remapped to the same winning drop-in as file; got: {d:?}"
    );
}

#[test]
fn dir_mode_no_false_w01_when_required_directive_supplied_by_dropin() {
    // No-false-positive when hardening is SPLIT across files. The base lacks a
    // STIG-required directive (Banner) but a drop-in supplies it (a correct effective
    // value). A NAIVE per-file impl would false-positive sshd-W01 "Banner missing" on
    // the minimal base; the merged view HAS Banner, so W01 must NOT fire for Banner.
    //
    // Pair-guard against a trivial "never run W01" satisfier: the companion test
    // `dir_mode_w01_fires_when_required_directive_missing_from_merged_view` requires
    // W01 to FIRE for a genuinely-missing directive, so an impl can't satisfy both by
    // simply never running W01. Here the merged view is otherwise STIG-complete
    // (CLEAN_CONFIG minus Banner, with Banner restored by the drop-in), so a correct
    // merged W01 run yields ZERO W01 findings and exit 0.
    //
    // (Today dir mode emits no W01 at all, so this currently passes VACUOUSLY; it
    // becomes a real guard only alongside the firing test below and is RED-meaningful
    // once W01 runs over the merged view.)
    let base_without_banner = CLEAN_CONFIG.replace("Banner /etc/issue.net\n", "");
    let dir = etc_ssh_layout(
        &format!("{base_without_banner}Include {{DIR}}\n"),
        &[("10-banner.conf", "Banner /etc/issue.net\n")],
    );
    let out = run_lint(dir.path(), &["--target", "rhel9"]);
    let stdout = String::from_utf8(out.stdout.clone()).expect("utf8");
    assert!(
        !stdout.contains("banner"),
        "Banner is supplied by a drop-in in the merged view; W01 must NOT report it \
         missing (no per-file false positive); stdout: {stdout}"
    );
    // The merged view is STIG-complete and compliant -> no findings at all -> exit 0.
    assert_eq!(
        out.status.code(),
        Some(0),
        "a merged view that is STIG-complete via a split drop-in exits 0 \
         (stdout: {stdout}; stderr: {})",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn dir_mode_w01_fires_when_required_directive_missing_from_merged_view() {
    // W01 fires when a STIG-required directive is genuinely missing from the MERGED
    // effective config. The base is CLEAN_CONFIG MINUS Banner, and NO drop-in supplies
    // Banner, so the merged view lacks a required directive entirely -> sshd-W01 must
    // fire naming `banner`, and the exit code reflects a warning (1).
    //
    // (Today dir mode emits no W01 -> RED.)
    let base_without_banner = CLEAN_CONFIG.replace("Banner /etc/issue.net\n", "");
    let dir = etc_ssh_layout(
        &format!("{base_without_banner}Include {{DIR}}\n"),
        // a drop-in that does NOT supply Banner (sets an unrelated value)
        &[("50-misc.conf", "MaxAuthTries 4\n")],
    );
    let out = run_lint(dir.path(), &["--target", "rhel9"]);
    let stdout = String::from_utf8(out.stdout.clone()).expect("utf8");
    assert!(
        stdout.contains("sshd-W01"),
        "a STIG-required directive missing from the merged view must fire sshd-W01; \
         stdout: {stdout}"
    );
    assert!(
        stdout.contains("banner"),
        "the sshd-W01 finding must name the missing directive (banner); stdout: {stdout}"
    );
    assert_eq!(
        out.status.code(),
        Some(1),
        "a warning-only result (W01) exits 1; got stdout: {stdout}; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn dir_mode_w02_no_finding_when_dropin_overrides_weak_base_to_strong() {
    // W02 effective-value correctness, COMPLIANT case. The base sets a STIG-WEAK value
    // (PermitRootLogin yes) and a later-winning drop-in OVERRIDES it to the strong
    // value. Because the drop-in is Included FIRST (first-value-wins), the EFFECTIVE
    // value is the drop-in's `no`, which is COMPLIANT -> W02 must NOT fire for
    // PermitRootLogin. A per-file impl would false-positive on the base `yes`.
    //
    // (Today dir mode emits no W02 -> this currently passes vacuously; it is the
    // compliant half of the converse pair below, which fires.)
    let base_weak = CLEAN_CONFIG.replace("PermitRootLogin no\n", "PermitRootLogin yes\n");
    // Include FIRST so the drop-in wins (first-value-wins), then the weak base value.
    let dir = etc_ssh_layout(
        &format!("Include {{DIR}}\n{base_weak}"),
        &[("10-fix.conf", "PermitRootLogin no\n")],
    );
    let out = run_lint(dir.path(), &["--target", "rhel9", "--format", "json"]);
    let diags = diagnostics_json(&out);
    let w02_prl: Vec<&serde_json::Value> = diags
        .iter()
        .filter(|d| {
            d["code"] == "sshd-W02"
                && d["message"]
                    .as_str()
                    .is_some_and(|m| m.to_ascii_lowercase().contains("permitrootlogin"))
        })
        .collect();
    assert!(
        w02_prl.is_empty(),
        "the drop-in overrides the weak base PermitRootLogin to the compliant 'no' \
         (effective value compliant) -> W02 must NOT fire for it; got: {diags:?}"
    );
}

#[test]
fn dir_mode_w02_fires_anchored_to_dropin_when_dropin_weakens_strong_base() {
    // W02 effective-value correctness, CONVERSE case. The base sets the STRONG value
    // (PermitRootLogin no) but a winning drop-in WEAKENS it to `yes`. Because the
    // drop-in is Included FIRST, the EFFECTIVE value is the drop-in's `yes`, which
    // FAILS the STIG baseline.
    //
    // NOTE: the same scenario also fires F02 (a drop-in beating a main-file directive
    // with a baseline-failing value IS the canonical F02). The #324 fix is that the
    // value-vs-baseline finding ALSO surfaces via the merged-W02 run, anchored to the
    // drop-in (line 1). We assert a W02 finding for PermitRootLogin anchored to the
    // drop-in. (Today dir mode runs neither W02 nor reports a W02 code -> RED.)
    let dir = etc_ssh_layout(
        &format!("Include {{DIR}}\n{CLEAN_CONFIG}"),
        &[("10-weaken.conf", "PermitRootLogin yes\n")],
    );
    let out = run_lint(dir.path(), &["--target", "rhel9", "--format", "json"]);
    let diags = diagnostics_json(&out);
    let w02_prl: Vec<&serde_json::Value> = diags
        .iter()
        .filter(|d| {
            d["code"] == "sshd-W02"
                && d["message"]
                    .as_str()
                    .is_some_and(|m| m.to_ascii_lowercase().contains("permitrootlogin"))
        })
        .collect();
    assert_eq!(
        w02_prl.len(),
        1,
        "the drop-in weakens the strong base PermitRootLogin to 'yes' (effective value \
         fails baseline) -> exactly one sshd-W02 for PermitRootLogin; got: {diags:?}"
    );
    let d = w02_prl[0];
    let file = d["file"].as_str().expect("file is a string");
    assert!(
        file.ends_with("10-weaken.conf"),
        "sshd-W02 must anchor to the drop-in that supplies the effective (weak) value, \
         not the base; got file = {file:?}"
    );
    assert_eq!(
        d["line"].as_u64(),
        Some(1),
        "sshd-W02 line is the directive's line within the drop-in (1); got: {d:?}"
    );
}

#[test]
fn dir_mode_f02_still_fires_alongside_merged_suite() {
    // F02 must keep working after the #324 fix (the merged-suite run is ADDITIVE).
    // A genuine cross-file override (base hardens PermitRootLogin no AFTER the Include;
    // a drop-in sets yes which wins by first-value-wins) emits the Fatal sshd-F02, and
    // the directory still exits 2 (F02 is Fatal). This guards against the fix breaking
    // or shadowing F02.
    //
    // The base is otherwise STIG-complete (CLEAN_CONFIG) so the ONLY Fatal is F02;
    // exit code 2 confirms F02 is still emitted at Fatal severity.
    let dir = etc_ssh_layout(
        &format!("Include {{DIR}}\n{CLEAN_CONFIG}"),
        &[("50-x.conf", "PermitRootLogin yes\n")],
    );
    let out = run_lint(dir.path(), &["--target", "rhel9"]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "a Fatal sshd-F02 still exits 2 alongside the merged suite (stdout: {}; stderr: {})",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).expect("utf8");
    assert!(
        stdout.contains("sshd-F02"),
        "sshd-F02 is still emitted in dir mode: {stdout}"
    );
}
