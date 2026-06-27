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

// ===========================================================================
// #324 follow-up (impl-aware adversarial miss): dir-mode must run the
// "as-written" single-file passes over the bodies of CONDITIONAL `Match`
// blocks too, not just over the global / `Match all` effective config.
//
// THE MISS (empirically confirmed against the current impl, 2026-06-27):
// `lint_merged` builds the merged view from `build_stream` ->
// `effective_directives_of`, which keeps ONLY `Block::Global` and the
// unconditional `Match all` body and DROPS every CONDITIONAL `Match`
// (`User`/`Group`/`Address`/...) block. So an "as-written" finding inside a
// conditional `Match` block -- a weak cipher, an operator-form weak algo, an
// unknown directive, a deprecated directive -- that single-file mode reports
// is SILENTLY LOST in dir mode. Reproduced: a base `sshd_config` with
//   Match Address 192.168.1.0/24
//       Ciphers aes256-cbc
// fires sshd-W03 in single-file mode but emits NOTHING in dir mode.
//
// THE CORRECT DISTINCTION (the fix implements; these tests pin the behavior):
//   * "AS-WRITTEN" passes -- sshd-E01 (unknown), sshd-W03 (weak algo),
//     sshd-W04 (deprecated), sshd-W06 (algo-list operator), and the
//     Match-oriented sshd-E04 / sshd-W05 -- MUST fire on content inside a
//     CONDITIONAL `Match` block in dir mode, anchored to the real source file
//     + line. (These passes already scan `Block::Match` bodies in single-file
//     mode; parity is the #324 contract.)
//   * "EFFECTIVE-VALUE" passes -- sshd-W01 (required-directive-missing) and
//     sshd-W02 (weaker-than-baseline) -- MUST stay effective-config-only: a
//     value set ONLY inside a conditional `Match` block is per-connection, not
//     the global daemon baseline, so it must NOT satisfy a W01 global
//     requirement nor by itself trigger/clear W02 for the global baseline.
//     (W01/W02 read the global block only; the fix must re-expose conditional
//     `Match` bodies AS a `Match` block -- not fold them into the synthetic
//     GLOBAL -- so the effective-value passes are unaffected.)
//
// SINGLE-FILE PARITY GROUNDING (verified 2026-06-27 with
// `cargo run -q -p rulesteward-cli -- sshd lint <file> --target rhel9 --format json`
// on a one-file fixture = CLEAN_CONFIG + the conditional `Match` block):
//   * `Match Address .../ Ciphers aes256-cbc`     -> sshd-W03 (+ sshd-E04)
//   * `Match Address .../ Ciphers +aes128-cbc`    -> sshd-W06 (+ sshd-E04)
//   * `Match Address .../ TotallyBogusDirective foo` -> sshd-E01 (only)
//   * `Match Address .../ UseLogin no`            -> sshd-W04 (+ sshd-E04)
//   * `Match User .../ Ciphers aes256-ctr`        -> sshd-E04 (only; strong)
//   * `Match User .../ PermitRootLogin yes`       -> sshd-W05 (only)
// (`Ciphers`/`UseLogin` co-fire sshd-E04 because they are not Match-permitted;
// the parity assertions filter on the target code, so the extra E04 is inert.)
//
// The POSITIVE parity tests are RED against the current impl (the finding is
// ABSENT in dir mode = an assertion failure, not a compile error). The
// NEGATIVE guards pass today and pin the effective-value exclusion so the fix
// cannot "satisfy" the parity tests by wrongly folding `Match` values into the
// global W01/W02 view.
// ===========================================================================

/// `CLEAN_CONFIG` with one CONDITIONAL `Match` block appended whose body is
/// `match_body` (verbatim, caller supplies the indentation). The merged dir-mode
/// view of `{CLEAN_CONFIG}Include {DIR}` + a drop-in carrying this block must run
/// the as-written passes over the conditional `Match` body.
fn clean_plus_conditional_match(header: &str, match_body: &str) -> String {
    format!("{CLEAN_CONFIG}{header}\n{match_body}")
}

// --- POSITIVE parity: as-written passes fire inside a conditional Match block ---

#[test]
fn dir_mode_w03_fires_inside_conditional_match_block() {
    // The base sshd_config is STIG-complete CLEAN_CONFIG (so W01/W02 stay quiet)
    // PLUS a conditional `Match Address 192.168.1.0/24` block whose body sets a
    // weak CBC cipher. Single-file mode fires sshd-W03 on that line (verified);
    // dir mode must too, anchored to the file + the real `Ciphers` line.
    //
    // The base is the file holding the block. Within the base, CLEAN_CONFIG is 20
    // lines, the `Include {DIR}` line is 21, the `Match Address ...` header is 22,
    // and the `    Ciphers aes256-cbc` body is line 23 -- the W03 anchor.
    //
    // (Today dir mode drops the conditional Match body -> diagnostics array carries
    // no W03 -> RED on the code-presence assertion.)
    let body = clean_plus_conditional_match(
        "Include {DIR}\nMatch Address 192.168.1.0/24",
        "    Ciphers aes256-cbc\n",
    );
    let dir = etc_ssh_layout(&body, &[("50-noise.conf", "# no drop-in directives\n")]);
    let out = run_lint(dir.path(), &["--target", "rhel9", "--format", "json"]);
    let diags = diagnostics_json(&out);

    let w03: Vec<&serde_json::Value> = diags.iter().filter(|d| d["code"] == "sshd-W03").collect();
    assert_eq!(
        w03.len(),
        1,
        "dir mode must run W03 over a CONDITIONAL Match body: exactly one sshd-W03 \
         for the weak cipher; got diagnostics: {diags:?}"
    );
    let d = w03[0];
    assert!(
        d["message"]
            .as_str()
            .is_some_and(|m| m.contains("aes256-cbc")),
        "the W03 message names the weak cipher; got: {d:?}"
    );
    let file = d["file"].as_str().expect("file is a string");
    assert!(
        file.ends_with("/sshd_config"),
        "the weak cipher lives in the base sshd_config (the file with the Match \
         block), so W03 anchors there; got file = {file:?}"
    );
    assert_eq!(
        d["line"].as_u64(),
        Some(23),
        "W03 anchors to the real `Ciphers` line inside the conditional Match block \
         (line 23 of the base: 20 CLEAN_CONFIG + Include + Match header + Ciphers); \
         got: {d:?}"
    );
}

#[test]
fn dir_mode_w06_fires_inside_conditional_match_block() {
    // A conditional `Match` block body with an operator-form weak algo list
    // (`Ciphers +aes128-cbc`) that sshd-W06 flags (verified single-file: W06 fires
    // on the `+aes128-cbc` token). dir mode must run W06 over the conditional Match
    // body, anchored to the real file + line.
    //
    // (Today dir mode drops the conditional Match body -> no W06 -> RED.)
    let body = clean_plus_conditional_match(
        "Include {DIR}\nMatch Address 192.168.1.0/24",
        "    Ciphers +aes128-cbc\n",
    );
    let dir = etc_ssh_layout(&body, &[("50-noise.conf", "# no drop-in directives\n")]);
    let out = run_lint(dir.path(), &["--target", "rhel9", "--format", "json"]);
    let diags = diagnostics_json(&out);

    let w06: Vec<&serde_json::Value> = diags.iter().filter(|d| d["code"] == "sshd-W06").collect();
    assert_eq!(
        w06.len(),
        1,
        "dir mode must run W06 over a CONDITIONAL Match body: exactly one sshd-W06 \
         for the `+aes128-cbc` operator token; got diagnostics: {diags:?}"
    );
    let d = w06[0];
    assert!(
        d["message"]
            .as_str()
            .is_some_and(|m| m.contains("aes128-cbc")),
        "the W06 message names the reintroduced weak algorithm; got: {d:?}"
    );
    let file = d["file"].as_str().expect("file is a string");
    assert!(
        file.ends_with("/sshd_config"),
        "the operator-form algo list lives in the base sshd_config; W06 anchors \
         there; got file = {file:?}"
    );
    assert_eq!(
        d["line"].as_u64(),
        Some(23),
        "W06 anchors to the real `Ciphers +aes128-cbc` line inside the conditional \
         Match block (line 23 of the base); got: {d:?}"
    );
}

#[test]
fn dir_mode_e01_fires_inside_conditional_match_block() {
    // A conditional `Match` block body with an unknown directive
    // (`TotallyBogusDirective foo`) that sshd-E01 flags (verified single-file: E01
    // fires, and -- because E04 skips unknown keywords -- it is the only finding on
    // that line). dir mode must run E01 over the conditional Match body.
    //
    // (Today dir mode drops the conditional Match body -> no E01 -> RED.)
    let body = clean_plus_conditional_match(
        "Include {DIR}\nMatch Address 192.168.1.0/24",
        "    TotallyBogusDirective foo\n",
    );
    let dir = etc_ssh_layout(&body, &[("50-noise.conf", "# no drop-in directives\n")]);
    let out = run_lint(dir.path(), &["--target", "rhel9", "--format", "json"]);
    let diags = diagnostics_json(&out);

    let e01: Vec<&serde_json::Value> = diags.iter().filter(|d| d["code"] == "sshd-E01").collect();
    assert_eq!(
        e01.len(),
        1,
        "dir mode must run E01 over a CONDITIONAL Match body: exactly one sshd-E01 \
         for the unknown directive; got diagnostics: {diags:?}"
    );
    let d = e01[0];
    assert!(
        d["message"]
            .as_str()
            .is_some_and(|m| m.contains("TotallyBogusDirective")),
        "the E01 message names the unknown directive; got: {d:?}"
    );
    let file = d["file"].as_str().expect("file is a string");
    assert!(
        file.ends_with("/sshd_config"),
        "the unknown directive lives in the base sshd_config; E01 anchors there; \
         got file = {file:?}"
    );
    assert_eq!(
        d["line"].as_u64(),
        Some(23),
        "E01 anchors to the real unknown-directive line inside the conditional \
         Match block (line 23 of the base); got: {d:?}"
    );
}

#[test]
fn dir_mode_w04_fires_inside_conditional_match_block() {
    // A conditional `Match` block body with a deprecated directive (`UseLogin no`,
    // version-uniform deprecated, verified single-file W04). dir mode must run W04
    // over the conditional Match body.
    //
    // (Today dir mode drops the conditional Match body -> no W04 -> RED.)
    let body = clean_plus_conditional_match(
        "Include {DIR}\nMatch Address 192.168.1.0/24",
        "    UseLogin no\n",
    );
    let dir = etc_ssh_layout(&body, &[("50-noise.conf", "# no drop-in directives\n")]);
    let out = run_lint(dir.path(), &["--target", "rhel9", "--format", "json"]);
    let diags = diagnostics_json(&out);

    let w04: Vec<&serde_json::Value> = diags.iter().filter(|d| d["code"] == "sshd-W04").collect();
    assert_eq!(
        w04.len(),
        1,
        "dir mode must run W04 over a CONDITIONAL Match body: exactly one sshd-W04 \
         for the deprecated directive; got diagnostics: {diags:?}"
    );
    let d = w04[0];
    assert!(
        d["message"]
            .as_str()
            .is_some_and(|m| m.to_ascii_lowercase().contains("uselogin")),
        "the W04 message names the deprecated directive; got: {d:?}"
    );
    let file = d["file"].as_str().expect("file is a string");
    assert!(
        file.ends_with("/sshd_config"),
        "the deprecated directive lives in the base sshd_config; W04 anchors there; \
         got file = {file:?}"
    );
    assert_eq!(
        d["line"].as_u64(),
        Some(23),
        "W04 anchors to the real `UseLogin` line inside the conditional Match block \
         (line 23 of the base); got: {d:?}"
    );
}

#[test]
fn dir_mode_e04_fires_inside_conditional_match_block() {
    // sshd-E04 (Match-illegal directive) is the SAME lost class: a strong global-only
    // directive (`Ciphers aes256-ctr` -- strong, so NO W03/W06) inside a conditional
    // `Match` block is silently ignored at runtime and fires exactly one sshd-E04 in
    // single-file mode (verified). dir mode must run E04 over the conditional Match
    // body and anchor to the real file + line.
    //
    // (Today dir mode drops the conditional Match body -> no E04 -> RED.)
    let body = clean_plus_conditional_match(
        "Include {DIR}\nMatch User someuser",
        "    Ciphers aes256-ctr\n",
    );
    let dir = etc_ssh_layout(&body, &[("50-noise.conf", "# no drop-in directives\n")]);
    let out = run_lint(dir.path(), &["--target", "rhel9", "--format", "json"]);
    let diags = diagnostics_json(&out);

    let e04: Vec<&serde_json::Value> = diags.iter().filter(|d| d["code"] == "sshd-E04").collect();
    assert_eq!(
        e04.len(),
        1,
        "dir mode must run E04 over a CONDITIONAL Match body: exactly one sshd-E04 \
         for the Match-illegal Ciphers directive; got diagnostics: {diags:?}"
    );
    let d = e04[0];
    assert!(
        d["message"].as_str().is_some_and(|m| m.contains("Ciphers")),
        "the E04 message names the Match-illegal directive; got: {d:?}"
    );
    let file = d["file"].as_str().expect("file is a string");
    assert!(
        file.ends_with("/sshd_config"),
        "the Match-illegal directive lives in the base sshd_config; E04 anchors \
         there; got file = {file:?}"
    );
    assert_eq!(
        d["line"].as_u64(),
        Some(23),
        "E04 anchors to the real `Ciphers` line inside the conditional Match block \
         (line 23 of the base); got: {d:?}"
    );
}

#[test]
fn dir_mode_w05_fires_inside_conditional_match_block() {
    // sshd-W05 (permissive Match override) is the SAME lost class: a Match-permitted
    // STIG directive set to a permissive value (`PermitRootLogin yes`) inside a
    // conditional `Match User` block fires exactly one sshd-W05 in single-file mode
    // (verified -- it is Match-permitted, so E04 does NOT co-fire). dir mode must run
    // W05 over the conditional Match body and anchor to the real file + line.
    //
    // (Today dir mode drops the conditional Match body -> no W05 -> RED.)
    let body = clean_plus_conditional_match(
        "Include {DIR}\nMatch User someuser",
        "    PermitRootLogin yes\n",
    );
    let dir = etc_ssh_layout(&body, &[("50-noise.conf", "# no drop-in directives\n")]);
    let out = run_lint(dir.path(), &["--target", "rhel9", "--format", "json"]);
    let diags = diagnostics_json(&out);

    let w05: Vec<&serde_json::Value> = diags.iter().filter(|d| d["code"] == "sshd-W05").collect();
    assert_eq!(
        w05.len(),
        1,
        "dir mode must run W05 over a CONDITIONAL Match body: exactly one sshd-W05 \
         for the permissive Match override; got diagnostics: {diags:?}"
    );
    let d = w05[0];
    assert!(
        d["message"]
            .as_str()
            .is_some_and(|m| m.contains("PermitRootLogin")),
        "the W05 message names the overridden STIG directive; got: {d:?}"
    );
    let file = d["file"].as_str().expect("file is a string");
    assert!(
        file.ends_with("/sshd_config"),
        "the permissive Match override lives in the base sshd_config; W05 anchors \
         there; got file = {file:?}"
    );
    assert_eq!(
        d["line"].as_u64(),
        Some(23),
        "W05 anchors to the real `PermitRootLogin yes` line inside the conditional \
         Match block (line 23 of the base); got: {d:?}"
    );
}

#[test]
fn dir_mode_match_block_finding_in_dropin_anchors_to_dropin() {
    // PROVENANCE through the Match path: the conditional `Match` block + its weak
    // directive live in a `*.conf` DROP-IN (not the base), Included from the base.
    // The dir-mode W03 finding must anchor to the DROP-IN file -- the file the
    // operator must edit -- not the base. The drop-in's two lines are
    //   1: Match Address 192.168.1.0/24
    //   2:     Ciphers aes256-cbc       <- the W03 anchor (verified single-file: line 2)
    //
    // (Today dir mode drops the conditional Match body entirely -> no W03 at all ->
    // RED on both the code-presence and the drop-in-anchoring assertions.)
    let dir = etc_ssh_layout(
        &format!("{CLEAN_CONFIG}Include {{DIR}}\n"),
        &[(
            "50-match.conf",
            "Match Address 192.168.1.0/24\n    Ciphers aes256-cbc\n",
        )],
    );
    let out = run_lint(dir.path(), &["--target", "rhel9", "--format", "json"]);
    let diags = diagnostics_json(&out);

    let w03: Vec<&serde_json::Value> = diags.iter().filter(|d| d["code"] == "sshd-W03").collect();
    assert_eq!(
        w03.len(),
        1,
        "dir mode must run W03 over a conditional Match body that lives in a drop-in: \
         exactly one sshd-W03; got diagnostics: {diags:?}"
    );
    let d = w03[0];
    let file = d["file"].as_str().expect("file is a string");
    assert!(
        file.ends_with("50-match.conf"),
        "the weak cipher physically lives in the drop-in's conditional Match block, \
         so W03 must anchor to the drop-in (50-match.conf), not the base sshd_config; \
         got file = {file:?}"
    );
    assert!(
        !file.ends_with("/sshd_config"),
        "W03 must NOT anchor to the base sshd_config; got file = {file:?}"
    );
    assert_eq!(
        d["line"].as_u64(),
        Some(2),
        "W03 anchors to the `Ciphers` line WITHIN the drop-in (line 2: Match header \
         is line 1), proving line provenance survives the Match-path remap; got: {d:?}"
    );
    assert_eq!(
        d["source_id"].as_str(),
        Some(file),
        "source_id is remapped to the same winning drop-in as file; got: {d:?}"
    );
}

// --- NEGATIVE guards: effective-value passes (W01/W02) ignore conditional Match ---

#[test]
fn dir_mode_w01_not_satisfied_by_conditional_match_value() {
    // EFFECTIVE-VALUE exclusion (W01). A STIG-required global directive (Banner) is
    // ABSENT from the global/effective config but PRESENT only inside a conditional
    // `Match` block (in a drop-in). A conditional Match value is per-connection, NOT
    // the global daemon baseline, so it must NOT satisfy the W01 global requirement:
    // sshd-W01 must STILL fire for `banner`. (Verified TODAY: W01 fires for banner
    // here; this guards that the fix re-exposes conditional Match bodies as a `Match`
    // block rather than folding them into the synthetic GLOBAL view -- folding would
    // wrongly clear this W01.)
    let base_without_banner = CLEAN_CONFIG.replace("Banner /etc/issue.net\n", "");
    let dir = etc_ssh_layout(
        &format!("{base_without_banner}Include {{DIR}}\n"),
        &[(
            "50-match.conf",
            "Match Address 192.168.1.0/24\n    Banner /etc/issue.net\n",
        )],
    );
    let out = run_lint(dir.path(), &["--target", "rhel9"]);
    let stdout = String::from_utf8(out.stdout.clone()).expect("utf8");
    assert!(
        stdout.contains("sshd-W01"),
        "Banner is set ONLY inside a conditional Match block (not the global \
         baseline), so W01 must STILL fire for the missing global Banner; stdout: \
         {stdout}"
    );
    assert!(
        stdout.contains("banner"),
        "the W01 finding must name the missing global directive (banner); stdout: \
         {stdout}"
    );
}

#[test]
fn dir_mode_w02_not_triggered_by_conditional_match_value() {
    // EFFECTIVE-VALUE exclusion (W02). The global/effective config is STIG-compliant,
    // but a conditional `Match User` block sets PermitRootLogin to the weak value
    // `yes`. A conditional Match value is per-connection, NOT the daemon baseline, so
    // it must NOT trigger sshd-W02 at the global baseline. (Verified TODAY: no W02
    // for PermitRootLogin here; this guards that the fix does not fold conditional
    // Match values into the synthetic GLOBAL W02 view.)
    let dir = etc_ssh_layout(
        &format!("{CLEAN_CONFIG}Include {{DIR}}\n"),
        &[(
            "50-match.conf",
            "Match User someuser\n    PermitRootLogin yes\n",
        )],
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
        "PermitRootLogin yes is set ONLY inside a conditional Match block (not the \
         global baseline), so W02 must NOT fire for it at the global baseline; got: \
         {diags:?}"
    );
}

#[test]
fn dir_mode_w03_silent_on_overridden_dead_global_value() {
    // OVERRIDDEN-GLOBAL exclusion (W03 effective-value for a GLOBAL directive). A
    // GLOBAL weak cipher is OVERRIDDEN to a strong effective value by a
    // higher-precedence drop-in (the drop-in is Included FIRST, so first-value-wins
    // makes its strong `aes256-ctr` the effective Ciphers value; the base's weak
    // `aes256-cbc` is dead). For a GLOBAL directive only the effective value matters,
    // so dir mode must NOT emit sshd-W03 for the dead weak global value. (Verified
    // TODAY: no W03 here. This pins that the conditional-Match fix does not regress
    // the merged GLOBAL pass into per-file noise on overridden global values.)
    let dir = etc_ssh_layout(
        &format!("Include {{DIR}}\n{CLEAN_CONFIG}Ciphers aes256-cbc\n"),
        &[("10-strong.conf", "Ciphers aes256-ctr\n")],
    );
    let out = run_lint(dir.path(), &["--target", "rhel9", "--format", "json"]);
    let diags = diagnostics_json(&out);
    let w03: Vec<&serde_json::Value> = diags.iter().filter(|d| d["code"] == "sshd-W03").collect();
    assert!(
        w03.is_empty(),
        "the strong drop-in cipher wins (first-value-wins) so the weak global value \
         is dead; for a GLOBAL directive only the effective value matters -> W03 must \
         NOT fire; got: {diags:?}"
    );
}

// ===========================================================================
// #324 round-2 review findings (TEST-AUTHOR strengthening).
//
// FINDING 1 (real bug): `collect_conditional_matches` (drop_in.rs) collects a
// conditional `Match` block TWICE when one drop-in is reachable via two Include
// edges (overlapping globs, glob + explicit, or a diamond), because the
// recursive Include walk has a per-ANCESTRY cycle guard but NO across-walk
// `seen`-file dedup -- so the same physical drop-in is visited once per edge,
// and its conditional `Match` body is appended to `matches` each time. The
// merged single-file suite then runs the as-written passes over the DUPLICATED
// block and emits DUPLICATE diagnostics. Single-file mode reports each physical
// Match-body finding ONCE, and F02's own stream walk dedups via a `seen` set,
// so the duplicate is unique to the conditional-Match collection path.
//
// FINDING 2 (mutation survivors): `follow_includes`'s depth cap
// (`if chain.len() > SERVCONF_MAX_DEPTH { continue; }`) had surviving `> -> ==`
// and `> -> >=` mutants -- no test exercised the Include depth cap on the
// conditional-Match collection path. The cap must match `build_stream`'s
// behavior (the merged F02 view and the conditional-Match view must resolve to
// the SAME reachable depth; an inconsistency would be a real bug). Confirmed by
// running both paths over the same chain at depths cap and cap+1: both fire at
// exactly SERVCONF_MAX_DEPTH hops and both stop one hop deeper.
// ===========================================================================

/// Build a diamond/double-Include layout under a fresh tempdir: a STIG-complete
/// base whose single `Include` line carries TWO OVERLAPPING globs that both
/// resolve to the same drop-in `50-m.conf`, whose body is `dropin_body`. Returns
/// the tempdir handle (kept alive by the caller).
///
/// `etc_ssh_layout` cannot express this (it resolves a single `{DIR}` glob), so
/// this helper writes the two-glob Include line explicitly: `*.conf` and `5*.conf`
/// both match `50-m.conf`, so the recursive Include walk reaches it via two edges.
fn etc_ssh_layout_double_include(base_prefix: &str, dropin_body: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    let dropin_dir = dir.path().join("sshd_config.d");
    std::fs::create_dir_all(&dropin_dir).expect("mkdir sshd_config.d");
    // Two overlapping globs in ONE Include line: `*.conf` and `5*.conf` both match
    // `50-m.conf`, so the drop-in is reachable via two Include edges (the diamond).
    let glob_all = dropin_dir.join("*.conf").display().to_string();
    let glob_five = dropin_dir.join("5*.conf").display().to_string();
    let main = format!("{base_prefix}Include {glob_all} {glob_five}\n");
    std::fs::write(dir.path().join("sshd_config"), &main).expect("write main");
    std::fs::write(dropin_dir.join("50-m.conf"), dropin_body).expect("write drop-in");
    dir
}

#[test]
fn dir_mode_diamond_include_match_finding_reported_once() {
    // FINDING 1 (RED today, count == 2): a single drop-in `50-m.conf` reachable
    // via TWO overlapping Include globs (`*.conf` and `5*.conf`, both matching it)
    // holds a conditional `Match User alice` block with a weak cipher
    // (`Ciphers aes256-cbc`). The merged single-file W03 pass must report that one
    // physical Match-body finding EXACTLY ONCE -- single-file mode reports it once,
    // so dir mode must match (no per-edge duplication).
    //
    // Today `collect_conditional_matches` visits `50-m.conf` once per Include edge
    // (no across-walk file dedup), so the conditional `Match` block is collected
    // TWICE and TWO identical sshd-W03 diagnostics are emitted at `50-m.conf:2`.
    // This test asserts count == 1, so it is RED (count == 2) until the dedup lands.
    let dir =
        etc_ssh_layout_double_include(CLEAN_CONFIG, "Match User alice\n    Ciphers aes256-cbc\n");
    let out = run_lint(dir.path(), &["--target", "rhel9", "--format", "json"]);
    let diags = diagnostics_json(&out);

    let w03: Vec<&serde_json::Value> = diags.iter().filter(|d| d["code"] == "sshd-W03").collect();
    assert_eq!(
        w03.len(),
        1,
        "a drop-in reached via two overlapping Include globs holds ONE conditional \
         Match weak-cipher finding; the merged W03 pass must report it EXACTLY ONCE \
         (single-file parity), not once per Include edge; got diagnostics: {diags:?}"
    );
    let d = w03[0];
    // The single finding anchors to the real drop-in + the real `Ciphers` line
    // (line 2: `Match User alice` is line 1, `    Ciphers aes256-cbc` is line 2).
    let file = d["file"].as_str().expect("file is a string");
    assert!(
        file.ends_with("50-m.conf"),
        "the W03 anchors to the drop-in holding the conditional Match block; \
         got file = {file:?}"
    );
    assert_eq!(
        d["line"].as_u64(),
        Some(2),
        "the W03 anchors to the real `Ciphers` line inside the conditional Match \
         block (line 2: Match header is line 1, Ciphers is line 2); got: {d:?}"
    );
    assert!(
        d["message"]
            .as_str()
            .is_some_and(|m| m.contains("aes256-cbc")),
        "the W03 names the weak cipher; got: {d:?}"
    );
}

/// `SERVCONF_MAX_DEPTH` mirrored from `rulesteward_sshd::lints::drop_in` (which
/// keeps the constant private). OpenSSH `servconf.c` caps Include recursion at
/// 16; this CLI-side mirror lets the depth-cap tests place a finding at exactly
/// the cap and one hop beyond without reaching into the crate internals. If the
/// crate constant ever changes, these tests drift and the crate-level unit tests
/// (`nested_include_at_max_depth_fires_f02` /
/// `nested_include_one_past_max_depth_does_not_fire`) catch it; this mirror is a
/// documented assumption, asserted indirectly by the crate parity above.
const SERVCONF_MAX_DEPTH_MIRROR: usize = 16;

/// Build a straight nested-`Include` chain of `hops` files under a fresh tempdir,
/// where the chain is followed on the CONDITIONAL-`Match` collection path (the
/// `collect_conditional_matches` / `follow_includes` walk), and run the dir-mode
/// lint over it. Layout:
///
///   `sshd_config`        -- STIG-complete base + `Include <inc-1.conf>`
///   `inc-1.conf`         -- `Include <inc-2.conf>`
///   ...
///   `inc-{hops-1}.conf`  -- `Include <inc-{hops}.conf>`
///   `inc-{hops}.conf`    -- a conditional `Match User alice` block whose body is
///                           `    Ciphers aes256-cbc` (the W03 target)
///
/// so the conditional-Match finding sits exactly `hops` Include hops below the
/// base. Each `Include` uses an ABSOLUTE path (one edge per level), so the chain
/// depth is deterministic. The base is the STIG-complete `CLEAN_CONFIG` so W01/W02
/// stay quiet and the only finding is the deep W03. Returns the tempdir handle.
fn conditional_match_chain(hops: usize) -> tempfile::TempDir {
    assert!(hops >= 1, "a chain needs at least one hop");
    let dir = tempfile::tempdir().expect("tempdir");
    let inc_path = |i: usize| dir.path().join(format!("inc-{i}.conf"));

    // Base: STIG-complete, then Include the first chain file (absolute path).
    let main = format!("{CLEAN_CONFIG}Include {}\n", inc_path(1).display());
    std::fs::write(dir.path().join("sshd_config"), &main).expect("write main");

    // Intermediate files 1..hops-1 each Include the next.
    for i in 1..hops {
        std::fs::write(
            inc_path(i),
            format!("Include {}\n", inc_path(i + 1).display()),
        )
        .unwrap_or_else(|e| panic!("write inc-{i}.conf: {e}"));
    }
    // Deepest file: a conditional Match block with a weak cipher (the W03 target,
    // collected via the conditional-Match path -> exercises `follow_includes`).
    std::fs::write(inc_path(hops), "Match User alice\n    Ciphers aes256-cbc\n")
        .unwrap_or_else(|e| panic!("write inc-{hops}.conf: {e}"));
    dir
}

#[test]
fn dir_mode_conditional_match_at_max_depth_fires_w03() {
    // FINDING 2, lower edge (kills `> -> >=` and `> -> ==` at follow_includes).
    //
    // A chain of EXACTLY SERVCONF_MAX_DEPTH Include hops places the conditional
    // `Match` weak cipher at the deepest level the resolver is still allowed to
    // follow (the include reached at `chain.len() == cap` is followed because
    // `cap > cap` is false). The correct `>` impl reaches the deepest file's
    // conditional Match body -> exactly one sshd-W03 anchored there.
    //
    // A `>=`/`==` mutant stops one hop short, never reads the deepest file, and
    // emits NO W03 -> count == 0 -> this assertion FAILS for the mutant. (Verified
    // empirically: hops==16 -> W03 count 1 under the correct impl.) The chain is on
    // the CONDITIONAL-Match path, so it exercises `follow_includes` (drop_in.rs),
    // not `splice_effective` -- the function the survivors live in.
    let dir = conditional_match_chain(SERVCONF_MAX_DEPTH_MIRROR);
    let out = run_lint(dir.path(), &["--target", "rhel9", "--format", "json"]);
    let diags = diagnostics_json(&out);

    let w03: Vec<&serde_json::Value> = diags.iter().filter(|d| d["code"] == "sshd-W03").collect();
    assert_eq!(
        w03.len(),
        1,
        "a conditional-Match weak cipher at exactly SERVCONF_MAX_DEPTH \
         ({SERVCONF_MAX_DEPTH_MIRROR}) Include hops is reached on the \
         conditional-Match path -> exactly one sshd-W03; got diagnostics: {diags:?}"
    );
    let d = w03[0];
    let deepest = format!("inc-{SERVCONF_MAX_DEPTH_MIRROR}.conf");
    let file = d["file"].as_str().expect("file is a string");
    assert!(
        file.ends_with(&deepest),
        "the W03 anchors to the deepest file ({deepest}); got file = {file:?}"
    );
    assert!(
        d["message"]
            .as_str()
            .is_some_and(|m| m.contains("aes256-cbc")),
        "the W03 names the weak cipher; got: {d:?}"
    );
}

#[test]
fn dir_mode_conditional_match_one_past_max_depth_does_not_fire_w03() {
    // FINDING 2, upper edge: a conditional `Match` finding one Include hop BEYOND
    // SERVCONF_MAX_DEPTH is NOT reached (the include at `chain.len() == cap + 1` is
    // skipped because `cap + 1 > cap`), so the deepest file is never collected and
    // no W03 fires. Pins the cap so a future drift that over-expands by one level
    // (a `> -> >=`-in-the-other-direction style change) is caught, and -- together
    // with the at-max-depth test -- straddles the exact boundary so `>=` (which
    // would also cut at the cap) cannot survive. (Verified empirically: hops==17 ->
    // W03 count 0.)
    let hops = SERVCONF_MAX_DEPTH_MIRROR + 1;
    let dir = conditional_match_chain(hops);
    let out = run_lint(dir.path(), &["--target", "rhel9", "--format", "json"]);
    let diags = diagnostics_json(&out);
    let w03: Vec<&serde_json::Value> = diags.iter().filter(|d| d["code"] == "sshd-W03").collect();
    assert!(
        w03.is_empty(),
        "a conditional-Match weak cipher one hop past SERVCONF_MAX_DEPTH ({hops}) is \
         beyond the cap and must NOT be reached -> no sshd-W03; got: {diags:?}"
    );
}
