//! End-to-end pins for #561: `--format json` must not be silently ignored on
//! a pre-parse PATH failure (a missing lint target) for the four backends
//! that early-return before ever calling the shared JSON renderer:
//! sysctld/sshd/auditd/sudoers.
//!
//! # Ground truth: the fapolicyd model
//!
//! Confirmed live against main `142282b` (2026-07-23):
//! ```text
//! $ rulesteward fapolicyd lint --file /nonexistent/9i/missing.rules --format json
//! error: linting /nonexistent/9i/missing.rules: No such file or directory (os error 2)
//! {
//!   "schemaVersion": 1,
//!   "kind": "lint",
//!   "diagnostics": []
//! }
//! $ echo $?
//! 3
//! ```
//! fapolicyd prints the plain-text error to stderr AND STILL emits a valid
//! JSON envelope to stdout, because `commands/fapolicyd/lint.rs`'s per-file
//! read loop never early-returns on an IO error -- it sets a `tool_err` flag
//! and falls through to the shared `output::render` call regardless. The
//! four backends below currently (bug #561) `eprintln!` + `return
//! EXIT_TOOL_FAILURE` BEFORE ever calling `output::emit_lint`, so stdout is
//! empty under `--format json` on a missing path (confirmed live, same
//! date): `sshd lint`, `sysctl lint`, and `sudoers lint` each print only to
//! stderr with empty stdout; `serde_json::from_str("")` fails to parse.
//!
//! The fix mirrors the fapolicyd shape exactly: each backend's OWN envelope
//! `kind` (`sshd-lint` / `sysctl-lint` / `sudoers-lint` / `auditd-lint`,
//! `schemaVersion` 1 -- see `output/json.rs`'s known-kind registry) with an
//! EMPTY `diagnostics` array (no file was ever read, so there is nothing to
//! report -- matching fapolicyd's own `[]` on this exact path, not a
//! synthesized path-error diagnostic).
//!
//! Human format is UNCHANGED by this fix and is NOT re-pinned here: each
//! backend's PRE-EXISTING `missing_path_exits_tool_failure` (sshd.rs,
//! sysctl.rs, sudoers.rs) / `lint_missing_target_exits_tool_failure`
//! (auditd.rs) unit test already covers the human-format exit-3 behavior in
//! its own `commands::<backend>` module and must stay green through this fix
//! -- adding a duplicate e2e assertion here would just be a second copy of an
//! already-passing (not RED) pin.
//!
//! # Extension (session 9j lane 3, #583 half B / #561 follow-up, 2026-07-24)
//!
//! The #561 fix above landed for exactly FOUR backends: sshd/sysctl/sudoers/
//! auditd. Two more gaps in the SAME contract were found and are closed here:
//!
//! - `selinux lint`: `commands/selinux/lint.rs`'s path-error arm does
//!   `eprintln!(...); return EXIT_TOOL_FAILURE;` with NO envelope call at
//!   all (not even a private `emit_path_error_envelope` of its own) - so
//!   `--format json` on a bad path emits ZERO bytes of stdout (confirmed
//!   live against the real binary). Unlike the four backends above, selinux
//!   never had this fixed; it is not a "fifth backend that already works".
//! - `fapolicyd lint <missing-dir>` (the POSITIONAL directory-scan mode,
//!   distinct from `--file <missing-file>` single-file mode): `resolve_targets`
//!   early-returns `Err("<dir>: not a directory")` BEFORE `output::emit_lint`
//!   is ever reached, so this ALSO emits zero bytes of stdout under
//!   `--format json` (confirmed live) - even though `--file` mode already
//!   works today (its per-file-tolerant loop always falls through to the
//!   shared render call regardless of read errors, as the fapolicyd model
//!   above describes; that path is UNCHANGED and not re-pinned here since it
//!   already passes). Per the operator ruling: pin the OBSERVABLE contract
//!   (bytes on stdout, exit code, envelope shape) and let the implementer
//!   choose the fix shape, since fapolicyd's per-file-tolerant architecture
//!   differs from every other backend's fail-fast one.
//!
//! `fapolicyd lint`'s envelope `kind` is `"lint"`, NOT `"fapolicyd-lint"` -
//! this is an EXISTING, RULED-KEPT inconsistency (renaming it would be a
//! breaking JSON-schema change belonging to a schemaVersion bump, not this
//! hardening wave), so `fapolicyd_lint_missing_dir_emits_json_envelope` below
//! pins `"lint"` deliberately, not as an oversight.

use std::time::Duration;

use assert_cmd::Command;

fn bin() -> Command {
    Command::cargo_bin("rulesteward").expect("binary built")
}

/// Run `<subcommand> lint <missing-path> --format json` and return the raw
/// output. Bounded by a generous timeout so a regression that reintroduces a
/// hang (see `path_error_fifo.rs`) fails fast instead of wedging the suite --
/// a plain missing path (not a FIFO) never hangs today, so this bound is
/// pure defense in depth.
fn run_missing_path_json(subcommand: &str, missing_path: &str) -> std::process::Output {
    bin()
        .args([subcommand, "lint", missing_path, "--format", "json"])
        .timeout(Duration::from_secs(10))
        .output()
        .unwrap_or_else(|e| panic!("`{subcommand} lint --format json` did not complete: {e}"))
}

/// Assert the #561 JSON-envelope-on-path-error shape: exit `EXIT_TOOL_FAILURE`
/// (3), stdout parses as JSON, carries the given `kind` + `schemaVersion: 1`,
/// an EMPTY `diagnostics` array (grounded: the fapolicyd model emits `[]`
/// here too), and a trailing newline (shell-pipeline safe, matching every
/// other JSON emitter in this codebase, e.g.
/// `json_format_emits_the_sysctl_lint_envelope` in `e2e_sysctl_lint.rs`).
fn assert_path_error_envelope(out: &std::process::Output, expected_kind: &str) {
    assert_eq!(
        out.status.code(),
        Some(3),
        "a path error must exit EXIT_TOOL_FAILURE (3) under --format json \
         too; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout.clone()).expect("utf8 stdout");
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!(
            "--format json on a path error must still emit a JSON envelope \
             on stdout (bug #561: today stdout is empty here, the error only \
             goes to stderr as plain text); parse error: {e}; stdout was: \
             {stdout:?}; stderr was: {}",
            String::from_utf8_lossy(&out.stderr)
        )
    });
    assert_eq!(v["kind"], expected_kind, "envelope kind, full body: {v}");
    assert_eq!(
        v["schemaVersion"], 1,
        "envelope schemaVersion, full body: {v}"
    );
    assert_eq!(
        v["diagnostics"],
        serde_json::json!([]),
        "no file was ever read, so diagnostics must be an EMPTY array \
         (matching the fapolicyd model's own [] on this path), not omitted \
         or populated with a synthetic finding; full body: {v}"
    );
    assert!(
        stdout.ends_with('\n'),
        "JSON output must end with a newline; got: {stdout:?}"
    );
}

#[test]
fn sshd_lint_missing_path_emits_json_envelope() {
    let out = run_missing_path_json("sshd", "/nonexistent/561/sshd_config");
    assert_path_error_envelope(&out, "sshd-lint");
}

#[test]
fn sysctl_lint_missing_path_emits_json_envelope() {
    let out = run_missing_path_json("sysctl", "/nonexistent/561/sysctl.conf");
    assert_path_error_envelope(&out, "sysctl-lint");
}

#[test]
fn sudoers_lint_missing_path_emits_json_envelope() {
    let out = run_missing_path_json("sudoers", "/nonexistent/561/sudoers");
    assert_path_error_envelope(&out, "sudoers-lint");
}

#[test]
fn auditd_lint_missing_path_emits_json_envelope() {
    let out = run_missing_path_json("auditd", "/nonexistent/561/audit.rules");
    assert_path_error_envelope(&out, "auditd-lint");
}

/// #583 half B: `selinux lint` had NO path-error envelope at all (not a
/// private helper like the four above, not the fapolicyd fallthrough model
/// below) - `--format json` on a bad path is zero bytes today.
#[test]
fn selinux_lint_missing_path_emits_json_envelope() {
    let out = run_missing_path_json("selinux", "/nonexistent/583/selinux-config");
    assert_path_error_envelope(&out, "selinux-lint");
}

/// #583 half B (operator-ruled scope expansion): `fapolicyd lint`'s
/// POSITIONAL directory-scan mode (no `--file`) hits `resolve_targets`'
/// `Err("<dir>: not a directory")` early-return before `output::emit_lint`
/// is ever reached, so this is ALSO zero bytes today - distinct from
/// `--file <missing-file>` single-file mode, which already emits the
/// envelope (per this file's "ground truth: the fapolicyd model" section
/// above) because its per-file-tolerant loop always falls through to the
/// shared render call. `expected_kind` is deliberately `"lint"` (not
/// `"fapolicyd-lint"`) - the existing, ruled-kept inconsistency, not a typo.
#[test]
fn fapolicyd_lint_missing_dir_emits_json_envelope() {
    let out = run_missing_path_json("fapolicyd", "/nonexistent/583/rules.d");
    assert_path_error_envelope(&out, "lint");
}
