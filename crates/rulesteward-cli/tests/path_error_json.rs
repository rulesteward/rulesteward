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
//! defect #561 named (confirmed live, same date) was the opposite shape: a
//! backend that does `eprintln!` + `return EXIT_TOOL_FAILURE` BEFORE ever
//! calling `output::emit_lint` leaves stdout empty under `--format json` on a
//! missing path, so `serde_json::from_str("")` fails to parse.
//!
//! Each of the four backends below mirrors the fapolicyd shape exactly: its
//! OWN envelope `kind` (`sshd-lint` / `sysctl-lint` / `sudoers-lint` / `auditd-lint`,
//! `schemaVersion` 1 -- see `output/json.rs`'s known-kind registry) with an
//! EMPTY `diagnostics` array (no file was ever read, so there is nothing to
//! report -- matching fapolicyd's own `[]` on this exact path, not a
//! synthesized path-error diagnostic).
//!
//! Human format is NOT re-pinned here: each backend's
//! `missing_path_exits_tool_failure` (sshd.rs, sysctl.rs, sudoers.rs) /
//! `lint_missing_target_exits_tool_failure` (auditd.rs) unit test already
//! covers the human-format exit-3 behavior in its own `commands::<backend>`
//! module -- a duplicate e2e assertion here would just be a second copy of it.
//!
//! # Extension (#583 half B / #561 follow-up)
//!
//! Beyond those four backends, two further call sites are held to the SAME
//! contract here:
//!
//! - `selinux lint`: its path-error arm (`commands/selinux/lint.rs`) must
//!   emit the envelope. An arm that did `eprintln!(...); return
//!   EXIT_TOOL_FAILURE;` with NO envelope call at all would make
//!   `--format json` on a bad path emit ZERO bytes of stdout.
//! - `fapolicyd lint <missing-dir>` (the POSITIONAL directory-scan mode,
//!   distinct from `--file <missing-file>` single-file mode): `resolve_targets`
//!   early-returns `Err("<dir>: not a directory")` before `output::render`
//!   (fapolicyd is NOT an `emit_lint` caller - see `output/mod.rs`'s own
//!   comment - it calls the three-variant `render` directly) is reached, so
//!   this arm needs its own envelope emission to avoid zero bytes of stdout
//!   under `--format json`. `--file` mode is a separate path (its
//!   per-file-tolerant loop always falls through to the shared render call
//!   regardless of read errors, as the fapolicyd model above describes) and is
//!   not re-pinned here.
//!
//!   RULING: pin the OBSERVABLE contract (bytes on stdout, exit code,
//!   envelope shape), not the fix shape, since fapolicyd's per-file-tolerant
//!   architecture differs from every other backend's fail-fast one.
//!   Rationale + evidence: #583
//!
//! `fapolicyd lint`'s envelope `kind` is `"lint"`, NOT `"fapolicyd-lint"` -
//! this is an EXISTING, RULED-KEPT inconsistency (renaming it would be a
//! breaking JSON-schema change belonging to a schemaVersion bump), so
//! `fapolicyd_lint_missing_dir_emits_json_envelope` below
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

/// #583 half B: `selinux lint`'s path-error envelope. Without one (it has no
/// private helper like the four above, and does not use the fapolicyd
/// fallthrough model below) `--format json` on a bad path is zero bytes.
#[test]
fn selinux_lint_missing_path_emits_json_envelope() {
    let out = run_missing_path_json("selinux", "/nonexistent/583/selinux-config");
    assert_path_error_envelope(&out, "selinux-lint");
}

/// #583 half B: `fapolicyd lint`'s
/// POSITIONAL directory-scan mode (no `--file`) hits `resolve_targets`'
/// `Err("<dir>: not a directory")` early-return before `output::render`
/// (fapolicyd is NOT an `emit_lint` caller) is reached, so without its own
/// envelope emission this arm is zero bytes - distinct from
/// `--file <missing-file>` single-file mode, which emits the
/// envelope (per this file's "ground truth: the fapolicyd model" section
/// above) because its per-file-tolerant loop always falls through to the
/// shared render call. `expected_kind` is deliberately `"lint"` (not
/// `"fapolicyd-lint"`) - the existing, ruled-kept inconsistency, not a typo.
#[test]
fn fapolicyd_lint_missing_dir_emits_json_envelope() {
    let out = run_missing_path_json("fapolicyd", "/nonexistent/583/rules.d");
    assert_path_error_envelope(&out, "lint");
}

// ---------------------------------------------------------------------------
// `open_trustdb_arg`
// (`commands/fapolicyd/lint.rs:84`) runs BEFORE `resolve_targets_or_fail`
// (`:90`), so a bad `--against-trustdb` on an otherwise-good lint target must
// ALSO emit the envelope -- the same #561 gap
// `fapolicyd_lint_missing_dir_emits_json_envelope` above pins for the
// target-path case.
// ---------------------------------------------------------------------------

/// Like `assert_path_error_envelope` above, but for an exit code OTHER than
/// `EXIT_TOOL_FAILURE` (3) -- specifically the `--against-trustdb`
/// LMDB-open-failure arm, which returns `EXIT_LMDB_ERROR` (4). A separate
/// sibling rather than a parameter on the existing helper: that helper's
/// signature is frozen and shared by every test above.
fn assert_path_error_envelope_with_code(
    out: &std::process::Output,
    expected_kind: &str,
    expected_code: i32,
) {
    assert_eq!(
        out.status.code(),
        Some(expected_code),
        "expected exit {expected_code}; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout.clone()).expect("utf8 stdout");
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!(
            "--format json on a path error must still emit a JSON envelope on \
             stdout; parse error: {e}; stdout was: {stdout:?}; stderr was: {}",
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
        "diagnostics must be an EMPTY array; full body: {v}"
    );
    assert!(
        stdout.ends_with('\n'),
        "JSON output must end with a newline; got: {stdout:?}"
    );
}

/// `--against-trustdb <not-a-directory>` on an otherwise-good lint target
/// must emit the same envelope shape as a bad target path -- exit
/// `EXIT_TOOL_FAILURE` (3), `kind: "lint"` (fapolicyd's existing, ruled-kept
/// inconsistency, not a typo), empty `diagnostics`.
#[test]
fn fapolicyd_lint_against_trustdb_not_a_directory_emits_json_envelope() {
    let rules_d = tempfile::tempdir().expect("tempdir for a valid rules.d");
    std::fs::write(rules_d.path().join("10-x.rules"), "allow uid=0 : all\n")
        .expect("write a clean rules file");

    let out = bin()
        .args(["fapolicyd", "lint"])
        .arg(rules_d.path())
        .arg("--against-trustdb")
        .arg("/nonexistent/583/trustdb")
        .args(["--format", "json"])
        .timeout(Duration::from_secs(10))
        .output()
        .unwrap_or_else(|e| panic!("`fapolicyd lint --against-trustdb` did not complete: {e}"));
    assert_path_error_envelope(&out, "lint");
}

/// Combination case: BOTH the positional rules.d target AND
/// `--against-trustdb` are bad. `open_trustdb_arg` runs FIRST
/// (`commands/fapolicyd/lint.rs:84`, before `resolve_targets_or_fail` at
/// `:90`), so its own envelope call fires and `resolve_targets_or_fail`'s is
/// never reached -- proving the fix does not depend on the target path also
/// being valid, and that stacking two bad inputs never silently drops back to
/// zero stdout bytes.
#[test]
fn fapolicyd_lint_missing_dir_and_against_trustdb_not_a_directory_still_emits_json_envelope() {
    let out = bin()
        .args(["fapolicyd", "lint", "/nonexistent/583/rules.d"])
        .arg("--against-trustdb")
        .arg("/nonexistent/583/trustdb")
        .args(["--format", "json"])
        .timeout(Duration::from_secs(10))
        .output()
        .unwrap_or_else(|e| panic!("`fapolicyd lint` (double-bad-input) did not complete: {e}"));
    assert_path_error_envelope(&out, "lint");
}

/// The LMDB-open-failure arm (a real directory, but not a valid LMDB
/// environment -- no `data.mdb`/`lock.mdb`) exits `EXIT_LMDB_ERROR` (4), NOT
/// `EXIT_TOOL_FAILURE` (3) like every other case in this file, but must ALSO
/// emit a non-empty envelope rather than reverting to zero stdout bytes.
#[test]
fn fapolicyd_lint_against_trustdb_invalid_lmdb_env_emits_json_envelope() {
    let rules_d = tempfile::tempdir().expect("tempdir for a valid rules.d");
    std::fs::write(rules_d.path().join("10-x.rules"), "allow uid=0 : all\n")
        .expect("write a clean rules file");
    let not_lmdb = tempfile::tempdir().expect("tempdir for the non-LMDB trust DB dir");

    let out = bin()
        .args(["fapolicyd", "lint"])
        .arg(rules_d.path())
        .arg("--against-trustdb")
        .arg(not_lmdb.path())
        .args(["--format", "json"])
        .timeout(Duration::from_secs(10))
        .output()
        .unwrap_or_else(|e| panic!("`fapolicyd lint --against-trustdb` did not complete: {e}"));
    // EXIT_LMDB_ERROR = 4 (crate::exit_code::EXIT_LMDB_ERROR).
    assert_path_error_envelope_with_code(&out, "lint", 4);
}
