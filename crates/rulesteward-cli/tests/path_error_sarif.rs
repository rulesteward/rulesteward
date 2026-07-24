//! End-to-end pins for the SARIF half of #561's path-error envelope contract
//! (#583 half B): `--format sarif` on a missing lint target must emit a
//! valid, non-empty SARIF 2.1.0 log, not silently drop to zero bytes.
//! `path_error_json.rs` is the JSON half of the same contract; this file
//! mirrors its subcommand list and missing-path convention.
//!
//! # Ground truth (confirmed live against the real binary, 2026-07-24)
//!
//! `output::emit_lint`'s `Sarif` arm (`output/mod.rs`) calls
//! `sarif::render(diags, None)` for every backend UNIFORMLY - `kind` is a
//! JSON-envelope-only concept the SARIF renderer never receives - so an
//! empty-diagnostics SARIF payload is BYTE-IDENTICAL across every backend
//! regardless of its `kind` string. Confirmed via `cmp` on five live
//! captures: `sshd lint <missing> --format sarif`, `sysctl lint <missing>
//! --format sarif`, `sudoers lint <missing> --format sarif`, `auditd lint
//! <missing> --format sarif`, and `fapolicyd lint --file <missing> --format
//! sarif` (the ALREADY-WORKING fapolicyd `--file` single-file mode) all
//! produced the exact same 349 bytes:
//! ```json
//! {
//!   "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
//!   "runs": [
//!     {
//!       "results": [],
//!       "tool": {
//!         "driver": {
//!           "informationUri": "https://github.com/rulesteward/rulesteward",
//!           "name": "rulesteward",
//!           "version": "0.7.0"
//!         }
//!       }
//!     }
//!   ],
//!   "version": "2.1.0"
//! }
//! ```
//! `selinux lint <missing> --format sarif` and `fapolicyd lint <missing-dir>`
//! (positional dir-scan mode, no `--file`) both produced ZERO bytes - the
//! SARIF counterpart of the exact same #561/#583 gap `path_error_json.rs`
//! pins for `--format json`. The `tool.driver.version` field is the crate's
//! own `env!("CARGO_PKG_VERSION")` (confirmed at `output/sarif.rs:368,373`),
//! so `expected_sarif_payload` below builds it the same way rather than
//! hardcoding `"0.7.0"` - a routine version bump must not spuriously break
//! this pin; only an actual SARIF-shape regression should.

use std::time::Duration;

use assert_cmd::Command;

fn bin() -> Command {
    Command::cargo_bin("rulesteward").expect("binary built")
}

/// The exact SARIF 2.1.0 log a path error must produce: empty `results`, the
/// `rulesteward` tool driver at the CURRENT crate version, `$schema` present,
/// trailing newline. `kind` never appears anywhere in this payload (see
/// module docs above), so ONE constant covers every backend.
fn expected_sarif_payload() -> String {
    format!(
        "{{\n  \"$schema\": \"https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json\",\n  \"runs\": [\n    {{\n      \"results\": [],\n      \"tool\": {{\n        \"driver\": {{\n          \"informationUri\": \"https://github.com/rulesteward/rulesteward\",\n          \"name\": \"rulesteward\",\n          \"version\": \"{}\"\n        }}\n      }}\n    }}\n  ],\n  \"version\": \"2.1.0\"\n}}\n",
        env!("CARGO_PKG_VERSION")
    )
}

/// Run `<args...> --format sarif`, bounded by a generous timeout (defense in
/// depth - a plain missing path never hangs today, mirroring
/// `path_error_json.rs`'s `run_missing_path_json`).
fn run_missing_path_sarif(args: &[&str]) -> std::process::Output {
    bin()
        .args(args)
        .args(["--format", "sarif"])
        .timeout(Duration::from_secs(10))
        .output()
        .unwrap_or_else(|e| panic!("`{args:?} --format sarif` did not complete: {e}"))
}

/// Assert `EXIT_TOOL_FAILURE` (3) and the byte-identical SARIF payload.
fn assert_byte_identical_sarif(out: &std::process::Output) {
    assert_eq!(
        out.status.code(),
        Some(3),
        "a path error must exit EXIT_TOOL_FAILURE (3) under --format sarif too; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout.clone()).expect("utf8 stdout");
    assert_eq!(
        stdout,
        expected_sarif_payload(),
        "the path-error SARIF payload must stay byte-identical across the \
         emit_path_error_envelope extraction (kind never appears in SARIF, \
         so every backend shares ONE expected payload); stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// ---------------------------------------------------------------------------
// GREEN today: the four backends #561 already fixed, plus fapolicyd's
// already-working `--file` mode. These are the safety net proving the
// shared-helper extraction does not perturb the SARIF branch either.
// ---------------------------------------------------------------------------

#[test]
fn sshd_lint_missing_path_sarif_is_byte_identical() {
    let out = run_missing_path_sarif(&["sshd", "lint", "/nonexistent/583/sshd_config"]);
    assert_byte_identical_sarif(&out);
}

#[test]
fn sysctl_lint_missing_path_sarif_is_byte_identical() {
    let out = run_missing_path_sarif(&["sysctl", "lint", "/nonexistent/583/99-x.conf"]);
    assert_byte_identical_sarif(&out);
}

#[test]
fn sudoers_lint_missing_path_sarif_is_byte_identical() {
    let out = run_missing_path_sarif(&["sudoers", "lint", "/nonexistent/583/sudoers"]);
    assert_byte_identical_sarif(&out);
}

#[test]
fn auditd_lint_missing_path_sarif_is_byte_identical() {
    let out = run_missing_path_sarif(&["auditd", "lint", "/nonexistent/583/audit.rules"]);
    assert_byte_identical_sarif(&out);
}

/// fapolicyd's ALREADY-WORKING `--file` single-file mode (distinct from the
/// positional dir-scan mode pinned RED below) - its per-file-tolerant loop
/// always falls through to the shared render call regardless of read errors.
#[test]
fn fapolicyd_lint_file_missing_sarif_is_byte_identical() {
    let out = run_missing_path_sarif(&["fapolicyd", "lint", "--file", "/nonexistent/583/x.rules"]);
    assert_byte_identical_sarif(&out);
}

// ---------------------------------------------------------------------------
// RED today: the two #583 half B sarif gaps.
// ---------------------------------------------------------------------------

/// `selinux lint`'s path-error arm has NO envelope call at all under any
/// format - `--format sarif` on a bad path is zero bytes today, same as
/// `--format json` (`path_error_json.rs::selinux_lint_missing_path_emits_json_envelope`).
#[test]
fn selinux_lint_missing_path_sarif_is_byte_identical() {
    let out = run_missing_path_sarif(&["selinux", "lint", "/nonexistent/583/selinux-config"]);
    assert_byte_identical_sarif(&out);
}

/// `fapolicyd lint <missing-dir>` (positional, no `--file`) early-returns
/// before `output::emit_lint` is ever reached (see `path_error_json.rs`'s
/// extension section for the full grounding); this is the SARIF counterpart
/// of `path_error_json.rs::fapolicyd_lint_missing_dir_emits_json_envelope`.
#[test]
fn fapolicyd_lint_missing_dir_sarif_is_byte_identical() {
    let out = run_missing_path_sarif(&["fapolicyd", "lint", "/nonexistent/583/rules.d"]);
    assert_byte_identical_sarif(&out);
}
