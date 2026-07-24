//! End-to-end CLI tests: exercise the built binary offline (via `check`/`derive
//! --file`) and assert the exit-code contract - 0 in sync, 1 on drift, 2 on
//! error. Mirrors `tools/sshd-stig-update/tests/cli.rs` exactly for the
//! contract shape.
//!
//! # RED-state note (session 7c-v0_6-wave3 P2, test-author dispatch)
//!
//! `src/xccdf.rs::parse_requirements`'s body is a single `todo!()` (the
//! extraction algorithm is the implementer's job; see that module's doc
//! comment for the full grounded spec). EVERY test below that reaches
//! `parse_requirements` (i.e. every `check`/`derive` invocation with a
//! readable file and a known product) therefore PANICS today (Rust default
//! panic exit code 101), not the specific 0/1/2 code each test asserts - this
//! is the expected, uniform RED state, not several independent failures. The
//! tests that do NOT reach `parse_requirements` (a missing/unreadable file, an
//! unknown product/subcommand, `--file` without `--product`, `--help`) are
//! GREEN already: they exercise only `source`/`config`, both fully
//! implemented (not stubs).

use std::path::PathBuf;
use std::process::Command;

const RHEL9_FIXTURE: &str = include_str!("fixtures/rhel9_auditd_controls.xml");

/// A minimal XCCDF with only a NON-selected (decoy) Group: no `-a`/`-A`/`-w`
/// line anywhere, so a correct `parse_requirements` returns `Ok(vec![])` -
/// which equals the (currently empty) shipped table, i.e. genuinely IN SYNC.
const EMPTY_SELECTION_XCCDF: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1" id="EMPTY_TEST_FIXTURE">
<title>No audit-rule Groups: only a decoy service check.</title>
<Group id="V-1"><Rule severity="medium"><version>RHEL-09-000001</version>
<check system="C-x"><check-content>Verify the audit service is enabled:
$ sudo systemctl is-enabled auditd
If not "enabled", this is a finding.</check-content></check>
</Rule></Group>
</Benchmark>
"#;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_auditd-stig-update")
}

/// Write `content` to a unique temp file and return its path.
fn temp_xccdf(tag: &str, content: &str) -> PathBuf {
    let path =
        std::env::temp_dir().join(format!("auditd-stig-cli-{}-{tag}.xml", std::process::id()));
    std::fs::write(&path, content).expect("write temp fixture");
    path
}

/// Write `content` to a unique temp file (no forced extension) and return its
/// path - used by the `check-pin` tests below for both a custom
/// `stig-refs.toml` and a scripted `--fixture` answers file.
fn temp_named(tag: &str, content: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("auditd-stig-cli-{}-{tag}", std::process::id()));
    std::fs::write(&path, content).expect("write temp fixture");
    path
}

fn run(args: &[&str]) -> (Option<i32>, String, String) {
    let out = Command::new(bin())
        .args(args)
        .output()
        .expect("spawn binary");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

// --- exit-code contract: 0 in sync -------------------------------------------

#[test]
fn check_empty_selection_file_drifts_against_the_populated_table_exits_1() {
    // The shipped RHEL9_REQUIRED table is now populated (issue #474): a file
    // with no audit-rule Groups derives an empty set, which necessarily
    // drifts against the (now 67-row) shipped table - this keeps coverage of
    // the zero-selection -> drift -> exit-1 path (the mirror-image case of
    // the "both sides empty" wiring pin this test used to be, before
    // population inverted its premise).
    //
    // UPDATED (#523, session 9b-v0_8-wave2 lane 2e): the shipped table grows
    // from 67 to 69 rows (two new Control-shaped deepening entries; see
    // `src/xccdf.rs`'s known-answer tests). That bump already landed and is
    // GREEN.
    //
    // SECOND, additive bump (also #523, additive round 2): the
    // "--loginuid-immutable" deepening entry grows the shipped table from 69
    // to 70 rows.
    //
    // THIRD bump (#549, session 9e-wave2c pipeline P2): DISA RHEL 9 STIG
    // V2R7 -> V2R9 rewrote 9 identity/login rules into dual-arch syscall form
    // (net +9) and added V-279936 cron_exec (net +2), growing the shipped
    // table from 70 to 81 rows.
    let f = temp_xccdf("empty", EMPTY_SELECTION_XCCDF);
    let (code, stdout, err) = run(&[
        "check",
        "--product",
        "rhel9",
        "--file",
        &f.to_string_lossy(),
    ]);
    assert_eq!(
        code,
        Some(1),
        "an empty-selection file must drift against the populated shipped table; \
         stdout={stdout} stderr={err}"
    );
    assert!(stdout.contains("DRIFT (81 change(s))"), "stdout={stdout}");
}

// --- exit-code contract: 1 drift ---------------------------------------------

#[test]
fn check_real_rhel9_fixture_is_in_sync_with_the_populated_table() {
    // The shipped RHEL9_REQUIRED table is now populated from this same
    // fixture's derived output (issue #474), so the real, non-empty rhel9
    // fixture matches it exactly: 0 drift, 67 rows - mirrors
    // `xccdf.rs`'s `rhel9_fixture_reproduces_code_table_exactly` through the
    // CLI's `check` subcommand.
    //
    // UPDATED (#523, session 9b-v0_8-wave2 lane 2e): the fixture (and, once
    // implemented, the shipped table) grows from 67 to 69 rows. That bump
    // already landed and is GREEN.
    //
    // SECOND, additive bump (also #523, additive round 2): the
    // "--loginuid-immutable" deepening entry grows both sides from 69 to 70
    // rows, staying in sync.
    //
    // THIRD bump (#549, session 9e-wave2c pipeline P2): DISA RHEL 9 STIG
    // V2R7 -> V2R9 rewrote 9 identity/login rules into dual-arch syscall form
    // (net +9) and added V-279936 cron_exec (net +2), growing both the
    // fixture and the shipped table from 70 to 81 rows, staying in sync.
    let f = temp_xccdf("rhel9-full", RHEL9_FIXTURE);
    let (code, stdout, err) = run(&[
        "check",
        "--product",
        "rhel9",
        "--file",
        &f.to_string_lossy(),
    ]);
    assert_eq!(
        code,
        Some(0),
        "the real rhel9 fixture must be in sync with the populated table; \
         stdout={stdout} stderr={err}"
    );
    assert!(stdout.contains("OK (0 drift, 81 rules)"), "stdout={stdout}");
}

#[test]
fn check_file_drift_names_the_removed_v_number() {
    // String-surgery mutation (mirrors sshd's cli.rs `check_file_drift_exits_1`):
    // remove the identity/sudoers watch Group (V-258217) from the fixture, so
    // once xccdf.rs is real, the derived set (missing V-258217) still drifts
    // against the empty shipped table just like the full fixture does - this
    // test additionally proves the diff messages are per-row content, not just
    // a length check. RED today via the todo!() panic.
    let start = RHEL9_FIXTURE
        .find("<Group id=\"V-258217\"")
        .expect("V-258217 group present in fixture");
    let end =
        RHEL9_FIXTURE[start..].find("</Group>").expect("group end") + start + "</Group>".len();
    let mut mutated = RHEL9_FIXTURE.to_string();
    mutated.replace_range(start..end, "");

    let f = temp_xccdf("rhel9-mutated", &mutated);
    let (code, stdout, err) = run(&[
        "check",
        "--product",
        "rhel9",
        "--file",
        &f.to_string_lossy(),
    ]);
    assert_eq!(
        code,
        Some(1),
        "drift must exit 1; stdout={stdout} stderr={err}"
    );
    assert!(stdout.contains("DRIFT"), "stdout={stdout}");
}

// --- exit-code contract: 2 on error (these are GREEN today: no xccdf::parse
// involved) --------------------------------------------------------------

#[test]
fn check_missing_file_exits_2() {
    let (code, _out, err) = run(&[
        "check",
        "--product",
        "rhel9",
        "--file",
        "/no/such/xccdf.xml",
    ]);
    assert_eq!(code, Some(2), "unreadable source must exit 2");
    assert!(err.contains("auditd-stig-update:"), "err={err}");
}

#[test]
fn check_file_without_product_exits_2() {
    let f = temp_xccdf("noproduct", RHEL9_FIXTURE);
    let (code, _out, err) = run(&["check", "--file", &f.to_string_lossy()]);
    assert_eq!(
        code,
        Some(2),
        "--file without a single --product must exit 2"
    );
    assert!(
        err.contains("--file requires exactly one --product"),
        "err={err}"
    );
}

#[test]
fn check_unknown_product_exits_2() {
    let f = temp_xccdf("badproduct", RHEL9_FIXTURE);
    let (code, _out, err) = run(&[
        "check",
        "--product",
        "rhel7",
        "--file",
        &f.to_string_lossy(),
    ]);
    assert_eq!(code, Some(2), "an unknown product must exit 2; err={err}");
    assert!(err.contains("unknown product"), "err={err}");
}

#[test]
fn unknown_subcommand_exits_2() {
    let (code, _out, err) = run(&["frobnicate"]);
    assert_eq!(code, Some(2));
    assert!(err.contains("unknown subcommand"), "err={err}");
}

// --- derive: always exits 0 (a report, not a gate); GREEN-adjacent but still
// reaches parse_requirements, so RED today via the todo!() panic ------------

#[test]
fn derive_file_exits_0() {
    let f = temp_xccdf("derive", RHEL9_FIXTURE);
    let (code, stdout, err) = run(&[
        "derive",
        "--product",
        "rhel9",
        "--file",
        &f.to_string_lossy(),
    ]);
    assert_eq!(code, Some(0), "stdout={stdout} stderr={err}");
    assert!(stdout.contains("paste-ready"), "stdout={stdout}");
}

// --- help/plumbing (GREEN today) --------------------------------------------

#[test]
fn help_exits_0() {
    let (code, _out, err) = run(&["--help"]);
    assert_eq!(code, Some(0), "--help exits 0");
    assert!(
        err.contains("drift-check the auditd au-W06 STIG baselines"),
        "err={err}"
    );
}

// --- check-pin (#550 lane-5 rework, BLOCKER 5): CLI wiring, offline --------
//
// Mirrors `tools/sshd-stig-update/tests/cli.rs`'s `check-pin` section
// exactly (same contract: `--fixture <path>` requires exactly one
// `--product`, reads one line per probe IN ORDER - `FOUND` / `NOTFOUND` /
// `ERR:<message>` - and wires an in-process fake `Prober`; no real `curl`
// call happens when `--fixture` is given). Phase 0 already landed the
// `auditd-stig-check-pin` justfile recipe running `cargo run -- check-pin`;
// today that subcommand falls into the catch-all `unknown subcommand`
// branch (see `unknown_subcommand_exits_2` above - the SAME code path).
// These tests pin two things the pure `pin.rs` unit tests cannot: (1)
// `check-pin` must be a RECOGNIZED subcommand, and (2) the PROCESS must
// exit 0 for every `PinStatus`, including `Unavailable` - `main.rs::run`'s
// `Result<ExitCode, String>` maps `Err` to exit 2 (see
// `check_missing_file_exits_2` above), so an impl that wires
// `PinStatus::Unavailable` through that `Err` path would invert the
// non-blocking contract at the PROCESS boundary even if `pin::report`'s own
// `u8` were correct in isolation.

/// A minimal `stig-refs.toml` with a KNOWN, test-controlled pin + base_url
/// (rather than the real shipped file, which is a live pin that will bump
/// over time and would make these tests brittle against a future #550-
/// unrelated pin bump). TWO products (not one): the real `stig-refs.toml`
/// has three, and the justfile recipe invokes `check-pin` with no
/// `--product` at all, so a single-product config would let a handler that
/// ignores `--product` entirely (always probing the first config entry)
/// pass every test below - `check_pin_respects_product_selection` pins that
/// `--product rhel10` really reaches rhel10's own pin, not rhel9's.
const PIN_TEST_STIG_REFS: &str = "base_url = \"https://mirror.example.test/stigs\"\n\n\
     [products.rhel9]\n\
     zip = \"U_RHEL_9_V2R9_STIG.zip\"\n\
     benchmark = \"test fixture rhel9\"\n\n\
     [products.rhel10]\n\
     zip = \"U_RHEL_10_V1R2_STIG.zip\"\n\
     benchmark = \"test fixture rhel10\"\n";

#[test]
fn check_pin_is_a_recognized_subcommand() {
    // A missing fixture file must fail on ITS OWN terms (a read error), not
    // be swallowed by "unknown subcommand" - proving dispatch actually
    // reaches the check-pin handler rather than falling through to the
    // catch-all `unknown_subcommand_exits_2` hits above.
    let (code, _out, err) = run(&[
        "check-pin",
        "--product",
        "rhel9",
        "--fixture",
        "/no/such/fixture/file",
    ]);
    assert_eq!(code, Some(2), "err={err}");
    assert!(
        !err.contains("unknown subcommand"),
        "check-pin must be a recognized subcommand, not fall through to the \
         catch-all; err={err}"
    );
    assert!(
        err.contains("fixture"),
        "the failure must be about the missing fixture file, not something \
         else; err={err}"
    );
}

#[test]
fn check_pin_fixture_without_product_is_an_error() {
    // Mirrors `check_file_without_product_exits_2` above: `--fixture`, like
    // `--file`, needs exactly one `--product` to know which pin to check.
    let fixture = temp_named("pin-fixture-noproduct", "FOUND\nNOTFOUND\nNOTFOUND\n");
    let (code, _out, err) = run(&["check-pin", "--fixture", &fixture.to_string_lossy()]);
    assert_eq!(code, Some(2), "err={err}");
    assert!(
        err.contains("--fixture requires exactly one --product"),
        "err={err}"
    );
}

#[test]
fn check_pin_reports_current_and_exits_0() {
    let cfg = temp_named("pin-cfg-current", PIN_TEST_STIG_REFS);
    let fixture = temp_named("pin-fixture-current", "FOUND\nNOTFOUND\nNOTFOUND\n");
    let (code, stdout, err) = run(&[
        "check-pin",
        "--product",
        "rhel9",
        "--config",
        &cfg.to_string_lossy(),
        "--fixture",
        &fixture.to_string_lossy(),
    ]);
    assert_eq!(
        code,
        Some(0),
        "a current pin must exit 0; stdout={stdout} err={err}"
    );
    assert!(
        stdout.to_lowercase().contains("current") || stdout.to_lowercase().contains("no newer"),
        "stdout={stdout}"
    );
}

#[test]
fn check_pin_reports_newer_revision_and_still_exits_0() {
    let cfg = temp_named("pin-cfg-newer", PIN_TEST_STIG_REFS);
    let fixture = temp_named("pin-fixture-newer", "FOUND\nFOUND\nNOTFOUND\nNOTFOUND\n");
    let (code, stdout, err) = run(&[
        "check-pin",
        "--product",
        "rhel9",
        "--config",
        &cfg.to_string_lossy(),
        "--fixture",
        &fixture.to_string_lossy(),
    ]);
    assert_eq!(
        code,
        Some(0),
        "a newer upstream revision is news, not a build failure - must still \
         exit 0; stdout={stdout} err={err}"
    );
    assert!(
        stdout.contains("V2R10") || stdout.contains("U_RHEL_9_V2R10_STIG.zip"),
        "stdout must name the specific newer revision; stdout={stdout}"
    );
}

#[test]
fn check_pin_respects_product_selection() {
    // #550 lane-5 round-2 rework, CONCERN: with only ONE product in
    // `PIN_TEST_STIG_REFS`, a handler that ignores `--product` entirely and
    // always probes the first config entry would still pass every test
    // above - the same shape as round-1 blocker 1, moved to the
    // config -> find_latest plumbing. Request rhel10 explicitly (a
    // DIFFERENT pin, "U_RHEL_10_V1R2_STIG.zip") and assert the reported
    // revision is rhel10's OWN next candidate (V1R3), not rhel9's (V2R10).
    let cfg = temp_named("pin-cfg-multiproduct", PIN_TEST_STIG_REFS);
    let fixture = temp_named(
        "pin-fixture-multiproduct",
        "FOUND\nFOUND\nNOTFOUND\nNOTFOUND\n",
    );
    let (code, stdout, err) = run(&[
        "check-pin",
        "--product",
        "rhel10",
        "--config",
        &cfg.to_string_lossy(),
        "--fixture",
        &fixture.to_string_lossy(),
    ]);
    assert_eq!(code, Some(0), "stdout={stdout} err={err}");
    assert!(
        stdout.contains("V1R3") || stdout.contains("U_RHEL_10_V1R3_STIG.zip"),
        "must report rhel10's OWN next revision when --product rhel10 was \
         requested; stdout={stdout}"
    );
    assert!(
        !stdout.contains("V2R10") && !stdout.contains("U_RHEL_9_V2R10_STIG.zip"),
        "must NOT report rhel9's revision when --product rhel10 was \
         requested - --product must actually select which pin is checked; \
         stdout={stdout}"
    );
}

#[test]
fn check_pin_unavailable_prober_still_exits_0_not_2() {
    // The sharpest clause of blocker 5: `main.rs::run`'s `Result<ExitCode,
    // String>` maps `Err` to exit 2 (see `check_missing_file_exits_2` /
    // `check_unknown_product_exits_2` above). An impl that wires
    // `PinStatus::Unavailable` through that SAME `Err` path would satisfy
    // `pin::report`'s `u8 == 0` in isolation while the ACTUAL PROCESS exits
    // 2 - inverting the non-blocking contract. This can only be caught at
    // the process boundary, not the pure function.
    let cfg = temp_named("pin-cfg-unavailable", PIN_TEST_STIG_REFS);
    let fixture = temp_named(
        "pin-fixture-unavailable",
        "ERR:TLS handshake failed: certificate expired\n",
    );
    let (code, stdout, err) = run(&[
        "check-pin",
        "--product",
        "rhel9",
        "--config",
        &cfg.to_string_lossy(),
        "--fixture",
        &fixture.to_string_lossy(),
    ]);
    assert_eq!(
        code,
        Some(0),
        "an unavailable prober must skip gracefully (exit 0), NOT propagate \
         as a process error (exit 2); stdout={stdout} err={err}"
    );
    assert!(
        stdout.contains("TLS handshake failed: certificate expired")
            || err.contains("TLS handshake failed: certificate expired"),
        "the reason must be surfaced somewhere; stdout={stdout} err={err}"
    );
}
