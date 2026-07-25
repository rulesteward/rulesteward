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
/// ignores `--product` entirely pass every test below -
/// `check_pin_respects_product_selection` and
/// `check_pin_reports_newer_revision_and_still_exits_0` together pin that
/// `--product` really selects the requested pin (see the former test's own
/// doc comment, corrected #550 lane-5 ATL L5-b, for exactly which cheat
/// each one catches).
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
    // `PIN_TEST_STIG_REFS`, a handler that ignores `--product` entirely
    // would still pass every test above - the same shape as round-1
    // blocker 1, moved to the config -> find_latest plumbing.
    //
    // [CORRECTED, #550 lane-5 ATL, L5-b - an earlier draft of this comment
    // had this backwards.] This test pins the MIRROR-IMAGE cheat: a handler
    // that always probes the LAST config entry (equivalently, always
    // rhel9). The "always the FIRST entry" cheat is killed by
    // `check_pin_reports_newer_revision_and_still_exits_0` instead, because
    // `Config::products` is a `BTreeMap` and `"rhel10" < "rhel9"`
    // lexicographically, so entry 0 IS rhel10 - a handler hardcoded to
    // entry 0 would already return rhel10's data for THIS test's
    // `--product rhel10` request and pass undetected. The two tests are
    // complementary; neither alone covers both cheats.
    //
    // Request rhel10 explicitly (a DIFFERENT pin,
    // "U_RHEL_10_V1R2_STIG.zip") and assert the reported revision is
    // rhel10's OWN next candidate (V1R3), not rhel9's (V2R10).
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

// --- workflow <-> report() literal coupling (#550 lane-5 ATL, MISS-1/MISS-2) -
//
// Nothing else couples `.github/workflows/auditd-pin-staleness.yml`'s
// "Detect a staleness hit" grep to `pin::report`'s own message text:
// rewording either side independently would leave every test in this file
// green while silently breaking (or permanently disabling) the
// staleness-detection issue-opening path. MISS-1 proved this: rewording
// report()'s two actionable messages left 142/142 tests green while the
// workflow's grep would have silently gone `hit=false` forever. Pin both
// directions.
//
// USER RULING (MISS-2): `PinStatus::Unparseable` IS actionable - report()'s
// own message already tells a human to act ("check stig-refs.toml for a
// typo"), and if DISA ever changes its filename scheme, the pin legitimately
// becomes unparseable while `check`/`derive` keep working, silently
// switching staleness detection off forever if this stayed non-actionable.
// So its literal is included below alongside Newer/PinNotFound.

const WORKFLOW_YML: &str = include_str!("../../../.github/workflows/auditd-pin-staleness.yml");

const NEWER_LITERAL: &str = "a newer DISA STIG revision exists";
// Deliberately excludes the trailing "(404)": the workflow's `grep -E`
// pattern must ESCAPE the parens for its own regex syntax (`was not found
// \(404\)`), while report()'s plain message text has no backslashes - a
// literal that included the parens could never match both verbatim.
const PIN_NOT_FOUND_LITERAL: &str = "was not found";
const UNPARSEABLE_LITERAL: &str = "no usable V<major>R<minor> token";

#[test]
fn workflow_grep_literals_stay_coupled_to_report_actionable_messages() {
    // Scope the haystack to the workflow's actual `grep -qE` line, NOT the
    // whole file. Each literal below appears TWICE in that workflow: once in
    // the explanatory comment block and once in the real grep. A whole-file
    // `contains` therefore stays green when a maintainer narrows the real
    // pattern and leaves the comment untouched -- which is precisely the
    // #550 MISS-1 failure this test exists to prevent, reintroduced by the
    // test itself (caught by the session-9j senior integration review).
    let grep_lines = WORKFLOW_YML
        .lines()
        .filter(|l| l.contains("grep -qE"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !grep_lines.is_empty(),
        "no `grep -qE` line in the workflow: the \"Detect a staleness hit\" \
         step was renamed, restructured, or removed, so this coupling test \
         has nothing to check and would pass vacuously; \
         workflow=.github/workflows/auditd-pin-staleness.yml"
    );
    for lit in [NEWER_LITERAL, PIN_NOT_FOUND_LITERAL, UNPARSEABLE_LITERAL] {
        assert!(
            grep_lines.contains(lit),
            "the workflow's \"Detect a staleness hit\" grep must contain the \
             actionable literal {lit:?} that report() emits - otherwise a \
             report() reword silently breaks the workflow's detection \
             forever without any test noticing (#550 MISS-1); \
             workflow=.github/workflows/auditd-pin-staleness.yml"
        );
    }

    let newer = auditd_stig_update::pin::PinStatus::Newer {
        revision: auditd_stig_update::pin::Revision { major: 3, minor: 2 },
        zip: "U_RHEL_9_V3R2_STIG.zip".to_string(),
    };
    let (newer_msg, _) = auditd_stig_update::pin::report("rhel9", &newer);
    assert!(
        newer_msg.contains(NEWER_LITERAL),
        "report()'s Newer message must contain the literal the workflow greps \
         for; message={newer_msg:?}"
    );

    let pin_not_found = auditd_stig_update::pin::PinStatus::PinNotFound {
        pinned_zip: "U_RHEL_9_V2R9_STIG.zip".to_string(),
    };
    let (pnf_msg, _) = auditd_stig_update::pin::report("rhel9", &pin_not_found);
    assert!(
        pnf_msg.contains(PIN_NOT_FOUND_LITERAL),
        "report()'s PinNotFound message must contain the literal the workflow \
         greps for; message={pnf_msg:?}"
    );

    let unparseable = auditd_stig_update::pin::PinStatus::Unparseable {
        pinned_zip: "U_RHEL_9_STIG.zip".to_string(),
    };
    let (unp_msg, _) = auditd_stig_update::pin::report("rhel9", &unparseable);
    assert!(
        unp_msg.contains(UNPARSEABLE_LITERAL),
        "report()'s Unparseable message must contain the literal the workflow \
         greps for (USER RULING: Unparseable IS actionable); message={unp_msg:?}"
    );

    // The two GRACEFUL, non-actionable statuses must NOT accidentally match
    // any actionable literal - the workflow must not open an issue for them.
    let (current_msg, _) =
        auditd_stig_update::pin::report("rhel9", &auditd_stig_update::pin::PinStatus::Current);
    let unavailable = auditd_stig_update::pin::PinStatus::Unavailable("boom".to_string());
    let (unavailable_msg, _) = auditd_stig_update::pin::report("rhel9", &unavailable);
    for (label, msg) in [("Current", &current_msg), ("Unavailable", &unavailable_msg)] {
        for lit in [NEWER_LITERAL, PIN_NOT_FOUND_LITERAL, UNPARSEABLE_LITERAL] {
            assert!(
                !msg.contains(lit),
                "{label}'s message must NOT contain the actionable literal \
                 {lit:?} - it must stay non-actionable; message={msg:?}"
            );
        }
    }
}

// --- check-pin Unparseable (#550 lane-5 ATL, MISS-2/MISS-4): CLI wiring ----

#[test]
fn check_pin_unparseable_pin_still_exits_0() {
    // USER RULING (MISS-2): Unparseable IS actionable (see the coupling
    // test above - the workflow now greps for it too), but the PROCESS must
    // still exit 0 - the same non-blocking contract as every other
    // PinStatus. A config/typo problem is news for a human, not a build
    // failure. No probe should happen (the empty `--fixture` file would
    // panic the harness if `check-pin` tried to probe anything).
    let cfg = temp_named(
        "pin-cfg-unparseable",
        "base_url = \"https://mirror.example.test/stigs\"\n\n\
         [products.rhel9]\n\
         zip = \"U_RHEL_9_STIG.zip\"\n\
         benchmark = \"test fixture rhel9 no version token\"\n",
    );
    let fixture = temp_named("pin-fixture-unparseable", "");
    let (code, stdout, err) = run(&[
        "check-pin",
        "--product",
        "rhel9",
        "--config",
        &cfg.to_string_lossy(),
        "--fixture",
        &fixture.to_string_lossy(),
    ]);
    assert_eq!(code, Some(0), "stdout={stdout} err={err}");
    assert!(
        stdout.contains("U_RHEL_9_STIG.zip"),
        "stdout must name the unparseable pin; stdout={stdout}"
    );
}

#[test]
fn check_pin_unparseable_oversized_revision_does_not_panic_and_exits_0() {
    // #550 lane-5 ATL MISS-4: a hand-edited stig-refs.toml pin whose minor
    // has rolled to `u32::MAX` must not crash the PROCESS (exit 101, Rust's
    // default panic code) - it must exit 0 like every other PinStatus. This
    // can only be caught at the process boundary: `pin.rs`'s own unit tests
    // call `find_latest` directly and cannot observe a real subprocess exit
    // code the way this test can.
    //
    // The `--fixture` file supplies a `FOUND\n` line the guard-correct code
    // path never consumes (Unparseable short-circuits before any probe) -
    // this is deliberate: an EMPTY fixture would make this test pass even
    // WITHOUT the guard, since the fixture-exhaustion error on the very
    // first probe attempt would ALSO gracefully report Unavailable (exit 0),
    // masking the real overflow. Supplying an answer lets a guard-less
    // implementation actually enter the enumeration loop and hit the
    // overflow this test exists to catch.
    let cfg = temp_named(
        "pin-cfg-oversized",
        "base_url = \"https://mirror.example.test/stigs\"\n\n\
         [products.rhel9]\n\
         zip = \"U_RHEL_9_V1R4294967295_STIG.zip\"\n\
         benchmark = \"test fixture rhel9 oversized minor\"\n",
    );
    let fixture = temp_named("pin-fixture-oversized", "FOUND\n");
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
        "an oversized revision must exit 0, not panic (101); stdout={stdout} err={err}"
    );
    assert!(
        stdout.contains("U_RHEL_9_V1R4294967295_STIG.zip"),
        "stdout={stdout}"
    );
}
