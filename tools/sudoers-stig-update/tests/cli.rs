//! End-to-end CLI tests: exercise the built binary offline (via `check --file`)
//! and assert the exit-code contract - 0 in sync, 1 on drift, 2 on error.
//!
//! Several tests here reach [`sudoers_stig_update::xccdf::parse_controls`] /
//! [`sudoers_stig_update::derive::code_table`] / `diff_controls` (#551). The
//! tests that never reach those (missing file, `--file` without `--product`,
//! unknown subcommand, `--help`) exercise only the surrounding CLI glue
//! (argument parsing, `Config`, `source::read_local`).

use std::path::PathBuf;
use std::process::Command;

const GOOD_RHEL8: &str = include_str!("fixtures/rhel8_sudoers_controls.xml");
const GOOD_RHEL10: &str = include_str!("fixtures/rhel10_sudoers_controls.xml");

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_sudoers-stig-update")
}

/// Write `content` to a unique temp file and return its path.
fn temp_xccdf(tag: &str, content: &str) -> PathBuf {
    let path =
        std::env::temp_dir().join(format!("sudoers-stig-cli-{}-{tag}.xml", std::process::id()));
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

// ---------------------------------------------------------------------------
// No-drift passes (the real, current fixture vs the real, current
// shipped table exits 0).
// ---------------------------------------------------------------------------
#[test]
fn check_file_in_sync_exits_0() {
    let f = temp_xccdf("insync", GOOD_RHEL10);
    let (code, stdout, err) = run(&[
        "check",
        "--product",
        "rhel10",
        "--file",
        &f.to_string_lossy(),
    ]);
    assert_eq!(
        code,
        Some(0),
        "in-sync must exit 0; stdout={stdout} err={err}"
    );
    // The EXACT row count, not a loose
    // `contains("OK (0 drift"`: the loose form matches
    // "OK (0 drift, 4 controls)" just as happily as the correct "... 3
    // controls)", so it cannot see a row-inflation regression (e.g. a
    // duplicate-family guard that fails to fire) even on this happy path.
    assert!(
        stdout.contains("OK (0 drift, 3 controls)"),
        "stdout={stdout}"
    );
}

// ---------------------------------------------------------------------------
// A future
// DISA revision that ADDS a second Rule to an already-matched family (here,
// a second Authenticate-family Rule alongside the real one) must fail LOUD
// (exit 2), never silently resolve the duplicate via first-wins and report a
// false-clean "OK (0 drift, ...)". A drift-detection tool that reports "no
// drift" after silently dropping an upstream addition is worse than useless.
// ---------------------------------------------------------------------------
#[test]
fn check_file_duplicate_family_exits_2_not_false_clean() {
    assert_eq!(
        GOOD_RHEL10.matches("</Benchmark>").count(),
        1,
        "fixture must have exactly one closing </Benchmark> to inject before"
    );
    let extra_group = r#"<Group id="V-281299"><title>SRG-OS-000373-GPOS-00156</title><Rule id="SV-281299r9999999_rule" weight="10.0" severity="medium"><version>RHEL-10-600535</version><title>RHEL 10 sudoers.d drop-in files must not contain "!authenticate".</title><fixtext fixref="F-99999r9999998_fix">Remove any occurrence of "!authenticate" found in files in the "/etc/sudoers.d" directory.</fixtext><check system="C-99999r9999997_chk"><check-content>Verify RHEL 10 "/etc/sudoers.d" has no occurrences of "!authenticate" with the following command:

$ sudo grep -ir '!authenticate' /etc/sudoers.d/

If any occurrences of "!authenticate" are returned, this is a finding.</check-content></check></Rule></Group>
"#;
    let mutated = GOOD_RHEL10.replace("</Benchmark>", &format!("{extra_group}</Benchmark>"));
    let f = temp_xccdf("dupfamily", &mutated);
    let (code, stdout, err) = run(&[
        "check",
        "--product",
        "rhel10",
        "--file",
        &f.to_string_lossy(),
    ]);
    assert_eq!(
        code,
        Some(2),
        "an upstream revision adding a SECOND Rule to an already-matched family must fail \
         closed (exit 2), not silently drop the new Rule; stdout={stdout} err={err}"
    );
    assert!(
        !stdout.contains("OK (0 drift"),
        "must never present a duplicated/over-matched family as a silent clean pass; \
         stdout={stdout}"
    );
}

// ---------------------------------------------------------------------------
// THE POSITIVE CONTROL. A single mutated STIG Rule id must be caught
// as drift and exit non-zero, naming the specific mismatched control -- a
// drift checker that only ever passes is worthless.
// ---------------------------------------------------------------------------
#[test]
fn check_file_drift_on_mutated_id_exits_1() {
    // Mutate the authenticate family's real RHEL-10-600530 id to a bogus one;
    // everything else in the fixture stays real/unmodified.
    assert!(
        GOOD_RHEL10.contains("RHEL-10-600530"),
        "fixture must contain the real authenticate id to mutate"
    );
    let drifted = GOOD_RHEL10.replace("RHEL-10-600530", "RHEL-10-999999");
    let f = temp_xccdf("drift", &drifted);
    let (code, stdout, err) = run(&[
        "check",
        "--product",
        "rhel10",
        "--file",
        &f.to_string_lossy(),
    ]);
    assert_eq!(
        code,
        Some(1),
        "a mutated STIG rule id must be reported as drift and exit 1; stdout={stdout} err={err}"
    );
    assert!(stdout.contains("DRIFT"), "stdout={stdout}");
    assert!(
        stdout.contains("authenticate"),
        "the drift must name the affected family; stdout={stdout}"
    );
    assert!(
        stdout.contains("RHEL-10-999999"),
        "the drift must name the new (upstream) id; stdout={stdout}"
    );
}

// ---------------------------------------------------------------------------
// THE #355 REGRESSION CLASS: the RHEL-08 `!authenticate` and pw-family ids
// SWAPPED with each other (#355 / #359).
// Simulate that swap against the real rhel8 fixture and confirm
// `check` reports drift (the id SET is unchanged, only which family owns
// which id -- a naive "is the id set the same" check would wrongly pass this).
// ---------------------------------------------------------------------------
#[test]
fn check_file_regression_355_swapped_ids_exits_1() {
    assert!(GOOD_RHEL8.contains("RHEL-08-010381"));
    assert!(GOOD_RHEL8.contains("RHEL-08-010383"));
    let swapped = GOOD_RHEL8
        .replace("RHEL-08-010381", "RHEL-08-TEMP-SWAP")
        .replace("RHEL-08-010383", "RHEL-08-010381")
        .replace("RHEL-08-TEMP-SWAP", "RHEL-08-010383");
    let f = temp_xccdf("swap355", &swapped);
    let (code, stdout, err) = run(&[
        "check",
        "--product",
        "rhel8",
        "--file",
        &f.to_string_lossy(),
    ]);
    assert_eq!(
        code,
        Some(1),
        "the #355 swapped-id class must be caught as drift, never silently pass; \
         stdout={stdout} err={err}"
    );
    assert!(stdout.contains("DRIFT"), "stdout={stdout}");
    assert!(
        stdout.contains("authenticate"),
        "the swap must surface a drift line for authenticate; stdout={stdout}"
    );
    assert!(
        stdout.contains("pw_family"),
        "the swap must surface a drift line for pw_family; stdout={stdout}"
    );
}

// ---------------------------------------------------------------------------
// Anti-vacuity at the CLI/exit-code level. A document with none of
// the 3 sudo-W04 families must fail LOUD (exit 2, the tool's fail-closed
// code), never silently report "OK, 0 controls" as if it were a clean pass.
// The injected document is a small, clearly-synthetic edge-case fixture (not
// claimed as real DISA text), mirroring the same convention
// tools/sshd-stig-update/tests/cli.rs uses for its own
// `check_unclassifiable_rule_exits_2` test.
// ---------------------------------------------------------------------------
#[test]
fn check_file_zero_matched_families_exits_2() {
    let doc = r#"<Benchmark><Group id="V-1"><Rule id="SV-1_rule"><version>RHEL-10-999999</version>
        <title>An unrelated control with no bearing on sudo-W04.</title>
        <fixtext>Do something unrelated to sudo.</fixtext>
        <check system="C-1"><check-content>Verify something unrelated to sudo entirely.
        If not configured, this is a finding.</check-content></check>
        </Rule></Group></Benchmark>"#;
    let f = temp_xccdf("vacuous", doc);
    let (code, stdout, err) = run(&[
        "check",
        "--product",
        "rhel10",
        "--file",
        &f.to_string_lossy(),
    ]);
    assert_eq!(
        code,
        Some(2),
        "zero matched sudo-W04 families must fail loud (exit 2), not report a false \
         clean pass; stdout={stdout} err={err}"
    );
}

// ---------------------------------------------------------------------------
// Plumbing already implemented for real (Config / arg parsing / source::read_local):
// these pass TODAY, no stub reached.
// ---------------------------------------------------------------------------

#[test]
fn check_missing_file_exits_2() {
    let (code, _out, err) = run(&[
        "check",
        "--product",
        "rhel10",
        "--file",
        "/no/such/xccdf.xml",
    ]);
    assert_eq!(code, Some(2), "unreadable source must exit 2");
    assert!(err.contains("sudoers-stig-update:"), "err={err}");
}

#[test]
fn check_file_without_product_exits_2() {
    let f = temp_xccdf("noproduct", GOOD_RHEL10);
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
fn unknown_subcommand_exits_2() {
    let (code, _out, err) = run(&["frobnicate"]);
    assert_eq!(code, Some(2));
    assert!(err.contains("unknown subcommand"), "err={err}");
}

// ---------------------------------------------------------------------------
// THE SCOPE GUARD, BEHAVIORAL form. A
// bare "--help must not contain the substring CIS" guard cannot detect a
// maintainer adding actual CIS derivation logic (it only catches a text
// mention) and is brittle against words that merely CONTAIN "cis". Instead,
// a POSITIVE assertion: help text must explicitly POINT AT the real
// tool that covers CIS (tools/cis-update) and the real location sudo-W06 is
// pinned (tags.rs), rather than either a vague disclaimer or an absent one.
// The complementary BEHAVIORAL half (this tool's own sources never reference
// `cis_baseline` / `Framework::Cis`) lives in `src/lib.rs`'s `scope_tests`
// module.
// ---------------------------------------------------------------------------
#[test]
fn help_points_at_the_real_cis_tool_and_the_real_w06_location() {
    let (code, _out, err) = run(&["--help"]);
    assert_eq!(code, Some(0));
    assert!(
        err.to_uppercase().contains("DISA"),
        "help text must name DISA explicitly; err={err}"
    );
    assert!(
        err.contains("tools/cis-update"),
        "help text must POINT AT the real tool that covers sudo-CIS (tools/cis-update), \
         not a vague disclaimer; err={err}"
    );
    assert!(
        err.contains("crates/rulesteward-sudoers/src/lints/tags.rs"),
        "help text must correctly name WHERE sudo-W06 is pinned (tags.rs), not a \
         vague 'see docs' pointer; err={err}"
    );
}

#[test]
fn help_exits_0() {
    let (code, _out, err) = run(&["--help"]);
    assert_eq!(code, Some(0));
    assert!(
        err.contains("drift-check the sudo-W04 DISA STIG control-id"),
        "err={err}"
    );
}
