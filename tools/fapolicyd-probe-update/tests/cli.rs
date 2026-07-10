//! End-to-end CLI tests: exercise the built binary OFFLINE (via `check --transcript-dir`
//! / `derive --transcript-dir`) against the committed probe fixtures and the real
//! `crates/rulesteward-fapolicyd` shipped tables.
//!
//! Every test here is RED as of the RED-test-authoring pass (issue #478): the CLI
//! plumbing (arg parsing, subcommand dispatch) is fully implemented, but every path
//! exercised below reaches `fapolicyd_probe_update::transcript::parse_tsv` (a
//! `todo!()` stub), so the child process panics instead of returning the asserted
//! exit code / stdout. This mirrors `tools/sshd-probe-update/tests/cli.rs`'s offline
//! contract (0 in sync, 1 on drift, 2 on error), adapted to the 3-file-per-target
//! `--transcript-dir` layout (see `src/main.rs`'s module doc). The docker LIVE path
//! is not exercised here (no docker in CI, and out of this pipeline's test scope per
//! the pipeline brief's PRE-ANSWERED decision #1/#4).

use std::path::PathBuf;
use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_fapolicyd-probe-update")
}

/// Absolute path to the committed fixtures directory (robust regardless of test cwd).
fn fixtures_dir() -> String {
    format!("{}/tests/fixtures", env!("CARGO_MANIFEST_DIR"))
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

/// Write a unique temp directory containing `<name>` -> `content` files and return its
/// path (used to build a synthetic/mutated 3-file transcript-dir triple).
fn temp_dir_with(tag: &str, files: &[(&str, &str)]) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("fapolicyd-probe-cli-{}-{tag}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("mkdir temp dir");
    for (name, content) in files {
        std::fs::write(dir.join(name), content).expect("write temp fixture");
    }
    dir
}

// -----------------------------------------------------------------------------
// Check GREEN-case (offline, real committed fixtures): must exit 0 and print OK.
// -----------------------------------------------------------------------------

#[test]
fn check_rhel8_real_fixtures_in_sync_exits_0() {
    let (code, stdout, err) = run(&[
        "check",
        "--target",
        "rhel8",
        "--transcript-dir",
        &fixtures_dir(),
    ]);
    assert_eq!(
        code,
        Some(0),
        "in-sync must exit 0; stdout={stdout} err={err}"
    );
    assert!(stdout.contains("OK (0 drift)"), "stdout={stdout}");
}

#[test]
fn check_rhel9_real_fixtures_in_sync_exits_0() {
    let (code, stdout, err) = run(&[
        "check",
        "--target",
        "rhel9",
        "--transcript-dir",
        &fixtures_dir(),
    ]);
    assert_eq!(
        code,
        Some(0),
        "in-sync must exit 0; stdout={stdout} err={err}"
    );
    assert!(stdout.contains("OK (0 drift)"), "stdout={stdout}");
}

#[test]
fn check_rhel10_real_fixtures_in_sync_exits_0() {
    let (code, stdout, err) = run(&[
        "check",
        "--target",
        "rhel10",
        "--transcript-dir",
        &fixtures_dir(),
    ]);
    assert_eq!(
        code,
        Some(0),
        "in-sync must exit 0; stdout={stdout} err={err}"
    );
    assert!(stdout.contains("OK (0 drift)"), "stdout={stdout}");
}

// -----------------------------------------------------------------------------
// Check RED-case (offline, one mutated fixture per dataset): must exit 1, print
// DRIFT, and name the offending dataset + entry.
// -----------------------------------------------------------------------------

const RHEL8_VERSION: &str = include_str!("fixtures/fapolicyd8-version.tsv");
const RHEL8_PATTERN: &str = include_str!("fixtures/fapolicyd8-pattern.tsv");
const RHEL8_E07: &str = include_str!("fixtures/fapolicyd8-e07.tsv");

#[test]
fn check_rhel8_mutated_pattern_fixture_exits_1_and_names_the_value() {
    let mutated_pattern = RHEL8_PATTERN.replacen(
        "pattern\tld_so\taccept\t1\t",
        "pattern\tld_so\treject\t0\t",
        1,
    );
    assert_ne!(
        mutated_pattern, RHEL8_PATTERN,
        "the ld_so accept row must be found"
    );
    let dir = temp_dir_with(
        "pattern-drift",
        &[
            ("fapolicyd8-version.tsv", RHEL8_VERSION),
            ("fapolicyd8-pattern.tsv", &mutated_pattern),
            ("fapolicyd8-e07.tsv", RHEL8_E07),
        ],
    );
    let (code, stdout, _e) = run(&[
        "check",
        "--target",
        "rhel8",
        "--transcript-dir",
        &dir.to_string_lossy(),
    ]);
    assert_eq!(code, Some(1), "drift must exit 1; stdout={stdout}");
    assert!(stdout.contains("DRIFT"), "stdout={stdout}");
    assert!(
        stdout.contains("ld_so"),
        "the drift must name ld_so; stdout={stdout}"
    );
}

#[test]
fn check_rhel8_mutated_version_fixture_exits_1_and_names_the_version() {
    let mutated_version = RHEL8_VERSION.replace(
        "fapolicyd-1.3.2-1.el8.x86_64",
        "fapolicyd-9.9.9-1.el8.x86_64",
    );
    assert_ne!(mutated_version, RHEL8_VERSION);
    let dir = temp_dir_with(
        "version-drift",
        &[
            ("fapolicyd8-version.tsv", &mutated_version),
            ("fapolicyd8-pattern.tsv", RHEL8_PATTERN),
            ("fapolicyd8-e07.tsv", RHEL8_E07),
        ],
    );
    let (code, stdout, _e) = run(&[
        "check",
        "--target",
        "rhel8",
        "--transcript-dir",
        &dir.to_string_lossy(),
    ]);
    assert_eq!(code, Some(1), "drift must exit 1; stdout={stdout}");
    assert!(stdout.contains("DRIFT"), "stdout={stdout}");
    assert!(
        stdout.contains("9.9.9"),
        "the drift must name the wrong probed version; stdout={stdout}"
    );
}

/// ATL finding 1b (adversary MISS 1, end-to-end leg): the same pid category flip as
/// derive.rs's `check_e07_category_mismatch_reports_directional_drift_naming_both_categories`,
/// driven through the built binary - `check` must exit 1 and its stdout must name
/// the pid drift in both directions (probed Signed added, shipped Unsigned
/// unconfirmed).
#[test]
fn check_rhel8_mutated_e07_fixture_exits_1_and_names_pid_categories() {
    let mutated_e07 = RHEL8_E07
        .replacen("e07\tpid_int\taccept\t1\t", "e07\tpid_int\treject\t0\t", 1)
        .replacen(
            "e07\tpid_signed_negfirst\treject\t0\t",
            "e07\tpid_signed_negfirst\taccept\t1\t",
            1,
        );
    assert_ne!(
        mutated_e07, RHEL8_E07,
        "both pid rows must have been rewritten"
    );
    let dir = temp_dir_with(
        "e07-drift",
        &[
            ("fapolicyd8-version.tsv", RHEL8_VERSION),
            ("fapolicyd8-pattern.tsv", RHEL8_PATTERN),
            ("fapolicyd8-e07.tsv", &mutated_e07),
        ],
    );
    let (code, stdout, _e) = run(&[
        "check",
        "--target",
        "rhel8",
        "--transcript-dir",
        &dir.to_string_lossy(),
    ]);
    assert_eq!(code, Some(1), "e07 drift must exit 1; stdout={stdout}");
    assert!(stdout.contains("DRIFT"), "stdout={stdout}");
    assert!(
        stdout.contains("pid=Signed") && stdout.contains("pid=Unsigned"),
        "the drift must name pid with both categories; stdout={stdout}"
    );
}

// -----------------------------------------------------------------------------
// derive (offline, real committed fixtures): must exit 0 and report in sync.
// -----------------------------------------------------------------------------

#[test]
fn derive_rhel8_real_fixtures_exits_0_and_reports_no_drift() {
    let (code, stdout, err) = run(&[
        "derive",
        "--target",
        "rhel8",
        "--transcript-dir",
        &fixtures_dir(),
    ]);
    assert_eq!(code, Some(0), "stdout={stdout} err={err}");
    assert!(
        stdout.contains("no drift vs the shipped tables"),
        "stdout={stdout}"
    );
}

// -----------------------------------------------------------------------------
// ATL strengthening round: CLI-glue pins for mutation survivors in main.rs.
// -----------------------------------------------------------------------------

/// ATL finding 3 (mutation survivor `require_single_product_for_transcript_dir ->
/// Ok(())`, main.rs): `--transcript-dir` with the default all-three-targets
/// selection must be REJECTED with the guard's error on stderr and exit 2. The
/// mutant silently proceeds to read all nine committed fixtures and exits 0
/// in-sync, so the exit-code assert alone kills it; the message assert pins WHICH
/// error fired.
#[test]
fn check_transcript_dir_without_single_target_exits_2() {
    let (code, _out, err) = run(&["check", "--transcript-dir", &fixtures_dir()]);
    assert_eq!(
        code,
        Some(2),
        "--transcript-dir without exactly one --target must exit 2; err={err}"
    );
    assert!(
        err.contains("--transcript-dir requires exactly one --target"),
        "err={err}"
    );
}

/// ATL finding 4 (mutation survivor `print_help -> ()`, main.rs): the cheap pin -
/// `--help` must exit 0 and print a non-empty usage on stderr naming both
/// subcommands. The mutant prints nothing, dying on the content asserts.
#[test]
fn help_exits_0_and_prints_usage_naming_both_subcommands() {
    let (code, _out, err) = run(&["--help"]);
    assert_eq!(code, Some(0));
    assert!(err.contains("USAGE"), "err={err}");
    assert!(
        err.contains("check") && err.contains("derive"),
        "help must name both subcommands; err={err}"
    );
}
