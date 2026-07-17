//! End-to-end CLI tests: exercise the built binary offline and assert the
//! intended exit-code contract - 0 in sync, 1 on drift, 2 on error. Mirrors
//! `tools/auditd-stig-update/tests/cli.rs`'s shape.
//!
//! # RED-state note (session 9d lane 2b, test-author dispatch)
//!
//! `src/main.rs` is a bare stub that ALWAYS exits 2 (no `check`/`derive`
//! subcommand parsing, no XCCDF extraction exists yet). Every test below
//! that expects a 0 or 1 exit is therefore RED today (it will observe 2,
//! not the code it asserts) - this is the expected, uniform RED state, not
//! several independent failures. The two tests that already expect exit 2
//! (`unknown_subcommand_exits_2`, `missing_file_exits_2`) are GREEN today by
//! construction of the stub, and remain meaningful forward-looking pins once
//! real subcommand parsing lands (an unknown subcommand or unreadable file
//! must still exit 2 then).

use std::path::PathBuf;
use std::process::Command;

const RHEL9_FIXTURE: &str = include_str!("fixtures/rhel9_selinux_controls.xml");

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_selinux-stig-update")
}

/// Write `content` to a unique temp file and return its path.
fn temp_xccdf(tag: &str, content: &str) -> PathBuf {
    let path =
        std::env::temp_dir().join(format!("selinux-stig-cli-{}-{tag}.xml", std::process::id()));
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

// --- exit-code contract: 0 in sync (RED today) -------------------------------

#[test]
fn check_real_rhel9_fixture_is_in_sync_with_the_shipped_table() {
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
        "the real rhel9 fixture must be in sync with stig.rs's shipped table \
         (5 rows); stdout={stdout} stderr={err}"
    );
}

// --- exit-code contract: 1 drift (RED today) --------------------------------

#[test]
fn check_file_drift_names_the_removed_v_number() {
    // Remove the FaillockDirContext Group (V-258080) so the derived set
    // drifts against the shipped table.
    let start = RHEL9_FIXTURE
        .find("<Group id=\"V-258080\"")
        .expect("V-258080 group present in fixture");
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

// --- derive: always exits 0 (a report, not a gate); RED today ---------------

#[test]
fn derive_file_exits_0_and_prints_paste_ready() {
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

// --- help/plumbing (RED today: the stub does not implement --help) ---------

#[test]
fn help_exits_0_and_documents_the_tool() {
    let (code, _out, err) = run(&["--help"]);
    assert_eq!(code, Some(0), "--help must exit 0");
    assert!(
        err.contains("drift-check the selinux"),
        "--help must describe the tool; err={err}"
    );
}

// --- exit-code contract: 2 on error, with a SPECIFIC message (RED today: the
// always-exit-2 stub satisfies the code but not the message assertions, so a
// wrong impl cannot pass these by exiting 2 unconditionally) -------------------

#[test]
fn unknown_subcommand_exits_2() {
    let (code, _out, err) = run(&["frobnicate"]);
    assert_eq!(code, Some(2));
    assert!(
        err.contains("unknown subcommand"),
        "error must name the unknown subcommand, got err={err}"
    );
}

#[test]
fn missing_file_exits_2() {
    let (code, _out, err) = run(&[
        "check",
        "--product",
        "rhel9",
        "--file",
        "/no/such/xccdf.xml",
    ]);
    assert_eq!(code, Some(2), "unreadable source must exit 2");
    assert!(
        err.contains("/no/such/xccdf.xml") || err.to_lowercase().contains("no such file"),
        "error must name the unreadable path, got err={err}"
    );
}
