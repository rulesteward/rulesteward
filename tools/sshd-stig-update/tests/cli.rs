//! End-to-end CLI tests: exercise the built binary offline (via `check`/`derive
//! --file`) and assert the exit-code contract - 0 in sync, 1 on drift, 2 on error.

use std::path::PathBuf;
use std::process::Command;

const GOOD_RHEL9: &str = include_str!("fixtures/rhel9_sshd_controls.xml");

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_sshd-stig-update")
}

/// Write `content` to a unique temp file and return its path.
fn temp_xccdf(tag: &str, content: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("sshd-stig-cli-{}-{tag}.xml", std::process::id()));
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

#[test]
fn check_file_in_sync_exits_0() {
    let f = temp_xccdf("insync", GOOD_RHEL9);
    let (code, stdout, _err) = run(&[
        "check",
        "--product",
        "rhel9",
        "--file",
        &f.to_string_lossy(),
    ]);
    assert_eq!(code, Some(0), "in-sync must exit 0; stdout={stdout}");
    assert!(stdout.contains("OK (0 drift"), "stdout={stdout}");
}

#[test]
fn check_file_drift_exits_1() {
    // Remove the Banner Group so the derived set is missing a required directive.
    let start = GOOD_RHEL9
        .find("<Group id=\"V-257981\"")
        .expect("banner group present");
    let end = GOOD_RHEL9[start..].find("</Group>").expect("group end") + start + "</Group>".len();
    let mut drifted = GOOD_RHEL9.to_string();
    drifted.replace_range(start..end, "");

    let f = temp_xccdf("drift", &drifted);
    let (code, stdout, _err) = run(&[
        "check",
        "--product",
        "rhel9",
        "--file",
        &f.to_string_lossy(),
    ]);
    assert_eq!(code, Some(1), "drift must exit 1; stdout={stdout}");
    assert!(stdout.contains("DRIFT"), "stdout={stdout}");
    assert!(
        stdout.contains("banner"),
        "the drift must name banner; stdout={stdout}"
    );
    // The DRIFT footer must name every map a human might need to reconcile,
    // including RHEL*_RULE_ID (issue #507): a rule_id-only drift is only fixed by
    // editing that map, so omitting it from the guidance misdirects the reader.
    assert!(
        stdout.contains("RHEL*_RULE_ID"),
        "the DRIFT footer must name RHEL*_RULE_ID in the maps-to-update list; stdout={stdout}"
    );
}

#[test]
fn check_unclassifiable_rule_exits_2() {
    // A Rule the selector picks (grep idiom + sshd_config) but with no fixtext config
    // line -> the parser fails closed -> the process exits 2.
    let doc = "<Benchmark><Group id=\"V-42\"><Rule><version>RHEL-09-999999</version>\
        <check><check-content>xargs sudo grep -iH '^\\s*permitrootlogin' /etc/ssh/sshd_config\
        </check-content></check><fixtext>Configure the daemon. See sshd_config.</fixtext>\
        </Rule></Group></Benchmark>";
    let f = temp_xccdf("unclass", doc);
    let (code, _out, err) = run(&[
        "check",
        "--product",
        "rhel9",
        "--file",
        &f.to_string_lossy(),
    ]);
    assert_eq!(code, Some(2), "unclassifiable Rule must exit 2");
    assert!(err.contains("no canonical config line"), "err={err}");
}

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
    assert!(err.contains("sshd-stig-update:"), "err={err}");
}

#[test]
fn check_file_without_product_exits_2() {
    let f = temp_xccdf("noproduct", GOOD_RHEL9);
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
fn derive_file_exits_0_and_reproduces_table() {
    let f = temp_xccdf("derive", GOOD_RHEL9);
    let (code, stdout, _err) = run(&[
        "derive",
        "--product",
        "rhel9",
        "--file",
        &f.to_string_lossy(),
    ]);
    assert_eq!(code, Some(0));
    assert!(
        stdout.contains("no drift vs the shipped table"),
        "stdout={stdout}"
    );
    assert!(
        stdout.contains("(\"permitrootlogin\", \"V-257985\")"),
        "stdout={stdout}"
    );
    // The paste-ready output must also emit a RHEL9_RULE_ID block (issue #507),
    // so a human reconciling a rule_id drift has the map contents to paste. The
    // permitrootlogin Rule id is RHEL-09-255045 (shipped RHEL9_RULE_ID map,
    // 0-drift against the rhel9 fixture).
    assert!(
        stdout.contains("RHEL9_RULE_ID"),
        "derive must emit a paste-ready RHEL9_RULE_ID block; stdout={stdout}"
    );
    assert!(
        stdout.contains("(\"permitrootlogin\", \"RHEL-09-255045\")"),
        "the RHEL9_RULE_ID block must carry the real permitrootlogin Rule id; stdout={stdout}"
    );
}

#[test]
fn unknown_subcommand_exits_2() {
    let (code, _out, err) = run(&["frobnicate"]);
    assert_eq!(code, Some(2));
    assert!(err.contains("unknown subcommand"), "err={err}");
}

#[test]
fn help_exits_0() {
    let (code, _out, err) = run(&["--help"]);
    assert_eq!(code, Some(0));
    assert!(
        err.contains("drift-check the sshd W01/W02 STIG baselines"),
        "err={err}"
    );
}
