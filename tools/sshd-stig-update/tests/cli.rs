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

/// Write `content` to a unique temp file (no forced extension) and return its
/// path - used by the `check-pin` tests below for both a custom
/// `stig-refs.toml` and a scripted `--fixture` answers file.
fn temp_named(tag: &str, content: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("sshd-stig-cli-{}-{tag}", std::process::id()));
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

/// #468 fail-loud guard, end to end: a benchmark carrying a directive checked ONLY
/// at runtime (`sshd -T | grep -i maxauthtries`, with NO file-grep idiom) is silently
/// skipped by the file-grep selector today, so `check` would report 0 drift and exit
/// 0 while quietly dropping a required control. The guard must instead FAIL LOUD -
/// exit 2 (the tool's fail-closed code, as for an unclassifiable rule) and name the
/// dropped directive on stderr. `maxauthtries` is absent from the rhel9 fixture, so
/// the injected Group is unambiguously the only runtime-only control.
#[test]
fn check_runtime_only_directive_fails_loud_exits_2() {
    let injected = "<Group id=\"V-800042\"><Rule><version>RHEL-09-800042</version>\
        <check><check-content>Verify the runtime configuration of the SSH daemon:\n\
        $ sudo sshd -T | grep -i maxauthtries\nmaxauthtries 3\n\
        If the value is not set to \"3\" or less, this is a finding.</check-content></check>\
        <fixtext>Add or edit the following line in /etc/ssh/sshd_config:\nMaxAuthTries 3</fixtext>\
        </Rule></Group></Benchmark>";
    let doc = GOOD_RHEL9.replace("</Benchmark>", injected);
    assert!(
        doc.contains("sshd -T | grep -i maxauthtries"),
        "the injected runtime-only Group must be present"
    );

    let f = temp_xccdf("runtimeonly", &doc);
    let (code, stdout, err) = run(&[
        "check",
        "--product",
        "rhel9",
        "--file",
        &f.to_string_lossy(),
    ]);
    assert_eq!(
        code,
        Some(2),
        "a runtime-only directive must fail loud (exit 2), not be silently skipped; \
         stdout={stdout} err={err}"
    );
    assert!(
        err.contains("maxauthtries"),
        "the fail-loud message must name the dropped directive; err={err}"
    );
    assert!(
        err.to_lowercase().contains("runtime"),
        "the fail-loud message must explain it is a runtime-only check; err={err}"
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

// --- check-pin (#550 lane-5 rework, BLOCKER 5): CLI wiring, offline --------
//
// Phase 0 already landed the `sshd-stig-check-pin` justfile recipe running
// `cargo run -- check-pin`; today that subcommand falls into the catch-all
// `unknown subcommand` branch (see `unknown_subcommand_exits_2` above - the
// SAME code path). These tests pin two things the pure `pin.rs` unit tests
// cannot: (1) `check-pin` must be a RECOGNIZED subcommand, and (2) the
// PROCESS must exit 0 for every `PinStatus`, including `Unavailable` -
// `main.rs::run`'s `Result<ExitCode, String>` maps `Err` to exit 2 (see
// `check_missing_file_exits_2` above), so an impl that wires
// `PinStatus::Unavailable` through that `Err` path would invert the
// non-blocking contract at the PROCESS boundary even if `pin::report`'s own
// `u8` were correct in isolation.
//
// Since CI must not depend on the network (#550's central constraint), these
// tests never invoke `check-pin` without a `--fixture`: a NEW, test-only CLI
// flag this test file's contract requires the implementer to add, mirroring
// `--file`'s existing "offline override" precedent for `check`/`derive`.
// `--fixture <path>` requires exactly one `--product` (same rule as
// `--file`) and reads a plain-text file, one line per probe IN ORDER (the
// same order `pin::Prober::probe` is called in): `FOUND`, `NOTFOUND`, or
// `ERR:<message>`. The implementer wires this into an in-process fake
// `Prober` reading those lines; no real `curl` call happens when `--fixture`
// is given.

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
    // `check_unclassifiable_rule_exits_2` above). An impl that wires
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
