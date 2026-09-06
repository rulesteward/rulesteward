//! The CLI and output contract, DESIGN.md §9.
//!
//! These are commitments, not conveniences: the domain slot has to stay spendable for
//! `selinux` and whatever follows, so anything that would quietly turn `fapolicyd`
//! into an optional word belongs here as a failing case.

use std::io::Write;
use std::process::{Command, Stdio};

fn run(args: &[&str], stdin: &[u8]) -> (i32, String, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_rulesteward"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(stdin)
        .expect("write");
    let out = child.wait_with_output().expect("wait");
    (
        out.status.code().unwrap(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

const DENIAL: &[u8] =
    b"rule=1 dec=deny_audit perm=open auid=1000 pid=1 exe=/usr/bin/bash : path=/tmp/x trust=0\n";

#[test]
fn no_arguments_lists_the_domains_and_exits_1() {
    let (code, _, err) = run(&[], b"");
    assert_eq!(code, 1, "stderr: {err}");
    assert!(err.contains("fapolicyd"), "should name the domains: {err}");
}

#[test]
fn there_is_no_bare_action_form() {
    // `rulesteward analyze` must never become an alias, or the domain slot is spent.
    let (code, _, _) = run(&["analyze"], b"");
    assert_eq!(code, 1);
}

#[test]
fn the_domain_cannot_be_abbreviated() {
    // clap v4 defaults infer_subcommands to false. If someone turns it on, a future
    // domain starting with "fap" collides with a prefix people got used to typing.
    for bad in [
        ["fapo", "analyze"],
        ["fap", "analyze"],
        ["fapolicy", "analyze"],
    ] {
        let (code, _, _) = run(&bad, b"");
        assert_eq!(code, 1, "{bad:?} must not resolve to fapolicyd");
    }
}

#[test]
fn the_action_is_not_spelled_the_other_way() {
    let (code, _, _) = run(&["fapolicyd", "analyse"], b"");
    assert_eq!(code, 1);
}

#[test]
fn conf_and_no_conf_are_mutually_exclusive() {
    // D9 puts both flags on the domain, so they can arrive on either side of the
    // action — including one on each side, which is the ordering clap's own
    // `conflicts_with` does not catch. All four have to be rejected.
    for args in [
        ["fapolicyd", "--no-conf", "--conf", "/dev/null", "analyze"],
        ["fapolicyd", "analyze", "--no-conf", "--conf", "/dev/null"],
        ["fapolicyd", "--no-conf", "analyze", "--conf", "/dev/null"],
        ["fapolicyd", "--conf", "/dev/null", "analyze", "--no-conf"],
    ] {
        let (code, _, err) = run(&args, b"");
        assert_eq!(code, 1, "{args:?} should be a usage error");
        assert!(err.contains("--no-conf"), "{args:?}: {err}");
    }
}

#[test]
fn the_domain_flags_are_accepted_before_the_action() {
    // D9: `--conf`/`--no-conf` belong to `fapolicyd`, not to `analyze`, so this form
    // has to work as well as the trailing one.
    let (code, out, _) = run(&["fapolicyd", "--no-conf", "analyze"], DENIAL);
    assert_eq!(code, 0);
    assert_eq!(
        out,
        "fapolicyd-cli --file add '/tmp/x'\nfapolicyd-cli --update\n"
    );
}

/// A denial that carries every field the shipped `syslog_format` names except the
/// last one, `trust=`. Whether that is a whole record or a truncated one is exactly
/// what §6's ladder decides, and the answer depends on whether a conf was read.
const NO_TRUST: &[u8] = b"rule=1 dec=deny_audit perm=open auid=1000 pid=1 \
exe=/usr/bin/bash : path=/tmp/x ftype=text/plain\n";

#[test]
fn a_conf_turns_a_missing_field_into_a_truncation_refusal() {
    // §6 step 3: with the format in hand the missing `trust=` names itself, and a
    // truncated record is not acted on — `path=` may be a prefix of the real path.
    let conf = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/conf/default.conf"
    );
    let (code, out, err) = run(&["fapolicyd", "--conf", conf, "analyze"], NO_TRUST);
    assert_eq!(code, 0, "a truncated record is not a failed run: {err}");
    assert!(out.is_empty(), "nothing may be emitted: {out}");
    assert!(err.contains("truncated"), "{err}");
    assert!(
        err.contains("trust="),
        "should name the missing field: {err}"
    );
}

#[test]
fn the_same_record_without_a_conf_falls_through_to_the_rule_arm() {
    // §6 step 4 is the only test left, and 92 bytes is nowhere near the 511-byte cap,
    // so the record reads as whole and `trust` absent means D12's rule.
    let (code, out, err) = run(&["fapolicyd", "--no-conf", "analyze"], NO_TRUST);
    assert_eq!(code, 0);
    assert_eq!(out, "allow perm=open exe=/usr/bin/bash : path=/tmp/x\n");
    assert!(err.contains("no trust= in this record"), "{err}");
}

#[test]
fn a_commented_out_example_record_is_not_analysed() {
    // F3: the framing prefix is stripped AFTER the `#` test. A research capture
    // annotates its interesting records as `# record: ...`, prefix and all, and
    // stripping first turned one of them into a trust entry.
    let commented = b"# record: 09/06/26 00:00:00 [ DEBUG ]: rule=2 dec=deny_audit \
perm=open exe=/usr/bin/x : path=/etc/login.defs trust=0\n";
    let (code, out, _) = run(&["fapolicyd", "--no-conf", "analyze"], commented);
    assert_eq!(code, 0, "a file of comments is not unparseable input");
    assert!(out.is_empty(), "a comment is not a record: {out}");
}

#[test]
fn a_denial_under_a_path_containing_deprecated_is_still_emitted() {
    // F2: the noise filter drops the SHA256HASH deprecation notice, which it must
    // anchor on both words — `deprecated` alone also matches /opt/deprecated.
    let denial = b"rule=1 dec=deny_audit perm=open auid=1000 pid=1 exe=/usr/bin/bash \
: path=/opt/deprecated/x trust=0\n";
    let (code, out, _) = run(&["fapolicyd", "--no-conf", "analyze"], denial);
    assert_eq!(code, 0);
    assert_eq!(
        out,
        "fapolicyd-cli --file add '/opt/deprecated/x'\nfapolicyd-cli --update\n"
    );
}

#[test]
fn help_and_version_are_successes_not_usage_errors() {
    // They arrive from clap as errors, and clap's own exit code for those is 2 —
    // which §9 reserves for unparseable input.
    for arg in ["--help", "--version"] {
        let (code, out, _) = run(&[arg], b"");
        assert_eq!(code, 0, "{arg} should exit 0");
        assert!(!out.is_empty(), "{arg} should print something");
    }
}

#[test]
fn a_good_capture_exits_0_with_bare_lines_on_stdout() {
    let (code, out, _) = run(&["fapolicyd", "analyze", "--no-conf"], DENIAL);
    assert_eq!(code, 0);
    assert_eq!(
        out,
        "fapolicyd-cli --file add '/tmp/x'\nfapolicyd-cli --update\n"
    );
}

#[test]
fn unparseable_input_exits_2() {
    let (code, out, _) = run(
        &["fapolicyd", "analyze", "--no-conf"],
        b"not a record\nnor this\n",
    );
    assert_eq!(code, 2);
    assert!(out.is_empty());
}

#[test]
fn a_log_with_no_denials_is_a_success_not_a_parse_failure() {
    // "No denials found" is the answer, not an error. §9's exit 2 is about input we
    // could not read, and an allow record reads perfectly well.
    let allow =
        b"rule=3 dec=allow perm=open auid=1000 pid=1 exe=/usr/bin/bash : path=/tmp/x trust=1\n";
    let (code, out, _) = run(&["fapolicyd", "analyze", "--no-conf"], allow);
    assert_eq!(code, 0);
    assert!(out.is_empty());
}

#[test]
fn empty_input_is_a_success() {
    let (code, out, _) = run(&["fapolicyd", "analyze", "--no-conf"], b"");
    assert_eq!(code, 0);
    assert!(out.is_empty());
}

#[test]
fn a_missing_conf_degrades_with_a_diagnostic_and_never_exits() {
    // §6 step 2: the packaged /etc/fapolicyd is 750 root:fapolicyd, so this read
    // failing is the ordinary case, not an error condition.
    let (code, out, err) = run(
        &[
            "fapolicyd",
            "analyze",
            "--conf",
            "/nonexistent/fapolicyd.conf",
        ],
        DENIAL,
    );
    assert_eq!(code, 0, "a failed conf read must not fail the run");
    assert!(err.contains("511-byte"), "should name the fallback: {err}");
    assert!(out.contains("--file add"), "should still emit: {out}");
}
