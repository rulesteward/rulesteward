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

/// §6 step 2: the packaged /etc/fapolicyd is 750 root:fapolicyd, so a conf read failing
/// is the ordinary case. Two tests run it, for the degradation and for the stream.
const MISSING_CONF: [&str; 4] = [
    "fapolicyd",
    "trust",
    "--conf",
    "/nonexistent/fapolicyd.conf",
];

#[test]
fn no_arguments_lists_the_domains_and_exits_1() {
    let (code, _, err) = run(&[], b"");
    assert_eq!(code, 1, "stderr: {err}");
    assert!(err.contains("fapolicyd"), "should name the domains: {err}");
}

#[test]
fn there_is_no_bare_action_form() {
    // `rulesteward rules` must never become an alias, or the domain slot is spent.
    for bad in ["rules", "trust"] {
        let (code, _, _) = run(&[bad], b"");
        assert_eq!(code, 1, "{bad} must not be a bare action");
    }
}

#[test]
fn the_domain_cannot_be_abbreviated() {
    // clap v4 defaults infer_subcommands to false. If someone turns it on, a future
    // domain starting with "fap" collides with a prefix people got used to typing.
    for bad in [["fapo", "rules"], ["fap", "rules"], ["fapolicy", "trust"]] {
        let (code, _, _) = run(&bad, b"");
        assert_eq!(code, 1, "{bad:?} must not resolve to fapolicyd");
    }
}

#[test]
fn the_action_is_not_spelled_the_other_way() {
    // `analyze` was the v0.3.0-unreleased action and is now two. It is a usage error
    // and never an alias for either of them, because §9 forbids aliases.
    for bad in ["analyse", "analyze"] {
        let (code, _, _) = run(&["fapolicyd", bad], b"");
        assert_eq!(code, 1, "{bad} must be a usage error");
    }
}

#[test]
fn conf_and_no_conf_are_mutually_exclusive() {
    // D9 puts both flags on the domain, so they can arrive on either side of the
    // action — including one on each side, which is the ordering clap's own
    // `conflicts_with` does not catch. All four have to be rejected.
    for args in [
        ["fapolicyd", "--no-conf", "--conf", "/dev/null", "rules"],
        ["fapolicyd", "rules", "--no-conf", "--conf", "/dev/null"],
        ["fapolicyd", "--no-conf", "trust", "--conf", "/dev/null"],
        ["fapolicyd", "--conf", "/dev/null", "trust", "--no-conf"],
    ] {
        let (code, _, err) = run(&args, b"");
        assert_eq!(code, 1, "{args:?} should be a usage error");
        assert!(err.contains("--no-conf"), "{args:?}: {err}");
    }
}

#[test]
fn the_domain_flags_are_accepted_before_the_action() {
    // D9: `--conf`/`--no-conf` belong to `fapolicyd`, not to the action, so this form
    // has to work as well as the trailing one.
    let (code, out, _) = run(&["fapolicyd", "--no-conf", "trust"], DENIAL);
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
    let (code, out, err) = run(&["fapolicyd", "--conf", conf, "rules"], NO_TRUST);
    assert_eq!(code, 0, "a truncated record is not a failed run: {err}");
    assert!(!out.contains("allow "), "nothing may be emitted: {out}");
    assert!(err.is_empty(), "a refusal is not an error: {err}");
    assert!(
        out.contains("# rulesteward: line 1: record truncated"),
        "{out}"
    );
    assert!(
        out.contains("trust="),
        "should name the missing field: {out}"
    );
}

#[test]
fn the_same_record_without_a_conf_falls_through_to_the_rule_arm() {
    // §6 step 4 is the only test left, and 92 bytes is nowhere near the 511-byte cap,
    // so the record reads as whole and `trust` absent means D12's rule.
    let (code, out, err) = run(&["fapolicyd", "--no-conf", "rules"], NO_TRUST);
    assert_eq!(code, 0);
    assert!(
        out.ends_with("allow perm=open exe=/usr/bin/bash : path=/tmp/x\n"),
        "{out}"
    );
    assert!(err.is_empty(), "{err}");
    assert!(
        out.contains("# rulesteward: line 1: no trust= in this record"),
        "{out}"
    );
}

#[test]
fn a_commented_out_example_record_is_not_analysed() {
    // F3: the framing prefix is stripped AFTER the `#` test. A research capture
    // annotates its interesting records as `# record: ...`, prefix and all, and
    // stripping first turned one of them into a trust entry.
    let commented = b"# record: 09/06/26 00:00:00 [ DEBUG ]: rule=2 dec=deny_audit \
perm=open exe=/usr/bin/x : path=/etc/login.defs trust=0\n";
    let (code, out, _) = run(&["fapolicyd", "--no-conf", "rules"], commented);
    assert_eq!(code, 0, "a file of comments is not unparseable input");
    assert!(out.is_empty(), "a comment is not a record: {out}");
}

#[test]
fn a_denial_under_a_path_containing_deprecated_is_still_emitted() {
    // F2: the noise filter drops the SHA256HASH deprecation notice, which it must
    // anchor on both words — `deprecated` alone also matches /opt/deprecated.
    let denial = b"rule=1 dec=deny_audit perm=open auid=1000 pid=1 exe=/usr/bin/bash \
: path=/opt/deprecated/x trust=0\n";
    let (code, out, _) = run(&["fapolicyd", "--no-conf", "trust"], denial);
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
    let (code, out, _) = run(&["fapolicyd", "trust", "--no-conf"], DENIAL);
    assert_eq!(code, 0);
    assert_eq!(
        out,
        "fapolicyd-cli --file add '/tmp/x'\nfapolicyd-cli --update\n"
    );
}

#[test]
fn unparseable_input_exits_2() {
    let (code, out, _) = run(
        &["fapolicyd", "rules", "--no-conf"],
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
    let (code, out, _) = run(&["fapolicyd", "rules", "--no-conf"], allow);
    assert_eq!(code, 0);
    assert!(out.is_empty());
}

#[test]
fn empty_input_is_a_success() {
    let (code, out, _) = run(&["fapolicyd", "rules", "--no-conf"], b"");
    assert_eq!(code, 0);
    assert!(out.is_empty());
}

#[test]
fn a_missing_conf_degrades_with_a_diagnostic_and_never_exits() {
    // §6 step 2: the packaged /etc/fapolicyd is 750 root:fapolicyd, so this read
    // failing is the ordinary case, not an error condition.
    let (code, out, err) = run(&MISSING_CONF, DENIAL);
    assert_eq!(code, 0, "a failed conf read must not fail the run");
    assert!(
        out.contains("# rulesteward: cannot read /nonexistent/fapolicyd.conf"),
        "the note is a comment on stdout: {out}"
    );
    assert!(out.contains("511-byte"), "should name the fallback: {out}");
    assert!(out.contains("--file add"), "should still emit: {out}");
    assert!(err.is_empty(), "{err}");
}

/// #10, end to end: the rules file is found beside the conf, `rule=5` resolves to the
/// shipped `pattern=ld_so` deny, and every record it denied is refused.
#[test]
fn a_conf_finds_the_rules_beside_it_and_refuses_the_subject_side_rule() {
    let conf = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/conf/default.conf"
    );
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/rocky9-journal-live-vm-short.log"
    );
    let input = std::fs::read(fixture).expect("read fixture");
    let (code, out, err) = run(&["fapolicyd", "--conf", conf, "trust"], &input);
    assert_eq!(code, 0, "{err}");
    assert!(
        out.ends_with(
            "fapolicyd-cli --file add '/tmp/live/probe-grep'\n\
             fapolicyd-cli --update\n\
             fapolicyd-cli --file add '/tmp/live/probe-lib.so'\n\
             fapolicyd-cli --update\n"
        ),
        "{out}"
    );
    assert!(
        !out.contains("path=/etc/hostname"),
        "the trust add issue #10 is about: {out}"
    );
    assert!(!out.contains("allow perm="), "{out}");
    assert!(err.is_empty(), "{err}");
    // Nothing is truncated, the conf names a syslog_format, the rules read succeeds and
    // no rule is suggested, so the refusal is the only comment left to write.
    assert_eq!(
        out.lines().filter(|l| l.starts_with("# ")).count(),
        1,
        "{out}"
    );
    assert!(out.contains("rule=5"), "{out}");
    assert!(out.contains("pattern=ld_so"), "{out}");
}

#[test]
fn no_conf_skips_the_rules_read_too() {
    // One flag governs both reads, which is also the golden tests' premise.
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/rocky9-journal-live-vm-short.log"
    );
    let input = std::fs::read(fixture).expect("read fixture");
    let (code, out, err) = run(&["fapolicyd", "--no-conf", "trust"], &input);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("--file add '/etc/hostname'"), "{out}");
}

#[test]
fn the_legacy_rules_file_wins_over_compiled_rules() {
    // The daemon opens fapolicyd.rules first and falls back only when that open fails,
    // so rule 1 here is the legacy file's ld_so deny and not compiled.rules' allow —
    // which would instead have emitted the trust add plus a mismatch note.
    let conf = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/conf/legacy/fapolicyd.conf"
    );
    let denial = b"rule=1 dec=deny_audit perm=open exe=/usr/bin/bash : path=/tmp/x trust=0\n";
    let (code, out, err) = run(&["fapolicyd", "--conf", conf, "rules"], denial);
    assert_eq!(code, 0, "{err}");
    assert!(!out.contains("allow "), "the legacy rule 1 refuses: {out}");
    assert!(!out.contains("--file add"), "{out}");
    // The two reads are independent: the conf itself does not exist.
    assert!(out.contains("# rulesteward: cannot read"), "{out}");
    assert!(out.contains("fapolicyd.conf"), "{out}");
    assert!(err.is_empty(), "{err}");
}

/// #30, end to end: the rule that denied is looked up in the split `rules.d/`, and the
/// suggested filename sorts before the file holding it.
const DENIED_BY_13: &[u8] = b"rule=13 dec=deny_audit perm=execute auid=1000 pid=1 \
exe=/usr/bin/bash : path=/tmp/gaps/trusted-ls ftype=application/x-executable trust=1\n";

#[test]
fn the_placement_note_names_the_rules_d_file_and_a_filename_before_it() {
    let conf = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/conf/default.conf"
    );
    let (code, out, err) = run(&["fapolicyd", "--conf", conf, "rules"], DENIED_BY_13);
    assert_eq!(code, 0, "{err}");
    assert!(
        out.ends_with("allow perm=execute exe=/usr/bin/bash : path=/tmp/gaps/trusted-ls\n"),
        "{out}"
    );
    assert!(
        out.contains("new file: rules.d/89-rulesteward.rules"),
        "{out}"
    );
    assert!(out.contains("sorts before 90-deny-execute.rules"), "{out}");
    assert!(out.contains("rule=13"), "{out}");
    assert!(
        !out.contains("30-patterns.rules"),
        "the canned example is gone: {out}"
    );
}

#[test]
fn rules_d_disagreeing_with_compiled_rules_recommends_no_filename() {
    // drifted/rules.d/ holds 13 rules and its 13th is not compiled.rules' 13th, which
    // is what a host looks like when fagenrules has not run since rules.d/ changed.
    // The merged order in hand is not the one that produced `rule=13`, so naming a
    // file from it would be a guess.
    let conf = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/conf/drifted/fapolicyd.conf"
    );
    let (code, out, err) = run(&["fapolicyd", "--conf", conf, "rules"], DENIED_BY_13);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("allow perm=execute"), "still emitted: {out}");
    assert!(out.contains("none recommended"), "{out}");
    assert!(out.contains("changed since fagenrules ran"), "{out}");
    assert!(out.contains("recapture"), "{out}");
    assert!(
        !out.contains("-rulesteward.rules"),
        "no filename may be named: {out}"
    );
}

/// #39: the two input-independent D12 advisories left the run output, so `--help` is
/// the only place they still exist. `-h` does not carry them, by design.
#[test]
fn rules_help_carries_the_two_standing_advisories() {
    let (code, out, err) = run(&["fapolicyd", "rules", "--help"], b"");
    assert_eq!(code, 0, "{err}");
    assert!(
        out.contains("legacy /etc/fapolicyd/fapolicyd.rules"),
        "{out}"
    );
    assert!(out.contains("--reload-rules exits 0"), "{out}");
    assert!(out.contains("first match wins"), "{out}");
}

// The four §9 promises of the split, one test each: what `rules` writes, what `trust`
// writes, that each names the other, and that stderr is empty in all of it.

#[test]
fn rules_stdout_is_a_rules_d_fragment() {
    let conf = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/conf/default.conf"
    );
    let (code, out, err) = run(&["fapolicyd", "--conf", conf, "rules"], DENIED_BY_13);
    assert_eq!(code, 0, "{err}");
    assert!(err.is_empty(), "{err}");
    for line in out.lines() {
        assert!(
            line.starts_with("# ") || line.starts_with("allow "),
            "not a rules.d line: {line}"
        );
    }
    assert!(out.contains("# rulesteward: new file: rules.d/"), "{out}");
}

#[test]
fn trust_stdout_is_commands_and_comments() {
    let (code, out, err) = run(&["fapolicyd", "--no-conf", "trust"], DENIAL);
    assert_eq!(code, 0, "{err}");
    assert!(err.is_empty(), "{err}");
    for line in out.lines() {
        assert!(
            line.starts_with("# ") || line.starts_with("fapolicyd-cli "),
            "not a trust line: {line}"
        );
    }
    assert!(out.contains("fapolicyd-cli --update"), "{out}");
}

#[test]
fn a_record_needing_trust_is_named_in_the_rules_output() {
    // DENIAL is trust=0, so `rules` has nothing to write for it. Saying so is how a
    // user who only ran `rules` learns the other action exists.
    let (code, out, err) = run(&["fapolicyd", "--no-conf", "rules"], DENIAL);
    assert_eq!(code, 0, "{err}");
    assert!(!out.contains("allow "), "{out}");
    assert!(
        out.contains(
            "1 untrusted path(s) need a trust entry, not a rule: run \
                      rulesteward fapolicyd trust on the same input"
        ),
        "{out}"
    );
}

#[test]
fn errors_are_the_only_thing_on_stderr() {
    // A failed conf read is a diagnostic and not an error, so it is a comment on
    // stdout and stderr stays empty. Only usage and I/O go the other way.
    let (_, out, err) = run(&MISSING_CONF, DENIAL);
    assert!(err.is_empty(), "a diagnostic is not an error: {err}");
    assert!(out.contains("# rulesteward: cannot read"), "{out}");

    let (code, _, err) = run(
        &["fapolicyd", "--no-conf", "--conf", "/dev/null", "rules"],
        b"",
    );
    assert_eq!(code, 1);
    assert!(
        err.contains("--no-conf"),
        "the flag conflict is an error: {err}"
    );
    assert!(!err.starts_with("# "), "errors are not comments: {err}");
}
