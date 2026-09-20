//! The CLI and output contract, DESIGN.md §9.
//!
//! These are commitments, not conveniences: the domain slot has to stay spendable for
//! `selinux` and whatever follows, so anything that would quietly turn `fapolicyd`
//! into an optional word belongs here as a failing case.

mod common;

/// The code and both streams as strings: every assertion below reads them that way.
fn run(args: &[&str], stdin: &[u8]) -> (i32, String, String) {
    let out = common::run(args, stdin);
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
    // `analyze` was the v0.3.0-unreleased action and is now three. It is a usage error
    // and never an alias for any of them, because §9 forbids aliases — and neither is
    // a near-miss spelling of `why`.
    for bad in ["analyse", "analyze", "explain", "whys", "checks"] {
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

// `why` writes a report and not an artifact (#76): run-level comments plus one line
// per denying rule, and nothing that belongs to a single input line.

#[test]
fn why_stdout_is_one_line_per_rule_and_comments() {
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/rocky9-journal-live-vm-short.log"
    );
    let input = std::fs::read(fixture).expect("read fixture");
    let (code, out, err) = run(&["fapolicyd", "--no-conf", "why"], &input);
    assert_eq!(code, 0, "{err}");
    assert!(err.is_empty(), "{err}");
    for line in out.lines() {
        assert!(
            line.starts_with("# ") || line.starts_with("rule="),
            "not a why line: {line}"
        );
    }
    let numbers: Vec<&str> = out
        .lines()
        .filter(|l| l.starts_with("rule="))
        .map(|l| l.split_whitespace().next().expect("a first column"))
        .collect();
    assert_eq!(numbers, ["rule=5", "rule=8", "rule=13"], "{out}");
    // D2: every per-line note is dropped, so no comment may name a line.
    assert!(!out.contains("# rulesteward: line "), "{out}");
}

#[test]
fn why_names_the_rules_d_file_and_the_subject_side_verdict() {
    let conf = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/conf/default.conf"
    );
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/rocky9-journal-live-vm-short.log"
    );
    let input = std::fs::read(fixture).expect("read fixture");
    let (code, out, err) = run(&["fapolicyd", "--conf", conf, "why"], &input);
    assert_eq!(code, 0, "{err}");
    assert!(err.is_empty(), "{err}");

    let line = out
        .lines()
        .find(|l| l.starts_with("rule=5 "))
        .expect("a rule=5 line");
    assert_eq!(
        line.split_whitespace().collect::<Vec<_>>().join(" "),
        "rule=5 30-patterns.rules 22 denials subject-side, nothing to emit \
         deny_audit perm=any pattern=ld_so : all",
        "{out}"
    );

    // The columns are padded to the run's widest value, so every count ends at the
    // same offset whatever the rule number and filename around it are.
    let offsets: Vec<Option<usize>> = out
        .lines()
        .filter(|l| l.starts_with("rule="))
        .map(|l| l.find("denials"))
        .collect();
    assert_eq!(offsets.len(), 3, "{out}");
    assert!(
        offsets.iter().all(|o| *o == offsets[0] && o.is_some()),
        "counts are not aligned: {out}"
    );
}

#[test]
fn why_without_a_rules_file_prints_numbers_and_counts() {
    // No rules file means no filename, no verdict and no rule text, so those columns
    // collapse: the line is the number and the count and nothing after it.
    let (code, out, err) = run(&["fapolicyd", "--no-conf", "why"], DENIED_BY_13);
    assert_eq!(code, 0, "{err}");
    let rules: Vec<&str> = out.lines().filter(|l| l.starts_with("rule=")).collect();
    assert_eq!(rules, ["rule=13  1 denials"], "{out}");
}

/// One denied `execve` as `ausearch -m FANOTIFY --raw` writes it (#87), trimmed to the
/// fields the reader looks at. `fan_info=D` is rule 13, and `items=2` is what makes
/// `item=0` the binary rather than the loader.
const AUDIT_EXEC: &[u8] = b"\
type=FANOTIFY msg=audit(1789678619.719:7454): resp=1 fan_type=1 fan_info=D subj_trust=2 obj_trust=0\x1d
type=SYSCALL msg=audit(1789678619.719:7454): arch=c000003e syscall=59 success=yes items=2 pid=91726 auid=1000 uid=1001 exe=\"/tmp/live/probe-grep\" key=\"rulesteward-live\"\x1dARCH=x86_64
type=PATH msg=audit(1789678619.719:7454): item=0 name=\"/tmp/live/probe-grep\" nametype=NORMAL cap_frootid=0\x1dOUID=\"root\"
type=PATH msg=audit(1789678619.719:7454): item=1 name=\"/lib64/ld-linux-x86-64.so.2\" nametype=NORMAL cap_frootid=0\x1dOUID=\"root\"
";

/// The same route with no exit rule loaded: the kernel collected no name, so the event
/// is FANOTIFY and SYSCALL only and there is no object to act on.
const AUDIT_NO_PATH: &[u8] = b"\
type=FANOTIFY msg=audit(1789678611.043:7402): resp=1 fan_type=1 fan_info=8 subj_trust=2 obj_trust=0\x1d
type=SYSCALL msg=audit(1789678611.043:7402): arch=c000003e syscall=257 success=yes items=0 pid=91648 auid=1000 uid=1001 exe=\"/usr/bin/cat\" key=(null)\x1dARCH=x86_64
";

#[test]
fn an_audit_event_with_no_path_is_a_success_that_names_both_fixes() {
    // Nothing to emit is not a failure (§9), and the run-level note has to carry both
    // ways out: load an exit rule, or take the journal route instead.
    let (code, out, err) = run(&["fapolicyd", "--no-conf", "rules"], AUDIT_NO_PATH);
    assert_eq!(code, 0, "{err}");
    assert!(err.is_empty(), "{err}");
    assert!(
        out.lines().all(|l| l.starts_with('#')),
        "the rules artifact has to be empty: {out}"
    );
    assert!(out.contains("no PATH record"), "{out}");
    assert!(out.contains("auditctl -a always,exit"), "{out}");
    assert!(out.contains("journal route"), "{out}");
}

#[test]
fn why_counts_the_rule_an_audit_record_names_in_hex() {
    // `fan_info=D` is the shipped rule 13. Without a rules file the verdict and text
    // columns collapse, exactly as they do for a daemon record.
    let (code, out, err) = run(&["fapolicyd", "--no-conf", "why"], AUDIT_EXEC);
    assert_eq!(code, 0, "{err}");
    let rules: Vec<&str> = out.lines().filter(|l| l.starts_with("rule=")).collect();
    assert_eq!(rules, ["rule=13  1 denials"], "{out}");
}

/// #121: a named `PATH` that cannot be read is §9's exit 1 and not a diagnostic, because
/// a verdict against rules that were never read would be a verdict about nothing. An
/// absent `PATH` is a different question and not an error (#158, below).
#[test]
fn check_without_a_readable_path_is_a_usage_error() {
    let (code, _, err) = run(
        &["fapolicyd", "--no-conf", "check", "/nonexistent/x.rules"],
        DENIAL,
    );
    assert_eq!(code, 1, "{err}");
    assert!(err.contains("/nonexistent/x.rules"), "{err}");
    assert!(!err.starts_with("# "), "errors are not comments: {err}");

    // fagenrules merges `*.rules` and nothing else, so a candidate under any other name
    // is a file the daemon would never read.
    let conf = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/conf/default.conf"
    );
    let (code, _, err) = run(&["fapolicyd", "--no-conf", "check", conf], DENIAL);
    assert_eq!(code, 1, "{err}");
    assert!(err.contains("*.rules"), "{err}");
}

/// The report is a report: every denial gets a line whatever the answer is, and nothing
/// about it is an error. `--no-conf` leaves no host to place the candidates against, so
/// the honest verdict for all of them is `unknown` -- never `denied`.
#[test]
fn check_reports_every_denial_and_exits_0() {
    let candidate = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/check/00-cand.rules"
    );
    let (code, out, err) = run(&["fapolicyd", "--no-conf", "check", candidate], DENIAL);
    assert_eq!(code, 0, "{err}");
    assert!(err.is_empty(), "{err}");
    let lines: Vec<&str> = out.lines().filter(|l| !l.starts_with("# ")).collect();
    assert_eq!(lines.len(), 1, "{out}");
    assert!(lines[0].starts_with("unknown "), "{out}");
    assert!(lines[0].contains("path=/tmp/x rule=1"), "{out}");
}

/// The candidate file is sorted into the host's rules.d/ under its own name, so the
/// filename is what decides whether a rule is reached before the one that denied. Same
/// rule, two names, two verdicts -- #120's `exec-before-N` and `exec-after-N`.
#[test]
fn a_candidate_is_placed_by_its_filename() {
    let conf = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/conf/default.conf"
    );
    let dir = std::env::temp_dir().join("rulesteward-check-placement");
    let rule = b"allow perm=execute all : path=/tmp/gaps/trusted-ls\n";
    for (name, want) in [("00-cand.rules", "allowed "), ("99-cand.rules", "denied ")] {
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join(name);
        std::fs::write(&path, rule).expect("write candidate");
        let (code, out, err) = run(
            &["fapolicyd", "--conf", conf, "check", path.to_str().unwrap()],
            DENIED_BY_13,
        );
        assert_eq!(code, 0, "{err}");
        let line = out
            .lines()
            .find(|l| !l.starts_with("# "))
            .unwrap_or_default();
        assert!(line.starts_with(want), "{name}: {out}");
        std::fs::remove_file(&path).expect("remove candidate");
    }
}

/// #158: with no `PATH` the proposal is the host's own `rules.d/` beside `--conf`, and
/// the baseline is `compiled.rules` — what the daemon actually loaded. An operator who
/// edited `rules.d/` in place and has not run fagenrules yet is exactly that
/// disagreement, so the edit has to read as a candidate and not as drift. The same
/// record and the same record's `rule=` against two confs: the verdict follows the
/// directory `--conf` names.
#[test]
fn the_default_path_is_the_rules_d_beside_conf() {
    for (conf, want) in [
        (
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/conf/default.conf"
            ),
            "denied ",
        ),
        (
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/conf/edited/fapolicyd.conf"
            ),
            "allowed ",
        ),
    ] {
        let (code, out, err) = run(&["fapolicyd", "--conf", conf, "check"], DENIED_BY_13);
        assert_eq!(code, 0, "{err}");
        assert!(err.is_empty(), "{err}");
        let line = out
            .lines()
            .find(|l| !l.starts_with("# "))
            .unwrap_or_default();
        assert!(line.starts_with(want), "{conf}: {out}");
        assert_eq!(
            out.contains("nothing is proposed"),
            want == "denied ",
            "the edited directory proposes something and the unedited one does not: {out}"
        );
    }
}

/// A `rules.d/` that still merges to `compiled.rules` proposes nothing at all, which is a
/// different answer from "every candidate was checked and none matched" and is said as a
/// diagnostic rather than left for the reader to infer from fourteen `denied` lines.
#[test]
fn an_unedited_rules_d_proposes_nothing() {
    let conf = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/conf/default.conf"
    );
    let (code, out, err) = run(&["fapolicyd", "--conf", conf, "check"], DENIED_BY_13);
    assert_eq!(code, 0, "{err}");
    assert!(err.is_empty(), "{err}");
    assert!(
        out.contains("# rulesteward: ") && out.contains("nothing is proposed"),
        "the diagnostic is a comment on stdout: {out}"
    );
}

/// A `%set` is in neither `rules::parse`'s output nor a rule number, so a `rules.d/`
/// whose only edit is a set definition merges to `compiled.rules` rule for rule and is
/// not the directory the daemon loaded. Claiming nothing is proposed there is a claim
/// about a file that changed.
#[test]
fn a_changed_set_definition_is_not_nothing_proposed() {
    let conf = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/conf/edited-set/fapolicyd.conf"
    );
    let (code, out, err) = run(&["fapolicyd", "--conf", conf, "check"], DENIED_BY_13);
    assert_eq!(code, 0, "{err}");
    assert!(
        !out.contains("nothing is proposed"),
        "the set definition is what changed: {out}"
    );
}

/// D3 skips the rules before N because the daemon walked past them, and that proof holds
/// only while the sets they name hold. Here the record's own ftype was added to
/// `%languages`, so the deny naming that set now matches and is reached before the new
/// allow. `allowed` would be the wrong answer the issue's hazard forbids; what this tool
/// may say is that it cannot decide, naming the rule.
#[test]
fn a_rule_naming_a_changed_set_is_evaluated_and_not_skipped() {
    let conf = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/conf/edited-set-and-rule/fapolicyd.conf"
    );
    let (code, out, err) = run(&["fapolicyd", "--conf", conf, "check"], DENIED_BY_13);
    assert_eq!(code, 0, "{err}");
    let line = out
        .lines()
        .find(|l| !l.starts_with("# "))
        .unwrap_or_default();
    assert!(line.starts_with("unknown "), "{out}");
    assert!(line.contains("ftype=%languages"), "{out}");
}

/// The default path is read beside `--conf`, so `--no-conf` leaves it nowhere to resolve
/// to. That is a usage error and not a run of unknowns, and it names both ways out.
///
/// The stdin is empty on purpose: the exit is before the stdin read, so a record written
/// to it races the child closing the pipe and fails the write with `BrokenPipe`.
#[test]
fn check_with_no_conf_and_no_path_is_a_usage_error() {
    let (code, out, err) = run(&["fapolicyd", "--no-conf", "check"], b"");
    assert_eq!(code, 1, "{err}");
    assert!(out.is_empty(), "{out}");
    assert!(err.contains("PATH") && err.contains("--no-conf"), "{err}");
}

/// A host loading a legacy `fapolicyd.rules` never reads `rules.d/`, so the default has
/// nothing to propose and no verdict can be placed against what is in that directory. The
/// run says which file the daemon loads rather than answering from the wrong one.
#[test]
fn a_legacy_rules_file_leaves_the_default_nothing_to_check() {
    let conf = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/conf/legacy/fapolicyd.conf"
    );
    let (code, out, err) = run(&["fapolicyd", "--conf", conf, "check"], DENIAL);
    assert_eq!(code, 0, "{err}");
    assert!(err.is_empty(), "{err}");
    assert!(out.contains("fapolicyd.rules"), "{out}");
    let line = out
        .lines()
        .find(|l| !l.starts_with("# "))
        .unwrap_or_default();
    assert!(line.starts_with("unknown "), "{out}");
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

/// D6: both artifacts come out of `build.rs` on every plain build, with no feature
/// gate, so the RPM can never ship a stale one. `.TH` is not the first line of the
/// page -- clap_mangen emits the `\*(Aq` quote definition ahead of it -- so the header
/// is matched anywhere rather than at the start.
#[test]
fn every_build_generates_the_man_page_and_the_bash_completion() {
    let out = std::path::Path::new(env!("OUT_DIR"));
    let page = std::fs::read_to_string(out.join("rulesteward.1")).unwrap();
    assert!(page.contains(".TH rulesteward 1"), "{page}");
    let bash = std::fs::read_to_string(out.join("rulesteward.bash")).unwrap();
    assert!(bash.contains("complete -F _rulesteward"), "{bash}");
}
