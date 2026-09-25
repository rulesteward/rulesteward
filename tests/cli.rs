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

// `rules --dir-min` and `--dir-system` (#138, #161). The flag surface is here; which
// directories group is pinned beside the grouping itself in `analyze.rs`.

/// `n` trust=1 denials sharing a perm and an exe under `dir`, differing only in the last
/// path component: what one group is made of.
fn group_in(dir: &str, n: usize) -> Vec<u8> {
    (0..n)
        .map(|i| {
            format!("dec=deny_audit perm=execute exe=/usr/bin/bash : path={dir}/f{i} trust=1\n")
        })
        .collect::<String>()
        .into_bytes()
}

/// The rules the run wrote, without the comments above them.
fn allow_lines(out: &str) -> Vec<&str> {
    out.lines().filter(|l| l.starts_with("allow ")).collect()
}

#[test]
fn without_dir_min_a_whole_directory_is_still_one_rule_per_path() {
    let (code, out, err) = run(&["fapolicyd", "--no-conf", "rules"], &group_in("/app", 5));
    assert_eq!(code, 0, "{err}");
    assert_eq!(allow_lines(&out).len(), 5, "{out}");
    assert!(!out.contains("dir="), "{out}");
}

#[test]
fn a_bare_dir_min_leaves_four_paths_alone_and_groups_five() {
    let args = ["fapolicyd", "--no-conf", "rules", "--dir-min"];
    let (code, four, err) = run(&args, &group_in("/app", 4));
    assert_eq!(code, 0, "{err}");
    assert_eq!(allow_lines(&four).len(), 4, "{four}");
    assert!(
        !four.contains("dir="),
        "four is under the default of 5: {four}"
    );

    let (code, five, err) = run(&args, &group_in("/app", 5));
    assert_eq!(code, 0, "{err}");
    assert_eq!(
        allow_lines(&five),
        ["allow perm=execute exe=/usr/bin/bash : dir=/app/"],
        "{five}"
    );
}

#[test]
fn a_grouped_rule_names_the_count_and_every_path_it_replaced() {
    // The comment is the only place the operator sees what the rule widened.
    let (code, out, err) = run(
        &["fapolicyd", "--no-conf", "rules", "--dir-min", "2"],
        &group_in("/app", 2),
    );
    assert_eq!(code, 0, "{err}");
    assert!(
        out.contains("# rulesteward: dir=/app/ replaces 2 rule"),
        "{out}"
    );
    assert!(out.contains("/app/f0 /app/f1"), "{out}");
    for line in out.lines() {
        assert!(
            line.starts_with("# ") || line.starts_with("allow "),
            "not a rules.d line: {line}"
        );
    }
}

#[test]
fn a_shared_directory_groups_only_under_dir_system() {
    let min = ["fapolicyd", "--no-conf", "rules", "--dir-min", "2"];
    let system = [
        "fapolicyd",
        "--no-conf",
        "rules",
        "--dir-min",
        "2",
        "--dir-system",
    ];
    for dir in ["/usr/bin", "/usr", "/opt", "/tmp/build"] {
        let input = group_in(dir, 2);
        let (code, out, err) = run(&min, &input);
        assert_eq!(code, 0, "{err}");
        assert!(
            !out.contains("dir="),
            "{dir} must not group on --dir-min: {out}"
        );

        let (code, out, err) = run(&system, &input);
        assert_eq!(code, 0, "{err}");
        assert_eq!(
            allow_lines(&out),
            [format!("allow perm=execute exe=/usr/bin/bash : dir={dir}/")],
            "{dir} must group under --dir-system: {out}"
        );
    }
}

#[test]
fn a_dir_min_below_two_is_a_usage_error() {
    // One path is not a group, and §9 maps a usage error to 1 rather than clap's 2.
    for n in ["1", "0"] {
        let (code, _, err) = run(&["fapolicyd", "--no-conf", "rules", "--dir-min", n], b"");
        assert_eq!(code, 1, "--dir-min {n} must be a usage error: {err}");
    }
}

#[test]
fn dir_system_without_dir_min_is_a_usage_error() {
    // It lifts refusals that only the grouping makes, so alone it means nothing.
    let (code, _, err) = run(&["fapolicyd", "--no-conf", "rules", "--dir-system"], b"");
    assert_eq!(code, 1, "{err}");
}

#[test]
fn the_grouping_flags_belong_to_rules_alone() {
    for action in ["trust", "why", "check"] {
        let (code, _, _) = run(&["fapolicyd", "--no-conf", action, "--dir-min", "2"], b"");
        assert_eq!(code, 1, "{action} must not take --dir-min");
    }
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

/// The #139 reproduction through a candidate directory, where the per-set gate is `main`'s
/// to compute: the proposed `rules.d/` prepends the record's own ftype to `%languages`, so
/// the shipped deny naming that set is reached before the new allow and matches it. Before
/// the gate reached `Proposal::Merged` this answered `allowed`, which is the wrong answer
/// the issue forbids.
#[test]
fn a_candidate_directory_that_edits_a_set_is_gated_on_that_set() {
    let conf = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/conf/default.conf"
    );
    let shipped = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/conf/rules.d/10-languages.rules"
    ))
    .expect("read the shipped set");
    let dir = std::env::temp_dir().join("rulesteward-check-edited-set");
    std::fs::create_dir_all(&dir).expect("create the proposal");
    for (name, body) in [
        (
            "10-languages.rules",
            shipped.replace("%languages=", "%languages=application/x-executable,"),
        ),
        (
            "70-trusted-lang.rules",
            "allow perm=open all : ftype=%languages trust=1\n\
             deny_audit perm=any all : ftype=%languages\n"
                .to_string(),
        ),
        (
            "71-new.rules",
            "allow perm=execute all : path=/tmp/gaps/trusted-ls\n".to_string(),
        ),
        (
            "90-deny-execute.rules",
            "deny_audit perm=execute all : all\n".to_string(),
        ),
    ] {
        std::fs::write(dir.join(name), body).expect("write the proposal");
    }
    let (code, out, err) = run(
        &["fapolicyd", "--conf", conf, "check", dir.to_str().unwrap()],
        DENIED_BY_13,
    );
    assert_eq!(code, 0, "{err}");
    let line = out
        .lines()
        .find(|l| !l.starts_with("# "))
        .unwrap_or_default();
    assert!(
        line.starts_with("denied ") && line.ends_with("deny_audit perm=any all : ftype=%languages"),
        "{out}"
    );
    std::fs::remove_dir_all(&dir).expect("remove the proposal");
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
/// `%languages`, so the deny naming that set is reached before the new allow and, resolved
/// by membership against the proposed definition, matches (#139). `allowed` is the wrong
/// answer the issue's hazard forbids, and the per-set gate in `main` is what keeps that
/// deny from being skipped as a rule the daemon already walked past.
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
    assert!(line.starts_with("denied "), "{out}");
    assert!(
        line.ends_with("deny_audit perm=any all : ftype=%languages"),
        "the deny naming the edited set is what decides it: {out}"
    );
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

// `--format json`, DESIGN.md §9.1 (#146). Every field in a document is published, so
// every one of them is pinned here and so is every branch that decides one: the text
// report can be reworded, a document cannot.

/// The code, the parsed document and stderr. Parsing here is itself the assertion that
/// what arrived is a document, and the newline check is §9.1's: one at the end and no
/// other, in both formats.
fn json_run(args: &[&str], stdin: &[u8]) -> (i32, serde_json::Value, String) {
    let out = common::run(args, stdin);
    let stdout = String::from_utf8(out.stdout).expect("a document is UTF-8");
    assert!(
        stdout.ends_with('\n') && !stdout.ends_with("\n\n"),
        "exactly one trailing newline: {stdout:?}"
    );
    (
        out.status.code().unwrap(),
        serde_json::from_str(&stdout).unwrap_or_else(|e| panic!("not a document ({e}): {stdout}")),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn a_why_document_carries_the_row_as_data() {
    let conf = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/conf/default.conf"
    );
    let input = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/rocky9-journal-live-vm-short.log"
    ))
    .expect("read fixture");
    let (code, doc, err) = json_run(
        &["fapolicyd", "--conf", conf, "why", "--format", "json"],
        &input,
    );
    assert_eq!(code, 0, "{err}");
    assert!(err.is_empty(), "{err}");
    assert_eq!(doc["schema"], 1, "{doc}");
    assert_eq!(doc["action"], "why", "{doc}");
    // The whole entry, so a field added without a contract fails here: rule 5 is the
    // shipped `pattern=ld_so` deny, which refuses the record outright (§7).
    assert_eq!(
        doc["entries"][0],
        serde_json::json!({
            "rule": 5,
            "file": "30-patterns.rules",
            "text": "deny_audit perm=any pattern=ld_so : all",
            "denials": 22,
            "subject_side": true,
            "rules": 0,
            "trust": 0,
        }),
        "{doc}"
    );
    // Rule 8 is the other side of `subject_side`, and the row that accounts for a
    // suggestion: a rule the pass did not refuse, and a trust entry it emitted.
    assert_eq!(
        doc["entries"][1],
        serde_json::json!({
            "rule": 8,
            "file": "41-shared-obj.rules",
            "text": "deny_audit perm=open all : ftype=application/x-sharedlib",
            "denials": 1,
            "subject_side": false,
            "rules": 0,
            "trust": 1,
        }),
        "{doc}"
    );
    // §9.1: `why` keeps run-level notes only, exactly as the text report does.
    for note in doc["diagnostics"].as_array().expect("an array") {
        assert!(note["line"].is_null(), "{note}");
        assert!(note["msg"].is_string(), "{note}");
    }
}

/// Where the text report collapses a column the document writes `null` (§9.1), and never
/// an empty string: with no rules file there is no filename, no rule text and no answer
/// to whether that rule refuses the record. The counts are still counted.
#[test]
fn a_row_with_no_rules_file_is_null_where_the_report_is_blank() {
    let (code, doc, err) = json_run(
        &["fapolicyd", "--no-conf", "why", "--format", "json"],
        DENIED_BY_13,
    );
    assert_eq!(code, 0, "{err}");
    assert_eq!(
        doc["entries"][0],
        serde_json::json!({
            "rule": 13,
            "file": null,
            "text": null,
            "denials": 1,
            "subject_side": null,
            "rules": 1,
            "trust": 0,
        }),
        "{doc}"
    );
}

#[test]
fn a_check_document_carries_the_verdict_word_and_its_detail() {
    let conf = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/conf/default.conf"
    );
    let candidate = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/check/00-cand.rules"
    );
    let input = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/rocky9-journal-live-vm-short.log"
    ))
    .expect("read fixture");
    let (code, doc, err) = json_run(
        &[
            "fapolicyd",
            "--conf",
            conf,
            "check",
            candidate,
            "--format",
            "json",
        ],
        &input,
    );
    assert_eq!(code, 0, "{err}");
    assert!(err.is_empty(), "{err}");
    assert_eq!(doc["action"], "check", "{doc}");
    // The whole entry again, including the two key fields the report line leaves out.
    assert_eq!(
        doc["entries"][0],
        serde_json::json!({
            "verdict": "allowed",
            "detail": "00-cand.rules: allow perm=execute all : path=/tmp/live/probe-grep",
            "denials": 1,
            "perm": "execute",
            "exe": "/usr/sbin/runuser",
            "path": "/tmp/live/probe-grep",
            "ftype": "application/x-executable",
            "trust": "0",
            "rule": 13,
        }),
        "{doc}"
    );
    let words: Vec<&str> = doc["entries"]
        .as_array()
        .expect("an array")
        .iter()
        .map(|e| e["verdict"].as_str().expect("a verdict"))
        .collect();
    assert!(words.contains(&"denied"), "{doc}");

    // `unknown` is the third, and the one that needs no host to reach: with no rules
    // read there is nothing to place the candidates against.
    let (code, doc, err) = json_run(
        &[
            "fapolicyd",
            "--no-conf",
            "check",
            candidate,
            "--format",
            "json",
        ],
        DENIAL,
    );
    assert_eq!(code, 0, "{err}");
    assert_eq!(doc["entries"][0]["verdict"], "unknown", "{doc}");
    assert!(
        doc["entries"][0]["detail"]
            .as_str()
            .expect("a detail")
            .contains("no rules file was read"),
        "{doc}"
    );
    // A record with no `ftype=` still has the key, holding null (§9.1).
    assert!(doc["entries"][0]["ftype"].is_null(), "{doc}");
}

/// §9.1: a value that is not UTF-8 survives as hex beside the lossy text, and the sibling
/// is absent -- not null -- for every value that did not need it. The path here is the
/// one byte no lossy decoding can carry.
#[test]
fn a_path_that_is_not_utf8_carries_its_bytes_in_hex() {
    let candidate = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/check/00-cand.rules"
    );
    let record: &[u8] = b"rule=1 dec=deny_audit perm=open auid=1000 pid=1 \
exe=/usr/bin/bash : path=/tmp/\xff trust=0\n";
    let (code, doc, err) = json_run(
        &[
            "fapolicyd",
            "--no-conf",
            "check",
            candidate,
            "--format",
            "json",
        ],
        record,
    );
    assert_eq!(code, 0, "{err}");
    let entry = &doc["entries"][0];
    assert_eq!(entry["path"], "/tmp/\u{fffd}", "{doc}");
    assert_eq!(entry["path_hex"], "2f746d702fff", "{doc}");
    assert_eq!(entry["exe"], "/usr/bin/bash", "{doc}");
    assert!(
        entry.get("exe_hex").is_none(),
        "a UTF-8 exe has no hex sibling: {doc}"
    );
}

/// §9.1: the two JSON formats are one document written two ways. Over every fixture,
/// through both report actions, because a field that only some real capture reaches is
/// exactly the one nobody would have written a case for.
#[test]
fn both_json_formats_are_the_same_document_over_every_fixture() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");
    let candidate = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/check/00-cand.rules"
    );
    let mut seen = 0;
    for entry in std::fs::read_dir(dir).expect("read the fixture directory") {
        let path = entry.expect("a directory entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("log") {
            continue;
        }
        let input = std::fs::read(&path).expect("read fixture");
        let name = path.display();
        for action in [
            vec!["why"],
            vec!["check", candidate],
            vec!["rules"],
            vec!["rules", "--dir-min", "2"],
            vec!["trust"],
        ] {
            let mut args = vec!["fapolicyd", "--no-conf"];
            args.extend(&action);
            args.extend(["--format", "json"]);
            let (code, pretty, err) = json_run(&args, &input);
            assert_eq!(code, 0, "{name}: {err}");
            assert_eq!(pretty["schema"], 1, "{name}: {pretty}");

            let compact_args = [&args[..args.len() - 1], &["json-compact"]].concat();
            let out = common::run(&compact_args, &input);
            let compact = String::from_utf8(out.stdout).expect("a document is UTF-8");
            assert_eq!(compact.lines().count(), 1, "{name}: {compact}");
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(&compact).expect("a document"),
                pretty,
                "{name}: the two formats differ in more than whitespace"
            );
        }
        seen += 1;
    }
    assert!(seen >= 15, "only {seen} fixtures were swept");
}

/// The `diagnostics` array is the comment block, said the way JSON can say it: the same
/// notes the text run writes, filtered the same way, in the same order. Both shapes are
/// in both runs -- a note about the host, and a note about an input line -- and the
/// `rules --dir-min` run adds the third source, a note the grouping itself wrote.
#[test]
fn the_json_diagnostics_are_the_comments_the_text_run_writes() {
    let candidate = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/check/00-cand.rules"
    );
    let input = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/rocky8-base-edge-paths.log"
    ))
    .expect("read fixture");
    for action in [
        vec!["check", candidate],
        vec!["rules", "--dir-min", "2", "--dir-system"],
    ] {
        // A conf that cannot be read is §6 step 2's ordinary case, and it is what puts
        // the host's own notes -- the conf read and the rules read -- in both outputs.
        let mut args = vec!["fapolicyd", "--conf", "/nonexistent/fapolicyd.conf"];
        args.extend(&action);
        let (_, text, _) = run(&args, &input);
        let mut json = args.clone();
        json.extend(["--format", "json"]);
        let (_, doc, _) = json_run(&json, &input);

        let notes = doc["diagnostics"].as_array().expect("an array");
        let rendered: Vec<String> = notes
            .iter()
            .map(|n| {
                let msg = n["msg"].as_str().expect("a message");
                match n["line"].as_u64() {
                    Some(line) => format!("# rulesteward: line {line}: {msg}"),
                    None => format!("# rulesteward: {msg}"),
                }
            })
            .collect();
        let comments: Vec<String> = text
            .lines()
            .filter(|l| l.starts_with("# rulesteward: "))
            .map(str::to_string)
            .collect();
        assert_eq!(rendered, comments, "{action:?}: {doc}");
        assert!(
            notes.iter().any(|n| n["line"].is_null()) && notes.iter().any(|n| n["line"].is_u64()),
            "both shapes belong in this run: {action:?}: {doc}"
        );
    }
    // The grouping note is a diagnostic and not an entry field, so it has to be in the
    // array the loop above just compared.
    let (_, doc, _) = json_run(
        &[
            "fapolicyd",
            "--no-conf",
            "rules",
            "--dir-min",
            "2",
            "--format",
            "json",
        ],
        &group_in("/app", 2),
    );
    assert!(
        doc["diagnostics"]
            .as_array()
            .expect("an array")
            .iter()
            .any(|n| n["msg"]
                .as_str()
                .is_some_and(|m| m.starts_with("dir=/app/ replaces 2 rules"))),
        "{doc}"
    );
}

/// §9.1: no document at all when nothing parsed, and none when the run ended before the
/// analysis. An `entries: []` there would read as "no denials", which is a different
/// answer and the one a log of allow records gets.
#[test]
fn a_json_run_that_reaches_no_answer_writes_no_document() {
    // Every action that needs no argument: an artifact action writing `entries: []`
    // here would read as "a log with nothing to suggest", which is exit 0's answer.
    for action in ["why", "rules", "trust"] {
        let out = common::run(
            &["fapolicyd", "--no-conf", action, "--format", "json"],
            b"not a record\nnor this\n",
        );
        assert_eq!(out.status.code().unwrap(), 2, "{action}");
        assert!(out.stdout.is_empty(), "{action}: {:?}", out.stdout);
    }

    let (code, out, err) = run(
        &[
            "fapolicyd",
            "--no-conf",
            "check",
            "/nonexistent/x.rules",
            "--format",
            "json",
        ],
        DENIAL,
    );
    assert_eq!(code, 1, "{err}");
    assert!(out.is_empty(), "{out}");
}

/// §9.1 (#147): a `rules` entry is the rule taken apart, and `text` is the line the same
/// run writes into the fragment. Both subject sides are here: an `exe=` the record
/// supplied, and the `all` an unusable one becomes, which the document spells `null`.
#[test]
fn a_rules_document_carries_the_rule_as_data() {
    let input: &[u8] = b"rule=13 dec=deny_audit perm=execute auid=1000 pid=1 \
exe=/usr/bin/bash : path=/app/probe trust=1\n\
rule=13 dec=deny_audit perm=open auid=1000 pid=1 exe=? : path=/app/lib.so trust=1\n";
    let (code, doc, err) = json_run(
        &["fapolicyd", "--no-conf", "rules", "--format", "json"],
        input,
    );
    assert_eq!(code, 0, "{err}");
    assert!(err.is_empty(), "{err}");
    assert_eq!(doc["action"], "rules", "{doc}");
    assert_eq!(
        doc["entries"][0],
        serde_json::json!({
            "decision": "allow",
            "perm": "execute",
            "exe": "/usr/bin/bash",
            "path": "/app/probe",
            "dir": null,
            "replaced": [],
            "text": "allow perm=execute exe=/usr/bin/bash : path=/app/probe",
        }),
        "{doc}"
    );
    assert_eq!(
        doc["entries"][1],
        serde_json::json!({
            "decision": "allow",
            "perm": "open",
            "exe": null,
            "path": "/app/lib.so",
            "dir": null,
            "replaced": [],
            "text": "allow perm=open all : path=/app/lib.so",
        }),
        "{doc}"
    );
    // The fragment and the document say the same thing, so the lines are the `text`
    // fields in order: one renderer, not two.
    let (_, fragment, _) = run(&["fapolicyd", "--no-conf", "rules"], input);
    assert_eq!(
        allow_lines(&fragment),
        doc["entries"]
            .as_array()
            .expect("an array")
            .iter()
            .map(|e| e["text"].as_str().expect("a text"))
            .collect::<Vec<_>>(),
        "{doc}"
    );
}

/// §9.1: a `--dir-min` group writes `dir` where a plain rule writes `path`, and the paths
/// it widened away are data here. The note beside it says the same thing in prose, which
/// is all the text report can do with a list.
#[test]
fn a_grouped_rules_entry_names_its_dir_and_what_it_replaced() {
    let (code, doc, err) = json_run(
        &[
            "fapolicyd",
            "--no-conf",
            "rules",
            "--dir-min",
            "2",
            "--format",
            "json",
        ],
        &group_in("/app", 2),
    );
    assert_eq!(code, 0, "{err}");
    assert_eq!(
        doc["entries"][0],
        serde_json::json!({
            "decision": "allow",
            "perm": "execute",
            "exe": "/usr/bin/bash",
            "path": null,
            "dir": "/app/",
            "replaced": [{ "path": "/app/f0" }, { "path": "/app/f1" }],
            "text": "allow perm=execute exe=/usr/bin/bash : dir=/app/",
        }),
        "{doc}"
    );
    assert_eq!(
        doc["entries"].as_array().expect("an array").len(),
        1,
        "{doc}"
    );
}

/// §9.1: a `trust` entry is the path and the two commands §8.3 pairs, one string each and
/// no newlines — `--file add` alone contacts no daemon, so neither line stands by itself.
#[test]
fn a_trust_document_carries_the_path_and_both_commands() {
    let (code, doc, err) = json_run(
        &["fapolicyd", "--no-conf", "trust", "--format", "json"],
        DENIAL,
    );
    assert_eq!(code, 0, "{err}");
    assert!(err.is_empty(), "{err}");
    assert_eq!(doc["action"], "trust", "{doc}");
    assert_eq!(
        doc["entries"][0],
        serde_json::json!({
            "path": "/tmp/x",
            "commands": [
                "fapolicyd-cli --file add '/tmp/x'",
                "fapolicyd-cli --update",
            ],
        }),
        "{doc}"
    );
}

/// §9.1 over the two artifact actions: every one of the four hex siblings is reachable on
/// a real attribute, and none of them is written when the value was UTF-8. A byte above
/// 127 passes through the daemon's escaper raw (§4), so this is what a foreign-locale
/// path does here; `policy` refuses a control byte and a space, so those never arrive.
///
/// And D18: `text` and `commands` are the rendered line, so they are `null` rather than
/// lossy whenever that line is not UTF-8. A string there would name a path the artifact
/// does not, which is worse than no string — the data fields carry the bytes instead.
#[test]
fn a_rules_or_trust_document_keeps_non_utf8_bytes_in_hex() {
    // `/app` and not `/tmp`, because a world-writable directory does not group (§8.1).
    let grouped: &[u8] = b"dec=deny_audit perm=execute exe=/usr/bin/b\xffsh : \
path=/app/d\xffr/x trust=1\n\
dec=deny_audit perm=execute exe=/usr/bin/b\xffsh : path=/app/d\xffr/y trust=1\n";
    let (code, doc, err) = json_run(
        &["fapolicyd", "--no-conf", "rules", "--format", "json"],
        grouped,
    );
    assert_eq!(code, 0, "{err}");
    let entry = &doc["entries"][0];
    assert_eq!(entry["exe"], "/usr/bin/b\u{fffd}sh", "{doc}");
    assert_eq!(entry["exe_hex"], "2f7573722f62696e2f62ff7368", "{doc}");
    assert_eq!(entry["path"], "/app/d\u{fffd}r/x", "{doc}");
    assert_eq!(entry["path_hex"], "2f6170702f64ff722f78", "{doc}");
    // D18: a lossy `text` would be a rule for a path nobody asked to allow, and nothing
    // reading it could tell. `null`, and the hex siblings are the recovery path.
    assert!(entry["text"].is_null(), "{doc}");

    let (code, doc, err) = json_run(
        &[
            "fapolicyd",
            "--no-conf",
            "rules",
            "--dir-min",
            "2",
            "--format",
            "json",
        ],
        grouped,
    );
    assert_eq!(code, 0, "{err}");
    let entry = &doc["entries"][0];
    assert_eq!(entry["dir"], "/app/d\u{fffd}r/", "{doc}");
    assert_eq!(entry["dir_hex"], "2f6170702f64ff722f", "{doc}");
    assert_eq!(
        entry["replaced"][0],
        serde_json::json!({ "path": "/app/d\u{fffd}r/x", "path_hex": "2f6170702f64ff722f78" }),
        "{doc}"
    );
    assert!(entry["text"].is_null(), "{doc}");

    // The asymmetric case: the bad bytes are in the leaves and the directory the group
    // widened to is UTF-8, so the line itself is representable and `text` is a string.
    // The `replaced` paths are where the bytes were, and each one keeps its own hex.
    let (code, doc, err) = json_run(
        &[
            "fapolicyd",
            "--no-conf",
            "rules",
            "--dir-min",
            "2",
            "--format",
            "json",
        ],
        b"dec=deny_audit perm=execute exe=/usr/bin/bash : path=/app/\xffone trust=1\n\
dec=deny_audit perm=execute exe=/usr/bin/bash : path=/app/\xfetwo trust=1\n",
    );
    assert_eq!(code, 0, "{err}");
    let entry = &doc["entries"][0];
    assert_eq!(entry["dir"], "/app/", "{doc}");
    assert!(entry.get("dir_hex").is_none(), "{doc}");
    assert_eq!(
        entry["text"], "allow perm=execute exe=/usr/bin/bash : dir=/app/",
        "{doc}"
    );
    assert_eq!(
        entry["replaced"],
        serde_json::json!([
            { "path": "/app/\u{fffd}one", "path_hex": "2f6170702fff6f6e65" },
            { "path": "/app/\u{fffd}two", "path_hex": "2f6170702ffe74776f" },
        ]),
        "{doc}"
    );

    let (code, doc, err) = json_run(
        &["fapolicyd", "--no-conf", "trust", "--format", "json"],
        b"dec=deny_audit perm=open exe=/usr/bin/bash : path=/tmp/\xff trust=0\n",
    );
    assert_eq!(code, 0, "{err}");
    let entry = &doc["entries"][0];
    assert_eq!(entry["path"], "/tmp/\u{fffd}", "{doc}");
    assert_eq!(entry["path_hex"], "2f746d702fff", "{doc}");
    // D18 again, and the sharper half of it: a lossy command is a shell line that trusts
    // a different file, and whatever runs it cannot tell.
    assert!(entry["commands"].is_null(), "{doc}");

    // And a UTF-8 run loses nothing: no sibling it did not need, and both rendered fields
    // still carry their line.
    let (_, doc, _) = json_run(
        &["fapolicyd", "--no-conf", "rules", "--format", "json"],
        DENIED_BY_13,
    );
    let entry = doc["entries"][0].as_object().expect("an entry");
    for key in ["exe_hex", "path_hex", "dir_hex"] {
        assert!(!entry.contains_key(key), "{key} is not needed here: {doc}");
    }
    assert_eq!(
        entry["text"], "allow perm=execute exe=/usr/bin/bash : path=/tmp/gaps/trusted-ls",
        "{doc:?}"
    );
    let (_, doc, _) = json_run(
        &["fapolicyd", "--no-conf", "trust", "--format", "json"],
        DENIAL,
    );
    assert_eq!(
        doc["entries"][0]["commands"],
        serde_json::json!([
            "fapolicyd-cli --file add '/tmp/x'",
            "fapolicyd-cli --update",
        ]),
        "{doc}"
    );
}

/// `--format` is a domain flag like `--conf` (§9), so it is accepted on either side of
/// the action.
#[test]
fn the_format_flag_is_accepted_before_the_action() {
    let (code, doc, err) = json_run(
        &["fapolicyd", "--no-conf", "--format", "json", "why"],
        DENIAL,
    );
    assert_eq!(code, 0, "{err}");
    assert_eq!(doc["action"], "why", "{doc}");
    assert_eq!(doc["entries"][0]["rule"], 1, "{doc}");
}

/// §9.1: a document escapes what the text report escapes. serde_json stops at U+0020, so
/// DEL and the C1 controls are this tool's to spell -- a raw U+009B is CSI on a terminal
/// that honours it, and a `check` document is read on a terminal. Synthetic, because no
/// captured fixture holds one: the daemon's own escaper would have written them octally.
#[test]
fn a_document_escapes_del_and_the_c1_controls() {
    let candidate = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/check/00-cand.rules"
    );
    // U+007F and U+009F are the ends of the range; `~` (U+007E) and U+00A0 sit just
    // outside it and pin both bounds against a mutated one.
    let record: &[u8] = b"rule=1 dec=deny_audit perm=open auid=1000 pid=1 \
exe=/usr/bin/bash : path=/tmp/a\x7fb\xc2\x9bc\xc2\x9fd~\xc2\xa0e trust=0\n";
    let path = "/tmp/a\u{7f}b\u{9b}c\u{9f}d~\u{a0}e";

    for format in ["json", "json-compact"] {
        let out = common::run(
            &[
                "fapolicyd",
                "--no-conf",
                "check",
                candidate,
                "--format",
                format,
            ],
            record,
        );
        assert_eq!(out.status.code().unwrap(), 0);
        let stdout = &out.stdout;
        for raw in [&b"\x7f"[..], &b"\xc2\x9b"[..], &b"\xc2\x9f"[..]] {
            assert!(
                !stdout.windows(raw.len()).any(|w| w == raw),
                "{format}: {raw:?} reached stdout raw: {stdout:?}"
            );
        }
        let text = String::from_utf8(stdout.clone()).expect("a document is UTF-8");
        for escape in ["\\u007f", "\\u009b", "\\u009f"] {
            assert!(
                text.contains(escape),
                "{format}: {escape} is missing: {text}"
            );
        }
        // The two neighbours are still themselves, and next to each other.
        assert!(text.contains("d~\u{a0}e"), "{format}: {text}");

        // The escape is a spelling and not a change: what parses out is the path the
        // record carried, and the bytes were UTF-8, so there is no hex sibling.
        let doc: serde_json::Value = serde_json::from_slice(stdout).expect("a document");
        assert_eq!(doc["entries"][0]["path"], path, "{format}: {text}");
        assert!(
            doc["entries"][0].get("path_hex").is_none(),
            "{format}: {text}"
        );
    }
}

// `--follow` (#153, DESIGN.md §9): the same pass, written a line at a time.

/// The next stdout line of a `--follow` run, or `None` once its stdout closed. A line
/// that does not arrive kills the child and fails the test instead of hanging the suite.
fn next_line(
    rx: &std::sync::mpsc::Receiver<String>,
    child: &mut std::process::Child,
) -> Option<String> {
    use std::sync::mpsc::RecvTimeoutError;
    match rx.recv_timeout(std::time::Duration::from_secs(10)) {
        Ok(line) => Some(line),
        Err(RecvTimeoutError::Disconnected) => None,
        Err(RecvTimeoutError::Timeout) => {
            let _ = child.kill();
            panic!("no stdout line within 10 s");
        }
    }
}

/// The Done-when test: stdin stays open after one denial, and its result has to arrive
/// anyway, which is also what guards the missing per-line flush (S1 F6). A per-line note
/// is a result too: the `trust=?` record's arrives with its line and not at EOF.
#[test]
fn a_follow_run_writes_the_result_before_stdin_closes() {
    use std::io::{BufRead, Write};
    use std::process::{Command, Stdio};
    let candidate = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/check/00-cand.rules"
    );
    let (row, detail) = (
        "unknown perm=open exe=/usr/bin/bash path=/tmp/x rule=1",
        "no rules file was read (--no-conf, a legacy fapolicyd.rules, or unreadable): rule= \
         resolves to nothing and the candidates cannot be placed",
    );
    let (check_live, check_end) = (
        format!("{row}  {detail}"),
        format!("{row} (1 denials)  {detail}"),
    );
    let unavailable = b"rule=1 dec=deny_audit perm=open auid=1000 pid=1 exe=/usr/bin/bash : \
                        path=/tmp/x trust=?\n";
    for (action, input, live, end) in [
        (
            &["trust"][..],
            DENIAL,
            &[
                "fapolicyd-cli --file add '/tmp/x'",
                "fapolicyd-cli --update",
            ][..],
            &[][..],
        ),
        (
            &["why"][..],
            DENIAL,
            &["rule=1"][..],
            &[
                "# rulesteward: 1 untrusted path(s) need a trust entry, not a rule: run \
                 rulesteward fapolicyd trust on the same input",
                "rule=1  1 denials",
            ][..],
        ),
        // The live row drops the count column that only the end can fill in.
        (
            &["check", candidate][..],
            DENIAL,
            &[check_live.as_str()][..],
            &[check_end.as_str()][..],
        ),
        (
            &["trust"][..],
            unavailable,
            &[
                "# rulesteward: line 1: trust attribute unavailable (trust=?); emitting \
                 nothing, because the file's trust state is unknown rather than untrusted",
            ][..],
            &[][..],
        ),
    ] {
        let mut child = Command::new(env!("CARGO_BIN_EXE_rulesteward"))
            .args(["fapolicyd", "--no-conf", "--follow"])
            .args(action)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn");
        let mut stdin = child.stdin.take().expect("stdin");
        let stdout = child.stdout.take().expect("stdout");
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for line in std::io::BufReader::new(stdout).lines() {
                if tx.send(line.expect("a UTF-8 line")).is_err() {
                    break;
                }
            }
        });

        stdin.write_all(input).expect("write");
        for want in live {
            assert_eq!(
                next_line(&rx, &mut child).as_deref(),
                Some(*want),
                "{action:?}"
            );
        }

        drop(stdin);
        let mut rest = Vec::new();
        while let Some(line) = next_line(&rx, &mut child) {
            rest.push(line);
        }
        assert_eq!(rest, end, "{action:?}: the end of the run");
        assert_eq!(child.wait().expect("wait").code(), Some(0), "{action:?}");
    }
}

#[test]
fn follow_with_a_json_format_is_a_usage_error() {
    for format in ["json", "json-compact"] {
        let (code, out, err) = run(
            &[
                "fapolicyd",
                "--no-conf",
                "--follow",
                "why",
                "--format",
                format,
            ],
            b"",
        );
        assert_eq!(code, 1, "{format}: {err}");
        assert!(out.is_empty(), "{format}: {out}");
        assert!(
            err.contains("one document for the whole log"),
            "{format}: {err}"
        );
    }
}

#[test]
fn follow_with_dir_min_is_a_usage_error() {
    let (code, out, err) = run(
        &[
            "fapolicyd",
            "--no-conf",
            "rules",
            "--dir-min",
            "3",
            "--follow",
        ],
        b"",
    );
    assert_eq!(code, 1, "{err}");
    assert!(out.is_empty(), "{out}");
    assert!(err.contains("only once the whole log is read"), "{err}");
}

#[test]
fn a_follow_run_decides_exit_2_at_eof() {
    let (code, out, _) = run(
        &["fapolicyd", "rules", "--no-conf", "--follow"],
        b"not a record\nnor this\n",
    );
    assert_eq!(code, 2);
    assert!(out.is_empty(), "{out}");
}

/// The suggestions are the batch run's, in the batch run's order: only the notes move.
/// The framing fixture is here because neither live capture yields a `rules` line.
#[test]
fn a_follow_run_suggests_what_the_batch_run_does() {
    let conf = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/conf/default.conf"
    );
    let mut seen = [0, 0];
    for fixture in [
        "rocky9-journal-live-vm-short.log",
        "rocky9-audit-live-vm-syscall-raw.log",
        "rocky10-base-syslog-framing-syslog-raw.log",
    ] {
        let input = std::fs::read(format!(
            "{}/tests/fixtures/{fixture}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .expect("read fixture");
        for (i, action) in ["rules", "trust"].into_iter().enumerate() {
            let suggested = |follow: &[&str]| {
                let mut args = vec!["fapolicyd", action, "--conf", conf];
                args.extend(follow);
                let (code, out, err) = run(&args, &input);
                assert_eq!(code, 0, "{fixture} {action}: {err}");
                out.lines()
                    .filter(|l| !l.starts_with('#'))
                    .map(str::to_string)
                    .collect::<Vec<_>>()
            };
            let batch = suggested(&[]);
            assert_eq!(suggested(&["--follow"]), batch, "{fixture} {action}");
            seen[i] += batch.len();
        }
    }
    assert!(
        seen.iter().all(|&n| n > 0),
        "an action suggested nothing: {seen:?}"
    );
}

/// A follow run's `#` lines with every live note folded into its `(xN)` total, which is
/// the line batch's collapse writes for it. Sorted, because the order legitimately
/// differs: the audit route's totals come after the live notes in follow and ahead of
/// them in batch.
fn folded(out: &str) -> Vec<String> {
    let notes: Vec<&str> = out.lines().filter(|l| l.starts_with('#')).collect();
    // A per-line note's text without its line number, which is what collapse keys on.
    let msg = |l: &'_ str| -> String {
        l.strip_prefix("# rulesteward: line ")
            .and_then(|r| r.split_once(": "))
            .map_or(l, |(_, m)| m)
            .to_string()
    };
    let totals: Vec<(String, usize)> = notes
        .iter()
        .filter_map(|l| {
            let (base, n) = l.strip_suffix(')')?.rsplit_once(" (x")?;
            Some((msg(base), n.parse().ok()?))
        })
        .collect();
    // A total's own text still ends in `(xN)`, so it is kept; the live notes it counts
    // are dropped, and there have to be exactly N of them.
    let mut live = vec![0; totals.len()];
    let mut kept: Vec<String> = Vec::new();
    for l in notes {
        match totals.iter().position(|(m, _)| *m == msg(l)) {
            Some(i) => live[i] += 1,
            None => kept.push(l.to_string()),
        }
    }
    for ((m, n), seen) in totals.iter().zip(live) {
        assert_eq!(seen, *n, "live notes against the total for {m}: {out}");
    }
    kept.sort();
    kept
}

/// The `#` lines are the batch run's once the live notes are folded into the totals at
/// the end (D5): a total that is missing, or that counts fewer notes than batch does,
/// fails here and nowhere else, because T4 drops every `#` line. The notes that name no
/// line keep batch's order too, which is what puts the audit totals ahead of the run's.
#[test]
fn a_follow_run_writes_the_notes_the_batch_run_does() {
    let conf = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/conf/default.conf"
    );
    let mut totals = 0;
    for fixture in [
        "rocky9-journal-live-vm-short.log",
        "rocky9-audit-live-vm-syscall-raw.log",
        "rocky10-base-syslog-framing-syslog-raw.log",
    ] {
        let input = std::fs::read(format!(
            "{}/tests/fixtures/{fixture}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .expect("read fixture");
        for action in ["rules", "trust"] {
            let (_, batch, _) = run(&["fapolicyd", action, "--conf", conf], &input);
            let (code, follow, err) =
                run(&["fapolicyd", action, "--conf", conf, "--follow"], &input);
            assert_eq!(code, 0, "{fixture} {action}: {err}");
            // D4, in order, for the notes that name no line: the host's, the audit
            // route's totals, then the run's, exactly as batch writes them.
            let run_level = |out: &str| -> Vec<String> {
                out.lines()
                    .filter(|l| {
                        l.starts_with("# rulesteward: ") && !l.starts_with("# rulesteward: line ")
                    })
                    .map(str::to_string)
                    .collect()
            };
            assert_eq!(run_level(&follow), run_level(&batch), "{fixture} {action}");
            let mut batch: Vec<&str> = batch.lines().filter(|l| l.starts_with('#')).collect();
            batch.sort();
            assert_eq!(folded(&follow), batch, "{fixture} {action}");
            totals += batch
                .iter()
                .filter(|l| l.ends_with(')') && l.contains(" (x"))
                .count();
        }
    }
    assert!(
        totals > 0,
        "no fixture repeated a note, so no total was checked"
    );
}

/// D4: after the last live line come the run's notes, then the repeat totals, then the
/// report with its counts, which is batch's report line for line.
#[test]
fn a_follow_run_ends_with_the_run_notes_the_totals_and_the_report() {
    let conf = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/conf/default.conf"
    );
    let input = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/handwritten-trusted-denial.log"
    ))
    .expect("read fixture");
    let (_, batch, _) = run(&["fapolicyd", "check", "--conf", conf], &input);
    let report: Vec<&str> = batch.lines().filter(|l| !l.starts_with('#')).collect();
    let (code, follow, err) = run(&["fapolicyd", "check", "--conf", conf, "--follow"], &input);
    assert_eq!(code, 0, "{err}");
    let lines: Vec<&str> = follow.lines().collect();
    assert!(
        !report.is_empty() && lines.len() > report.len() + 2,
        "{follow}"
    );
    let end = &lines[lines.len() - report.len() - 2..];
    assert!(
        end[0].starts_with("# rulesteward: the rules file does not match this log"),
        "the run note: {follow}"
    );
    assert!(
        end[1].starts_with("# rulesteward: line 19: record truncated") && end[1].ends_with(" (x2)"),
        "the total: {follow}"
    );
    assert_eq!(&end[2..], &report[..], "the report: {follow}");
}

/// `common::run` writes stdin from its own thread: a follow run writes as it reads, so
/// output past one pipe buffer would otherwise deadlock the test against the child.
#[test]
fn a_follow_run_with_more_output_than_a_pipe_holds_finishes() {
    let input: String = (0..5000)
        .map(|i| {
            format!(
                "rule=1 dec=deny_audit perm=open auid=1000 pid=1 exe=/usr/bin/bash : \
                 path=/tmp/x{i} trust=0\n"
            )
        })
        .collect();
    let (code, out, err) = run(
        &["fapolicyd", "trust", "--no-conf", "--follow"],
        input.as_bytes(),
    );
    assert_eq!(code, 0, "{err}");
    assert_eq!(out.lines().count(), 10_000);
}
