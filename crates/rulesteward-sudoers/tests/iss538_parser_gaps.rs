//! #538 barrier suite: the THREE INDEPENDENT `sudoers` parser gaps.
//!
//! All three are false negatives on a line real sudo accepts: the privilege
//! parses into an AST shape no lint can match (A and B) or is discarded
//! entirely (C), so `RuleSteward` reports nothing useful about a line that
//! grants real power. They share one issue number and one acceptance signal
//! but they are separate defects in separate functions, so they get separate
//! tests here and must be positive-controlled by SEPARATE reverts: reverting
//! any one gap must redden that gap's tests and no other's.
//!
//! * **Gap A** - `parser::parse_cmnd_spec`'s tag loop recognizes only the
//!   `TAG:` form. An `=`-form `Option_Spec` (`ROLE=`, `TYPE=`, `NOTBEFORE=`,
//!   `TIMEOUT=`, ...) has no colon, so the loop breaks immediately and hands
//!   the ENTIRE remainder to the command constructor: `ROLE=sysadm_r
//!   TYPE=sysadm_t /usr/bin/vim` becomes ONE garbage `CmndItem::Cmnd` token
//!   that matches no `Cmnd_Alias`, no reserved-`ALL` check and no path check.
//! * **Gap B** - `parser::classify_user_spec` splits the pre-`=` text with
//!   `split_first_word`, so a `User_List` containing internal whitespace is
//!   truncated at its first space: `bob, ALL ALL=(ALL) ALL` yields
//!   `users = ["bob"]` and `hosts = ["ALL ALL"]`, dropping the reserved `ALL`
//!   principal and taking `sudo-W06` (the DISA finding for `ALL` in a
//!   `User_List`) down with it.
//! * **Gap C** - `parser::split_top_level_segments` resets its preceding-token
//!   marker on every `=`, so an `Option_Spec`'s own `=` hides a following tag
//!   keyword and the tag colon is mistaken for a top-level host-group
//!   separator. `alice ALL = TIMEOUT=30 NOEXEC: /bin/ls` is thrown away as
//!   `Malformed`. Found during this lane's satisfiability run; see the Gap C
//!   section below for the full mechanism.
//!
//! One test is named `gap_ac_` rather than `gap_a_` / `gap_c_`: it is the
//! deliberate INTEGRATION of A and C and is not separably attributable. Every
//! other test belongs to exactly one gap.
//!
//! # Evidence level
//!
//! Every test here drives the PUBLIC entry points (`parse`, and `lint` for the
//! operator-visible half) with a REAL sudoers input string. None hand-builds a
//! `SudoersFile`: a hand-built AST supplies its own input, so it proves the
//! consumer handles a token and says nothing about whether the parser can emit
//! it. That is exactly how a real parser gap sat underneath a green suite for a
//! whole session.
//!
//! # Grounding
//!
//! Inputs are labelled by where their expected values come from:
//!
//! * **corpus** - the committed recorded-oracle fixture under
//!   `tests/corpus/sudoers-oracle/<id>/`, whose `el9.json` / `el10.json` are
//!   real `cvtsudoers -f json` output. The corpus is the AUTHORITY.
//! * **host probe** - a live `visudo -c -f -` / `cvtsudoers -f json` run on
//!   this development host (sudo 1.9.17p2, `visudo grammar version 50`, probed
//!   2026-07-30), the SAME upstream release as the corpus el9/el10 images.
//!   Corroboration for boundary cases the corpus does not contain, never a
//!   substitute for a corpus row.
//! * **man page** - `man 5 sudoers` on the same host, rendered page lines
//!   652-666, quoted in `ast::CmndOptionKey`'s doc comment.

use std::path::Path;

use rulesteward_sudoers::ast::{CmndItem, CmndOption, CmndOptionKey, LineKind, Tag, UserSpec};
use rulesteward_sudoers::{SudoersLintContext, lint, parse};

/// Parse `src` and return its single `UserSpec`, panicking on anything else.
///
/// Drives `parser::parse`, the public entry point, so the parser really is the
/// system under test.
fn only_spec(src: &str) -> UserSpec {
    let file = parse(src, Path::new("/etc/sudoers"));
    let mut specs: Vec<UserSpec> = file
        .lines
        .into_iter()
        .filter_map(|l| match l.kind {
            LineKind::UserSpec(s) => Some(s),
            _ => None,
        })
        .collect();
    assert_eq!(
        specs.len(),
        1,
        "expected exactly one user-spec from {src:?}, got {}",
        specs.len()
    );
    specs.remove(0)
}

/// The `LineKind` of the first non-blank logical line of `src`.
fn first_kind(src: &str) -> LineKind {
    parse(src, Path::new("/etc/sudoers"))
        .lines
        .into_iter()
        .map(|l| l.kind)
        .find(|k| !matches!(k, LineKind::Blank))
        .expect("at least one non-blank logical line")
}

/// How many `sudo-W06` findings `lint` emits for `src`.
fn w06_count(src: &str) -> usize {
    let files = vec![parse(src, Path::new("/etc/sudoers"))];
    lint(&files, &SudoersLintContext {})
        .iter()
        .filter(|d| d.code == "sudo-W06")
        .count()
}

/// How many `sudo-F01` (parse-failure Fatal) findings `lint` emits for `src`.
///
/// The operator-visible half of the Gap C failure class: a `Malformed` logical
/// line does not merely lose its grant, it is REPORTED as a syntax error on a
/// line real `visudo` accepts rc 0.
fn f01_count(src: &str) -> usize {
    let files = vec![parse(src, Path::new("/etc/sudoers"))];
    lint(&files, &SudoersLintContext {})
        .iter()
        .filter(|d| d.code == "sudo-F01")
        .count()
}

/// The single user-spec's single host group's host list.
fn s_hosts(src: &str) -> Vec<String> {
    let s = only_spec(src);
    assert_eq!(s.host_groups.len(), 1, "expected exactly one host group");
    s.host_groups[0].hosts.clone()
}

/// Build the expected one-element option list for the common single-option
/// case, keeping each test's assertion to one line.
fn opt(key: CmndOptionKey, value: &str) -> Vec<CmndOption> {
    vec![CmndOption {
        key,
        value: value.to_string(),
    }]
}

// ===========================================================================
// Gap A: `=`-form Option_Spec must not swallow the command
// ===========================================================================

/// corpus `accept-selinux-role-type`, input line verbatim (`cat -A`-pinned:
/// one line, no trailing spaces).
///
/// `cvtsudoers -f json` (corpus `el9.json` / `el10.json`) reports
/// `Options [{"role":"sysadm_r"},{"type":"sysadm_t"}]` and
/// `Commands [{"command":"/usr/bin/vim"}]`. Today our AST reports the single
/// garbage command `"ROLE=sysadm_r TYPE=sysadm_t /usr/bin/vim"`.
///
/// The whole-`Vec` equality is deliberate and is the single most important
/// assertion in this lane: no projector reads the option field, so an
/// implementation that recognizes the keyword and THROWS THE VALUE AWAY passes
/// the L3 differential and every mutation gate. Only a direct assertion on the
/// parsed values can kill that. Comparing the whole `Vec` (rather than a
/// `contains` / length check) simultaneously pins the values, the SOURCE order,
/// and the absence of any extra entry.
#[test]
fn gap_a_selinux_role_and_type_options_leave_the_command_clean() {
    let s = only_spec("alice ALL = ROLE=sysadm_r TYPE=sysadm_t /usr/bin/vim\n");
    assert_eq!(s.users, vec!["alice".to_string()]);
    assert_eq!(s.host_groups.len(), 1);
    assert_eq!(s.host_groups[0].hosts, vec!["ALL".to_string()]);

    let specs = &s.host_groups[0].cmnd_specs;
    assert_eq!(specs.len(), 1, "one Cmnd_Spec; got {specs:?}");
    assert_eq!(
        specs[0].cmnd,
        CmndItem::Cmnd("/usr/bin/vim".to_string()),
        "the ROLE=/TYPE= options must NOT be glued onto the command token"
    );
    assert_eq!(
        specs[0].options,
        vec![
            CmndOption {
                key: CmndOptionKey::Role,
                value: "sysadm_r".to_string(),
            },
            CmndOption {
                key: CmndOptionKey::Type,
                value: "sysadm_t".to_string(),
            },
        ],
        "both option VALUES must survive verbatim, in source order"
    );
}

/// corpus `accept-notbefore`, input line verbatim.
///
/// Oracle: `Options [{"notbefore":"20260101000000Z"}]`,
/// `Commands [{"command":"/usr/bin/ls"}]`.
#[test]
fn gap_a_notbefore_option_leaves_the_command_clean() {
    let s = only_spec("carol ALL = NOTBEFORE=20260101000000Z /usr/bin/ls\n");
    let specs = &s.host_groups[0].cmnd_specs;
    assert_eq!(specs.len(), 1);
    assert_eq!(specs[0].cmnd, CmndItem::Cmnd("/usr/bin/ls".to_string()));
    assert_eq!(
        specs[0].options,
        opt(CmndOptionKey::NotBefore, "20260101000000Z"),
        "the timestamp must survive verbatim, not be reparsed or truncated"
    );
}

/// corpus `accept-timeout-option`, input line verbatim. This is the only corpus
/// line that exercises the runas strip AND the option loop together.
///
/// Oracle: `runasusers [{"username":"root"}]`,
/// `Options [{"command_timeout":30}]`, `Commands [{"command":"/usr/bin/ls"}]`.
/// Note `cvtsudoers` renders the timeout as the JSON NUMBER `30`; the AST is a
/// faithful record of the source token, so it holds the STRING `"30"` (see
/// `ast::CmndOption`). An implementation that parses the value into an integer
/// and re-renders it would lose e.g. a `30m` suffix, which sudoers permits.
#[test]
fn gap_a_timeout_option_after_a_runas_group_leaves_the_command_clean() {
    let s = only_spec("bob ALL = (root) TIMEOUT=30 /usr/bin/ls\n");
    let specs = &s.host_groups[0].cmnd_specs;
    assert_eq!(specs.len(), 1);

    let runas = specs[0]
        .runas
        .as_ref()
        .expect("the `(root)` group must still be parsed as a runas spec");
    assert_eq!(runas.users, vec!["root".to_string()]);
    assert!(runas.groups.is_empty(), "no `:group` was written");

    assert_eq!(specs[0].cmnd, CmndItem::Cmnd("/usr/bin/ls".to_string()));
    assert_eq!(
        specs[0].options,
        opt(CmndOptionKey::Timeout, "30"),
        "the timeout value must survive as the raw source token"
    );
}

/// Every one of the TEN accepted keywords must be recognized, with its value
/// captured and the command left clean.
///
/// Without this, an implementation could ship only the four keywords the corpus
/// happens to contain and no gate would notice: the corpus has no `NOTAFTER=`,
/// `CWD=`, `CHROOT=`, `PRIVS=`, `LIMITPRIVS=` or `APPARMOR_PROFILE=` scenario
/// at all.
///
/// TEN, not the seven in the `man 5 sudoers` `Option_Spec` block: that block is
/// incomplete as a description of what the shipping parser ACCEPTS, and for
/// acceptance the parser is the better primary source. Probed on this host
/// (sudo 1.9.17p2, `visudo grammar version 50`, 2026-07-30) with
/// `printf '%s\n' "<line>" | visudo -c -f -` and the same line through
/// `cvtsudoers -f json`:
///
/// ```text
/// alice ALL = PRIVS=x /bin/ls              rc 0  Options [{"privs":"x"}]
/// alice ALL = LIMITPRIVS=y /bin/ls         rc 0  Options [{"limitprivs":"y"}]
/// alice ALL = APPARMOR_PROFILE=p /bin/ls   rc 0  Options [{"apparmor_profile":"p"}]
/// alice ALL = NOTAFTER=...Z /bin/ls        rc 0  Options [{"notafter":"...Z"}]
/// alice ALL = CWD=/tmp /bin/ls             rc 0  Options [{"runcwd":"/tmp"}]
/// alice ALL = CHROOT=/srv /bin/ls          rc 0  Options [{"runchroot":"/srv"}]
/// alice ALL = BOGUSKEY=z /bin/ls           rc 1  syntax error
/// ```
///
/// The `BOGUSKEY` row is what makes this a CLOSED ten rather than an open set;
/// it is pinned by its own negative-control test below. `CHROOT=/srv`
/// additionally prints `"CHROOT" is deprecated` on stderr and still exits 0.
///
/// Grounding per row: `ROLE` / `TYPE` / `NOTBEFORE` / `TIMEOUT` are corpus rows
/// (see the three tests above); the other six are host probes only. The parser
/// is deliberately NOT version-aware, so all ten are implemented on every
/// target; no el8 measurement is claimed for the six probe-only keywords.
///
/// # Round 2: the value may be QUOTED or BACKSLASH-ESCAPED
///
/// Every value spelling above is a whitespace-free, unquoted, punctuation-free
/// token, which is exactly why round 1 could end the option token at the first
/// whitespace and still pass. `man 5 sudoers` (sudo 1.9.17p2, rendered page
/// line 399) records that special characters may be quoted or hex-escaped, and
/// the shipping parser accepts both spellings for an option value. Host probes
/// on this host (2026-07-31), all `visudo -c -f -` rc 0:
///
/// ```text
/// alice ALL = CWD="/tmp/a b" /bin/ls
///     cvtsudoers: Options [{"runcwd":"/tmp/a b"}]        Commands [{"command":"/bin/ls"}]
/// alice ALL = CWD=/tmp/a\ b /bin/ls
///     cvtsudoers: Options [{"runcwd":"/tmp/a b"}]        Commands [{"command":"/bin/ls"}]
/// alice ALL = APPARMOR_PROFILE="my profile" /bin/ls
///     cvtsudoers: Options [{"apparmor_profile":"my profile"}] Commands [{"command":"/bin/ls"}]
/// ```
///
/// Round 1 ends the option token at `rest.find(char::is_whitespace)`, so it
/// splits INSIDE the value: `CWD="/tmp/a` becomes the option and the command
/// becomes the garbage `b" /bin/ls`. That is Gap A's own failure class, on the
/// `commands` axis the L3 differential really compares, re-created by the fix.
///
/// The expected AST value is the VERBATIM SOURCE BYTES, quotes and backslash
/// retained (`ast::CmndOption`: "kept as WRITTEN, never coerced"; the same
/// choice `RunasSpec` makes for its raw comma-split members). This DIVERGES
/// from `cvtsudoers -f json`, which dequotes: the projection that compares the
/// two is what must account for the difference, never the AST. Keeping the
/// source bytes preserves information a consumer can still strip; dequoting in
/// the parser would throw away the distinction between `CWD="/a b"` and a
/// hypothetical unquoted spelling.
#[test]
fn gap_a_all_ten_accepted_option_keywords_are_recognized() {
    let cases: &[(&str, CmndOptionKey, &str)] = &[
        ("ROLE=sysadm_r", CmndOptionKey::Role, "sysadm_r"),
        ("TYPE=sysadm_t", CmndOptionKey::Type, "sysadm_t"),
        (
            "NOTBEFORE=20260101000000Z",
            CmndOptionKey::NotBefore,
            "20260101000000Z",
        ),
        (
            "NOTAFTER=20270101000000Z",
            CmndOptionKey::NotAfter,
            "20270101000000Z",
        ),
        ("TIMEOUT=30", CmndOptionKey::Timeout, "30"),
        ("CWD=/tmp", CmndOptionKey::Cwd, "/tmp"),
        ("CHROOT=/srv", CmndOptionKey::Chroot, "/srv"),
        ("PRIVS=x", CmndOptionKey::Privs, "x"),
        ("LIMITPRIVS=y", CmndOptionKey::LimitPrivs, "y"),
        ("APPARMOR_PROFILE=p", CmndOptionKey::AppArmorProfile, "p"),
        // Round 2: a DOUBLE-QUOTED value whose content contains whitespace. The
        // option token ends at the closing quote, not at the space inside it.
        (
            "CWD=\"/tmp/a b\"",
            CmndOptionKey::Cwd,
            "\"/tmp/a b\"", // verbatim source bytes, quotes retained
        ),
        // Round 2: a BACKSLASH-ESCAPED space, the other spelling of the same
        // value. `split_top_level_segments` and `split_cmnd_specs` already honor
        // a backslash; the option scanner must too.
        (
            "CWD=/tmp/a\\ b",
            CmndOptionKey::Cwd,
            "/tmp/a\\ b", // verbatim, backslash retained
        ),
        // Round 2: a quoted value on a DIFFERENT keyword, so no implementation
        // can pass by special-casing `CWD`.
        (
            "APPARMOR_PROFILE=\"my profile\"",
            CmndOptionKey::AppArmorProfile,
            "\"my profile\"",
        ),
    ];
    for (written, key, value) in cases {
        let src = format!("alice ALL = {written} /bin/ls\n");
        let s = only_spec(&src);
        let specs = &s.host_groups[0].cmnd_specs;
        assert_eq!(specs.len(), 1, "one Cmnd_Spec for {written:?}");
        assert_eq!(
            specs[0].cmnd,
            CmndItem::Cmnd("/bin/ls".to_string()),
            "{written:?} must not be glued onto the command"
        );
        assert_eq!(
            specs[0].options,
            opt(*key, value),
            "{written:?} must be captured as {key:?} with its value verbatim"
        );
    }
}

/// Negative control (host probe, rc 0): the option keyword set is CLOSED, so a
/// `WORD=VALUE` that is NOT one of the ten is ordinary command text.
///
/// `alice ALL = /usr/bin/env FOO=bar` is valid sudoers and `cvtsudoers -f json`
/// reports the SINGLE command `"/usr/bin/env FOO=bar"` with the `=` intact. A
/// generic `WORD=VALUE` matcher would corrupt this real command line, which is
/// precisely why the keyword set may not be generalised.
#[test]
fn gap_a_option_keyword_set_is_closed_so_env_assignment_stays_in_the_command() {
    let s = only_spec("alice ALL = /usr/bin/env FOO=bar\n");
    let specs = &s.host_groups[0].cmnd_specs;
    assert_eq!(specs.len(), 1);
    assert_eq!(
        specs[0].cmnd,
        CmndItem::Cmnd("/usr/bin/env FOO=bar".to_string()),
        "a command's own `KEY=value` argument must stay part of the command"
    );
    assert!(
        specs[0].options.is_empty(),
        "no Option_Spec was written; got {:?}",
        specs[0].options
    );
}

/// The option scan is POSITION-ANCHORED: it consumes a run of options at the
/// START of the `Cmnd_Spec` and stops at the first token that is not one. A
/// REAL option keyword appearing AFTER the command word is a command argument,
/// not an option.
///
/// This is the sharpest control in the file, and the only one that kills a
/// POSITION-BLIND scanner - one that walks every whitespace token, harvests
/// anything matching the keyword table, and rejoins the rest as the command:
///
/// ```text
/// for w in rest.split_whitespace() {
///     match parse_option(w) { Some(o) => options.push(o), None => kept.push(w) }
/// }
/// let cmnd = kept.join(" ");
/// ```
///
/// Such an implementation passes every OTHER test here and every corpus
/// scenario, because they all place their options at the leading position and
/// the only command-side control uses `FOO=bar`, a key outside the ten. It is
/// invisible to the mutation gate too. What it corrupts is the `commands` axis
/// L3 actually compares - it would yield `cmnd = "/usr/bin/env"` plus a phantom
/// `Timeout("30")`, a truncated token matching no `Cmnd_Alias` and no path
/// check. That is Gap A's own failure class, re-created by the fix.
///
/// Grounded (host probes, sudo 1.9.17p2, 2026-07-30, both rc 0):
///
/// ```text
/// alice ALL = /usr/bin/env TIMEOUT=30    cvtsudoers: Commands [{"command":"/usr/bin/env TIMEOUT=30"}], no Options
/// alice ALL = /usr/bin/env  TIMEOUT=30   cvtsudoers: Commands [{"command":"/usr/bin/env TIMEOUT=30"}], no Options
/// ```
///
/// Real sudo reports ONE command with the keyword intact and NO options in
/// both spellings.
///
/// The double-space case additionally kills the whitespace-collapsing half of
/// that shortcut (`kept.join(" ")` normalises the run). Our AST keeps the raw
/// token verbatim, per `ast::CmndItem::Cmnd`, so the two spaces survive here.
/// Note that `cvtsudoers` NORMALISES the run to one space in its own report;
/// that difference is real but out of scope - no corpus scenario's COMPARED
/// COMMAND TOKEN contains an interior doubled space, so L3 never compares one.
/// (Scanned all 41 corpus `input.sudoers` files, 2026-07-30: exactly one
/// contains any doubled space or tab at all - `accept-continuation-line`'s
/// four-space continuation indent, which sits before the `NOPASSWD:` tag and
/// is trimmed off well before the command token. Both sides report that
/// scenario's command as `ALL`, and it is a clean non-xfail L3 row.) Do not
/// "fix" the divergence by collapsing whitespace in the parser, which would
/// defeat this control; if a future corpus row ever does carry an interior
/// doubled space in a command, this frozen test forces that to surface as an
/// escalation rather than a silent normalisation.
#[test]
fn gap_a_option_keyword_after_the_command_word_is_a_command_argument() {
    for (src, want_cmnd) in [
        (
            "alice ALL = /usr/bin/env TIMEOUT=30\n",
            "/usr/bin/env TIMEOUT=30",
        ),
        (
            "alice ALL = /usr/bin/env  TIMEOUT=30\n",
            "/usr/bin/env  TIMEOUT=30",
        ),
    ] {
        let s = only_spec(src);
        let specs = &s.host_groups[0].cmnd_specs;
        assert_eq!(specs.len(), 1, "one Cmnd_Spec for {src:?}");
        assert_eq!(
            specs[0].cmnd,
            CmndItem::Cmnd(want_cmnd.to_string()),
            "a real option keyword AFTER the command word is a command argument \
             and must stay in the command token, verbatim and unnormalised"
        );
        assert!(
            specs[0].options.is_empty(),
            "{src:?}: nothing is at the option position, so no option may be \
             captured; got {:?}",
            specs[0].options
        );
    }
}

/// Negative control (host probe, rc 1): an UNKNOWN uppercase `WORD=VALUE` at
/// the option position is not an option.
///
/// This is the assertion that keeps the set CLOSED. The other closed-set
/// control (`/usr/bin/env FOO=bar`) only rules out a matcher that fires
/// mid-command; a matcher that fired on any `WORD=VALUE` at the SPEC START
/// would still pass it. `alice ALL = BOGUSKEY=z /bin/ls` is `rc 1`
/// (`stdin:1:21: syntax error`) on this host (sudo 1.9.17p2,
/// `visudo grammar version 50`, 2026-07-30), so real sudo does not accept an
/// arbitrary keyword there and neither may the option table.
///
/// `parse_cmnd_spec` is TOTAL and has no reject path, so this pins only that no
/// option is CAPTURED and that the text is not silently dropped - not any
/// particular diagnostic.
#[test]
fn gap_a_unknown_option_keyword_is_not_captured() {
    for written in ["BOGUSKEY=z", "SELINUX=x", "NOTAFTERX=1"] {
        let src = format!("alice ALL = {written} /bin/ls\n");
        let s = only_spec(&src);
        let specs = &s.host_groups[0].cmnd_specs;
        assert!(
            specs[0].options.is_empty(),
            "{written:?} is not one of the ten accepted Option_Spec keywords and \
             must not be captured as an option; got {:?}",
            specs[0].options
        );
        let CmndItem::Cmnd(raw) = &specs[0].cmnd else {
            panic!("{written:?} must not parse as the reserved ALL");
        };
        assert!(
            raw.contains(written),
            "{written:?} must not be silently dropped from the command token; got {raw:?}"
        );
    }
}

/// Negative control (host probe): keyword matching is CASE-SENSITIVE, exactly
/// like `parse_tag`'s.
///
/// `alice ALL = timeout=30 /bin/ls` and the `Timeout=30` spelling are BOTH rc 1
/// on the host (`expected a fully-qualified path name` - sudo read the token as
/// a command word, not an option), while `TIMEOUT=30` is rc 0. So a
/// case-insensitive matcher would recognize an option real sudo does not.
///
/// `parse_cmnd_spec` is TOTAL and has no reject path, so this pins only that
/// no option is CAPTURED and that the text is not silently dropped - not any
/// particular diagnostic. Asserting the text survives also kills an
/// implementation that strips an unrecognized `WORD=` prefix without recording
/// it.
#[test]
fn gap_a_option_keyword_matching_is_case_sensitive() {
    for written in ["timeout=30", "Timeout=30", "role=sysadm_r"] {
        let src = format!("alice ALL = {written} /bin/ls\n");
        let s = only_spec(&src);
        let specs = &s.host_groups[0].cmnd_specs;
        assert!(
            specs[0].options.is_empty(),
            "{written:?} is not an uppercase Option_Spec keyword and must not be \
             captured as an option; got {:?}",
            specs[0].options
        );
        let CmndItem::Cmnd(raw) = &specs[0].cmnd else {
            panic!("{written:?} must not parse as the reserved ALL");
        };
        assert!(
            raw.contains(written),
            "{written:?} must not be silently dropped from the command token; got {raw:?}"
        );
    }
}

/// Order control (host probe): `Option_Spec*` precedes `(Tag_Spec ':')*`, and
/// both must parse on the same `Cmnd_Spec`.
///
/// `alice ALL = TIMEOUT=30 NOEXEC: /bin/ls` is rc 0; the reversed
/// `alice ALL = NOEXEC: TIMEOUT=30 /bin/ls` is rc 1 (`syntax error`), which is
/// why the two loops must not be reordered or interleaved. This is the only
/// shape that pins options-and-tags working together: the corpus has
/// `(root) NOEXEC: /bin/ls` and `(root) TIMEOUT=30 ...` but no line with both.
///
/// Named `gap_ac_` because it is the INTEGRATION of Gap A and Gap C and is
/// therefore the one test in this file that is not separably attributable: it
/// needs the segment splitter to keep the line whole (Gap C) AND the option
/// loop to capture the value (Gap A), so it reddens under either revert. The
/// two gaps each also have their own separably-attributable tests; see
/// `gap_c_option_before_a_tag_does_not_split_the_user_spec` for the Gap C half
/// on its own.
///
/// No assertion is made about the reversed order: `parse_cmnd_spec` is total
/// and has no reject path, so the grammar's order is a reason not to build an
/// interleaved matcher, not a verdict this parser can render.
#[test]
fn gap_ac_options_then_tags_both_parse_on_one_cmnd_spec() {
    let s = only_spec("alice ALL = TIMEOUT=30 NOEXEC: /bin/ls\n");
    let specs = &s.host_groups[0].cmnd_specs;
    assert_eq!(specs.len(), 1);
    assert_eq!(specs[0].options, opt(CmndOptionKey::Timeout, "30"));
    assert_eq!(specs[0].tags, vec![Tag::NoExec]);
    assert_eq!(specs[0].cmnd, CmndItem::Cmnd("/bin/ls".to_string()));
}

/// Host probe (rc 0): each `Cmnd_Spec` in a `Cmnd_Spec_List` keeps its OWN
/// option.
///
/// `split_cmnd_specs` already runs before `parse_cmnd_spec`, so per-spec
/// options fall out for free and no second splitter is needed - this pins that,
/// and kills an implementation that only handles the first spec of the list.
///
/// Like `tags`, `options` records the EXPLICIT options written on THIS spec,
/// not inheritance-resolved ones: the AST stays a faithful record of what was
/// written and the resolving walk belongs to a lint pass. `cvtsudoers` takes
/// the opposite view and PRE-RESOLVES inheritance - on this input it reports
/// the second spec as `[{"runcwd":"/tmp"},{"command_timeout":30}]`, carrying
/// the first spec's `TIMEOUT` forward. That divergence is a deliberate,
/// documented modelling choice (see `ast::CmndSpec`), and it is invisible to
/// the L3 differential, which compares users / hosts / commands only.
#[test]
fn gap_a_each_cmnd_spec_in_a_list_keeps_its_own_option() {
    let s = only_spec("alice ALL = TIMEOUT=30 /bin/ls, CWD=/tmp /bin/cat\n");
    let specs = &s.host_groups[0].cmnd_specs;
    assert_eq!(specs.len(), 2, "two Cmnd_Specs; got {specs:?}");
    assert_eq!(specs[0].options, opt(CmndOptionKey::Timeout, "30"));
    assert_eq!(specs[0].cmnd, CmndItem::Cmnd("/bin/ls".to_string()));
    assert_eq!(
        specs[1].options,
        opt(CmndOptionKey::Cwd, "/tmp"),
        "the second spec carries only the option WRITTEN on it (explicit, not \
         inheritance-resolved)"
    );
    assert_eq!(specs[1].cmnd, CmndItem::Cmnd("/bin/cat".to_string()));
}

// ===========================================================================
// Gap B: a User_List with internal whitespace must not be truncated
// ===========================================================================

/// corpus `accept-user-list-whitespace-bug`, input line verbatim - note the
/// space after `bob,` and the space-free `ALL=(ALL)`.
///
/// `cvtsudoers -f json` (corpus `el9.json` / `el10.json`) reports
/// `User_List [{"username":"bob"},{"username":"ALL"}]`,
/// `Host_List [{"hostname":"ALL"}]`, `Commands [{"command":"ALL"}]`.
/// Today our AST reports `users = ["bob"]` and `hosts = ["ALL ALL"]`: the
/// reserved `ALL` principal is DROPPED and the two host tokens are merged into
/// one whitespace-containing garbage token.
#[test]
fn gap_b_comma_space_user_list_keeps_the_reserved_all_principal() {
    let s = only_spec("bob, ALL ALL=(ALL) ALL\n");
    assert_eq!(
        s.users,
        vec!["bob".to_string(), "ALL".to_string()],
        "the User_List continues across the comma, so ALL is a SUBJECT"
    );
    assert_eq!(s.host_groups.len(), 1);
    assert_eq!(
        s.host_groups[0].hosts,
        vec!["ALL".to_string()],
        "the host list is exactly [ALL]"
    );
    assert!(
        !s.host_groups[0].hosts.iter().any(|h| h.contains(' ')),
        "no host token may contain whitespace - a merged `ALL ALL` token is the \
         specific corruption this pins; got {:?}",
        s.host_groups[0].hosts
    );

    let specs = &s.host_groups[0].cmnd_specs;
    assert_eq!(specs.len(), 1);
    let runas = specs[0]
        .runas
        .as_ref()
        .expect("`(ALL)` must still parse as a runas spec");
    assert_eq!(runas.users, vec!["ALL".to_string()]);
    assert_eq!(specs[0].cmnd, CmndItem::All);
}

/// Host probe (rc 0): whitespace BEFORE the comma is equally legal, so the
/// `User_List` must continue across a free-standing comma token too.
///
/// `bob , ALL ALL=(ALL) ALL` parses OK and `cvtsudoers` reports the same
/// `User_List [{"username":"bob"},{"username":"ALL"}]` /
/// `Host_List [{"hostname":"ALL"}]` as the corpus row above. An implementation
/// that only looks for a TRAILING comma on the previous token would drop `ALL`
/// here while passing the corpus row.
#[test]
fn gap_b_space_before_the_comma_also_keeps_the_all_principal() {
    let s = only_spec("bob , ALL ALL=(ALL) ALL\n");
    assert_eq!(s.users, vec!["bob".to_string(), "ALL".to_string()]);
    assert_eq!(s.host_groups[0].hosts, vec!["ALL".to_string()]);
    assert_eq!(s.host_groups[0].cmnd_specs[0].cmnd, CmndItem::All);
}

/// Host probe (rc 0): the third and last comma placement - glued to the NEXT
/// token.
///
/// `bob ,ALL ALL=(ALL) ALL` reports the same
/// `User_List [{"username":"bob"},{"username":"ALL"}]` /
/// `Host_List [{"hostname":"ALL"}]` as the other two spellings. With the
/// trailing form (`bob, ALL`) and the standalone form (`bob , ALL`) already
/// covered, this completes the set, so no implementation can pass by handling
/// only the comma placements the corpus happens to contain.
#[test]
fn gap_b_leading_comma_continuation_keeps_the_all_principal() {
    let s = only_spec("bob ,ALL ALL=(ALL) ALL\n");
    assert_eq!(s.users, vec!["bob".to_string(), "ALL".to_string()]);
    assert_eq!(s.host_groups[0].hosts, vec!["ALL".to_string()]);
    assert_eq!(s.host_groups[0].cmnd_specs[0].cmnd, CmndItem::All);
}

/// Host probe (rc 0): the user list must stop at the END of its comma-continued
/// run, NOT swallow a comma-separated HOST list that follows.
///
/// `alice, bob web1, web2 = /bin/ls` reports
/// `User_List [alice, bob]` / `Host_List [web1, web2]`. This is the sharpest
/// over-consumption control in the lane: an implementation that greedily
/// consumes every comma-continued run would take `web1,` as a fourth user and
/// leave `web2` as the whole host list, and every other Gap B test here would
/// still pass.
#[test]
fn gap_b_user_list_stops_before_a_comma_separated_host_list() {
    let s = only_spec("alice, bob web1, web2 = /bin/ls\n");
    assert_eq!(s.users, vec!["alice".to_string(), "bob".to_string()]);
    assert_eq!(
        s.host_groups[0].hosts,
        vec!["web1".to_string(), "web2".to_string()],
        "the host list keeps BOTH of its comma-separated members"
    );
    assert_eq!(
        s.host_groups[0].cmnd_specs[0].cmnd,
        CmndItem::Cmnd("/bin/ls".to_string())
    );
}

/// Host probe (rc 0): with no comma at all the split is still at the first
/// space. `alice bob = /bin/ls` reports `User_List [alice]` /
/// `Host_List [bob]`.
///
/// This pins that the new splitting rule is comma-DRIVEN, not "consume until
/// something looks like a host": an implementation that always merged the first
/// two words would break this.
#[test]
fn gap_b_user_list_without_a_comma_still_ends_at_the_first_space() {
    let s = only_spec("alice bob = /bin/ls\n");
    assert_eq!(s.users, vec!["alice".to_string()]);
    assert_eq!(s.host_groups[0].hosts, vec!["bob".to_string()]);
}

/// Regression control - corpus `accept-multi-user-list` (`alice,bob ALL =
/// /bin/ls`, no spaces). Passes today and must keep passing.
#[test]
fn gap_b_multi_user_list_without_spaces_still_parses() {
    let s = only_spec("alice,bob ALL = /bin/ls\n");
    assert_eq!(s.users, vec!["alice".to_string(), "bob".to_string()]);
    assert_eq!(s.host_groups[0].hosts, vec!["ALL".to_string()]);
    assert_eq!(
        s.host_groups[0].cmnd_specs[0].cmnd,
        CmndItem::Cmnd("/bin/ls".to_string())
    );
}

/// Regression control - corpus `accept-basic-all-grant` (`root ALL=(ALL) ALL`),
/// the differential's own two-sided positive control. Passes today and must
/// keep passing.
#[test]
fn gap_b_basic_all_grant_still_parses() {
    let s = only_spec("root ALL=(ALL) ALL\n");
    assert_eq!(s.users, vec!["root".to_string()]);
    assert_eq!(s.host_groups[0].hosts, vec!["ALL".to_string()]);
    assert_eq!(s.host_groups[0].cmnd_specs[0].cmnd, CmndItem::All);
}

/// Malformed control (host probe, rc 1 `syntax error`): a spec whose ENTIRE
/// pre-`=` text is one comma-continued run has a user list and NO host list,
/// and the existing `user_part.is_empty() || host_part.is_empty()` guard must
/// still reject it.
///
/// `alice, bob = /bin/ls` is where the two readings diverge visibly: today
/// `split_first_word` hands back `("alice,", "bob")` - both non-empty - so the
/// line is wrongly accepted as `users = [alice]`, `hosts = [bob]`, inventing a
/// host named after a user. Once the user list is comma-aware the whole LHS is
/// the user list, `host_part` is empty, and the guard fires as real sudo does.
///
/// The message is pinned so a future refactor cannot satisfy this by
/// classifying the line `Malformed` for some UNRELATED reason.
#[test]
fn gap_b_user_list_with_no_host_list_is_malformed() {
    match first_kind("alice, bob = /bin/ls\n") {
        LineKind::Malformed(msg) => assert_eq!(
            msg, "user specification needs both a user list and a host list before the `=`",
            "must fail on the MISSING HOST LIST specifically"
        ),
        other => panic!(
            "`alice, bob = /bin/ls` has no host list (visudo rc 1) and must be \
             Malformed; got {other:?}"
        ),
    }
}

// ===========================================================================
// Gap B, operator-visible: the false negative this issue is actually about
// ===========================================================================

/// The whole point of Gap B, at the surface an operator sees.
///
/// `sudo-W06` is the DISA finding for the reserved `ALL` appearing in a
/// `User_List`. `bob, ALL ALL=(ALL) ALL` really does grant EVERY user on the
/// box unrestricted sudo, and `cvtsudoers` agrees the `User_List` is
/// `[bob, ALL]` - but because the parser drops `ALL` from the subject list, the
/// lint sees only `bob` and stays silent. A false negative on a STIG control is
/// the worst failure class this product has, and no parser-level assertion
/// proves the operator ever sees the finding.
///
/// The space-free spelling is asserted alongside as a regression control: it is
/// the fixture the existing in-crate W06 test uses precisely BECAUSE it
/// sidesteps this gap, so it fires today and must keep firing.
///
/// # Round 2: the comma spelling is not the only one that hides `ALL`
///
/// Round 1 covers only whitespace introduced by a COMMA. A principal may also
/// carry whitespace inside itself. `man 5 sudoers` on this host (sudo 1.9.17p2,
/// rendered page lines 399-402, read 2026-07-31):
///
/// ```text
/// A user name, user-ID, group, group-ID, netgroup, nonunix_group or
/// nonunix_gid may be enclosed in double quotes to avoid the need for escaping
/// special characters.  Alternately, special characters may be specified in
/// escaped hex mode, e.g., \x20 for space.
/// ```
///
/// Host probe, 2026-07-31, `visudo -c -f -` rc 0:
///
/// ```text
/// "my user", ALL ALL = ALL
///     cvtsudoers: User_List [{"username":"my user"},{"username":"ALL"}]
///                 Host_List [{"hostname":"ALL"}]  Commands [{"command":"ALL"}]
/// ```
///
/// So this line grants EVERY user on the box unrestricted sudo, exactly as
/// `bob, ALL ALL=(ALL) ALL` does, and round 1 leaves W06 silent on it: the
/// user list is truncated to `"my` at the space inside the quotes. Same DISA
/// false negative, different spelling.
#[test]
fn gap_b_w06_fires_on_a_spaced_user_list_granting_all() {
    assert_eq!(
        w06_count("bob,ALL ALL=(ALL) ALL\n"),
        1,
        "control: the space-free spelling already fires today"
    );
    assert_eq!(
        w06_count("bob, ALL ALL=(ALL) ALL\n"),
        1,
        "the reserved ALL principal is a MEMBER of this User_List regardless of \
         the whitespace after the comma, so W06 must fire on the spaced form too"
    );
    assert_eq!(
        w06_count("\"my user\", ALL ALL = ALL\n"),
        1,
        "a QUOTED principal carrying a space must not truncate the User_List \
         either: `ALL` is still a member and W06 must fire (host probe, rc 0)"
    );
    assert_eq!(
        s_hosts("\"my user\", ALL ALL = ALL\n"),
        vec!["ALL".to_string()],
        "and the Host_List is exactly [ALL], not a merged garbage token"
    );
}

// ===========================================================================
// Gap C: an Option_Spec's own `=` must not desync the top-level `:` splitter
// ===========================================================================
//
// Found during this lane's satisfiability run, and accepted as part of #538
// (same root cause - the parser has no model of `Option_Spec` - same issue,
// same file). It is a THIRD independent defect, in `split_top_level_segments`
// rather than `parse_cmnd_spec`, and it is strictly worse than Gap A: Gap A
// yields a garbage command token, Gap C throws the WHOLE LINE away as
// `Malformed`, so `sudo-F01` fires on a line real sudo accepts and every lint
// that would have read the line never sees it.
//
// Mechanism: in `split_top_level_segments` the `'='` arm resets `tok_start`
// unconditionally, and interior whitespace deliberately does not. So on
// `alice ALL = TIMEOUT=30 NOEXEC: /bin/ls` the option's own `=` moves
// `tok_start` to just before `30`, the tag-colon check then sees the preceding
// text as `"30 NOEXEC"`, `parse_tag` rejects it, and the tag colon is treated
// as a genuine top-level host-group separator. The line splits into
// `alice ALL = TIMEOUT=30 NOEXEC` and `/bin/ls`; the second segment has no
// `=`, so the whole logical line is classified `Malformed`.
//
// Any `Option_Spec` followed by any `Tag_Spec` triggers it, which is why the
// tests below use two different keyword/tag pairs.

/// The core Gap C pin, deliberately asserting STRUCTURE ONLY so it is
/// attributable to Gap C alone.
///
/// It does not touch `options` or `tags`, because with Gap C fixed and Gap A
/// still broken the line parses as a user-spec whose command token is the
/// garbage `"TIMEOUT=30 NOEXEC: /bin/ls"` - one host group, one `Cmnd_Spec`,
/// which is exactly what this asserts. So this test reddens under a Gap C
/// revert and NOT under a Gap A revert. Grounded: `visudo -c -f -` rc 0 on
/// this host (sudo 1.9.17p2, 2026-07-30).
#[test]
fn gap_c_option_before_a_tag_does_not_split_the_user_spec() {
    let kind = first_kind("alice ALL = TIMEOUT=30 NOEXEC: /bin/ls\n");
    let LineKind::UserSpec(s) = kind else {
        panic!(
            "`alice ALL = TIMEOUT=30 NOEXEC: /bin/ls` is rc 0 to real visudo and must \
             parse as a user-spec, not be thrown away; got {kind:?}"
        );
    };
    assert_eq!(
        s.host_groups.len(),
        1,
        "the `NOEXEC:` tag colon is NOT a top-level host-group separator, so this \
         line has exactly ONE host group; got {:?}",
        s.host_groups
    );
    assert_eq!(
        s.host_groups[0].cmnd_specs.len(),
        1,
        "one Cmnd_Spec; got {:?}",
        s.host_groups[0].cmnd_specs
    );
}

/// The same defect with a different option keyword and a different tag, so an
/// implementation cannot special-case the `TIMEOUT`/`NOEXEC` pair the other
/// test uses. `alice ALL = ROLE=sysadm_r NOPASSWD: /bin/ls` is rc 0 on this
/// host.
///
/// `NOPASSWD` also makes the operator cost concrete: this is a passwordless
/// grant, and today the entire line is discarded as `Malformed` rather than
/// linted.
#[test]
fn gap_c_selinux_option_before_a_tag_does_not_split_the_user_spec() {
    let kind = first_kind("alice ALL = ROLE=sysadm_r NOPASSWD: /bin/ls\n");
    let LineKind::UserSpec(s) = kind else {
        panic!("`ROLE=sysadm_r NOPASSWD: /bin/ls` is rc 0 to real visudo; got {kind:?}");
    };
    assert_eq!(s.host_groups.len(), 1);
    assert_eq!(s.host_groups[0].hosts, vec!["ALL".to_string()]);
}

/// Regression control (host probe, rc 0): fixing Gap C must not make the
/// splitter blind to a GENUINE top-level `:` separator that follows an option.
///
/// `alice h1 = TIMEOUT=30 /bin/ls : h2 = /bin/id` really is two host groups
/// (`cvtsudoers` reports two `User_Specs` entries). This passes today only by
/// luck - `tok_start` happens to land on `30` and the preceding text
/// `"30 /bin/ls"` is not a tag either way - so it is a control against an
/// over-broad Gap C fix that suppressed real separators, not a RED test.
#[test]
fn gap_c_option_does_not_swallow_a_genuine_host_group_separator() {
    let s = only_spec("alice h1 = TIMEOUT=30 /bin/ls : h2 = /bin/id\n");
    assert_eq!(
        s.host_groups.len(),
        2,
        "the top-level `:` still separates two host groups; got {:?}",
        s.host_groups
    );
    assert_eq!(s.host_groups[0].hosts, vec!["h1".to_string()]);
    assert_eq!(s.host_groups[1].hosts, vec!["h2".to_string()]);
    assert_eq!(
        s.host_groups[1].cmnd_specs[0].cmnd,
        CmndItem::Cmnd("/bin/id".to_string())
    );
}

/// Regression control: a tag keyword SPACED away from its colon must still be
/// recognized after the Gap C fix.
///
/// `alice h1 = NOPASSWD : ALL` (rc 0) stays ONE host group. This is the
/// behavior the current `tok_start` design deliberately supports by NOT
/// resetting on whitespace, and it is exactly what a careless Gap C fix (for
/// instance, resetting `tok_start` on whitespace) would break. Pinning it here
/// means the implementer finds that out from this suite rather than from a
/// surprised reviewer.
#[test]
fn gap_c_tag_keyword_spaced_from_its_colon_is_still_a_tag() {
    let s = only_spec("alice h1 = NOPASSWD : ALL\n");
    assert_eq!(
        s.host_groups.len(),
        1,
        "`NOPASSWD :` is a tag colon, not a separator; got {:?}",
        s.host_groups
    );
    assert_eq!(s.host_groups[0].cmnd_specs[0].tags, vec![Tag::NoPasswd]);
    assert_eq!(s.host_groups[0].cmnd_specs[0].cmnd, CmndItem::All);
}

// ===========================================================================
// Round 2 (strengthening): QUOTED and BACKSLASH-ESCAPED tokens
// ===========================================================================
//
// Round 1 closed gaps A, B and C for the token spellings the corpus happens to
// contain: every option value is a whitespace-free, unquoted, punctuation-free
// word, and every principal is a bare name. No corpus scenario contains a `"`
// at all. The round-1 code therefore ends an option token at the first
// whitespace and a `User_List` at the first non-comma-adjacent whitespace, and
// both readings split INSIDE a quoted or escaped token.
//
// `man 5 sudoers` on this host (sudo 1.9.17p2, `visudo grammar version 50`,
// rendered page lines 399-402, read 2026-07-31) records the quoting rule for
// principals, and every input in this section was re-derived on this host with
// `printf '%s\n' "<line>" | visudo -c -f -` and the same line through
// `cvtsudoers -f json` on 2026-07-31. Every one of them is rc 0: these are
// valid sudoers lines that RuleSteward gets wrong.
//
// The two pre-existing splitters in `parser.rs` already honor a backslash
// (`split_top_level_segments` and `split_cmnd_specs`), and the former also
// tracks paren depth and double quotes, so honoring quotes and escapes in the
// option scanner is CONSISTENCY with the surrounding code, not an expansion of
// the lane.
//
// The expected AST value for a quoted or escaped token is the VERBATIM SOURCE
// BYTES: `CWD="/a b"` stores `"/a b"` WITH its quotes, `my\ user` stores
// `my\ user` WITH its backslash. That matches the documented convention on
// `ast::CmndOption` ("kept as WRITTEN, never coerced") and `ast::RunasSpec`
// ("RAW comma-split tokens"), and it preserves information a consumer can
// still strip. It DIVERGES from `cvtsudoers -f json`, which dequotes; where a
// differential projection compares the two, the PROJECTION accounts for the
// difference, never the AST.
//
// Failure classes closed here, in increasing order of harm:
//
//   1. a truncated option value plus a garbage command token (Gap A's own
//      failure class, on the `commands` axis L3 compares);
//   2. an EMPTY command token from a `Cmnd_Spec_List` split inside a quoted
//      value;
//   3. the whole logical line thrown away as `Malformed`, which also emits a
//      `sudo-F01` FATAL on a line real sudo accepts (Gap C's failure class);
//   4. a dropped `ALL` principal and a silent `sudo-W06`, the DISA finding
//      (Gap B's failure class).

/// Two options where the FIRST value is quoted and contains a space.
///
/// Host probe, 2026-07-31, `visudo -c -f -` rc 0:
///
/// ```text
/// alice ALL = TYPE="a b" ROLE=r /bin/ls
///     cvtsudoers: Options [{"role":"r"},{"type":"a b"}]
///                 Commands [{"command":"/bin/ls"}]
/// ```
///
/// Round 1 splits the option token at the space inside the quotes, yielding
/// `options = [Type("\"a")]` and the garbage command `b" ROLE=r /bin/ls`. Note
/// what that costs beyond the corrupted command: the ENTIRE `ROLE=r` option is
/// LOST, because the scan stops at the first token it cannot read as an option.
///
/// The `options.len() == 2` assertion is deliberately made FIRST and separately
/// from the whole-`Vec` comparison: it kills the silent option loss
/// independently of how the value is spelled, so an implementation that gets
/// the quote handling subtly wrong still fails here with a message that names
/// the actual defect.
///
/// Source order, not `cvtsudoers` order: the AST records options in the order
/// WRITTEN (`ast::CmndSpec::options`, "in SOURCE order"), and `cvtsudoers`
/// reports this line's `SELinux` pair as `role` then `type` even though the
/// source writes `TYPE=` first. That reordering is the oracle's, not ours.
#[test]
fn gap_a_two_options_survive_when_the_first_value_is_quoted() {
    let s = only_spec("alice ALL = TYPE=\"a b\" ROLE=r /bin/ls\n");
    let specs = &s.host_groups[0].cmnd_specs;
    assert_eq!(specs.len(), 1, "one Cmnd_Spec; got {specs:?}");
    assert_eq!(
        specs[0].options.len(),
        2,
        "BOTH options must survive: a quoted value in the first option must not \
         end the option scan and silently discard `ROLE=r`; got {:?}",
        specs[0].options
    );
    assert_eq!(
        specs[0].options,
        vec![
            CmndOption {
                key: CmndOptionKey::Type,
                value: "\"a b\"".to_string(),
            },
            CmndOption {
                key: CmndOptionKey::Role,
                value: "r".to_string(),
            },
        ],
        "values are the verbatim source bytes, in SOURCE order"
    );
    assert_eq!(
        specs[0].cmnd,
        CmndItem::Cmnd("/bin/ls".to_string()),
        "the command token must not inherit the tail of a quoted option value"
    );
}

/// A comma INSIDE a quoted option value must not split the `Cmnd_Spec_List`.
///
/// Host probe, 2026-07-31, `visudo -c -f -` rc 0:
///
/// ```text
/// alice ALL = CWD="/a,b" /bin/ls
///     cvtsudoers: ONE Cmnd_Spec, Options [{"runcwd":"/a,b"}],
///                 Commands [{"command":"/bin/ls"}]
/// ```
///
/// Round 1 produces TWO `CmndSpec`s here - `{options:[Cwd("\"/a")], cmnd:
/// Cmnd("")}` and `{cmnd: Cmnd("b\" /bin/ls")}` - so a grant becomes an EMPTY
/// command token plus a garbage one.
///
/// `split_cmnd_specs`'s own doc justifies "There is NO quote tracking" on the
/// premise that sudo REJECTS an unescaped quoted comma. That premise is true
/// for a COMMAND and FALSE for an option value, re-derived on this host
/// 2026-07-31:
///
/// ```text
/// alice ALL = /bin/echo "a, b"    rc 1  "expected a fully-qualified path name"
/// alice ALL = CWD="/a,b" /bin/ls  rc 0
/// ```
///
/// So the new option code inherited a premise that is false in its own domain.
/// The command-side premise is untouched and stays grounded.
#[test]
fn gap_a_comma_inside_a_quoted_option_value_does_not_split_the_cmnd_spec_list() {
    let s = only_spec("alice ALL = CWD=\"/a,b\" /bin/ls\n");
    let specs = &s.host_groups[0].cmnd_specs;
    assert_eq!(
        specs.len(),
        1,
        "the comma is INSIDE a quoted option value, so it is not a Cmnd_Spec \
         separator; got {specs:?}"
    );
    assert_eq!(specs[0].options, opt(CmndOptionKey::Cwd, "\"/a,b\""));
    assert_eq!(specs[0].cmnd, CmndItem::Cmnd("/bin/ls".to_string()));
}

/// General guard: no `CmndSpec` produced from a VALID sudoers line may carry an
/// empty command token.
///
/// An empty `CmndItem::Cmnd("")` is never a real grant - it is the signature of
/// a splitter that cut a token in half - and it matches no `Cmnd_Alias`, no
/// reserved-`ALL` check and no path check, so it is silent. This guard is
/// spelling-independent: it catches the next quoted-separator bug even if that
/// bug's value spelling is one nobody thought to enumerate.
///
/// Every input below is `visudo -c -f -` rc 0 on this host (2026-07-31).
///
/// The `seen > 0` assertion is the instrument's own positive control: a guard
/// that inspected NOTHING (because every line came back `Malformed`, which is
/// exactly what round 1 does to four of these) would otherwise report clean.
#[test]
fn no_cmnd_spec_from_a_valid_line_carries_an_empty_command_token() {
    let cases = [
        "alice ALL = CWD=\"/a,b\" /bin/ls\n",
        "alice ALL = CWD=\"/tmp/a b\" /bin/ls\n",
        "alice h1 = CWD=\"/a:b\" /bin/ls\n",
        "alice ALL = CWD=/tmp/a\\ b /bin/ls\n",
        "alice ALL = TYPE=\"a b\" ROLE=r /bin/ls\n",
        "alice ALL = APPARMOR_PROFILE=\"my profile\" /bin/ls\n",
        "alice ALL = CWD=\"/a b\" NOEXEC: /bin/ls, /bin/cat\n",
        "alice ALL = CWD=/a)b NOEXEC: /bin/ls\n",
    ];
    for src in cases {
        let file = parse(src, Path::new("/etc/sudoers"));
        let mut seen = 0usize;
        for line in &file.lines {
            let LineKind::UserSpec(s) = &line.kind else {
                continue;
            };
            for group in &s.host_groups {
                for spec in &group.cmnd_specs {
                    seen += 1;
                    assert_ne!(
                        spec.cmnd,
                        CmndItem::Cmnd(String::new()),
                        "{src:?} produced a Cmnd_Spec with an EMPTY command token, the \
                         signature of a splitter cutting a token in half; got {:?}",
                        s.host_groups
                    );
                }
            }
        }
        assert!(
            seen > 0,
            "positive control: {src:?} is visudo rc 0 and must yield at least one \
             Cmnd_Spec to inspect, but the guard saw none (the line was discarded)"
        );
    }
}

/// A whitespace-bearing option value before a TAG COLON must not throw the
/// whole line away.
///
/// This is the sharpest input in the section: the line grants `ALL`, and round
/// 1 makes it VANISH.
///
/// Host probe, 2026-07-31, `visudo -c -f -` rc 0:
///
/// ```text
/// alice ALL = CWD="/a b" NOEXEC: ALL
///     cvtsudoers: Options [{"runcwd":"/a b"},{"noexec":true},{"setenv":true}]
///                 Commands [{"command":"ALL"}]
/// ```
///
/// (The `setenv` entry is `cvtsudoers` reporting the semantics sudo attaches to
/// a bare `ALL` command; it is not a tag written on the line, and the AST
/// records only the tags actually WRITTEN.)
///
/// Round 1 returns
/// `Malformed("user specification segment is missing its `= command` part")`.
/// The mechanism: the `'='` arm advances the preceding-token marker by
/// `s[after_eq..].find(char::is_whitespace)`, which for `CWD="/a b"` lands
/// INSIDE the quoted value; at the tag colon the marker has overshot, the
/// clamp in `preceding_token` yields `""`, `""` is not a tag, and the tag colon
/// is read as a top-level host-group separator. The second segment has no `=`,
/// so the whole logical line is discarded.
///
/// The harm doubles, which is why this test asserts both halves: the grant
/// becomes invisible to every lint, AND `sudo-F01` fires, so `RuleSteward`
/// actively reports a valid line as a syntax error.
#[test]
fn gap_c_quoted_option_value_with_a_space_before_a_tag_does_not_split_the_user_spec() {
    let src = "alice ALL = CWD=\"/a b\" NOEXEC: ALL\n";
    let kind = first_kind(src);
    assert!(
        !matches!(kind, LineKind::Malformed(_)),
        "`{}` is visudo rc 0 and must not be discarded; got {kind:?}",
        src.trim_end()
    );
    let LineKind::UserSpec(s) = kind else {
        panic!("expected a user-spec");
    };
    assert_eq!(
        s.host_groups.len(),
        1,
        "the `NOEXEC:` tag colon is not a host-group separator; got {:?}",
        s.host_groups
    );
    let specs = &s.host_groups[0].cmnd_specs;
    assert_eq!(specs.len(), 1, "one Cmnd_Spec; got {specs:?}");
    assert_eq!(specs[0].options, opt(CmndOptionKey::Cwd, "\"/a b\""));
    assert_eq!(specs[0].tags, vec![Tag::NoExec]);
    assert_eq!(
        specs[0].cmnd,
        CmndItem::All,
        "this line grants the reserved ALL command and must not lose it"
    );
    assert_eq!(
        f01_count(src),
        0,
        "no parse-failure Fatal may be emitted for a line real visudo accepts"
    );
}

/// The same defect with a BACKSLASH-ESCAPED space instead of quotes, and a
/// named host instead of `ALL`, so no implementation can pass by handling only
/// the double-quote spelling.
///
/// Host probe, 2026-07-31, rc 0:
///
/// ```text
/// alice h1 = CWD=/tmp/a\ b NOEXEC: /bin/ls
///     cvtsudoers: Options [{"runcwd":"/tmp/a b"},{"noexec":true}]
///                 Commands [{"command":"/bin/ls"}]
/// ```
#[test]
fn gap_c_escaped_space_in_an_option_value_before_a_tag_does_not_split_the_user_spec() {
    let src = "alice h1 = CWD=/tmp/a\\ b NOEXEC: /bin/ls\n";
    assert_eq!(f01_count(src), 0, "visudo rc 0: no sudo-F01 may fire");
    let s = only_spec(src);
    assert_eq!(s.host_groups.len(), 1);
    assert_eq!(s.host_groups[0].hosts, vec!["h1".to_string()]);
    let specs = &s.host_groups[0].cmnd_specs;
    assert_eq!(specs.len(), 1, "one Cmnd_Spec; got {specs:?}");
    assert_eq!(
        specs[0].options,
        opt(CmndOptionKey::Cwd, "/tmp/a\\ b"),
        "the backslash is kept VERBATIM, matching the `\\:` precedent the two \
         pre-existing splitters already set"
    );
    assert_eq!(specs[0].tags, vec![Tag::NoExec]);
    assert_eq!(specs[0].cmnd, CmndItem::Cmnd("/bin/ls".to_string()));
}

/// A COLON inside a quoted option value is not a separator of any kind.
///
/// Host probe, 2026-07-31, rc 0:
///
/// ```text
/// alice h1 = CWD="/a:b" /bin/ls
///     cvtsudoers: Options [{"runcwd":"/a:b"}]  Commands [{"command":"/bin/ls"}]
/// ```
///
/// This is the case that falsifies the round-1 grounding claim that "real sudo
/// REJECTS a colon in an option value". That is true UNQUOTED - `CWD=/a:/b` and
/// `TIMEOUT=30:x` are both rc 1 - and false once the value is quoted. The
/// unquoted reading is untouched by this test; only the quoted one is pinned.
#[test]
fn gap_c_quoted_colon_in_an_option_value_is_not_a_separator() {
    let src = "alice h1 = CWD=\"/a:b\" /bin/ls\n";
    assert_eq!(f01_count(src), 0, "visudo rc 0: no sudo-F01 may fire");
    let s = only_spec(src);
    assert_eq!(
        s.host_groups.len(),
        1,
        "a quoted colon is a value byte, not a host-group separator; got {:?}",
        s.host_groups
    );
    assert_eq!(s.host_groups[0].hosts, vec!["h1".to_string()]);
    let specs = &s.host_groups[0].cmnd_specs;
    assert_eq!(specs.len(), 1, "one Cmnd_Spec; got {specs:?}");
    assert_eq!(specs[0].options, opt(CmndOptionKey::Cwd, "\"/a:b\""));
    assert_eq!(specs[0].cmnd, CmndItem::Cmnd("/bin/ls".to_string()));
}

/// The whitespace-bearing option value combined with a multi-command
/// `Cmnd_Spec_List`, so the fix cannot be a special case for a single-command
/// line.
///
/// Host probe, 2026-07-31, rc 0:
///
/// ```text
/// alice ALL = CWD="/a b" NOEXEC: /bin/ls, /bin/cat
///     cvtsudoers: Options [{"runcwd":"/a b"},{"noexec":true}]
///                 Commands [{"command":"/bin/ls"},{"command":"/bin/cat"}]
/// ```
///
/// `cvtsudoers` reports ONE `Cmnd_Spec` with two `Commands`; the AST models the
/// list as TWO `CmndSpec`s carrying only the options and tags WRITTEN on each
/// (tag inheritance is the separate #330 pass), the same shape
/// `gap_a_each_cmnd_spec_in_a_list_keeps_its_own_option` already pins. Round 1
/// discards the entire line as `Malformed`.
#[test]
fn gap_c_quoted_option_value_before_a_tag_keeps_the_whole_cmnd_spec_list() {
    let src = "alice ALL = CWD=\"/a b\" NOEXEC: /bin/ls, /bin/cat\n";
    assert_eq!(f01_count(src), 0, "visudo rc 0: no sudo-F01 may fire");
    let s = only_spec(src);
    assert_eq!(s.host_groups.len(), 1);
    let specs = &s.host_groups[0].cmnd_specs;
    assert_eq!(specs.len(), 2, "two Cmnd_Specs; got {specs:?}");
    assert_eq!(specs[0].options, opt(CmndOptionKey::Cwd, "\"/a b\""));
    assert_eq!(specs[0].tags, vec![Tag::NoExec]);
    assert_eq!(specs[0].cmnd, CmndItem::Cmnd("/bin/ls".to_string()));
    assert_eq!(
        specs[1].cmnd,
        CmndItem::Cmnd("/bin/cat".to_string()),
        "the second command must survive intact, not carry the tail of the \
         quoted option value"
    );
}

/// A `)` inside an option value must not drag the preceding-token marker
/// BACKWARD, undoing the `'='` arm's skip.
///
/// No quotes are involved: this is a defect entirely inside the code round 1
/// added. Host probe, 2026-07-31, rc 0:
///
/// ```text
/// alice ALL = CWD=/a)b NOEXEC: /bin/ls
///     cvtsudoers: Options [{"runcwd":"/a)b"},{"noexec":true}]
///                 Commands [{"command":"/bin/ls"}]
/// ```
///
/// Mechanism: the `'='` arm sets the marker to the END of the whole `CWD=/a)b`
/// token, and the `')'` arm - which runs at a byte INSIDE that token - then
/// unconditionally resets the marker to just after itself, i.e. BACKWARD into
/// the middle of the value. At the tag colon the span is `"b NOEXEC"`, which is
/// not a tag, so the colon splits and the line is discarded as `Malformed`.
///
/// The `=` sibling of this defect is unreachable (`CWD=/a=b` is rc 1,
/// `stdin:1:19: syntax error`, re-derived 2026-07-31); the `)` one is
/// reachable, because a `)` is an ordinary byte in a directory name.
#[test]
fn gap_c_option_value_containing_a_paren_does_not_split_the_user_spec() {
    let src = "alice ALL = CWD=/a)b NOEXEC: /bin/ls\n";
    assert_eq!(f01_count(src), 0, "visudo rc 0: no sudo-F01 may fire");
    let s = only_spec(src);
    assert_eq!(
        s.host_groups.len(),
        1,
        "a `)` inside an option value is not a token boundary, so the tag colon \
         is still a tag colon; got {:?}",
        s.host_groups
    );
    let specs = &s.host_groups[0].cmnd_specs;
    assert_eq!(specs.len(), 1, "one Cmnd_Spec; got {specs:?}");
    assert_eq!(specs[0].options, opt(CmndOptionKey::Cwd, "/a)b"));
    assert_eq!(specs[0].tags, vec![Tag::NoExec]);
    assert_eq!(specs[0].cmnd, CmndItem::Cmnd("/bin/ls".to_string()));
}

// ---------------------------------------------------------------------------
// Round 2, Gap B: a principal may carry whitespace inside itself
// ---------------------------------------------------------------------------

/// A QUOTED principal containing a space, in a `User_List` that also grants
/// `ALL`.
///
/// Host probe, 2026-07-31, `visudo -c -f -` rc 0:
///
/// ```text
/// "my user", ALL ALL = ALL
///     cvtsudoers: User_List [{"username":"my user"},{"username":"ALL"}]
///                 Host_List [{"hostname":"ALL"}]  Commands [{"command":"ALL"}]
/// ```
///
/// Round 1 truncates the user list at the space INSIDE the quotes, yielding
/// `users = ["\"my"]` and `hosts = ["user\"", "ALL ALL"]`: the reserved `ALL`
/// principal is dropped from the subject list, exactly the Gap B harm, for the
/// spelling the Gap B fix did not cover. The operator-visible half (`sudo-W06`
/// stays silent) is asserted in
/// `gap_b_w06_fires_on_a_spaced_user_list_granting_all`.
///
/// The stored principal is the VERBATIM source token, quotes retained, matching
/// `ast::RunasSpec`'s "RAW comma-split tokens" convention. `cvtsudoers`
/// dequotes to `my user`; that difference belongs to the projection.
#[test]
fn gap_b_quoted_principal_with_a_space_keeps_the_reserved_all_principal() {
    let s = only_spec("\"my user\", ALL ALL = ALL\n");
    assert_eq!(
        s.users,
        vec!["\"my user\"".to_string(), "ALL".to_string()],
        "the quoted principal is ONE user and `ALL` is the second, so the \
         reserved principal stays in the subject list"
    );
    assert_eq!(s.host_groups.len(), 1);
    assert_eq!(s.host_groups[0].hosts, vec!["ALL".to_string()]);
    assert!(
        !s.host_groups[0].hosts.iter().any(|h| h.contains(' ')),
        "no host token may contain whitespace; got {:?}",
        s.host_groups[0].hosts
    );
    assert_eq!(s.host_groups[0].cmnd_specs[0].cmnd, CmndItem::All);
}

/// The same quoted principal with NO comma, so the fix cannot key on a comma.
///
/// Host probe, 2026-07-31, rc 0: `"my user" ALL = ALL` reports
/// `User_List [{"username":"my user"}]` / `Host_List [{"hostname":"ALL"}]`.
///
/// Round 1 yields `users = ["\"my"]` and the single merged garbage host token
/// `"user\" ALL"`. This is the input that proves the user-list boundary is not
/// merely comma-driven: a quoted token is ONE token whether or not a comma
/// follows it.
#[test]
fn gap_b_quoted_principal_alone_does_not_swallow_the_host_list() {
    let s = only_spec("\"my user\" ALL = ALL\n");
    assert_eq!(s.users, vec!["\"my user\"".to_string()]);
    assert_eq!(
        s.host_groups[0].hosts,
        vec!["ALL".to_string()],
        "the host list is exactly [ALL], not a merged token"
    );
    assert_eq!(s.host_groups[0].cmnd_specs[0].cmnd, CmndItem::All);
}

/// The BACKSLASH-ESCAPED spelling of the same principal.
///
/// `man 5 sudoers` (rendered page line 401, this host) offers escaping as the
/// alternative to quoting, and the shipping parser accepts it: host probe,
/// 2026-07-31, rc 0, `my\ user ALL = ALL` reports
/// `User_List [{"username":"my user"}]` / `Host_List [{"hostname":"ALL"}]`.
///
/// Round 1 yields `users = ["my\\"]` and the merged host token `"user ALL"`.
/// Both pre-existing splitters in `parser.rs` already honor a backslash, so
/// this is the user-list side of the same consistency.
#[test]
fn gap_b_escaped_space_in_a_principal_does_not_swallow_the_host_list() {
    let s = only_spec("my\\ user ALL = ALL\n");
    assert_eq!(
        s.users,
        vec!["my\\ user".to_string()],
        "the backslash-escaped space is part of the principal, kept verbatim"
    );
    assert_eq!(s.host_groups[0].hosts, vec!["ALL".to_string()]);
    assert_eq!(s.host_groups[0].cmnd_specs[0].cmnd, CmndItem::All);
}

/// Regression control for the user-list cursor arithmetic: a MULTI-space
/// whitespace run inside a comma-continued `User_List`.
///
/// Host probe, 2026-07-31, rc 0: `bob,   ALL   ALL=(ALL) ALL` reports the same
/// `User_List [{"username":"bob"},{"username":"ALL"}]` /
/// `Host_List [{"hostname":"ALL"}]` as the single-space corpus spelling.
///
/// Every other Gap B input in this file uses SINGLE spaces, where the end of a
/// whitespace run is trivially `ws_start + 1`. That makes the arithmetic that
/// advances the scan cursor past a run unobservable, and an implementation that
/// advanced by one byte instead of to the end of the run would pass every other
/// test here while returning the untrimmed user part `"bob, "` and the merged
/// host token `"ALL   ALL"` on this line. This is also the exact input that
/// exposes the `split_user_list` cursor arithmetic to the mutation gate.
#[test]
fn gap_b_multi_space_run_in_a_comma_continued_user_list_splits_at_the_run_end() {
    let s = only_spec("bob,   ALL   ALL=(ALL) ALL\n");
    assert_eq!(s.users, vec!["bob".to_string(), "ALL".to_string()]);
    assert!(
        !s.users.iter().any(|u| u.contains(char::is_whitespace)),
        "no user token may carry whitespace from the run; got {:?}",
        s.users
    );
    assert_eq!(s.host_groups[0].hosts, vec!["ALL".to_string()]);
    assert_eq!(s.host_groups[0].cmnd_specs[0].cmnd, CmndItem::All);
}

// ---------------------------------------------------------------------------
// Round 2, Gap C: end-to-end siblings for the splitter's in-crate unit tests
// ---------------------------------------------------------------------------

/// End-to-end sibling of the in-crate unit test
/// `command_argument_tag_keyword_before_a_colon_still_splits`
/// (`src/parser.rs`), which drives the private `split_top_level_segments`
/// directly and has had no test at the public entry point.
///
/// Host probe, 2026-07-31, `visudo -c -f -` rc 0:
///
/// ```text
/// alice h1 = /bin/echo NOPASSWD : h2 = ALL
///     cvtsudoers: TWO User_Specs
///       h1 -> Commands [{"command":"/bin/echo NOPASSWD"}]
///       h2 -> Commands [{"command":"ALL"}]
/// ```
///
/// Once the COMMAND word has begun a tag keyword is an ARGUMENT, so the colon
/// really does separate two host groups. This passes today; it is the control
/// half of the pair, and it exists so the RED test below is attributable to the
/// `=` in the argument rather than to the tag keyword.
#[test]
fn gap_c_command_argument_tag_keyword_before_a_colon_still_splits_end_to_end() {
    let s = only_spec("alice h1 = /bin/echo NOPASSWD : h2 = ALL\n");
    assert_eq!(
        s.host_groups.len(),
        2,
        "a tag keyword used as a command ARGUMENT does not make the following \
         colon a tag colon; got {:?}",
        s.host_groups
    );
    assert_eq!(s.host_groups[0].hosts, vec!["h1".to_string()]);
    assert_eq!(
        s.host_groups[0].cmnd_specs[0].cmnd,
        CmndItem::Cmnd("/bin/echo NOPASSWD".to_string())
    );
    assert_eq!(s.host_groups[1].hosts, vec!["h2".to_string()]);
    assert_eq!(s.host_groups[1].cmnd_specs[0].cmnd, CmndItem::All);
}

/// The RED half of that pair: the same line with a `KEY=value` ARGUMENT in
/// front of the tag keyword.
///
/// Host probe, 2026-07-31, `visudo -c -f -` rc 0:
///
/// ```text
/// alice h1 = /bin/echo X=NOPASSWD : h2 = ALL
///     cvtsudoers: TWO User_Specs
///       h1 -> Commands [{"command":"/bin/echo X=NOPASSWD"}]
///       h2 -> Commands [{"command":"ALL"}]
/// ```
///
/// Round 1 collapses this into ONE host group whose single command is the
/// garbage `"/bin/echo X=NOPASSWD : h2 = ALL"`, and the `h2` grant - a bare
/// `ALL` - disappears entirely.
///
/// Mechanism, and why the unit test above does not catch it: the `'='` arm
/// resets the preceding-token marker on a COMMAND-ARGUMENT `=` as well as on
/// the structural one. With `X=` present the marker lands just after that `=`,
/// so the span at the colon is the bare `"NOPASSWD"` - a tag - and the colon is
/// suppressed. Without `X=` the span is `"/bin/echo NOPASSWD"`, which is not a
/// tag, so the unit test's input splits correctly and the over-reach it claims
/// to guard is invisible to it. A command argument's `=` is not a token
/// boundary for tag-keyword purposes at all.
#[test]
fn gap_c_command_argument_assignment_before_a_tag_keyword_colon_still_splits() {
    let s = only_spec("alice h1 = /bin/echo X=NOPASSWD : h2 = ALL\n");
    assert_eq!(
        s.host_groups.len(),
        2,
        "a `KEY=value` command ARGUMENT must not turn the following separator \
         colon into a tag colon and swallow the second host group; got {:?}",
        s.host_groups
    );
    assert_eq!(s.host_groups[0].hosts, vec!["h1".to_string()]);
    assert_eq!(
        s.host_groups[0].cmnd_specs[0].cmnd,
        CmndItem::Cmnd("/bin/echo X=NOPASSWD".to_string()),
        "the first command keeps its `KEY=value` argument verbatim"
    );
    assert_eq!(s.host_groups[1].hosts, vec!["h2".to_string()]);
    assert_eq!(
        s.host_groups[1].cmnd_specs[0].cmnd,
        CmndItem::All,
        "the second host group's `ALL` grant must not disappear"
    );
}

/// The STRUCTURAL `=` is never an option `=`, even when the token in front of
/// it is spelled like an option keyword.
///
/// This pins the `in_cmnd_list` half of the `'='` arm's guard independently of
/// the keyword-match half, which nothing else in the suite does. Drop it, so
/// that any `=` whose preceding token is an option keyword counts as an option
/// `=`, and the marker skips past the following `NOPASSWD:` token, the clamp
/// then yields `""` at the tag colon, the colon is read as a host-group
/// separator, and the whole line is discarded as `Malformed` with a `sudo-F01`
/// Fatal.
/// (Verified by hand on 2026-07-31 by making exactly that one-operator change
/// in `split_top_level_segments` and re-parsing this line.)
///
/// Grounding, and its limit: `visudo -c -f -` REJECTS this line rc 1,
/// `stdin:1:10: syntax error` pointing at `CWD`, because all ten option
/// keywords are reserved words in sudo's lexer and cannot be used bare as a
/// Host (`alice ROLE = /bin/ls` and `Cmnd_Alias CWD = /bin/ls` are rc 1 too,
/// the latter saying so explicitly: `reserved word CWD used as an alias name`).
/// Quoting rescues the line (`alice "CWD" = /bin/ls` is rc 0) but then the
/// token carries its quotes and is no longer spelled like a keyword. So there
/// is NO visudo-accepted input that separates these two conjuncts, and this
/// test necessarily pins `RuleSteward`'s RECOVERY behavior on a line sudo
/// rejects, in the same spirit as the in-crate
/// `colon_inside_an_option_value_does_not_panic`.
///
/// What is asserted is narrow and defensible on its own terms: `RuleSteward` has
/// no reserved-word check, so it must parse this line leniently rather than
/// discard it, and a `sudo-F01` fired here would be a right answer for an
/// entirely wrong reason.
#[test]
fn gap_c_the_structural_equals_is_never_an_option_equals() {
    let src = "alice h1,CWD=NOPASSWD: /bin/ls\n";
    let kind = first_kind(src);
    assert!(
        !matches!(kind, LineKind::Malformed(_)),
        "the structural `=` must not be mistaken for an option `=`; got {kind:?}"
    );
    let s = only_spec(src);
    assert_eq!(
        s.host_groups.len(),
        1,
        "the `NOPASSWD:` tag colon is not a host-group separator; got {:?}",
        s.host_groups
    );
    assert_eq!(
        s.host_groups[0].hosts,
        vec!["h1".to_string(), "CWD".to_string()],
        "`CWD` here is the last member of the Host_List, not an option keyword"
    );
    let specs = &s.host_groups[0].cmnd_specs;
    assert_eq!(specs.len(), 1, "one Cmnd_Spec; got {specs:?}");
    assert!(
        specs[0].options.is_empty(),
        "no Option_Spec was written on this Cmnd_Spec; got {:?}",
        specs[0].options
    );
    assert_eq!(specs[0].tags, vec![Tag::NoPasswd]);
    assert_eq!(specs[0].cmnd, CmndItem::Cmnd("/bin/ls".to_string()));
    assert_eq!(
        f01_count(src),
        0,
        "the line must not be reported as a parse failure"
    );
}
