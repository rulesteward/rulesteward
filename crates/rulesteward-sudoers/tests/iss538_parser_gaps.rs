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
//! * **Gap A** - `parser::parse_cmnd_spec`'s tag loop originally recognized
//!   only the `TAG:` form. An `=`-form `Option_Spec` (`ROLE=`, `TYPE=`,
//!   `NOTBEFORE=`, `TIMEOUT=`, ...) has no colon, so the loop broke
//!   immediately and handed the ENTIRE remainder to the command constructor:
//!   `ROLE=sysadm_r TYPE=sysadm_t /usr/bin/vim` became ONE garbage
//!   `CmndItem::Cmnd` token that matched no `Cmnd_Alias`, no reserved-`ALL`
//!   check and no path check. Fixed: `parse_cmnd_spec` now runs a separate
//!   `Option_Spec*` loop before the tag loop, matching the grammar's
//!   `Runas_Spec? Option_Spec* (Tag_Spec ':')* Cmnd` order.
//! * **Gap B** - `parser::classify_user_spec` originally split the pre-`=`
//!   text with `split_first_word`, so a `User_List` containing internal
//!   whitespace was truncated at its first space: `bob, ALL ALL=(ALL) ALL`
//!   yielded `users = ["bob"]` and `hosts = ["ALL ALL"]`, dropping the
//!   reserved `ALL` principal and taking `sudo-W06` (the DISA finding for
//!   `ALL` in a `User_List`) down with it. Fixed: `classify_user_spec` now
//!   calls the comma-continuation-aware `split_user_list` instead.
//! * **Gap C** - `parser::split_top_level_segments` originally reset its
//!   preceding-token marker on every `=`, so an `Option_Spec`'s own `=` hid a
//!   following tag keyword and the tag colon was mistaken for a top-level
//!   host-group separator. `alice ALL = TIMEOUT=30 NOEXEC: /bin/ls` was
//!   thrown away as `Malformed`. Found during this lane's satisfiability run.
//!   Fixed: the `'='` arm now checks whether the token is an `Option_Spec`'s
//!   own `=` and, if so, skips `tok_start` past the whole value instead of
//!   resetting it; see the Gap C section below for the full mechanism.
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

use rulesteward_sudoers::ast::{
    AliasKind, CmndItem, CmndOption, CmndOptionKey, LineKind, Tag, UserSpec,
};
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

/// How many `sudo-W05` (STIG-strict broad any-NOPASSWD) findings `lint` emits
/// for `src`. Round 3: several quote-scoping misses hide a `NOPASSWD` grant
/// behind a swallowed command or a merged spec/host-group, and `sudo-W05` is
/// the operator-visible signal that the grant is (or is not) actually seen.
fn w05_count(src: &str) -> usize {
    let files = vec![parse(src, Path::new("/etc/sudoers"))];
    lint(&files, &SudoersLintContext {})
        .iter()
        .filter(|d| d.code == "sudo-W05")
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
/// Before the Gap B fix, our AST reported `users = ["bob"]` and
/// `hosts = ["ALL ALL"]`: the reserved `ALL` principal was DROPPED and the
/// two host tokens were merged into one whitespace-containing garbage token.
/// Fixed: `split_user_list` now finds the true `User_List`/`Host_List`
/// boundary across a comma-continued whitespace run; the assertions below
/// pin the corrected shape.
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
/// Host probe, 2026-07-31, `visudo -c -f -` rc 0, `"my user", ALL ALL=(ALL) ALL`:
///
/// ```text
/// cvtsudoers: User_List [{"username":"my user"},{"username":"ALL"}]
///             Host_List [{"hostname":"ALL"}]  Commands [{"command":"ALL"}]
///             runasusers [{"username":"ALL"}]
/// ```
///
/// So this line grants EVERY user on the box unrestricted sudo, exactly as
/// `bob, ALL ALL=(ALL) ALL` does, and round 1 leaves W06 silent on it: the
/// user list is truncated to `"my` at the space inside the quotes. Same DISA
/// false negative, different spelling.
///
/// The `(ALL)` runas group is load-bearing here, not incidental: `sudo-W06`
/// requires an explicit `Runas_Spec` naming the reserved `ALL` user (DISA's
/// literal check-content is `ALL ALL=(ALL) ALL` / `ALL ALL=(ALL:ALL) ALL`,
/// both WITH a runas group), so a bare `"my user", ALL ALL = ALL` with no
/// runas group at all must NOT fire -- see
/// `gap_b_w06_does_not_fire_without_a_runas_group` immediately below, which
/// pins that as its own negative control with its own host probe.
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
        w06_count("\"my user\", ALL ALL=(ALL) ALL\n"),
        1,
        "a QUOTED principal carrying a space must not truncate the User_List \
         either: `ALL` is still a member and, with the runas group present, \
         W06 must fire (host probe, rc 0)"
    );
    assert_eq!(
        s_hosts("\"my user\", ALL ALL=(ALL) ALL\n"),
        vec!["ALL".to_string()],
        "and the Host_List is exactly [ALL], not a merged garbage token"
    );
}

/// Negative control for the assertion directly above: `sudo-W06` requires an
/// explicit `Runas_Spec` naming the reserved `ALL` user
/// (`is_unrestricted_privilege_elevation` in `tags.rs` early-returns `false`
/// when `effective_runas` is `None`) -- DISA's own check-content literal is
/// `ALL ALL=(ALL) ALL` / `ALL ALL=(ALL:ALL) ALL`, both WITH a runas group.
///
/// Host probe, 2026-07-31, `visudo -c -f -` rc 0, `"my user", ALL ALL = ALL`
/// (no parens at all):
///
/// ```text
/// cvtsudoers: User_List [{"username":"my user"},{"username":"ALL"}]
///             Host_List [{"hostname":"ALL"}]  Commands [{"command":"ALL"}]
/// ```
///
/// No `runasusers` key appears at all, so sudo defaults the runas user to
/// root at invocation time -- narrower than either grounded DISA pattern --
/// and `sudo-W06` must stay silent even though `ALL` is (correctly, per Gap
/// B's fix) a member of the `User_List`. This is the exact defect this test
/// module once had: this fixture was originally asserted to fire W06 with no
/// runas group present at all.
#[test]
fn gap_b_w06_does_not_fire_without_a_runas_group() {
    assert_eq!(
        w06_count("\"my user\", ALL ALL = ALL\n"),
        0,
        "no Runas_Spec at all is narrower than either grounded DISA \
         (ALL)/(ALL:ALL) pattern; W06 must not fire even though ALL is a \
         User_List member"
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
/// grant, and before the gap-C fix the entire line was discarded as `Malformed`
/// rather than linted.
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
/// reserved-`ALL` check and no path check, so it is silent. This guard's
/// MECHANISM is spelling-independent (it never hardcodes an expected value,
/// so any splitter bug that produces an empty command is caught) - but that is
/// not the same as its ENUMERATED CASES being exhaustive: every one of the
/// original eight has an EVEN unescaped-quote count in its option value, and
/// round 3 found that an ODD count takes a genuinely different code path in
/// `option_value_end` (the live `in_quotes` toggle never flips back off, so the
/// scan swallows everything to the end of the line). The two round-3 cases
/// below close that gap; a future case still needs to pick a spelling the
/// current set does not already cover.
///
/// Every input below is `visudo -c -f -` rc 0 on this host (2026-07-31).
///
/// The `seen > 0` assertion is the instrument's own positive control: a guard
/// that inspected NOTHING (because every line came back `Malformed`, which is
/// exactly what round 1 does to four of these) would otherwise report clean.
///
/// The two round-6 cases (glued to a preceding `,` and to a preceding `)`)
/// were a KNOWN-OPEN #538 defect through commit ec11a15's narrow-reverted
/// attempted fix (it regressed real `visudo`-accepted input elsewhere: a
/// false `sudo-F01` fatal, and silently swallowed grants/aliases). Commit
/// `2de19ea` closed this properly: retiring the position-BLIND
/// `is_option_value_quote_opener`/`word_immediately_before` pair and
/// recording each option value's quote span inline, at the same
/// position-ANCHORED point (`preceding_token`/`tok_start`) the `'='` arm's
/// own `is_option_eq` check already used, resolves exactly the
/// two-recognizer disagreement the section comment above
/// `option_keyword_glued_to_a_runas_close_paren_still_opens_its_quoted_value`
/// describes. Both cases are ordinary passing rows below now (measured: FAIL
/// at `93ef75b`, PASS from `2de19ea` onward, re-confirmed at current HEAD
/// 2026-07-31); see that test (no longer `#[ignore]`d) for the fuller
/// history. A narrower #538 subclass - a comma INSIDE a quoted option value,
/// unrelated to any glued spelling - remains open; see the "KNOWN-OPEN #538
/// defects" section later in this file.
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
        // Round 3: an ODD (single) unescaped quote in the value - host probe
        // 2026-07-31, `visudo -c -f -` rc 0, `cvtsudoers -f json`
        // `Options [{"runcwd":"/tmp/a\"b"}]` `Commands [{"command":"/bin/ls"}]`.
        "alice ALL = CWD=/tmp/a\"b /bin/ls\n",
        // Same defect across a host-group separator - rc 0, TWO User_Specs,
        // h1's `Commands [{"command":"/bin/ls"}]`.
        "alice h1 = CWD=/a\"b /bin/ls : h2 = ALL\n",
        // Round 6: an Option_Spec keyword GLUED to a preceding `,` - the
        // since-retired `word_immediately_before` (round 5) split on
        // WHITESPACE ONLY, so it read the preceding word as `/bin/true,CWD`
        // rather than `CWD` and the quote never opened an enclosing span.
        // `visudo -c -f -` rc 0, `cvtsudoers -f json` reports TWO Cmnd_Specs
        // (`/bin/true`, and `runcwd=/a,b` + `/bin/ls`); before commit
        // `2de19ea` this code yielded THREE, with an empty `Cmnd("")` in the
        // middle. Fixed since `2de19ea`. See
        // `option_keyword_glued_to_a_comma_does_not_merge_into_the_preceding_command`
        // below (no longer `#[ignore]`d) for the full AST pin.
        "alice ALL = /bin/true,CWD=\"/a,b\" /bin/ls\n",
        // Round 6: the same defect glued to a preceding `)` instead of `,`.
        // `visudo -c -f -` rc 0, `cvtsudoers -f json` reports ONE Cmnd_Spec
        // (runas root, `runcwd=/a,b`, `/bin/ls`); before commit `2de19ea`
        // this code yielded TWO, the first an empty `Cmnd("")`. Fixed since
        // `2de19ea`. See
        // `option_keyword_glued_to_a_runas_close_paren_with_a_comma_in_its_value_does_not_split_the_cmnd_spec_list`
        // below (no longer `#[ignore]`d) for the full AST pin.
        "alice ALL = (root)CWD=\"/a,b\" /bin/ls\n",
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

// DESCOPED, NOT FORGOTTEN: the RED half of the pair above lived here and is
// tracked as issue #612.
//
// `alice h1 = /bin/echo X=NOPASSWD : h2 = ALL` is `visudo -c -f -` rc 0 with
// TWO User_Specs (`h1 -> /bin/echo X=NOPASSWD`, `h2 -> ALL`), but the `'='` arm
// resets the preceding-token marker on a COMMAND-ARGUMENT `=` as well as on the
// structural one. With `X=` present, the span at the colon is the bare
// `"NOPASSWD"` - a tag - so the colon is suppressed, the two host groups
// collapse into one, and the `h2` grant disappears from the model entirely.
//
// The unit test this file's neighbour mirrors,
// `command_argument_tag_keyword_before_a_colon_still_splits` (in-crate
// `#[cfg(test)]`, `parser.rs`), claims to guard exactly that property and
// passes: its input has no `KEY=` before the colon, which is why. The property
// it names does not hold one level up.
//
// The defect is PRE-EXISTING (not introduced by #538) and was descoped from
// session 9m lane 3 by explicit user ruling, under the standing rule that
// adjacent findings are filed rather than fixed in flight. The deleted test was
// verified satisfiable alongside the four in-crate #416 splitter tests and
// `gap_c_option_does_not_swallow_a_genuine_host_group_separator`, so whoever
// picks up #612 should restore it verbatim from the commit that removed it
// rather than writing a new one.

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

// ---------------------------------------------------------------------------
// Round 3 (#538 lane 3, ATL round 3): quote handling must be TOKEN-SCOPED. A
// `"` only quotes when it ENCLOSES the whole value/token it opens; sudo never
// lets an interior or cross-token quote suppress a real separator.
//
// Two independent root causes, both re-derived on this host 2026-07-31 (sudo
// 1.9.17p2, visudo grammar version 50), each with a negative control:
//
//   * ROOT CAUSE 1 - `option_value_end`'s `in_quotes` toggle is a LIVE ON/OFF
//     switch: an ODD (single) quote in a `CWD=`/`CHROOT=` value toggles it ON
//     and it never toggles back OFF, so the scan reads the rest of the LINE
//     (a following tag, or even the next command) as still inside the value.
//   * ROOT CAUSE 2 - `inside_a_clean_quoted_region` pairs
//     `unescaped_quote_positions` with `chunks_exact(2)` over the WHOLE
//     string, with no notion of which TOKEN each quote belongs to. Two quotes
//     that each close a DIFFERENT token (two different commands, or two
//     different host-groups) still form a "clean pair" by that blind pairing,
//     so a real separator sitting between them is wrongly masked.
//
// Negative control for both: `alice h1 = ` (no command at all) is
// `visudo -c -f -` rc 1, `stdin:1:12: syntax error` - confirming these probes
// are not just "everything is rc 0 no matter what".
// ---------------------------------------------------------------------------

/// ROOT CAUSE 1: a single (non-enclosing) `"` inside a `CWD=` value must not
/// swallow the rest of the line.
///
/// `man 5 sudoers` (rendered page line 619, sudo 1.9.17p2): a value's special
/// characters "may be enclosed in double quotes" - at BOTH ends. A `"` that
/// does not itself CLOSE the value is a literal value byte, not a live
/// on/off toggle that stays flipped for the remainder of the line.
///
/// Host probe, 2026-07-31, `visudo -c -f -` rc 0:
///
/// ```text
/// alice ALL = CWD=/a"b NOPASSWD: /bin/ls
///     cvtsudoers: Options [{"runcwd":"/a\"b"},{"authenticate":false}]
///                 Commands [{"command":"/bin/ls"}]
/// ```
///
/// Mechanism: the lone `"` toggles `option_value_end`'s `in_quotes` ON and
/// nothing later in the line toggles it back OFF, so the scan reads the
/// `NOPASSWD:` tag and the `/bin/ls` command as still inside the `CWD`
/// value. The tag is lost, the command becomes empty, and
/// `split_top_level_segments`'s `:` arm then mis-reads the tag colon as a
/// top-level separator (the clamp in `preceding_token` yields `""` there),
/// producing a bogus second segment `/bin/ls` with no `=` - the whole line is
/// discarded `Malformed("user specification segment is missing its `= command`
/// part")` and `sudo-F01` fires on a line real `visudo` accepts.
#[test]
fn interior_quote_in_an_option_value_does_not_swallow_a_following_tag_and_command() {
    let src = "alice ALL = CWD=/a\"b NOPASSWD: /bin/ls\n";
    assert_eq!(
        f01_count(src),
        0,
        "visudo rc 0: no sudo-F01 may fire for an interior (non-enclosing) quote"
    );
    let s = only_spec(src);
    assert_eq!(s.host_groups.len(), 1, "got {:?}", s.host_groups);
    let specs = &s.host_groups[0].cmnd_specs;
    assert_eq!(specs.len(), 1, "one Cmnd_Spec; got {specs:?}");
    assert_eq!(specs[0].options, opt(CmndOptionKey::Cwd, "/a\"b"));
    assert_eq!(specs[0].tags, vec![Tag::NoPasswd]);
    assert_eq!(specs[0].cmnd, CmndItem::Cmnd("/bin/ls".to_string()));
    assert_eq!(
        w05_count(src),
        1,
        "the NOPASSWD grant on a specific (non-ALL) command must be visible to sudo-W05"
    );
}

/// ROOT CAUSE 1, no tag involved: the same live-toggle defect swallows a
/// following COMMAND directly, with no tag colon in between at all.
///
/// Host probe, 2026-07-31, `visudo -c -f -` rc 0:
///
/// ```text
/// alice ALL = CWD=/tmp/a"b /bin/ls
///     cvtsudoers: Options [{"runcwd":"/tmp/a\"b"}]
///                 Commands [{"command":"/bin/ls"}]
/// ```
///
/// Mechanism: `option_value_end` never finds an unquoted whitespace (the lone
/// `"` stays toggled ON for the rest of the string), so it returns the FULL
/// string length; `split_leading_option` then takes the ENTIRE remainder
/// (including `/bin/ls`) as the `CWD` value, and `parse_cmnd_spec`'s command
/// constructor is left with an empty string. This line is not `Malformed`
/// (`classify_user_spec` only rejects an EMPTY `Cmnd_Spec_List`, not one whose
/// sole spec has an empty command), so `sudo-F01` does not fire here; the harm
/// is silent instead - the grant is present in the AST but unreachable by any
/// lint that inspects the command. This case is also added to
/// `no_cmnd_spec_from_a_valid_line_carries_an_empty_command_token`'s `cases`
/// above for the general guard; this test pins the exact expected values.
#[test]
fn interior_quote_in_an_option_value_does_not_swallow_the_bare_command_that_follows() {
    let src = "alice ALL = CWD=/tmp/a\"b /bin/ls\n";
    let s = only_spec(src);
    let specs = &s.host_groups[0].cmnd_specs;
    assert_eq!(specs.len(), 1, "one Cmnd_Spec; got {specs:?}");
    assert_eq!(specs[0].options, opt(CmndOptionKey::Cwd, "/tmp/a\"b"));
    assert_eq!(
        specs[0].cmnd,
        CmndItem::Cmnd("/bin/ls".to_string()),
        "the command must not be swallowed into the option value past an \
         interior (non-enclosing) quote"
    );
}

/// ROOT CAUSE 1 across a host-group separator: the swallowed command shows up
/// in the FIRST host group while the second host group (and its grant) stays
/// intact - two host groups survive, but the first one's command is gone.
///
/// Host probe, 2026-07-31, `visudo -c -f -` rc 0:
///
/// ```text
/// alice h1 = CWD=/a"b /bin/ls : h2 = ALL
///     cvtsudoers: TWO User_Specs
///       h1 -> Options [{"runcwd":"/a\"b"}]  Commands [{"command":"/bin/ls"}]
///       h2 -> Options [{"setenv":true}]     Commands [{"command":"ALL"}]
/// ```
///
/// (The `setenv` entry on h2 is `cvtsudoers` reporting the semantics it
/// attaches to a bare `ALL` command, matching the documented convention seen
/// on `gap_c_quoted_option_value_with_a_space_before_a_tag_does_not_split_the_user_spec`'s
/// sibling comment; it is not a tag written on the line.)
#[test]
fn interior_quote_in_an_option_value_does_not_swallow_a_bare_command_across_a_host_group_separator()
{
    let src = "alice h1 = CWD=/a\"b /bin/ls : h2 = ALL\n";
    assert_eq!(f01_count(src), 0, "visudo rc 0: no sudo-F01 may fire");
    let s = only_spec(src);
    assert_eq!(
        s.host_groups.len(),
        2,
        "the `:` still separates two host groups; got {:?}",
        s.host_groups
    );
    assert_eq!(s.host_groups[0].hosts, vec!["h1".to_string()]);
    let specs0 = &s.host_groups[0].cmnd_specs;
    assert_eq!(specs0.len(), 1, "one Cmnd_Spec; got {specs0:?}");
    assert_eq!(specs0[0].options, opt(CmndOptionKey::Cwd, "/a\"b"));
    assert_eq!(
        specs0[0].cmnd,
        CmndItem::Cmnd("/bin/ls".to_string()),
        "h1's command must not be swallowed into the option value"
    );
    assert_eq!(s.host_groups[1].hosts, vec!["h2".to_string()]);
    assert_eq!(s.host_groups[1].cmnd_specs[0].cmnd, CmndItem::All);
}

/// ROOT CAUSE 2: two quotes that each CLOSE a DIFFERENT command must not pair
/// up across a comma and mask the `Cmnd_Spec_List` separator between them.
///
/// Host probe, 2026-07-31, `visudo -c -f -` rc 0:
///
/// ```text
/// alice ALL = /bin/echo x", NOPASSWD: /bin/ls "y
///     cvtsudoers: TWO Cmnd_Specs
///       1st -> Commands [{"command":"/bin/echo x\""}]
///       2nd -> Options [{"authenticate":false}]
///              Commands [{"command":"/bin/ls \"y"}]
/// ```
///
/// Mechanism: `inside_a_clean_quoted_region` pairs `unescaped_quote_positions`
/// with `chunks_exact(2)` over the WHOLE `Cmnd_Spec_List` text with no notion
/// of which command each quote belongs to. The first command's trailing `"`
/// and the second command's trailing `"` form a "clean pair" by that blind
/// pairing even though neither quote OPENS the other's token, so the comma
/// between them is wrongly read as sitting inside a quoted region and does
/// not split - merging the hidden `NOPASSWD` grant into the first spec's tags
/// (or losing it, depending on exact mutation), a `sudo-W05` FALSE NEGATIVE.
#[test]
fn two_quotes_each_closing_a_different_command_do_not_mask_the_comma_separator() {
    let src = "alice ALL = /bin/echo x\", NOPASSWD: /bin/ls \"y\n";
    let s = only_spec(src);
    let specs = &s.host_groups[0].cmnd_specs;
    assert_eq!(
        specs.len(),
        2,
        "the comma sits between two quotes that each close a DIFFERENT \
         command - it is not enclosed by either pair and must still split \
         the Cmnd_Spec_List; got {specs:?}"
    );
    assert_eq!(specs[0].cmnd, CmndItem::Cmnd("/bin/echo x\"".to_string()));
    assert!(
        specs[0].tags.is_empty(),
        "the first command carries no tag; got {:?}",
        specs[0].tags
    );
    assert_eq!(specs[1].tags, vec![Tag::NoPasswd]);
    assert_eq!(specs[1].cmnd, CmndItem::Cmnd("/bin/ls \"y".to_string()));
    assert_eq!(
        w05_count(src),
        1,
        "the NOPASSWD grant on the second (non-ALL) command must be visible to sudo-W05"
    );
}

/// The runas-group twin of the above, so the fix cannot be specific to a
/// `NOPASSWD` tag: the hidden grant carries a `(root)` runas group instead.
///
/// Host probe, 2026-07-31, `visudo -c -f -` rc 0:
///
/// ```text
/// alice ALL = /bin/echo x", (root) /bin/su "y
///     cvtsudoers: TWO Cmnd_Specs
///       1st -> Commands [{"command":"/bin/echo x\""}]
///       2nd -> runasusers [{"username":"root"}]
///              Commands [{"command":"/bin/su \"y"}]
/// ```
#[test]
fn two_quotes_each_closing_a_different_command_do_not_mask_the_comma_separator_runas_variant() {
    let src = "alice ALL = /bin/echo x\", (root) /bin/su \"y\n";
    let s = only_spec(src);
    let specs = &s.host_groups[0].cmnd_specs;
    assert_eq!(specs.len(), 2, "got {specs:?}");
    assert_eq!(specs[0].cmnd, CmndItem::Cmnd("/bin/echo x\"".to_string()));
    assert_eq!(
        specs[1].runas.as_ref().map(|r| r.users.clone()),
        Some(vec!["root".to_string()]),
        "the second spec's runas group must survive; got {:?}",
        specs[1].runas
    );
    assert_eq!(specs[1].cmnd, CmndItem::Cmnd("/bin/su \"y".to_string()));
}

/// ROOT CAUSE 2, colon-splitter analog: two quotes that each close a
/// DIFFERENT host-group's command must not pair up across a top-level `:` and
/// mask the host-group separator between them.
///
/// Host probe, 2026-07-31, `visudo -c -f -` rc 0:
///
/// ```text
/// alice h1 = /bin/echo a" : h2 = /bin/echo b"
///     cvtsudoers: TWO User_Specs
///       h1 -> Commands [{"command":"/bin/echo a\""}]
///       h2 -> Commands [{"command":"/bin/echo b\""}]
/// ```
///
/// The existing frozen `#416` regressions
/// (`unterminated_quote_does_not_swallow_the_segment_colon` and its
/// `w05_fires_past_an_unterminated_quote_hiding_a_host_group_grant` sibling)
/// use exactly ONE `"` (an odd, never-closed count) - which is precisely the
/// blind spot this test closes: TWO quotes, one per host-group, form an
/// unintended "clean pair" that a single unterminated quote never could.
#[test]
fn two_quotes_each_closing_a_different_host_groups_command_do_not_mask_the_segment_colon() {
    let src = "alice h1 = /bin/echo a\" : h2 = /bin/echo b\"\n";
    let s = only_spec(src);
    assert_eq!(
        s.host_groups.len(),
        2,
        "the `:` sits between two quotes that each close a DIFFERENT \
         host-group's command - it is not enclosed by either pair and must \
         still split the User_Spec; got {:?}",
        s.host_groups
    );
    assert_eq!(s.host_groups[0].hosts, vec!["h1".to_string()]);
    assert_eq!(
        s.host_groups[0].cmnd_specs[0].cmnd,
        CmndItem::Cmnd("/bin/echo a\"".to_string())
    );
    assert_eq!(s.host_groups[1].hosts, vec!["h2".to_string()]);
    assert_eq!(
        s.host_groups[1].cmnd_specs[0].cmnd,
        CmndItem::Cmnd("/bin/echo b\"".to_string())
    );
}

/// The NOPASSWD companion of the colon-splitter case above, so the
/// operator-visible half (`sudo-W05`) is pinned too, not just the AST shape.
///
/// Host probe, 2026-07-31, `visudo -c -f -` rc 0:
///
/// ```text
/// alice h1 = /bin/echo a" : h2 = NOPASSWD: /bin/echo b"
///     cvtsudoers: TWO User_Specs
///       h1 -> Commands [{"command":"/bin/echo a\""}]
///       h2 -> Options [{"authenticate":false}]
///              Commands [{"command":"/bin/echo b\""}]
/// ```
#[test]
fn two_quotes_each_closing_a_different_host_groups_command_keep_the_second_grant_visible_to_w05() {
    let src = "alice h1 = /bin/echo a\" : h2 = NOPASSWD: /bin/echo b\"\n";
    let s = only_spec(src);
    assert_eq!(s.host_groups.len(), 2, "got {:?}", s.host_groups);
    assert_eq!(s.host_groups[1].hosts, vec!["h2".to_string()]);
    assert_eq!(s.host_groups[1].cmnd_specs[0].tags, vec![Tag::NoPasswd]);
    assert_eq!(
        s.host_groups[1].cmnd_specs[0].cmnd,
        CmndItem::Cmnd("/bin/echo b\"".to_string())
    );
    assert_eq!(
        w05_count(src),
        1,
        "the NOPASSWD grant hidden past two paired (cross-host-group) quotes \
         must be visible to sudo-W05"
    );
}

/// ROOT CAUSE 2, principal axis: a `"` immediately after a BARE word (no
/// intervening whitespace) still starts a fresh token - it does not glue onto
/// the preceding word the way shell quoting does.
///
/// Host probe, 2026-07-31, `visudo -c -f -` rc 0:
///
/// ```text
/// alice" h1" = ALL
///     cvtsudoers: User_List [{"username":"alice"}]
///                 Host_List [{"hostname":" h1"}]
///                 Commands [{"command":"ALL"}]
/// ```
///
/// Negative control: `alice" h1" = ` (no command) is rc 1,
/// `stdin:1:14: syntax error`.
///
/// Mechanism: `split_user_list`'s boundary search
/// (`unquoted_whitespace_runs`) only looks for whitespace OUTSIDE a genuinely
/// CLOSED quote pair. In `alice" h1"`, `unescaped_quote_positions` finds the
/// pair `[5, 9]` (both quotes), and the ONLY whitespace in the string (the
/// space right after `alice"`) sits strictly between them, so it is read as
/// "inside a clean quoted region" and is never offered as the User/Host
/// boundary - `split_user_list` returns an EMPTY host part and
/// `classify_user_spec` discards the whole line as `Malformed`, firing
/// `sudo-F01` on a line real `visudo` accepts. Real sudo's lexer disagrees:
/// a `"` always opens a NEW token, whether or not whitespace precedes it, so
/// `alice` and `" h1"` are two separate principals, not one glued one.
///
/// `RuleSteward` keeps the verbatim source token, quotes retained (matching
/// the established convention in
/// `gap_b_quoted_principal_with_a_space_keeps_the_reserved_all_principal`);
/// `cvtsudoers` dequotes to `" h1"` -> ` h1` for its JSON report, a
/// difference that belongs to the projection, not the AST.
#[test]
fn a_quote_right_after_a_bare_word_starts_a_new_principal_token_with_no_whitespace_needed() {
    let src = "alice\" h1\" = ALL\n";
    assert_eq!(
        f01_count(src),
        0,
        "visudo rc 0: no sudo-F01 may fire for a bare word immediately \
         followed by a quoted principal"
    );
    let s = only_spec(src);
    assert_eq!(
        s.users,
        vec!["alice".to_string()],
        "the bare `alice` ends where the quote opens - a `\"` starts a fresh \
         token even with no preceding whitespace"
    );
    assert_eq!(s.host_groups.len(), 1, "got {:?}", s.host_groups);
    assert_eq!(
        s.host_groups[0].hosts,
        vec!["\" h1\"".to_string()],
        "the quoted principal is the verbatim source token, quotes retained"
    );
    assert_eq!(s.host_groups[0].cmnd_specs[0].cmnd, CmndItem::All);
}

/// Pins that an ESCAPED quote (`\"`) is not counted as a quote position: doing
/// so re-pairs every later quote, and `chunks_exact(2)` then silently drops a
/// leftover odd element, flipping a separator from "inside a clean region" to
/// "outside" it.
///
/// This is the escape HALF of the user's "honor quotes and escapes" ruling
/// for this lane, and until this test it was pinned by no assertion at all -
/// every existing quoted-value test in this file has EITHER zero backslashes
/// inside its quotes, or a backslash that is not itself immediately before an
/// interior quote.
///
/// The mechanism below describes the ORIGINAL implementation, a match arm
/// `'\\' => escaped = true` inside `unescaped_quote_positions`, and the mutant
/// that deleted it. Both are gone: that function is now a three-line iterator
/// chain delegating to `quote_is_escaped` (a `"` is escaped iff a backslash
/// immediately precedes it), so the named mutant can no longer be generated.
/// The POSITIONS are unchanged - `[0, 9]` under either rule for this input - so
/// the assertion still pins what it was written to pin.
///
/// The old text also attributed the masking to `unescaped_quote_positions` +
/// `chunks_exact(2)`. That call path does not exist: `split_cmnd_specs`'s `,`
/// guard reads a registry built by `quoted_value_span` / `find_closing_quote`.
/// The two share the escape RULE, not a call.
///
/// Host probe, 2026-07-31, `visudo -c -f -` rc 0:
///
/// ```text
/// alice ALL = CWD="/a\"b, c" /bin/ls
///     cvtsudoers: Options [{"runcwd":"/a\"b, c"}]
///                 Commands [{"command":"/bin/ls"}]
/// ```
///
/// WITH the escape arm (current, correct code): scanning the value text
/// `"/a\"b, c" ` (quote at 0, backslash at 3, quote at 4, comma at 6, quote at
/// 9), the backslash at index 3 sets `escaped`, so the `"` at index 4 is
/// consumed literally and never pushed. `unescaped_quote_positions` therefore
/// returns `[0, 9]` - ONE clean pair - and the comma at index 6 sits strictly
/// inside it, so it is masked: the whole quoted value (backslash and both
/// enclosing quotes) is kept as ONE option value and the comma does not split
/// anything.
///
/// WITHOUT it (the surviving mutant): the backslash falls through to the
/// catch-all and never sets `escaped`, so the `"` at index 4 IS counted:
/// positions become `[0, 4, 9]`. `chunks_exact(2)` yields only the pair
/// `(0, 4)` and silently drops the trailing `9`. The comma at index 6 is now
/// OUTSIDE every recognized "clean" region, so it would be read as a real
/// separator, corrupting this value into two pieces. This test pins the
/// WITH-arm behavior and therefore reddens when the arm is deleted.
#[test]
fn escaped_quote_inside_an_option_value_does_not_reopen_the_comma_separator() {
    let src = "alice ALL = CWD=\"/a\\\"b, c\" /bin/ls\n";
    let s = only_spec(src);
    let specs = &s.host_groups[0].cmnd_specs;
    assert_eq!(
        specs.len(),
        1,
        "the comma sits inside the value's own clean quote pair - an escaped \
         interior quote must not count as a pairing boundary; got {specs:?}"
    );
    assert_eq!(
        specs[0].options,
        opt(CmndOptionKey::Cwd, "\"/a\\\"b, c\""),
        "the value is kept VERBATIM: backslash and both enclosing quotes included"
    );
    assert_eq!(specs[0].cmnd, CmndItem::Cmnd("/bin/ls".to_string()));
}

// ===========================================================================
// MISS-1 (round 5): an opener is anchored on ANY `=`, not on an OPTION `=`
// ===========================================================================
//
// `enclosing_option_value_quote_spans` originally tested
// `bytes[open - 1] == b'='`, with no check that the `=` was an
// `Option_Spec`'s OWN `=` (that check no longer exists in the shipping
// code - it was replaced by `is_option_value_quote_opener`, which
// additionally requires the word before the `=` to be a real `Option_Spec`
// keyword). A command-argument `=` glued to a `"` (`/bin/echo x="`)
// therefore GOT the same pairing power as a real `CWD="..."` opener under
// the old check, and wrongly paired with an unrelated LATER quote that
// merely closes a different command, masking the real separator between
// them. This was NEW code from round 4 (`enclosing_option_value_quote_spans`
// did not exist before round 3); it is a distinct mechanism from #612
// (`classify_user_spec`'s quote-blind `seg.find('=')`), and distinct from
// the comma face's sibling function `split_cmnd_specs`, which has no `'='`
// arm at all.
//
// The mutation gate could not find this: mutating `bytes[open - 1] == b'='`
// in either direction was killed by EXISTING tests (`true` kills the
// two-quote tests below it in this file; `false` kills the `CWD="/a:b"`
// masking tests), because every existing two-quote test had its quote
// preceded by a bare word (`x"`, `a"`), never by `=`. Only a quote preceded
// by `=` -- and specifically a command-argument `=`, not an option's --
// exercised the missing check.

/// ROOT CAUSE (round 5), comma-splitter face: a command-argument `=` glued to
/// a `"` must not gain the option-value `=`'s pairing power across a comma.
///
/// Host probe, 2026-07-31, `visudo -c -f -` rc 0 for BOTH lines:
///
/// ```text
/// alice ALL = /bin/echo x", NOPASSWD: /bin/ls "y      (no `=` before the quote)
///     cvtsudoers: TWO Cmnd_Specs
///       1st -> Commands [{"command":"/bin/echo x\""}]
///       2nd -> Options [{"authenticate":false}]
///              Commands [{"command":"/bin/ls \"y"}]
///
/// alice ALL = /bin/echo x=", NOPASSWD: /bin/ls "y     (a command-argument `=`)
///     cvtsudoers: IDENTICAL split - TWO Cmnd_Specs, same shape as above
/// ```
///
/// The discriminating pair: the two lines differ ONLY by the `=` glued onto
/// the first command's trailing quote, and real sudo splits them IDENTICALLY.
/// This test asserts the WITHOUT-`=` line first as a positive control (it
/// already passes today - round 3 closed that face), then asserts the SAME
/// shape for the WITH-`=` line, which `enclosing_option_value_quote_spans`
/// wrongly treats as an option-value opener (`bytes[open - 1] == b'='` is
/// true for a command-argument `=` too), pairing it with the second command's
/// trailing `"` and masking the comma between them - hiding a `NOPASSWD`
/// grant from `sudo-W05`.
#[test]
fn command_argument_equals_glued_to_a_quote_does_not_gain_the_option_values_pairing_power() {
    // Positive control: no `=` before the opener. Already correct (round 3).
    let control = "alice ALL = /bin/echo x\", NOPASSWD: /bin/ls \"y\n";
    let control_specs = only_spec(control).host_groups[0].cmnd_specs.len();
    assert_eq!(
        control_specs, 2,
        "positive control must already split in two"
    );
    assert_eq!(
        w05_count(control),
        1,
        "positive control: NOPASSWD must be visible"
    );

    // The discriminator: a command-argument `=` glued to the SAME quote.
    let src = "alice ALL = /bin/echo x=\", NOPASSWD: /bin/ls \"y\n";
    let s = only_spec(src);
    let specs = &s.host_groups[0].cmnd_specs;
    assert_eq!(
        specs.len(),
        2,
        "a command-argument `=` must not grant its following quote the \
         option-value opener's pairing power; got {specs:?}"
    );
    assert_eq!(specs[0].cmnd, CmndItem::Cmnd("/bin/echo x=\"".to_string()));
    assert!(
        specs[0].tags.is_empty(),
        "the first command carries no tag; got {:?}",
        specs[0].tags
    );
    assert_eq!(specs[1].tags, vec![Tag::NoPasswd]);
    assert_eq!(specs[1].cmnd, CmndItem::Cmnd("/bin/ls \"y".to_string()));
    assert_eq!(
        w05_count(src),
        1,
        "the NOPASSWD grant on the second (non-ALL) command must be visible to sudo-W05"
    );
}

/// ROOT CAUSE (round 5), colon-splitter face: the same command-argument-`=`
/// mispairing, but masking a top-level HOST-GROUP `:` instead of a `,`.
///
/// Host probe, 2026-07-31, `visudo -c -f -` rc 0:
///
/// ```text
/// alice h1 = /bin/echo x=" : h2 = NOPASSWD: /bin/su "y
///     cvtsudoers: TWO User_Specs (h1, h2), sharing user "alice"
///       h1 -> Commands [{"command":"/bin/echo x=\""}]
///       h2 -> Options [{"authenticate":false}]
///             Commands [{"command":"/bin/su \"y"}]
/// ```
#[test]
fn command_argument_equals_glued_to_a_quote_does_not_mask_the_segment_colon() {
    let src = "alice h1 = /bin/echo x=\" : h2 = NOPASSWD: /bin/su \"y\n";
    let s = only_spec(src);
    assert_eq!(
        s.host_groups.len(),
        2,
        "the `:` sits between a command-argument-`=`-glued quote and an \
         unrelated LATER quote - it is not enclosed by a real option-value \
         pair and must still split the User_Spec; got {:?}",
        s.host_groups
    );
    assert_eq!(s.host_groups[0].hosts, vec!["h1".to_string()]);
    assert_eq!(
        s.host_groups[0].cmnd_specs[0].cmnd,
        CmndItem::Cmnd("/bin/echo x=\"".to_string())
    );
    assert_eq!(s.host_groups[1].hosts, vec!["h2".to_string()]);
    assert_eq!(s.host_groups[1].cmnd_specs[0].tags, vec![Tag::NoPasswd]);
    assert_eq!(
        s.host_groups[1].cmnd_specs[0].cmnd,
        CmndItem::Cmnd("/bin/su \"y".to_string())
    );
    assert_eq!(
        w05_count(src),
        1,
        "the NOPASSWD grant hidden behind the mispaired quotes must be visible to sudo-W05"
    );
}

/// ROOT CAUSE (round 5), alias-splitter face: `classify_alias` shares
/// `split_top_level_segments` with the user-spec colon splitter (only
/// `skip_tag_colons` differs), so the SAME mispairing swallows an alias-def's
/// `:` separator too - here with NO tag/comma involved at all, just two
/// `Cmnd_Alias` specs.
///
/// Host probe, 2026-07-31, `visudo -c -f -` rc 0 (both `A` and `B` unused,
/// which is expected - this line defines but never references them):
///
/// ```text
/// Cmnd_Alias A = /bin/echo x=" : B = /bin/ls "y
///     Warning: unused Cmnd_Alias "A"
///     Warning: unused Cmnd_Alias "B"
///     cvtsudoers: Command_Aliases {
///         A: [{"command":"/bin/echo x=\""}],
///         B: [{"command":"/bin/ls \"y"}]
///     }
/// ```
///
/// Before this fix, the mispaired quotes swallowed the `:` between `A`'s and
/// `B`'s specs, so `classify_alias` saw only ONE top-level segment: `A =
/// /bin/echo x=" : B = /bin/ls "y`. It split that segment's OWN first `=`
/// (giving name `A`), and since the member list is comma-split with no comma
/// present, the whole remainder - INCLUDING the literal text `: B = /bin/ls
/// "y` - became A's single member. Alias `B` was never defined at all, which
/// fed #331's undefined/dead-alias walk (`sudo-E01`/`W02`/`W03`) a corrupt
/// alias table. Fixed: `is_option_value_quote_opener` now requires the `=`
/// before an opening quote to be an `Option_Spec` keyword's own `=`, not any
/// `=`, so a command-argument `=` glued to a quote (`x="`) no longer gains
/// an option value's pairing power; the assertions below pin the corrected
/// two-spec split, shipped and verified (not reverted by `50594c4`).
#[test]
fn command_argument_equals_glued_to_a_quote_does_not_mask_the_alias_spec_colon() {
    let src = "Cmnd_Alias A = /bin/echo x=\" : B = /bin/ls \"y\n";
    let kind = first_kind(src);
    let LineKind::Alias(a) = kind else {
        panic!("expected an alias definition, got {kind:?}");
    };
    assert_eq!(a.kind, AliasKind::Cmnd);
    assert_eq!(
        a.specs.len(),
        2,
        "the `:` between A's and B's specs must still split them; got {:?}",
        a.specs
    );
    assert_eq!(a.specs[0].name, "A");
    assert_eq!(a.specs[0].members, vec!["/bin/echo x=\"".to_string()]);
    assert_eq!(a.specs[1].name, "B");
    assert_eq!(a.specs[1].members, vec!["/bin/ls \"y".to_string()]);
}

// ===========================================================================
// MISS-2 (round 5): the option value is assumed to start right after `=`
// ===========================================================================
//
// `split_leading_option`, `option_value_end`, and the `'='` arm's
// `tok_start = option_value_end(s, after_eq)` call all ORIGINALLY assumed an
// `Option_Spec` value's first byte sat IMMEDIATELY after the `=`. The code
// has since changed: `split_leading_option` now reads
// `let value_start = skip_value_leading_whitespace(rest, eq + 1);`, and the
// `'='` arm routes through the same helper before calling `option_value_end`
// - see `skip_value_leading_whitespace`'s doc comment. Real sudo accepts
// whitespace on either side of an `Option_Spec`'s `=`, but that tolerance is
// grounded ONLY by live `visudo -c -f -` probes, never by `man 5 sudoers`
// (which documents the glued `KEY=value` spelling only and states no general
// whitespace tolerance around `=` - see `skip_value_leading_whitespace`'s
// doc comment for the full grounding); every FROZEN test written before this
// fix happened to write the value glued (`TIMEOUT=30`, `CWD="/a b"`). This
// was the third `sudo-F01` FATAL false positive of the lane, and unlike
// MISS-1 it needed no quotes at all.

/// The sharpest MISS-2 face: a space AFTER the `=`, before a value that then
/// precedes a TAG COLON, throws the whole line away.
///
/// Host probe, 2026-07-31, `visudo -c -f -` rc 0:
///
/// ```text
/// alice ALL = TIMEOUT= 30 NOEXEC: /bin/ls
///     cvtsudoers: Options [{"command_timeout":30},{"noexec":true}]
///                 Commands [{"command":"/bin/ls"}]
/// ```
///
/// Mechanism: `option_value_end`'s first check is
/// `s.as_bytes().get(start) == Some(&b'"')`, where `start` is the byte
/// IMMEDIATELY after `=`. Here that byte is a space, so the quoted-value
/// branch never triggers and the scan falls to `unquoted_value_end(s,
/// start)`, whose very FIRST character is whitespace - it returns `start`
/// unchanged, an EMPTY value ending BEFORE `30` even begins. Downstream this
/// desyncs BOTH `split_leading_option` (which never advances past the space,
/// so `parse_cmnd_spec`'s option loop re-reads `"30 NOEXEC: ..."` as if it
/// were the tag/command text) and `split_top_level_segments`'s `'='` arm
/// (`tok_start` lands right after the `=`, so the tag-colon's
/// `preceding_token` spans `"30 NOEXEC"`, which is not an exact `Tag_Spec`
/// match, so the colon is misread as a genuine top-level host-group
/// separator and the whole line is discarded `Malformed`).
#[test]
fn option_value_space_after_the_equals_before_a_tag_does_not_throw_away_a_valid_line() {
    let src = "alice ALL = TIMEOUT= 30 NOEXEC: /bin/ls\n";
    assert_eq!(f01_count(src), 0, "visudo rc 0: no sudo-F01 may fire");
    let s = only_spec(src);
    assert_eq!(
        s.host_groups.len(),
        1,
        "the `NOEXEC:` tag colon is not a host-group separator; got {:?}",
        s.host_groups
    );
    let specs = &s.host_groups[0].cmnd_specs;
    assert_eq!(specs.len(), 1, "one Cmnd_Spec; got {specs:?}");
    assert_eq!(
        specs[0].options,
        opt(CmndOptionKey::Timeout, "30"),
        "the value must survive as the raw source token, with the leading \
         space (part of the `= value` separator, not the value) excluded"
    );
    assert_eq!(specs[0].tags, vec![Tag::NoExec]);
    assert_eq!(
        specs[0].cmnd,
        CmndItem::Cmnd("/bin/ls".to_string()),
        "the command must not be swallowed into the option value or lost \
         when the (mis-detected) host-group split discards the line"
    );
}

/// Four more MISS-2 F01 spellings, table-driven: whitespace on both sides of
/// the `=`, and the SAME defect reached through a quoted (rather than bare)
/// value. Each asserts only the operator-visible signal (`sudo-F01` must not
/// fire) - the deep AST pinning above already covers one full spelling; this
/// table's job is breadth across the option keyword / quoting axis.
///
/// All four are `visudo -c -f -` rc 0 on this host, 2026-07-31:
///
/// ```text
/// alice ALL = TIMEOUT = 30 NOEXEC: /bin/ls
///     cvtsudoers: Options [{"command_timeout":30},{"noexec":true}] Commands [{"command":"/bin/ls"}]
/// alice ALL = CWD= "/a:b" NOEXEC: /bin/ls
///     cvtsudoers: Options [{"runcwd":"/a:b"},{"noexec":true}] Commands [{"command":"/bin/ls"}]
/// alice ALL = CHROOT= "/a:b" NOEXEC: /bin/ls   (CHROOT deprecated warning only, still rc 0)
///     cvtsudoers: Options [{"runchroot":"/a:b"},{"noexec":true}] Commands [{"command":"/bin/ls"}]
/// alice ALL = CWD= "/a b" NOEXEC: /bin/ls
///     cvtsudoers: Options [{"runcwd":"/a b"},{"noexec":true}] Commands [{"command":"/bin/ls"}]
/// ```
///
/// The `TIMEOUT = 30 NOEXEC:` spelling (space on BOTH sides) fails via a
/// DIFFERENT sub-path than the single-space case above: at the top-level
/// splitter, `preceding_token` already trims, so `" TIMEOUT "` still matches
/// the `TIMEOUT` keyword and `is_option_eq` is still true - but the value
/// scan still lands on the space right after `=` and returns immediately, so
/// `tok_start` never advances past `30`, and the tag colon's preceding token
/// becomes `"30 NOEXEC"` - not a tag - same Malformed outcome via the same
/// root cause.
#[test]
fn option_value_space_around_the_equals_before_a_tag_fires_no_sudo_f01() {
    let cases = [
        "alice ALL = TIMEOUT = 30 NOEXEC: /bin/ls\n",
        "alice ALL = CWD= \"/a:b\" NOEXEC: /bin/ls\n",
        "alice ALL = CHROOT= \"/a:b\" NOEXEC: /bin/ls\n",
        "alice ALL = CWD= \"/a b\" NOEXEC: /bin/ls\n",
    ];
    for src in cases {
        assert_eq!(
            f01_count(src),
            0,
            "{src:?} is visudo rc 0 and must not be reported as a syntax error"
        );
        assert_eq!(
            only_spec(src).host_groups[0].cmnd_specs.len(),
            1,
            "{src:?}: exactly one Cmnd_Spec must survive"
        );
    }
}

/// The corrupt-AST-only face: a space after `=`, with NO following tag, so no
/// `sudo-F01` fires but the option value and the command are still both
/// wrong.
///
/// Host probe, 2026-07-31, `visudo -c -f -` rc 0:
///
/// ```text
/// alice ALL = TIMEOUT= 30 /bin/ls
///     cvtsudoers: Options [{"command_timeout":30}] Commands [{"command":"/bin/ls"}]
/// ```
///
/// Without a tag colon to mis-locate, `split_top_level_segments` never
/// discards the line - but `option_value_end` still returns an empty value at
/// `parse_cmnd_spec`'s option-loop level, so the loop's SECOND iteration
/// tries `split_leading_option` again on the untouched `" 30 /bin/ls"`, finds
/// no `=` in it, and hands the ENTIRE remainder to the command constructor.
#[test]
fn option_value_space_after_the_equals_with_no_following_tag_still_parses_the_command_clean() {
    let src = "alice ALL = TIMEOUT= 30 /bin/ls\n";
    assert_eq!(f01_count(src), 0, "visudo rc 0: no sudo-F01 may fire");
    let s = only_spec(src);
    let specs = &s.host_groups[0].cmnd_specs;
    assert_eq!(specs.len(), 1, "one Cmnd_Spec; got {specs:?}");
    assert_eq!(
        specs[0].options,
        opt(CmndOptionKey::Timeout, "30"),
        "the numeric value must not be dropped in favor of an empty string"
    );
    assert_eq!(
        specs[0].cmnd,
        CmndItem::Cmnd("/bin/ls".to_string()),
        "the value `30` must not be glued onto the command token"
    );
}

/// The same no-tag corrupt-AST face with a PATH value (`CWD`), so the fix
/// cannot be specific to a numeric `TIMEOUT`.
///
/// Host probe, 2026-07-31, `visudo -c -f -` rc 0:
///
/// ```text
/// alice ALL = CWD= /tmp /bin/ls
///     cvtsudoers: Options [{"runcwd":"/tmp"}] Commands [{"command":"/bin/ls"}]
/// ```
#[test]
fn option_value_space_after_the_equals_leaves_a_bare_unquoted_value_clean() {
    let src = "alice ALL = CWD= /tmp /bin/ls\n";
    assert_eq!(f01_count(src), 0, "visudo rc 0: no sudo-F01 may fire");
    let s = only_spec(src);
    let specs = &s.host_groups[0].cmnd_specs;
    assert_eq!(specs.len(), 1, "one Cmnd_Spec; got {specs:?}");
    assert_eq!(specs[0].options, opt(CmndOptionKey::Cwd, "/tmp"));
    assert_eq!(specs[0].cmnd, CmndItem::Cmnd("/bin/ls".to_string()));
}

/// The interior-comma face: a space after `=` before a QUOTED value whose
/// content contains a comma. Because `option_value_end` never recognizes the
/// value as starting at the (space-preceded) quote, the corresponding
/// `enclosing_option_value_quote_spans` scan (shared by `split_cmnd_specs`)
/// ALSO never anchors an opener here (`bytes[open - 1]` is the space, not
/// `=`), so the comma INSIDE the quoted value is read as a genuine
/// `Cmnd_Spec_List` separator - splitting what real sudo parses as ONE
/// command into two.
///
/// Host probe, 2026-07-31, `visudo -c -f -` rc 0:
///
/// ```text
/// alice ALL = CWD= "/a,b" /bin/ls
///     cvtsudoers: ONE Cmnd_Spec
///                 Options [{"runcwd":"/a,b"}] Commands [{"command":"/bin/ls"}]
/// ```
#[test]
fn option_value_space_after_the_equals_with_an_interior_comma_does_not_split_into_two_specs() {
    let src = "alice ALL = CWD= \"/a,b\" /bin/ls\n";
    assert_eq!(f01_count(src), 0, "visudo rc 0: no sudo-F01 may fire");
    let s = only_spec(src);
    let specs = &s.host_groups[0].cmnd_specs;
    assert_eq!(
        specs.len(),
        1,
        "the comma sits INSIDE the quoted value's own pair and must not \
         split the Cmnd_Spec_List; got {specs:?}"
    );
    assert_eq!(specs[0].options, opt(CmndOptionKey::Cwd, "\"/a,b\""));
    assert_eq!(specs[0].cmnd, CmndItem::Cmnd("/bin/ls".to_string()));
}

/// The mirror-image face: whitespace BEFORE the `=` instead of after. Unlike
/// every case above, this one is not recognized as an `Option_Spec` AT ALL,
/// because `split_leading_option` matches the keyword against `rest[..eq]`
/// WITHOUT trimming it - `"CWD "` (trailing space) fails `parse_option_key`'s
/// exact-match check - so the option loop breaks on its very first iteration
/// and the ENTIRE remainder (including the literal text `CWD = "/a b"`)
/// becomes the command token. (`split_top_level_segments`'s OWN key check
/// uses `preceding_token`, which DOES trim, so this spelling reaches the tag
/// loop with no host-group split at all here - there is no tag colon in this
/// input - and no `sudo-F01` fires; the corruption is confined to the
/// `Cmnd_Spec` this option belongs to.)
///
/// Host probe, 2026-07-31, `visudo -c -f -` rc 0:
///
/// ```text
/// alice ALL = CWD = "/a b" /bin/ls
///     cvtsudoers: Options [{"runcwd":"/a b"}] Commands [{"command":"/bin/ls"}]
/// ```
#[test]
fn option_keyword_with_trailing_space_before_the_equals_is_still_recognized_as_an_option() {
    let src = "alice ALL = CWD = \"/a b\" /bin/ls\n";
    assert_eq!(f01_count(src), 0, "visudo rc 0: no sudo-F01 may fire");
    let s = only_spec(src);
    let specs = &s.host_groups[0].cmnd_specs;
    assert_eq!(specs.len(), 1, "one Cmnd_Spec; got {specs:?}");
    assert_eq!(
        specs[0].options,
        opt(CmndOptionKey::Cwd, "\"/a b\""),
        "a space before the `=` must not hide the option from \
         `split_leading_option`'s (untrimmed) keyword match"
    );
    assert_eq!(
        specs[0].cmnd,
        CmndItem::Cmnd("/bin/ls".to_string()),
        "the option text `CWD = \"/a b\"` must not be glued onto the command"
    );
}

// ===========================================================================
// Mutation survivors (round 4 `cargo mutants`), routed here per the round 5
// brief. Two of the four are closed below; two are EQUIVALENT (verified, not
// assumed - see the reasoning in each doc comment) and get no test, because
// no input can ever distinguish an equivalent mutant's output from the real
// code's.
// ===========================================================================

/// MUTATION SURVIVOR: mutating `option_value_end`'s
/// `unquoted_value_end(s, close + 1)` call to `unquoted_value_end(s, close -
/// 1)` (replace + with -) SURVIVES today.
///
/// Verified NOT equivalent: `close - 1` starts the post-closing-quote scan
/// ONE BYTE EARLY, landing on the byte immediately before the closing quote
/// instead of immediately after it. When that byte is whitespace (a value
/// like `CWD="/a "`, a trailing space INSIDE the quotes), the mutant's scan
/// returns immediately at `close - 1`, truncating the value one byte short
/// and dropping the closing quote entirely - a real, observable corruption.
///
/// Host probe, 2026-07-31, `visudo -c -f -` rc 0:
///
/// ```text
/// alice ALL = CWD="/a " /bin/ls
///     cvtsudoers: Options [{"runcwd":"/a "}] Commands [{"command":"/bin/ls"}]
/// ```
///
/// (The sibling `replace + with *` mutant, `unquoted_value_end(s, close *
/// 1)` i.e. `unquoted_value_end(s, close)`, starts the scan AT the closing
/// quote itself. A `"` is never whitespace and never toggles `escaped`, so
/// `unquoted_value_end` treats it as an ordinary literal byte and continues
/// scanning forward to the exact same first-whitespace boundary the correct
/// `close + 1` would have found. That mutant is therefore EQUIVALENT - this
/// same test cannot kill it, and no other input can either, since the
/// argument holds for ANY value text. Confirmed, not merely assumed: traced
/// both `unquoted_value_end` call sites against this input by hand and the
/// resulting `value_end` is identical either way.)
#[test]
fn trailing_space_before_the_closing_quote_of_an_option_value_is_kept_verbatim() {
    let src = "alice ALL = CWD=\"/a \" /bin/ls\n";
    assert_eq!(f01_count(src), 0, "visudo rc 0: no sudo-F01 may fire");
    let s = only_spec(src);
    let specs = &s.host_groups[0].cmnd_specs;
    assert_eq!(specs.len(), 1, "one Cmnd_Spec; got {specs:?}");
    assert_eq!(
        specs[0].options,
        opt(CmndOptionKey::Cwd, "\"/a \""),
        "the trailing space sits INSIDE the closing quote and is part of the \
         value; the scan for the value's end must resume just AFTER the \
         closing quote (`close + 1`), not one byte before it (`close - 1`, \
         which would read this space as the boundary and truncate the value)"
    );
    assert_eq!(specs[0].cmnd, CmndItem::Cmnd("/bin/ls".to_string()));
}

/// MUTATION SURVIVOR (two, closed by one test): mutating `split_user_list`'s
/// `bytes[open - 1]` to `bytes[open / 1]` (i.e. `bytes[open]`, replace - with
/// /) and mutating its `prev != b',' && !prev.is_ascii_whitespace()` guard to
/// use `||` in place of `&&` both SURVIVE today.
///
/// Verified NOT equivalent, and the SAME input kills both: `bytes[open / 1]`
/// makes `prev` the OPENING QUOTE BYTE ITSELF (`b'"'`) instead of the real
/// preceding byte. `prev != b',' && !prev.is_ascii_whitespace()` is then
/// `true` unconditionally (a `"` is never a comma and never whitespace), so
/// EVERY quote pair is wrongly treated as "glued" and added as a
/// zero-width candidate boundary - even one that is legitimately preceded by
/// whitespace and already reachable through the ordinary whitespace-run
/// candidate list. The `&&` -> `||` mutant reaches the identical wrong
/// outcome a different way: with the real (correct) `prev` byte, `prev !=
/// b','` is `true` for any non-comma preceding byte (in particular an
/// ordinary space), so the `||` makes the whole condition `true` regardless
/// of the `is_ascii_whitespace` check - the intended AND-of-two-conditions
/// collapses to "not a comma", which whitespace always satisfies.
///
/// The existing Gap-B case (`"my user", ALL ALL = ALL`) CANNOT catch either
/// mutant: its quote sits at index 0, so the `if open > 0` guard skips the
/// branch before either buggy expression is ever evaluated. This input uses
/// a quoted principal preceded by a SPACE (after a comma), so `open > 0` and
/// the guard does not shield it.
///
/// Host probe, 2026-07-31, `visudo -c -f -` rc 0:
///
/// ```text
/// alice, "b c" h1 = ALL
///     cvtsudoers: User_List [{"username":"alice"},{"username":"b c"}]
///                 Host_List [{"hostname":"h1"}]
///                 Commands [{"command":"ALL"}]
/// ```
///
/// Under either mutant, the spurious zero-width candidate at the quote's own
/// open position sorts BEFORE the real whitespace-run candidate that spans
/// `"b c"`'s trailing space, and unlike a real glued-quote candidate its
/// `before` half is NOT already comma/whitespace-trimmed (`"alice, "`,
/// trailing space and comma both retained) while `after` becomes `"\"b c\"
/// h1"` (the closing quote through `h1`, un-split) - so `comma_split` yields
/// `users = ["alice"]` (silently DROPPING the second principal `"b c"`) and
/// `hosts = ["\"b c\" h1"]` (one garbage host token instead of `h1`).
#[test]
fn a_quoted_principal_preceded_by_whitespace_after_a_comma_is_a_separate_user_list_member() {
    let src = "alice, \"b c\" h1 = ALL\n";
    let s = only_spec(src);
    assert_eq!(
        s.users,
        vec!["alice".to_string(), "\"b c\"".to_string()],
        "the quoted principal, already reachable via the ordinary \
         whitespace-run boundary, must remain a distinct User_List member - \
         not silently dropped by a spurious glued-quote candidate"
    );
    assert_eq!(s.host_groups.len(), 1, "got {:?}", s.host_groups);
    assert_eq!(
        s.host_groups[0].hosts,
        vec!["h1".to_string()],
        "the host list must be the clean token `h1`, not a garbage \
         concatenation of the quoted principal and `h1`"
    );
    assert_eq!(s.host_groups[0].cmnd_specs[0].cmnd, CmndItem::All);
}

// ===========================================================================
// KNOWN-OPEN #538 defects (round 6 fix reverted) -- PARTIALLY CLOSED.
// ===========================================================================
//
// This section originally held two independent round-6 defect classes, both
// verified against real `visudo` 1.9.17p2 (`visudo -c -f -` and
// `cvtsudoers -f json`, this host, 2026-07-31). They are not stale or
// speculative: each input below IS accepted (rc 0) by real sudo, and the
// AST/diagnostic shape each test asserts IS what real sudo's own tooling
// reports for that input.
//
// Commit ec11a15 ("9m lane 3 round 6: glued option keywords + the ','
// arm's missing guard (#538)") attempted to fix BOTH classes by (1) widening
// `word_immediately_before`'s boundary set from whitespace-only to also
// include `)`, `,`, and `=`, and (2) guarding `split_top_level_segments`'s
// `','` arm with `i >= tok_start`, mirroring its `')'` sibling. Both changes
// were NARROW-REVERTED (commit 50594c4) because they introduced two
// confirmed regressions against the real `visudo` oracle:
//   * a FALSE `sudo-F01` fatal on a valid line with NO comma at all in the
//     option value (`alice ALL = CWD="/a b"/bin/ls, (root:grp) /bin/su`,
//     real visudo rc 0), which disproves the ','-arm guard's stated premise;
//   * SILENTLY SWALLOWED grants/aliases (a second `Cmnd_Alias` or a
//     `NOPASSWD: ALL` grant vanishing with no diagnostic at all) on inputs
//     shaped like `Cmnd_Alias A = /bin/echo X=CWD="/a : B = /bin/su"`.
//
// Two PRE-EXISTING substrate defects underlay the two round-6 symptoms:
//   * `is_option_value_quote_opener` (via `word_immediately_before`) matched
//     the LAST WORD before an `=` and was POSITION-BLIND, while the `'='`
//     arm's own recognizer (`preceding_token`/`tok_start`) does a
//     WHOLE-SPAN, POSITION-ANCHORED match -- the two disagreed about where
//     an `Option_Spec` keyword starts for any glued spelling. CLOSED: commit
//     `2de19ea` ("position-anchor the option-value quote opener") retired
//     `is_option_value_quote_opener`/`word_immediately_before` outright and
//     now records each option value's quote span inline, at the same
//     position-anchored point `is_option_eq` already used, rather than
//     patching the position-blind side with another boundary character (as
//     ec11a15's reverted attempt did). The "Round 6 (ATL round 6)" tests
//     immediately below this section, plus
//     `no_cmnd_spec_from_a_valid_line_carries_an_empty_command_token`'s two
//     round-6 cases earlier in this file, are ordinary passing (no longer
//     `#[ignore]`d) rows since `2de19ea` (measured: FAIL at `93ef75b`, PASS
//     from `2de19ea` onward, re-confirmed at current HEAD 2026-07-31).
//   * `split_top_level_segments`'s `','` arm had no guard against a comma
//     INSIDE a quoted option value re-arming `tok_start` mid-value. CLOSED as
//     #643: the arm now consults the same `quotes` registry the `':'` arm
//     uses, and the "Round 6, second brief" tests below (the
//     `comma_inside_a_quoted_*` trio) are no longer `#[ignore]`d.
//
// That fix addressed the substrate rather than patching around it with another
// positional guard -- and deliberately did NOT mirror the `')'` arm, which
// ec11a15 attempted. The two arms are not symmetric: for a comma, QUOTING is
// the only thing that makes the byte literal (`CWD=/a,b` unquoted is visudo
// rc 1), so a positional guard would mask a comma sudo actually rejects and
// convert a loud fatal into a silent misparse. For a `)`, an unquoted value may
// legitimately contain one (`CWD=/a)b` is rc 0), so that arm needs the
// structural `depth > 0` test instead.
// ===========================================================================

// ===========================================================================
// Round 6 (ATL round 6): a REGRESSION introduced BY round 5 - FIXED by
// commit 2de19ea (9m lane 3, later the same session).
// ===========================================================================
//
// Round 5 narrowed the (since-retired) `is_option_value_quote_opener`'s
// anchor from "any `=` before the quote" to "an `Option_Spec` keyword's own
// `=`" (MISS-1's fix), via a NEW helper, `word_immediately_before`, that
// computed "the word before the `=`". That helper split on WHITESPACE ONLY
// (`rsplit(char::is_whitespace)`, `parser.rs`). But the sibling `'='` arm of
// `split_top_level_segments` computes the SAME concept - the keyword
// preceding an `Option_Spec`'s own `=` - via `preceding_token`, whose
// `tok_start` resets not just on whitespace but on `)`, `,` AND `=` too. The
// two paths disagreed about where a keyword STARTS: `preceding_token` saw
// `CWD` glued to a preceding `)`/`=`/`,`, while `word_immediately_before`
// saw the whole glued run (`)CWD`, `=CWD`, `,CWD`) and `parse_option_key`
// rejected it.
//
// Consequence, through commit 50594c4 (when this section and the five tests
// below were pinned and `#[ignore]`d): an `Option_Spec` keyword GLUED to a
// preceding `)`, `=`, or `,` (no whitespace) did not open its own value's
// quote span, so a colon or comma INSIDE that quoted value was read as a
// genuine separator - `is_option_value_quote_opener` regressed to round 5's
// own MISS-1 failure class for exactly this one spelling. `ALL=(ALL)` (no
// space before the option keyword) is one of the most common real-world
// sudoers idioms, so this was a live `sudo-F01` false positive on operator
// configs.
//
// FIXED by commit `2de19ea` ("position-anchor the option-value quote
// opener"): it retires `is_option_value_quote_opener`/`word_immediately_
// before` entirely and records each option value's quote span inline, at
// the same position-anchored point (`preceding_token`/`tok_start`) the
// `'='` arm's own `is_option_eq` check already used - eliminating the
// two-recognizer disagreement rather than widening one side's boundary set
// (as ec11a15's reverted attempt did). All five tests below are ordinary
// passing rows now (measured: FAIL at `93ef75b`, PASS from `2de19ea`
// onward, re-confirmed at current HEAD 2026-07-31) and are no longer
// `#[ignore]`d.
//
// All five inputs below are `visudo -c -f -` rc 0 on this host (sudo
// 1.9.17p2, `visudo grammar version 50`, re-probed 2026-07-31), with the AST
// taken from `cvtsudoers -f json` on the same host. The control
// `%wheel ALL=(ALL) CWD="/a:b" NOPASSWD: /bin/ls` (ONE space added before
// `CWD`) is already correct today and is NOT re-asserted here - it is
// covered by the existing round-5 `option_value_space_around_the_equals_*`
// tests, which exercise the whitespace-preceded spelling this section
// deliberately does not touch.

/// MISS: an `Option_Spec` keyword glued to a preceding `)` (the single most
/// common real-world spelling, `ALL=(ALL)CWD=...`) must still open its
/// quoted value's span.
///
/// Host probe, 2026-07-31, `visudo -c -f -` rc 0:
///
/// ```text
/// %wheel ALL=(ALL)CWD="/a:b" NOPASSWD: /bin/ls
///     cvtsudoers: runasusers [{"username":"ALL"}]
///                 Options [{"runcwd":"/a:b"},{"authenticate":false}]
///                 Commands [{"command":"/bin/ls"}]
/// ```
///
/// Before commit `2de19ea`: `sudo-F01` fatal (the colon inside `"/a:b"` was
/// misread as a top-level separator once the quote's opener was rejected,
/// exactly MISS-1's mechanism, and the whole line was discarded
/// `Malformed`). Fixed since `2de19ea` (see the section comment above).
#[test]
fn option_keyword_glued_to_a_runas_close_paren_still_opens_its_quoted_value() {
    let src = "%wheel ALL=(ALL)CWD=\"/a:b\" NOPASSWD: /bin/ls\n";
    assert_eq!(f01_count(src), 0, "visudo rc 0: no sudo-F01 may fire");
    let s = only_spec(src);
    assert_eq!(
        s.users,
        vec!["%wheel".to_string()],
        "the `%` group principal must survive intact"
    );
    assert_eq!(s.host_groups.len(), 1);
    assert_eq!(s.host_groups[0].hosts, vec!["ALL".to_string()]);
    let specs = &s.host_groups[0].cmnd_specs;
    assert_eq!(specs.len(), 1, "one Cmnd_Spec; got {specs:?}");
    let runas = specs[0]
        .runas
        .as_ref()
        .expect("the `(ALL)` runas group, glued to the structural `=`, must still parse");
    assert_eq!(runas.users, vec!["ALL".to_string()]);
    assert!(runas.groups.is_empty(), "no `:group` was written");
    assert_eq!(
        specs[0].options,
        opt(CmndOptionKey::Cwd, "\"/a:b\""),
        "the quoted value, glued to the runas close-paren, must survive verbatim"
    );
    assert_eq!(specs[0].tags, vec![Tag::NoPasswd]);
    assert_eq!(specs[0].cmnd, CmndItem::Cmnd("/bin/ls".to_string()));
    assert_eq!(
        w05_count(src),
        1,
        "the NOPASSWD grant on the specific (non-ALL) /bin/ls command must be \
         visible to sudo-W05"
    );
}

/// MISS: the same option keyword glued directly to the STRUCTURAL `=` (no
/// runas group at all), so the fix cannot special-case a preceding `)`.
///
/// Host probe, 2026-07-31, `visudo -c -f -` rc 0:
///
/// ```text
/// %wheel ALL=CWD="/a:b" NOPASSWD: /bin/ls
///     cvtsudoers: Options [{"runcwd":"/a:b"},{"authenticate":false}]
///                 Commands [{"command":"/bin/ls"}]
/// ```
///
/// (No `runasusers` key: with no `(...)` written, `word_immediately_before`'s
/// backward walk from the quote lands on `%wheel ALL=CWD`, whose last
/// whitespace-delimited word is `ALL=CWD` - not `CWD` - so
/// `parse_option_key` rejects it exactly as it does the `)`-glued spelling.)
///
/// Before commit `2de19ea`: `sudo-F01` fatal, same mechanism as the
/// `)`-glued case above. Fixed since `2de19ea`.
#[test]
fn option_keyword_glued_to_the_structural_equals_still_opens_its_quoted_value() {
    let src = "%wheel ALL=CWD=\"/a:b\" NOPASSWD: /bin/ls\n";
    assert_eq!(f01_count(src), 0, "visudo rc 0: no sudo-F01 may fire");
    let s = only_spec(src);
    assert_eq!(s.users, vec!["%wheel".to_string()]);
    assert_eq!(s.host_groups.len(), 1);
    assert_eq!(s.host_groups[0].hosts, vec!["ALL".to_string()]);
    let specs = &s.host_groups[0].cmnd_specs;
    assert_eq!(specs.len(), 1, "one Cmnd_Spec; got {specs:?}");
    assert!(
        specs[0].runas.is_none(),
        "no `(...)` runas group was written on this line; got {:?}",
        specs[0].runas
    );
    assert_eq!(specs[0].options, opt(CmndOptionKey::Cwd, "\"/a:b\""));
    assert_eq!(specs[0].tags, vec![Tag::NoPasswd]);
    assert_eq!(specs[0].cmnd, CmndItem::Cmnd("/bin/ls".to_string()));
    assert_eq!(
        w05_count(src),
        1,
        "the NOPASSWD grant on the specific (non-ALL) /bin/ls command must be \
         visible to sudo-W05"
    );
}

/// MISS: the `)`-glued spelling again, but with spaces AROUND the structural
/// `=` (`ALL = (root)CWD=...`) and NO tag at all, so this test is
/// attributable to the glued-keyword defect alone, independent of both the
/// round-5 MISS-2 whitespace-around-`=` fix and any tag-colon interaction.
///
/// Host probe, 2026-07-31, `visudo -c -f -` rc 0:
///
/// ```text
/// alice ALL = (root)CWD="/a:b" /bin/ls
///     cvtsudoers: runasusers [{"username":"root"}]
///                 Options [{"runcwd":"/a:b"}]
///                 Commands [{"command":"/bin/ls"}]
/// ```
///
/// Before commit `2de19ea`: `sudo-F01` fatal - the colon inside `"/a:b"` was
/// misread as a top-level separator even with no tag keyword anywhere on the
/// line, which is what made this the sharpest of the three F01 rows: the
/// defect fired on the QUOTED VALUE's own interior colon, with no tag
/// involved at all. Fixed since `2de19ea`.
#[test]
fn option_keyword_glued_to_a_runas_close_paren_with_spaces_around_the_structural_equals() {
    let src = "alice ALL = (root)CWD=\"/a:b\" /bin/ls\n";
    assert_eq!(f01_count(src), 0, "visudo rc 0: no sudo-F01 may fire");
    let s = only_spec(src);
    assert_eq!(s.host_groups.len(), 1);
    assert_eq!(s.host_groups[0].hosts, vec!["ALL".to_string()]);
    let specs = &s.host_groups[0].cmnd_specs;
    assert_eq!(specs.len(), 1, "one Cmnd_Spec; got {specs:?}");
    let runas = specs[0]
        .runas
        .as_ref()
        .expect("the `(root)` runas group must still parse");
    assert_eq!(runas.users, vec!["root".to_string()]);
    assert!(runas.groups.is_empty(), "no `:group` was written");
    assert_eq!(specs[0].options, opt(CmndOptionKey::Cwd, "\"/a:b\""));
    assert!(
        specs[0].tags.is_empty(),
        "no tag was written on this line; got {:?}",
        specs[0].tags
    );
    assert_eq!(specs[0].cmnd, CmndItem::Cmnd("/bin/ls".to_string()));
    assert_eq!(
        w05_count(src),
        0,
        "no NOPASSWD tag was written anywhere on this line, so sudo-W05 must not fire"
    );
}

/// MISS: the glued-`)` spelling combined with an option value whose CONTENT
/// is a comma, so a wrongly-unopened span mis-splits the `Cmnd_Spec_List`
/// too (not just the top-level `:`/`,` splitters MISS-1 already covers - this
/// is `split_cmnd_specs`'s own comma guard, sharing the same
/// `enclosing_option_value_quote_spans` producer).
///
/// Host probe, 2026-07-31, `visudo -c -f -` rc 0:
///
/// ```text
/// alice ALL = (root)CWD="/a,b" /bin/ls
///     cvtsudoers: runasusers [{"username":"root"}]
///                 Options [{"runcwd":"/a,b"}]
///                 Commands [{"command":"/bin/ls"}]
/// ```
///
/// Before commit `2de19ea`: TWO `Cmnd_Spec`s (`specs[0]` an empty
/// `Cmnd("")`, `specs[1]` the garbage `Cmnd("b\" /bin/ls")`) and NO
/// diagnostic at all - this was the SILENT face of the regression (also
/// pinned by the general empty-command guard,
/// `no_cmnd_spec_from_a_valid_line_carries_an_empty_command_token`, which
/// this test's input was added to above; this test additionally pins the
/// exact expected values that guard does not check). Fixed since
/// `2de19ea`.
#[test]
fn option_keyword_glued_to_a_runas_close_paren_with_a_comma_in_its_value_does_not_split_the_cmnd_spec_list()
 {
    let src = "alice ALL = (root)CWD=\"/a,b\" /bin/ls\n";
    let s = only_spec(src);
    assert_eq!(s.host_groups.len(), 1);
    let specs = &s.host_groups[0].cmnd_specs;
    assert_eq!(
        specs.len(),
        1,
        "the comma sits INSIDE the quoted option value, glued to the runas \
         close-paren, and must not split the Cmnd_Spec_List; got {specs:?}"
    );
    let runas = specs[0]
        .runas
        .as_ref()
        .expect("the `(root)` runas group must still parse");
    assert_eq!(runas.users, vec!["root".to_string()]);
    assert_eq!(specs[0].options, opt(CmndOptionKey::Cwd, "\"/a,b\""));
    assert_eq!(specs[0].cmnd, CmndItem::Cmnd("/bin/ls".to_string()));
}

/// MISS: the glued-`,` spelling - an `Option_Spec` keyword glued to a
/// PRECEDING command's trailing comma in a `Cmnd_Spec_List`
/// (`/bin/true,CWD=...`), whose option value also contains an interior
/// comma. This is the sharpest of the silent misses: it corrupts not one but
/// TWO command slots, and it is the one glued spelling `split_cmnd_specs`
/// itself (not just `split_top_level_segments`) must get right, since the
/// leading `,` is itself a `Cmnd_Spec_List` separator candidate.
///
/// Host probe, 2026-07-31, `visudo -c -f -` rc 0:
///
/// ```text
/// alice ALL = /bin/true,CWD="/a,b" /bin/ls
///     cvtsudoers: TWO Cmnd_Specs
///       [0] Commands [{"command":"/bin/true"}]
///       [1] Options [{"runcwd":"/a,b"}]  Commands [{"command":"/bin/ls"}]
/// ```
///
/// Before commit `2de19ea`: THREE `Cmnd_Spec`s (`specs[1]` an empty
/// `Cmnd("")`, `specs[2]` the garbage `Cmnd("b\" /bin/ls")`) and NO
/// diagnostic at all - also added to the general empty-command guard above;
/// this test pins the exact expected two-spec shape that guard does not
/// check. Fixed since `2de19ea`.
#[test]
fn option_keyword_glued_to_a_comma_does_not_merge_into_the_preceding_command() {
    let src = "alice ALL = /bin/true,CWD=\"/a,b\" /bin/ls\n";
    let s = only_spec(src);
    assert_eq!(s.host_groups.len(), 1);
    let specs = &s.host_groups[0].cmnd_specs;
    assert_eq!(
        specs.len(),
        2,
        "two Cmnd_Specs: the leading `/bin/true,` comma is a real \
         Cmnd_Spec_List separator, and the trailing quoted comma is not; got \
         {specs:?}"
    );
    assert_eq!(specs[0].cmnd, CmndItem::Cmnd("/bin/true".to_string()));
    assert!(
        specs[0].options.is_empty(),
        "the first spec carries no option; got {:?}",
        specs[0].options
    );
    assert_eq!(
        specs[1].options,
        opt(CmndOptionKey::Cwd, "\"/a,b\""),
        "the second spec's option must survive verbatim, glued to the \
         preceding comma"
    );
    assert_eq!(
        specs[1].cmnd,
        CmndItem::Cmnd("/bin/ls".to_string()),
        "the second command must not carry the tail of the quoted option value"
    );
}

// ===========================================================================
// Round 6, second brief: the `','` arm of `split_top_level_segments` had
// neither guard its siblings have. FIXED as #643; these three tests are the
// regression pins and are no longer `#[ignore]`d.
// ===========================================================================
//
// As written then, `split_top_level_segments`'s `')'` arm was guarded
// `i >= tok_start` (#538 gap C round 2): a `)` byte sitting INSIDE an
// `Option_Spec` value the `'='` arm has already skipped past must not drag
// `tok_start` BACKWARD into the middle of that value. Its `':'` arm was
// additionally guarded `!inside_a_clean_quoted_region(&quotes, i)`. The `','`
// arm had NEITHER, despite identical exposure: a comma inside a
// legitimately-quoted `Option_Spec` value dragged `tok_start` backward into the
// value exactly as an unguarded `)` would, and re-armed `at_spec_start` when
// `in_cmnd_list`, corrupting whatever boundary check came next.
//
// Both arms have since changed and the two guards are NOT the same: the `','`
// arm took the content-based `!inside_a_clean_quoted_region(&quotes, i)`, and
// the `')'` arm moved OFF the positional test to the structural `depth > 0`.
// See this file's earlier "#538 status" block for why symmetry would be wrong.
//
// This is PRE-EXISTING (not a round-5/round-6 regression): the same defect
// sits in the very first published cut of `split_top_level_segments`'s `','`
// arm and was never guarded across any prior round. It ships two distinct
// failure classes:
//
//   * a FALSE FATAL: the comma desyncs `tok_start` so badly that a later tag
//     colon (`NOPASSWD:`) is misread as a genuine top-level separator, and the
//     whole line - which real `visudo` accepts rc 0 - is thrown away
//     `Malformed`, firing `sudo-F01` and losing the grant `sudo-W05` would
//     otherwise see (`sudo-W05` count 0). Two option keywords are pinned so
//     the defect cannot be dismissed as CWD-specific: `CWD` (a corpus-grounded
//     keyword) and `APPARMOR_PROFILE` (a keyword the corpus never exercises).
//     `TIMEOUT="3,0"` was considered as the second keyword and REJECTED: host
//     probe (`visudo -c -f -`, sudo 1.9.17p2, 2026-07-31) gives rc 1
//     `invalid timeout value` - `TIMEOUT`'s value grammar does not accept a
//     comma at all, quoted or not, so that spelling never reaches this
//     defect's mechanism and would not be a RED test. `APPARMOR_PROFILE="a,b"`
//     is rc 0 (`cvtsudoers`: `Options [{"apparmor_profile":"a,b"}]`) and
//     substitutes cleanly.
//   * a SILENT swallow, strictly worse: an in-value comma followed (still
//     inside the same still-open quote) by an in-value `(` reads that `(` as
//     `at_spec_start`'s runas opener and permanently bumps `depth` to 1 - so
//     the real top-level `:` that follows (`depth == 0` gated) is masked
//     entirely, and a WHOLE SECOND HOST GROUP - a whole extra grant - vanishes
//     into the first group's command string with no diagnostic of any kind.
//
// All six inputs below were re-derived on this host (sudo 1.9.17p2, `visudo
// grammar version 50`) via `visudo -c -f -` and `cvtsudoers -f json`,
// 2026-07-31 (same day as the round-6 first-brief probes above).

/// FALSE FATAL, `CWD` spelling (corpus-grounded keyword).
///
/// Host probe, rc 0:
///
/// ```text
/// alice ALL = CWD="/a,b" NOPASSWD: /bin/ls
///     cvtsudoers: Options [{"runcwd":"/a,b"},{"authenticate":false}]
///                 Commands [{"command":"/bin/ls"}]
/// ```
///
/// Before #643: `sudo-F01` fatal, `sudo-W05` count 0 - the comma inside the
/// quoted value dragged `tok_start` back into the value, so the following
/// `NOPASSWD:` tag colon was misread as a genuine top-level separator and the
/// whole line was discarded `Malformed`. Measured on a build of `96038c9`.
#[test]
// Un-ignored: re-pointed from the closed #538 to #643, which tracks this defect.
fn comma_inside_a_quoted_cwd_option_value_does_not_trigger_a_false_fatal() {
    let src = "alice ALL = CWD=\"/a,b\" NOPASSWD: /bin/ls\n";
    assert_eq!(f01_count(src), 0, "visudo rc 0: no sudo-F01 may fire");
    assert_eq!(
        w05_count(src),
        1,
        "the NOPASSWD grant on the specific (non-ALL) /bin/ls command must be \
         visible to sudo-W05"
    );
    let s = only_spec(src);
    assert_eq!(s.host_groups.len(), 1);
    assert_eq!(s.host_groups[0].hosts, vec!["ALL".to_string()]);
    let specs = &s.host_groups[0].cmnd_specs;
    assert_eq!(specs.len(), 1, "one Cmnd_Spec; got {specs:?}");
    assert_eq!(
        specs[0].options,
        opt(CmndOptionKey::Cwd, "\"/a,b\""),
        "the quoted value, comma and all, must survive verbatim"
    );
    assert_eq!(specs[0].tags, vec![Tag::NoPasswd]);
    assert_eq!(specs[0].cmnd, CmndItem::Cmnd("/bin/ls".to_string()));
}

/// FALSE FATAL, `APPARMOR_PROFILE` spelling - a keyword the corpus never
/// exercises, so this cannot pass by special-casing `CWD`.
///
/// `TIMEOUT="3,0"` was the brief's original choice for this "not
/// CWD-specific" control and was REJECTED after a host probe: sudo's
/// `TIMEOUT` value grammar does not accept a comma in any spelling
/// (`visudo -c -f -` on this host, sudo 1.9.17p2, 2026-07-31, gives rc 1
/// `invalid timeout value` on `TIMEOUT="3,0"`), so that input never reaches
/// the `','`-arm defect at all and would not be a RED test.
/// `APPARMOR_PROFILE="a,b"` was substituted after confirming it IS `visudo`
/// rc 0 with a comma-bearing value, which the round-6-first-brief tests above
/// establish is one of the ten accepted keywords and orthogonal to `CWD`.
///
/// Host probe, rc 0:
///
/// ```text
/// alice ALL = APPARMOR_PROFILE="a,b" NOPASSWD: /bin/ls
///     cvtsudoers: Options [{"authenticate":false},{"apparmor_profile":"a,b"}]
///                 Commands [{"command":"/bin/ls"}]
/// ```
///
/// (`cvtsudoers` lists `authenticate` before `apparmor_profile` here - it
/// does not preserve source order; the AST assertion below uses SOURCE
/// order, per `ast::CmndOption`'s documented convention, which is why the
/// option is asserted first here and not against `cvtsudoers`'s own field
/// order.)
#[test]
// Un-ignored: re-pointed from the closed #538 to #643, which tracks this defect.
fn comma_inside_a_quoted_non_cwd_option_value_does_not_trigger_a_false_fatal() {
    let src = "alice ALL = APPARMOR_PROFILE=\"a,b\" NOPASSWD: /bin/ls\n";
    assert_eq!(f01_count(src), 0, "visudo rc 0: no sudo-F01 may fire");
    assert_eq!(
        w05_count(src),
        1,
        "the NOPASSWD grant on the specific (non-ALL) /bin/ls command must be \
         visible to sudo-W05"
    );
    let s = only_spec(src);
    assert_eq!(s.host_groups.len(), 1);
    let specs = &s.host_groups[0].cmnd_specs;
    assert_eq!(specs.len(), 1, "one Cmnd_Spec; got {specs:?}");
    assert_eq!(
        specs[0].options,
        opt(CmndOptionKey::AppArmorProfile, "\"a,b\""),
        "the quoted value, comma and all, must survive verbatim on a keyword \
         other than CWD"
    );
    assert_eq!(specs[0].tags, vec![Tag::NoPasswd]);
    assert_eq!(specs[0].cmnd, CmndItem::Cmnd("/bin/ls".to_string()));
}

/// SILENT SWALLOW - the important one. An in-value comma followed, still
/// inside the same open quote, by an in-value `(` permanently bumps `depth`
/// to 1, so the real top-level `:` that follows is masked and an entire
/// SECOND host group vanishes into the first group's command token with NO
/// diagnostic at all: no `sudo-F01`, no anything.
///
/// Host probe, rc 0:
///
/// ```text
/// alice ALL = CWD="/a,(b" NOEXEC: /bin/ls : h2 = /bin/cat
///     cvtsudoers: TWO User_Specs
///       [0] Host_List [ALL]  Options [{"runcwd":"/a,(b"},{"noexec":true}]
///           Commands [/bin/ls]
///       [1] Host_List [h2]   Commands [/bin/cat]
/// ```
///
/// Before #643: ONE host group, `hosts == ["ALL"]`, one `Cmnd_Spec` whose
/// `cmnd` was the garbage `"/bin/ls : h2 = /bin/cat"` - the ENTIRE second grant
/// swallowed into a command string that matched no `Cmnd_Alias`, no reserved
/// `ALL` check and no path check, with nothing about `h2` reported at all.
/// Measured on a build of `96038c9`.
#[test]
// Un-ignored: re-pointed from the closed #538 to #643, which tracks this defect.
fn comma_inside_a_quoted_option_value_with_an_unbalanced_paren_does_not_swallow_the_next_host_group()
 {
    let src = "alice ALL = CWD=\"/a,(b\" NOEXEC: /bin/ls : h2 = /bin/cat\n";
    let s = only_spec(src);
    assert_eq!(
        s.host_groups.len(),
        2,
        "the top-level `:` after `/bin/ls` still separates two host groups; \
         got {:?}",
        s.host_groups
    );
    assert_eq!(s.host_groups[0].hosts, vec!["ALL".to_string()]);
    let specs0 = &s.host_groups[0].cmnd_specs;
    assert_eq!(
        specs0.len(),
        1,
        "one Cmnd_Spec in the first group; got {specs0:?}"
    );
    assert_eq!(
        specs0[0].options,
        opt(CmndOptionKey::Cwd, "\"/a,(b\""),
        "the quoted value, comma-then-paren and all, must survive verbatim"
    );
    assert_eq!(specs0[0].tags, vec![Tag::NoExec]);
    assert_eq!(
        specs0[0].cmnd,
        CmndItem::Cmnd("/bin/ls".to_string()),
        "the first command must not carry the second host group's text"
    );
    assert_eq!(
        s.host_groups[1].hosts,
        vec!["h2".to_string()],
        "the second host group must survive as its own group, not vanish \
         into the first command"
    );
    assert_eq!(
        s.host_groups[1].cmnd_specs[0].cmnd,
        CmndItem::Cmnd("/bin/cat".to_string())
    );
}

/// Control - always been correct, must STAY green: a HYPHEN in the quoted
/// value, not a comma, so the `','` arm never sees it at all. Only the
/// punctuation byte differs from the `CWD` false-fatal input pinned by
/// `comma_inside_a_quoted_cwd_option_value_does_not_trigger_a_false_fatal`
/// above. This control exists so a fix at that arm cannot pass by being
/// over-broad (e.g. rejecting every byte inside a quoted value at this
/// position) and breaking this clean line. That fix has since shipped as #643
/// and this control held.
///
/// Host probe, rc 0:
///
/// ```text
/// alice ALL = CWD="/a-b" NOPASSWD: /bin/ls
///     cvtsudoers: Options [{"runcwd":"/a-b"},{"authenticate":false}]
///                 Commands [{"command":"/bin/ls"}]
/// ```
#[test]
fn hyphen_inside_a_quoted_cwd_option_value_is_unaffected_by_the_comma_guard() {
    let src = "alice ALL = CWD=\"/a-b\" NOPASSWD: /bin/ls\n";
    assert_eq!(f01_count(src), 0, "visudo rc 0: no sudo-F01 may fire");
    let s = only_spec(src);
    let specs = &s.host_groups[0].cmnd_specs;
    assert_eq!(specs.len(), 1);
    assert_eq!(specs[0].options, opt(CmndOptionKey::Cwd, "\"/a-b\""));
    assert_eq!(specs[0].tags, vec![Tag::NoPasswd]);
    assert_eq!(specs[0].cmnd, CmndItem::Cmnd("/bin/ls".to_string()));
}

/// Control - already correct today, must STAY green: an ESCAPED comma in an
/// UNQUOTED value (`CWD=/a\,b`, no double quotes at all). This is the
/// spelling that stops a fix anchored only on `enclosing_option_value_quote_spans`
/// (the quoted-value case) from being assumed to cover the unquoted-escape
/// case too - the two are handled by different code paths
/// (`option_value_end`'s quote branch vs its `unquoted_value_end` fallback).
///
/// Host probe, rc 0:
///
/// ```text
/// alice ALL = CWD=/a\,b NOPASSWD: /bin/ls
///     cvtsudoers: Options [{"runcwd":"/a,b"},{"authenticate":false}]
///                 Commands [{"command":"/bin/ls"}]
/// ```
///
/// (`cvtsudoers` unescapes the backslash in its own report; the AST keeps the
/// source bytes verbatim, backslash retained, per `ast::CmndOption`'s
/// documented convention.)
#[test]
fn escaped_comma_in_an_unquoted_cwd_option_value_stays_clean() {
    let src = "alice ALL = CWD=/a\\,b NOPASSWD: /bin/ls\n";
    assert_eq!(f01_count(src), 0, "visudo rc 0: no sudo-F01 may fire");
    let s = only_spec(src);
    let specs = &s.host_groups[0].cmnd_specs;
    assert_eq!(specs.len(), 1);
    assert_eq!(
        specs[0].options,
        opt(CmndOptionKey::Cwd, "/a\\,b"),
        "the backslash-escaped comma must survive verbatim, unquoted"
    );
    assert_eq!(specs[0].tags, vec![Tag::NoPasswd]);
    assert_eq!(specs[0].cmnd, CmndItem::Cmnd("/bin/ls".to_string()));
}

/// Control - already correct today, must STAY green: a quoted COLON rather
/// than a quoted comma. This is the sibling of the `':'` arm's own guard
/// (`!inside_a_clean_quoted_region`), already correct, and pins that fixing
/// the `','` arm's missing guard must not somehow break the `':'` arm's
/// existing one.
///
/// Host probe, rc 0:
///
/// ```text
/// alice ALL = CWD="/a:b" NOPASSWD: /bin/ls
///     cvtsudoers: Options [{"runcwd":"/a:b"},{"authenticate":false}]
///                 Commands [{"command":"/bin/ls"}]
/// ```
#[test]
fn colon_inside_a_quoted_cwd_option_value_stays_clean() {
    let src = "alice ALL = CWD=\"/a:b\" NOPASSWD: /bin/ls\n";
    assert_eq!(f01_count(src), 0, "visudo rc 0: no sudo-F01 may fire");
    let s = only_spec(src);
    let specs = &s.host_groups[0].cmnd_specs;
    assert_eq!(specs.len(), 1);
    assert_eq!(specs[0].options, opt(CmndOptionKey::Cwd, "\"/a:b\""));
    assert_eq!(specs[0].tags, vec![Tag::NoPasswd]);
    assert_eq!(specs[0].cmnd, CmndItem::Cmnd("/bin/ls".to_string()));
}

// ===========================================================================
// 9m senior-review regression: a command ARGUMENT merely SPELLED like an
// `Option_Spec` keyword wrongly gains the option-value quote's pairing power
// ===========================================================================
//
// `is_option_value_quote_opener` decides whether a `"` opens an
// `Option_Spec`'s own VALUE by taking the WHOLE prefix `s[..open]`, trimming
// trailing whitespace, stripping one `=`, and testing only whether the LAST
// whitespace-delimited word (`word_immediately_before`) is one of the ten
// `parse_option_key` keywords. It never asks whether that `=` sits at the
// `Option_Spec` POSITION - i.e. in the run of options at the START of a
// `Cmnd_Spec`, before the command word begins (`Runas_Spec? Option_Spec*
// (Tag_Spec ':')* Cmnd`). So a command ARGUMENT that happens to be spelled
// `CWD=` (or any of the other nine keywords) gains the same quote-pairing
// power as a genuine leading `Option_Spec`, purely because
// `word_immediately_before` looks at only the LAST word before the `=` and
// discards everything earlier in the string.
//
// The sibling `'='` arm in `split_top_level_segments` answers the identical
// question CORRECTLY: its candidate is `preceding_token(s, tok_start, i)`,
// the text since the LAST token boundary (a `,` / structural `=` / `)` /
// consumed `:`) - which, once a command word has begun, is a MULTI-WORD span
// (`"/bin/echo CWD"`) that can never exact-match a bare keyword. That
// position check is exactly what `is_option_value_quote_opener` is missing.
//
// Consequence: the bogus span feeds `enclosing_option_value_quote_spans` ->
// `inside_a_clean_quoted_region`, which gates BOTH `split_top_level_segments`'s
// `:` arm and `split_cmnd_specs`'s `,` arm - so a `,` or `:` sitting inside a
// command argument's own quotes is wrongly masked whenever that argument
// happens to spell an `Option_Spec` keyword, silently hiding a `NOPASSWD`
// grant or a `Cmnd_Alias` definition. This is a REGRESSION, not a
// pre-existing gap: at the pre-9m commit these four helpers did not exist at
// all, so quotes had zero masking power and these lines split correctly; the
// fail-open was introduced by giving quotes masking power without also
// checking the `=`'s POSITION.
//
// # Grounding (visudo 1.9.17p2, `visudo grammar version 50`; live host probe
// 2026-07-31 - `printf '%s\n' "<line>" | visudo -c -f -` (all rc 0) and the
// same line through `cvtsudoers -f json`)
//
// Real sudo's command lexer does not care whether a quoted command-argument
// token happens to spell an `Option_Spec` keyword - it splits identically
// whether the argument is `CWD="..."` or a non-keyword control `XWD="..."`:
//
// ```text
// alice ALL = /bin/echo CWD="/a, NOPASSWD: /bin/su"
//     cvtsudoers: TWO Cmnd_Specs
//       1st -> Commands [{"command":"/bin/echo CWD=\"/a"}]
//       2nd -> Options [{"authenticate":false}]
//              Commands [{"command":"/bin/su\""}]
// alice ALL = /bin/echo XWD="/a, NOPASSWD: /bin/su"
//     cvtsudoers: IDENTICAL split, same shape
//
// alice h1 = /bin/echo CWD=" : h2 = /bin/su "y
//     cvtsudoers: TWO User_Specs (h1, h2)
//       h1 -> Commands [{"command":"/bin/echo CWD=\""}]
//       h2 -> Commands [{"command":"/bin/su \"y"}]
// alice h1 = /bin/echo XWD=" : h2 = /bin/su "y
//     cvtsudoers: IDENTICAL split, same shape
//
// Cmnd_Alias A = /bin/echo CWD="/a : B = /bin/su"
//     cvtsudoers: TWO Command_Aliases (both "unused" warnings only)
//       A: [{"command":"/bin/echo CWD=\"/a"}]
//       B: [{"command":"/bin/su\""}]
// Cmnd_Alias A = /bin/echo XWD="/a : B = /bin/su"
//     cvtsudoers: IDENTICAL split, same shape
// ```
//
// # Positive direction (already covered above, not duplicated here)
//
// A GENUINE leading `Option_Spec` value must still mask a `,` and a `:` -
// already pinned by
// `gap_a_comma_inside_a_quoted_option_value_does_not_split_the_cmnd_spec_list`
// (comma) and `gap_c_quoted_colon_in_an_option_value_is_not_a_separator` /
// `colon_inside_a_quoted_cwd_option_value_stays_clean` (colon), plus the
// escape (`escaped_quote_inside_an_option_value_does_not_reopen_the_comma_separator`)
// and space-around-`=`
// (`option_value_space_around_the_equals_before_a_tag_fires_no_sudo_f01`,
// `option_value_space_after_the_equals_with_an_interior_comma_does_not_split_into_two_specs`)
// variants earlier in this file. Checked, not assumed: all four already
// anchor their opening quote on a genuine leading `CWD=`/`TIMEOUT=` in
// `Option_Spec` position, so a positional fix cannot regress any of them.
// None is touched or duplicated here.

/// The comma face: a command argument spelled `CWD=` must not mask a `,`
/// inside its own quotes, and the hidden `NOPASSWD` grant must be visible to
/// `sudo-W05`. A non-keyword control (`XWD=`) proves the keyword spelling -
/// not something incidental about the fixture - is what flips the behavior:
/// both lines are `visudo -c -f -` rc 0 and `cvtsudoers -f json` splits them
/// IDENTICALLY (see the section grounding above).
#[test]
fn keyword_spelled_command_argument_does_not_gain_the_option_values_pairing_power_across_a_comma() {
    // Positive control: a non-keyword word before the `=` already splits
    // correctly today.
    let control = "alice ALL = /bin/echo XWD=\"/a, NOPASSWD: /bin/su\"\n";
    let control_specs = only_spec(control).host_groups[0].cmnd_specs.len();
    assert_eq!(
        control_specs, 2,
        "positive control: a non-keyword `XWD=` must already split on the comma"
    );
    assert_eq!(
        w05_count(control),
        1,
        "positive control: the NOPASSWD grant must already be visible"
    );

    // The regression: `CWD=` is a command ARGUMENT here (it comes AFTER
    // `/bin/echo`, not at the Cmnd_Spec's leading Option_Spec position), so
    // it must behave identically to the XWD control.
    let src = "alice ALL = /bin/echo CWD=\"/a, NOPASSWD: /bin/su\"\n";
    let s = only_spec(src);
    let specs = &s.host_groups[0].cmnd_specs;
    assert_eq!(
        specs.len(),
        2,
        "a command argument merely SPELLED `CWD=` must not gain an option \
         value's quote-pairing power across the comma; got {specs:?}"
    );
    assert_eq!(
        specs[0].cmnd,
        CmndItem::Cmnd("/bin/echo CWD=\"/a".to_string())
    );
    assert!(
        specs[0].tags.is_empty(),
        "the first command carries no tag; got {:?}",
        specs[0].tags
    );
    assert_eq!(specs[1].tags, vec![Tag::NoPasswd]);
    assert_eq!(specs[1].cmnd, CmndItem::Cmnd("/bin/su\"".to_string()));
    assert_eq!(
        w05_count(src),
        1,
        "the NOPASSWD grant hidden behind the bogus quote-pairing must be \
         visible to sudo-W05"
    );
}

/// The colon face, host-group axis: the same `CWD=` command argument must not
/// mask a top-level `:` and merge two host groups into one.
#[test]
fn keyword_spelled_command_argument_does_not_mask_the_segment_colon_across_a_host_group() {
    let control = "alice h1 = /bin/echo XWD=\" : h2 = /bin/su \"y\n";
    let control_groups = only_spec(control).host_groups.len();
    assert_eq!(
        control_groups, 2,
        "positive control: a non-keyword `XWD=` must already split the host groups"
    );

    let src = "alice h1 = /bin/echo CWD=\" : h2 = /bin/su \"y\n";
    let s = only_spec(src);
    assert_eq!(
        s.host_groups.len(),
        2,
        "a command argument merely SPELLED `CWD=` must not mask the segment \
         colon between two host groups; got {:?}",
        s.host_groups
    );
    assert_eq!(s.host_groups[0].hosts, vec!["h1".to_string()]);
    assert_eq!(
        s.host_groups[0].cmnd_specs[0].cmnd,
        CmndItem::Cmnd("/bin/echo CWD=\"".to_string())
    );
    assert_eq!(s.host_groups[1].hosts, vec!["h2".to_string()]);
    assert_eq!(
        s.host_groups[1].cmnd_specs[0].cmnd,
        CmndItem::Cmnd("/bin/su \"y".to_string())
    );
}

/// The colon face, alias-table axis: `classify_alias` shares
/// `split_top_level_segments` with the user-spec colon splitter, so the same
/// mispairing swallows a `Cmnd_Alias` definition's `:` separator - the hidden
/// alias `B` is never defined at all, corrupting whatever consumes the alias
/// table (`sudo-E01`/`W02`/`W03`).
#[test]
fn keyword_spelled_command_argument_does_not_mask_the_alias_spec_colon() {
    let control = "Cmnd_Alias A = /bin/echo XWD=\"/a : B = /bin/su\"\n";
    let LineKind::Alias(control_alias) = first_kind(control) else {
        panic!("expected an alias definition");
    };
    assert_eq!(
        control_alias.specs.len(),
        2,
        "positive control: a non-keyword `XWD=` must already split A and B"
    );

    let src = "Cmnd_Alias A = /bin/echo CWD=\"/a : B = /bin/su\"\n";
    let kind = first_kind(src);
    let LineKind::Alias(a) = kind else {
        panic!("expected an alias definition, got {kind:?}");
    };
    assert_eq!(a.kind, AliasKind::Cmnd);
    assert_eq!(
        a.specs.len(),
        2,
        "a command argument merely SPELLED `CWD=` must not mask the `:` \
         separating A's and B's specs, hiding B's definition entirely; got {:?}",
        a.specs
    );
    assert_eq!(a.specs[0].name, "A");
    assert_eq!(a.specs[0].members, vec!["/bin/echo CWD=\"/a".to_string()]);
    assert_eq!(a.specs[1].name, "B");
    assert_eq!(a.specs[1].members, vec!["/bin/su\"".to_string()]);
}

/// Table-driven over the REAL keyword set (enumerated from `parse_option_key`
/// itself, not assumed): all TEN keywords must behave identically when
/// spelled as a command argument rather than a genuine leading `Option_Spec`.
///
/// `parse_option_key` recognizes `ROLE`, `TYPE`, `NOTBEFORE`, `NOTAFTER`,
/// `TIMEOUT`, `CWD`, `CHROOT`, `PRIVS`, `LIMITPRIVS`, `APPARMOR_PROFILE` - a
/// hand-picked subset (e.g. testing only the seven `man 5 sudoers`
/// `Option_Spec` keywords) would miss `NOTAFTER` / `PRIVS` / `LIMITPRIVS`,
/// none of which is documented in that man page block either (see
/// `gap_a_all_ten_accepted_option_keywords_are_recognized`'s doc comment for
/// the closed-ten grounding). Live host probe (2026-07-31) confirms
/// `cvtsudoers -f json` splits every one of the ten identically to the `CWD`
/// / `XWD` case documented in the section grounding above; only `CWD` was
/// individually re-probed against `visudo`/`cvtsudoers` given how mechanical
/// (spelling-only) the defect is, but the shipping parser's own behavior
/// for the other nine was verified directly (not assumed) before this test
/// was written.
#[test]
fn all_ten_option_keywords_spelled_as_a_command_argument_do_not_mask_the_comma_separator() {
    let keywords = [
        "ROLE",
        "TYPE",
        "NOTBEFORE",
        "NOTAFTER",
        "TIMEOUT",
        "CWD",
        "CHROOT",
        "PRIVS",
        "LIMITPRIVS",
        "APPARMOR_PROFILE",
    ];
    for kw in keywords {
        let src = format!("alice ALL = /bin/echo {kw}=\"/a, NOPASSWD: /bin/su\"\n");
        let specs = only_spec(&src).host_groups[0].cmnd_specs.len();
        assert_eq!(
            specs, 2,
            "{kw}= as a command argument must not mask the comma; got {specs} Cmnd_Specs"
        );
        assert_eq!(
            w05_count(&src),
            1,
            "{kw}=: the NOPASSWD grant hidden behind the bogus quote-pairing \
             must be visible to sudo-W05"
        );
    }
}

// ===========================================================================
// 9m round 2: the SAME regression, reached by a CHAINED `=`
// ===========================================================================
//
// Round 1 (this file's section above) fixed the case where a command argument
// merely SPELLED like an `Option_Spec` keyword sat directly after the command
// word (`/bin/echo CWD="..."`): `preceding_token(s, tok_start, i)` since the
// last boundary is the multi-word `"/bin/echo CWD"`, which can never
// exact-match a bare keyword, so `is_option_eq` correctly comes back `false`.
//
// What round 1 left open: the `'='` arm's `false` branch
// (`split_top_level_segments` and `split_cmnd_specs` both have one) resets
// `tok_start` to `after_eq` - the byte right after THAT `=` - rather than
// leaving it at the `Cmnd_Spec`'s own last real boundary. A command argument
// containing a SECOND `=` therefore gets its anchor RE-ARMED mid-word: for
// `/bin/echo X=CWD="..."`, the first `=` (after `X`) is correctly rejected
// (`"/bin/echo X"` is multi-word), but `tok_start` then lands right after
// that `=`, so the SECOND `=` (after `CWD`) measures its own preceding token
// from THERE - `"CWD"`, a single word - and is wrongly recognized as a
// genuine leading `Option_Spec`, exactly reproducing round 1's fail-open one
// `=` later. This is not a hypothetical: round 1's own implementer flagged
// the case as a theoretical edge with no test coverage; it reproduces
// (`visudo -c -f -` rc 0 throughout) and is the same severity - a `NOPASSWD`
// grant or a `Cmnd_Alias` definition silently disappears.
//
// # Grounding (visudo 1.9.17p2, `visudo grammar version 50`; live host probe
// 2026-07-31 - `printf '%s\n' "<line>" | visudo -c -f -` (all rc 0) and the
// same line through `cvtsudoers -f json`)
//
// Real sudo's command lexer does not care how many `=` a command argument
// contains before the one spelled like a keyword - it splits the chained form
// IDENTICALLY to round 1's directly-glued form, and identically whether the
// keyword-spelled segment is `CWD=` or a non-keyword control `XWD=`:
//
// ```text
// alice ALL = /bin/echo X=CWD="/a, NOPASSWD: /bin/su"
//     cvtsudoers: TWO Cmnd_Specs
//       1st -> Commands [{"command":"/bin/echo X=CWD=\"/a"}]
//       2nd -> Options [{"authenticate":false}]
//              Commands [{"command":"/bin/su\""}]
// alice ALL = /bin/echo X=XWD="/a, NOPASSWD: /bin/su"
//     cvtsudoers: IDENTICAL split, same shape
//
// alice h1 = /bin/echo X=CWD=" : h2 = /bin/su "y
//     cvtsudoers: TWO User_Specs (h1, h2)
//       h1 -> Commands [{"command":"/bin/echo X=CWD=\""}]
//       h2 -> Commands [{"command":"/bin/su \"y"}]
// alice h1 = /bin/echo X=XWD=" : h2 = /bin/su "y
//     cvtsudoers: IDENTICAL split, same shape
//
// Cmnd_Alias A = /bin/echo X=CWD="/a : B = /bin/su"
//     cvtsudoers: TWO Command_Aliases (both "unused" warnings only)
//       A: [{"command":"/bin/echo X=CWD=\"/a"}]
//       B: [{"command":"/bin/su\""}]
// Cmnd_Alias A = /bin/echo X=XWD="/a : B = /bin/su"
//     cvtsudoers: IDENTICAL split, same shape
// ```
//
// All ten `parse_option_key` keywords were re-probed in the chained form
// (`alice ALL = /bin/echo X=<KW>="/a, NOPASSWD: /bin/su"`, host probe
// 2026-07-31): every one produces the same two-`Commands`-entry split as
// `CWD` above via `cvtsudoers -f json`.
//
// # Over-correction fences
//
// A naive "only the very first token in the whole Cmnd_Spec can ever be an
// option" fix would break legitimate configurations that chain MULTIPLE
// genuine leading options, or that put a genuine leading option at the start
// of a LATER Cmnd_Spec in a comma-separated list. Both are pinned below as
// GREEN fences - they already pass today (the round 2 defect is specifically
// the mis-anchor on a REJECTED `=`'s `false` branch, not on a correctly
// accepted one) and must keep passing after the fix.
//
// A third candidate fence - a leading option written directly after a TAG
// (`NOPASSWD: CWD="/a,b" /bin/su`) - was probed and is NOT a legitimate sudo
// construct at all: `visudo -c -f -` (host probe 2026-07-31) rejects it
// outright, `stdin:1:23: syntax error` pointing directly at `CWD` (and the
// colon-face analog `alice h1 = NOPASSWD: CWD="/a : h2 = /bin/su "y` is
// rejected the same way, `stdin:1:22: syntax error`). This matches the
// grammar-order evidence already on `parse_cmnd_spec`'s own doc comment
// (`Option_Spec*` precedes `(Tag_Spec ':')*`, never follows it - the reversed
// `NOEXEC: TIMEOUT=30 /bin/ls` is also rc 1). There is therefore no
// valid-sudo interpretation of "option after a tag" and so no masking
// behavior to require here; asserting one would invent an answer with no
// oracle behind it, which this brief explicitly rules out. What IS grounded
// and worth pinning is that our own lenient splitter does not accidentally
// grant this REJECTED position masking power either - see
// `option_after_a_tag_is_not_valid_sudo_so_the_comma_splitter_still_does_not_mask_it`
// below, which is a documentation-and-stability test, not a fence against the
// round 2 defect specifically (no chained `=` is even involved: `CWD` here
// sees only ONE `=`, its own).

/// The comma face: a command argument spelled `CWD=`, reached through a
/// CHAINED `=` (`X=CWD=...`), must not mask a `,` inside its own quotes, and
/// the hidden `NOPASSWD` grant must be visible to `sudo-W05`. A non-keyword
/// control (`X=XWD=...`) proves the keyword spelling - not the chaining
/// itself - is what flips the behavior: both lines are `visudo -c -f -` rc 0
/// and `cvtsudoers -f json` splits them IDENTICALLY (see the section
/// grounding above).
#[test]
fn chained_equals_command_argument_does_not_gain_the_option_values_pairing_power_across_a_comma() {
    // Positive control: chaining through a non-keyword word already splits
    // correctly today.
    let control = "alice ALL = /bin/echo X=XWD=\"/a, NOPASSWD: /bin/su\"\n";
    let control_specs = only_spec(control).host_groups[0].cmnd_specs.len();
    assert_eq!(
        control_specs, 2,
        "positive control: a non-keyword `XWD=` chained after `X=` must \
         already split on the comma"
    );
    assert_eq!(
        w05_count(control),
        1,
        "positive control: the NOPASSWD grant must already be visible"
    );

    // The regression: the first `=` (after `X`) is correctly rejected as an
    // option anchor - `"/bin/echo X"` is multi-word - but that rejection's
    // `tok_start` reset re-arms the anchor right after it, so the SECOND `=`
    // (after `CWD`) measures its own preceding token as just `"CWD"` and is
    // wrongly recognized as a genuine leading option.
    let src = "alice ALL = /bin/echo X=CWD=\"/a, NOPASSWD: /bin/su\"\n";
    let s = only_spec(src);
    let specs = &s.host_groups[0].cmnd_specs;
    assert_eq!(
        specs.len(),
        2,
        "a command argument merely SPELLED `CWD=`, reached through a chained \
         `=`, must not gain an option value's quote-pairing power across the \
         comma; got {specs:?}"
    );
    assert_eq!(
        specs[0].cmnd,
        CmndItem::Cmnd("/bin/echo X=CWD=\"/a".to_string())
    );
    assert!(
        specs[0].tags.is_empty(),
        "the first command carries no tag; got {:?}",
        specs[0].tags
    );
    assert_eq!(specs[1].tags, vec![Tag::NoPasswd]);
    assert_eq!(specs[1].cmnd, CmndItem::Cmnd("/bin/su\"".to_string()));
    assert_eq!(
        w05_count(src),
        1,
        "the NOPASSWD grant hidden behind the chained-equals quote-pairing \
         bug must be visible to sudo-W05"
    );
}

/// The colon face, host-group axis: the same chained `X=CWD=` command
/// argument must not mask a top-level `:` and merge two host groups into
/// one.
#[test]
fn chained_equals_command_argument_does_not_mask_the_segment_colon_across_a_host_group() {
    let control = "alice h1 = /bin/echo X=XWD=\" : h2 = /bin/su \"y\n";
    let control_groups = only_spec(control).host_groups.len();
    assert_eq!(
        control_groups, 2,
        "positive control: a non-keyword `XWD=` chained after `X=` must \
         already split the host groups"
    );

    let src = "alice h1 = /bin/echo X=CWD=\" : h2 = /bin/su \"y\n";
    let s = only_spec(src);
    assert_eq!(
        s.host_groups.len(),
        2,
        "a command argument merely SPELLED `CWD=`, reached through a chained \
         `=`, must not mask the segment colon between two host groups; got \
         {:?}",
        s.host_groups
    );
    assert_eq!(s.host_groups[0].hosts, vec!["h1".to_string()]);
    assert_eq!(
        s.host_groups[0].cmnd_specs[0].cmnd,
        CmndItem::Cmnd("/bin/echo X=CWD=\"".to_string())
    );
    assert_eq!(s.host_groups[1].hosts, vec!["h2".to_string()]);
    assert_eq!(
        s.host_groups[1].cmnd_specs[0].cmnd,
        CmndItem::Cmnd("/bin/su \"y".to_string())
    );
}

/// The colon face, alias-table axis: the chained `X=CWD=` command argument
/// must not mask a `Cmnd_Alias` definition's `:` separator either - the
/// hidden alias `B` would otherwise never be defined at all.
#[test]
fn chained_equals_command_argument_does_not_mask_the_alias_spec_colon() {
    let control = "Cmnd_Alias A = /bin/echo X=XWD=\"/a : B = /bin/su\"\n";
    let LineKind::Alias(control_alias) = first_kind(control) else {
        panic!("expected an alias definition");
    };
    assert_eq!(
        control_alias.specs.len(),
        2,
        "positive control: a non-keyword `XWD=` chained after `X=` must \
         already split A and B"
    );

    let src = "Cmnd_Alias A = /bin/echo X=CWD=\"/a : B = /bin/su\"\n";
    let kind = first_kind(src);
    let LineKind::Alias(a) = kind else {
        panic!("expected an alias definition, got {kind:?}");
    };
    assert_eq!(a.kind, AliasKind::Cmnd);
    assert_eq!(
        a.specs.len(),
        2,
        "a command argument merely SPELLED `CWD=`, reached through a chained \
         `=`, must not mask the `:` separating A's and B's specs, hiding B's \
         definition entirely; got {:?}",
        a.specs
    );
    assert_eq!(a.specs[0].name, "A");
    assert_eq!(a.specs[0].members, vec!["/bin/echo X=CWD=\"/a".to_string()]);
    assert_eq!(a.specs[1].name, "B");
    assert_eq!(a.specs[1].members, vec!["/bin/su\"".to_string()]);
}

/// Table-driven over the REAL keyword set (the same closed ten
/// `parse_option_key` recognizes; re-enumerated here rather than trusting the
/// sibling table above, per the brief - `ROLE`, `TYPE`, `NOTBEFORE`,
/// `NOTAFTER`, `TIMEOUT`, `CWD`, `CHROOT`, `PRIVS`, `LIMITPRIVS`,
/// `APPARMOR_PROFILE`): all ten must behave identically when reached through
/// a chained `=` rather than a directly-glued one. Live host probe
/// (2026-07-31) confirms `cvtsudoers -f json` splits every one of the ten
/// identically to the `CWD` / `XWD` case documented in the section grounding
/// above.
#[test]
fn all_ten_option_keywords_spelled_as_a_chained_equals_command_argument_do_not_mask_the_comma_separator()
 {
    let keywords = [
        "ROLE",
        "TYPE",
        "NOTBEFORE",
        "NOTAFTER",
        "TIMEOUT",
        "CWD",
        "CHROOT",
        "PRIVS",
        "LIMITPRIVS",
        "APPARMOR_PROFILE",
    ];
    for kw in keywords {
        let src = format!("alice ALL = /bin/echo X={kw}=\"/a, NOPASSWD: /bin/su\"\n");
        let specs = only_spec(&src).host_groups[0].cmnd_specs.len();
        assert_eq!(
            specs, 2,
            "X={kw}= as a chained command argument must not mask the comma; \
             got {specs} Cmnd_Specs"
        );
        assert_eq!(
            w05_count(&src),
            1,
            "X={kw}=: the NOPASSWD grant hidden behind the chained-equals \
             quote-pairing bug must be visible to sudo-W05"
        );
    }
}

/// Fence 1: multiple CHAINED leading options must still work. `TIMEOUT=30`
/// is a genuine leading option (its `=` is correctly recognized, so
/// `tok_start` advances past its whole value rather than through the `false`
/// branch); `CWD="..."` immediately after it is the SECOND genuine leading
/// option, and its quoted value must still mask the interior comma. Host
/// probe (2026-07-31, `visudo -c -f -` rc 0): `cvtsudoers -f json` reports
/// ONE `Cmnd_Spec` with `Options [{"runcwd":"/a,b"},{"command_timeout":30}]`
/// (`cvtsudoers` pre-resolves and reorders; the AST keeps SOURCE order - see
/// `ast::CmndOption` and `gap_a_selinux_role_and_type_options_leave_the_command_clean`).
#[test]
fn fence_multiple_chained_leading_options_still_mask_a_comma_in_the_second_values_quotes() {
    let src = "alice ALL = TIMEOUT=30 CWD=\"/a,b\" /bin/ls\n";
    let s = only_spec(src);
    let specs = &s.host_groups[0].cmnd_specs;
    assert_eq!(
        specs.len(),
        1,
        "a genuine second leading option must not split on its own quoted \
         comma; got {specs:?}"
    );
    assert_eq!(
        specs[0].options,
        vec![
            CmndOption {
                key: CmndOptionKey::Timeout,
                value: "30".to_string(),
            },
            CmndOption {
                key: CmndOptionKey::Cwd,
                value: "\"/a,b\"".to_string(),
            },
        ],
        "both options must survive, in source order, with CWD's quoted value \
         kept whole; got {:?}",
        specs[0].options
    );
    assert_eq!(specs[0].cmnd, CmndItem::Cmnd("/bin/ls".to_string()));
}

/// Fence 2: a leading option at the START of the SECOND `Cmnd_Spec` in a
/// comma-separated list is genuine (the comma splitter resets `at_spec_start`
/// / `tok_start` at the top-level `,`) and must still mask its own quoted
/// comma. Host probe (2026-07-31, `visudo -c -f -` rc 0): `cvtsudoers -f
/// json` reports TWO `Cmnd_Specs`, the second carrying
/// `Options [{"runcwd":"/a,b"}]` and `Commands [{"command":"/bin/su"}]`.
#[test]
fn fence_leading_option_in_the_second_cmnd_spec_of_a_comma_list_still_masks_its_own_comma() {
    let src = "alice ALL = /bin/ls, CWD=\"/a,b\" /bin/su\n";
    let s = only_spec(src);
    let specs = &s.host_groups[0].cmnd_specs;
    assert_eq!(
        specs.len(),
        2,
        "the comma after /bin/ls is a genuine Cmnd_Spec separator; got \
         {specs:?}"
    );
    assert!(
        specs[0].options.is_empty(),
        "the first spec has no leading option; got {:?}",
        specs[0].options
    );
    assert_eq!(specs[0].cmnd, CmndItem::Cmnd("/bin/ls".to_string()));
    assert_eq!(
        specs[1].options,
        opt(CmndOptionKey::Cwd, "\"/a,b\""),
        "a leading option at the START of the SECOND Cmnd_Spec is genuine \
         and must mask its own comma; got {:?}",
        specs[1].options
    );
    assert_eq!(specs[1].cmnd, CmndItem::Cmnd("/bin/su".to_string()));
}

/// Not a round-2 chained-`=` fence (only ONE `=` appears, `CWD`'s own) - a
/// documentation-and-stability check for the third candidate fence the brief
/// raised ("leading option after a tag"), which turned out not to be valid
/// sudo at all. `alice ALL = NOPASSWD: CWD="/a,b" /bin/su` is REJECTED by
/// real sudo (host probe 2026-07-31: `visudo -c -f -` rc 1,
/// `stdin:1:23: syntax error` pointing at `CWD`), matching the grammar-order
/// evidence already on `parse_cmnd_spec`'s doc comment - an `Option_Spec` can
/// never legitimately follow a `Tag_Spec`. So there is no masking behavior to
/// require; what's pinned instead is that our own lenient comma splitter
/// does not accidentally grant this invalid position masking power either -
/// `parse_option_key(preceding_token(..))` sees the multi-word
/// `"NOPASSWD: CWD"` (the splitter has no tag-colon awareness of its own, so
/// the token run since the `Cmnd_Spec` start still includes the tag text) and
/// correctly fails the exact-match, so the interior comma still splits and
/// the `NOPASSWD` tag - recognized by `parse_cmnd_spec`'s own tag loop on the
/// first resulting fragment - stays visible to `sudo-W05`.
#[test]
fn option_after_a_tag_is_not_valid_sudo_so_the_comma_splitter_still_does_not_mask_it() {
    let src = "alice ALL = NOPASSWD: CWD=\"/a,b\" /bin/su\n";
    let s = only_spec(src);
    let specs = &s.host_groups[0].cmnd_specs;
    assert_eq!(
        specs.len(),
        2,
        "the splitter has no tag-colon awareness, so `CWD=` right after a \
         tag colon must not be mistaken for a genuine leading option; got \
         {specs:?}"
    );
    assert_eq!(specs[0].tags, vec![Tag::NoPasswd]);
    assert_eq!(specs[0].cmnd, CmndItem::Cmnd("CWD=\"/a".to_string()));
    assert_eq!(specs[1].cmnd, CmndItem::Cmnd("b\" /bin/su".to_string()));
    // TWO, not one: `for_each_nopasswd_command` (`lints/tags.rs`) folds NOPASSWD
    // forward across a Cmnd_Spec_List in source order until an explicit PASSWD
    // resets it (real sudoers tag-inheritance), and BOTH resulting fragments are
    // non-ALL commands - spec[0]'s own explicit NOPASSWD fires it there, and
    // spec[1] inherits that same running state and fires it again.
    assert_eq!(
        w05_count(src),
        2,
        "the NOPASSWD tag recognized ahead of the mis-split must still be \
         visible to sudo-W05, and it inherits forward onto the second \
         (mis-split) fragment too"
    );
}

// ===========================================================================
// 9m round 3: `split_cmnd_specs`'s `')'` arm reset `tok_start` on a `)` that
// closes nothing, unlike its `split_top_level_segments` sibling at the time.
// ===========================================================================
//
// HISTORICAL. Both arms are now guarded `depth > 0` (#629) and neither uses
// the positional test this section was written about; the header once claimed
// the sibling arm still had `i >= tok_start` while `split_cmnd_specs` had no
// guard at all, which stopped being true before this section was last touched.
// The scenario below still reproduces the defect it was written for, so the
// test stays; only the mechanism description is dated.
//
// As written then: `split_top_level_segments`'s `')'` arm was guarded
// `i >= tok_start` (9m round 2, #538 gap C round 2): a `)` byte sitting INSIDE
// an `Option_Spec` value the `'='` arm has already skipped past (`tok_start`
// now points AHEAD of the `)`) is a literal value byte, not a runas
// close-paren, and must not drag `tok_start` BACKWARD into the middle of that
// value. `split_cmnd_specs`'s own `')'` arm, new in commit `2de19ea`
// ("position-anchor the option-value quote opener"), never got that guard: it
// reset `tok_start = i + 1` UNCONDITIONALLY on every `)`, including one
// sitting inside an option value already skipped past.
//
// Consequence, on `alice ALL = CHROOT="/a)CWD=" /bin/ls, NOPASSWD: /bin/su
// "x`: `CHROOT`'s own `=` is correctly recognized (`is_option_eq`), so
// `tok_start` advances past the whole quoted value `"/a)CWD="`. The `)`
// INSIDE that value then drags `tok_start` backward to just after itself --
// short of the value's own closing quote. The `=` that ends `CWD=` (also
// inside the value) now measures its preceding token, from that dragged-back
// `tok_start`, as the single word `CWD`, is wrongly accepted as a SECOND
// option anchor, and a bogus quote span opens on what is really CHROOT's own
// closing `"`. That bogus span pairs with the stray `"` later in the line
// (`/bin/su "x`) and masks the genuine top-level comma, so the whole line
// becomes ONE `Cmnd_Spec` and the `NOPASSWD` grant on `/bin/su "x` vanishes
// (MISS-B below).
//
// On `alice ALL = CHROOT="/a)b" CWD="/x, NOPASSWD: /bin/su" /bin/ls` the
// same backward drag instead makes the GENUINE `CWD`'s own `=` (the one
// right after `"/a)b"`) get REJECTED: with `tok_start` dragged back into
// CHROOT's value, `CWD`'s preceding token no longer measures as the single
// word `"CWD"`, so the line is wrongly torn into two `Cmnd_Spec`s and a
// `sudo-W05` finding is INVENTED on a line that grants no NOPASSWD at all
// (MISS-C below).
//
// # Grounding (visudo 1.9.17p2, `visudo grammar version 50`; live host probe
// 2026-07-31 -- `printf '%s\n' "<line>" | visudo -c -f -` (all rc 0) and the
// same line through `cvtsudoers -f json`)
//
// ```text
// alice ALL = CHROOT="/a)CWD=" /bin/ls, NOPASSWD: /bin/su "x
//     cvtsudoers: TWO Cmnd_Specs
//       1st -> Options [{"runchroot":"/a)CWD="}]
//              Commands [{"command":"/bin/ls"}]
//       2nd -> Options [{"runchroot":"/a)CWD="},{"authenticate":false}]
//              Commands [{"command":"/bin/su \"x"}]
// alice ALL = CHROOT="/a)XWD=" /bin/ls, NOPASSWD: /bin/su "x
//     cvtsudoers: IDENTICAL split, same shape (positive control: the only
//     difference is one letter INSIDE the value, `C` vs `X`)
//
// alice ALL = CHROOT="/a)b" CWD="/x, NOPASSWD: /bin/su" /bin/ls
//     cvtsudoers: ONE Cmnd_Spec
//       Options [{"runchroot":"/a)b"},{"runcwd":"/x, NOPASSWD: /bin/su"}]
//       Commands [{"command":"/bin/ls"}]
// alice ALL = CHROOT="/ab" CWD="/x, NOPASSWD: /bin/su" /bin/ls
//     cvtsudoers: IDENTICAL shape (positive control: CHROOT's value has no
//     `)` at all)
// ```
//
// Note: `cvtsudoers -f json`'s resolved view additionally shows
// `runchroot` STICKING to the second `Cmnd_Spec` in the MISS-B family (real
// sudo's own tag/option forward-inheritance across a comma-separated
// `Cmnd_Spec_List`). The AST does not model that inheritance at parse time
// -- see `ast::CmndOption`'s doc comment and every neighbouring two-spec
// test in this file that asserts a non-option-bearing spec's `options` as
// empty (e.g. `option_keyword_glued_to_a_comma_does_not_merge_into_the_preceding_command`)
// -- so each spec below is asserted with only its OWN written options,
// matching that established convention.
//
// # Over-correction fence
//
// The single most common real-world sudoers idiom is a runas group glued
// directly to a leading option with no space, `ALL=(ALL)CWD=...` -- and
// THAT is exactly the shape the `')'` arm's reset exists to handle: without
// resetting `tok_start` at a genuine runas close-paren, `CWD` glued to the
// `)` would measure its preceding token as the whole `")CWD"` and be
// wrongly rejected. A naive fix that simply DELETES the reset would repair
// MISS-B/C but break this idiom; the reset must instead be GUARDED, not
// removed outright. The guard that shipped is `depth > 0` on both arms
// (#629) -- a `)` that actually closes a runas group this scan opened. The
// `i >= tok_start` spelling this paragraph used to prescribe was retired:
// it cannot see a `)` in plain COMMAND text, where `tok_start` is
// legitimately behind the cursor, so it left the #629 fail-open open.
// Six tests un-ignored in commit `b2fafd9` already pin
// this idiom and its siblings and must stay green throughout:
// `option_keyword_glued_to_a_runas_close_paren_still_opens_its_quoted_value`,
// `option_keyword_glued_to_a_runas_close_paren_with_spaces_around_the_structural_equals`,
// `option_keyword_glued_to_a_runas_close_paren_with_a_comma_in_its_value_does_not_split_the_cmnd_spec_list`,
// `option_keyword_glued_to_the_structural_equals_still_opens_its_quoted_value`,
// `option_keyword_glued_to_a_comma_does_not_merge_into_the_preceding_command`,
// and `no_cmnd_spec_from_a_valid_line_carries_an_empty_command_token`. None
// are duplicated here.
//
// # A direct unit-level assertion was considered and skipped
//
// Several tests elsewhere in the crate assert on `split_cmnd_specs`'s
// output directly (e.g. `parser.rs`'s own tests around
// `split_cmnd_specs("(ALL) /bin/echo a(b, NOPASSWD: /bin/su")`), but those
// live in the PRIVATE `#[cfg(test)] mod tests` embedded inside
// `src/parser.rs` itself -- the function is not `pub`, so an integration
// test under `tests/` cannot reach it without a visibility change. This
// test-author brief forbids touching anything under `src/`, including that
// inline module, so no direct byte-index-vs-`tok_start` assertion is added
// here; both regressions below are pinned at the public `parse`/`lint`
// surface instead, the same evidence level every other test in this file
// already uses (see the module doc comment's "Evidence level" section).

/// MISS-B (9m round 3): `CHROOT`'s own value contains a `)` immediately
/// followed by `CWD=` (`"/a)CWD="`). `split_cmnd_specs`'s unconditional
/// `')'` reset drags `tok_start` backward into the middle of that
/// already-skipped value, so the trailing `=` inside it is wrongly accepted
/// as a SECOND option anchor and a bogus quote span opens on CHROOT's own
/// closing `"`. That bogus span pairs with the stray `"` in `/bin/su "x`
/// and masks the genuine top-level comma, so the `NOPASSWD` grant on
/// `/bin/su "x` disappears entirely. Positive control: `XWD=` in place of
/// `CWD=` (a non-keyword control one letter away) already splits correctly
/// today, proving the keyword spelling -- not the `)` itself -- is what
/// flips the behavior. Both lines are `visudo -c -f -` rc 0 (host probe
/// 2026-07-31, sudo 1.9.17p2); see the section grounding above for the full
/// `cvtsudoers -f json` output.
#[test]
fn close_paren_inside_a_chroot_value_must_not_mask_the_nopasswd_comma_separator() {
    // Positive control: a non-keyword `XWD=` inside the CHROOT value already
    // splits on the comma correctly today.
    let control = "alice ALL = CHROOT=\"/a)XWD=\" /bin/ls, NOPASSWD: /bin/su \"x\n";
    let control_s = only_spec(control);
    let control_specs = &control_s.host_groups[0].cmnd_specs;
    assert_eq!(
        control_specs.len(),
        2,
        "positive control: a non-keyword `XWD=` inside the value must not \
         mask the comma; got {control_specs:?}"
    );
    assert_eq!(
        control_specs[0].options,
        opt(CmndOptionKey::Chroot, "\"/a)XWD=\""),
        "positive control: CHROOT's value must survive verbatim; got {:?}",
        control_specs[0].options
    );
    assert!(control_specs[0].tags.is_empty());
    assert_eq!(control_specs[0].cmnd, CmndItem::Cmnd("/bin/ls".to_string()));
    assert!(control_specs[1].options.is_empty());
    assert_eq!(control_specs[1].tags, vec![Tag::NoPasswd]);
    assert_eq!(
        control_specs[1].cmnd,
        CmndItem::Cmnd("/bin/su \"x".to_string())
    );
    assert_eq!(
        w05_count(control),
        1,
        "positive control: the NOPASSWD grant must already be visible"
    );

    // The regression: `CWD=` (a real Option_Spec keyword) glued right after
    // the `)` inside CHROOT's own value drags `tok_start` backward via the
    // unguarded `')'` reset, and the resulting bogus quote span masks the
    // real top-level comma.
    let src = "alice ALL = CHROOT=\"/a)CWD=\" /bin/ls, NOPASSWD: /bin/su \"x\n";
    let s = only_spec(src);
    let specs = &s.host_groups[0].cmnd_specs;
    assert_eq!(
        specs.len(),
        2,
        "a `)` inside CHROOT's own value must not gain a later option \
         value's quote-pairing power across the comma; got {specs:?}"
    );
    assert_eq!(
        specs[0].options,
        opt(CmndOptionKey::Chroot, "\"/a)CWD=\""),
        "CHROOT's own value must survive verbatim, `)` and all; got {:?}",
        specs[0].options
    );
    assert!(
        specs[0].tags.is_empty(),
        "the first command carries no tag; got {:?}",
        specs[0].tags
    );
    assert_eq!(specs[0].cmnd, CmndItem::Cmnd("/bin/ls".to_string()));
    assert!(
        specs[1].options.is_empty(),
        "the second spec has no leading option of its own; got {:?}",
        specs[1].options
    );
    assert_eq!(specs[1].tags, vec![Tag::NoPasswd]);
    assert_eq!(
        specs[1].cmnd,
        CmndItem::Cmnd("/bin/su \"x".to_string()),
        "the second command must not be swallowed into the first"
    );
    assert_eq!(
        w05_count(src),
        1,
        "the NOPASSWD grant hidden behind the close-paren-inside-a-value bug \
         must be visible to sudo-W05"
    );
}

/// MISS-C (9m round 3): the SAME unguarded `')'` reset, this time dragging
/// `tok_start` backward from inside CHROOT's own value (`"/a)b"`) far enough
/// that the GENUINE `CWD=` right after it is wrongly REJECTED as an option
/// anchor instead of wrongly accepted. `CWD`'s value (`"/x, NOPASSWD:
/// /bin/su"`) is then read as ordinary command text: its own `,` splits the
/// `Cmnd_Spec_List` in two, and its own `NOPASSWD:` is picked up by the tag
/// loop on the second fragment, INVENTING a `sudo-W05` finding on a line
/// that grants no NOPASSWD at all. Positive control: dropping the `)` from
/// CHROOT's value (`"/ab"`) already parses as ONE `Cmnd_Spec` with no
/// `sudo-W05` finding today. Both lines are `visudo -c -f -` rc 0 (host
/// probe 2026-07-31, sudo 1.9.17p2); see the section grounding above for
/// the full `cvtsudoers -f json` output.
#[test]
fn close_paren_inside_a_chroot_value_must_not_invent_a_false_nopasswd_split() {
    // Positive control: no `)` in CHROOT's value, so CWD's own `=` is
    // recognized correctly and the whole line stays one Cmnd_Spec today.
    let control = "alice ALL = CHROOT=\"/ab\" CWD=\"/x, NOPASSWD: /bin/su\" /bin/ls\n";
    let control_s = only_spec(control);
    let control_specs = &control_s.host_groups[0].cmnd_specs;
    assert_eq!(
        control_specs.len(),
        1,
        "positive control: with no `)` in CHROOT's value, CWD's own `=` \
         must be recognized and the line stays one Cmnd_Spec; got \
         {control_specs:?}"
    );
    assert_eq!(
        control_specs[0].options,
        vec![
            CmndOption {
                key: CmndOptionKey::Chroot,
                value: "\"/ab\"".to_string(),
            },
            CmndOption {
                key: CmndOptionKey::Cwd,
                value: "\"/x, NOPASSWD: /bin/su\"".to_string(),
            },
        ],
        "positive control: both options must survive verbatim, in source \
         order; got {:?}",
        control_specs[0].options
    );
    assert!(control_specs[0].tags.is_empty());
    assert_eq!(control_specs[0].cmnd, CmndItem::Cmnd("/bin/ls".to_string()));
    assert_eq!(
        w05_count(control),
        0,
        "positive control: no NOPASSWD is granted anywhere on this line"
    );

    // The regression: the `)` inside CHROOT's own value drags `tok_start`
    // backward, so CWD's genuine `=` is wrongly rejected, its value is read
    // as command text, and its interior `,` and `NOPASSWD:` are wrongly
    // treated as a real separator and a real tag.
    let src = "alice ALL = CHROOT=\"/a)b\" CWD=\"/x, NOPASSWD: /bin/su\" /bin/ls\n";
    let s = only_spec(src);
    let specs = &s.host_groups[0].cmnd_specs;
    assert_eq!(
        specs.len(),
        1,
        "a `)` inside CHROOT's own value must not eject a genuine LATER \
         option's `=` from being recognized; got {specs:?}"
    );
    assert_eq!(
        specs[0].options,
        vec![
            CmndOption {
                key: CmndOptionKey::Chroot,
                value: "\"/a)b\"".to_string(),
            },
            CmndOption {
                key: CmndOptionKey::Cwd,
                value: "\"/x, NOPASSWD: /bin/su\"".to_string(),
            },
        ],
        "both options must survive verbatim, in source order, with CWD's \
         quoted comma and colon kept whole; got {:?}",
        specs[0].options
    );
    assert!(
        specs[0].tags.is_empty(),
        "no tag is genuinely written on this line; got {:?}",
        specs[0].tags
    );
    assert_eq!(specs[0].cmnd, CmndItem::Cmnd("/bin/ls".to_string()));
    assert_eq!(
        w05_count(src),
        0,
        "no NOPASSWD is granted anywhere on this line; sudo-W05 must not \
         fire on text trapped inside CWD's own quoted value"
    );
}
