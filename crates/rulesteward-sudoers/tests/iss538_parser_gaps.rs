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
