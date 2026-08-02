//! Boundary-location fidelity: the structural `=`, the `Option_Spec` value's end,
//! and the four boundary arms of the top-level splitters.
//!
//! ONE root cause, six faces, filed as #612, #622, #629, #630, #631 and #643.
//! `parser.rs` decides where a structural boundary is in two under-contextualized
//! ways:
//!
//!   1. A QUOTE-BLIND byte search for the structural `=` (`seg.find('=')` in
//!      `classify_user_spec` and `classify_alias`), which lands inside a quoted
//!      principal that contains one.
//!   2. A POSITION ANCHOR (`tok_start`) in `split_top_level_segments` and
//!      `split_cmnd_specs`, whose four boundary arms (`)`, `,`, `:`, `=`) each
//!      carry a hand-written guard. Only the `':'` arm consults the `quotes`
//!      registry the `'='` arm builds; the `','` arm has no guard at all and the
//!      `')'` arm's is positional and fires on a `)` in plain command text.
//!
//! Four of the six faces are FAIL-OPEN: a `NOPASSWD` grant disappears from the
//! parsed model with no diagnostic, so a compliance run reports clean on a file
//! that grants passwordless sudo. That is the worst outcome this tool has.
//!
//! GROUNDING. Every expectation below was re-derived on THIS host on 2026-08-02,
//! not copied from the issues: `visudo -c -f -` for the rc and `cvtsudoers -f json`
//! for the AST, both on sudo 1.9.17p2 (`visudo grammar version 50`), both reading
//! stdin only. The oracle's discrimination was positive-controlled in the same run:
//! `alice h1 = ` returns rc 1, so the rc 0 behind every case here is meaningful
//! rather than an oracle that accepts anything.

use std::path::Path;

use rulesteward_sudoers::ast::{CmndItem, LineKind, UserSpec};
use rulesteward_sudoers::{SudoersLintContext, lint, parse};

/// The single user-spec of `src`, or a panic naming what was found instead.
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

fn count_code(src: &str, code: &str) -> usize {
    let files = vec![parse(src, Path::new("/etc/sudoers"))];
    lint(&files, &SudoersLintContext {})
        .iter()
        .filter(|d| d.code == code)
        .count()
}

/// `sudo-F01`: the file does not parse. On every input in this file real
/// `visudo` returns rc 0, so any F01 here is a false FATAL on a valid file.
fn f01_count(src: &str) -> usize {
    count_code(src, "sudo-F01")
}

/// `sudo-W01`: NOPASSWD applies to an ALL command (passwordless run-anything).
fn w01_count(src: &str) -> usize {
    count_code(src, "sudo-W01")
}

/// `sudo-W05`: NOPASSWD on a specific (non-ALL) command. The operator-visible
/// signal that a passwordless grant was actually SEEN; a fail-open face drives
/// it to zero.
fn w05_count(src: &str) -> usize {
    count_code(src, "sudo-W05")
}

// ===========================================================================
// #622 / #630 - the structural `=` search is quote- and escape-blind.
//
// `classify_user_spec` locates the `Host_List = Cmnd_Spec_List` boundary with a
// bare `seg.find('=')`. `=` is exactly the special character quoting exists to
// protect, and `sudoers(5)` documents both spellings: a name "may be enclosed in
// double quotes to avoid the need for escaping special characters", and lists
// `=` among the characters that otherwise must be escaped.
// ===========================================================================

/// `"a=b" h1 = ALL` - visudo rc 0, `User_List ['a=b']`, `Host_List ['h1']`,
/// `Commands ['ALL']`.
///
/// Today the `eq` index lands on the `=` INSIDE the quotes, so `lhs` is `"a` and
/// the host part comes back empty: a `sudo-F01` Fatal on a valid file.
#[test]
fn quoted_user_containing_eq_is_not_a_false_fatal() {
    let src = "\"a=b\" h1 = ALL\n";
    assert_eq!(f01_count(src), 0, "visudo rc 0: no sudo-F01 may fire");

    let s = only_spec(src);
    // Values are kept VERBATIM from the source bytes, quotes included, per the
    // crate's convention; cvtsudoers reports the UNQUOTED name `a=b`.
    assert_eq!(s.users, vec!["\"a=b\"".to_string()]);
    assert_eq!(s.host_groups.len(), 1);
    assert_eq!(s.host_groups[0].hosts, vec!["h1".to_string()]);
}

/// `alice "h=1" = NOPASSWD: ALL` - visudo rc 0, `Host_List ['h=1']`,
/// `authenticate: false`, `Commands ['ALL']`.
///
/// The fail-open direction: today the host list is `["\"h"]` and the whole
/// remainder becomes one command string, so the run-anything-without-a-password
/// grant is never seen and `sudo-W01` fires zero times.
#[test]
fn quoted_host_containing_eq_still_reports_the_passwordless_all_grant() {
    let src = "alice \"h=1\" = NOPASSWD: ALL\n";
    assert_eq!(f01_count(src), 0, "visudo rc 0: no sudo-F01 may fire");
    assert_eq!(
        w01_count(src),
        1,
        "cvtsudoers: authenticate false on an ALL command - the grant must be seen"
    );
}

/// The three `#630` spellings, each a documented way to put `=` in a principal.
/// All are visudo rc 0 with `authenticate: false` on `/bin/ls`, so each must
/// produce exactly one `sudo-W05` and no false fatal.
#[test]
fn principal_containing_eq_still_reports_its_nopasswd_grant() {
    for src in [
        "\"a=b\" ALL = NOPASSWD: /bin/ls\n",
        "alice \"h=1\" = NOPASSWD: /bin/ls\n",
        "a\\=b ALL = NOPASSWD: /bin/ls\n",
    ] {
        assert_eq!(f01_count(src), 0, "visudo rc 0 for {src:?}");
        assert_eq!(
            w05_count(src),
            1,
            "the NOPASSWD grant must be seen in {src:?}"
        );
    }
}

/// Positive control, one character shorter than the first `#630` face and
/// already correct today. If this ever fails, the fix above broke ordinary
/// quoted principals rather than teaching the search about quotes.
#[test]
fn control_quoted_principal_without_eq_is_unaffected() {
    let src = "\"ab\" ALL = NOPASSWD: /bin/ls\n";
    assert_eq!(f01_count(src), 0);
    assert_eq!(w05_count(src), 1);
}

// ===========================================================================
// #612 - a `KEY=value` COMMAND ARGUMENT before a tag colon.
// ===========================================================================

/// `alice h1 = /bin/echo X=NOPASSWD : h2 = ALL` - visudo rc 0, and cvtsudoers
/// reports TWO `User_Specs`: `h1` with command `/bin/echo X=NOPASSWD`, and `h2`
/// with `ALL`.
///
/// Today the command-argument `=` resets `tok_start` just as the structural one
/// does, so at the tag colon the candidate span is the bare `NOPASSWD` (which
/// parses as a tag) rather than `/bin/echo X=NOPASSWD` (which does not). The
/// colon is read as a tag colon, `h2 = ALL` is swallowed into the first
/// command's text, and that grant leaves the model entirely.
#[test]
fn command_argument_eq_before_a_tag_colon_does_not_swallow_the_next_host_group() {
    let src = "alice h1 = /bin/echo X=NOPASSWD : h2 = ALL\n";
    let s = only_spec(src);
    assert_eq!(
        s.host_groups.len(),
        2,
        "cvtsudoers reports two User_Specs (h1 and h2); the h2 = ALL grant must not vanish"
    );
    assert_eq!(s.host_groups[0].hosts, vec!["h1".to_string()]);
    assert_eq!(s.host_groups[1].hosts, vec!["h2".to_string()]);
}

// ===========================================================================
// #631 - `option_value_end` runs PAST the closing quote.
//
// It computes a quoted value's end as "the next whitespace AFTER the closing
// quote" rather than "the closing quote", so a `Tag_Spec` glued to that quote is
// swallowed into the value. `quoted_value_span`, which records the SAME concept
// for the `':'` arm's benefit, correctly stops AT the closing quote - two
// recognizers of one concept disagreeing, which is the shape of every prior
// regression on this surface.
//
// `man 5 sudoers` documents no `Option_Spec` value quoting at all, so the live
// probe is the primary source. Re-derived here:
//   `alice ALL = CWD="/a:b"c NOPASSWD: /bin/su` -> rc 1 (sudo saw `c` as a FRESH
//       token, not as value bytes)
//   `alice ALL = CWD="/a"/bin/su`               -> rc 0, runcwd `/a`, command
//       `/bin/su`
// ===========================================================================

/// Face A, fully silent: a grant vanishes with zero diagnostics.
///
/// cvtsudoers: `runcwd '/a'`, `authenticate false`, command
/// `/usr/bin/env FOO=/bin/ls`. Today `RuleSteward` emits no `sudo-W05`, no
/// `sudo-F01` and no `sudo-E01` - it simply does not see the grant.
#[test]
fn tag_glued_to_a_closing_quote_still_reports_the_grant() {
    let src = "alice ALL = CWD=\"/a\"NOPASSWD: /usr/bin/env FOO=/bin/ls\n";
    assert_eq!(f01_count(src), 0, "visudo rc 0: no sudo-F01 may fire");
    assert_eq!(
        w05_count(src),
        1,
        "cvtsudoers: authenticate false - the NOPASSWD grant must be seen"
    );
}

/// The one-space control for face A, already correct today.
#[test]
fn control_tag_spaced_from_a_closing_quote_is_unaffected() {
    let src = "alice ALL = CWD=\"/a\" NOPASSWD: /usr/bin/env FOO=/bin/ls\n";
    assert_eq!(f01_count(src), 0);
    assert_eq!(w05_count(src), 1);
}

/// A command glued directly to the closing quote is a fresh token too:
/// `alice ALL = CWD="/a"/bin/su` is rc 0 with runcwd `/a` and command `/bin/su`.
#[test]
fn command_glued_to_a_closing_quote_is_a_fresh_token() {
    let src = "alice ALL = CWD=\"/a\"/bin/su\n";
    assert_eq!(f01_count(src), 0, "visudo rc 0: no sudo-F01 may fire");
    let s = only_spec(src);
    assert_eq!(s.host_groups.len(), 1);
    let specs = &s.host_groups[0].cmnd_specs;
    assert_eq!(specs.len(), 1, "one Cmnd_Spec");
    assert_eq!(
        specs[0].cmnd,
        CmndItem::Cmnd("/bin/su".to_string()),
        "the command must not be swallowed into the CWD value"
    );
}

// ===========================================================================
// #629 - a `)` in ordinary command text re-arms the option anchor.
//
// The `')'` arm resets `tok_start` on ANY `)`, including one that is plain
// command text and closed nothing, which restores a single-token span after a
// command word has already begun. A command argument merely SPELLED like an
// option keyword then regains an option value's quote-pairing power, and its
// quotes mask a real separator.
//
// `depth` is 0 at such a `)` (a mid-command `(` never bumps it), whereas a
// genuine runas close-paren has `depth > 0`. The arms do not distinguish them.
// ===========================================================================

/// cvtsudoers reports TWO `Cmnd_Spec`s here, the second with
/// `authenticate: false` and command `/bin/su"`. Today `RuleSteward` sees one and
/// `sudo-W05` never fires.
#[test]
fn literal_close_paren_in_command_text_does_not_mask_a_cmnd_spec_comma() {
    let src = "alice ALL = /bin/echo a) CWD=\"/a, NOPASSWD: /bin/su\"\n";
    assert_eq!(f01_count(src), 0, "visudo rc 0: no sudo-F01 may fire");
    assert_eq!(
        w05_count(src),
        1,
        "cvtsudoers: the second Cmnd_Spec carries authenticate false"
    );
}

/// The `XWD=` control: identical but for a keyword real sudo does not know, and
/// already correct today. Real sudo parses BOTH inputs the same way (two
/// `Cmnd_Spec`s); it is `RuleSteward` that diverges between them, which is what
/// isolates the mechanism to the option-keyword anchor.
#[test]
fn control_unknown_keyword_after_a_close_paren_is_unaffected() {
    let src = "alice ALL = /bin/echo a) XWD=\"/a, NOPASSWD: /bin/su\"\n";
    assert_eq!(f01_count(src), 0);
    assert_eq!(w05_count(src), 1);
}

/// The host-group face: cvtsudoers reports two `User_Specs`, `h1` and `h2`,
/// the second with `authenticate: false`.
#[test]
fn literal_close_paren_in_command_text_does_not_mask_a_host_group_colon() {
    let src = "alice h1 = /bin/sh -c f() CWD=\" : h2 = NOPASSWD: /bin/su \"y\n";
    let s = only_spec(src);
    assert_eq!(
        s.host_groups.len(),
        2,
        "cvtsudoers reports two User_Specs; the h2 grant must not vanish"
    );
}

/// The single-quoted negative control from #629. `'f()'` does NOT reproduce,
/// because the quote makes the preceding-token span multi-word again. Its job
/// is to stop a fix passing by removing the `)` reset outright.
#[test]
fn control_single_quoted_parens_do_not_reproduce() {
    let src = "alice ALL = /bin/echo 'f()' CWD=\"/a, NOPASSWD: /bin/su\"\n";
    assert_eq!(f01_count(src), 0);
}

// ===========================================================================
// The idiom that must keep working.
//
// `%wheel ALL=(ALL)CWD="/a:b" NOPASSWD: /bin/ls` is the single most common
// real-world sudoers spelling and NEEDS the `)` reset. Re-derived: rc 0,
// `runcwd '/a:b'`, `authenticate false`, command `/bin/ls`. Six further tests
// in iss538_parser_gaps.rs pin the `(root)CWD=` / `ALL=(ALL)CWD=` / `ALL=CWD=`
// spellings and must stay green.
// ===========================================================================

#[test]
fn idiom_runas_group_glued_to_an_option_keyword_still_works() {
    let src = "%wheel ALL=(ALL)CWD=\"/a:b\" NOPASSWD: /bin/ls\n";
    assert_eq!(f01_count(src), 0, "the most common real-world idiom");
    assert_eq!(w05_count(src), 1);
    let s = only_spec(src);
    assert_eq!(
        s.host_groups.len(),
        1,
        "the `:` inside the CWD value is a value byte"
    );
}
