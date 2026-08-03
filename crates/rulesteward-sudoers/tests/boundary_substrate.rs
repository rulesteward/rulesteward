//! Boundary-location fidelity: the structural `=`, the `Option_Spec` value's end,
//! and the four boundary arms of the top-level splitters.
//!
//! ONE root cause, five reproducing faces, filed as #622, #629, #630, #631 and
//! #643. Before the fix these tests pin, `parser.rs` decided where a structural
//! boundary is in two under-contextualized ways:
//!
//!   1. A QUOTE-BLIND byte search for the structural `=` (`seg.find('=')` in
//!      `classify_user_spec` and `classify_alias`), which landed inside a quoted
//!      principal that contains one. Now `structural_eq`.
//!   2. A POSITION ANCHOR (`tok_start`) in `split_top_level_segments` and
//!      `split_cmnd_specs`, whose boundary arms (`)`, `,`, `:`, `=`) each
//!      decided independently what counts as a boundary. At the fork point
//!      (`96038c9`) the guards were uneven: exactly two arms consulted the
//!      `quotes` registry the `'='` arms build - `split_top_level_segments`'s
//!      `':'` and `split_cmnd_specs`'s `','`. Of the rest,
//!      `split_top_level_segments`'s `','` had no guard at all, both `'='` arms
//!      were unguarded, and the two `')'` arms shared a POSITIONAL guard that
//!      fired on a `)` in plain command text.
//!
//! Four of the five are FAIL-OPEN: a `NOPASSWD` grant disappears from the
//! parsed model with no diagnostic, so a compliance run reports clean on a file
//! that grants passwordless sudo. That is the worst outcome this tool has.
//!
//! #612 was filed as a sixth face and is NOT one: it was already fixed on `main`
//! before this work began, verified against a build of `96038c9`, and its
//! reproducer contains no `(`, `)`, `,` or `"` so none of the changes here can
//! reach it. Its test is kept below purely as a regression pin.
//!
//! Two siblings of the same root cause remain OPEN as #645 and are deliberately
//! not pinned here: a quoted `:` in a principal-ALIAS member, and `comma_split`'s
//! quote-blindness. Both are pre-existing and both need changes outside this
//! surface. Do not read a green run of this file as covering them.
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
/// Before the fix, the `eq` index landed on the `=` INSIDE the quotes, so `lhs`
/// was `"a` and the host part came back empty: a `sudo-F01` Fatal on a valid
/// file.
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
/// The fail-open direction: before the fix the host list was `["\"h"]` and the
/// whole remainder became one command string, so the run-anything-without-a-
/// password grant was never seen and `sudo-W01` fired zero times.
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
/// REGRESSION PIN ONLY - this face does not reproduce and never did on any tree
/// this branch touched. It passed immediately against a `parser.rs` byte-identical
/// to `main`, and a build of `96038c9` reports no `sudo-F01` on it either.
///
/// #612 attributes it to the command-argument `=` resetting `tok_start` "just as
/// the structural one does". That is not what the code does: the `'='` arm
/// already leaves `tok_start` untouched on a rejected `=` while `in_cmnd_list`
/// (the `else if !in_cmnd_list` branch), so `preceding_token` at the tag colon is
/// the full `/bin/echo X=NOPASSWD`, never the bare `NOPASSWD`. Recorded so a
/// future reader does not go hunting for a bug that is not there.
///
/// The input contains no `(`, `)`, `,` or `"`, so none of the boundary changes on
/// this branch can reach it - which is the second, independent proof that
/// whatever fixed it, it was not this work.
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
// It computed a quoted value's end as "the next whitespace AFTER the closing
// quote" rather than "the closing quote", so a `Tag_Spec` glued to that quote was
// swallowed into the value. `quoted_value_span`, which records the SAME concept
// for the `':'` arm's benefit, always stopped AT the closing quote - two
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
/// `/usr/bin/env FOO=/bin/ls`. Before the fix `RuleSteward` emitted no
/// `sudo-W05`, no `sudo-F01` and no `sudo-E01` - it simply did not see the grant.
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
// The `')'` arm reset `tok_start` on ANY `)`, including one that is plain
// command text and closed nothing, which restored a single-token span after a
// command word had already begun. A command argument merely SPELLED like an
// option keyword then regained an option value's quote-pairing power, and its
// quotes masked a real separator.
//
// `depth` is 0 at such a `)` (a mid-command `(` never bumps it), whereas a
// genuine runas close-paren has `depth > 0`. The arms did not distinguish them;
// `depth > 0` is now part of the guard on both. It is not the WHOLE guard - see
// the quoted-runas-principal section below, where a `)` at `depth > 0` is still
// a literal byte and needs `runas_quotes` to exclude it.
// ===========================================================================

/// cvtsudoers reports TWO `Cmnd_Spec`s here, the second with
/// `authenticate: false` and command `/bin/su"`. Before the fix `RuleSteward` saw
/// one and `sudo-W05` never fired.
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

// ===========================================================================
// The third `)`, which the `depth > 0` guard alone does not model.
//
// BEFORE the fix the arm was `')' if depth > 0` - structural and quote-blind,
// with neither of the two registries then present reaching this byte
// (`principal_quotes` is gated `!in_cmnd_list`, already true by the time a runas
// group can open; `quotes` tracks only `Option_Spec` values). A `)` inside a
// QUOTED RUNAS PRINCIPAL therefore fired the arm, dropped `depth` to 0, and left
// the real closer to fall through to `_` without resetting `tok_start` -
// desyncing the rest of the line and discarding an independent grant.
//
// A `)` is literal in THREE ways, not two: unquoted in command text (structural,
// `depth` is 0 there), unquoted in an `Option_Spec` value, and quoted anywhere.
// The arm needs the structural AND the content test, so it now takes both, and
// `runas_quotes` is the third registry that supplies the second.
//
// Re-derived 2026-08-02, sudo 1.9.17p2, stdin only: the line below is
// `visudo -c -f -` rc 0, and `cvtsudoers -f json` reports TWO `User_Specs`,
// `runasusers ["root", "a)b"]`, and `authenticate: false` on BOTH.
// ===========================================================================

#[test]
fn quoted_close_paren_in_a_runas_principal_does_not_swallow_the_next_host_group() {
    let src = "alice ALL = (root,\"a)b\") NOPASSWD: /bin/ls : h2 = NOPASSWD: /bin/su\n";
    assert_eq!(f01_count(src), 0, "visudo accepts this line rc 0");
    let s = only_spec(src);
    assert_eq!(
        s.host_groups.len(),
        2,
        "cvtsudoers reports two User_Specs; the h2 grant must not vanish"
    );
    // 1 and not 2, and the missing one is NOT this arm's doing: `parse_cmnd_spec`
    // locates the runas list's end with a bare `after_open.find(')')`, which stops at
    // the QUOTED paren and truncates the token to `"a` (visible in the collateral
    // `sudo-F02` text). That drops the FIRST group's grant, identically on the fork
    // point and on HEAD, and is filed as #650. When #650 lands this becomes 2.
    //
    // THIS test is the regression pin, and it pins via `f01_count` above rather
    // than via the count below: with the content guard removed from both `')'`
    // arms, it is the ONLY test in this file that fails, and it fails on
    // `f01_count` (`left: 1, right: 0`) -- the regression surfaces as a false
    // FATAL, not as a missing grant. Measured by building that mutant, 2026-08-02.
    assert_eq!(w05_count(src), 1, "h2's grant; group 1's is lost to #650");
}

/// The security property with #650's interference removed: only the SECOND host
/// group carries a `NOPASSWD`, so the count cannot be satisfied by the first
/// group's grant.
///
/// NOT the regression pin, despite testing the property the regression violated.
/// Its line has no tag colon in the first host group, and the tag colon is what
/// makes a corrupted `tok_start` observable -- so a `')'` arm that loses its
/// content guard leaves this test GREEN. Isolating it from #650 also isolated it
/// from the defect. The pin is
/// [`quoted_close_paren_in_a_runas_principal_does_not_swallow_the_next_host_group`].
#[test]
fn quoted_close_paren_in_a_runas_principal_keeps_the_independent_h2_grant() {
    let src = "alice ALL = (root,\"a)b\") /bin/ls : h2 = NOPASSWD: /bin/su\n";
    assert_eq!(f01_count(src), 0);
    assert_eq!(only_spec(src).host_groups.len(), 2);
    assert_eq!(w05_count(src), 1, "the h2 grant must survive");
}

/// The one-byte negative control: the same line with the `)` deleted from the
/// quoted principal. sudo treats `a)b` and `ab` alike as principal NAMES. The two
/// lines still do not lint IDENTICALLY -- `w05_count` is 1 above and 2 here --
/// because #650 truncates the first group's grant on the `a)b` spelling only.
///
/// Green on the fork point as well, so a fix cannot pass by DISABLING the `')'`
/// arm outright. It is blind to deletion of `depth > 0` on its own: this line
/// holds exactly one `)`, at which `depth` is 1, so that guard is a no-op here.
/// Deleting `depth > 0` is killed instead by
/// [`literal_close_paren_in_command_text_does_not_mask_a_host_group_colon`],
/// [`literal_close_paren_in_command_text_does_not_mask_a_cmnd_spec_comma`] and
/// [`control_unknown_keyword_after_a_close_paren_is_unaffected`] -- verified by
/// building that mutant, 2026-08-02.
#[test]
fn control_quoted_runas_principal_without_a_paren_is_unaffected() {
    let src = "alice ALL = (root,\"ab\") NOPASSWD: /bin/ls : h2 = NOPASSWD: /bin/su\n";
    assert_eq!(f01_count(src), 0);
    assert_eq!(only_spec(src).host_groups.len(), 2);
    assert_eq!(w05_count(src), 2);
}

/// The second one-byte control: `(` instead of `)`. INSIDE a quoted principal
/// only the CLOSING paren can desync `depth`, because `at_spec_start` is already
/// false there so the `(` never bumps it. (Elsewhere a `(` certainly can desync
/// depth - see the #416 note on the `'('` arm in `parser.rs`.) Green on both
/// shas, isolating the defect to the close-paren rather than to
/// quoting-in-a-runas-list at all.
#[test]
fn control_quoted_open_paren_in_a_runas_principal_is_unaffected() {
    let src = "alice ALL = (root,\"a(b\") NOPASSWD: /bin/ls : h2 = NOPASSWD: /bin/su\n";
    assert_eq!(f01_count(src), 0);
    assert_eq!(only_spec(src).host_groups.len(), 2);
    assert_eq!(w05_count(src), 2);
}

// ===========================================================================
// The OTHER arms that need the runas registry.
//
// Adding `runas_quotes` and wiring only the `')'` arm to it left the `','` and
// `'='` arms of `split_top_level_segments` still blind to a quoted runas
// principal - the same one-arm-of-three sweep miss this whole file exists to
// close, one registry later.
//
// The chain, for `alice ALL = ("a,CWD=") /bin/ls, CWD="/tmp" NOPASSWD: ALL`:
// the `,` INSIDE the quoted principal advances `tok_start`, so `preceding_token`
// at the following `=` is exactly `CWD` - an `Option_Spec` keyword harvested from
// inside a principal. `quoted_value_span` then reads the principal's own CLOSING
// quote as a value OPENER, pairs it with the next quote, and the resulting bogus
// span covers the real top-level `,`. The tag colon then measures
// `/bin/ls, CWD="/tmp" NOPASSWD`, `parse_tag` rejects it, and the line is
// discarded - losing a NOPASSWD-on-ALL grant.
//
// Oracle 2026-08-02 (sudo 1.9.17p2, stdin only): rc 0, ONE host group with TWO
// Cmnd_Specs, `runasusers ["a,CWD="]` on both, and `authenticate: false` +
// `command: ALL` on the second.
//
// The quoted-HOST-principal twin is already protected, because the `'='` arm
// does consult `principal_quotes`; that asymmetry is what identifies the gap.
// ===========================================================================

#[test]
fn comma_inside_a_quoted_runas_principal_does_not_hide_the_passwordless_all_grant() {
    let src = "alice ALL = (\"a,CWD=\") /bin/ls, CWD=\"/tmp\" NOPASSWD: ALL\n";
    assert_eq!(f01_count(src), 0, "visudo accepts this line rc 0");
    assert_eq!(
        w01_count(src),
        1,
        "the passwordless ALL grant must be reported"
    );
}

/// One-byte negative control: `CWD` -> `XWD` is not an `Option_Spec` keyword, so
/// no anchor is manufactured inside the principal and no bogus span opens. Green
/// on the fork point AND on HEAD, so a fix cannot pass by deleting a guard.
#[test]
fn control_non_keyword_inside_a_quoted_runas_principal_is_unaffected() {
    let src = "alice ALL = (\"a,XWD=\") /bin/ls, CWD=\"/tmp\" NOPASSWD: ALL\n";
    assert_eq!(f01_count(src), 0);
    assert_eq!(w01_count(src), 1);
}

/// The twin that was ALREADY protected, kept as the contrast that localises the
/// defect: the identical construct in a quoted HOST principal works, because the
/// `'='` arm consults `principal_quotes`. Only the runas region lacked a registry.
#[test]
fn comma_inside_a_quoted_host_principal_is_protected_by_principal_quotes() {
    let src = "alice \"h,CWD=\" = CWD=\"/tmp\" NOPASSWD: ALL\n";
    assert_eq!(f01_count(src), 0);
    assert_eq!(w01_count(src), 1);
}

// ===========================================================================
// The unswept siblings.
//
// Routing the `'='` arm through a quoted-principal registry closed the `=` face
// and left the SEPARATOR faces open, because a quoted principal may contain a
// `:` as legitimately as it contains an `=`. Both faces below are one boundary
// arm away from the ones above and neither was sampled by any of the 95 frozen
// tests, so a green suite said nothing about them.
//
// The openers themselves follow real sudo's ALTERNATE PAIRING: a `"` opens a
// principal unless it is closing one already open. Whitespace before it is
// irrelevant, which the frozen suite already recorded in
// `a_quote_right_after_a_bare_word_starts_a_new_principal_token_with_no_whitespace_needed`
// ("a `\"` always opens a NEW token, whether or not whitespace precedes it").
//
// All ground truth below re-derived on 2026-08-02, sudo 1.9.17p2, same
// positive-controlled oracle as the rest of this file.
// ===========================================================================

/// `alice" h=1" = NOPASSWD: /bin/ls` - visudo rc 0, `Host_List [' h=1']`,
/// `authenticate: false`. The opening `"` is GLUED to `alice` with no space,
/// and real sudo still starts a fresh principal token there.
#[test]
fn glued_quoted_principal_containing_eq_still_reports_its_nopasswd_grant() {
    for src in [
        "alice\" h=1\" = NOPASSWD: /bin/ls\n",
        "alice\"h=1\" = NOPASSWD: /bin/ls\n",
    ] {
        assert_eq!(f01_count(src), 0, "visudo rc 0 for {src:?}");
        assert_eq!(
            w05_count(src),
            1,
            "the NOPASSWD grant must be seen in {src:?}"
        );
    }
    assert_eq!(
        w01_count("alice\"h=1\" = NOPASSWD: ALL\n"),
        1,
        "passwordless ALL on a glued quoted host"
    );
    assert_eq!(
        only_spec("alice\" h=1\" = ALL\n").host_groups[0].hosts,
        vec!["\" h=1\"".to_string()],
        "the host is the whole quoted token, kept verbatim"
    );
}

/// The same glued spelling WITHOUT an `=` inside the quotes. This one already
/// parsed correctly, which is exactly why the defect above survived: the frozen
/// suite covered the glued opener here and the interior `=` elsewhere, and
/// never their intersection.
#[test]
fn control_glued_quoted_principal_without_eq_is_unaffected() {
    let src = "alice\" h1\" = ALL\n";
    assert_eq!(f01_count(src), 0);
    assert_eq!(
        only_spec(src).host_groups[0].hosts,
        vec!["\" h1\"".to_string()]
    );
}

/// `alice "h:1" = NOPASSWD: ALL` - visudo rc 0, `Host_List ['h:1']`,
/// `authenticate: false`. `sudoers(5)` documents quoting a name precisely "to
/// avoid the need for escaping special characters", and `:` is one of them.
#[test]
fn quoted_colon_in_a_principal_is_not_a_host_group_separator() {
    let src = "alice \"h:1\" = NOPASSWD: ALL\n";
    assert_eq!(f01_count(src), 0, "visudo rc 0");
    assert_eq!(w01_count(src), 1, "the passwordless ALL grant must be seen");
    let s = only_spec(src);
    assert_eq!(s.host_groups.len(), 1, "the quoted `:` is a host byte");
    assert_eq!(s.host_groups[0].hosts, vec!["\"h:1\"".to_string()]);

    let specific = "alice \"h:1\" = NOPASSWD: /bin/ls\n";
    assert_eq!(f01_count(specific), 0);
    assert_eq!(w05_count(specific), 1);
}

// The ALIAS face of this same arm is NOT fixed here and is tracked as #645,
// which carries its ready-to-restore RED test. `Host_Alias A = "h:1"` is rc 0
// and still reports a false `sudo-F01` plus a cascading `sudo-E01` on every
// reference to the alias. It needs a model change rather than another guard:
// `split_top_level_segments` takes a `skip_tag_colons: bool`, but there are
// THREE modes, not two -- a user-spec has commands after the structural `=`,
// `User_`/`Host_`/`Runas_Alias` have PRINCIPALS there, and `Cmnd_Alias` has
// commands (real sudo rejects `Cmnd_Alias C = "/bin/foo:bar"`, rc 1, so the
// distinction is not cosmetic). Pre-existing, verified identical on 96038c9.

/// An unmatched principal quote must STILL be rejected: `%bad"group ALL = ALL`
/// is visudo rc 1. Alternate pairing must not become "any quote opens a span
/// that runs to end of line", which would silently accept it.
#[test]
fn control_unmatched_principal_quote_is_still_rejected() {
    assert_eq!(
        count_code("%bad\"group ALL = ALL\n", "sudo-F02"),
        1,
        "visudo rc 1; an unterminated principal quote must not be waved through"
    );
}

// ---------------------------------------------------------------------------
// Mutation-survivor kills. The principal-opener predicate arrived with six
// survivors, all reporting it as observationally inert: nothing pinned WHICH
// quote opens a span. Each line below is visudo rc 0 with `authenticate: false`.
//
// The predicate has since been rewritten (positional -> alternate pairing), so
// the surviving mutant SET is not the one these were written against; what each
// test still does is stated per-test below and was checked by running the
// mutant, not by inspection.
// ---------------------------------------------------------------------------

/// Kills the `-> true` / `-> false` / `delete !` family on the opener predicate
/// and the `guard -> true` mutants at both call sites: with every `"` opening a
/// span, the CLOSING quote of `"a b"` re-opens one that then swallows the
/// structural `=`.
#[test]
fn quoted_user_with_a_space_plus_a_chroot_value_holding_a_paren_and_a_keyword() {
    let src = "\"a b\" ALL=(ALL:ALL)CHROOT=\"/a)CWD=\" NOPASSWD: /bin/ls\n";
    assert_eq!(f01_count(src), 0, "visudo rc 0");
    assert_eq!(w05_count(src), 1, "the NOPASSWD grant must be seen");
    assert_eq!(only_spec(src).users, vec!["\"a b\"".to_string()]);
}

/// A comma-preceded opener: the second user is a quoted principal containing an
/// `=`. With only ONE span in play this cannot distinguish the comparison
/// mutants (`open < i` already holds); it pins the `-> false` / `delete !`
/// family and the shape itself. The two-span test below is what separates
/// `&&` from `||`.
#[test]
fn comma_separated_user_list_with_a_quoted_eq_member() {
    let src = "alice,\"b=c\" ALL = NOPASSWD: /bin/ls\n";
    assert_eq!(f01_count(src), 0, "visudo rc 0");
    assert_eq!(w05_count(src), 1);
    assert_eq!(
        only_spec(src).users,
        vec!["alice".to_string(), "\"b=c\"".to_string()]
    );
}

/// A colon-preceded, GLUED opener: the second host group's principal is a
/// quoted token containing an `=`, glued to the segment colon before it. Also a
/// single-span case, so it pins the shape rather than the comparison operators.
#[test]
fn glued_quoted_host_containing_eq_after_a_segment_colon() {
    let src = "alice h1 = /bin/ls :\"h=2\" = NOPASSWD: ALL\n";
    assert_eq!(f01_count(src), 0, "visudo rc 0");
    assert_eq!(w01_count(src), 1, "the second group's passwordless ALL");
    let s = only_spec(src);
    assert_eq!(s.host_groups.len(), 2, "cvtsudoers reports two User_Specs");
    assert_eq!(s.host_groups[1].hosts, vec!["\"h=2\"".to_string()]);
}

/// TWO quoted principals on one line, each carrying its own `=`. Every earlier
/// case has at most one, so none of them can tell `open < i && i <= close` from
/// `open < i || i <= close` in `opens_principal`: spans are pushed only AFTER
/// the open decision, so `open < i` already holds for every span in the vector,
/// and under `||` the first span alone would mask every later quote. The second
/// principal would then never open, its interior `=` would be taken for the
/// structural one, and the grant would be lost.
///
/// visudo rc 0 for all three; `cvtsudoers` reports
/// `User_List ['a=b']` + `Host_List ['h=1']` for the first,
/// `User_List ['a=b','c=d']` for the second, and `['alice','b=c']` for the
/// third, each with `authenticate: false`.
#[test]
fn two_quoted_principals_each_containing_eq_both_open_their_own_span() {
    for src in [
        "\"a=b\" \"h=1\" = NOPASSWD: /bin/ls\n",
        "\"a=b\",\"c=d\" ALL = NOPASSWD: /bin/ls\n",
        "alice,\"b=c\" \"h=1\" = NOPASSWD: /bin/ls\n",
    ] {
        assert_eq!(f01_count(src), 0, "visudo rc 0 for {src:?}");
        assert_eq!(
            w05_count(src),
            1,
            "the grant must survive both spans in {src:?}"
        );
    }

    let s = only_spec("\"a=b\" \"h=1\" = NOPASSWD: /bin/ls\n");
    assert_eq!(s.users, vec!["\"a=b\"".to_string()]);
    assert_eq!(
        s.host_groups[0].hosts,
        vec!["\"h=1\"".to_string()],
        "the SECOND quoted principal must open its own span, not be masked by the first"
    );
}

// ===========================================================================
// The escape model inside a quoted string.
//
// A backslash escapes ONLY a `"`. A backslash followed by anything else -
// INCLUDING another backslash - is a literal byte that consumes nothing, so
// `\\"` is literal-backslash + ESCAPED-quote and the string CONTINUES.
//
// Probes, sudo 1.9.17p2, 2026-08-02, stdin only:
//   `alice "h\"1" = ALL`     -> rc 0, Host_List ['h"1']    (one backslash)
//   `alice "h\\1" = ALL`     -> rc 0, Host_List ['h\\1']   (both kept, neither consumed)
//   `alice "h\\" = ALL`      -> rc 1                       (that `"` does NOT close)
//   `alice "a\\"b" = ALL`    -> rc 0, Host_List ['a\"b']   (span runs past it)
//   `alice "a\\\\" = ALL`    -> rc 1                       (four backslashes: still escaped)
//
// The rule that reproduces all five is simply: a `"` is escaped IFF the byte
// immediately before it is `\`. `find_closing_quote` and
// `unescaped_quote_positions` instead had a backslash consume whatever came
// next, which closes the span one quote too early.
//
// That model was latent for as long as nothing depended on it in a
// grant-bearing position. `opens_principal` made it load-bearing: closing the
// span early leaves the NEXT quote looking like a fresh opener, and the bogus
// span it opens covers the structural `=`, so the line is thrown away
// Malformed and its NOPASSWD grant is never linted. No test in this crate
// contained the byte sequence `\ \ "` before these.
// ===========================================================================

/// The fail-open witness. visudo rc 0, `Host_List ['h\"1']`,
/// `authenticate: false`, command `/bin/echo "x"` - a real passwordless grant.
#[test]
fn doubled_backslash_before_a_quote_does_not_close_the_principal_span() {
    let src = "alice \"h\\\\\"1\" = NOPASSWD: /bin/echo \"x\"\n";
    assert_eq!(f01_count(src), 0, "visudo rc 0: no sudo-F01 may fire");
    assert_eq!(w05_count(src), 1, "the NOPASSWD grant must be seen");
    assert_eq!(
        only_spec(src).host_groups[0].hosts,
        vec!["\"h\\\\\"1\"".to_string()],
        "the whole quoted token is one host, kept verbatim"
    );
}

/// The same escape, with a genuine host-group separator after it. visudo rc 0
/// and cvtsudoers reports TWO `User_Specs`, the second carrying
/// `authenticate: false`. Closing the span early makes the bogus second span
/// swallow that separator too.
#[test]
fn doubled_backslash_span_does_not_swallow_a_later_host_group() {
    let src = "alice \"h\\\\\"1\" = /bin/ls : h2 = NOPASSWD: /bin/echo \"x\"\n";
    assert_eq!(f01_count(src), 0, "visudo rc 0");
    assert_eq!(w05_count(src), 1, "the second group's grant must be seen");
    let s = only_spec(src);
    assert_eq!(s.host_groups.len(), 2, "cvtsudoers reports two User_Specs");
    assert_eq!(s.host_groups[1].hosts, vec!["h2".to_string()]);
}

/// Control: a SINGLE backslash before the quote, where both escape models agree
/// (`alice "h\"1" = ALL` is rc 0 with `Host_List ['h"1']`). If this ever fails,
/// the fix went too far and stopped honouring `\"` as an escape at all.
#[test]
fn control_single_backslash_still_escapes_the_quote() {
    let src = "alice \"h\\\"1\" = ALL\n";
    assert_eq!(f01_count(src), 0);
    assert_eq!(
        only_spec(src).host_groups[0].hosts,
        vec!["\"h\\\"1\"".to_string()]
    );
}

// ===========================================================================
// #651 - `split_user_list` discards the CLOSING-quote position.
//
// It iterated quote spans as `for (open, _close) in simple_quote_pairs(lhs)`,
// binding the close to `_close` and throwing it away, so `close + 1` was never
// a boundary candidate. When a principal's closing quote is GLUED to the next
// token no candidate exists at all: `unquoted_whitespace_runs` finds no
// whitespace outside the pair, and the glued-OPENER candidate is skipped when
// `open == 0`. `split_user_list` returns `(lhs, "")`, the host part is empty,
// and the line dies as `sudo-F01` - taking any grant on it with it. FAIL-OPEN.
//
// The crate already models "the next token starts at `close + 1`" TWICE on the
// value/command side - `option_value_end` (`return close + 1`, #631) and
// `parse_cmnd_spec` (`rest = after_open[close + 1..]`) - and models the
// MIRROR-IMAGE opener rule on the principal side in `split_user_list` itself.
// The principal side modelled the glued OPENER and not the glued CLOSER. That
// asymmetry is the bug.
//
// PRE-EXISTING, not a regression: identical on `96038c9` (the fork point of the
// PREVIOUS branch, `fix/sudoers-boundary-substrate`, not of this one - this
// branch forks at `ee250aa`) and on that branch's tip. `96038c9` is the right
// baseline for the claim because it PRECEDES the change being exonerated;
// `split_user_list` there still reads `for (open, _close) in ...`.
//
// Ground truth re-derived on rs-oracle9 (sudo 1.9.17p2) 2026-08-02, every row
// `visudo -c -f -` rc 0 `parsed OK`, every row carrying a one-byte space
// control that isolates the defect to the glued closing quote:
//
//   `"ab"ALL = NOPASSWD: ALL`          -> User_List ["ab"],      Host_List ["ALL"]
//   `"ab" ALL = NOPASSWD: ALL`         -> identical (the control)
//   `"ops team"web1 = NOPASSWD: /bin/ls` -> User_List ["ops team"], Host_List ["web1"]
//   `alice,"b c"ALL = NOPASSWD: ALL`   -> User_List ["alice","b c"], Host_List ["ALL"]
// ===========================================================================

/// Face A: the grant vanishes behind a false FATAL.
///
/// cvtsudoers splits this into `User_List ["ab"]` / `Host_List ["ALL"]` with
/// `authenticate: false`, so the correct output is exactly one `sudo-W01`
/// (NOPASSWD on ALL). Before the fix `RuleSteward` emitted `sudo-F01` ("needs
/// both a user list and a host list before the `=`") and NO `sudo-W01`.
#[test]
fn glued_closing_quote_in_the_principal_list_still_reports_the_grant() {
    let src = "\"ab\"ALL = NOPASSWD: ALL\n";
    assert_eq!(f01_count(src), 0, "visudo rc 0: no sudo-F01 may fire");
    assert_eq!(
        w01_count(src),
        1,
        "cvtsudoers: authenticate false on Host_List ALL - the NOPASSWD grant must be seen"
    );
}

/// The one-byte control for face A. A single added space is the whole
/// difference, which is what isolates the defect to the glued CLOSING quote
/// rather than to quoting in a principal generally.
///
/// The structural assertion below pins the split shape for its own sake. It is
/// deliberately NOT claimed as a mutant-killer, and the correction is recorded
/// because getting it wrong once already cost a false comment on this branch.
///
/// The `bytes.get(close + 1)` -> `close - 1` / `close * 1` mutants SURVIVE this
/// test, structural assertion included. The mutated guard does push a spurious
/// candidate `(close + 1, close + 1)` here, where `close + 1` IS the space, and
/// that candidate does sort ahead of the whitespace run and win - but
/// `comma_split` maps `str::trim` over the halves, so `host_groups[0].hosts`
/// comes back `["ALL"]` either way and the stray byte never reaches an
/// assertion. That is exactly WHY the mutants survived the original five tests.
///
/// The kill belongs to `a_space_then_a_comma_after_a_closing_quote_is_not_a_boundary`,
/// where the comma-continuation filter, not trimming, is what the spurious
/// candidate defeats. See that test for the mechanism.
///
/// Both mutants were built and run: this test PASSES under each, while
/// `a_space_then_a_comma_after_a_closing_quote_is_not_a_boundary` goes RED under
/// each.
/// verified: 2026-08-03
#[test]
fn control_principal_spaced_from_a_closing_quote_is_unaffected() {
    let src = "\"ab\" ALL = NOPASSWD: ALL\n";
    assert_eq!(f01_count(src), 0);
    assert_eq!(w01_count(src), 1);
    let s = only_spec(src);
    assert_eq!(s.users, vec!["\"ab\"".to_string()]);
    assert_eq!(
        s.host_groups[0].hosts,
        vec!["ALL".to_string()],
        "the host must be exactly `ALL`: a candidate placed ON the space instead \
         of after it yields a leading-space host that every lint-code count misses"
    );
}

/// The structural face, sharper than a lint-code count: the boundary must land
/// AT `close + 1`, so the quoted token is the whole user list and `ALL` is the
/// whole host list. A count-only assertion would still pass if the split landed
/// somewhere else that happened to produce one `sudo-W01`.
#[test]
fn glued_closing_quote_splits_the_user_list_from_the_host_list() {
    let s = only_spec("\"ab\"ALL = NOPASSWD: ALL\n");
    assert_eq!(
        s.users,
        vec!["\"ab\"".to_string()],
        "the quoted token is the whole user list, kept verbatim"
    );
    assert_eq!(s.host_groups.len(), 1);
    assert_eq!(
        s.host_groups[0].hosts,
        vec!["ALL".to_string()],
        "the host list starts at close + 1, not at the next whitespace"
    );
}

/// The guard's two EXCLUSIONS are load-bearing, and this is what proves it.
///
/// `close + 1` is only a boundary when the next byte is neither whitespace (the
/// whitespace run already supplies a candidate) nor `,` (the user list
/// continues). Both exclusions look redundant in isolation: drop the whitespace
/// one and trimming hides it, drop the comma one and the continuation filter
/// below rejects the candidate anyway. They stop being redundant where the two
/// cases MEET - a space followed by a comma.
///
/// `"ab" ,alice ALL = NOPASSWD: ALL` is `visudo -c -f -` rc 0 with
/// `User_List ["ab","alice"]`, `Host_List ["ALL"]`, `authenticate false`
/// (rs-oracle9, sudo 1.9.17p2, 2026-08-03). The whitespace-run candidate
/// `(4, 5)` is correctly REJECTED because its `after` begins `,alice`, so the
/// split falls through to the real boundary before `ALL`.
///
/// A guard that inspects the wrong byte pushes an extra candidate `(4, 4)` whose
/// `after` is `" ,alice ALL"` - beginning with the SPACE, so
/// `after.starts_with(',')` is false and the continuation filter no longer fires.
/// It sorts first, wins, and the line parses as user `"ab"` with host list
/// `,alice ALL`.
///
/// This is the case the mutation gate found: `bytes.get(close + 1)` ->
/// `bytes.get(close - 1)` and `-> bytes.get(close * 1)` both survived the
/// original five tests, including a structural assertion on the spaced control,
/// because every one of those inputs let trimming or the comma filter absorb the
/// stray candidate (verified: 2026-08-03, both mutants built and run; RED here,
/// green everywhere else).
#[test]
fn a_space_then_a_comma_after_a_closing_quote_is_not_a_boundary() {
    let src = "\"ab\" ,alice ALL = NOPASSWD: ALL\n";
    assert_eq!(f01_count(src), 0, "visudo rc 0: no sudo-F01 may fire");
    let s = only_spec(src);
    assert_eq!(
        s.users,
        vec!["\"ab\"".to_string(), "alice".to_string()],
        "the comma continues the USER list; it must not be swallowed into the hosts"
    );
    assert_eq!(
        s.host_groups[0].hosts,
        vec!["ALL".to_string()],
        "the host list is exactly `ALL`, not `,alice ALL`"
    );
}

/// A THREE-token left-hand side must stay rejected, and this is the one input
/// where #651's new candidate would otherwise have lost an existing catch.
///
/// `a\ "b"c = NOPASSWD: ALL` is `visudo -c -f -` **rc 1**, `stdin:1:7: syntax
/// error`: sudo lexes three LHS tokens, `a ` (the backslash escapes the space),
/// `b`, and `c`, and a user spec takes exactly two.
///
/// The escape is what makes it delicate. `unquoted_whitespace_runs` deliberately
/// emits NO run here (its `\` arm consumes the next byte), and the glued-OPENER
/// candidate is skipped because `prev` is that escaped space. So before #651
/// there was no candidate at all, `split_user_list` fell through to `(lhs, "")`,
/// and the line was rejected - correct verdict, reached by accident. #651's
/// `close + 1` candidate is a genuine boundary between `"b"` and `c`, and
/// supplying it turned the accidental rejection into an acceptance.
///
/// The real defect is that a 3-token LHS was never DETECTED, only stumbled over.
/// That gap is pre-existing and wider than this input: `a\ "b" c = ...` is also
/// oracle rc 1 and is accepted identically on `ee250aa` and here, which is the
/// one-byte control isolating the flip to the glued spelling.
///
/// KNOWN-OPEN, filed as #669. `#[ignore]`d rather than deleted, per this
/// repo's convention: removing the `#[ignore]` is how the fix gets demonstrated.
///
/// A repair WAS built and then reverted, and the reason is the useful part.
/// Detecting the arity means reclassifying such a line as `Malformed`, and the
/// frozen `f02_malformed_group_subject_fires` shows what that costs: `%bad group
/// ALL = ALL` is also a three-token LHS, and today `RuleSteward` parses it
/// structurally and catches it with a PRECISE `sudo-F02` naming the bad group
/// token. Under the arity check it became a generic Fatal instead, and a
/// `Malformed` line is invisible to every W/E pass (#668). So the obvious fix
/// trades a specific finding for a vague one and can SUPPRESS other lints - the
/// fail-open shape, arriving through the front door.
///
/// That is a design decision about diagnostic precedence, not an implementation
/// detail, so it is filed rather than guessed at, and the frozen test was left
/// alone rather than weakened to reach green.
#[test]
#[ignore = "#669: a 3-token LHS is not detected; repairing it needs a diagnostic-precedence decision"]
fn a_three_token_left_hand_side_is_rejected() {
    let src = "a\\ \"b\"c = NOPASSWD: ALL\n";
    assert_eq!(
        f01_count(src),
        1,
        "visudo rc 1 (three LHS tokens): sudo-F01 must fire"
    );
}

/// The one-byte control for the case above, and the evidence that #669 is a
/// PRE-EXISTING hole rather than this branch's doing: `a\ "b" c = ...` is oracle
/// rc 1 and is accepted identically on `ee250aa` and here.
///
/// The pair together is what makes the regression legible. This spelling is
/// wrong on BOTH shas; the glued one was right on `ee250aa` only because no
/// boundary candidate existed at all, so the line fell through to `(lhs, "")`
/// and was rejected for the wrong reason. #651 supplied the missing candidate
/// and the accident stopped happening.
#[test]
#[ignore = "#669: pre-existing on both shas; the paired control for the regression"]
fn a_three_token_left_hand_side_with_a_spaced_quote_is_also_rejected() {
    let src = "a\\ \"b\" c = NOPASSWD: ALL\n";
    assert_eq!(f01_count(src), 1, "visudo rc 1: sudo-F01 must fire");
}

/// The two-token controls, which must keep parsing. If either of these ever
/// fires `sudo-F01`, the arity check above has become a false-FATAL generator -
/// the worst regression shape for a compliance linter, and the reason the check
/// reuses the splitter's own candidate logic instead of a fresh whitespace scan.
#[test]
fn control_two_token_left_hand_sides_still_parse() {
    for src in [
        "alice ALL = NOPASSWD: ALL\n",
        "alice,bob ALL = NOPASSWD: ALL\n",
        "alice, bob ALL = NOPASSWD: ALL\n",
        "alice ,bob ALL = NOPASSWD: ALL\n",
        "alice , bob ALL = NOPASSWD: ALL\n",
        "\"ab\"ALL = NOPASSWD: ALL\n",
        "\"ops team\"web1 = NOPASSWD: /bin/ls\n",
        "alice h1,h2 = NOPASSWD: ALL\n",
        "alice h1, h2 = NOPASSWD: ALL\n",
        "my\\ user ALL = ALL\n",
    ] {
        assert_eq!(f01_count(src), 0, "must still parse: {src:?}");
    }
}

/// A quoted principal whose value CONTAINS whitespace. This is the case a
/// whitespace-run boundary can never reach on its own: the only space in the
/// line sits INSIDE the quoted span, so before the fix there was no candidate
/// boundary anywhere in `"ops team"web1`.
#[test]
fn quoted_principal_containing_a_space_glued_to_its_host_still_reports_the_grant() {
    let src = "\"ops team\"web1 = NOPASSWD: /bin/ls\n";
    assert_eq!(f01_count(src), 0, "visudo rc 0: no sudo-F01 may fire");
    assert_eq!(
        w05_count(src),
        1,
        "the name promises a reported grant, so assert one: cvtsudoers gives \
         authenticate false on /bin/ls"
    );
    let s = only_spec(src);
    assert_eq!(s.users, vec!["\"ops team\"".to_string()]);
    assert_eq!(s.host_groups[0].hosts, vec!["web1".to_string()]);
}

/// The comma-list form: the glued closing quote is the boundary even when the
/// quoted principal is the LAST element of a multi-principal user list, where
/// the comma-continuation logic also has to not swallow it.
#[test]
fn glued_closing_quote_after_a_comma_list_still_reports_the_grant() {
    let src = "alice,\"b c\"ALL = NOPASSWD: ALL\n";
    assert_eq!(f01_count(src), 0, "visudo rc 0: no sudo-F01 may fire");
    assert_eq!(w01_count(src), 1, "the NOPASSWD grant must be seen");
    let s = only_spec(src);
    assert_eq!(
        s.users,
        vec!["alice".to_string(), "\"b c\"".to_string()],
        "cvtsudoers reports two usernames"
    );
    assert_eq!(s.host_groups[0].hosts, vec!["ALL".to_string()]);
}
