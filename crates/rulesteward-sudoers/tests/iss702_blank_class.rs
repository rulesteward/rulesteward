//! sudo separates on `[[:blank:]]` only (#702).
//!
//! sudo's lexer (`toke.l`) discards `[[:blank:]]+` - space and tab - and
//! nothing else. Every other whitespace character is an ordinary `WORD` byte
//! and can appear inside, or BE, a principal name. This crate asked
//! `char::is_whitespace` or `str::trim`, which are far wider, in SIX places, so
//! the same concept had six recognizers and they did not agree with sudo or with
//! each other. (Four of the six asked `str::trim`, not `char::is_whitespace`;
//! naming only the predicate was itself imprecise.)
//!
//! Two failure directions, both live before this fix:
//!
//! * a line `visudo` ACCEPTS loses its `Host_List`, folds to `Malformed`, and
//!   per #668 every W/E lint is suppressed on it - so a `NOPASSWD: ALL` grant
//!   is never evaluated and nothing says so. That is #702 as filed.
//! * the SAME confusion, one round later: #701's `holds_a_principal` used the
//!   NARROW class while `split_user_list`'s entry `trim` used the WIDE one, so
//!   the trim ate the very character that made a half a principal and the
//!   postcondition then correctly saw a half of nothing but `!` and killed the
//!   split. That direction was CORRECT at `6abb10a` and regressed at `360ca9c`;
//!   it is the `a_sigil_followed_by_*` rows below.
//!
//! The second one is why this is a class fix and not another patch. Four
//! consecutive adversarial rounds on this lane each found one defect, and all
//! four were the same shape: two recognizers of one lexical concept
//! disagreeing. Narrowing one of them created the next round's regression at
//! precisely the seam the previous round's comment had described.
//!
//! GROUNDING. Every row re-derived on `rs-oracle9` (sudo 1.9.17p2), fed on
//! stdin with `--network=none`, 2026-08-19. `<NBSP>` is U+00A0, `<VT>` is
//! U+000B, `<FF>` is U+000C. VT and FF are pure ASCII, so this is not a
//! Unicode corner case:
//!
//! | input | `visudo` |
//! |---|---|
//! | `"a"<NBSP> = NOPASSWD: ALL` | rc 0 |
//! | `"a"<VT> = NOPASSWD: ALL` | rc 0 |
//! | `alice <NBSP> = NOPASSWD: ALL` | rc 0 |
//! | `alice <VT> = NOPASSWD: ALL` | rc 0 |
//! | `<NBSP>!h1 = NOPASSWD: ALL` | rc 0 |
//! | `a,<NBSP>!h1 = NOPASSWD: ALL` | rc 0 |
//! | `a, !h1 = NOPASSWD: ALL` | **rc 1** |
//! | `al<NBSP>ice h1 = NOPASSWD: ALL` | rc 0 |
//! | `a!<VT>`, `a!<FF>`, `a!<NBSP>`, `ALL !<NBSP>`, `<NBSP>! h1` | rc 0 |
//! | `a<VT>!h1`, `"a" h1`, `a !h1` | rc 0 (already correct) |
//! | `a! = NOPASSWD: ALL` | **rc 1** |
//!
//! The `a,<NBSP>!h1` / `a, !h1` pair is the sharpest in the set: ONE byte
//! separates a file sudo loads from one it refuses, and `RuleSteward` answered
//! `Malformed` to both. Its `Malformed` on the ASCII spelling is CORRECT.

use std::path::Path;

use rulesteward_sudoers::{SudoersLintContext, lint, parse};

fn count_code(src: &str, code: &str) -> usize {
    let files = vec![parse(src, Path::new("/etc/sudoers"))];
    lint(&files, &SudoersLintContext {})
        .iter()
        .filter(|d| d.code == code)
        .count()
}

/// Assert a `visudo`-ACCEPTED line reports its grant.
///
/// `sudo-F01 == 0` alone is satisfied by a file that parsed to nothing at all,
/// so the `sudo-W01 == 1` witness is what makes each row mean anything.
fn accepts_and_reports(src: &str, label: &str) {
    assert_eq!(
        count_code(src, "sudo-F01"),
        0,
        "{label}: visudo accepts this file (rc 0), so there is no F01 to report"
    );
    assert_eq!(
        count_code(src, "sudo-W01"),
        1,
        "{label}: the NOPASSWD-on-ALL grant must be reported; 0 here is the fail-open"
    );
}

/// Assert a `visudo`-REJECTED line still draws its structural FATAL and reports
/// no grant.
fn rejects_and_reports_no_grant(src: &str, label: &str) {
    assert_eq!(
        count_code(src, "sudo-F01"),
        1,
        "{label}: visudo rejects this file (rc 1); the F01 must keep firing"
    );
    assert_eq!(
        count_code(src, "sudo-W01"),
        0,
        "{label}: no grant may be reported off a line real sudo refuses to load"
    );
}

/// visudo rc 0. A non-blank whitespace character IS the host principal, so the
/// grant stands. These are #702's own reproducers, all wrong at the fork point.
#[test]
fn a_non_blank_whitespace_host_principal_still_reports_the_grant() {
    for (src, label) in [
        ("\"a\"\u{a0} = NOPASSWD: ALL\n", "quoted user, NBSP host"),
        ("\"a\"\u{b} = NOPASSWD: ALL\n", "quoted user, VT host"),
        ("alice \u{a0} = NOPASSWD: ALL\n", "spaced NBSP host"),
        ("alice \u{b} = NOPASSWD: ALL\n", "spaced VT host"),
    ] {
        accepts_and_reports(src, label);
    }
}

/// visudo rc 0. The USER half is the non-blank whitespace principal.
#[test]
fn a_non_blank_whitespace_user_principal_still_reports_the_grant() {
    for (src, label) in [
        ("\u{a0}!h1 = NOPASSWD: ALL\n", "NBSP user, negated host"),
        ("a,\u{a0}!h1 = NOPASSWD: ALL\n", "NBSP as a list member"),
        ("al\u{a0}ice h1 = NOPASSWD: ALL\n", "NBSP inside a name"),
    ] {
        accepts_and_reports(src, label);
    }
}

/// visudo rc **1**. The one-byte control for `a,<NBSP>!h1` above: with an ASCII
/// space the comma really does continue the user list, no host list remains,
/// and `sudo-F01` is correct. This row is what stops the repair from being
/// "treat every whitespace run as a separator".
#[test]
fn an_ascii_blank_after_a_comma_is_still_a_real_f01() {
    rejects_and_reports_no_grant("a, !h1 = NOPASSWD: ALL\n", "ASCII space after comma");
}

/// visudo rc 0. The #701 REGRESSION, and the reason this is a class fix: at
/// `360ca9c` the entry `trim` (wide) deleted the trailing non-blank whitespace,
/// `holds_a_principal` (narrow) then saw a half of nothing but `!`, and the
/// only candidate was rejected. `6abb10a` answered these correctly.
///
/// `ALL !<NBSP>` is the row that makes the severity concrete: `cvtsudoers`
/// reports the literal `ALL` user with `authenticate:false` on a command of
/// `ALL`, so this is passwordless run-anything for everyone.
#[test]
fn a_sigil_followed_by_a_non_blank_whitespace_principal_still_reports_the_grant() {
    for (src, label) in [
        ("a!\u{b} = NOPASSWD: ALL\n", "glued sigil then VT"),
        ("a!\u{c} = NOPASSWD: ALL\n", "glued sigil then FF"),
        ("a!\u{a0} = NOPASSWD: ALL\n", "glued sigil then NBSP"),
        (
            "ALL !\u{a0} = NOPASSWD: ALL\n",
            "ALL user, spaced sigil then NBSP",
        ),
        (
            "\u{a0}! h1 = NOPASSWD: ALL\n",
            "NBSP user, spaced sigil host",
        ),
    ] {
        accepts_and_reports(src, label);
    }
}

/// visudo rc **1**. The control for the block above, and the row #701 exists
/// for: with nothing after the sigil there is genuinely no host list. A repair
/// that simply drops the postcondition passes every row above and loses this.
#[test]
fn a_sigil_with_nothing_after_it_is_still_a_real_f01() {
    rejects_and_reports_no_grant("a! = NOPASSWD: ALL\n", "glued sigil, nothing after");
}

/// visudo rc 0, and correct on every sha of this lane. Asserted so the class
/// fix cannot be credited for rows that never moved, and so a repair that
/// breaks the ordinary spellings is caught here rather than in the corpus.
#[test]
fn the_ordinary_spellings_are_unaffected() {
    for (src, label) in [
        ("a\u{b}!h1 = NOPASSWD: ALL\n", "VT INSIDE the user name"),
        ("\"a\" h1 = NOPASSWD: ALL\n", "quoted user, ASCII space"),
        ("a !h1 = NOPASSWD: ALL\n", "ASCII space, negated host"),
        ("alice h1 = NOPASSWD: ALL\n", "the plain form"),
    ] {
        accepts_and_reports(src, label);
    }
}
