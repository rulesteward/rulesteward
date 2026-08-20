//! A half of separators is not a principal list either (#704).
//!
//! #701 gave `split_user_list` a postcondition: a boundary is only admissible
//! when BOTH halves hold something that could be a principal. The predicate
//! asked "is there one char that is neither `!` nor a blank", so a `,` or a `"`
//! satisfied it and a half of nothing but sigils and separators still counted.
//! `a!,` is `visudo` rc 1 and `RuleSteward` reported a passwordless-`ALL` grant
//! off it.
//!
//! THE RULE IS NOT "EXCLUDE MORE CHARACTERS", and the probe that established
//! that is the reason this file exists. `alice " " = NOPASSWD: ALL` is `visudo`
//! **rc 0**: a quoted blank is a legal host name, and so is `"!"`. Excluding the
//! quote character outright - which is what #704's own fix sketch proposed -
//! turns both into a false `sudo-F01`. What distinguishes them is not the
//! characters but whether a quoted span has a NON-EMPTY interior: `""` is rc 1,
//! `" "` is rc 0.
//!
//! So the predicate is "some character outside `{! , " blank}`, OR a quote pair
//! with a non-empty interior", and [`simple_quote_pairs`] already computes the
//! second half. One more concept modelled rather than one more character
//! excluded - which is the whole lesson of this lane's five adversarial rounds.
//!
//! GROUNDING, rs-oracle9 (sudo 1.9.17p2), stdin, `--network=none`, 2026-08-19:
//!
//! | input | `visudo` | why |
//! |---|---|---|
//! | `a!, = NOPASSWD: ALL` | rc 1 | the half `!,` is sigils and separators |
//! | `a!" = NOPASSWD: ALL` | rc 1 | unbalanced quote, no span at all |
//! | `a!"" = NOPASSWD: ALL` | rc 1 | a span with an EMPTY interior |
//! | `alice , = NOPASSWD: ALL` | rc 1 | the half is one separator |
//! | `alice " " = NOPASSWD: ALL` | **rc 0** | a quoted blank IS a host name |
//! | `alice "!" = NOPASSWD: ALL` | **rc 0** | so is a quoted sigil |
//! | `" " h1 = NOPASSWD: ALL` | **rc 0** | and on the USER side too |
//! | `alice "a" = NOPASSWD: ALL` | **rc 0** | the ordinary quoted principal |
//! | `a!h1 = NOPASSWD: ALL` | **rc 0** | the control: a real principal follows |
//!
//! `a!: = NOPASSWD: ALL` is rc 1 and ALREADY correct, so `:` is deliberately NOT
//! in the excluded set: the top-level `:` splits host-group segments upstream of
//! this predicate. #704's sketch listed it as an open question; the answer is no.

use std::path::Path;

use rulesteward_sudoers::{SudoersLintContext, lint, parse};

fn count_code(src: &str, code: &str) -> usize {
    let files = vec![parse(src, Path::new("/etc/sudoers"))];
    lint(&files, &SudoersLintContext {})
        .iter()
        .filter(|d| d.code == code)
        .count()
}

/// visudo rc **1**. A half of nothing but sigils and separators is not a
/// principal list, so there is no boundary and the line is a real `sudo-F01`.
///
/// Reporting a grant here is the worst outcome this tool has: a passwordless
/// `ALL` announced off a policy sudo will never load.
#[test]
fn a_half_of_sigils_and_separators_is_still_a_real_f01() {
    for src in [
        "a!, = NOPASSWD: ALL\n",
        "a!\" = NOPASSWD: ALL\n",
        "a!\"\" = NOPASSWD: ALL\n",
        "alice , = NOPASSWD: ALL\n",
    ] {
        assert_eq!(
            count_code(src, "sudo-F01"),
            1,
            "visudo rejects this file (rc 1): {src:?}"
        );
        assert_eq!(
            count_code(src, "sudo-W01"),
            0,
            "no grant may be reported off a line real sudo refuses to load: {src:?}"
        );
    }
}

/// visudo rc **0**, and the rows that stop the lazy repair. A quoted span with
/// any interior at all is a principal, whatever the interior contains - so
/// excluding `"` as a character is wrong, and excluding it only when the span
/// is empty is right.
///
/// Without these three rows, "add `"` to the excluded set" passes every test
/// above and ships a false `sudo-F01` on three shapes sudo accepts.
#[test]
fn a_quoted_span_with_any_interior_is_a_principal() {
    for src in [
        "alice \" \" = NOPASSWD: ALL\n",
        "alice \"!\" = NOPASSWD: ALL\n",
        "\" \" h1 = NOPASSWD: ALL\n",
        "alice \"a\" = NOPASSWD: ALL\n",
    ] {
        assert_eq!(
            count_code(src, "sudo-F01"),
            0,
            "visudo accepts this file (rc 0): {src:?}"
        );
        assert_eq!(
            count_code(src, "sudo-W01"),
            1,
            "the grant must be reported: {src:?}"
        );
    }
}

/// visudo rc **1**, already correct before #704 and required to stay so. The
/// top-level `:` splits host-group segments upstream of this predicate, so it
/// never reaches a half at all and must NOT join the excluded set. #704's fix
/// sketch listed the `:` axis as undecided; this is the answer.
#[test]
fn the_top_level_colon_is_not_a_separator_this_predicate_sees() {
    let src = "a!: = NOPASSWD: ALL\n";
    assert_eq!(count_code(src, "sudo-F01"), 1, "visudo rejects this file");
    assert_eq!(count_code(src, "sudo-W01"), 0);
}

/// visudo rc 0. The control: a real principal after the sigil, unaffected by
/// any of this.
#[test]
fn a_sigil_followed_by_a_real_principal_is_unaffected() {
    let src = "a!h1 = NOPASSWD: ALL\n";
    assert_eq!(count_code(src, "sudo-F01"), 0, "visudo accepts this file");
    assert_eq!(count_code(src, "sudo-W01"), 1);
}
