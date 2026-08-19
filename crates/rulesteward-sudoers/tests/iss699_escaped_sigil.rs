//! The ESCAPED negation sigil `\!` (#699), across the three sites that read a
//! bare `!` as a sigil without asking whether it is escaped.
//!
//! A backslash-escaped `\!` is a LITERAL `!` character inside one principal
//! name. It is not a negation sigil and it is not a token boundary. Three
//! predicates decided otherwise by comparing the char alone:
//!
//! | site | predicate | consequence |
//! |---|---|---|
//! | `split_user_list` opener guard | `prev != '!'` | the only candidate at a glued quote is suppressed |
//! | `split_user_list` `!` scan | `prev != '!'` | the only candidate in a sigil run is suppressed |
//! | `runas.rs::first_invalid_char` | `trim_start_matches('!')` + a bare denylist scan | a legal runas principal draws a FALSE `sudo-F02` |
//!
//! The first two are FAIL-OPENS, and that is the whole severity argument: a
//! suppressed candidate makes `split_user_list` fall through to `(lhs, "")`,
//! the line becomes `LineKind::Malformed`, and per #668 the token-lint
//! dispatcher skips it entirely - so a passwordless-ALL grant on a file
//! `visudo` accepts is never evaluated and nothing says so.
//!
//! NOT a shipped defect: `prev != '!'` does not exist at `a700c38` and appears
//! at `c153bc5`, the #670/#671/#672 commit on this same branch. That commit
//! closed three UNESCAPED-sigil fail-opens and opened this ESCAPED one.
//!
//! GROUNDING. Every row below was re-derived on THIS host on 2026-08-19 against
//! sudo 1.9.17p2 in `rs-oracle9`, fed on stdin with `--network=none`, not
//! copied from the issue:
//!
//! | input | `visudo -c -f -` | `cvtsudoers -f json` |
//! |---|---|---|
//! | `alice\!"h1" = NOPASSWD: ALL` | rc 0 | users `["alice!"]`, hosts `["h1"]`, `authenticate:false` |
//! | `a\!!h1 = NOPASSWD: ALL` | rc 0 | users `["a!"]`, host `h1` NEGATED |
//! | `alice ALL = (\!root) /bin/ls` | rc 0 | runasusers `[{"username":"!root"}]`, NOT negated |
//! | `alice\!h1 = NOPASSWD: ALL` | **rc 1** | (control) |
//! | `alice\\!"h1" = NOPASSWD: ALL` | rc 0 | user `alice\`, host `h1` NEGATED |
//! | `a\\!!h1 = NOPASSWD: ALL` | rc 0 | user `a\`, host `h1` (double negation collapses) |
//! | `alice ALL = (\\!root) /bin/ls` | **rc 1** | (control) |
//! | `alice,!bob ALL = ALL` | rc 0 | users `alice` + `bob` NEGATED |
//!
//! Read the accepted rows for their SHAPE, not just their rc: the escape is
//! CONSUMED and the `!` survives inside the name (`alice!`, `a!`, `!root`). An
//! escaped sigil is a character, not a modifier.
//!
//! THE PARITY ROWS DO NOT ALL POINT THE SAME WAY, and that is what makes them
//! worth having. The separator rule is a parity rule, so an EVEN backslash run
//! leaves the `!` unescaped and the sigil reading becomes correct again - but
//! `alice\\!"h1"` is rc 0 while `(\\!root)` is rc **1**, because in runas
//! position the even run leaves a literal `\` and the `!` is then MID-token,
//! exactly the `(ro!ot)` reject. Same bytes, opposite verdicts, decided by
//! grammar position. `an_even_backslash_run_leaves_the_runas_sigil_unescaped`
//! is therefore the test that stops the lazy repair: any fix that treats every
//! `!` following a backslash as literal turns that rc-1 file into a silent
//! pass.
//!
//! The UNESCAPED-sigil direction is pinned mainly in `iss670_negation_sigil.rs`,
//! which this fix must leave untouched. It is not absent here, though, and an
//! earlier version of this line wrongly said it was: the three
//! `an_even_backslash_run_*` rows assert unescaped-sigil behaviour by
//! construction (an even run leaves a REAL sigil), and the #701 block at the end
//! of this file is entirely unescaped.

use std::path::Path;

use rulesteward_sudoers::ast::LineKind;
use rulesteward_sudoers::{SudoersLintContext, lint, parse};

fn count_code(src: &str, code: &str) -> usize {
    let files = vec![parse(src, Path::new("/etc/sudoers"))];
    lint(&files, &SudoersLintContext {})
        .iter()
        .filter(|d| d.code == code)
        .count()
}

/// `(users, hosts)` of the single user-spec, as the parser recorded them.
///
/// The lint counts below are mostly ABSENCE assertions (a false FATAL must stop
/// firing), and absence alone is satisfied by a line that parsed to nothing at
/// all. Pinning the principal lists is what makes these rows witness that the
/// line was parsed, and parsed where `cvtsudoers` says the boundary is.
///
/// Tokens are compared RAW. This parser does not unescape or dequote anywhere,
/// so `alice\!` here is `alice!` in `cvtsudoers` (#696 escape retention) and
/// `"h1"` here is `h1` there (#667 quote retention). Both are known, filed
/// projection divergences, not defects this file introduces.
fn principals(src: &str) -> (Vec<String>, Vec<String>) {
    let file = parse(src, Path::new("/etc/sudoers"));
    for line in file.lines {
        if let LineKind::UserSpec(spec) = line.kind {
            let hosts = spec
                .host_groups
                .first()
                .map(|g| g.hosts.clone())
                .unwrap_or_default();
            return (spec.users, hosts);
        }
    }
    (Vec::new(), Vec::new())
}

// ------------------------------------------- the opener guard (parser.rs)

/// visudo rc 0. The escaped `!` is a literal char in the user name, so the
/// boundary is the GLUED QUOTE that follows it. Before the fix the opener guard
/// saw `prev == '!'`, suppressed its own candidate, and since no whitespace and
/// no other quote exists on this line there was no candidate left at all: the
/// line folded to `Malformed` and the passwordless-ALL grant vanished.
#[test]
fn an_escaped_sigil_before_a_glued_quote_is_a_principal_boundary() {
    let src = r#"alice\!"h1" = NOPASSWD: ALL
"#;
    assert_eq!(count_code(src, "sudo-F01"), 0, "visudo accepts this file");
    assert_eq!(
        count_code(src, "sudo-W01"),
        1,
        "the NOPASSWD-on-ALL grant must be reported; 0 here is the #699 fail-open"
    );
    assert_eq!(
        principals(src),
        (vec![r"alice\!".to_string()], vec![r#""h1""#.to_string()]),
        "cvtsudoers: ONE user `alice!` and host `h1`"
    );
}

/// visudo rc 0, and the PARITY counterpart of the row above: an EVEN backslash
/// run leaves the `!` unescaped, so it IS a sigil, the boundary is the `!`
/// rather than the quote, and the host is negated. Correct before this fix and
/// required to stay correct after it - this is what the added disjunct must not
/// swallow.
#[test]
fn an_even_backslash_run_before_a_glued_quote_keeps_the_sigil_boundary() {
    let src = r#"alice\\!"h1" = NOPASSWD: ALL
"#;
    assert_eq!(count_code(src, "sudo-F01"), 0, "visudo accepts this file");
    assert_eq!(count_code(src, "sudo-W01"), 1);
    assert_eq!(
        principals(src),
        (vec![r"alice\\".to_string()], vec![r#"!"h1""#.to_string()]),
        "cvtsudoers: user `alice\\`, host `h1` NEGATED - the boundary is the `!`"
    );
}

// ---------------------------------------------- the `!` scan (parser.rs)

/// visudo rc 0. The FIRST `!` is escaped and literal; the SECOND is the sigil
/// and the boundary. Before the fix the second was suppressed because its
/// predecessor was a `!`, and the `!` scan is the only candidate producer on
/// this line - no whitespace, no quotes - so the grant was dropped.
#[test]
fn an_escaped_sigil_run_still_yields_a_negated_host() {
    let src = r"a\!!h1 = NOPASSWD: ALL
";
    assert_eq!(count_code(src, "sudo-F01"), 0, "visudo accepts this file");
    assert_eq!(
        count_code(src, "sudo-W01"),
        1,
        "the NOPASSWD-on-ALL grant must be reported; 0 here is the #699 fail-open"
    );
    assert_eq!(
        principals(src),
        (vec![r"a\!".to_string()], vec!["!h1".to_string()]),
        "cvtsudoers: user `a!`, host `h1` NEGATED"
    );
}

/// visudo rc 0, the parity counterpart: an EVEN run leaves BOTH sigils
/// unescaped, so the boundary is the FIRST of them and the run stays with the
/// host token (`cvtsudoers` collapses the double negation to a plain `h1`).
/// Correct before this fix and required to stay correct after it.
#[test]
fn an_even_backslash_run_before_a_sigil_run_keeps_one_boundary() {
    let src = r"a\\!!h1 = NOPASSWD: ALL
";
    assert_eq!(count_code(src, "sudo-F01"), 0, "visudo accepts this file");
    assert_eq!(count_code(src, "sudo-W01"), 1);
    assert_eq!(
        principals(src),
        (vec![r"a\\".to_string()], vec!["!!h1".to_string()]),
        "the boundary is the FIRST sigil; the run stays with the host token"
    );
}

/// visudo rc **1**. The one-byte control for both parser sites: an escaped
/// sigil with NO following boundary really is a file with no host list, and
/// `sudo-F01` is correct. This is the assertion that keeps the fix from being
/// "admit a candidate whenever a backslash appears".
#[test]
fn an_escaped_sigil_without_a_following_boundary_is_still_a_real_f01() {
    let src = r"alice\!h1 = NOPASSWD: ALL
";
    assert_eq!(
        count_code(src, "sudo-F01"),
        1,
        "visudo rejects this file (rc 1); the F01 must keep firing"
    );
    assert_eq!(
        count_code(src, "sudo-W01"),
        0,
        "and no grant may be reported off a line real sudo refuses to load"
    );
}

// ----------------------------------------------------- runas (runas.rs)

/// visudo rc 0, runasuser `!root` as a LITERAL name with no `negated` flag.
/// Before the fix `trim_start_matches('!')` stripped nothing (the token starts
/// with `\`), the denylist scan then found the `!`, and a legal file drew a
/// FALSE `sudo-F02`.
#[test]
fn an_escaped_sigil_in_a_runas_principal_is_not_an_invalid_char() {
    let src = r"alice ALL = (\!root) /bin/ls
";
    assert_eq!(
        count_code(src, "sudo-F02"),
        0,
        "an escaped `!` is a literal char in the name; 1 here is the #699 false FATAL"
    );
    assert_eq!(count_code(src, "sudo-F01"), 0, "visudo accepts this file");
}

/// visudo rc **1**, and the sharpest test in this file. An EVEN backslash run
/// leaves a literal `\` followed by an UNESCAPED `!`, which is mid-token and
/// therefore genuinely invalid - the same reject as `(ro!ot)`.
///
/// A repair that asked `ends_with('\\')` instead of the parity predicate, or
/// that widened `trim_start_matches` to swallow a preceding backslash, passes
/// every other test in this file and silently loses this true positive. It is
/// asserted here beside its reproducer rather than in some other file for that
/// reason. The plain mid-token case is pinned separately by
/// `mid_token_bang_is_still_invalid` in `iss670_negation_sigil.rs`.
#[test]
fn an_even_backslash_run_leaves_the_runas_sigil_unescaped() {
    let src = r"alice ALL = (\\!root) /bin/ls
";
    assert_eq!(
        count_code(src, "sudo-F02"),
        1,
        "visudo rejects this file (rc 1): the `!` is mid-token after a literal backslash"
    );
}

// ------------------------------------- the conjunct #675 left unpinned

/// visudo rc 0, users `alice` + `bob` NEGATED.
///
/// This row exists because of a measurement, not a suspicion. #675's `!`-scan
/// comment claimed its `prev != ','` conjunct was "NOT redundant against the
/// continuation filter"; deleting that conjunct outright leaves the whole suite
/// green, so nothing pinned it and the claim was false. The candidate it
/// suppresses here is one the continuation filter rejects anyway (`before` ends
/// in an unescaped comma), which is exactly why deleting it changes no answer.
///
/// The comment has been corrected to say REDUNDANT. This test pins the ANSWER
/// rather than the conjunct, so the line stays correct however the producer is
/// later simplified.
#[test]
fn an_unescaped_sigil_after_a_comma_continues_the_user_list() {
    let src = "alice,!bob ALL = ALL\n";
    assert_eq!(count_code(src, "sudo-F01"), 0, "visudo accepts this file");
    assert_eq!(count_code(src, "sudo-F02"), 0);
    let (users, hosts) = principals(src);
    assert_eq!(
        users,
        vec!["alice".to_string(), "!bob".to_string()],
        "cvtsudoers: TWO users, the second negated - the comma continues the list"
    );
    assert_eq!(hosts, vec!["ALL".to_string()]);
}

// -------------------------------------- #701: a half of nothing but sigils
//
// Found by the impl-AWARE adversarial review of THIS file's own fix, and by the
// suppression lens in the same round. `split_user_list` picks a boundary and
// never asks whether either half IS a principal list, so a half of nothing but
// `!` becomes a `Host_List`, the line parses as a well-formed `UserSpec`, and a
// passwordless-ALL grant is reported off a file `visudo` REFUSES TO LOAD.
//
// That is the exact contract
// `an_escaped_sigil_without_a_following_boundary_is_still_a_real_f01` above
// states, applied to a shape no test in this crate covered: every `!`-bearing
// test here and in `iss670_negation_sigil.rs` puts a principal AFTER the sigil.
//
// TWO of these are lane regressions rather than inherited defects, confirmed
// two-sided against binaries built at four revisions:
//
//   `alice!`  correct at `a700c38`, wrong from `c153bc5` (#670/#671/#672)
//   `a\!!`    correct through `11f6ea0`, wrong from `6abb10a` (#699)
//
// `cargo mutants` cannot see either: both are a MISSING conjunct and there is
// no insert-a-conjunct operator, which is why the scoped gate returned rc 0
// with 25 mutants and 0 missed over exactly this code.
//
// GROUNDING, rs-oracle9 (sudo 1.9.17p2), stdin, `--network=none`, 2026-08-19.
// The discriminator is whether a principal FOLLOWS the sigil - not escape
// parity, not sigil count:
//
// | input | `visudo` |
// |---|---|
// | `a\!! = NOPASSWD: ALL` | rc 1 |
// | `alice! = NOPASSWD: ALL` | rc 1 |
// | `alice!! = NOPASSWD: ALL` | rc 1 |
// | `alice ! = NOPASSWD: ALL` | rc 1 |
// | `! h1 = NOPASSWD: ALL` | rc 1 (the USER half) |
// | `alice!h1`, `alice!!h1`, `a\!!h1`, `!!alice ALL`, `alice,!bob h1` | rc 0 |

/// visudo rc 1. Its one-byte-longer twin `a\!!h1` is rc 0 and asserted above,
/// which is what makes this a discriminating row rather than a restatement.
#[test]
fn an_escaped_sigil_run_with_no_principal_after_it_is_still_a_real_f01() {
    let src = r"a\!! = NOPASSWD: ALL
";
    assert_eq!(
        count_code(src, "sudo-F01"),
        1,
        "visudo rejects this file (rc 1)"
    );
    assert_eq!(
        count_code(src, "sudo-W01"),
        0,
        "no grant may be reported off a line real sudo refuses to load"
    );
}

/// visudo rc 1. The `c153bc5` half of the regression: a glued sigil with
/// nothing after it. `alice!h1` is rc 0 and pinned in `iss670_negation_sigil.rs`.
#[test]
fn a_glued_sigil_with_no_principal_after_it_is_still_a_real_f01() {
    let src = "alice! = NOPASSWD: ALL\n";
    assert_eq!(
        count_code(src, "sudo-F01"),
        1,
        "visudo rejects this file (rc 1)"
    );
    assert_eq!(count_code(src, "sudo-W01"), 0);
}

/// visudo rc 1. The sigil RUN spelling, so a fix cannot be a `strip_prefix`
/// that leaves a second sigil looking like a principal.
#[test]
fn a_glued_sigil_run_with_no_principal_after_it_is_still_a_real_f01() {
    let src = "alice!! = NOPASSWD: ALL\n";
    assert_eq!(
        count_code(src, "sudo-F01"),
        1,
        "visudo rejects this file (rc 1)"
    );
    assert_eq!(count_code(src, "sudo-W01"), 0);
}

/// visudo rc 1. The WHITESPACE-separated spelling, which reaches the same
/// fallthrough through a different producer (a run candidate, not the `!`
/// scan). Without this row a fix scoped to the `!` scan looks complete.
#[test]
fn a_spaced_sigil_with_no_principal_after_it_is_still_a_real_f01() {
    let src = "alice ! = NOPASSWD: ALL\n";
    assert_eq!(
        count_code(src, "sudo-F01"),
        1,
        "visudo rejects this file (rc 1)"
    );
    assert_eq!(count_code(src, "sudo-W01"), 0);
}

/// visudo rc 1, and the mirror direction: the degenerate half is the USER list,
/// not the host list. A postcondition that checks only the host half passes
/// every row above and still fails here.
#[test]
fn a_lone_sigil_user_list_is_still_a_real_f01() {
    let src = "! h1 = NOPASSWD: ALL\n";
    assert_eq!(
        count_code(src, "sudo-F01"),
        1,
        "visudo rejects this file (rc 1)"
    );
    assert_eq!(count_code(src, "sudo-W01"), 0);
}

/// visudo rc 0. The control that stops the lazy repair "reject any half
/// containing a sigil": a sigil RUN followed by a real principal is legal, and
/// `cvtsudoers` collapses the double negation to a plain `alice`.
#[test]
fn a_user_list_of_sigils_plus_a_principal_still_reports_the_grant() {
    let src = "!!alice ALL = NOPASSWD: ALL\n";
    assert_eq!(count_code(src, "sudo-F01"), 0, "visudo accepts this file");
    assert_eq!(
        count_code(src, "sudo-W01"),
        1,
        "the grant must still be reported; 0 here means the postcondition is too wide"
    );
}

/// visudo rc 0. The list control: a negated MEMBER inside a comma list leaves
/// the half holding a principal, so the boundary stands.
#[test]
fn a_negated_member_inside_a_list_still_reports_the_grant() {
    let src = "alice,!bob h1 = NOPASSWD: ALL\n";
    assert_eq!(count_code(src, "sudo-F01"), 0, "visudo accepts this file");
    assert_eq!(count_code(src, "sudo-W01"), 1);
    assert_eq!(
        principals(src),
        (
            vec!["alice".to_string(), "!bob".to_string()],
            vec!["h1".to_string()]
        ),
        "cvtsudoers: two users, the second negated, host h1"
    );
}
