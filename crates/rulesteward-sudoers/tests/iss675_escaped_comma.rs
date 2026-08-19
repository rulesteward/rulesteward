//! The escape-blind comma in `split_user_list`, all THREE faces (#675).
//!
//! A backslash-escaped `\,` is a LITERAL comma inside ONE principal; it does not
//! continue the `User_List`. THREE predicates in `split_user_list` re-decided
//! that with bare comparisons and got it wrong, so a line real sudo ACCEPTS
//! folded to `Malformed` and, per #668, became invisible to every W/E pass. All
//! three faces are therefore fail-opens: the grant is never evaluated and
//! nothing says so. (This paragraph said "Two conjuncts" and "Both faces" while
//! the table below already listed three; corrected by #699's review.)
//!
//! | call site | before |
//! |---|---|
//! | the continuation filter (`!before.ends_with(',')`) | **Face A** |
//! | the opener guard's `,` conjunct (`prev != ','`) | **Face B** |
//! | the `!` boundary scan's `,` conjunct (`prev != ','`) | **Face C** |
//!
//! No face repairs a row on its own, which is why they are one issue and one
//! commit. Face A is required by ALL THREE: B and C only PRODUCE a candidate,
//! and A is what admits it. Measured by reverting A alone, which turns four of
//! the rows below RED including Face C's.
//!
//! **Face C is absent from #675's sibling sweep**, and that is not an oversight
//! in the issue: the sweep predates `c153bc5`, the commit that introduced the
//! `!` boundary scan. The issue's claim that the two comma conjuncts were "the
//! last of that class in this function" was true when written and false by the
//! time it was fixed. Face C was found by the post-GREEN adversarial review of
//! faces A and B, and is reported back to #675 rather than filed separately.
//!
//! Face C is NOT special in the way this paragraph used to claim. On `a\,!h1`
//! the `!` scan is indeed the only candidate producer, so an escape-BLIND
//! conjunct there is not a worse split but NO split: `Malformed`, and the grant
//! is gone. But that is an argument for the ESCAPE-AWARENESS, not for the `,`
//! member, and this paragraph said "Face C is the one face redundant against
//! nothing" while the opener's twin was "redundant AS A FILTER".
//!
//! Measured 2026-08-19, which is what #699's review did and this text did not:
//! deleting the `,` member leaves the whole suite green at BOTH sites, because
//! the continuation filter re-answers the comma axis downstream. The two sites
//! are symmetric. See `parser.rs`'s opener block for the full equivalence
//! record and the correction 220 lines below for the same repair at the row it
//! describes.
//!
//! GROUNDING. Every row below was re-derived on THIS host on 2026-08-19 against
//! sudo 1.9.17p2 in `rs-oracle9`, fed on stdin with `--network=none`, rather than
//! copied from the issue:
//!
//! | input | `visudo -c -f -` | `cvtsudoers -f json` |
//! |---|---|---|
//! | `alice\, h1 = NOPASSWD: /bin/ls` | rc 0 | `User_List ["alice,"]`, `Host_List ["h1"]` |
//! | `a\,"b" = NOPASSWD: ALL` | rc 0 | `User_List ["a,"]`, `Host_List ["b"]` |
//! | `a\,!h1 = NOPASSWD: ALL` | rc 0 | `User_List ["a,"]`, `Host_List ["h1"]` NEGATED |
//! | `a\,b\, c = NOPASSWD: ALL` | rc 0 | `User_List ["a,b,"]`, `Host_List ["c"]` |
//! | `alice, h1 = NOPASSWD: /bin/ls` | **rc 1** | (control) |
//! | `a,"b" = NOPASSWD: ALL` | **rc 1** | (control) |
//! | `a,!h1 = NOPASSWD: ALL` | **rc 1** | (control) |
//! | `a\\, b = NOPASSWD: ALL` | **rc 1** | (PARITY control) |
//! | `a\\,"b" = NOPASSWD: ALL` | **rc 1** | (PARITY control) |
//! | `a\\,!h1 = NOPASSWD: ALL` | **rc 1** | (PARITY control) |
//!
//! The three rejects all fail for the RIGHT reason, which is what makes them
//! controls rather than coincidences: in EVERY case visudo's caret lands on the
//! `=`, so the `User_List` continued across the comma and no host list remained.
//! Not one is rejected for carrying an invalid username token, which is the way
//! a reject-side control on this surface usually goes wrong.
//!
//! The three doubled-backslash rows are the sharpest here and NONE is among
//! #675's suggested pins. The SEPARATOR escape rule counts a backslash RUN mod
//! 2, so an EVEN run leaves the comma UNESCAPED and the list really does
//! continue. They are what separate `separator_escaped` from a naive
//! `ends_with('\\')` check, which would call that comma escaped and convert a
//! correct `sudo-F01` into a fail-open.
//!
//! Measured 2026-08-19 with `--no-fail-fast`: replacing `separator_escaped`'s
//! parity count with `ends_with` turns all three of them RED, and they are the
//! only rows IN THIS FILE that catch it. It also turns #699's three parity rows
//! and BOTH corpus layers that fire - `l1_f01_matches_visudo_verdict_per_target`
//! and `l3_structure_projection_matches_cvtsudoers` - RED. (L2 stays green; the
//! corpus has three layers, not two.) The L3 half was omitted when this
//! paragraph was written, in the same breath as its own rule to name the rows.
//!
//! An earlier version of this paragraph said "exactly those three rows RED and
//! nothing else". That was wrong twice over: it was measured under a plain
//! `cargo test`, which stops after the first failing test BINARY and cannot see
//! the corpus layers at all, and an exclusivity claim about a whole suite is
//! invalidated by any test anyone adds later. Name the rows, not a count.
//!
//! # What these tests deliberately do NOT assert
//!
//! The recovered `User_List` text `alice\,` is then split by `comma_split`, which
//! is itself a bare `s.split(',')`, so the member arrives spelled `alice\` (comma
//! lost, backslash kept) where `cvtsudoers` says `alice,`. That is #645 Face B,
//! which #675's own sibling sweep marks `[ALREADY-ROUTED]`, and it is inert here:
//! no lint pass reads that token in a way that fires. So the rows below assert
//! the member COUNT, which is what #675 is about and which stays true after #645
//! lands, and leave the member SPELLING to #645 rather than freezing a value that
//! is known to be wrong.

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
/// line was parsed, and parsed into the arity `cvtsudoers` reports.
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

// ------------------------------------------------------- Face A: the filter

/// `visudo` rc 0. The `\,` is a literal comma inside the single user `alice,`,
/// so the whitespace run really is the `User_List`/`Host_List` boundary. Before
/// the fix the continuation filter saw `before` ending in `,`, rejected the only
/// correct candidate, and the line fell through to `(lhs, "")` -> `Malformed`,
/// taking its `NOPASSWD` grant with it.
#[test]
fn an_escaped_comma_does_not_continue_the_user_list() {
    let src = "alice\\, h1 = NOPASSWD: /bin/ls\n";
    assert_eq!(count_code(src, "sudo-F01"), 0, "visudo accepts this line");
    // The positive witness. A bare `F01 == 0` is satisfied by an empty file;
    // this is the grant that was being dropped.
    assert_eq!(
        count_code(src, "sudo-W05"),
        1,
        "the NOPASSWD grant is reported"
    );
    let (users, hosts) = principals(src);
    assert_eq!(users.len(), 1, "one user, not two: got {users:?}");
    assert_eq!(hosts, ["h1"], "the host list is the text after the run");
}

/// The one-byte control, and the reason this fix must DISCRIMINATE rather than
/// stop looking at commas. Drop the backslash and the comma really does continue
/// the `User_List`, leaving no host list: `visudo` rc 1, so the `sudo-F01` here
/// is CORRECT and must survive the fix.
#[test]
fn an_unescaped_comma_leaves_no_host_list_and_that_is_a_real_f01() {
    let src = "alice, h1 = NOPASSWD: /bin/ls\n";
    assert_eq!(count_code(src, "sudo-F01"), 1, "visudo rejects this line");
}

/// The PARITY control. `a\\,` is an EVEN backslash run, so under the separator
/// escape rule the two backslashes are one literal byte and the comma is NOT
/// escaped: the list continues, no host list remains, `visudo` rc 1.
///
/// This is the row that pins `separator_escaped`'s run-parity count against a
/// naive "is the previous byte a backslash" check. That naive check calls this
/// comma escaped, admits a boundary, and turns a correct FATAL into silence.
#[test]
fn a_doubled_backslash_leaves_the_comma_unescaped() {
    let src = "a\\\\, b = NOPASSWD: ALL\n";
    assert_eq!(
        count_code(src, "sudo-F01"),
        1,
        "an even backslash run does not escape the comma"
    );
}

/// A RUN of escaped commas whose LAST one is trailing, so the filter sees
/// `before == "a\,b\,"`. `visudo` rc 0 with `User_List ["a,b,"]` and
/// `Host_List ["c"]` (re-derived on rs-oracle9, 2026-08-19). Guards against a
/// fix that handles a single escaped comma but re-decides on a run of them.
///
/// This row was first drafted as `a\,b\,c d`, which does NOT exercise this face
/// at all: that `before` is `a\,b\,c`, which does not end in a comma, so the
/// filter already admits the boundary today and only the MEMBER split is wrong.
/// It was measuring #645 Face B and would have stayed RED after this fix. Worth
/// recording, because a test failing for a neighbouring bug is easy to mistake
/// for a fix that did not work.
///
/// The member COUNT is deliberately not asserted here even though it is asserted
/// on the single-comma rows. `comma_split` turns `a\,b\,` into TWO members
/// today (`["a\\", "b\\"]`, the trailing empty piece filtered out) and will turn
/// it into one when #645 lands. `Host_List` is the axis this face actually
/// decides, and it is pinned.
#[test]
fn a_trailing_escaped_comma_after_a_run_still_ends_the_user_list() {
    let src = "a\\,b\\, c = NOPASSWD: ALL\n";
    assert_eq!(count_code(src, "sudo-F01"), 0, "visudo accepts this line");
    assert_eq!(
        count_code(src, "sudo-W01"),
        1,
        "the passwordless-ALL grant is reported"
    );
    let (_users, hosts) = principals(src);
    assert_eq!(
        hosts,
        ["c"],
        "the boundary is after the trailing escaped comma"
    );
}

// -------------------------------------------------- Face B: the opener guard

/// `visudo` rc 0. The quote is GLUED to the bare word `a\,` with no whitespace,
/// so the only possible boundary is the opener candidate the guard suppressed:
/// its `prev` is the comma at index 2, which is escaped and therefore not a list
/// separator. With no candidate at all the line went `Malformed` and its
/// passwordless-ALL grant was never reported.
#[test]
fn an_escaped_comma_before_a_glued_quote_is_not_a_list_separator() {
    let src = "a\\,\"b\" = NOPASSWD: ALL\n";
    assert_eq!(count_code(src, "sudo-F01"), 0, "visudo accepts this line");
    assert_eq!(
        count_code(src, "sudo-W01"),
        1,
        "the passwordless-ALL grant is reported"
    );
    let (users, _hosts) = principals(src);
    assert_eq!(users.len(), 1, "one user, not two: got {users:?}");
}

/// The control for the guard's ORIGINAL conjunct, which the fix must keep. An
/// UNESCAPED comma before a glued quote does continue the list, so there is no
/// boundary there and no host list remains: `visudo` rc 1.
#[test]
fn an_unescaped_comma_before_a_glued_quote_is_still_a_list_separator() {
    let src = "a,\"b\" = NOPASSWD: ALL\n";
    assert_eq!(count_code(src, "sudo-F01"), 1, "visudo rejects this line");
}

// --------------------------------------- Face C: the `!` boundary scan (#675)

/// The THIRD escape-blind `,` in this function, and the one #675's own sibling
/// sweep does not list: that sweep predates `c153bc5`, which is the commit that
/// introduced the `!` boundary scan. Found by the post-GREEN adversarial review
/// of faces A and B.
///
/// `visudo` rc 0, `User_List ["a,"]`, `Host_List ["h1"]` NEGATED (rs-oracle9,
/// sudo 1.9.17p2, 2026-08-19). The `!` scan is the ONLY candidate producer for
/// this line - no whitespace, no quotes - so a suppressed candidate is not a
/// worse split, it is no split at all: `Malformed`, and the passwordless-ALL
/// grant is never reported.
///
/// What makes this row necessary is the ESCAPE-AWARENESS, not the `,` member
/// itself. Measured 2026-08-19: making the conjunct escape-blind turns this test
/// RED, but deleting the `,` member outright leaves the whole suite green,
/// because the continuation filter re-answers the comma axis downstream. This
/// comment claimed the site was "NOT redundant against the continuation filter
/// the way the opener guard's twin is"; that was reasoned rather than run, and
/// running it refutes it. See the guard's own block in `parser.rs` for the full
/// equivalence record.
#[test]
fn an_escaped_comma_before_a_negation_sigil_is_not_a_list_separator() {
    let src = "a\\,!h1 = NOPASSWD: ALL\n";
    assert_eq!(count_code(src, "sudo-F01"), 0, "visudo accepts this line");
    assert_eq!(
        count_code(src, "sudo-W01"),
        1,
        "the passwordless-ALL grant is reported"
    );
    let (users, hosts) = principals(src);
    assert_eq!(users.len(), 1, "one user, not two: got {users:?}");
    assert_eq!(hosts, ["!h1"], "the negated host list");
}

/// The control for Face C's original conjunct, which the fix must keep. An
/// UNESCAPED `!` after a comma continues the `User_List`, so there is no boundary
/// and no host list remains: `visudo` rc 1 (caret on the `=`).
#[test]
fn an_unescaped_comma_before_a_negation_sigil_is_still_a_list_separator() {
    let src = "a,!h1 = NOPASSWD: ALL\n";
    assert_eq!(count_code(src, "sudo-F01"), 1, "visudo rejects this line");
}

// ------------------------------------------------- parity, at all three sites

/// The parity twin of the opener-guard face. `a\\,` is an EVEN backslash run, so
/// the comma is UNESCAPED, the list continues, no host list remains and `visudo`
/// gives rc 1 (caret on the `=`, column 9).
///
/// Together with the two rows beside it this is what kills the naive-`ends_with`
/// mutant at every site that consults `separator_escaped`. The single-site rows
/// above cannot: each of them is satisfied by a fix that gets parity wrong in
/// the fail-open direction.
#[test]
fn a_doubled_backslash_before_a_glued_quote_leaves_the_comma_unescaped() {
    let src = "a\\\\,\"b\" = NOPASSWD: ALL\n";
    assert_eq!(
        count_code(src, "sudo-F01"),
        1,
        "an even backslash run does not escape the comma"
    );
}

/// The parity twin of the `!`-scan face. `visudo` rc 1, caret on the `=`.
#[test]
fn a_doubled_backslash_before_a_negation_sigil_leaves_the_comma_unescaped() {
    let src = "a\\\\,!h1 = NOPASSWD: ALL\n";
    assert_eq!(
        count_code(src, "sudo-F01"),
        1,
        "an even backslash run does not escape the comma"
    );
}
