//! The negation sigil `!`, across the four call sites that model it (#670, #671,
//! #672).
//!
//! `sudoers(5)` lets a leading `!` negate a principal in a `User_List`,
//! `Host_List` or `Runas_List`. Four places in this crate have an opinion about
//! that sigil, and until this file they did not agree:
//!
//! | call site | before |
//! |---|---|
//! | `lints/tokens/command_specs.rs` | CORRECT |
//! | the subject-list walk | CORRECT |
//! | `split_user_list`'s candidate set | did not treat `!` as a token boundary (#670, #672) |
//! | `lints/tokens/runas.rs::first_invalid_char` | rejected the sigil outright (#671) |
//!
//! Three faces, all of them defects of the same unmodelled concept:
//!
//! * **#672** an UNQUOTED `!` glued to a principal (`alice!h1`) is a boundary
//!   the splitter never saw, so the line folded to `Malformed` and its grant
//!   was never linted.
//! * **#670** a NEGATED QUOTED principal (`!"svc acct"`) mangled the host list
//!   and went completely silent - no F01, no F02, no W06 on a full
//!   privilege-elevation grant.
//! * **#671** a legal negated RUNAS principal (`(ALL,!root)`) drew a FALSE
//!   `sudo-F02`, because the denylist scan saw the sigil as an invalid
//!   character.
//!
//! GROUNDING. Every row below was re-derived on THIS host on 2026-08-19 against
//! sudo 1.9.17p2, fed on stdin, not copied from the issues:
//!
//! | input | `visudo -c -f -` | `cvtsudoers -f json` |
//! |---|---|---|
//! | `alice!h1 = NOPASSWD: ALL` | rc 0 | user `alice`, host `h1` NEGATED, `authenticate:false`, command `ALL` |
//! | `alice !h1 = NOPASSWD: ALL` | rc 0 | (control) same shape |
//! | `ALL,!"svc acct" ALL = (ALL) ALL` | rc 0 | users `ALL` + `svc acct` NEGATED, host `ALL`, runas `ALL`, command `ALL` |
//! | `ALL,"svc acct" ALL = (ALL) ALL` | rc 0 | (control, `!` dropped) |
//! | `ALL,!svcacct ALL = (ALL) ALL` | rc 0 | (control, quotes dropped) |
//! | `alice ALL = (ALL,!root) /bin/ls` | rc 0 | runasusers `ALL` + `root` NEGATED |
//! | `alice ALL = (ro!ot) /bin/ls` | **rc 1** | (control) a MID-token `!` really is invalid |
//!
//! The last row is the load-bearing one. A `!` in the middle of a token is
//! genuinely rejected by sudo, so #671's fix must strip only a LEADING sigil.
//! Deleting the denylist entry outright would satisfy every other test in this
//! file and lose a real positive, which is why that control is asserted beside
//! its reproducer rather than in some other file.

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
/// line was parsed, and parsed the way `cvtsudoers` says.
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

// ---------------------------------------------------------------- #672

/// visudo rc 0. The glued `!` is a token boundary: `alice` is the user list and
/// `!h1` the negated host list. Before the fix the splitter found no boundary,
/// the line folded to `Malformed`, and the passwordless-ALL grant was never
/// linted.
#[test]
fn glued_unquoted_bang_is_a_principal_boundary() {
    let src = "alice!h1 = NOPASSWD: ALL\n";
    assert_eq!(count_code(src, "sudo-F01"), 0, "visudo accepts this file");
    assert_eq!(
        count_code(src, "sudo-W01"),
        1,
        "the NOPASSWD-on-ALL grant must be reported; 0 here is the #672 fail-open"
    );
    assert_eq!(
        principals(src),
        (vec!["alice".to_string()], vec!["!h1".to_string()]),
        "cvtsudoers: user `alice`, host `h1` negated"
    );
}

/// visudo rc 0. The one-byte control: a single space where the sigil is glued.
/// Correct on both shas, which isolates the defect to the GLUED spelling rather
/// than to negation generally.
#[test]
fn spaced_bang_control_reports_the_same_grant() {
    let src = "alice !h1 = NOPASSWD: ALL\n";
    assert_eq!(count_code(src, "sudo-F01"), 0, "visudo accepts this file");
    assert_eq!(count_code(src, "sudo-W01"), 1);
    assert_eq!(
        principals(src),
        (vec!["alice".to_string()], vec!["!h1".to_string()])
    );
}

// ---------------------------------------------------------------- #670

/// visudo rc 0. A negated QUOTED principal. Before the fix the opener rule did
/// not bind the leading `!` to the quoted principal that follows it, so the
/// user list became `["ALL", "!"]` and the host list swallowed the rest - and
/// the line went completely silent on a full ALL/ALL privilege elevation.
#[test]
fn negated_quoted_principal_still_reports_the_elevation() {
    let src = "ALL,!\"svc acct\" ALL = (ALL) ALL\n";
    assert_eq!(count_code(src, "sudo-F01"), 0, "visudo accepts this file");
    assert_eq!(
        count_code(src, "sudo-W06"),
        1,
        "ALL/ALL elevation must be reported; 0 here is the #670 silent fail-open"
    );
    let (users, hosts) = principals(src);
    assert_eq!(
        hosts,
        vec!["ALL".to_string()],
        "the host list is `ALL`; a mangled one is the #670 signature"
    );
    assert_eq!(users.len(), 2, "cvtsudoers: `ALL` and a negated `svc acct`");
}

/// visudo rc 0. Control: the same line without the sigil. Correct today.
#[test]
fn quoted_principal_without_the_sigil_control() {
    let src = "ALL,\"svc acct\" ALL = (ALL) ALL\n";
    assert_eq!(count_code(src, "sudo-W06"), 1);
}

/// visudo rc 0. Control: the same line with the sigil but no quotes. Correct
/// today. Together with the row above this isolates #670 to the COMBINATION,
/// so a fix cannot be credited to either half alone.
#[test]
fn negated_unquoted_principal_control() {
    let src = "ALL,!svcacct ALL = (ALL) ALL\n";
    assert_eq!(count_code(src, "sudo-W06"), 1);
}

// ---------------------------------------------------------------- #671

/// visudo rc 0. A LEADING sigil on a runas principal is legal sudoers. Before
/// the fix `first_invalid_char`'s denylist matched the `!` and reported a FALSE
/// `sudo-F02` on a file real sudo accepts.
#[test]
fn leading_bang_on_a_runas_principal_is_legal() {
    let src = "alice ALL = (ALL,!root) /bin/ls\n";
    assert_eq!(
        count_code(src, "sudo-F02"),
        0,
        "a leading `!` on a runas principal is legal; 1 here is the #671 false FATAL"
    );
    assert_eq!(count_code(src, "sudo-F01"), 0, "visudo accepts this file");
}

/// visudo rc **1**. The true positive that must survive the fix: a `!` in the
/// MIDDLE of a token really is invalid, and `sudo-F02` is correct here.
///
/// This is the assertion that stops the lazy repair. Removing `'!'` from
/// `is_denylist_char` satisfies every other test in this file and silently
/// loses this finding, so the two must be read together.
#[test]
fn mid_token_bang_is_still_invalid() {
    let src = "alice ALL = (ro!ot) /bin/ls\n";
    assert_eq!(
        count_code(src, "sudo-F02"),
        1,
        "visudo rejects this file (rc 1); the F02 must keep firing"
    );
}

// ------------------------------------------------- multi-sigil runs
//
// Added because a mutant SURVIVED. Replacing `runas.rs`'s
// `trim_start_matches('!')` with a single `strip_prefix('!')` - which is what
// #671's issue text actually proposes - left every test above green. The two
// rows below are what discriminate them.
//
// Grounded 2026-08-19, sudo 1.9.17p2, both rc 0. Note that sudo COLLAPSES the
// double negation rather than nesting it: `cvtsudoers` reports plain
// `{"username":"root"}` and `{"hostname":"h1"}` with no `negated` flag at all.
// verified: 2026-08-19

/// visudo rc 0. A RUN of leading sigils on a runas principal is legal.
/// Killed by `strip_prefix('!')`, which leaves `!root` in the token and draws
/// the same false `sudo-F02` #671 is about.
#[test]
fn a_run_of_leading_bangs_on_a_runas_principal_is_legal() {
    let src = "alice ALL = (!!root) /bin/ls\n";
    assert_eq!(
        count_code(src, "sudo-F02"),
        0,
        "a RUN of leading sigils is legal; 1 here means only ONE `!` was trimmed"
    );
    assert_eq!(count_code(src, "sudo-F01"), 0, "visudo accepts this file");
}

/// visudo rc 0. The principal-boundary counterpart: the boundary is at the
/// FIRST sigil of the run, and the whole run belongs to the host token.
#[test]
fn a_run_of_leading_bangs_still_binds_to_one_principal() {
    let src = "alice!!h1 = NOPASSWD: ALL\n";
    assert_eq!(count_code(src, "sudo-F01"), 0, "visudo accepts this file");
    assert_eq!(count_code(src, "sudo-W01"), 1);
    assert_eq!(
        principals(src),
        (vec!["alice".to_string()], vec!["!!h1".to_string()]),
        "the boundary is the FIRST `!`; the run stays with the host token"
    );
}
