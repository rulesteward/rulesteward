//! The runas group's boundary and the "embedded whitespace is impossible"
//! premise (#650, #652).
//!
//! These are ONE commit because #650 MASKS #652's runas face: `is_denylist_char`
//! matches the `"` first and reports the quote as the invalid character, so
//! fixing #650's quote face alone would UNMASK a still-live false FATAL on
//! `("r t")`. #652 says so in its own text, and the two are therefore fixed
//! together rather than in sequence.
//!
//! **#650** - `parse_cmnd_spec` located the runas group's closing paren with a
//! bare `after_open.find(')')`, which is quote- AND escape-blind. It stopped at
//! a quoted or escaped `)` and truncated the group, dropping the `NOPASSWD`
//! grant that follows. `sudo-W05` is a DISA STIG control
//! (RHEL-08-010380 / RHEL-09-611085 / RHEL-10-600560).
//!
//! **#652** - two lint passes asserted that embedded whitespace in a principal
//! is structurally impossible ("the parser must have split the name at a
//! space"). That premise is false for a QUOTED principal, which may legally
//! contain one.
//!
//! GROUNDING. Re-derived on THIS host 2026-08-19, sudo 1.9.17p2, stdin only.
//! **Quoting legitimises the whole denylist, not just whitespace** - every row
//! here is `visudo -c -f -` rc 0:
//!
//! ```text
//! alice ALL = ("a b") /bin/ls      alice ALL = ("a(b") /bin/ls
//! alice ALL = ("a>b") /bin/ls      alice ALL = ("a!b") /bin/ls
//! %grp "h(c" = /bin/ls             %grp "h>c" = /bin/ls
//! ```
//!
//! so the fix is not "ignore whitespace inside quotes" but the simpler and more
//! honest "a CLEAN quoted region's interior is literal". Two rc-1 rows pin the
//! other direction and must keep firing:
//!
//! ```text
//! alice ALL = (a>b) /bin/ls        rc 1 - UNQUOTED denylist char
//! alice ALL = ("a b) /bin/ls       rc 1 - UNTERMINATED quote, not a clean region
//! %bad group ALL = ALL             rc 1 - genuinely split group name
//! ```
//!
//! The last of those is the assertion that stops the lazy repair. #652 warns
//! that deleting the whitespace predicate outright satisfies every positive row
//! in this file, and #669's abandoned attempt broke exactly this test's
//! sibling. Both directions or nothing.

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

/// The runas users of the single user-spec's first command spec, as parsed.
///
/// The `sudo-W05` counts below are the real assertions, but a count alone does
/// not say the runas group was located CORRECTLY - only that a grant survived.
/// Pinning the token is what witnesses the boundary itself.
fn runas_users(src: &str) -> Vec<String> {
    let file = parse(src, Path::new("/etc/sudoers"));
    for line in file.lines {
        if let LineKind::UserSpec(spec) = line.kind
            && let Some(g) = spec.host_groups.first()
            && let Some(cs) = g.cmnd_specs.first()
            && let Some(r) = &cs.runas
        {
            return r.users.clone();
        }
    }
    Vec::new()
}

// ------------------------------------------------------------ #650

/// visudo rc 0. A QUOTED `)` inside the runas group. The bare `find(')')`
/// stopped at it, truncating the group to `root,"a` and taking the NOPASSWD
/// grant with it.
#[test]
fn quoted_close_paren_in_runas_reports_the_grant() {
    let src = "alice ALL = (root,\"a)b\") NOPASSWD: /bin/ls\n";
    assert_eq!(count_code(src, "sudo-F01"), 0, "visudo accepts this file");
    assert_eq!(
        count_code(src, "sudo-W05"),
        1,
        "the NOPASSWD grant must be reported; 0 here is the #650 fail-open"
    );
    assert_eq!(
        runas_users(src),
        vec!["root".to_string(), "\"a)b\"".to_string()],
        "the runas group ends at the UNQUOTED `)`, not the quoted one"
    );
}

/// visudo rc 0. An ESCAPED `)` inside the runas group - the second face of the
/// same bare `find`. Before the fix this line was COMPLETELY silent: no F01, no
/// F02, no W05.
#[test]
fn escaped_close_paren_in_runas_reports_the_grant() {
    let src = "alice ALL = (root,a\\)b) NOPASSWD: /bin/ls\n";
    assert_eq!(count_code(src, "sudo-F01"), 0, "visudo accepts this file");
    assert_eq!(
        count_code(src, "sudo-W05"),
        1,
        "the NOPASSWD grant must be reported; 0 here is the #650 fail-open"
    );
}

/// visudo rc 0. One-byte control for the quoted face: the `)` removed from
/// inside the quotes. Correct on both shas.
#[test]
fn quoted_runas_without_a_paren_control() {
    let src = "alice ALL = (root,\"ab\") NOPASSWD: /bin/ls\n";
    assert_eq!(count_code(src, "sudo-W05"), 1);
}

/// visudo rc 0. One-byte control for the escaped face.
#[test]
fn unquoted_runas_control() {
    let src = "alice ALL = (root,ab) NOPASSWD: /bin/ls\n";
    assert_eq!(count_code(src, "sudo-W05"), 1);
}

// ------------------------------------------------------------ #652 face A

/// visudo rc 0. A quoted HOST may contain a space. The sub-case (a) check
/// assumed any whitespace in a host token meant the parser had split a group
/// name, which is false when the token is quoted.
#[test]
fn quoted_host_with_whitespace_after_a_group_subject_is_legal() {
    let src = "%grp \"h c\" = /bin/ls\n";
    assert_eq!(
        count_code(src, "sudo-F02"),
        0,
        "a quoted host may contain a space; 1 here is the #652 false FATAL"
    );
    assert_eq!(count_code(src, "sudo-F01"), 0, "visudo accepts this file");
}

/// visudo rc 0. One-byte control: the space removed. Correct on both shas.
#[test]
fn quoted_host_without_whitespace_control() {
    let src = "%grp \"hc\" = /bin/ls\n";
    assert_eq!(count_code(src, "sudo-F02"), 0);
}

/// visudo rc **1**. THE true positive. An UNQUOTED space really does split the
/// group name, and `sudo-F02` is correct here.
///
/// #652 states plainly that without this row the fix is satisfiable by deleting
/// sub-case (a) outright, and #669's abandoned arity check broke this exact
/// test. It is the reason the fix DISCRIMINATES quoted-origin whitespace rather
/// than dropping the predicate.
#[test]
fn unquoted_whitespace_in_a_group_subject_is_still_invalid() {
    let src = "%bad group ALL = ALL\n";
    assert_eq!(
        count_code(src, "sudo-F02"),
        1,
        "visudo rejects this file (rc 1); the F02 must keep firing"
    );
}

// ------------------------------------------------------------ #652 face B

/// visudo rc 0. A quoted RUNAS principal may contain a space. Masked by #650
/// until now, because the denylist matched the `"` before reaching the
/// whitespace check.
#[test]
fn quoted_runas_principal_with_whitespace_is_legal() {
    let src = "alice ALL = (\"r t\") /bin/ls\n";
    assert_eq!(
        count_code(src, "sudo-F02"),
        0,
        "a quoted runas principal may contain a space; 1 here is #652 face B"
    );
}

/// visudo rc 0. The same for a quoted runas GROUP, after the `:`.
#[test]
fn quoted_runas_group_with_whitespace_is_legal() {
    let src = "alice ALL = (root:\"g p\") /bin/ls\n";
    assert_eq!(count_code(src, "sudo-F02"), 0);
}

/// visudo rc 0. Quoting legitimises the whole denylist, not only whitespace.
/// `(` is one of the five denylist characters and is legal inside quotes.
#[test]
fn a_denylist_char_inside_quotes_is_literal() {
    let src = "alice ALL = (\"a(b\") /bin/ls\n";
    assert_eq!(count_code(src, "sudo-F02"), 0, "visudo accepts this file");
}

/// visudo rc **1**. Control: the same character UNQUOTED is still invalid.
#[test]
fn an_unquoted_denylist_char_is_still_invalid() {
    let src = "alice ALL = (a>b) /bin/ls\n";
    assert_eq!(
        count_code(src, "sudo-F02"),
        1,
        "visudo rejects this file (rc 1); the F02 must keep firing"
    );
}

/// visudo rc **1**. Control: an UNTERMINATED quote is not a clean region, so
/// its contents are not literal and the whitespace is still a defect.
#[test]
fn an_unterminated_quote_is_not_a_clean_region() {
    let src = "alice ALL = (\"a b) /bin/ls\n";
    assert_eq!(
        count_code(src, "sudo-F02"),
        1,
        "visudo rejects this file (rc 1); the F02 must keep firing"
    );
}
