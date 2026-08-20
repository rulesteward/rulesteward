//! #649: the shared comment stripper was escape-blind, so a backslash-escaped
//! `\#` truncated the logical line before parsing and every lint pass after it
//! went silent.
//!
//! This is a FAIL-OPEN, and the silent kind: the truncated remainder is never
//! parsed and no diagnostic ABOUT IT is emitted, so a compliance run reports a
//! file that grants passwordless sudo as carrying only the baseline findings an
//! EMPTY file also carries. (Measured, because the blunter phrasing "no
//! diagnostic of any kind" was wrong and is what the issue says: the
//! escape-blind build emits three `sudo-W04`s here, the same three it emits on
//! an empty file.) The defect lived in
//! `rulesteward-core`'s `comment_index`, which carried `in_quote`,
//! `in_runas_paren`, `seen_token` and `prev` but no escape state at all.
//!
//! GROUNDING. Re-derived on THIS host on 2026-08-19 against sudo 1.9.17p2,
//! both files fed on stdin, not copied from the issue. (`\#` is not a bash
//! `printf` escape, so the backslash below survives verbatim and these commands
//! reproduce as written. That is NOT true of a `\"` case - see the note on the
//! re-grounded row in `rulesteward-core/src/comment.rs`.)
//!
//! ```text
//! $ printf 'alice ALL = /bin/echo \#x, NOPASSWD: /bin/su\n' | visudo -c -f -
//! stdin: parsed OK                                             (rc 0)
//! $ printf 'alice ALL = /bin/echo \#x, NOPASSWD: /bin/su\n' | cvtsudoers -f json
//!   Cmnd_Specs: [ { "command": "/bin/echo #x" },
//!                 { "authenticate": false } + { "command": "/bin/su" } ]
//!                 (TWO specs; the `+` joins the Options and Commands of the
//!                 second, which is one object, not two)
//!
//! $ printf 'alice ALL = /bin/echo a#b, NOPASSWD: /bin/su\n' | visudo -c -f -
//! stdin: parsed OK                                             (rc 0)
//! $ printf 'alice ALL = /bin/echo a#b, NOPASSWD: /bin/su\n' | cvtsudoers -f json
//!   Cmnd_Specs: [ { "command": "/bin/echo a" } ]     <- NO "authenticate"
//! ```
//!
//! So sudo genuinely truncates at an UNESCAPED `#` and genuinely does not at an
//! escaped one, and the two inputs differ by exactly one byte. Neither test
//! below is meaningful alone: the first alone is passed by an implementation
//! that simply stopped treating `#` as a comment marker, and the second alone is
//! passed by the escape-blind code this file exists to pin against.
//!
//! `sudo-W05` is the discriminator because it is the STIG control the dropped
//! grant belongs to (RHEL-08-010380 / RHEL-09-611085 / RHEL-10-600560). The
//! `sudo-W04` findings both inputs also carry are the three baseline
//! missing-`Defaults` findings (`use_pty`, I/O logging, and
//! `timestamp_timeout`) that fire on any minimal file. Measured 2026-08-19:
//! the same three appear on `alice ALL = /bin/true` and on an EMPTY file, so
//! they discriminate nothing here.

use std::path::Path;

use rulesteward_sudoers::ast::{CmndItem, LineKind};
use rulesteward_sudoers::{SudoersLintContext, lint, parse};

/// Every command token of `src`'s single user-spec, in source order, as the
/// parser actually recorded it.
///
/// The absence assertions below (`sudo-W05 == 0`) are satisfied by an EMPTY
/// file, so on their own they witness nothing: a regression that reduced these
/// lines to `Blank` would keep them green. Pairing each with the command the
/// oracle says survives the truncation is what makes them assert that the line
/// was PARSED and parsed to the right thing.
fn commands(src: &str) -> Vec<String> {
    let file = parse(src, Path::new("/etc/sudoers"));
    let mut out = Vec::new();
    for line in file.lines {
        if let LineKind::UserSpec(spec) = line.kind {
            for group in spec.host_groups {
                for cs in group.cmnd_specs {
                    out.push(match cs.cmnd {
                        CmndItem::All => "ALL".to_string(),
                        CmndItem::Cmnd(c) => c,
                    });
                }
            }
        }
    }
    out
}

fn count_code(src: &str, code: &str) -> usize {
    let files = vec![parse(src, Path::new("/etc/sudoers"))];
    lint(&files, &SudoersLintContext {})
        .iter()
        .filter(|d| d.code == code)
        .count()
}

/// visudo rc 0. The escaped `#` is a literal command byte, and the `NOPASSWD`
/// grant that follows it on the same logical line is live.
#[test]
fn escaped_hash_still_reports_the_nopasswd_grant() {
    let src = "alice ALL = /bin/echo \\#x, NOPASSWD: /bin/su\n";
    assert_eq!(
        count_code(src, "sudo-W05"),
        1,
        "the NOPASSWD grant after an escaped `#` must be reported; \
         0 here is the #649 fail-open"
    );
    // The line parses, so the drop must not be laundered into a visible FATAL
    // either: before the fix this was silent, and a false F01 would be a
    // different defect on a file real visudo accepts.
    assert_eq!(count_code(src, "sudo-F01"), 0, "visudo accepts this file");
    // Positive witness. cvtsudoers records `/bin/echo #x` here; the AST keeps
    // the backslash, which is the known escape-RETENTION divergence xfailed in
    // the corpus oracle (the sibling of #667). Pinning the AST value is what
    // makes this row notice a change in EITHER direction.
    assert_eq!(commands(src), vec![r"/bin/echo \#x", "/bin/su"]);
}

/// visudo rc 0. The one-byte control: with the backslash removed, sudo really
/// does truncate at the `#`, so there is no grant left to report and silence is
/// the CORRECT answer.
#[test]
fn unescaped_hash_control_reports_no_grant() {
    let src = "alice ALL = /bin/echo a#b, NOPASSWD: /bin/su\n";
    assert_eq!(
        count_code(src, "sudo-W05"),
        0,
        "sudo truncates at an unescaped `#`, so no grant survives to report"
    );
    assert_eq!(count_code(src, "sudo-F01"), 0, "visudo accepts this file");
    // Positive witness: `sudo-W05 == 0` alone is also true of an EMPTY file.
    // cvtsudoers records exactly one command here and so does the AST.
    assert_eq!(commands(src), vec!["/bin/echo a"]);
}

// ---- Backslash PARITY. The separator-finding rule outside a quoted span
// consumes exactly the next byte, so whether a `#` is escaped depends on
// whether the backslash run before it is odd or even.
//
// There are THREE tests below, and they do not all discriminate the same wrong
// implementation. Both relationships were established by RUNNING each mutant,
// not by reading the code:
//
//   mutant A, "is the previous byte a backslash?" (no parity):
//     kills `even_backslash_run_leaves_the_hash_unescaped_so_no_grant_survives`
//     and `even_backslash_run_before_a_quote_still_opens_the_span`.
//     `odd_backslash_run_escapes_the_hash_so_the_grant_survives` SURVIVES it -
//     the naive rule marks the `#` escaped and the grant is reported, which is
//     the right answer for the wrong reason.
//   mutant B, the pre-#649 escape-blind reading (`SUDOERS` back to
//     `EscapeRule::None`): kills the odd-run test and
//     `escaped_hash_still_reports_the_nopasswd_grant`, and the other three
//     survive.
//
// So neither mutant alone justifies all three rows, and that is why both are
// recorded. An earlier version of this comment claimed mutant A killed "both
// tests below" when there were two; it was already false when the third was
// added and it credited mutant A with the odd-run row it does not kill.
// verified: 2026-08-19
//
// GROUNDING, same host and sudo 1.9.17p2, 2026-08-19, all three visudo rc 0:
//
//   `/bin/echo \#x, NOPASSWD: /bin/su`     -> "/bin/echo #x"   + authenticate:false
//   `/bin/echo \\#x, NOPASSWD: /bin/su`    -> "/bin/echo \"    and NOTHING after
//   `/bin/echo \\\#x, NOPASSWD: /bin/su`   -> "/bin/echo \#x"  + authenticate:false
//
// So the even run truncates and the odd runs do not.

/// visudo rc 0. An EVEN backslash run: the two backslashes escape each other,
/// the `#` is therefore unescaped, and sudo truncates. No grant survives, so
/// reporting none is correct and reporting one would be a false positive.
#[test]
fn even_backslash_run_leaves_the_hash_unescaped_so_no_grant_survives() {
    let src = "alice ALL = /bin/echo \\\\#x, NOPASSWD: /bin/su\n";
    assert_eq!(
        count_code(src, "sudo-W05"),
        0,
        "`\\\\#` is an unescaped `#`; sudo truncates and no grant remains"
    );
    assert_eq!(count_code(src, "sudo-F01"), 0, "visudo accepts this file");
    // Positive witness, and the one place AST and cvtsudoers AGREE exactly:
    // both record `/bin/echo \`. This is why this scenario is deliberately NOT
    // an L3 xfail in the corpus oracle.
    assert_eq!(commands(src), vec![r"/bin/echo \"]);
}

/// visudo rc 0. An ODD backslash run of three: the first two escape each other
/// and the third escapes the `#`, so the line is NOT truncated and the
/// `NOPASSWD` grant after it is live.
#[test]
fn odd_backslash_run_escapes_the_hash_so_the_grant_survives() {
    let src = "alice ALL = /bin/echo \\\\\\#x, NOPASSWD: /bin/su\n";
    assert_eq!(
        count_code(src, "sudo-W05"),
        1,
        "`\\\\\\#` escapes the `#`; the NOPASSWD grant after it must be reported"
    );
    assert_eq!(count_code(src, "sudo-F01"), 0, "visudo accepts this file");
    // Positive witness. cvtsudoers records `/bin/echo \#x`; the AST keeps all
    // three backslashes (escape retention again).
    assert_eq!(commands(src), vec![r"/bin/echo \\\#x", "/bin/su"]);
}

/// visudo rc 0. An even backslash run immediately before a QUOTE: the
/// backslashes escape each other, so the `"` is a real opener, the span closes
/// at the second `"`, and the following `#t` is an ordinary comment that
/// truncates the line. cvtsudoers records the command as `/bin/echo \"a b"`
/// with no second `Cmnd_Spec`, so the absent grant is correct here too.
#[test]
fn even_backslash_run_before_a_quote_still_opens_the_span() {
    let src = "alice ALL = /bin/echo \\\\\"a b\" #t, NOPASSWD: /bin/su\n";
    assert_eq!(
        count_code(src, "sudo-W05"),
        0,
        "the `#t` after the closed span is a real comment; sudo truncates"
    );
    assert_eq!(count_code(src, "sudo-F01"), 0, "visudo accepts this file");
    // Positive witness. Distinguishes "the span opened and the comment
    // truncated" from "the line vanished", which the W05 count cannot.
    assert_eq!(commands(src), vec![r#"/bin/echo \\"a b""#]);
}
