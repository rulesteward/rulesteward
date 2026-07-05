//! sudo-F02 Case 4 (#433 split from `tokens.rs`): malformed group subject
//! (embedded whitespace or an invalid char in the `%group` name).

use rulesteward_core::{Diagnostic, Severity};

use crate::ast::SudoersFile;
use crate::lints::anchored;

use super::shared::{is_denylist_char, is_malformed_gid_tail};

/// Case 4: malformed group subject.
///
/// Two sub-cases:
///
/// (a) Embedded-whitespace: `%bad group ALL = ALL` splits into `users = ["%bad"]`,
///     `hosts = ["group ALL"]`. A host token with embedded whitespace is
///     structurally impossible in a valid file and signals the group name had
///     a space.
///
/// (b) Invalid group-name char in the user token itself: `%bad!group ALL = ALL`
///     splits into `users = ["%bad!group"]`, `hosts = ["ALL"]`. The invalid
///     char is INSIDE the user token, not expressed as host whitespace.
///
/// CLOSED grounded denylist for sub-case (b): `! ( ) > "`. Derived from an
/// exhaustive visudo -cf probe of every printable-ASCII char CH in
/// `%bad<CH>group` (rockylinux:9, sudo 1.9.17p2, 2026-06-30):
///
/// ```text
/// REJECTED (rc=1, syntax error): !  "  #  (  )  :  =  >   (8 chars)
/// ACCEPTED (rc=0): the other 86 printable-ASCII chars + non-ASCII.
/// ```
///
/// F01 carve-out: `#`, `:`, `=` also reject but fold the line to Malformed in
/// the AST, so they are caught by sudo-F01 before F02 is reached. They MUST NOT
/// appear here to avoid double-reporting. The F02-relevant rejected chars are
/// exactly the 5 above (do NOT convert to a positive allowlist -- the parser
/// already ensures clean tokens reach this point; a denylist is simpler and
/// more mutation-resistant).
///
/// GID-form exemption: `%#NNN` (pure GID: `#` followed only by one or more
/// ASCII digits) is valid (visudo rc=0) and must be exempt. The exemption is
/// STRICTLY the pure-GID form: `%#1000>x` and `%#1000!x` contain a denylist
/// char after the digit run and are visudo-rejected (rc=1). A bare
/// `starts_with('#')` guard over-exempts any `#`-prefix name entirely; the
/// correct guard uses `is_pure_gid` (see below).
pub(super) fn check_group_subject(
    file: &SudoersFile,
    logical: &crate::ast::LogicalLine,
    spec: &crate::ast::UserSpec,
    diags: &mut Vec<Diagnostic>,
) {
    for user in &spec.users {
        let Some(name) = user.strip_prefix('%') else {
            continue;
        };
        // Sub-case (b): invalid char in the group name portion of the user token.
        //
        // `%#NNN` (pure GID: `#` followed only by ASCII digits) is valid
        // (visudo rc=0). Exempt it from the denylist check.
        // `%#1000>x` is NOT a pure GID (digit run followed by `>`): `is_pure_gid`
        // is false, the denylist runs, and `>` is caught.
        //
        // Note: `%#` (empty digit run) is vacuously a pure GID by this predicate
        // (`"".bytes().all(...)` is vacuously true), but visudo rejects `%#` via
        // F01 (the parser marks it Malformed before F02 runs), so F02 is silent
        // for `%#` regardless of whether `is_pure_gid` is true or false -- the
        // denylist contains none of `{! ( ) > "}` so `#` would not fire anyway.
        // The empty-rest case is therefore F02-silent under BOTH the old and new
        // predicate; dropping `!rest.is_empty()` eliminates an equivalent mutant
        // (`delete !` in is_pure_gid was unreachable through the denylist
        // mechanism) without changing any observable behavior.
        let is_pure_gid = name
            .strip_prefix('#')
            .is_some_and(|rest| rest.bytes().all(|b| b.is_ascii_digit()));
        if !is_pure_gid {
            if let Some(bad_char) = name.chars().find(|c| is_denylist_char(*c)) {
                diags.push(anchored(
                    Severity::Fatal,
                    "sudo-F02",
                    logical.span.clone(),
                    format!(
                        "group subject {user:?} contains an invalid character `{bad_char}` \
                         in the group name that visudo rejects"
                    ),
                    file.path.clone(),
                    logical.line,
                ));
                return; // fire once per spec line
            }
            // #375 Rule 3: a `#`-prefixed name that is not a pure GID (no
            // denylist char present either, or the denylist check above would
            // already have fired) is still GID-structurally invalid -- either
            // a digit run followed by non-digit char(s) (`%#1000abc`) or no
            // digits at all after the `#` (`%#abc`). Only the pure-digit-run
            // form is a valid GID reference; a name that does NOT start with
            // `#` (`%1000abc`, `%wheel`) is an ordinary group name and is
            // untouched by this check. `is_malformed_gid_tail` encodes exactly
            // this (and is shared with the runas-user check in `check_runas`);
            // inside this `!is_pure_gid` block it reduces to `starts_with('#')`.
            if is_malformed_gid_tail(name) {
                diags.push(anchored(
                    Severity::Fatal,
                    "sudo-F02",
                    logical.span.clone(),
                    format!(
                        "group subject {user:?} has a `#`-prefixed name that is not a \
                         pure GID digit run, which visudo rejects"
                    ),
                    file.path.clone(),
                    logical.line,
                ));
                return; // fire once per spec line
            }
        }
    }
    // Sub-case (a): whitespace embedded in host token -- the parser split the group
    // name at the space and left the tail in the host field.
    if spec.users.iter().any(|u| u.starts_with('%')) {
        for host_group in &spec.host_groups {
            for host in &host_group.hosts {
                if host.contains(char::is_whitespace) {
                    let pct_user = spec
                        .users
                        .iter()
                        .find(|u| u.starts_with('%'))
                        .map_or("%group", String::as_str);
                    diags.push(anchored(
                        Severity::Fatal,
                        "sudo-F02",
                        logical.span.clone(),
                        format!(
                            "group subject {pct_user:?} has an invalid name \
                             (embedded whitespace) that visudo rejects"
                        ),
                        file.path.clone(),
                        logical.line,
                    ));
                    return; // fire once per spec line
                }
            }
        }
    }
}
