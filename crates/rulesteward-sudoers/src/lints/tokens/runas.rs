//! sudo-F02 #375 Rule 1 (#433 split from `tokens.rs`): runas-position
//! defects on a `CmndSpec.runas` group (denylist chars, embedded
//! whitespace, `%`-prefixed runas-group tokens, and malformed `#`-GID
//! tails).

use rulesteward_core::{Diagnostic, Severity};

use crate::ast::SudoersFile;
use crate::lints::anchored;

use super::shared::{is_denylist_char, is_malformed_gid_tail};

/// Return the first Case-4(b) denylist char (`! ( ) > "`) or whitespace char
/// found in `token`, or `None` if the token is clean. Used by `check_runas`
/// (#375 Rule 1a), which -- unlike the subject-position check -- applies
/// directly to every runas token regardless of a `%` prefix, and additionally
/// treats embedded whitespace as invalid (a runas token is comma/colon-split
/// only, so unlike a subject `%name` it can carry an internal space straight
/// through to this check).
fn first_invalid_char(token: &str) -> Option<char> {
    token
        .chars()
        .find(|c| is_denylist_char(*c) || c.is_whitespace())
}

/// #375 Rule 1: runas-position defects on a single `CmndSpec.runas` group.
///
/// `check_user_spec`'s Case-4 walk only inspects `UserSpec.users` (the
/// SUBJECT list before ` = `); it never scans `RunasSpec.users` /
/// `RunasSpec.groups` (the `(runas_user:runas_group)` group attached to an
/// individual command). Two sub-rules, grounded via local `visudo -cf`
/// 1.9.17p2, 2026-07-02:
///
/// (a) Reuse the Case-4(b) denylist (`is_denylist_char`) plus an embedded-
///     whitespace check, applied directly to every `runas.users` AND
///     `runas.groups` token. Unlike the subject-position check, this does
///     NOT require a `%` prefix: a bare runas-user name like `grpbad!x` (no
///     `%`) is also invalid, e.g. `(grpbad!x)`.
/// (b) NEW, `runas.groups`-only: a token starting with `%` is invalid
///     regardless of denylist chars. The post-colon `RUNAS_GROUP` position
///     already denotes a group, so a `%` prefix there is a THIRD, distinct
///     mechanism (not a denylist-char miss) -- `(root:%grp)` is rejected even
///     though `grp` alone contains no denylist char. This does NOT apply to
///     `runas.users`, where `%group` is the normal, valid way to reference a
///     group (`(%wheel)` is valid).
///
/// #407 addendum: the GID-tail check (Rule 3 below) now ALSO applies to
/// `runas.groups` (a bare, non-`%` `#`-GID token, e.g. `(root:#1000abc)`) and
/// to a BARE (non-`%`) `runas.users` token (e.g. `(#1000abc)`, no colon at
/// all). Both shapes previously never reached this function with the
/// malformed token intact: `strip_inline_comment`'s `prev_allows_uid`
/// predicate (parser.rs) did not allow `:` or `(` to precede a `#<digits>`
/// token, so the whole rest of the line (including the command) was
/// swallowed as an inline comment before parsing ever produced a `RunasSpec`.
pub(super) fn check_runas(
    file: &SudoersFile,
    logical: &crate::ast::LogicalLine,
    runas: &crate::ast::RunasSpec,
    diags: &mut Vec<Diagnostic>,
) {
    for user in &runas.users {
        // Rule 1a: denylist char / embedded whitespace, position-independent.
        if let Some(bad) = first_invalid_char(user) {
            diags.push(anchored(
                Severity::Fatal,
                "sudo-F02",
                logical.span.clone(),
                format!(
                    "runas-user token {user:?} contains an invalid character `{bad}` \
                     that visudo rejects"
                ),
                file.path.clone(),
                logical.line,
            ));
            continue; // one diag per token; denylist takes priority over Rule 3
        }
        // Rule 3 (mirrors `check_group_subject`): a `#`-GID token whose digit run
        // is followed by a non-digit tail is visudo-rejected even with no
        // denylist char. Covers BOTH the `%`-prefixed group-of-GID form
        // (`%#1000abc`, `%#0z`) and the BARE (non-`%`) UID form (`#1000abc`,
        // #407: `(#1000abc)` with no colon at all is a bare `runas.users` UID
        // reference). `is_malformed_gid_tail` preserves the pure-GID exemption
        // (`%#1000` / bare `#1000` both stay clean).
        let gid_check_target = user.strip_prefix('%').unwrap_or(user);
        if is_malformed_gid_tail(gid_check_target) {
            diags.push(anchored(
                Severity::Fatal,
                "sudo-F02",
                logical.span.clone(),
                format!(
                    "runas-user token {user:?} has a `#`-prefixed name that is not a \
                     pure GID digit run, which visudo rejects"
                ),
                file.path.clone(),
                logical.line,
            ));
        }
    }
    for group in &runas.groups {
        if group.starts_with('%') {
            diags.push(anchored(
                Severity::Fatal,
                "sudo-F02",
                logical.span.clone(),
                format!(
                    "runas-group token {group:?} has a `%` prefix that visudo rejects \
                     (the runas-group position already denotes a group)"
                ),
                file.path.clone(),
                logical.line,
            ));
            continue;
        }
        if let Some(bad) = first_invalid_char(group) {
            diags.push(anchored(
                Severity::Fatal,
                "sudo-F02",
                logical.span.clone(),
                format!(
                    "runas-group token {group:?} contains an invalid character `{bad}` \
                     that visudo rejects"
                ),
                file.path.clone(),
                logical.line,
            ));
            continue;
        }
        // #407: a bare (non-`%`) `#`-GID runas-GROUP token whose digit run is
        // followed by a non-digit tail (`#1000abc`) is visudo-rejected even
        // with no denylist char, mirroring Rule 3 above for `runas.users`.
        // `is_malformed_gid_tail` preserves the pure-GID exemption (`#1000`
        // stays clean, per `f02_runas_group_position_gid_form_no_f02`).
        if is_malformed_gid_tail(group) {
            diags.push(anchored(
                Severity::Fatal,
                "sudo-F02",
                logical.span.clone(),
                format!(
                    "runas-group token {group:?} has a `#`-prefixed name that is not a \
                     pure GID digit run, which visudo rejects"
                ),
                file.path.clone(),
                logical.line,
            ));
        }
    }
}
