//! Per-position token-validation lint pass (#346): sudo-F02 (the file contains a
//! token that `visudo -c` rejects but the current `RuleSteward` classifier keeps as
//! a clean spec). Severity Fatal -- the file will not load.
//!
//! # Scope (v1, issue #346)
//!
//! Four invalid-token positions, each grounded via `visudo -c` on Rocky Linux 9
//! (sudo 1.9.17p2, 2026-06-30):
//!
//! 1. **`#<digits>` in COMMAND position** (e.g. `alice ALL = /bin/ls #2`):
//!    visudo rejects this as a syntax error (rc=1). The inline-comment stripper
//!    in stage 1 preserves `#<digits>` when preceded by whitespace/comma/`%` (it
//!    is a UID/GID token in those positions), so this reaches the AST as
//!    `CmndItem::Cmnd("/bin/ls #2")`. F02 detects the `#<digits>` suffix in the
//!    command token.
//!
//! 2. **`#<digits>` in Defaults-VALUE position** (e.g.
//!    `Defaults env_reset #2 reasons`): visudo rejects this (rc=1, message
//!    "Success" at the `#2` position -- a quirk of the visudo error reporter).
//!    The inline-comment stripper preserves `#<digits>` after a space, so the
//!    value reaches the AST as `DefaultSetting { name: "env_reset #2 reasons",
//!    value: None }` (the whole thing becomes the setting name). F02 detects a
//!    `#<digits>` substring in the setting name or value.
//!
//! 3. **Relative-path command** (e.g. `alice ALL = bin/ls`): visudo reports
//!    "expected a fully-qualified path name" (rc=1). `RuleSteward` keeps this as
//!    `CmndItem::Cmnd("bin/ls")`. F02 detects a command token whose path (after
//!    stripping any leading `!` negation prefixes) contains `/` but does not start
//!    with `/`. A `!`-negated absolute path (`!/bin/su`) is VALID (visudo rc=0)
//!    and must not fire.
//!
//! 4. **Malformed group subject**: two sub-cases, both grounded against visudo
//!    (Rocky Linux 9, sudo 1.9.17p2, 2026-06-30):
//!    - **Embedded whitespace** (`%bad group ALL = ALL`, rc=1): `RuleSteward`
//!      parses `%bad` as the user and `group ALL` as the host. F02 detects a
//!      `%`-prefixed user whose host token contains whitespace.
//!    - **Invalid char in group name** (`%bad!group ALL = ALL`, rc=1): the `!`,
//!      `(`, or `)` char sits inside the user token itself (no whitespace split
//!      occurs). F02 checks each `%`-prefixed user token's name for these chars.
//!      Note: `%#NNN` (GID form) is valid (rc=0) and is excluded from this check.
//!
//! ## Issue #375 tail (Case-4/Case-5 completeness)
//!
//! Three more visudo-rejected shapes outside the four positions above, all
//! grounded via local `visudo -cf` 1.9.17p2, 2026-07-02:
//!
//! 5. **Runas-position group defects**: `CmndSpec.runas.users` /
//!    `.groups` (the `(runas_user:runas_group)` group on an individual
//!    command) are never scanned by the subject-position walk above. Two
//!    sub-rules: (a) the Case-4(b) denylist (plus embedded whitespace),
//!    applied directly to every runas.users/groups token; (b) a
//!    runas.groups token starting with `%` is invalid regardless of
//!    denylist chars (the post-colon position already denotes a group).
//! 6. **Lone `!` command**: `CmndItem::Cmnd("!")` -- a negation with nothing
//!    to negate. Keyed off the exact token `"!"`, not `starts_with('!')`, so
//!    `!ALL` and `!/bin/su` are unaffected.
//! 7. **GID-then-non-digit subject**: a `%#<digits><non-digit>` or `%#<all
//!    non-digit>` name (e.g. `%#1000abc`, `%#abc`) is not a pure GID and has
//!    no denylist char, but is still visudo-rejected.
//!
//! ## Issue #407 (runas / Defaults `#`-GID false negatives, parser-level root cause)
//!
//! `(root:#1000abc)` and bare `(#1000abc)` used to reach `RuleSteward` as
//! `CmndSpec { runas: None, cmnd: Cmnd("(root:") }` / `Cmnd("(")` -- the
//! `strip_inline_comment` classifier (parser.rs) misread the `#` after `:` /
//! `(` as a real comment and swallowed the rest of the line (including the
//! command), so `check_runas` below never even saw the malformed token: ZERO
//! diagnostics for a `visudo -c`-rejected file. The same root cause hit the
//! `Defaults` scope sigils: `Defaults:#1000` / `Defaults>#1000` / `Defaults@#1000`
//! (all visudo rc=0) folded to a FALSE-POSITIVE `Malformed` / sudo-F01 because
//! their `#<digits>` scope target was stripped as a comment, while the invalid
//! `Defaults:#1000abc` / `Defaults>#1000abc` / `Defaults@#1000abc` (visudo rc=1)
//! either stayed silent or mis-reported. Fixed by widening
//! `strip_inline_comment`'s `prev_allows_uid` predicate to allow `:` / `(` / `>` /
//! `@`, extending the GID-tail check (Rule 3 in `check_runas`) to the bare (non-`%`)
//! form in BOTH `runas.users` and `runas.groups`, and adding the same
//! `is_malformed_gid_tail` structural check to the User (`:`), Runas (`>`) and Host
//! (`@`) `Defaults` scopes in `check_defaults`. visudo lexes `#<digits>` uniformly
//! in all three scope positions (pure digit run valid; digit-run + non-digit tail
//! a syntax error); the `!` command scope is left to fold to F01 (every `#`-command
//! target is invalid). MISS 2 -- the letter-first `(root:#abc)` runas FN on the
//! delicate `next_is_digit` gate -- is a tracked follow-up, out of scope here.
//!
//! # Must-NOT-regress (valid, no F02)
//!
//! - `User_Alias FOO = #1000`: the `#1000` follows `=` in an alias DEFINITION
//!   and is a valid UID member (visudo -c: rc=0 with only an "unused alias"
//!   warning). F02 must never fire on alias member positions.
//! - `!/bin/su` or `/bin/ls, !/bin/su`: negated absolute-path commands are valid
//!   (visudo rc=0). The `!` prefix is stripped before the path check.
//! - `%#1000 ALL = ALL`: GID-referenced group subject is valid (visudo rc=0).
//! - Any ordinary valid sudoers line (root rule, Defaults, `%wheel` rule, etc.).

use rulesteward_core::{Diagnostic, Severity};

use crate::ast::{CmndItem, LineKind, SudoersFile};
use crate::lints::{SudoersLintContext, anchored};

/// sudo-F02: a token that `visudo -c` rejects is present in the file but the
/// `RuleSteward` classifier produced a clean (non-Malformed) AST node. Operator
/// signal: the file will not load. Fatal severity.
///
/// Covers four per-position cases (see module doc + issue #346):
/// 1. `#<digits>` in command position.
/// 2. `#<digits>` in Defaults setting name or value.
/// 3. Relative-path command: path (after stripping `!` negation) contains `/`
///    but does not start with `/`. `!/bin/su` (negated absolute) does NOT fire.
/// 4. Malformed group subject: `%name` with embedded whitespace OR `%name`
///    containing an invalid char (`!`, `(`, `)`) in the group name portion.
///
/// Each diagnostic names the offending token / position in its message and is
/// anchored at the containing line.
#[must_use]
pub fn f02(files: &[SudoersFile], _ctx: &SudoersLintContext) -> Vec<Diagnostic> {
    let mut diags = Vec::new();
    for file in files {
        for logical in &file.lines {
            match &logical.kind {
                LineKind::UserSpec(spec) => {
                    check_user_spec(file, logical, spec, &mut diags);
                }
                LineKind::Defaults(entry) => {
                    check_defaults(file, logical, entry, &mut diags);
                }
                // Alias defs, includes, blanks, comments, and Malformed lines are
                // not checked: alias member `#<digits>` are valid UIDs (not command
                // position), and Malformed lines already emit sudo-F01.
                _ => {}
            }
        }
    }
    diags
}

/// Cases 1, 3, 4: check a `UserSpec` line for per-position invalid tokens.
fn check_user_spec(
    file: &SudoersFile,
    logical: &crate::ast::LogicalLine,
    spec: &crate::ast::UserSpec,
    diags: &mut Vec<Diagnostic>,
) {
    check_command_specs(file, logical, spec, diags);
    check_group_subject(file, logical, spec, diags);
}

/// Cases 1 and 3, plus #375 Rules 1 and 2: check every command spec (and its
/// optional runas group) in every host-group.
fn check_command_specs(
    file: &SudoersFile,
    logical: &crate::ast::LogicalLine,
    spec: &crate::ast::UserSpec,
    diags: &mut Vec<Diagnostic>,
) {
    for host_group in &spec.host_groups {
        for cmnd_spec in &host_group.cmnd_specs {
            // #375 Rule 1: runas-position defects. `RunasSpec.users` /
            // `.groups` (the `(runas_user:runas_group)` group attached to
            // THIS command) are never scanned by the subject-position walk
            // below (that only inspects `UserSpec.users`), so a malformed
            // runas token reaches F02 unseen without this check.
            if let Some(runas) = &cmnd_spec.runas {
                check_runas(file, logical, runas, diags);
            }
            if let CmndItem::Cmnd(token) = &cmnd_spec.cmnd {
                // #375 Rule 2: a lone `!` command (no path to negate) is a
                // distinct defect from a `!`-negated command with a real path
                // (Case 3 below) or a `!`-negated `ALL`. Key off the EXACT
                // token `"!"`, not `starts_with('!')`: `!ALL` and `!/bin/su`
                // both start with `!` but are valid (or handled elsewhere) --
                // only a bare `!` with nothing after it is invalid on its own.
                if token == "!" {
                    diags.push(anchored(
                        Severity::Fatal,
                        "sudo-F02",
                        logical.span.clone(),
                        "command is a lone `!` negation with no command to negate".to_string(),
                        file.path.clone(),
                        logical.line,
                    ));
                    continue;
                }
                // Case 1: `#<digits>` in command position. strip_inline_comment
                // preserves `#<digits>` preceded by whitespace/comma/`%`/start as a
                // UID token; visudo rejects them in command position (rc=1).
                if has_hash_digits(token) {
                    diags.push(anchored(
                        Severity::Fatal,
                        "sudo-F02",
                        logical.span.clone(),
                        format!("command position contains a `#<digits>` token that visudo rejects: {token}"),
                        file.path.clone(),
                        logical.line,
                    ));
                    continue;
                }
                // Case 3: relative-path command. Inspect ONLY the first
                // whitespace-delimited word (the command path), not arguments.
                // Strip any leading `!` negation prefixes before the path check:
                // `!/bin/su` is a valid negated absolute command (visudo rc=0);
                // only the underlying path matters for the relative-vs-absolute test.
                // A `!`-negated RELATIVE path (`!bin/su`) still fires F02.
                let cmd_path = token.split_whitespace().next().unwrap_or(token);
                let cmd_path_bare = cmd_path.trim_start_matches('!');
                if cmd_path_bare.contains('/') && !cmd_path_bare.starts_with('/') {
                    diags.push(anchored(
                        Severity::Fatal,
                        "sudo-F02",
                        logical.span.clone(),
                        format!(
                            "command is a relative path that visudo rejects \
                             (expected a fully-qualified path): {cmd_path}"
                        ),
                        file.path.clone(),
                        logical.line,
                    ));
                }
            }
        }
    }
}

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
fn check_group_subject(
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

/// The five printable-ASCII chars a sudoers group/runas name may not contain,
/// grounded via the exhaustive `visudo -cf` probe documented above in the
/// Case-4 doc comment: `! ( ) > "`. Shared by the subject-position sub-case
/// (b) check in `check_user_spec` and the #375 runas-position check
/// (`check_runas`) below.
fn is_denylist_char(c: char) -> bool {
    matches!(c, '!' | '(' | ')' | '>' | '"')
}

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

/// #375 Rule 3 predicate: `true` when `name` (the part after a `%` prefix) is a
/// `#`-prefixed group name that is NOT a pure-digit GID run and is therefore
/// visudo-rejected -- i.e. a digit run followed by non-digit char(s)
/// (`#1000abc`) or no digits at all after the `#` (`#abc`). The valid pure-GID
/// form (`#1000`) and the empty `#` (`""` after strip -- `all` is vacuously
/// true) both return `false`, preserving the pure-GID exemption. A name that
/// does NOT start with `#` (`1000abc`, `wheel`) returns `false` (it is an
/// ordinary group name). Shared by `check_group_subject`, both `check_runas`
/// token loops (runas-user and runas-group), and the `check_defaults` scope
/// targets (User/Runas/Host) so all `#`-GID validations stay consistent.
fn is_malformed_gid_tail(name: &str) -> bool {
    name.strip_prefix('#')
        .is_some_and(|rest| !rest.bytes().all(|b| b.is_ascii_digit()))
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
fn check_runas(
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

/// Case 2: check a `Defaults` line for `#<digits>` in setting name or value, plus
/// the #407 scope-target GID-tail check.
fn check_defaults(
    file: &SudoersFile,
    logical: &crate::ast::LogicalLine,
    entry: &crate::ast::DefaultsEntry,
    diags: &mut Vec<Diagnostic>,
) {
    // #407: a `Defaults` scope target that is a `#<digits>`-shaped token with a
    // non-digit tail (`Defaults:#1000abc`, `Defaults>#1000abc`, `Defaults@#1000abc`)
    // is visudo-rejected (rc=1) but reaches the AST as a clean `DefaultsEntry` with a
    // `#`-prefixed binding -- the #407 predicate widening (`:` / `>` / `@` now precede
    // a preserved `#<digits>` token) is what lets these scope targets survive the
    // comment strip. visudo lexes `#<digits>` UNIFORMLY in all three scope positions:
    // a pure digit run is valid (`:#1000` userid, `>#1000` runas userid, `@#1000`
    // host literally named `#1000`), and a digit run followed by a non-digit tail is
    // a syntax error. So all three scopes get the same `is_malformed_gid_tail`
    // structural check and the same `sudo-F02` code (a clean-spec-that-visudo-rejects
    // defect, consistent with the Case-2 setting check and the runas checks); the
    // valid pure-digit forms stay clean.
    //
    // The `!` (command) scope is intentionally NOT handled here: `!` is not in
    // `prev_allows_uid`, so a `#<digits>` command target (`Defaults!#1000` and
    // `Defaults!#1000abc`, BOTH visudo rc=1) still strips as a comment, folding the
    // line to `Malformed` / sudo-F01 -- the correct outcome, since every `#`-command
    // form is invalid (there is nothing valid to preserve).
    //
    // Message note: for the host (`@`) scope the token is a host name, not a GID, so
    // its message says "not a pure digit run" (no "GID") even though the shared
    // `is_malformed_gid_tail` shape-check is reused. (MISS 2, a letter-first
    // `(root:#abc)` runas FN, is a tracked follow-up on the delicate `next_is_digit`
    // gate and is out of scope here.)
    //
    // A `Defaults` scope target may be a COMMA LIST (bind settings to multiple
    // users / runas-users / hosts), e.g. `Defaults:#1000,alice` (rc=0 valid:
    // userid 1000 + username alice). The parser stores the binding as one raw
    // string, so -- like `check_runas` iterates already-split runas tokens -- we
    // must split on `,` and validate PER ELEMENT: a non-`#` element (a plain
    // user / host name) is IGNORED, a pure `#<digits>` element is valid, and a
    // `#<digits><non-digits>` element fires one F02 naming THAT element (NOT the
    // whole binding). A plain `,` split suffices (grounded, visudo/cvtsudoers
    // 1.9.17p2, 2026-07-03): a valid `#<digits>` UID/GID token is `#` + pure
    // digits (it can contain no comma / quote / space), and a quoted username
    // (`Defaults:"#1000abc"`, rc=0 valid) starts with `"` so it never trips the
    // `#`-prefix gate; the only comma that can land inside a would-be `#`-token
    // is one that makes it malformed anyway (`Defaults:#1000\,abc` is rc=1
    // invalid, and the split's `#1000\` fragment correctly fires).
    let scope_binding: Option<(&str, &str, bool)> = match &entry.scope {
        crate::ast::DefaultsScope::User(binding) => Some((binding.as_str(), "user", false)),
        crate::ast::DefaultsScope::Runas(binding) => Some((binding.as_str(), "runas", false)),
        crate::ast::DefaultsScope::Host(binding) => Some((binding.as_str(), "host", true)),
        // Global (no scope) and Cmnd (`!`, handled via strip->F01) are not checked.
        _ => None,
    };
    if let Some((binding, scope_word, is_host)) = scope_binding {
        let before = diags.len();
        for element in binding.split(',') {
            if is_malformed_gid_tail(element) {
                // Host targets are host names, not GIDs -- omit the word "GID".
                let tail_phrase = if is_host {
                    "not a pure digit run"
                } else {
                    "not a pure GID digit run"
                };
                diags.push(anchored(
                    Severity::Fatal,
                    "sudo-F02",
                    logical.span.clone(),
                    format!(
                        "Defaults {scope_word}-scope target has a `#`-prefixed name \
                         {element:?} that is {tail_phrase}, which visudo rejects"
                    ),
                    file.path.clone(),
                    logical.line,
                ));
            }
        }
        // If any scope element was flagged, the line is already reported; skip the
        // setting check (a clean-scope line still falls through to it).
        if diags.len() > before {
            return;
        }
    }

    // The inline-comment stripper keeps `#<digits>` preceded by whitespace as a UID
    // token, so `env_reset #2 reasons` arrives with name = "env_reset #2 reasons".
    // visudo rejects this as a syntax error (rc=1).
    for setting in &entry.settings {
        let in_name = has_hash_digits(&setting.name);
        let in_value = setting.value.as_deref().is_some_and(has_hash_digits);
        if in_name || in_value {
            let offending = if in_name {
                setting.name.as_str()
            } else {
                setting.value.as_deref().unwrap_or("")
            };
            diags.push(anchored(
                Severity::Fatal,
                "sudo-F02",
                logical.span.clone(),
                format!(
                    "Defaults setting contains a `#<digits>` token that visudo rejects: {offending}"
                ),
                file.path.clone(),
                logical.line,
            ));
            break; // one diagnostic per Defaults line
        }
    }
}

/// Return `true` when `s` contains a `#<digits>` token that the
/// `strip_inline_comment` stage preserved as a UID/GID reference and that is
/// invalid in a command or Defaults-value context.
///
/// By the time a string reaches this function, `strip_inline_comment` has already
/// removed any `#` that is a genuine inline comment. The only surviving `#` followed
/// by digits are ones preceded by start-of-string or whitespace -- the positions
/// that produce invalid UID-like tokens in command / Defaults-value context.
///
/// # Which preceding chars are (and are NOT) checked here
///
/// A surviving `#<digits>` is only a UID/GID token -- and thus visudo-invalid in a
/// command / Defaults-value context -- when it is preceded by start-of-string,
/// whitespace, or `%`. Those three are checked:
///
/// - **start-of-string / whitespace**: `/bin/ls #2`, a bare `#2` command.
/// - **`%`**: `%#<digits>` glued in a command arg or a Defaults value, e.g.
///   `/bin/prog %#2` or `Defaults passprompt=x%#2`. The byte immediately before the
///   `#` is `%` (NOT whitespace), so the whitespace arm cannot reach it -- the `%`
///   arm is required. Grounded: both forms are visudo-rejected (rc=1, rockylinux:9,
///   sudo 1.9.17p2, 2026-06-30). (Round-2 wrongly dropped this arm on the claim the
///   whitespace arm covered it; it does not -- restored in round-3.)
///
/// The `,` preceding char is deliberately NOT checked: it is dead. Both call sites
/// (`parse_cmnd_spec_list` and `parse_default_settings`) split on `,` -- an
/// unescaped `\,` is also consumed by that naive split -- before producing the
/// tokens passed here, so no literal `,` can appear before a `#` in any string that
/// reaches this function. Omitting it removes a mutation survivor with no behaviour
/// change.
fn has_hash_digits(s: &str) -> bool {
    let bytes = s.as_bytes();
    for i in 0..bytes.len() {
        if bytes[i] == b'#' && bytes.get(i + 1).is_some_and(u8::is_ascii_digit) {
            let prev_ok = match i.checked_sub(1) {
                None => true, // `#` at position 0
                Some(j) => {
                    let p = bytes[j];
                    // whitespace-preceded (`/bin/ls #2`) OR `%`-preceded (`%#2`);
                    // `,` is not checked (dead -- see the doc comment).
                    p == b'%' || (p as char).is_whitespace()
                }
            };
            if prev_ok {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::f02;
    use crate::lints::{SudoersLintContext, f01};
    use crate::parser::parse;
    use std::path::Path;

    /// Parse one source string into the single-element file slice the passes take.
    fn files(src: &str) -> Vec<crate::ast::SudoersFile> {
        vec![parse(src, Path::new("/etc/sudoers"))]
    }

    /// Run f02 over `src` and return the diagnostics.
    fn lint(src: &str) -> Vec<rulesteward_core::Diagnostic> {
        let f = files(src);
        f02(&f, &SudoersLintContext::default())
    }

    /// Run f01 over `src` and return the diagnostics (for the tests that pin a
    /// shape as a PARSE failure caught by sudo-F01 rather than a clean-spec F02).
    fn lint_f01(src: &str) -> Vec<rulesteward_core::Diagnostic> {
        let f = files(src);
        f01(&f, &SudoersLintContext::default())
    }

    /// Count f02 (sudo-F02) diagnostics.
    fn f02_count(src: &str) -> usize {
        lint(src).iter().filter(|d| d.code == "sudo-F02").count()
    }

    // -----------------------------------------------------------------------
    // Oracle grounding (Rocky Linux 9, sudo 1.9.17p2, verified 2026-06-30):
    //
    //   Case 1: `root ALL=(ALL:ALL) ALL\nalice ALL = /bin/ls #2\n`
    //           -> visudo rc=1, "syntax error" at col 21
    //   Case 2: `root ALL=(ALL:ALL) ALL\nDefaults env_reset #2 reasons\n`
    //           -> visudo rc=1, "Success" at col 20 (visudo quirk)
    //   Case 3: `root ALL=(ALL:ALL) ALL\nalice ALL = bin/ls\n`
    //           -> visudo rc=1, "expected a fully-qualified path name"
    //   Case 4: `root ALL=(ALL:ALL) ALL\n%bad group ALL = ALL\n`
    //           -> visudo rc=1, "syntax error" at col 12
    //   Not-regress 1: `root ALL=(ALL:ALL) ALL\nUser_Alias FOO = #1000\n`
    //           -> visudo rc=0 (warning "unused User_Alias 'FOO'" only)
    //   Not-regress 2: `root ALL=(ALL:ALL) ALL\nDefaults env_reset\nDefaults use_pty\n%wheel ALL=(ALL) ALL\n`
    //           -> visudo rc=0, "parsed OK"
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // Case 1: #<digits> in COMMAND position
    // -----------------------------------------------------------------------

    /// `alice ALL = /bin/ls #2` -- visudo rc=1 syntax error.
    ///
    /// The inline-comment stripper preserves `#2` (preceded by whitespace, so it
    /// looks like a UID token). The command reaches the AST as the string
    /// `/bin/ls #2`. F02 must fire exactly once, the diagnostic must have code
    /// `sudo-F02` and severity Fatal, and the message must name the offending
    /// token position (command or `#<digits>`).
    #[test]
    fn f02_hash_digits_in_command_position_fires() {
        // Fixture: visudo -c rc=1, syntax error at the `#2` in command position.
        // Verified: Rocky Linux 9, sudo 1.9.17p2, 2026-06-30.
        let diags = lint("root ALL=(ALL:ALL) ALL\nalice ALL = /bin/ls #2\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert_eq!(
            f02_diags.len(),
            1,
            "exactly one F02 for `#digits` in command position; got {diags:?}"
        );
        assert_eq!(
            f02_diags[0].severity,
            rulesteward_core::Severity::Fatal,
            "F02 must be Fatal"
        );
        assert!(
            f02_diags[0].message.contains("#2")
                || f02_diags[0].message.to_lowercase().contains("command"),
            "F02 message must name the offending token (#2) or its position; got {:?}",
            f02_diags[0].message
        );
    }

    /// `#2` in COMMAND position fires even when it immediately follows the `=`.
    ///
    /// `alice ALL = #2` -- the command is `#2` itself (not an annotation after a
    /// valid command). visudo rejects this with `expected a fully-qualified path
    /// name` (rc=1): a bare `#<digits>` in command position is not a valid path.
    /// F02 must fire. Note: the inline-comment stripper keeps `#2` here (preceded
    /// by whitespace), so the command reaches the AST as `CmndItem::Cmnd("#2")` --
    /// the `#<digits>`-in-command check (not the relative-path check) fires.
    #[test]
    fn f02_hash_digits_bare_command_fires() {
        // Fixture: visudo rejects `alice ALL = #2` with "expected a fully-qualified
        // path name" (rc=1). Distinct from the `#2`-suffix case (Case 1a) where
        // visudo says "syntax error" -- but both reach F02's `#<digits>` branch.
        // Verified: Rocky Linux 9, sudo 1.9.17p2, 2026-06-30.
        let diags = lint("root ALL=(ALL:ALL) ALL\nalice ALL = #2\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert_eq!(
            f02_diags.len(),
            1,
            "exactly one F02 for bare `#digits` command; got {diags:?}"
        );
        assert_eq!(f02_diags[0].severity, rulesteward_core::Severity::Fatal);
    }

    // -----------------------------------------------------------------------
    // Case 2: #<digits> in Defaults-VALUE position
    // -----------------------------------------------------------------------

    /// `Defaults env_reset #2 reasons` -- visudo rc=1.
    ///
    /// The inline-comment stripper preserves `#2` (preceded by whitespace). The
    /// whole `env_reset #2 reasons` becomes the setting name in the AST. F02 must
    /// fire exactly once with code `sudo-F02` and severity Fatal.
    #[test]
    fn f02_hash_digits_in_defaults_value_fires() {
        // Fixture: visudo -c rc=1, "Success" (quirk) at the `#2` position.
        // Verified: Rocky Linux 9, sudo 1.9.17p2, 2026-06-30.
        let diags = lint("root ALL=(ALL:ALL) ALL\nDefaults env_reset #2 reasons\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert_eq!(
            f02_diags.len(),
            1,
            "exactly one F02 for `#digits` in Defaults value; got {diags:?}"
        );
        assert_eq!(f02_diags[0].severity, rulesteward_core::Severity::Fatal);
        // Message should reference the offending token or position.
        assert!(
            f02_diags[0].message.contains("#2")
                || f02_diags[0].message.to_lowercase().contains("defaults")
                || f02_diags[0].message.to_lowercase().contains("setting"),
            "F02 message must name the token or position; got {:?}",
            f02_diags[0].message
        );
    }

    /// `Defaults secure_path=/usr/bin #3` -- `#3` in the VALUE (after `=`).
    ///
    /// visudo rejects this (rc=1). F02 must fire.
    #[test]
    fn f02_hash_digits_in_defaults_assigned_value_fires() {
        // Fixture: same oracle case, but the `#digits` appears in the assigned value.
        // Verified by oracle analogy: the strip_inline_comment function keeps any
        // `#<digits>` preceded by whitespace, so `/usr/bin #3` is preserved in the
        // AST value, and visudo rejects it as a syntax error at the `#`.
        let diags = lint("root ALL=(ALL:ALL) ALL\nDefaults secure_path=/usr/bin #3\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert_eq!(
            f02_diags.len(),
            1,
            "exactly one F02 for `#digits` in Defaults assigned value; got {diags:?}"
        );
        assert_eq!(f02_diags[0].severity, rulesteward_core::Severity::Fatal);
    }

    // -----------------------------------------------------------------------
    // #407 follow-up: `#`-token tail in a `Defaults` scope TARGET (`:`/`>`/`@`)
    // -----------------------------------------------------------------------
    //
    // The #407 parser fix widened `strip_inline_comment`'s `prev_allows_uid`
    // predicate to allow `:` / `>` / `@` before a `#<digits>` token. That is
    // required for the VALID scope targets `Defaults:#1000` (user UID),
    // `Defaults>#1000` (runas UID) and `Defaults@#1000` (a host literally named
    // `#1000`) -- all visudo rc=0 -- to survive the comment strip; previously the
    // whole `<sigil>#1000 !lecture` was swallowed as a comment and the line folded
    // to `Malformed("Defaults<sigil> scope is missing its target")`, a FALSE
    // POSITIVE. But the SAME widening lets the INVALID `Defaults:#1000abc` /
    // `Defaults>#1000abc` / `Defaults@#1000abc` (a `#<digits>` token with a
    // non-digit tail, visudo rc=1) reach the AST as a clean `DefaultsEntry` with a
    // `#`-prefixed binding. visudo lexes `#<digits>` UNIFORMLY in all three scope
    // positions (grounded, visudo/cvtsudoers 1.9.17p2, 2026-07-03), so all three
    // get the same `is_malformed_gid_tail` structural check `check_runas` uses and
    // the same `sudo-F02` code (a clean-spec-that-visudo-rejects defect). The host
    // (`@`) message avoids the word "GID" since the token is a host name.
    //
    // The `!` (command) scope is NOT in `prev_allows_uid`: both `Defaults!#1000`
    // and `Defaults!#1000abc` are visudo rc=1, so leaving the `#<digits>` target to
    // strip as a comment folds the line to `Malformed` / sudo-F01 -- the correct
    // outcome (every `#`-command target is invalid, nothing valid to preserve).
    // The `!`-scope no-regression is pinned by `f02_defaults_cmnd_scope_hash_*`.

    /// `Defaults:#1000abc !lecture` -- a `Defaults:` user-scope target that is a
    /// `#`-GID whose digit run is followed by a non-digit tail.
    ///
    /// Oracle: `visudo -c` rc=1, "syntax error" at col 15 (the `abc` tail).
    /// Verified locally: visudo 1.9.17p2, 2026-07-03. RED before the
    /// `check_defaults` scope-target check: the #407 predicate widening let this
    /// parse to a clean `DefaultsEntry { scope: User("#1000abc") }` with ZERO
    /// diagnostics.
    #[test]
    fn f02_defaults_user_scope_gid_form_digits_then_letters_fires() {
        let diags = lint("root ALL=(ALL:ALL) ALL\nDefaults:#1000abc !lecture\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert_eq!(
            f02_diags.len(),
            1,
            "`Defaults:#1000abc` scope target (digit run followed by letters) is \
             visudo-rejected and must fire exactly one F02; got {diags:?}"
        );
        assert_eq!(f02_diags[0].severity, rulesteward_core::Severity::Fatal);
    }

    /// `Defaults:#1000 !lecture` -- the VALID pure-GID `Defaults:` user-scope
    /// target (#407's critical non-regression control for the Defaults path).
    ///
    /// A bare `f02_diags.is_empty()` alone is satisfiable by the OLD, BROKEN
    /// parse too (the pre-#407 comment-swallow folded the line to Malformed, so
    /// F02 trivially found no clean Defaults entry to flag). This test also
    /// asserts the AST shape so the regression can't hide behind an
    /// empty-diagnostics vacuity: the scope target must survive as
    /// `User("#1000")`.
    ///
    /// Oracle: `visudo -c` rc=0, "parsed OK"; `cvtsudoers -f json` shows the
    /// binding as `{"userid": 1000}`. Verified locally: visudo/cvtsudoers
    /// 1.9.17p2, 2026-07-03.
    #[test]
    fn f02_defaults_user_scope_pure_gid_no_f02_and_parses_correctly() {
        let src = "root ALL=(ALL:ALL) ALL\nDefaults:#1000 !lecture\n";
        let diags = lint(src);
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert!(
            f02_diags.is_empty(),
            "`Defaults:#1000` is a valid pure-GID user-scope target -- must NOT \
             fire F02; got {f02_diags:?}"
        );
        let f = files(src);
        let crate::ast::LineKind::Defaults(entry) = &f[0].lines[1].kind else {
            panic!(
                "expected the second logical line to classify as a Defaults entry, \
                 not be swallowed by the comment strip; got {:?}",
                f[0].lines[1].kind
            );
        };
        assert_eq!(
            entry.scope,
            crate::ast::DefaultsScope::User("#1000".to_string()),
            "the pure-GID user-scope target must survive as `User(\"#1000\")`"
        );
    }

    /// `Defaults>#1000abc !lecture` -- a `Defaults>` RUNAS-scope target that is a
    /// `#`-GID whose digit run is followed by a non-digit tail.
    ///
    /// Oracle: `visudo -c` rc=1, "syntax error" at col 15 (the `abc` tail).
    /// Verified locally: visudo 1.9.17p2, 2026-07-03. RED before the `>` was added
    /// to `prev_allows_uid` + the Runas-scope check: previously `>#1000abc`
    /// stripped as a comment, folding the line to `Malformed` / sudo-F01 -- so this
    /// asserts the code is now `sudo-F02` (not F01) with the runas-scope message.
    #[test]
    fn f02_defaults_runas_scope_gid_form_digits_then_letters_fires() {
        let diags = lint("root ALL=(ALL:ALL) ALL\nDefaults>#1000abc !lecture\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert_eq!(
            f02_diags.len(),
            1,
            "`Defaults>#1000abc` runas-scope target (digit run followed by letters) \
             is visudo-rejected and must fire exactly one F02; got {diags:?}"
        );
        assert_eq!(f02_diags[0].severity, rulesteward_core::Severity::Fatal);
        assert!(
            f02_diags[0].message.contains("runas-scope"),
            "the runas-scope message must name the runas scope; got {:?}",
            f02_diags[0].message
        );
    }

    /// `Defaults>#1000 !lecture` -- the VALID pure-UID `Defaults>` runas-scope
    /// target. Non-regression control (was a false-positive sudo-F01 before the
    /// `>` predicate widening). Asserts the AST scope survives as `Runas("#1000")`
    /// so the fix can't hide behind empty-diagnostics vacuity.
    ///
    /// Oracle: `visudo -c` rc=0, "parsed OK"; `cvtsudoers -f json` binding
    /// `{"userid": 1000}`. Verified locally: visudo/cvtsudoers 1.9.17p2,
    /// 2026-07-03.
    #[test]
    fn f02_defaults_runas_scope_pure_gid_no_f02_and_parses_correctly() {
        let src = "root ALL=(ALL:ALL) ALL\nDefaults>#1000 !lecture\n";
        let diags = lint(src);
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert!(
            f02_diags.is_empty(),
            "`Defaults>#1000` is a valid pure-UID runas-scope target -- must NOT \
             fire F02; got {f02_diags:?}"
        );
        let f = files(src);
        let crate::ast::LineKind::Defaults(entry) = &f[0].lines[1].kind else {
            panic!(
                "expected a Defaults entry, not a comment-swallowed Malformed; got {:?}",
                f[0].lines[1].kind
            );
        };
        assert_eq!(
            entry.scope,
            crate::ast::DefaultsScope::Runas("#1000".to_string()),
            "the pure-UID runas-scope target must survive as `Runas(\"#1000\")`"
        );
    }

    /// `Defaults@#1000abc !lecture` -- a `Defaults@` HOST-scope target that is a
    /// `#`-token whose digit run is followed by a non-digit tail. GROUNDED (this
    /// contradicted the initial "host is an arbitrary string literal" assumption):
    /// visudo lexes `#<digits>` in the host position the same as `:`/`>`, so
    /// `#1000abc` is a syntax error even though `#1000` alone is a valid host.
    ///
    /// Oracle: `visudo -c` rc=1, "syntax error" at col 15 (the `abc` tail).
    /// Verified locally: visudo 1.9.17p2, 2026-07-03. RED before the `@` predicate
    /// widening + Host-scope check: previously stripped to `Malformed` / sudo-F01.
    /// Asserts the code is now `sudo-F02` with a HOST-appropriate message that does
    /// NOT call the token a GID.
    #[test]
    fn f02_defaults_host_scope_hash_tail_digits_then_letters_fires() {
        let diags = lint("root ALL=(ALL:ALL) ALL\nDefaults@#1000abc !lecture\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert_eq!(
            f02_diags.len(),
            1,
            "`Defaults@#1000abc` host-scope target (digit run followed by letters) \
             is visudo-rejected and must fire exactly one F02; got {diags:?}"
        );
        assert_eq!(f02_diags[0].severity, rulesteward_core::Severity::Fatal);
        assert!(
            f02_diags[0].message.contains("host-scope"),
            "the host-scope message must name the host scope; got {:?}",
            f02_diags[0].message
        );
        assert!(
            !f02_diags[0].message.contains("GID"),
            "the host-scope target is a host name, not a GID -- the message must not \
             call it a GID; got {:?}",
            f02_diags[0].message
        );
    }

    /// `Defaults@#1000 !lecture` -- the VALID host-scope target: a host literally
    /// named `#1000` (visudo rc=0, `cvtsudoers` binding `{"hostname": "#1000"}`).
    /// Non-regression control (was a false-positive sudo-F01 before the `@`
    /// predicate widening). Asserts the AST scope survives as `Host("#1000")`.
    ///
    /// Verified locally: visudo/cvtsudoers 1.9.17p2, 2026-07-03.
    #[test]
    fn f02_defaults_host_scope_pure_digit_hash_no_f02_and_parses_correctly() {
        let src = "root ALL=(ALL:ALL) ALL\nDefaults@#1000 !lecture\n";
        let diags = lint(src);
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert!(
            f02_diags.is_empty(),
            "`Defaults@#1000` is a valid host literally named `#1000` -- must NOT \
             fire F02; got {f02_diags:?}"
        );
        let f = files(src);
        let crate::ast::LineKind::Defaults(entry) = &f[0].lines[1].kind else {
            panic!(
                "expected a Defaults entry, not a comment-swallowed Malformed; got {:?}",
                f[0].lines[1].kind
            );
        };
        assert_eq!(
            entry.scope,
            crate::ast::DefaultsScope::Host("#1000".to_string()),
            "the valid `#1000` host-scope target must survive as `Host(\"#1000\")`"
        );
    }

    /// `!` (command) scope non-regression: BOTH `Defaults!#1000` and
    /// `Defaults!#1000abc` are visudo rc=1 ("expected a fully-qualified path
    /// name"). `!` is NOT in `prev_allows_uid`, so the `#<digits>` target strips as
    /// a comment and the line folds to `Malformed` / sudo-F01 -- the correct
    /// outcome (there is no valid `#`-command target to preserve). Pins that the
    /// `:`/`>`/`@` widening did NOT accidentally start emitting a Defaults-scope
    /// F02 for the command scope, and that F01 still fires.
    #[test]
    fn f02_defaults_cmnd_scope_hash_targets_stay_f01_no_f02() {
        for src in [
            "root ALL=(ALL:ALL) ALL\nDefaults!#1000 !lecture\n",
            "root ALL=(ALL:ALL) ALL\nDefaults!#1000abc !lecture\n",
        ] {
            let f02_diags: Vec<_> = lint(src)
                .into_iter()
                .filter(|d| d.code == "sudo-F02")
                .collect();
            assert!(
                f02_diags.is_empty(),
                "the `!` command scope must not emit a Defaults-scope F02 ({src:?}); \
                 got {f02_diags:?}"
            );
            let f01_diags: Vec<_> = lint_f01(src)
                .into_iter()
                .filter(|d| d.code == "sudo-F01")
                .collect();
            assert_eq!(
                f01_diags.len(),
                1,
                "the invalid `#`-command Defaults scope must fold to exactly one \
                 sudo-F01 ({src:?}); got {f01_diags:?}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // #407 round-2: `Defaults` scope target is a COMMA LIST -- validate per
    // element, not the whole raw binding string.
    // -----------------------------------------------------------------------
    //
    // A `Defaults` scope target can bind to multiple users / runas-users / hosts
    // via a comma list. The parser stores the binding as ONE raw string, so a
    // naive `is_malformed_gid_tail(whole_binding)` mis-fires: `"#1000,alice"`
    // starts with `#` and has a non-digit tail (`,alice`) -> a FALSE POSITIVE on
    // a visudo rc=0 line; and `"alice,#1000abc"` does NOT start with `#` -> a
    // FALSE NEGATIVE on a visudo rc=1 line. The fix splits on `,` and validates
    // each element. Grounded (visudo/cvtsudoers 1.9.17p2, 2026-07-03).

    /// `Defaults:#1000,alice !lecture` -- a valid two-element user list (a UID
    /// plus a plain username). visudo rc=0 (`cvtsudoers` Binding: `userid 1000`
    /// then `username alice`). RED before the per-element split: the whole
    /// binding `"#1000,alice"` was validated as one string (starts `#`, non-digit
    /// tail) and wrongly fired F02. Must be CLEAN.
    #[test]
    fn f02_defaults_user_scope_list_uid_then_name_no_f02() {
        let f02_diags: Vec<_> = lint("root ALL=(ALL:ALL) ALL\nDefaults:#1000,alice !lecture\n")
            .into_iter()
            .filter(|d| d.code == "sudo-F02")
            .collect();
        assert!(
            f02_diags.is_empty(),
            "`Defaults:#1000,alice` is a valid UID+name user list -- must NOT fire \
             F02; got {f02_diags:?}"
        );
    }

    /// `Defaults:#1000,#1001 !lecture` -- two pure-UID elements. visudo rc=0.
    /// Control: both elements are valid GIDs, so the per-element split must leave
    /// the line clean (a whole-string check would fire on `"#1000,#1001"`).
    #[test]
    fn f02_defaults_user_scope_list_two_uids_no_f02() {
        let f02_diags: Vec<_> = lint("root ALL=(ALL:ALL) ALL\nDefaults:#1000,#1001 !lecture\n")
            .into_iter()
            .filter(|d| d.code == "sudo-F02")
            .collect();
        assert!(
            f02_diags.is_empty(),
            "`Defaults:#1000,#1001` is two valid UIDs -- must NOT fire F02; got \
             {f02_diags:?}"
        );
    }

    /// `Defaults>#1000,root !lecture` -- valid runas list (UID + name). rc=0.
    /// RED before the per-element split (whole binding `"#1000,root"` mis-fired).
    #[test]
    fn f02_defaults_runas_scope_list_uid_then_name_no_f02() {
        let f02_diags: Vec<_> = lint("root ALL=(ALL:ALL) ALL\nDefaults>#1000,root !lecture\n")
            .into_iter()
            .filter(|d| d.code == "sudo-F02")
            .collect();
        assert!(
            f02_diags.is_empty(),
            "`Defaults>#1000,root` is a valid runas list -- must NOT fire F02; got \
             {f02_diags:?}"
        );
    }

    /// `Defaults@#1000,localhost !lecture` -- valid host list (`#1000` a host
    /// literally named `#1000`, plus `localhost`). rc=0. RED before the split.
    #[test]
    fn f02_defaults_host_scope_list_hash_then_name_no_f02() {
        let f02_diags: Vec<_> = lint("root ALL=(ALL:ALL) ALL\nDefaults@#1000,localhost !lecture\n")
            .into_iter()
            .filter(|d| d.code == "sudo-F02")
            .collect();
        assert!(
            f02_diags.is_empty(),
            "`Defaults@#1000,localhost` is a valid host list -- must NOT fire F02; \
             got {f02_diags:?}"
        );
    }

    /// `Defaults:alice,#1000abc !lecture` -- companion FALSE-NEGATIVE case: the
    /// SECOND element `#1000abc` is a malformed GID tail (visudo rc=1, "syntax
    /// error" at col 21). RED before the per-element split: the raw binding
    /// `"alice,#1000abc"` does not start with `#`, so the whole-string check was
    /// silent. After: exactly one F02 that NAMES the specific bad element
    /// `#1000abc` (NOT the whole binding, and NOT the valid `alice`).
    #[test]
    fn f02_defaults_user_scope_list_second_element_bad_gid_fires() {
        let diags = lint("root ALL=(ALL:ALL) ALL\nDefaults:alice,#1000abc !lecture\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert_eq!(
            f02_diags.len(),
            1,
            "`Defaults:alice,#1000abc` has a malformed 2nd GID element and must fire \
             exactly one F02; got {diags:?}"
        );
        assert_eq!(f02_diags[0].severity, rulesteward_core::Severity::Fatal);
        assert!(
            f02_diags[0].message.contains("#1000abc"),
            "the F02 must name the specific bad element `#1000abc`; got {:?}",
            f02_diags[0].message
        );
        assert!(
            !f02_diags[0].message.contains("alice"),
            "the F02 must NOT name the valid element or the whole raw binding; got {:?}",
            f02_diags[0].message
        );
    }

    /// `Defaults@#1000abc,localhost !lecture` -- host list whose FIRST element is
    /// a malformed `#`-tail (visudo rc=1). Fires one F02 naming `#1000abc` with a
    /// HOST-appropriate message (no "GID"); the valid `localhost` element does
    /// not fire.
    ///
    /// The `!message.contains("localhost")` assertion is the discriminator that
    /// makes this a genuine fail-before witness: under the OLD whole-string check
    /// the message interpolated the entire binding `#1000abc,localhost` (which
    /// contains `localhost`); the per-element split names ONLY the bad element.
    #[test]
    fn f02_defaults_host_scope_list_first_element_bad_fires() {
        let diags = lint("root ALL=(ALL:ALL) ALL\nDefaults@#1000abc,localhost !lecture\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert_eq!(
            f02_diags.len(),
            1,
            "`Defaults@#1000abc,localhost` has a malformed 1st host element and must \
             fire exactly one F02; got {diags:?}"
        );
        assert!(
            f02_diags[0].message.contains("#1000abc")
                && f02_diags[0].message.contains("host-scope"),
            "the host-scope F02 must name `#1000abc` and the host scope; got {:?}",
            f02_diags[0].message
        );
        assert!(
            !f02_diags[0].message.contains("localhost"),
            "the F02 must name ONLY the bad element, not the whole raw binding \
             (which contains the valid `localhost`); got {:?}",
            f02_diags[0].message
        );
        assert!(
            !f02_diags[0].message.contains("GID"),
            "a host-scope target is not a GID -- the message must not say GID; got {:?}",
            f02_diags[0].message
        );
    }

    // -----------------------------------------------------------------------
    // #407 round-3 (tests-only): pin the scope early-return guard
    // `if diags.len() > before { return; }` and the parser's quote-retention.
    // -----------------------------------------------------------------------
    //
    // The early-return means "a malformed scope target already flagged the line
    // -> skip the setting/value check", faithful to visudo's first-error-wins.
    // These tests pin its exact `>` semantics so the mutation gate cannot flip it
    // to `<` / `==` / `>=` silently. The value-check setting used is
    // `secure_path=/usr/bin #3`: visudo rejects the `#3` in the value (rc=1,
    // grounded 1.9.17p2, 2026-07-03), and the Case-2 value check fires on it
    // standalone (see `f02_hash_digits_in_defaults_assigned_value_fires`).

    /// Malformed scope element AND a malformed setting value on ONE line
    /// (`Defaults:#1000abc secure_path=/usr/bin #3`, visudo rc=1). The scope check
    /// fires an F02 and the early-return skips the value check, so EXACTLY ONE F02
    /// (the scope one) is emitted.
    ///
    /// Kills the `> -> <` and `> -> ==` mutants: both make `diags.len() > before`
    /// false after one scope push (`before+1 < before` and `before+1 == before`
    /// are both false), so the fn falls through to the value check and emits a
    /// SECOND F02 -- this test's `== 1` assertion then fails.
    #[test]
    fn f02_defaults_scope_defect_early_returns_before_value_check() {
        let diags = lint("root ALL=(ALL:ALL) ALL\nDefaults:#1000abc secure_path=/usr/bin #3\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert_eq!(
            f02_diags.len(),
            1,
            "a malformed scope target must early-return and emit EXACTLY ONE F02 \
             (the scope one), not also run the value check; got {diags:?}"
        );
        assert!(
            f02_diags[0].message.contains("user-scope")
                && f02_diags[0].message.contains("#1000abc"),
            "the single F02 must be the SCOPE diagnostic naming `#1000abc`; got {:?}",
            f02_diags[0].message
        );
        assert!(
            !f02_diags[0].message.contains("setting contains"),
            "the value-check F02 must NOT have run (early-return); got {:?}",
            f02_diags[0].message
        );
    }

    /// VALID scope AND a malformed setting value on one line
    /// (`Defaults:root secure_path=/usr/bin #3`, visudo rc=1). The valid `:root`
    /// scope pushes no diagnostic, so `diags.len() > before` is false and the fn
    /// MUST fall through to the value check, which fires its F02.
    ///
    /// Kills the `> -> >=` mutant: with no scope push, `before >= before` is true,
    /// so the mutant returns early and SKIPS the value check -> zero diagnostics --
    /// this test's `>= 1` (and the value-message) assertion then fails. (Also
    /// reds under `==`, a free bonus.)
    #[test]
    fn f02_defaults_valid_scope_still_runs_value_check() {
        let diags = lint("root ALL=(ALL:ALL) ALL\nDefaults:root secure_path=/usr/bin #3\n");
        let value_f02: Vec<_> = diags
            .iter()
            .filter(|d| d.code == "sudo-F02" && d.message.contains("setting contains"))
            .collect();
        assert_eq!(
            value_f02.len(),
            1,
            "a valid scope must NOT early-return -- the value check must still fire \
             its F02 for the malformed `#3` value; got {diags:?}"
        );
        assert_eq!(value_f02[0].severity, rulesteward_core::Severity::Fatal);
    }

    /// `Defaults:"#1000abc" !lecture` -- a QUOTED literal username (visudo rc=0,
    /// VALID). Guard test: correctness depends on the parser KEEPING the quotes in
    /// the scope binding (`"#1000abc"`), so `strip_prefix('#')` returns `None` and
    /// `is_malformed_gid_tail` never trips. A future parser change that strips the
    /// surrounding quotes would silently turn this valid line into a false-positive
    /// F02; lock the current behavior now.
    #[test]
    fn f02_defaults_user_scope_quoted_literal_name_no_f02() {
        let src = "root ALL=(ALL:ALL) ALL\nDefaults:\"#1000abc\" !lecture\n";
        let f02_diags: Vec<_> = lint(src)
            .into_iter()
            .filter(|d| d.code == "sudo-F02")
            .collect();
        assert!(
            f02_diags.is_empty(),
            "`Defaults:\"#1000abc\"` is a valid quoted literal username -- must NOT \
             fire F02 (the quote must survive so the `#` gate is not tripped); got \
             {f02_diags:?}"
        );
        // Pin the quote-retention that makes the above hold: the binding is kept
        // verbatim WITH its surrounding quotes.
        let f = files(src);
        let crate::ast::LineKind::Defaults(entry) = &f[0].lines[1].kind else {
            panic!("expected a Defaults entry; got {:?}", f[0].lines[1].kind);
        };
        assert_eq!(
            entry.scope,
            crate::ast::DefaultsScope::User("\"#1000abc\"".to_string()),
            "the quoted scope binding must retain its surrounding quotes"
        );
    }

    // -----------------------------------------------------------------------
    // Case 3: relative-path command
    // -----------------------------------------------------------------------

    /// `alice ALL = bin/ls` -- visudo rc=1, "expected a fully-qualified path name".
    ///
    /// `RuleSteward` parses this as `CmndItem::Cmnd("bin/ls")`. F02 must fire once.
    #[test]
    fn f02_relative_path_command_fires() {
        // Fixture: visudo -c rc=1, "expected a fully-qualified path name" at `bin/ls`.
        // Verified: Rocky Linux 9, sudo 1.9.17p2, 2026-06-30.
        let diags = lint("root ALL=(ALL:ALL) ALL\nalice ALL = bin/ls\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert_eq!(
            f02_diags.len(),
            1,
            "exactly one F02 for a relative-path command; got {diags:?}"
        );
        assert_eq!(f02_diags[0].severity, rulesteward_core::Severity::Fatal);
        assert!(
            f02_diags[0].message.contains("bin/ls")
                || f02_diags[0].message.to_lowercase().contains("relative")
                || f02_diags[0].message.to_lowercase().contains("path"),
            "F02 message must name the offending path or call it relative; got {:?}",
            f02_diags[0].message
        );
    }

    /// `alice ALL = /bin/ls some/rel/arg` -- fully-qualified command WITH a
    /// relative-looking ARGUMENT must NOT fire F02.
    ///
    /// Oracle: `alice ALL = /bin/ls some/rel/arg` -- visudo rc=0 (accepted). The
    /// relative-path check must inspect ONLY the command token (`/bin/ls`), not
    /// the argument tokens that follow. An impl that splits on whitespace and
    /// checks any word containing `/` but not starting with `/` would false-positive
    /// on `some/rel/arg`.
    ///
    /// This test is GREEN now (stub emits nothing) and MUST STAY GREEN after the
    /// correct implementation, which scopes the check to the command path only.
    #[test]
    fn f02_relative_arg_on_qualified_command_no_f02() {
        // Fixture: visudo -c rc=0 (accepted). The argument `some/rel/arg` is a
        // relative path but it is NOT the command token -- it is a command argument.
        // The relative-path check must NOT flag arguments, only the command itself.
        // Verified: Rocky Linux 9, sudo 1.9.17p2, 2026-06-30.
        let diags = lint("root ALL=(ALL:ALL) ALL\nalice ALL = /bin/ls some/rel/arg\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert!(
            f02_diags.is_empty(),
            "a fully-qualified command `/bin/ls` with a relative argument `some/rel/arg` \
             must NOT fire F02 -- only the command token is checked, not its arguments; \
             got {f02_diags:?}"
        );
    }

    /// `alice ALL = sub/dir/cmd` -- a multi-segment relative path also fires.
    #[test]
    fn f02_multi_segment_relative_path_fires() {
        // Fixture: same oracle case; any path containing `/` but not starting with
        // `/` is rejected by visudo.
        let diags = lint("root ALL=(ALL:ALL) ALL\nalice ALL = sub/dir/cmd\n");
        assert_eq!(
            f02_count("root ALL=(ALL:ALL) ALL\nalice ALL = sub/dir/cmd\n"),
            1,
            "multi-segment relative path also fires F02; got {diags:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Case 4: malformed group subject
    // -----------------------------------------------------------------------

    /// `%bad group ALL = ALL` -- visudo rc=1, syntax error at the space after `%bad`.
    ///
    /// `RuleSteward` parses `%bad` as the user and `group ALL` as the host list, so
    /// the structural parse succeeds. F02 must detect the malformed group token.
    #[test]
    fn f02_malformed_group_subject_fires() {
        // Fixture: visudo -c rc=1, "syntax error" at col 12 (the space in `%bad group`).
        // The `%` prefix indicates a Unix group; group names may not contain spaces.
        // Verified: Rocky Linux 9, sudo 1.9.17p2, 2026-06-30.
        let diags = lint("root ALL=(ALL:ALL) ALL\n%bad group ALL = ALL\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert_eq!(
            f02_diags.len(),
            1,
            "exactly one F02 for malformed group subject `%bad group`; got {diags:?}"
        );
        assert_eq!(f02_diags[0].severity, rulesteward_core::Severity::Fatal);
        assert!(
            f02_diags[0].message.contains("%bad")
                || f02_diags[0].message.to_lowercase().contains("group")
                || f02_diags[0].message.to_lowercase().contains("subject"),
            "F02 message must name the offending group token or position; got {:?}",
            f02_diags[0].message
        );
    }

    // -----------------------------------------------------------------------
    // MUST-NOT-REGRESS: valid files produce NO sudo-F02
    // -----------------------------------------------------------------------

    /// `User_Alias FOO = #1000` -- the `#1000` after `=` in an alias DEFINITION
    /// is a valid UID member per `visudo -x` (rc=0; only an "unused alias" warning).
    ///
    /// F02 must NOT fire: alias member positions are not command/Defaults positions.
    #[test]
    fn f02_alias_uid_member_is_valid_no_f02() {
        // Fixture: visudo -c rc=0 (warning "unused User_Alias FOO" only, not an error).
        // Verified: Rocky Linux 9, sudo 1.9.17p2, 2026-06-30.
        let diags = lint("root ALL=(ALL:ALL) ALL\nUser_Alias FOO = #1000\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert!(
            f02_diags.is_empty(),
            "a UID alias member `#1000` is valid and must produce no F02; got {f02_diags:?}"
        );
    }

    /// A plain valid sudoers file (root rule, Defaults, %wheel) produces no F02.
    #[test]
    fn f02_clean_file_no_f02() {
        // Fixture: visudo -c rc=0, "parsed OK".
        // Verified: Rocky Linux 9, sudo 1.9.17p2, 2026-06-30.
        let diags = lint(
            "root ALL=(ALL:ALL) ALL\nDefaults env_reset\nDefaults use_pty\n%wheel ALL=(ALL) ALL\n",
        );
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert!(
            f02_diags.is_empty(),
            "a clean valid sudoers file must produce no F02; got {f02_diags:?}"
        );
    }

    /// A fully-qualified command (`/bin/ls`) does NOT fire F02 (only relative paths do).
    #[test]
    fn f02_fully_qualified_path_is_valid_no_f02() {
        // Fixture: `alice ALL = /bin/ls` -- visudo -c rc=0. Not a relative path.
        let diags = lint("root ALL=(ALL:ALL) ALL\nalice ALL = /bin/ls\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert!(
            f02_diags.is_empty(),
            "a fully-qualified path `/bin/ls` must not fire F02; got {f02_diags:?}"
        );
    }

    /// A well-formed group subject (`%wheel`) is valid; F02 must not fire.
    #[test]
    fn f02_valid_group_subject_no_f02() {
        // Fixture: `%wheel ALL=(ALL) ALL` -- visudo -c rc=0. The group name has no space.
        let diags = lint("root ALL=(ALL:ALL) ALL\n%wheel ALL=(ALL) ALL\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert!(
            f02_diags.is_empty(),
            "`%wheel` is a valid group subject and must not fire F02; got {f02_diags:?}"
        );
    }

    /// `#1000 ALL = /bin/ls` -- `#1000` in USER (subject) position is a valid UID
    /// user-spec, NOT a command-position `#<digits>`. F02 must not fire.
    #[test]
    fn f02_uid_in_user_subject_position_is_valid_no_f02() {
        // Fixture: `#1000 ALL = /bin/ls` -- visudo -c rc=0. The #1000 is a UID
        // subject, which is valid. Same disambiguation the w01 test uses.
        let diags = lint("root ALL=(ALL:ALL) ALL\n#1000 ALL = /bin/ls\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert!(
            f02_diags.is_empty(),
            "`#1000` in user-subject position is valid and must not fire F02; got {f02_diags:?}"
        );
    }

    /// Multiple invalid tokens in separate lines fire once per line.
    #[test]
    fn f02_multiple_invalid_lines_fire_per_line() {
        // Two lines that each contain an invalid token; F02 should fire once per line.
        // Fixture: visudo rejects both lines (rc=1).
        let diags = lint(
            "root ALL=(ALL:ALL) ALL\n\
             alice ALL = /bin/ls #2\n\
             bob ALL = bin/ls\n",
        );
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert_eq!(
            f02_diags.len(),
            2,
            "two invalid lines must fire two F02 diagnostics; got {diags:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Defect 1 (FALSE POSITIVE fix): `!`-negated commands in Case 3
    // Grounded: Rocky Linux 9, sudo 1.9.17p2, 2026-06-30.
    // -----------------------------------------------------------------------

    /// `alice ALL = !/bin/su` -- a `!`-negated ABSOLUTE path is VALID.
    ///
    /// Oracle: visudo -cf rc=0 ("parsed OK").
    /// The `!` prefix is a command negation in sudoers; the underlying path `/bin/su`
    /// is absolute. Case 3 must NOT fire because stripping the leading `!` reveals an
    /// absolute path.
    ///
    /// Before fix: fires (FP) because `!/bin/su` does not start with `/`.
    #[test]
    fn f02_bang_negated_absolute_path_no_f02() {
        // Fixture: visudo -cf rc=0, "parsed OK".
        // `!/bin/su` is the standard sudoers syntax for "deny /bin/su".
        // Verified: Rocky Linux 9, sudo 1.9.17p2, 2026-06-30.
        let diags = lint("root ALL=(ALL:ALL) ALL\nalice ALL = !/bin/su\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert!(
            f02_diags.is_empty(),
            "`!/bin/su` is a valid negated absolute command and must NOT fire F02; got {f02_diags:?}"
        );
    }

    /// `alice ALL = /bin/ls, !/bin/su` -- list form with a negated absolute path.
    ///
    /// Oracle: visudo -cf rc=0 ("parsed OK").
    /// The comma-separated list containing `/bin/ls` (allow) and `!/bin/su` (deny)
    /// is a standard sudoers pattern. Case 3 must NOT fire on `!/bin/su`.
    ///
    /// Before fix: fires (FP) because `!/bin/su` does not start with `/`.
    #[test]
    fn f02_bang_negated_absolute_in_list_no_f02() {
        // Fixture: visudo -cf rc=0, "parsed OK".
        // Verified: Rocky Linux 9, sudo 1.9.17p2, 2026-06-30.
        let diags = lint("root ALL=(ALL:ALL) ALL\nalice ALL = /bin/ls, !/bin/su\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert!(
            f02_diags.is_empty(),
            "`/bin/ls, !/bin/su` list with negated absolute must NOT fire F02; got {f02_diags:?}"
        );
    }

    /// `alice ALL = !bin/su` -- `!`-negated RELATIVE path MUST still fire F02.
    ///
    /// Oracle: visudo -cf rc=1, "expected a fully-qualified path name".
    /// Stripping the `!` reveals `bin/su` which is relative. F02 must fire.
    ///
    /// This test is GREEN before and after the fix (the fix must preserve this).
    #[test]
    fn f02_bang_negated_relative_path_fires() {
        // Fixture: visudo -cf rc=1, "expected a fully-qualified path name".
        // `!bin/su` is a negated relative path -- visudo rejects it.
        // Verified: Rocky Linux 9, sudo 1.9.17p2, 2026-06-30.
        let diags = lint("root ALL=(ALL:ALL) ALL\nalice ALL = !bin/su\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert_eq!(
            f02_diags.len(),
            1,
            "`!bin/su` is a negated relative path and MUST fire F02; got {diags:?}"
        );
        assert_eq!(f02_diags[0].severity, rulesteward_core::Severity::Fatal);
    }

    // -----------------------------------------------------------------------
    // Defect 2 (FALSE NEGATIVE fix): invalid chars in `%group` name (Case 4)
    //
    // Grounded char class (Rocky Linux 9, sudo 1.9.17p2, 2026-06-30):
    //   REJECTED in group name: `!`, `(`, `)`, space, tab (and `:`, `=` which
    //   cause Malformed/F01 before F02 can fire -- those are not F02 cases).
    //   ACCEPTED in group name: letters, digits, `_`, `-`, `.`, `/`, `@`, `+`,
    //   `~`, `\`, `[`, `,`, `#` (as `%#NNN` GID form).
    // -----------------------------------------------------------------------

    /// `%bad!group ALL = ALL` -- visudo rc=1, "syntax error" at col 10.
    ///
    /// Oracle: `!` is not a valid char in a sudoers group name. The parser produces
    /// `UserSpec` with `users=["%bad!group"]` (the `!` is inside the token, not
    /// whitespace-split), so it reaches F02 as a clean `UserSpec`. Case 4 must fire.
    ///
    /// Before fix: Case 4 only checks embedded whitespace -- stays silent (FN).
    #[test]
    fn f02_group_name_with_bang_fires() {
        // Fixture: visudo -cf rc=1, "syntax error" at the `!` in `%bad!group`.
        // Verified: Rocky Linux 9, sudo 1.9.17p2, 2026-06-30.
        let diags = lint("root ALL=(ALL:ALL) ALL\n%bad!group ALL = ALL\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert_eq!(
            f02_diags.len(),
            1,
            "`%bad!group` has `!` in the group name and must fire exactly one F02; got {diags:?}"
        );
        assert_eq!(f02_diags[0].severity, rulesteward_core::Severity::Fatal);
        assert!(
            f02_diags[0].message.contains("%bad!group")
                || f02_diags[0].message.to_lowercase().contains("group")
                || f02_diags[0].message.to_lowercase().contains("subject"),
            "F02 message must name the group token; got {:?}",
            f02_diags[0].message
        );
    }

    /// `%bad(group ALL = ALL` -- visudo rc=1, "syntax error" (paren in group name).
    ///
    /// Oracle: `(` is not valid in a sudoers group name. The parser produces
    /// `UserSpec` with `users=["%bad(group"]`, so F02 Case 4 must fire.
    #[test]
    fn f02_group_name_with_open_paren_fires() {
        // Fixture: visudo -cf rc=1, "syntax error" at the `(` in `%bad(group`.
        // Verified: Rocky Linux 9, sudo 1.9.17p2, 2026-06-30.
        let diags = lint("root ALL=(ALL:ALL) ALL\n%bad(group ALL = ALL\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert_eq!(
            f02_diags.len(),
            1,
            "`%bad(group` has `(` in the group name and must fire exactly one F02; got {diags:?}"
        );
        assert_eq!(f02_diags[0].severity, rulesteward_core::Severity::Fatal);
    }

    /// `%bad)group ALL = ALL` -- visudo rc=1, "syntax error" (close-paren in group name).
    #[test]
    fn f02_group_name_with_close_paren_fires() {
        // Fixture: visudo -cf rc=1, "syntax error" at the `)` in `%bad)group`.
        // Verified: Rocky Linux 9, sudo 1.9.17p2, 2026-06-30.
        let diags = lint("root ALL=(ALL:ALL) ALL\n%bad)group ALL = ALL\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert_eq!(
            f02_diags.len(),
            1,
            "`%bad)group` has `)` in the group name and must fire exactly one F02; got {diags:?}"
        );
        assert_eq!(f02_diags[0].severity, rulesteward_core::Severity::Fatal);
    }

    // -----------------------------------------------------------------------
    // Round-3 Fix 3: group-name char class completed via exhaustive grounding.
    //
    // Exhaustive visudo -cf probe of every printable-ASCII char CH in the middle of
    // a `%bad<CH>group` SUBJECT token (rockylinux:9, sudo 1.9.17p2, 2026-06-30):
    //   REJECTED (rc=1): `!  "  #  (  )  :  =  >`  (8 chars)
    //   ACCEPTED (rc=0): the other 86 printable-ASCII chars AND non-ASCII (e.g. `é`).
    // Of the 8 rejected, the parser marks `#`, `:`, `=` as Malformed -> caught by
    // sudo-F01, so they never reach F02. The 5 that reach F02 as a clean UserSpec
    // are exactly `! ( ) > "`. Round-2 caught only `! ( )`; `>` and `"` were missed.
    // -----------------------------------------------------------------------

    /// `%bad>group ALL = ALL` -- visudo rc=1, "syntax error" (`>` in group name).
    ///
    /// Oracle: `>` is invalid in a sudoers group name (rc=1). The parser keeps a
    /// clean `UserSpec` with `users=["%bad>group"]`, so F02 Case 4 must fire.
    /// Round-2 missed this (`>` was not in the denylist).
    #[test]
    fn f02_group_name_with_gt_fires() {
        // Fixture: visudo -cf rc=1, "syntax error" at the `>` in `%bad>group`.
        // Verified: rockylinux:9, sudo 1.9.17p2, 2026-06-30 (exhaustive probe).
        let diags = lint("root ALL=(ALL:ALL) ALL\n%bad>group ALL = ALL\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert_eq!(
            f02_diags.len(),
            1,
            "`%bad>group` has `>` in the group name and must fire exactly one F02; got {diags:?}"
        );
        assert_eq!(f02_diags[0].severity, rulesteward_core::Severity::Fatal);
    }

    /// `%bad"group ALL = ALL` -- visudo rc=1 (`"` in group name).
    ///
    /// Oracle: `"` is invalid in a sudoers group name (rc=1). The parser keeps a
    /// clean `UserSpec` with `users=["%bad\"group"]`, so F02 Case 4 must fire.
    /// Round-2 missed this (`"` was not in the denylist).
    #[test]
    fn f02_group_name_with_dquote_fires() {
        // Fixture: visudo -cf rc=1 at the `"` in `%bad"group`.
        // Verified: rockylinux:9, sudo 1.9.17p2, 2026-06-30 (exhaustive probe).
        let diags = lint("root ALL=(ALL:ALL) ALL\n%bad\"group ALL = ALL\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert_eq!(
            f02_diags.len(),
            1,
            "`%bad\"group` has `\"` in the group name and must fire exactly one F02; got {diags:?}"
        );
        assert_eq!(f02_diags[0].severity, rulesteward_core::Severity::Fatal);
    }

    /// `%bad<group ALL = ALL` -- visudo rc=0; `<` is ACCEPTED (pins the `<`/`>`
    /// asymmetry: `<` valid, `>` invalid). Must NOT fire F02.
    #[test]
    fn f02_group_name_with_lt_no_f02() {
        // Fixture: visudo -cf rc=0, "parsed OK". `<` is a valid group-name char even
        // though the mirror `>` is not (grounded asymmetry).
        // Verified: rockylinux:9, sudo 1.9.17p2, 2026-06-30 (exhaustive probe).
        let diags = lint("root ALL=(ALL:ALL) ALL\n%bad<group ALL = ALL\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert!(
            f02_diags.is_empty(),
            "`%bad<group` is valid (`<` accepted; asymmetric with `>`) -- must NOT fire F02; got {f02_diags:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Defect 2: valid sibling guards -- these must NOT fire F02
    // -----------------------------------------------------------------------

    /// `%bad/group ALL = ALL` -- visudo rc=0; `/` is a valid char in a group name.
    #[test]
    fn f02_group_name_with_slash_no_f02() {
        // Fixture: visudo -cf rc=0, "parsed OK".
        // `/` is valid in group names (e.g. system/admin groups on some distros).
        // Verified: Rocky Linux 9, sudo 1.9.17p2, 2026-06-30.
        let diags = lint("root ALL=(ALL:ALL) ALL\n%bad/group ALL = ALL\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert!(
            f02_diags.is_empty(),
            "`%bad/group` is valid (/ accepted in group name) -- must NOT fire F02; got {f02_diags:?}"
        );
    }

    /// `%bad@group ALL = ALL` -- visudo rc=0; `@` is valid in group names.
    #[test]
    fn f02_group_name_with_at_no_f02() {
        // Fixture: visudo -cf rc=0, "parsed OK".
        // Verified: Rocky Linux 9, sudo 1.9.17p2, 2026-06-30.
        let diags = lint("root ALL=(ALL:ALL) ALL\n%bad@group ALL = ALL\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert!(
            f02_diags.is_empty(),
            "`%bad@group` is valid (@ accepted in group name) -- must NOT fire F02; got {f02_diags:?}"
        );
    }

    /// `%1000abc ALL = ALL` -- visudo rc=0; digits + alpha are valid in group names.
    #[test]
    fn f02_group_name_alphanumeric_no_f02() {
        // Fixture: visudo -cf rc=0, "parsed OK".
        // Verified: Rocky Linux 9, sudo 1.9.17p2, 2026-06-30.
        let diags = lint("root ALL=(ALL:ALL) ALL\n%1000abc ALL = ALL\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert!(
            f02_diags.is_empty(),
            "`%1000abc` is valid (digits+alpha in group name) -- must NOT fire F02; got {f02_diags:?}"
        );
    }

    /// `%#1000 ALL = ALL` -- visudo rc=0; `%#NNN` is the GID form, valid.
    ///
    /// This is distinct from the `%bad!group` user token: `%#1000` starts with `%#`
    /// and is a GID-referenced group subject. F02 must not fire.
    #[test]
    fn f02_group_gid_form_no_f02() {
        // Fixture: visudo -cf rc=0, "parsed OK".
        // `%#1000` means "the group with GID 1000" -- a valid sudoers syntax.
        // Verified: Rocky Linux 9, sudo 1.9.17p2, 2026-06-30.
        let diags = lint("root ALL=(ALL:ALL) ALL\n%#1000 ALL = ALL\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert!(
            f02_diags.is_empty(),
            "`%#1000` (GID group form) is valid -- must NOT fire F02; got {f02_diags:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Defect 3: has_hash_digits simplification / mutation kill tests
    //
    // Reachability analysis (2026-06-30, refined round-3):
    //   has_hash_digits is called on:
    //     (a) individual CmndSpec command tokens (comma-split BEFORE call, so no `,`
    //         in the string at call time)
    //     (b) Defaults setting name / value strings (also comma-split before call)
    //   The `,` preceding-char branch is DEAD CODE in both call sites and is removed.
    //   The `%` preceding-char branch is REACHABLE and NOT equivalent to whitespace:
    //   for `/bin/prog %#2` the byte immediately before `#` is `%`, so only a `%` arm
    //   returns true (round-3 restored it after round-2 wrongly dropped it -- see the
    //   f02_percent_hash_digits_* tests above). visudo rejects `%#digits` in both
    //   command and Defaults-value positions (rc=1, grounded rockylinux:9 2026-06-30).
    // -----------------------------------------------------------------------

    /// `/bin/ls2` -- the digit `2` appears IN the path (not after `#`). Must not fire.
    ///
    /// This test kills the `&& -> ||` mutant on line 207: if the condition were `||`,
    /// any `#` in the string (even not followed by digits) would fire; this path
    /// has no `#` at all, so it stays silent regardless. But combined with the
    /// `#` assertion below, it pins that the digit check is necessary.
    #[test]
    fn f02_digit_in_path_no_hash_no_f02() {
        // Fixture: visudo -cf rc=0. `/bin/ls2` is a valid absolute path.
        // Kills the && -> || mutant: the `||` form would check if `bytes[i] == b'#'`
        // OR if the next byte is a digit -- but we need BOTH. This path (/bin/ls2)
        // has no `#`, so a byte at position 6 is `2` not `#`; neither condition
        // fires alone.
        let diags = lint("root ALL=(ALL:ALL) ALL\nalice ALL = /bin/ls2\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert!(
            f02_diags.is_empty(),
            "`/bin/ls2` has a digit but no `#`-prefix -- must NOT fire F02; got {f02_diags:?}"
        );
    }

    /// `alice ALL = /bin/ls #2` -- `#2` preceded by whitespace in a command token.
    ///
    /// This test (already present as `f02_hash_digits_in_command_position_fires`)
    /// kills the `p == b','`->`!=` and the `,`/`%` `|| -> &&` mutants by verifying
    /// that whitespace-preceded `#digits` DOES fire. The simplified `has_hash_digits`
    /// (whitespace + start-of-string only) fires correctly via the whitespace arm.
    ///
    /// NOTE: this duplicates `f02_hash_digits_in_command_position_fires` above to make
    /// the killing intent explicit for Defect 3.
    #[test]
    fn f02_hash_digits_after_whitespace_fires_kills_survivors() {
        // Fixture: visudo -cf rc=1.
        // Verified: Rocky Linux 9, sudo 1.9.17p2, 2026-06-30.
        // Kills: `p == b','`->`!=` (the negated comma check would suppress whitespace
        // cases because b' ' != b','); `|| -> &&` (whitespace-only would need BOTH
        // comma and whitespace, never true for a space-preceded `#`).
        assert_eq!(
            f02_count("root ALL=(ALL:ALL) ALL\nalice ALL = /bin/ls #2\n"),
            1,
            "whitespace-preceded `#2` in command must fire F02"
        );
        // Also confirm the bare-at-start case (kills the start-of-string -> false mutant):
        assert_eq!(
            f02_count("root ALL=(ALL:ALL) ALL\nalice ALL = #2\n"),
            1,
            "`#2` at start of command token must fire F02"
        );
    }

    // -----------------------------------------------------------------------
    // Round-3 Fix 1 (REGRESSION): `%#<digits>` glued in command / Defaults-value
    // must fire F02. Round-2 dropped the `%` preceding-char arm of has_hash_digits
    // on the (wrong) claim it was caught by the whitespace arm. It is NOT: for
    // `/bin/prog %#2` the byte immediately before `#` is `%`, not whitespace, so
    // only a `%`-preceding arm reaches the return. Parent commit 14b13d2 fired
    // correctly; these tests restore + pin that behavior.
    //
    // Grounding (rockylinux:9, sudo 1.9.17p2, 2026-06-30, visudo -cf):
    //   `alice ALL = /bin/prog %#2`   -> rc=1 (syntax error at col 24)
    //   `Defaults passprompt=x%#2`    -> rc=1 (col 23)
    // -----------------------------------------------------------------------

    /// `alice ALL = /bin/prog %#2` -- `%#2` glued in a command arg. visudo rc=1.
    ///
    /// `strip_inline_comment` keeps `#2` because it is `#<digit>` preceded by `%`
    /// (Exception 2, a GID token). The command reaches the AST as
    /// `/bin/prog %#2`; the byte before `#` is `%` (not whitespace), so this only
    /// fires if `has_hash_digits` has the `%`-preceding arm.
    #[test]
    fn f02_percent_hash_digits_in_command_fires() {
        // Fixture: visudo -cf rc=1, "syntax error" at the `%#2`.
        // Verified: rockylinux:9, sudo 1.9.17p2, 2026-06-30.
        let diags = lint("root ALL=(ALL:ALL) ALL\nalice ALL = /bin/prog %#2\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert_eq!(
            f02_diags.len(),
            1,
            "`/bin/prog %#2` (%-preceded #digits in command) must fire exactly one F02; got {diags:?}"
        );
        assert_eq!(f02_diags[0].severity, rulesteward_core::Severity::Fatal);
    }

    /// `Defaults passprompt=x%#2` -- `%#2` glued in a Defaults value. visudo rc=1.
    ///
    /// `strip_inline_comment` keeps `#2` (preceded by `%`), so the value reaches the
    /// AST as `x%#2`; the byte before `#` is `%`. Fires only with the `%`-preceding arm.
    #[test]
    fn f02_percent_hash_digits_in_defaults_value_fires() {
        // Fixture: visudo -cf rc=1 at col 23.
        // Verified: rockylinux:9, sudo 1.9.17p2, 2026-06-30.
        let diags = lint("root ALL=(ALL:ALL) ALL\nDefaults passprompt=x%#2\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert_eq!(
            f02_diags.len(),
            1,
            "`Defaults passprompt=x%#2` (%-preceded #digits in value) must fire exactly one F02; got {diags:?}"
        );
        assert_eq!(f02_diags[0].severity, rulesteward_core::Severity::Fatal);
    }

    // -----------------------------------------------------------------------
    // Round-3 Fix 2: kill the `has_hash_digits` `&& -> ||` mutation survivor
    // (the `bytes[i] == b'#' && next_is_ascii_digit` guard). Two grounded rc=0
    // inputs distinguish `&&` from `||` where the CORRECT `&&` stays silent but
    // `||` wrongly fires:
    //   (Case A) a `#` NOT followed by a digit at a whitespace-preceded slot.
    //   (Case B) a digit NOT preceded by `#` at a whitespace-preceded slot.
    // -----------------------------------------------------------------------

    /// Case A: `Defaults passprompt="a #x b"` -- a quoted `#` NOT followed by a digit.
    ///
    /// Oracle: visudo -cf rc=0 (a `#` inside a double-quoted value is literal, and
    /// `#x` is not a `#<digits>` token). `strip_inline_comment` KEEPS the quoted `#`
    /// (Exception 3), so `has_hash_digits` receives a string containing `#x`. The
    /// correct `&&` form: `#`==`#` (true) AND next-is-digit (`x`, false) -> no fire.
    /// The `||` mutant: `#`==`#` (true) OR ... -> true -> would WRONGLY fire F02.
    #[test]
    fn f02_quoted_hash_nondigit_no_f02_kills_and_to_or() {
        // Fixture: visudo -cf rc=0, "parsed OK".
        // Verified: rockylinux:9, sudo 1.9.17p2, 2026-06-30.
        // Kills `has_hash_digits` `&& -> ||`: a `#` reaches the fn but is followed by
        // a non-digit; only `&&` stays silent, `||` fires.
        let diags = lint("root ALL=(ALL:ALL) ALL\nDefaults passprompt=\"a #x b\"\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert!(
            f02_diags.is_empty(),
            "a quoted `#x` (# not followed by a digit) is visudo-valid -- must NOT fire F02; got {f02_diags:?}"
        );
    }

    /// Case B: `alice ALL = /bin/prog a5` -- a digit `5` NOT preceded by `#`, at a
    /// whitespace-preceded slot (`a` follows the space, `5` follows `a`).
    ///
    /// Oracle: visudo -cf rc=0 (`a5` is a free-form command argument). The string
    /// `/bin/prog a5` reaches `has_hash_digits` (no `#` stripped). The correct `&&`:
    /// no byte is `#`, so never fires. The `||` mutant: at the `a` slot (preceded by
    /// whitespace, `prev_ok=true`) the next byte `5` IS a digit, so `||` returns true
    /// -> would WRONGLY fire F02.
    #[test]
    fn f02_digit_after_space_no_hash_no_f02_kills_and_to_or() {
        // Fixture: visudo -cf rc=0, "parsed OK". A command with a `a5` argument.
        // Verified: rockylinux:9, sudo 1.9.17p2, 2026-06-30.
        // Kills `has_hash_digits` `&& -> ||`: a digit at a whitespace-preceded slot+1
        // makes the `||` right-hand side true even though no `#` is present.
        let diags = lint("root ALL=(ALL:ALL) ALL\nalice ALL = /bin/prog a5\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert!(
            f02_diags.is_empty(),
            "`/bin/prog a5` (digit not preceded by `#`) is visudo-valid -- must NOT fire F02; got {f02_diags:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Round-4 Fix: pure-GID guard over-exempts `#`-prefix group names
    //
    // The guard `!name.starts_with('#')` was meant to exempt the valid pure-GID
    // form `%#1000` from the denylist check. But it over-exempts ANY name that
    // starts with `#`, including `#1000>x`, `#1000!x`, etc. -- these have a
    // denylist char after the `#<digits>` prefix and are visudo-rejected (rc=1).
    //
    // Grounding (rockylinux:9, sudo 1.9.17p2, 2026-06-30, visudo -cf):
    //   `%#1000>x ALL = ALL`  -> rc=1 (syntax error at col 7, the `>`)
    //   `%#1000!x ALL = ALL`  -> rc=1 (syntax error at col 10, the `!`)
    //   `%#1000 ALL = ALL`    -> rc=0 (valid pure-GID form, must stay silent)
    //   `%#1000abc ALL = ALL` -> rc=1 (syntax error; no denylist char present
    //                                  so out of scope for this fix -- the
    //                                  `#<digits><alpha>` class is a separate gap)
    //
    // The correct exemption: pure-GID form = `#` followed by one or more ASCII
    // digits and NOTHING else.
    // -----------------------------------------------------------------------

    /// `%#1000>x ALL = ALL` -- visudo rc=1; `>` follows the digits in a `#`-prefix
    /// group name. The old guard `!name.starts_with('#')` exempts this and stays
    /// silent (FALSE NEGATIVE). The fixed guard recognises `#1000>x` as NOT a pure
    /// GID (contains a non-digit after `#`) and runs the denylist, which finds `>`.
    ///
    /// Oracle: rockylinux:9, sudo 1.9.17p2, visudo -cf rc=1 "syntax error" at col 7.
    #[test]
    fn f02_hash_prefix_group_name_with_gt_fires() {
        // Fixture: visudo -cf rc=1. Verified: rockylinux:9, sudo 1.9.17p2, 2026-06-30.
        // RED before fix (old `!starts_with('#')` exempts `#1000>x` entirely).
        // GREEN after fix (`is_pure_gid` is false for `#1000>x` -> denylist fires on `>`).
        let diags = lint("root ALL=(ALL:ALL) ALL\n%#1000>x ALL = ALL\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert_eq!(
            f02_diags.len(),
            1,
            "`%#1000>x` has `>` in group name after digits -- must fire exactly one F02; got {diags:?}"
        );
        assert_eq!(f02_diags[0].severity, rulesteward_core::Severity::Fatal);
    }

    /// `%#1000!x ALL = ALL` -- visudo rc=1; `!` follows the digits.
    ///
    /// Companion to the `>` case: same over-exemption in the old guard.
    ///
    /// Oracle: rockylinux:9, sudo 1.9.17p2, visudo -cf rc=1 "syntax error" at col 10.
    #[test]
    fn f02_hash_prefix_group_name_with_bang_fires() {
        // Fixture: visudo -cf rc=1. Verified: rockylinux:9, sudo 1.9.17p2, 2026-06-30.
        // RED before fix; GREEN after fix (`is_pure_gid` false -> denylist finds `!`).
        let diags = lint("root ALL=(ALL:ALL) ALL\n%#1000!x ALL = ALL\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert_eq!(
            f02_diags.len(),
            1,
            "`%#1000!x` has `!` in group name after digits -- must fire exactly one F02; got {diags:?}"
        );
        assert_eq!(f02_diags[0].severity, rulesteward_core::Severity::Fatal);
    }

    /// `%#1000 ALL = ALL` -- visudo rc=0; pure-GID form MUST stay silent after the fix.
    ///
    /// The fix must preserve the pure-GID exemption exactly: `is_pure_gid` is true
    /// for `#1000` (all-digit rest), so the denylist does NOT run. No F02.
    ///
    /// NOTE: already covered by `f02_group_gid_form_no_f02` above; this companion
    /// test makes the Round-4 must-not-regress intent explicit.
    #[test]
    fn f02_pure_gid_group_still_silent_after_fix() {
        // Fixture: visudo -cf rc=0. Verified: rockylinux:9, sudo 1.9.17p2, 2026-06-30.
        // GREEN before AND after fix.
        let diags = lint("root ALL=(ALL:ALL) ALL\n%#1000 ALL = ALL\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert!(
            f02_diags.is_empty(),
            "`%#1000` is the valid pure-GID form -- must NOT fire F02 after the fix; got {f02_diags:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Issue #375: out-of-scope tail (Case-4/Case-5 completeness pass)
    //
    // Three visudo-rejected shapes that sit OUTSIDE the four documented F02
    // positions above (deferred from #346's post-GREEN adversarial review):
    //   1. Runas-position group defects: a malformed `%group`/`%#gid` token
    //      inside a `(...)` runas spec (RunasSpec.users / RunasSpec.groups),
    //      which check_user_spec's Case-4 walk never scans today (it only
    //      inspects UserSpec.users, the SUBJECT list).
    //   2. Lone `!` command with no path: `CmndItem::Cmnd("!")`, a negation
    //      with nothing to negate.
    //   3. `%#<digits><non-digit>`: a GID-looking name whose digit run is
    //      followed by a non-digit, non-denylist char (e.g. `1000abc`) -- the
    //      existing denylist `{! ( ) > "}` never matches plain alnum tails.
    //
    // All fixtures grounded via local `visudo -cf` 1.9.17p2 (matches the
    // rockylinux:9 sudo version this file's other oracle comments cite),
    // 2026-07-02. See raw grounding transcript in the task's GROUNDING section.
    // -----------------------------------------------------------------------

    // --- Shape 1: runas-position group defects -----------------------------

    /// `alice ALL = (grpbad!x) /bin/ls` -- issue #375's literal example.
    ///
    /// Oracle: `visudo -cf` rc=1, "syntax error" at the `!` (col 20). The `!` sits
    /// inside the `RUNAS_USER` token (before any `:`), so `RunasSpec.users =
    /// ["grpbad!x"]`. `check_user_spec`'s Case-4 walk only inspects
    /// `UserSpec.users` (the SUBJECT list before ` = `), never `CmndSpec.runas`,
    /// so today this fires ZERO sudo-F02 diagnostics (RED).
    #[test]
    fn f02_runas_user_position_bang_in_name_fires() {
        // Fixture: visudo -cf rc=1, "syntax error" at the `!` in `(grpbad!x)`.
        // Verified locally: visudo 1.9.17p2, 2026-07-02 (matches this file's
        // rockylinux:9 sudo 1.9.17p2 oracle baseline).
        let diags = lint("root ALL=(ALL:ALL) ALL\nalice ALL = (grpbad!x) /bin/ls\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert_eq!(
            f02_diags.len(),
            1,
            "a `!` inside a runas-USER-position token is visudo-rejected and must fire \
             exactly one F02; got {diags:?}"
        );
        assert_eq!(f02_diags[0].severity, rulesteward_core::Severity::Fatal);
    }

    /// `alice ALL = (%grpbad!x) /bin/ls` -- `%group` form (`RUNAS_USER` position)
    /// with a Case-4 denylist char (`!`) inside the group name.
    ///
    /// Oracle: `visudo -cf` rc=1, "syntax error" at the `!`. This is the direct
    /// runas-position analog of the existing SUBJECT-position
    /// `f02_group_name_with_bang_fires` test -- same denylist char, different
    /// AST field (`RunasSpec.users` instead of `UserSpec.users`).
    #[test]
    fn f02_runas_user_position_pct_group_bang_fires() {
        // Fixture: visudo -cf rc=1, "syntax error" at the `!` in `(%grpbad!x)`.
        // Verified locally: visudo 1.9.17p2, 2026-07-02.
        let diags = lint("root ALL=(ALL:ALL) ALL\nalice ALL = (%grpbad!x) /bin/ls\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert_eq!(
            f02_diags.len(),
            1,
            "a `%group` runas-USER token with `!` in the name must fire exactly one F02; \
             got {diags:?}"
        );
        assert_eq!(f02_diags[0].severity, rulesteward_core::Severity::Fatal);
    }

    /// `alice ALL = (root:grp!x) /bin/ls` -- a bare (non-`%`) name in the
    /// `RUNAS_GROUP` position (after `:`) with a Case-4 denylist char (`!`).
    ///
    /// Oracle: `visudo -cf` rc=1, "syntax error" at the `!`. `RunasSpec.groups =
    /// ["grp!x"]`; the walk must cover BOTH `RunasSpec.users` and
    /// `RunasSpec.groups`, not just the pre-colon list.
    #[test]
    fn f02_runas_group_position_bang_in_name_fires() {
        // Fixture: visudo -cf rc=1, "syntax error" at the `!` in `(root:grp!x)`.
        // Verified locally: visudo 1.9.17p2, 2026-07-02.
        let diags = lint("root ALL=(ALL:ALL) ALL\nalice ALL = (root:grp!x) /bin/ls\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert_eq!(
            f02_diags.len(),
            1,
            "a `!` inside a runas-GROUP-position (post-colon) token must fire exactly \
             one F02; got {diags:?}"
        );
        assert_eq!(f02_diags[0].severity, rulesteward_core::Severity::Fatal);
    }

    /// `alice ALL = (root : %grp) /bin/ls` -- issue #375's literal example.
    ///
    /// Oracle: `visudo -cf` rc=1, "syntax error" at `%grp` (col 21). Grounded
    /// separately (no embedded whitespace, no denylist char):
    /// `alice ALL = (root:%grp) /bin/ls` is ALSO rc=1 at the `%grp` token, and
    /// `alice ALL = (root:grp) /bin/ls` (same name, no `%`) is rc=0 "parsed OK".
    /// So the defect here is the bare `%`-PREFIX ITSELF inside the `RUNAS_GROUP`
    /// position -- unlike the pre-colon `RUNAS_USER` list (where `%group` is the
    /// normal, valid way to name a group), the post-colon `RUNAS_GROUP` list
    /// already denotes groups, so a `%` prefix there is categorically invalid
    /// regardless of the name's contents. This is DISTINCT from the Case-4(b)
    /// denylist-char mechanism (`grp` alone contains no denylist char) --
    /// implementer: this is a THIRD mechanism, not a reuse of the denylist walk.
    #[test]
    fn f02_runas_group_position_pct_prefix_fires() {
        // Fixture: visudo -cf rc=1, "syntax error" at `%grp` in `(root : %grp)`.
        // Verified locally: visudo 1.9.17p2, 2026-07-02.
        let diags = lint("root ALL=(ALL:ALL) ALL\nalice ALL = (root : %grp) /bin/ls\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert_eq!(
            f02_diags.len(),
            1,
            "a bare `%`-prefixed token in the RUNAS_GROUP (post-colon) position is \
             visudo-rejected regardless of denylist chars and must fire exactly one \
             F02; got {diags:?}"
        );
        assert_eq!(f02_diags[0].severity, rulesteward_core::Severity::Fatal);
    }

    /// `alice ALL = (root) /bin/ls` -- a plain runas user, no groups. Valid.
    #[test]
    fn f02_runas_user_position_plain_no_f02() {
        // Fixture: visudo -cf rc=0, "parsed OK".
        // Verified locally: visudo 1.9.17p2, 2026-07-02.
        let diags = lint("root ALL=(ALL:ALL) ALL\nalice ALL = (root) /bin/ls\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert!(
            f02_diags.is_empty(),
            "`(root)` is a valid runas-user spec -- must NOT fire F02; got {f02_diags:?}"
        );
    }

    /// `alice ALL = (root:wheel) /bin/ls` -- a bare (non-`%`) group name after
    /// `:`. Valid: the `RUNAS_GROUP` position never uses a `%` prefix.
    #[test]
    fn f02_runas_group_position_bare_name_no_f02() {
        // Fixture: visudo -cf rc=0, "parsed OK".
        // Verified locally: visudo 1.9.17p2, 2026-07-02.
        let diags = lint("root ALL=(ALL:ALL) ALL\nalice ALL = (root:wheel) /bin/ls\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert!(
            f02_diags.is_empty(),
            "`(root:wheel)` is a valid runas group-list entry -- must NOT fire F02; \
             got {f02_diags:?}"
        );
    }

    /// `alice ALL = (%wheel) /bin/ls` -- `%group` form in the `RUNAS_USER`
    /// position with a well-formed name. Valid.
    #[test]
    fn f02_runas_user_position_pct_group_valid_no_f02() {
        // Fixture: visudo -cf rc=0, "parsed OK".
        // Verified locally: visudo 1.9.17p2, 2026-07-02.
        let diags = lint("root ALL=(ALL:ALL) ALL\nalice ALL = (%wheel) /bin/ls\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert!(
            f02_diags.is_empty(),
            "`(%wheel)` is a valid runas-user group reference -- must NOT fire F02; \
             got {f02_diags:?}"
        );
    }

    /// `alice ALL = (root:#1000) /bin/ls` -- pure-GID form in the `RUNAS_GROUP`
    /// position (no `%` prefix needed for a GID either). Valid.
    #[test]
    fn f02_runas_group_position_gid_form_no_f02() {
        // Fixture: visudo -cf rc=0, "parsed OK".
        // Verified locally: visudo 1.9.17p2, 2026-07-02.
        let diags = lint("root ALL=(ALL:ALL) ALL\nalice ALL = (root:#1000) /bin/ls\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert!(
            f02_diags.is_empty(),
            "`(root:#1000)` is a valid runas GID-group entry -- must NOT fire F02; \
             got {f02_diags:?}"
        );
    }

    /// `alice ALL = (%wheel:root) /bin/ls` -- both runas lists populated and
    /// valid (a `%group` runas-user, a bare-name runas-group). Valid.
    #[test]
    fn f02_runas_both_positions_valid_no_f02() {
        // Fixture: visudo -cf rc=0, "parsed OK".
        // Verified locally: visudo 1.9.17p2, 2026-07-02.
        let diags = lint("root ALL=(ALL:ALL) ALL\nalice ALL = (%wheel:root) /bin/ls\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert!(
            f02_diags.is_empty(),
            "`(%wheel:root)` has both a valid runas-user and runas-group -- must NOT \
             fire F02; got {f02_diags:?}"
        );
    }

    // Post-GREEN adversarial-impl finding: the GID-tail (Rule 3) structural check
    // fires for a SUBJECT-position `%#1000abc` (see
    // `f02_gid_form_digits_then_letters_fires` in Shape 3 below) but NOT for the
    // SAME token in the RUNAS-USER position -- `check_runas`'s `runas.users` loop
    // only runs the denylist (`first_invalid_char`), which finds no denylist char
    // in `%#1000abc` and stays silent. These tests pin the consistency: the
    // GID-tail defect must fire in the runas-user position too.

    /// `alice ALL = (%#1000abc) /bin/ls` -- the runas-USER analog of the
    /// subject-position `f02_gid_form_digits_then_letters_fires`: a `%#`-GID
    /// token whose digit run is followed by letters, with no denylist char.
    ///
    /// Oracle: `visudo -cf` rc=1, "syntax error" at `abc` (col 20). The token
    /// survives `strip_inline_comment` (the `#` is preceded by `%` and followed
    /// by a digit, so it is kept as a GID token) and reaches `check_runas` as a
    /// clean `RunasSpec.users = ["%#1000abc"]`. RED today: the runas-user loop
    /// only checks the denylist, and `1000abc` has no denylist char, so F02 is
    /// silent -- the GID-tail structural check is not applied in this position.
    #[test]
    fn f02_runas_user_gid_form_digits_then_letters_fires() {
        // Fixture: visudo -cf rc=1, "syntax error" at `abc` in `(%#1000abc)`.
        // Verified locally: visudo 1.9.17p2, 2026-07-02.
        let diags = lint("root ALL=(ALL:ALL) ALL\nalice ALL = (%#1000abc) /bin/ls\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert_eq!(
            f02_diags.len(),
            1,
            "`(%#1000abc)` runas-user (digit run followed by letters, no denylist char) \
             is visudo-rejected and must fire exactly one F02, mirroring the \
             subject-position case; got {diags:?}"
        );
        assert_eq!(f02_diags[0].severity, rulesteward_core::Severity::Fatal);
    }

    /// `alice ALL = (%#0z) /bin/ls` -- runas-USER `%#`-GID with a single-digit
    /// run (`0`) immediately followed by a letter (`z`). Sibling of the case
    /// above at the shortest-digit-run boundary.
    ///
    /// Oracle: `visudo -cf` rc=1, "syntax error" at the `z` (col 17). `is_pure_gid`
    /// is false for `#0z` (the rest is not all-digit), so once the GID-tail check
    /// is applied to `runas.users` this must fire; RED today for the same reason.
    #[test]
    fn f02_runas_user_gid_form_short_digit_run_then_letter_fires() {
        // Fixture: visudo -cf rc=1, "syntax error" at `z` in `(%#0z)`.
        // Verified locally: visudo 1.9.17p2, 2026-07-02.
        let diags = lint("root ALL=(ALL:ALL) ALL\nalice ALL = (%#0z) /bin/ls\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert_eq!(
            f02_diags.len(),
            1,
            "`(%#0z)` runas-user (single-digit GID run then a letter) is visudo-rejected \
             and must fire exactly one F02; got {diags:?}"
        );
        assert_eq!(f02_diags[0].severity, rulesteward_core::Severity::Fatal);
    }

    /// `alice ALL = (%#1000) /bin/ls` -- the runas-USER pure-GID form MUST stay
    /// clean after the GID-tail check is added (the exemption must be preserved,
    /// exactly as `f02_runas_group_position_gid_form_no_f02` pins for the group
    /// position and `f02_group_gid_form_no_f02` pins for the subject position).
    #[test]
    fn f02_runas_user_pure_gid_form_no_f02() {
        // Fixture: visudo -cf rc=0, "parsed OK".
        // Verified locally: visudo 1.9.17p2, 2026-07-02.
        let diags = lint("root ALL=(ALL:ALL) ALL\nalice ALL = (%#1000) /bin/ls\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert!(
            f02_diags.is_empty(),
            "`(%#1000)` is the valid pure-GID runas-user form -- must NOT fire F02 after \
             the GID-tail check is applied to the runas-user position; got {f02_diags:?}"
        );
    }

    // --- #407: runas-GROUP `#`-GID token + bare (non-`%`) runas-USER `#`-GID
    // token, both false-negatives via `strip_inline_comment` -----------------
    //
    // Root cause distinct from the `%#1000abc` cases above: `strip_inline_comment`'s
    // `prev_allows_uid` predicate (parser.rs) did not allow `:` (the runas-group
    // separator) or `(` (the runas open-paren) to precede a `#<digits>` token, so
    // for `(root:#1000abc)` / `(#1000abc)` the ENTIRE REST OF THE LINE -- including
    // the real command -- was swallowed as an inline comment. The line reached the
    // AST as `CmndSpec { runas: None, cmnd: Cmnd("(root:") }` / `Cmnd("(")`, so
    // `check_runas` was never even invoked with the malformed token: RuleSteward
    // emitted ZERO diagnostics for a file `visudo -c` rejects outright (rc=1).
    // Fixed by widening `prev_allows_uid` (parser.rs) plus a GID-tail check on the
    // `runas.groups` loop and broadening the `runas.users` GID-tail check to the
    // bare (non-`%`) form (both in `check_runas` below).

    /// `alice ALL = (root:#1000abc) /bin/su` -- a runas-GROUP (post-colon) `#`-GID
    /// token whose digit run is followed by a non-digit tail.
    ///
    /// Oracle: `visudo -c` rc=1, "syntax error" at the `abc` tail (col 22).
    /// Verified locally: sudo/visudo 1.9.17p2, 2026-07-03.
    #[test]
    fn f02_runas_group_gid_form_digits_then_letters_fires() {
        let diags = lint("root ALL=(ALL:ALL) ALL\nalice ALL = (root:#1000abc) /bin/su\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert_eq!(
            f02_diags.len(),
            1,
            "`(root:#1000abc)` runas-group (digit run followed by letters, no \
             denylist char) is visudo-rejected and must fire exactly one F02; \
             got {diags:?}"
        );
        assert_eq!(f02_diags[0].severity, rulesteward_core::Severity::Fatal);
    }

    /// `alice ALL = (#1000abc) /bin/su` -- the BARE (no `%`) runas-USER form
    /// (no colon at all, so the whole `(...)` is `runas.users`) with the same
    /// malformed GID/UID tail. Distinct from the already-covered `%#1000abc`
    /// case: no `%` prefix, so the OLD `user.strip_prefix('%')`-gated GID-tail
    /// check in `check_runas` would not have applied even if the token had
    /// reached it.
    ///
    /// Oracle: `visudo -c` rc=1, "syntax error" at the `abc` tail (col 17).
    /// Verified locally: sudo/visudo 1.9.17p2, 2026-07-03.
    #[test]
    fn f02_runas_user_bare_hash_gid_form_digits_then_letters_fires() {
        let diags = lint("root ALL=(ALL:ALL) ALL\nalice ALL = (#1000abc) /bin/su\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert_eq!(
            f02_diags.len(),
            1,
            "`(#1000abc)` bare runas-user GID/UID form (digit run then letters, \
             no `%`, no denylist char) is visudo-rejected and must fire exactly \
             one F02; got {diags:?}"
        );
        assert_eq!(f02_diags[0].severity, rulesteward_core::Severity::Fatal);
    }

    /// `alice ALL = (root:#1000) /bin/su` -- the VALID pure-GID runas-GROUP form
    /// (#407's critical non-regression control).
    ///
    /// A bare `f02_diags.is_empty()` assertion alone is satisfiable by the OLD,
    /// BROKEN parse too: the comment-swallowing bug truncates the line to
    /// `CmndSpec { runas: None, cmnd: Cmnd("(root:") }` before `check_runas` (or
    /// any command-position check) ever runs, so F02 trivially finds nothing --
    /// a false pass masking real data loss (the command `/bin/su` vanishes
    /// silently). This test additionally asserts the AST shape so the
    /// regression can't hide behind an empty-diagnostics vacuity.
    ///
    /// Oracle: `visudo -c` rc=0, "parsed OK"; `cvtsudoers -f json` shows
    /// `"runasgroups": [{"usergroup": "#1000"}]`. Verified locally: sudo/visudo
    /// 1.9.17p2, 2026-07-03.
    #[test]
    fn f02_runas_group_gid_form_no_f02_and_parses_correctly() {
        let src = "root ALL=(ALL:ALL) ALL\nalice ALL = (root:#1000) /bin/su\n";
        let diags = lint(src);
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert!(
            f02_diags.is_empty(),
            "`(root:#1000)` is a valid runas GID-group entry -- must NOT fire \
             F02; got {f02_diags:?}"
        );
        let f = files(src);
        let crate::ast::LineKind::UserSpec(spec) = &f[0].lines[1].kind else {
            panic!("expected the second logical line to classify as a UserSpec");
        };
        let runas = spec.host_groups[0].cmnd_specs[0]
            .runas
            .as_ref()
            .expect("runas group must be populated -- not swallowed by the comment strip");
        assert_eq!(runas.users, vec!["root".to_string()]);
        assert_eq!(runas.groups, vec!["#1000".to_string()]);
        assert_eq!(
            spec.host_groups[0].cmnd_specs[0].cmnd,
            crate::ast::CmndItem::Cmnd("/bin/su".to_string()),
            "the real command must survive -- not be truncated into the runas group"
        );
    }

    /// `alice ALL = (#1000) /bin/su` -- the VALID bare pure-GID/UID runas-USER
    /// form (no colon). Sibling non-regression control to the group-position
    /// test above.
    ///
    /// Oracle: `visudo -c` rc=0, "parsed OK"; `cvtsudoers -f json` shows
    /// `"runasusers": [{"userid": 1000}]`. Verified locally: sudo/visudo
    /// 1.9.17p2, 2026-07-03.
    #[test]
    fn f02_runas_user_bare_hash_pure_gid_no_f02_and_parses_correctly() {
        let src = "root ALL=(ALL:ALL) ALL\nalice ALL = (#1000) /bin/su\n";
        let diags = lint(src);
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert!(
            f02_diags.is_empty(),
            "`(#1000)` is a valid bare runas-user GID/UID entry -- must NOT fire \
             F02; got {f02_diags:?}"
        );
        let f = files(src);
        let crate::ast::LineKind::UserSpec(spec) = &f[0].lines[1].kind else {
            panic!("expected the second logical line to classify as a UserSpec");
        };
        let runas = spec.host_groups[0].cmnd_specs[0]
            .runas
            .as_ref()
            .expect("runas group must be populated -- not swallowed by the comment strip");
        assert_eq!(runas.users, vec!["#1000".to_string()]);
        assert_eq!(
            spec.host_groups[0].cmnd_specs[0].cmnd,
            crate::ast::CmndItem::Cmnd("/bin/su".to_string()),
            "the real command must survive -- not be truncated into the runas group"
        );
    }

    // --- Shape 2: lone `!` command with no path -----------------------------

    /// `alice ALL = !` -- issue #375's literal example: a bare negation with no
    /// command to negate.
    ///
    /// Oracle: `visudo -cf` rc=1, "syntax error" at the `!` (col 14). The parser
    /// keeps this as `CmndItem::Cmnd("!")` (an ordinary command token whose
    /// content happens to be exactly `"!"`), so today's Case-3 relative-path
    /// check does not fire (`"!".trim_start_matches('!')` is `""`, which
    /// contains no `/`) and no other case matches it either -- F02 is silent.
    #[test]
    fn f02_lone_bang_command_no_path_fires() {
        // Fixture: visudo -cf rc=1, "syntax error" at the bare `!`.
        // Verified locally: visudo 1.9.17p2, 2026-07-02.
        let diags = lint("root ALL=(ALL:ALL) ALL\nalice ALL = !\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert_eq!(
            f02_diags.len(),
            1,
            "a lone `!` command with no path is visudo-rejected and must fire exactly \
             one F02; got {diags:?}"
        );
        assert_eq!(f02_diags[0].severity, rulesteward_core::Severity::Fatal);
    }

    /// `alice ALL = /bin/ls, !` -- a lone trailing `!` after a comma-separated
    /// valid command. Only the SECOND `Cmnd_Spec` (`!` alone) is malformed.
    ///
    /// Oracle: `visudo -cf` rc=1, "syntax error" at the trailing `!` (col 23).
    /// `split_cmnd_specs` produces two `CmndSpec`s: `/bin/ls` (valid) and `!`
    /// (the lone-bang defect). F02 must fire once (only for the second).
    #[test]
    fn f02_lone_bang_after_comma_fires() {
        // Fixture: visudo -cf rc=1, "syntax error" at the trailing lone `!`.
        // Verified locally: visudo 1.9.17p2, 2026-07-02.
        let diags = lint("root ALL=(ALL:ALL) ALL\nalice ALL = /bin/ls, !\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert_eq!(
            f02_diags.len(),
            1,
            "a lone trailing `!` command in a comma list must fire exactly one F02 \
             (the valid `/bin/ls` sibling must not); got {diags:?}"
        );
        assert_eq!(f02_diags[0].severity, rulesteward_core::Severity::Fatal);
    }

    /// `alice ALL = !ALL` -- negated `ALL` is a DIFFERENT, VALID construct; must
    /// NOT be conflated with the lone-bang-no-command defect above.
    ///
    /// Oracle: `visudo -cf` rc=0, "parsed OK". Source-verified AST shape
    /// (`parse_cmnd_spec`, parser.rs): the command token is the full string
    /// `"!ALL"`, and the `cmnd_token == "ALL"` reserved-word check compares that
    /// FULL string (`"!ALL" != "ALL"`), so this becomes `CmndItem::Cmnd("!ALL")`
    /// -- the leading `!` is kept verbatim (ast.rs `CmndItem::Cmnd` doc) -- NOT
    /// `CmndItem::All`. That makes this a sharp guard for the lone-`!` check: an
    /// over-broad impl keyed on `token.starts_with('!')` would WRONGLY fire on
    /// `Cmnd("!ALL")`, so the implementer must key the lone-bang defect off the
    /// EXACT token `"!"`, not a `!` prefix.
    #[test]
    fn f02_bang_negated_all_no_f02() {
        // Fixture: visudo -cf rc=0, "parsed OK".
        // Verified locally: visudo 1.9.17p2, 2026-07-02.
        let diags = lint("root ALL=(ALL:ALL) ALL\nalice ALL = !ALL\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert!(
            f02_diags.is_empty(),
            "`!ALL` is a valid negated-ALL command, distinct from a lone `!` -- must \
             NOT fire F02; got {f02_diags:?}"
        );
    }

    // --- Shape 3: `%#<digits><non-digit>` GID-then-letters form -------------

    /// `%#1000abc ALL = ALL` -- issue #375's literal example: a digit run
    /// immediately followed by letters, with no Case-4 denylist char present.
    ///
    /// Oracle: `visudo -cf` rc=1, "syntax error" at `abc` (col 11). `is_pure_gid`
    /// is already `false` for `#1000abc` (the rest is not all-digit), so the
    /// existing denylist WOULD run -- but `abc` contains none of
    /// `{! ( ) > "}`, so F02 stays silent today. This is a distinct
    /// GID-structural-validation gap (module doc already calls it out: "a
    /// separate gap"), not a denylist-char miss.
    #[test]
    fn f02_gid_form_digits_then_letters_fires() {
        // Fixture: visudo -cf rc=1, "syntax error" at `abc` in `%#1000abc`.
        // Verified locally: visudo 1.9.17p2, 2026-07-02.
        let diags = lint("root ALL=(ALL:ALL) ALL\n%#1000abc ALL = ALL\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert_eq!(
            f02_diags.len(),
            1,
            "`%#1000abc` (digit run followed by letters, no denylist char) is \
             visudo-rejected and must fire exactly one F02; got {diags:?}"
        );
        assert_eq!(f02_diags[0].severity, rulesteward_core::Severity::Fatal);
    }

    /// `%#abc ALL = ALL` -- a `%#` immediately followed by a non-digit (zero
    /// leading digits). visudo-rejected, but it is an F01 (parse-failure) case,
    /// NOT an F02 (clean-spec defect) case -- the crucial distinction from the
    /// `%#1000abc` shape above.
    ///
    /// Why this is F01 not F02 (source-verified, `strip_inline_comment`,
    /// parser.rs Exception 2): the `#` in `%#abc` is preceded by `%` (a
    /// UID/GID-allowing position) but is NOT followed by a digit (`a`). So the
    /// stripper treats it as a genuine inline comment and drops everything from
    /// the `#` onward, collapsing the subject token to a bare `%`. A lone `%`
    /// group with no name fails to parse -> `LineKind::Malformed` -> sudo-F01
    /// (the anchored parse error from #382, present on this session branch).
    /// It therefore never reaches F02 as a clean spec.
    ///
    /// Contrast `%#1000abc`: there the `#` IS followed by a digit (`1`), so the
    /// stripper keeps `#1000abc`, the line parses to a clean `UserSpec` with
    /// `users = ["%#1000abc"]`, and F02's GID-structural check is what must fire.
    /// The digit-run-then-letters shape is a clean-spec F02 defect; the
    /// no-digit-run shape is an F01 parse failure.
    ///
    /// Oracle: `visudo -cf` on `%#abc ALL = ALL` is rc=1 "empty group" (a parse
    /// error), consistent with the F01 classification. Verified locally: visudo
    /// 1.9.17p2, 2026-07-02.
    #[test]
    fn f02_gid_form_hash_then_letters_only_is_f01_not_f02() {
        let src = "root ALL=(ALL:ALL) ALL\n%#abc ALL = ALL\n";
        // The `%#abc` line collapses to `%` (inline-comment strip) -> Malformed
        // -> sudo-F01 must fire on it.
        let f01_diags: Vec<_> = lint_f01(src)
            .into_iter()
            .filter(|d| d.code == "sudo-F01")
            .collect();
        assert_eq!(
            f01_diags.len(),
            1,
            "`%#abc` collapses to a bare `%` (# not followed by a digit) and must fire \
             exactly one sudo-F01 parse error; got {f01_diags:?}"
        );
        assert_eq!(f01_diags[0].severity, rulesteward_core::Severity::Fatal);
        // And it must NOT be double-reported as an F02 clean-spec defect.
        let f02_diags: Vec<_> = lint(src)
            .into_iter()
            .filter(|d| d.code == "sudo-F02")
            .collect();
        assert!(
            f02_diags.is_empty(),
            "`%#abc` is an F01 parse failure, not an F02 clean-spec defect -- F02 must \
             stay silent to avoid double-reporting; got {f02_diags:?}"
        );
    }
}
