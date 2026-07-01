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
    // Cases 1 and 3: check every command token in every host-group.
    for host_group in &spec.host_groups {
        for cmnd_spec in &host_group.cmnd_specs {
            if let CmndItem::Cmnd(token) = &cmnd_spec.cmnd {
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

    // Case 4: malformed group subject.
    //
    // Two sub-cases:
    //
    // (a) Embedded-whitespace: `%bad group ALL = ALL` splits into users=["%bad"],
    //     hosts=["group ALL"]. A host token with embedded whitespace is structurally
    //     impossible in a valid file and signals the group name had a space.
    //
    // (b) Invalid group-name char in the user token itself: `%bad!group ALL = ALL`
    //     splits into users=["%bad!group"], hosts=["ALL"]. The invalid char is INSIDE
    //     the user token, not expressed as host whitespace.
    //
    //     CLOSED grounded denylist for sub-case (b): { '!', '(', ')', '>', '"' }.
    //     Derived from an exhaustive visudo -cf probe of every printable-ASCII char CH
    //     in `%bad<CH>group` (rockylinux:9, sudo 1.9.17p2, 2026-06-30):
    //       REJECTED (rc=1, syntax error): `!  "  #  (  )  :  =  >`  (8 chars)
    //       ACCEPTED (rc=0): the other 86 printable-ASCII chars + non-ASCII.
    //     F01 carve-out: `#`, `:`, `=` also reject but fold the line to Malformed
    //     in the AST, so they are caught by sudo-F01 before F02 is reached. They
    //     MUST NOT appear here to avoid double-reporting.
    //     The F02-relevant rejected chars are exactly the 5 above (do NOT convert
    //     to a positive allowlist -- the parser already ensures clean tokens reach
    //     this point; a denylist is simpler and more mutation-resistant).
    //     GID-form exemption: `%#NNN` (pure GID: `#` followed only by one or more
    //     ASCII digits) is valid (visudo rc=0) and must be exempt. The exemption is
    //     STRICTLY the pure-GID form: `%#1000>x` and `%#1000!x` contain a denylist
    //     char after the digit run and are visudo-rejected (rc=1). A bare
    //     `starts_with('#')` guard over-exempts any `#`-prefix name entirely; the
    //     correct guard uses `is_pure_gid` (see below).
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
        if !is_pure_gid
            && let Some(bad_char) = name
                .chars()
                .find(|c| matches!(c, '!' | '(' | ')' | '>' | '"'))
        {
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

/// Case 2: check a `Defaults` line for `#<digits>` in setting name or value.
fn check_defaults(
    file: &SudoersFile,
    logical: &crate::ast::LogicalLine,
    entry: &crate::ast::DefaultsEntry,
    diags: &mut Vec<Diagnostic>,
) {
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
    use crate::lints::SudoersLintContext;
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
}
