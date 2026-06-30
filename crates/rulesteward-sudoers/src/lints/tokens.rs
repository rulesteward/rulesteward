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
//!    `CmndItem::Cmnd("bin/ls")`. F02 detects a command token that contains `/`
//!    but does not start with `/`, `ALL`, or a tag keyword.
//!
//! 4. **Malformed group subject** (e.g. `%bad group ALL = ALL`): visudo reports
//!    a syntax error at the space after the group name (rc=1). `RuleSteward`
//!    parses `%bad` as the user and `group ALL` as the host, so the structural
//!    parse succeeds. F02 detects a `%`-prefixed user token that contains
//!    embedded whitespace when the token is inspected from the original line
//!    (or equivalently, a user token starting with `%` whose group name would
//!    include a space).
//!
//! # Must-NOT-regress (valid, no F02)
//!
//! - `User_Alias FOO = #1000`: the `#1000` follows `=` in an alias DEFINITION
//!   and is a valid UID member (visudo -c: rc=0 with only an "unused alias"
//!   warning). F02 must never fire on alias member positions.
//! - Any ordinary valid sudoers line (root rule, Defaults, %wheel rule, etc.).
//!
//! # Implementation stub
//!
//! The function body is a stub (`Vec::new()`) in Phase 0. The implementer
//! fills the body; the tests here are the RED gate.

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
/// 3. Relative-path command (not fully-qualified: contains `/` but does NOT
///    start with `/`).
/// 4. Malformed group subject (`%name` with embedded whitespace).
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
                // A relative path contains `/` but does not start with `/`.
                let cmd_path = token.split_whitespace().next().unwrap_or(token);
                if cmd_path.contains('/') && !cmd_path.starts_with('/') {
                    diags.push(anchored(
                        Severity::Fatal,
                        "sudo-F02",
                        logical.span.clone(),
                        format!("command is a relative path that visudo rejects (expected a fully-qualified path): {cmd_path}"),
                        file.path.clone(),
                        logical.line,
                    ));
                }
            }
        }
    }

    // Case 4: malformed group subject (`%group name` with embedded whitespace).
    // The parser splits on the first whitespace, so `%bad group ALL = ALL`
    // produces users=["%bad"] and hosts=["group ALL"]. A host token with embedded
    // whitespace is structurally impossible in a valid file and signals that a
    // `%`-prefixed user's group name contained a space.
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
                        format!("group subject {pct_user:?} has an invalid name (embedded whitespace) that visudo rejects"),
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
/// `strip_inline_comment` stage preserved as a UID/GID reference.
///
/// By the time a string reaches the AST, `strip_inline_comment` has already
/// removed any `#` that is a real comment (ones preceded by non-UID context).
/// The only surviving `#` followed by digits are the ones preceded by start-
/// of-string, whitespace, `,`, or `%` -- exactly the positions that produce
/// invalid tokens in command / Defaults-value context.
fn has_hash_digits(s: &str) -> bool {
    let bytes = s.as_bytes();
    for i in 0..bytes.len() {
        if bytes[i] == b'#' && bytes.get(i + 1).is_some_and(u8::is_ascii_digit) {
            let prev_ok = match i.checked_sub(1) {
                None => true, // `#` at position 0
                Some(j) => {
                    let p = bytes[j];
                    p == b',' || p == b'%' || (p as char).is_whitespace()
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
}
