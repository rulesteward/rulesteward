//! sudo-F02 command-position checks (#433 split from `tokens.rs`): Case 1
//! (`#<digits>` in command position), Case 3 (relative-path command), and
//! #375 Rules 1-2 (runas-position defects + lone `!` command).

use rulesteward_core::{Diagnostic, Severity};

use crate::ast::{CmndItem, SudoersFile};
use crate::lints::anchored;

use super::runas::check_runas;
use super::shared::has_hash_digits;

/// Cases 1 and 3, plus #375 Rules 1 and 2: check every command spec (and its
/// optional runas group) in every host-group.
pub(super) fn check_command_specs(
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
