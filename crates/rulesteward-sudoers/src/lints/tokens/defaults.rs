//! sudo-F02 Case 2 (#433 split from `tokens.rs`): `Defaults` line checks --
//! `#<digits>` in setting name/value, plus the #407 scope-target GID-tail
//! check.

use rulesteward_core::{Diagnostic, Severity};

use crate::ast::SudoersFile;
use crate::lints::anchored;

use super::shared::{has_hash_digits, is_malformed_gid_tail};

/// Case 2: check a `Defaults` line for `#<digits>` in setting name or value, plus
/// the #407 scope-target GID-tail check.
pub(super) fn check_defaults(
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
    // string. `split_scope_binding` (parser.rs, #426) captured the WHOLE scope
    // comma-list, and -- like `check_runas` iterates already-split runas tokens --
    // we split it into members with the quote/escape-aware `split_default_settings`
    // (which trims each member) and validate PER MEMBER: a non-`#` member (a plain
    // user / host name) is IGNORED, a pure `#<digits>` member is valid, and a
    // `#<digits><non-digits>` member fires one F02 naming THAT member (NOT the whole
    // binding). Grounded visudo/cvtsudoers 1.9.17p2: a quoted username
    // (`Defaults:"#1000abc"`, rc=0 valid) starts with `"`, so it never trips the
    // `#`-prefix gate.
    //
    // #426: capturing the full list (rather than the old first-whitespace
    // truncation) both (a) exposes an EMPTY member -- a leading/interior empty or an
    // exact `""` -- which visudo rejects and which now fires F02 (see below), and
    // (b) stops a later `#<digits>` member of a space-separated list (the valid
    // `Defaults:#1000, #1001`) from leaking into the settings scan as a false
    // positive.
    let scope_binding: Option<ScopeCheck<'_>> = match &entry.scope {
        crate::ast::DefaultsScope::User(binding) => Some(ScopeCheck {
            binding: binding.as_str(),
            scope_word: "user",
            is_host: false,
            check_gid_tail: true,
        }),
        crate::ast::DefaultsScope::Runas(binding) => Some(ScopeCheck {
            binding: binding.as_str(),
            scope_word: "runas",
            is_host: false,
            check_gid_tail: true,
        }),
        crate::ast::DefaultsScope::Host(binding) => Some(ScopeCheck {
            binding: binding.as_str(),
            scope_word: "host",
            is_host: true,
            check_gid_tail: true,
        }),
        // #429: the Cmnd (`!`) scope now runs the #426 empty-member check, but
        // NOT the #407 GID-tail loop -- `!` is not in `prev_allows_uid`, so a
        // `#<digits>` command target (`Defaults!#1000`, `Defaults!#1000abc`)
        // still strips as a comment upstream and folds to Malformed/sudo-F01
        // (see the long comment above); there is no `#`-prefixed command form
        // that survives to the AST for this loop to validate. `scope_word` is
        // "command" per the frozen tests' scope-word-agnostic message.
        crate::ast::DefaultsScope::Cmnd(binding) => Some(ScopeCheck {
            binding: binding.as_str(),
            scope_word: "command",
            is_host: false,
            check_gid_tail: false,
        }),
        // Global (no scope) is not a list.
        crate::ast::DefaultsScope::Global => None,
    };
    if check_defaults_scope(scope_binding, file, logical, diags) {
        // If any scope element was flagged, the line is already reported; skip the
        // setting check (a clean-scope line still falls through to it).
        return;
    }

    // The inline-comment stripper keeps `#<digits>` preceded by whitespace as a UID
    // token, so `env_reset #2 reasons` arrives with name = "env_reset #2 reasons".
    // visudo rejects this as a syntax error (rc=1).
    for setting in &entry.settings {
        let in_name = has_hash_digits(&setting.name);
        // #423 quote-region gate: a `#<digits>` inside a CLEAN double-quoted
        // value (`passprompt="Enter #5 now"`, visudo rc=0) is a literal, not a
        // UID-like token, so skip the value scan when the value was a
        // fully-quoted region (`DefaultSetting::value_double_quoted`). The
        // byte-identical UNQUOTED form (`passprompt=Enter #5 now`, rc=1) and a
        // value with an unquoted `#5` tail outside a quoted span (`"hi" #5`,
        // rc=1) both have `value_double_quoted == false` and still fire.
        // `has_hash_digits` itself stays quote-blind -- it is also called on
        // command tokens and setting names, which are never quote-stripped.
        // The base scan (`has_hash_digits`) catches a `#<digits>` preceded by
        // whitespace/start/`%`. #424 adds the `"`-glued case
        // (`passprompt="a"#5`): the value is NOT one clean quoted region
        // (`value_double_quoted == false`, so we are already past the #423 gate),
        // the `"` is a region boundary, and a `#<digits>` right after it is a
        // genuinely unquoted, visudo-rejected token. Kept value-path-local (not
        // folded into the shared quote-blind `has_hash_digits`, which also scans
        // command tokens / setting names).
        let in_value = !setting.value_double_quoted
            && setting
                .value
                .as_deref()
                .is_some_and(|v| has_hash_digits(v) || hash_digits_glued_after_quote(v));
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

/// The per-scope inputs to [`check_defaults_scope`]. `check_gid_tail` is the
/// #429 decoupling signal: User/Runas/Host run the #407 GID-tail loop AND the
/// #426 empty-member check; Cmnd (`!`) runs only the empty-member check (a
/// `#`-prefixed command target never survives to the AST -- see the long
/// comment in `check_defaults`).
#[derive(Clone, Copy)]
struct ScopeCheck<'a> {
    binding: &'a str,
    scope_word: &'a str,
    is_host: bool,
    check_gid_tail: bool,
}

/// Extracted from `check_defaults` (#433) to flatten its nesting: validates a
/// `Defaults` scope-target binding (the User/Runas/Host/Cmnd comma-list) for a
/// `#`-prefixed member with a non-digit tail (User/Runas/Host only, per
/// `check_gid_tail`), or an empty comma-list member (all four scopes).
/// `scope_binding` is `None` for a Global scope, in which case this is a
/// no-op (`false`). Returns `true` when a diagnostic was pushed, so the
/// caller can skip the setting scan for a line that already reported (one F02
/// per line) -- mirroring the early `return` the inline `if let` block used
/// to perform itself.
fn check_defaults_scope(
    scope_binding: Option<ScopeCheck<'_>>,
    file: &SudoersFile,
    logical: &crate::ast::LogicalLine,
    diags: &mut Vec<Diagnostic>,
) -> bool {
    let Some(ScopeCheck {
        binding,
        scope_word,
        is_host,
        check_gid_tail,
    }) = scope_binding
    else {
        return false;
    };
    let before = diags.len();
    // The scope binding is now the full comma list (issue #426); split it into
    // members with the quote/escape-aware splitter (which trims each member) so
    // a quoted/escaped comma stays inside one member and any whitespace padding
    // around a member is stripped before the per-member checks.
    let members = crate::parser::split_default_settings(binding);
    if check_gid_tail {
        for &element in &members {
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
    }
    // #426: an EMPTY comma-list member -- a leading/interior empty, or an exact
    // empty-quoted `""` member -- is a token visudo rejects. Run only when the
    // GID-tail check above did not already flag this line (one F02 per line). A
    // lone TRAILING empty never reaches here: `split_scope_binding` lets a
    // dangling comma absorb the next token (routing the line to the F01
    // "no settings" Fatal), so any empty member seen here is genuine.
    if diags.len() == before && members.iter().any(|&e| e.is_empty() || e == "\"\"") {
        diags.push(anchored(
            Severity::Fatal,
            "sudo-F02",
            logical.span.clone(),
            format!(
                "Defaults {scope_word}-scope target has an empty \
                 comma-list member, which visudo rejects"
            ),
            file.path.clone(),
            logical.line,
        ));
    }
    diags.len() > before
}

/// #424 value-path addendum to [`has_hash_digits`]: `true` when `s` contains a
/// `#<digits>` token glued immediately after a double quote (`"a"#5`). Used ONLY
/// by `check_defaults`'s value scan, and only for a value that is NOT one clean
/// double-quoted region (`value_double_quoted == false`) -- there the `"` is a
/// region boundary, so a `#<digits>` right after it is a genuinely unquoted token
/// that visudo rejects (`Defaults passprompt="a"#5`, rc=1). Deliberately kept OUT
/// of the shared `has_hash_digits`: that predicate also scans command tokens and
/// setting names and stays quote-blind, so it does not begin flagging the
/// quoted-`#`-in-command cases the `strip_inline_comment` KNOWN DIVERGENCE
/// intentionally leaves to a Phase-1 position-aware lexer.
fn hash_digits_glued_after_quote(s: &str) -> bool {
    let bytes = s.as_bytes();
    for i in 1..bytes.len() {
        if bytes[i] == b'#'
            && bytes[i - 1] == b'"'
            && bytes.get(i + 1).is_some_and(u8::is_ascii_digit)
        {
            return true;
        }
    }
    false
}
