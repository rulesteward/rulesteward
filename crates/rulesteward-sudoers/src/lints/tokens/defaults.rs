//! sudo-F02 Case 2 (#433 split from `tokens.rs`): `Defaults` line checks --
//! `#<digits>` in setting name/value, the #407 scope-target GID-tail check,
//! and the #451 Cmnd-scope member path-validity check.

use rulesteward_core::{Diagnostic, Severity};

use crate::ast::SudoersFile;
use crate::lints::aliases::is_alias_ref;
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
    // The `!` (command) scope runs the #426 empty-member check (see the Cmnd arm
    // below) but intentionally SKIPS this #407 GID-tail loop (`check_gid_tail:
    // false`). Two reasons: (a) a bare `#<digits>` command target (`Defaults!#1000`,
    // `Defaults!#1000abc`, both visudo rc=1) is not in `prev_allows_uid`, so it
    // strips as a comment upstream and folds to `Malformed` / sudo-F01. (b) A
    // `#<digits>` member that DOES survive (non-leading, e.g.
    // `Defaults!/bin/ls,#1000abc`) still must not go through this loop: unlike the
    // user/runas/host scopes where a pure digit run is a VALID id, visudo rejects
    // `#<digits>` outright in command position ("expected a fully-qualified path
    // name"), so the loop's "pure digits = valid" assumption is wrong for commands
    // and it would emit a nonsensical "GID" message. Validating command-target
    // paths is a separate, broader defect class (was out of #429's empty-member
    // scope; #451 below adds the dedicated `check_cmnd_path` member-validity loop
    // that covers it).
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
            check_cmnd_path: false,
        }),
        crate::ast::DefaultsScope::Runas(binding) => Some(ScopeCheck {
            binding: binding.as_str(),
            scope_word: "runas",
            is_host: false,
            check_gid_tail: true,
            check_cmnd_path: false,
        }),
        crate::ast::DefaultsScope::Host(binding) => Some(ScopeCheck {
            binding: binding.as_str(),
            scope_word: "host",
            is_host: true,
            check_gid_tail: true,
            check_cmnd_path: false,
        }),
        // #429: the Cmnd (`!`) scope runs the #426 empty-member check, but NOT the
        // #407 GID-tail loop (`check_gid_tail: false`; see the long comment above
        // for why command-position `#<digits>` must not use that loop). `scope_word`
        // is "command" per the frozen tests' scope-word-agnostic message. #451:
        // Cmnd is the ONLY scope that runs the dedicated path-validity loop
        // (`check_cmnd_path: true`) -- a bare digit run is a valid GID in the
        // other three scopes but visudo rejects it outright in command position,
        // so this is a distinct predicate, not a relaxation of the GID-tail one.
        crate::ast::DefaultsScope::Cmnd(binding) => Some(ScopeCheck {
            binding: binding.as_str(),
            scope_word: "command",
            is_host: false,
            check_gid_tail: false,
            check_cmnd_path: true,
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
/// #426 empty-member check; Cmnd (`!`) runs the empty-member check plus its
/// own #451 `check_cmnd_path` member-validity loop instead (a `#`-prefixed
/// command target never survives to the AST -- see the long comment in
/// `check_defaults`).
#[derive(Clone, Copy)]
struct ScopeCheck<'a> {
    binding: &'a str,
    scope_word: &'a str,
    is_host: bool,
    check_gid_tail: bool,
    check_cmnd_path: bool,
}

/// Extracted from `check_defaults` (#433) to flatten its nesting: validates a
/// `Defaults` scope-target binding (the User/Runas/Host/Cmnd comma-list) for a
/// `#`-prefixed member with a non-digit tail (User/Runas/Host only, per
/// `check_gid_tail`), an empty comma-list member (all four scopes), or --
/// Cmnd only, per `check_cmnd_path` (#451) -- a member that is not a valid
/// command-position target. `scope_binding` is `None` for a Global scope, in
/// which case this is a no-op (`false`). Returns `true` when a diagnostic was
/// pushed, so the caller can skip the setting scan for a line that already
/// reported (one F02 per line) -- mirroring the early `return` the inline
/// `if let` block used to perform itself.
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
        check_cmnd_path,
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
    // #451: Cmnd-only path-validity loop. Run only when neither check above
    // already flagged this line (one F02 per line) -- an empty member is
    // caught by the #426 check just above and must not ALSO be re-flagged
    // here as "not a valid command target" (both scans would otherwise fire
    // on the same offending position with two different messages).
    if diags.len() == before && check_cmnd_path {
        for &element in &members {
            if !is_valid_cmnd_scope_member(element) {
                diags.push(anchored(
                    Severity::Fatal,
                    "sudo-F02",
                    logical.span.clone(),
                    format!(
                        "Defaults {scope_word}-scope target has a member {element:?} \
                         that visudo rejects (expected a fully-qualified path name, \
                         `ALL`, or a Cmnd_Alias reference)"
                    ),
                    file.path.clone(),
                    logical.line,
                ));
                break; // one diagnostic per Defaults line
            }
        }
    }
    diags.len() > before
}

/// #451: `true` when `member` is a valid `Defaults!` (Cmnd-scope) comma-list
/// member -- the reserved `ALL` (bare or `!`-negated), a `Cmnd_Alias`-shaped
/// reference (`[A-Z][A-Z0-9_]*`, delegating to the shared
/// [`is_alias_ref`](crate::lints::aliases::is_alias_ref) so the two shape
/// checks never drift apart), a (`!`-negatable) fully-qualified absolute
/// path, or one of the two reserved Cmnd-position pseudo-commands `sudoedit`
/// / `list` (also `!`-negatable). `is_alias_ref` strips its own leading `!`
/// run and rejects `ALL` itself, so only the `ALL`, path, and
/// `sudoedit`/`list` arms need an explicit strip here.
///
/// `sudoedit`/`list` are matched CASE-SENSITIVELY on the exact lowercase
/// spelling -- they are not a case-insensitive keyword pair. Grounded
/// against `visudo -cf` (Rocky Linux 9, sudo 1.9.17p2,
/// rockylinux/rockylinux:9 image, `dnf install sudo`, 2026-07-08):
/// `sudoedit` / `list` (lowercase) rc=0 "parsed OK"; `Sudoedit` / `List`
/// (mixed case) rc=1 "expected a fully-qualified path name". Note
/// `SUDOEDIT` / `LIST` (all-uppercase) also rc=0, but NOT via a
/// case-insensitive keyword match -- an all-uppercase bareword happens to
/// satisfy the pre-existing `is_alias_ref` shape (`[A-Z][A-Z0-9_]*`), so
/// `visudo -cf` (syntax-only, no semantic "is this alias defined" pass)
/// accepts it as an alias-shaped reference. No dedicated uppercase handling
/// is needed here; `is_alias_ref` already covers it.
///
/// #451 round-3 (impl-aware adversarial review, 2026-07-08) grounded two
/// further quirks against the same oracle:
///
/// - A DOUBLE-QUOTED `"list"` member is accepted (`Defaults!"list"`, rc=0
///   "parsed OK") even though `split_default_settings` retains the quotes
///   (they only protect an interior comma from the split), so the member
///   arrives as the literal 6-byte string `"list"` (quotes included). This
///   is a `list`-SPECIFIC grammar quirk, not a general "quotes are
///   unwrapped" rule: `Defaults!"sudoedit"`, `Defaults!"ALL"`, and
///   `Defaults!"/bin/ls"` are all still rc=1 "expected a fully-qualified
///   path name". The exact quoted spelling `"list"` (with quotes) is
///   therefore matched as its own literal, distinct from the bare `list`
///   arm below.
/// - A bare `/` member is REJECTED (`Defaults!/`, rc=1 "expected a
///   fully-qualified path name"), unlike every other path starting with
///   `/` (e.g. `/.`, rc=0 "parsed OK") -- a lone `/` names the root
///   directory, not a fully-qualified command path, so the
///   `starts_with('/')` arm must exclude the degenerate single-slash case
///   (after stripping a leading `!`) while still accepting any longer
///   absolute path.
///
/// Anything else is visudo-rejected in command position: a `#<digits>` token
/// (tail or pure -- unlike the User/Runas/Host scopes, a PURE digit run is
/// still invalid here, which is why this is a dedicated predicate and not a
/// relaxed `is_malformed_gid_tail`), a `%group` / `%#gid` group reference, a
/// quoted literal (other than the `"list"` quirk above), a relative path, an
/// ordinary (non-reserved) lowercase bareword, a digest-spec fragment
/// (`sha224:<hex>`) split out of its `sha224:<hex> /path` pairing, or a lone
/// `!`. All cases grounded locally: `visudo -cf`, Rocky Linux 9, sudo
/// 1.9.17p2, 2026-07-08 (rockylinux/rockylinux:9 image, `dnf install sudo`).
fn is_valid_cmnd_scope_member(member: &str) -> bool {
    let stripped = member.trim_start_matches('!');
    stripped == "ALL"
        || (stripped.starts_with('/') && stripped != "/")
        || is_alias_ref(member)
        || matches!(stripped, "sudoedit" | "list" | "\"list\"")
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
