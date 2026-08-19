//! `sudoers(5)` parser: a hand-rolled TWO-STAGE parser (#329).
//!
//! # Grounding (`sudoers(5)`, sudo 1.9.17p2; project grounding doc)
//! Stage 1 (physical -> logical lines): a long logical line is continued with a
//! trailing backslash. The two physical lines `carol ALL = \` + `NOPASSWD: ALL`
//! are ONE user-spec, so the join MUST happen BEFORE classification. Byte spans
//! are tracked across the join (the logical line's span covers from the first
//! physical line's start to the last physical line's end).
//!
//! Stage 2 (classify each logical line into a [`LineKind`]): the comment
//! disambiguation is the subtle part. A `#` is a comment UNLESS:
//!   (a) it begins a `#include` / `#includedir` directive, or
//!   (b) it is `#<digits>` in user-name position (a UID subject of a user-spec).
//! Everywhere else `#` to EOL is a comment. A line that is none of the valid
//! kinds and is not well-formed becomes [`LineKind::Malformed`].
//!
//! # Total parser
//! [`parse`] ALWAYS returns a [`SudoersFile`]; it never returns `Err`. An
//! unparseable logical line becomes [`LineKind::Malformed`] so the good lines in
//! the file still lint (the F01 pass emits one Fatal per malformed line).
//!
//! # Design
//! Hand-rolled (NOT chumsky), KISS per CLAUDE.md - the grammar is a line classifier
//! plus a handful of field splitters, not a recursive grammar warranting a DSL.

use std::path::Path;

use rulesteward_core::Span;
use rulesteward_core::comment::{StripConfig, strip};

use crate::boundary::{
    clean_double_quoted_interior, find_closing_quote, inside_a_clean_quoted_region,
    opens_principal, option_value_end, preceding_token, quoted_value_span, separator_escaped,
    simple_quote_pairs, structural_eq, unquoted_unescaped, unquoted_whitespace_runs,
};

use crate::ast::{
    AliasDef, AliasKind, AliasSpec, CmndItem, CmndOption, CmndOptionKey, CmndSpec, DefaultSetting,
    DefaultsEntry, DefaultsScope, HostGroup, IncludeDirective, IncludeKind, LineKind, LogicalLine,
    RunasSpec, SudoersFile, Tag, UserSpec,
};

/// Parse a sudoers file's `source` (read from `path`) into a [`SudoersFile`].
///
/// TOTAL: always returns a [`SudoersFile`]. Stage 1 joins physical lines on a
/// trailing `\`; stage 2 classifies each logical line.
#[must_use]
pub fn parse(source: &str, path: &Path) -> SudoersFile {
    let logical = join_physical_lines(source);
    let lines = logical
        .into_iter()
        .map(|raw| LogicalLine {
            line: raw.line,
            span: raw.span.clone(),
            kind: classify_logical_line(&raw.text, raw.was_comment),
        })
        .collect();
    SudoersFile {
        path: path.to_path_buf(),
        source: source.to_string(),
        lines,
    }
}

/// A logical line after the stage-1 backslash join: the joined text, the 1-based
/// number of its FIRST physical line, and the byte span across all joined physical
/// lines.
struct RawLogicalLine {
    text: String,
    line: usize,
    span: Span,
    /// `true` when the (first physical line of the) logical line was a wholly-`#`
    /// comment whose comment-strip emptied the text. Distinguishes a comment line
    /// (`# foo`) from a truly blank line once the inline-comment strip has removed
    /// the comment body. A `#include` directive is NOT a comment, so this stays
    /// `false` for it.
    was_comment: bool,
}

/// Stage 1: join physical lines on a trailing backslash into logical lines.
///
/// Per physical line, in order (grounded against `visudo -c` / `visudo -x -`,
/// 1.9.17p2):
///   1. Strip the inline `#` comment to EOL (see [`rulesteward_core::comment::strip`]
///      with [`StripConfig::SUDOERS`]). The
///      comment strip happens FIRST, so a `#`-comment whose text ends in `\`
///      cannot continue (the `\` is inside the comment and is removed). Decisive
///      grounding: `# disable \`<NL>`@@@bad@@@` -> line 2 is an independent syntax
///      error, NOT a continuation (part B / #329).
///   2. Then evaluate continuation: a backslash followed by zero-or-more
///      whitespace then the newline continues. `\<NL>`, `\<TAB><NL>`,
///      `\<SPACE><NL>` all continue; `\x<NL>` (non-whitespace after the backslash)
///      does NOT - the backslash is literal text. Re-derived with the
///      line-1-invalid-alone probe (part B / #329).
///
/// The `\` (and any trailing whitespace after it) and the newline are dropped from
/// the joined text (replaced by a single space, matching how sudo treats a
/// continuation as whitespace). The logical line's span runs from the first
/// physical line's start byte to the last physical line's end byte; its `line` is
/// the first physical line's 1-based number.
fn join_physical_lines(source: &str) -> Vec<RawLogicalLine> {
    let mut out: Vec<RawLogicalLine> = Vec::new();
    // State of an in-progress (continued) logical line.
    let mut pending: Option<RawLogicalLine> = None;

    let mut offset = 0usize;
    for (idx, phys) in source.split('\n').enumerate() {
        let lineno = idx + 1; // 1-based
        let phys_start = offset;
        let phys_end = offset + phys.len();
        offset = phys_end + 1; // +1 for the consumed '\n'

        // Drop a trailing `\r` from a CRLF line ending, then strip any inline `#`
        // comment to EOL BEFORE the continuation check.
        let raw = phys.strip_suffix('\r').unwrap_or(phys);
        let body = strip(raw, StripConfig::SUDOERS);

        // A wholly-comment physical line: the strip emptied the text but the raw
        // line had non-whitespace content (the comment). Distinguishes Comment from
        // Blank in stage 2 once the comment body is gone.
        let was_comment = body.trim().is_empty() && !raw.trim().is_empty();

        // Continuation: a backslash followed only by whitespace up to the newline.
        // Find the last `\`; if everything after it (on this physical line) is
        // whitespace, this line continues and the `\` + trailing whitespace are
        // dropped from the joined text.
        let (text_part, continued) = match split_continuation(body) {
            Some(before) => (before, true),
            None => (body, false),
        };

        match pending.as_mut() {
            Some(p) => {
                // Continuation: append a separating space + this physical line's
                // text, and extend the span to this physical line's end.
                p.text.push(' ');
                p.text.push_str(text_part);
                p.span.end = phys_end;
            }
            None => {
                pending = Some(RawLogicalLine {
                    text: text_part.to_string(),
                    line: lineno,
                    span: phys_start..phys_end,
                    was_comment,
                });
            }
        }

        if !continued {
            // Logical line complete: flush it.
            if let Some(p) = pending.take() {
                out.push(p);
            }
        }
    }
    // A file ending with a trailing `\` leaves an open continuation; flush it.
    if let Some(p) = pending.take() {
        out.push(p);
    }
    out
}

/// If `body` ends with a continuation (`\` followed by zero-or-more whitespace),
/// return the text BEFORE that `\`. Otherwise return `None`.
///
/// Grounding (visudo 1.9.17p2, line-1-invalid-alone probe): `\<NL>`, `\<TAB><NL>`,
/// `\<SPACE><NL>`, `\<SP><SP><NL>` all continue; `\x<NL>` (a non-whitespace char
/// after the backslash) does NOT (the `\` is literal). The `#` comment has already
/// been stripped by [`rulesteward_core::comment::strip`] before this runs, so a
/// `\` that was inside a comment is already gone and cannot continue.
fn split_continuation(body: &str) -> Option<&str> {
    // Everything from the last `\` onward must be the `\` plus only whitespace.
    let bslash = body.rfind('\\')?;
    let after = &body[bslash + 1..];
    if after.chars().all(char::is_whitespace) {
        Some(&body[..bslash])
    } else {
        None
    }
}

// Cross-reference (#383, updated by #562): inline-`#` stripping now has a
// single parameterized implementation shared by three backends, plus one
// deliberately-separate token-level stripper:
//   - fapolicyd, auditd, sudoers all call `rulesteward_core::comment::strip`
//     / `comment_index` with their own `StripConfig` (`StripConfig::SUDOERS`
//     here: double-quote aware, plus the `#include`/`#includedir` bypass and
//     the `#<digits>` UID/GID-token exception with runas-paren state
//     tracking, per the doc comment on `join_physical_lines` above and the
//     grounding notes carried over into `rulesteward-core/src/comment.rs`'s
//     `sudoers_table` tests). See that module for the parameterized scan and
//     each backend's exact config.
//   - sshd      algo_list_value (lints/crypto.rs): token-level, not
//     line-level, and stays OUT of the shared helper by decision
//     (2026-07-23) - it ends an already-whitespace-split algorithm list at
//     the first `#`-prefixed arg, a different unit of work than a raw-line
//     byte scan.
// sysctld has NONE: sysctl.d(5) defines only whole-line `#`/`;` comments (a `#`
// mid-value is literal). If you fix an edge case in the shared stripper, check
// sshd's separate implementation too.
//
// Phase-0 contract note (preserved from the old in-crate `strip_inline_comment`):
// the shared stripper is a CLASSIFIER, not a command-token validator. visudo
// treats `#<digits>` as a token EVERYWHERE in the lexer but then REJECTS it as a
// syntax error in command / `Defaults`-value position (`alice ALL = /bin/ls #2`
// and `Defaults env_reset #2 reasons` are `visudo -c` errors). This parser does
// NOT do that command-token validation - just as it keeps a relative path like
// `bin/ls` (also a visudo error) as a clean user-spec rather than rejecting it.
// So a `#<digits>` glued in command/value position is kept on the (already
// visudo-invalid) line rather than special-cased; faithful per-position token
// validation is a documented Phase-1 extension.
//
// KNOWN DIVERGENCE (documented, NOT handled here, and NOT benign): sudo's
// COMMAND lexer does not protect a `#` with double quotes the way its
// Defaults-value and principal lexers do, so `/bin/echo "a # b"` is truncated by
// real sudo at the `#` while the quote-balance rule here keeps `a # b`.
//
// This comment used to say the over-protection "never corrupts a normal rule ...
// which is the safe direction". That is FALSE and it was falsified on the input
// below, not by inspection. Retaining the tail retains any STRUCTURAL byte inside
// it, and a retained `:` reaches the host-group splitter:
//
//   alice ALL = NOPASSWD: /bin/su, /bin/echo "a#b:c"
//     visudo -c -f -     -> rc 0 "parsed OK"
//     cvtsudoers -f json -> { "authenticate": false }, { "command": "/bin/su" },
//                           { "command": "/bin/echo \"a" }
//     RuleSteward        -> a FALSE sudo-F01 and ZERO sudo-W05
//
// So the live passwordless grant on `/bin/su` disappears behind a fabricated
// FATAL. Per #668 a Malformed line suppresses every other pass, which is what
// converts the mis-parse into a dropped grant rather than a visible complaint.
// Two controls, both rc 0 with the same `authenticate:false` and both handled
// CORRECTLY today, isolate it to the quote plus the retained `:`:
// `/bin/echo a#b:c` (no quotes) and `/bin/echo "a#b"` (no colon) each give
// sudo-W05 x2 and no F01.
//
// The quote protection is still CORRECT in the other positions and must not
// simply be dropped: `Defaults passprompt="a # b"` keeps the value `a # b`, and
// `alice "h#1" = ALL` keeps the hostname `h#1`. Both verified on sudo 1.9.17p2,
// 2026-08-19. The fix is therefore POSITION-AWARENESS, which this line-level
// stripper structurally cannot have - it belongs with the parser's boundary
// substrate, alongside the rest of the quote/escape call sites.
//
// Pre-existing and unchanged by #649 (which is the ESCAPE axis; this is the
// QUOTE axis). Verified two-sided against the fork point a700c38. Filed as
// #695, scoped with #668.

/// Stage 2: classify one joined logical line into a [`LineKind`].
///
/// `was_comment` is `true` when stage 1's inline-comment strip emptied a
/// wholly-`#` comment line (so the now-empty text is a `Comment`, not a `Blank`).
fn classify_logical_line(text: &str, was_comment: bool) -> LineKind {
    let trimmed = text.trim();

    if trimmed.is_empty() {
        // Stage 1 already stripped any inline comment. An empty text that came from
        // a wholly-`#` comment line is a Comment; a genuinely empty line is Blank.
        return if was_comment {
            LineKind::Comment
        } else {
            LineKind::Blank
        };
    }

    // Include directives: modern `@include`/`@includedir` OR legacy
    // `#include`/`#includedir`. A `#include` is NOT a comment (stage 1 left its
    // text intact). Checked before the user-spec classifier.
    if let Some(inc) = classify_include(trimmed) {
        return LineKind::Include(inc);
    }

    // `Defaults` and `Defaults@host` / `Defaults:user` / `Defaults!cmnd` /
    // `Defaults>runas`. The sigil is glued to `Defaults` (no whitespace allowed).
    if let Some(entry) = classify_defaults(trimmed) {
        return entry;
    }

    // Alias definitions: `User_Alias` / `Runas_Alias` / `Host_Alias` /
    // `Cmnd_Alias` (and the `Cmd_Alias` synonym).
    if let Some(alias) = classify_alias(trimmed) {
        return alias;
    }

    // Anything else is a user specification (or malformed).
    classify_user_spec(trimmed)
}

/// Classify a leading include directive, if any. Recognizes both spellings:
/// modern `@include PATH` / `@includedir DIR` and legacy `#include PATH` /
/// `#includedir DIR`. Returns `None` if the line is not an include directive.
fn classify_include(trimmed: &str) -> Option<IncludeDirective> {
    let (legacy, rest) = if let Some(r) = trimmed.strip_prefix('@') {
        (false, r)
    } else {
        let r = trimmed.strip_prefix('#')?;
        (true, r)
    };

    // The keyword (`include` / `includedir`) is the first whitespace-delimited
    // word; the remainder (trimmed) is the path. `includedir` MUST be checked
    // before `include` (it is a longer prefix of the same word).
    let (kw, path_part) = split_first_word(rest);
    let kind = match kw {
        "includedir" => IncludeKind::IncludeDir,
        "include" => IncludeKind::Include,
        _ => return None,
    };
    let path = path_part.trim();
    if path.is_empty() {
        // `@include` with no path is not a directive we can model; let it fall
        // through to be classified (and ultimately reported Malformed for the
        // legacy `#include` case, or as a user-spec attempt for `@include`).
        return None;
    }
    Some(IncludeDirective {
        kind,
        legacy,
        path: path.to_string(),
    })
}

/// Classify a `Defaults` entry, if the line is one. Returns `None` when the line
/// does not begin with the `Defaults` keyword (so it can fall through to the alias
/// / user-spec classifiers). Returns `Some(LineKind::Malformed(..))` when it IS a
/// `Defaults` line but is structurally broken.
fn classify_defaults(trimmed: &str) -> Option<LineKind> {
    let rest = trimmed.strip_prefix("Defaults")?;
    // The next char (if any) is the scope sigil (glued, no whitespace) OR
    // whitespace (global scope). Anything else (e.g. `Defaultsfoo`) means this was
    // not actually the `Defaults` keyword - fall through.
    let (scope, settings_str) = match rest.chars().next() {
        // Global: `Defaults <settings>` or just `Defaults` (whitespace or EOL).
        None => (DefaultsScope::Global, ""),
        Some(c) if c.is_whitespace() => (DefaultsScope::Global, rest.trim_start()),
        Some(sigil @ ('@' | ':' | '!' | '>')) => {
            // The scope binding is a comma-separated list (User/Host/Runas/Cmnd);
            // `split_scope_binding` captures the WHOLE list -- honoring whitespace
            // around separator commas, quotes, and escapes -- and returns the rest
            // as the settings list. Each sigil is a single-byte ASCII char.
            let after = &rest[sigil.len_utf8()..];
            let (binding, settings) = split_scope_binding(after);
            if binding.is_empty() {
                return Some(LineKind::Malformed(format!(
                    "Defaults{sigil} scope is missing its target"
                )));
            }
            let scope = match sigil {
                '@' => DefaultsScope::Host(binding.to_string()),
                ':' => DefaultsScope::User(binding.to_string()),
                '!' => DefaultsScope::Cmnd(binding.to_string()),
                '>' => DefaultsScope::Runas(binding.to_string()),
                // The outer arm bound `sigil` to exactly `@:!>`, but the compiler
                // cannot carry that refinement across the nested match, so a
                // wildcard is required for exhaustiveness.
                _ => unreachable!("sigil bound to one of @:!> by the outer match arm"),
            };
            (scope, settings.trim())
        }
        // `Defaults` glued to a non-sigil, non-whitespace char (`Defaultsfoo`):
        // not the keyword. Fall through to other classifiers.
        Some(_) => return None,
    };

    let settings = parse_default_settings(settings_str);
    if settings.is_empty() {
        return Some(LineKind::Malformed(
            "Defaults entry has no settings".to_string(),
        ));
    }
    Some(LineKind::Defaults(DefaultsEntry { scope, settings }))
}

/// Split a `Defaults` settings list into [`DefaultSetting`]s on top-level `,`
/// boundaries (escape/quote-aware; #405). Returns an empty vec when there is
/// nothing parseable (the caller treats that as Malformed).
fn parse_default_settings(s: &str) -> Vec<DefaultSetting> {
    split_default_settings(s)
        .into_iter()
        .map(str::trim)
        .filter(|tok| !tok.is_empty())
        .map(parse_one_default_setting)
        .collect()
}

/// Split a `Defaults` settings list on top-level `,` -- i.e. a `,` that is
/// neither backslash-escaped nor inside a double-quoted value.
///
/// Grounded against visudo/cvtsudoers 1.9.17p2 (2026-07-03): a Defaults value
/// may contain a literal comma either by escaping it (`Wrong\,ok`, unquoted) or
/// simply by quoting (`"Wrong, try again"` -- the comma need not even be
/// escaped there); BOTH forms parse as ONE setting, never two. A naive
/// `s.split(',')` mis-parses both into extra bogus settings (#405).
///
/// Mirrors the escape-awareness `split_cmnd_specs` (#370) already has for the
/// `Cmnd_Spec_List`, plus quote-awareness that list never needed (commands are
/// not quoted). Unlike `split_cmnd_specs`, this has no paren-depth tracking --
/// Defaults values never contain a `(runas)` group.
///
/// Escape pairing matches `split_cmnd_specs`: a `\` toggles `escaped`, which
/// consumes exactly the next char literally (so `\\` is one literal backslash
/// and does NOT re-arm escaping -- grounded via visudo: an escaped comma after
/// an EVEN run of backslashes is a real separator, after an ODD run it stays
/// literal). That is the SEPARATOR-finding rule, correct for commas here; the
/// QUOTE-finding rule differs -- see [`unescaped_quote_positions`] for both. An escaped `"` (`\"`) inside a quoted value does not end the
/// quote (grounded: `"a \" b, c"` is ONE setting).
///
/// Per the #370 precedent, this function only fixes the split BOUNDARY; it
/// does not unescape the resulting value (the backslash before an unquoted
/// escaped comma stays in the token verbatim, same as `cmnd_token`).
pub(crate) fn split_default_settings(s: &str) -> Vec<&str> {
    let mut segments = Vec::new();
    let mut seg_start = 0usize;
    let mut escaped = false;
    let mut in_quotes = false;
    for (i, c) in s.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match c {
            '\\' => escaped = true,
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => {
                segments.push(s[seg_start..i].trim());
                seg_start = i + c.len_utf8();
            }
            _ => {}
        }
    }
    segments.push(s[seg_start..].trim());
    segments
}

/// Split the text after a `Defaults` scope sigil (`:` / `@` / `>` / `!`) into
/// `(scope_list, settings)`, honoring sudo's list grammar: a scope target is a
/// comma-separated list `elem (WS* ',' WS* elem)*`, so a whitespace run ENDS the
/// list only when no top-level comma is adjacent -- whitespace may sit on either
/// side of a separating comma and the list continues. Double quotes and backslash
/// escapes protect a comma AND any internal whitespace (the escape/quote
/// conventions mirror [`split_default_settings`]). Both returned slices borrow
/// from `after`; the scope list is trimmed and the settings are left-trimmed.
///
/// Replaces a bare first-whitespace split at the Defaults scope site (issue #426):
/// a valid multi-member list such as `root, root env_reset` is captured whole
/// (`root, root` + `env_reset`) instead of truncated to `root,`, which
/// leaked the second member into the settings scan (a false positive).
fn split_scope_binding(after: &str) -> (&str, &str) {
    let mut escaped = false;
    let mut in_quotes = false;
    // True at the start and right after a separator comma: the next token is a
    // pending list element, so a whitespace run here is inter-element padding and
    // does not end the list.
    let mut expecting_element = true;
    let mut chars = after.char_indices();
    while let Some((idx, c)) = chars.next() {
        if escaped {
            escaped = false;
            expecting_element = false;
            continue;
        }
        if in_quotes {
            match c {
                '\\' => escaped = true,
                '"' => in_quotes = false,
                _ => {}
            }
            expecting_element = false;
            continue;
        }
        match c {
            '\\' => {
                escaped = true;
                expecting_element = false;
            }
            '"' => {
                in_quotes = true;
                expecting_element = false;
            }
            ',' => expecting_element = true,
            c if c.is_whitespace() => {
                // A whitespace run only ends the list when an element just closed
                // AND no separator comma follows across the whitespace.
                if !expecting_element {
                    let resumes = chars
                        .clone()
                        .find(|&(_, nc)| !nc.is_whitespace())
                        .is_some_and(|(_, nc)| nc == ',');
                    if !resumes {
                        return (after[..idx].trim(), after[idx..].trim_start());
                    }
                }
            }
            _ => expecting_element = false,
        }
    }
    (after.trim(), "")
}

/// Parse one `Defaults` setting token: `name`, `!name`, or `name[+-]?=value`.
fn parse_one_default_setting(token: &str) -> DefaultSetting {
    let (negated, body) = match token.strip_prefix('!') {
        Some(rest) => (true, rest.trim_start()),
        None => (false, token),
    };
    // Split on the FIRST `=`; a `+=` / `-=` list operator collapses to name+value
    // (the trailing `+`/`-` is dropped from the name). A `=` in the value stays.
    if let Some(eq) = body.find('=') {
        let mut name = body[..eq].trim();
        name = name
            .strip_suffix('+')
            .or_else(|| name.strip_suffix('-'))
            .unwrap_or(name);
        let value = body[eq + 1..].trim();
        // Strip surrounding double quotes when the value is ONE clean quoted
        // region (common for paths: `secure_path="/usr/bin"`). Record whether
        // it was (`value_double_quoted`): a `#<digits>` inside such a fully
        // quoted value is a literal that visudo accepts (rc=0), so sudo-F02
        // (#423) must NOT flag it -- even though the stripped value is
        // byte-identical to the visudo-rejected unquoted form. A value is one
        // clean region only if the FIRST UNESCAPED `"` after the opening quote
        // is its last byte (see `clean_double_quoted_interior`): `"hi" #5` and
        // `"a" #5 "b"` (an unquoted `#5` after a closing quote) are NOT clean
        // regions and stay verbatim + unquoted, so their unquoted `#5` fires.
        let (value, value_double_quoted) = match clean_double_quoted_interior(value) {
            Some(inner) => (inner, true),
            None => (value, false),
        };
        DefaultSetting {
            negated,
            name: name.trim().to_string(),
            value: Some(value.to_string()),
            value_double_quoted,
        }
    } else {
        DefaultSetting {
            negated,
            name: body.trim().to_string(),
            value: None,
            value_double_quoted: false,
        }
    }
}

/// Classify an alias definition, if the line is one. Returns `None` when the first
/// word is not one of the alias keywords. Returns `Some(Malformed)` when it IS an
/// alias keyword but the body is broken (e.g. no `=`).
fn classify_alias(trimmed: &str) -> Option<LineKind> {
    let (kw, rest) = split_first_word(trimmed);
    let kind = match kw {
        "User_Alias" => AliasKind::User,
        "Runas_Alias" => AliasKind::Runas,
        "Host_Alias" => AliasKind::Host,
        // `Cmd_Alias` is the >=1.9.0 synonym for `Cmnd_Alias`.
        "Cmnd_Alias" | "Cmd_Alias" => AliasKind::Cmnd,
        _ => return None,
    };

    // One alias line may define SEVERAL aliases of the same kind, separated by a
    // top-level `:` (`Alias ::= '<Kind>_Alias' Spec (':' Spec)*`, sudoers(5) #345).
    // Split on those segment colons; alias defs carry no tag colons, so
    // `skip_tag_colons = false`. Each segment is one `NAME = member, member, ...`.
    let mut specs: Vec<AliasSpec> = Vec::new();
    for seg in split_top_level_segments(rest, false) {
        // `structural_eq`, not `find('=')`: an alias member may be a quoted or
        // backslash-escaped principal containing its own `=` (#622).
        let Some(eq) = structural_eq(seg) else {
            return Some(LineKind::Malformed(format!(
                "{kw} definition is missing its `=` and member list"
            )));
        };
        let name = seg[..eq].trim();
        if name.is_empty() {
            return Some(LineKind::Malformed(format!("{kw} definition has no name")));
        }
        let members: Vec<String> = seg[eq + 1..]
            .split(',')
            .map(str::trim)
            .filter(|m| !m.is_empty())
            .map(str::to_string)
            .collect();
        if members.is_empty() {
            return Some(LineKind::Malformed(format!(
                "{kw} {name} has an empty member list"
            )));
        }
        specs.push(AliasSpec {
            name: name.to_string(),
            members,
        });
    }
    // `split_top_level_segments` always yields at least one segment, so `specs` is
    // non-empty here.
    Some(LineKind::Alias(AliasDef { kind, specs }))
}

/// Classify a user specification, or report it Malformed.
///
/// Shape: `User_List Host_List = Cmnd_Spec_List (: Host_List = Cmnd_Spec_List)*`
/// (sudoers(5) `User_Spec`). The line is split into top-level `:`-separated
/// host-group segments (see [`split_top_level_segments`]); the FIRST segment is
/// `User_List Host_List = Cmnd_Spec_List` (the user list is the leading
/// COMMA-CONTINUED token run - see [`split_user_list`]), and every later segment is
/// `Host_List = Cmnd_Spec_List` sharing that same user list. Each segment becomes one
/// [`HostGroup`], so tag inheritance is per-group and does not cross the `:` (the
/// #345 fix; grounded against `cvtsudoers -f json`, sudo 1.9.17p2).
fn classify_user_spec(trimmed: &str) -> LineKind {
    // A user-spec MUST contain a STRUCTURAL `=` (the User/Host = Cmnd boundary).
    // Without one it is not a valid spec - report the dispatcher's catch-all
    // message. A line whose ONLY `=` is inside a quoted principal (`"a=b" h1`)
    // has no boundary at all, so the byte-level `contains('=')` this replaced
    // waved it through to the segment loop and produced a message blaming the
    // segment rather than the line (#622/#630).
    if structural_eq(trimmed).is_none() {
        return LineKind::Malformed(
            "not a recognized sudoers entry (expected a Defaults entry, an alias \
             definition, an include directive, or a `user host = command` spec)"
                .to_string(),
        );
    }

    // Split into host-group segments on the top-level `:` (told apart from the
    // `NOPASSWD:` tag colon, the runas `(u:g)` colon, and an escaped `\:` by the
    // splitter). `skip_tag_colons = true` for user-specs.
    let segments = split_top_level_segments(trimmed, true);

    let mut users: Vec<String> = Vec::new();
    let mut host_groups: Vec<HostGroup> = Vec::new();
    for (idx, seg) in segments.iter().enumerate() {
        // `structural_eq`, not `find('=')`: a `User_List`/`Host_List` principal may
        // be a quoted or backslash-escaped name containing its own `=`, and
        // splitting at that byte puts the boundary inside the principal - dropping
        // the host list on one side or the whole `NOPASSWD` grant on the other
        // (#622/#630).
        let Some(eq) = structural_eq(seg) else {
            return LineKind::Malformed(
                "user specification segment is missing its `= command` part".to_string(),
            );
        };
        let lhs = seg[..eq].trim();
        let rhs = &seg[eq + 1..];

        let hosts = if idx == 0 {
            // First segment: `User_List Host_List`. The `User_List` is a
            // COMMA-CONTINUED run, not just the first word (see
            // `split_user_list`); the rest is the host list. sudoers requires both.
            let (user_part, host_part) = split_user_list(lhs);
            if user_part.is_empty() || host_part.is_empty() {
                return LineKind::Malformed(
                    "user specification needs both a user list and a host list before the `=`"
                        .to_string(),
                );
            }
            users = comma_split(user_part);
            comma_split(host_part)
        } else {
            // Continuation segment: the whole LHS is the host list (the user list is
            // shared from the first segment).
            if lhs.is_empty() {
                return LineKind::Malformed(
                    "user specification continuation segment needs a host list before its `=`"
                        .to_string(),
                );
            }
            comma_split(lhs)
        };

        let cmnd_specs = parse_cmnd_spec_list(rhs);
        if cmnd_specs.is_empty() {
            return LineKind::Malformed(
                "user specification has no command after the `=`".to_string(),
            );
        }
        host_groups.push(HostGroup { hosts, cmnd_specs });
    }

    LineKind::UserSpec(UserSpec { users, host_groups })
}

/// Split `s` into top-level `:`-separated segments, in source order (always >= 1).
///
/// The sudoers(5) top-level `:` separates user-spec host-groups
/// (`Host_List = Cmnd_Spec_List`) and alias-def specs (`NAME = members`). It must be
/// told apart from three other colons (all grounded against `visudo`/`cvtsudoers`,
/// sudo 1.9.17p2 - see #345):
///   * the runas-group colon inside `(runas_users:runas_groups)` - suppressed by paren
///     `depth`. A `(` bumps `depth` ONLY at a `Cmnd_Spec` start (the runas position: after
///     the host-group's STRUCTURAL `Host_List = Cmnd_Spec_List` `=`, or after a top-level
///     `,` in that command list). A bare mid-command `(` - including one right after a
///     command-argument `=` (`/bin/echo a(b`, `/bin/echo X=(y`) - is a literal byte and
///     does NOT desync `depth` (#416). So only a depth-0 colon can separate;
///   * a literal colon inside a command/argument - sudo REQUIRES it to be
///     backslash-escaped (`\:`; an unescaped `:` in a command is a syntax error), so
///     the char after a backslash is skipped;
///   * when `skip_tag_colons` (user-specs only), the `NOPASSWD:` / `PASSWD:` tag
///     colon - recognised because the token immediately before it (the text back to
///     the last GUARDED `,` / `)` / consumed colon / structural or genuine-option
///     `=` (a `,` inside a quoted option value and a `)` at depth 0 are value or
///     command bytes and reset nothing - see those arms), with
///     whitespace irrelevant) is a [`Tag`] keyword. Alias defs carry no tags, so
///     they pass `false`. A genuine `Option_Spec`'s own `=` puts that boundary
///     after the option's VALUE rather than after the `=`, so `TIMEOUT=30 NOEXEC:`
///     still leaves `NOEXEC` alone in the span (#538 gap C - see the `'='` arm); a
///     REJECTED `=` (a command argument's own) leaves the boundary where it
///     already was rather than re-arming it mid-argument (see the `'='` arm).
fn split_top_level_segments(s: &str, skip_tag_colons: bool) -> Vec<&str> {
    // Byte-range PAIRS of every value-ENCLOSING quoted span in `s`, built
    // INCREMENTALLY by the `'='` arm below, exactly when it recognizes the
    // CURRENT `=` as a genuine `Option_Spec` anchor (#538 gap C; see
    // `quoted_value_span`'s doc comment): a colon INSIDE
    // an `Option_Spec` value's own enclosing quotes (`CWD="/a:b"`) is a value
    // byte, not a tag/separator colon -- but a colon sitting between two
    // UNRELATED quotes (e.g. two different host-groups' commands each ending
    // in their own `"`) is a genuine separator and must still split; see the
    // `:` arm. Recording a span happens no later than the `=` that opens it,
    // which is always at a LOWER byte index than anything the span could
    // enclose, so by the time the scan below reaches a character inside a
    // span, that span is already in `quotes` -- one forward pass suffices.
    let mut quotes: Vec<(usize, usize)> = Vec::new();
    // Quoted PRINCIPAL spans, built incrementally by the `'"'` arm below.
    // Needed because a `User_List`/`Host_List` principal may contain its OWN
    // `=` (`"a=b" ALL = NOPASSWD: /bin/ls` is rc 0 with `User_List ["a=b"]`,
    // probe 2026-08-02): without this the `'='` arm takes that byte for the
    // structural `Host_List = Cmnd_Spec_List` separator, arms `in_cmnd_list`
    // before the real one, and leaves `tok_start` stranded behind it -- so the
    // following tag colon measures a span like `b" ALL = NOPASSWD`, `parse_tag`
    // rejects it, the colon is read as a segment separator, and the trailing
    // command becomes its own segment with no `=`, failing the whole line as
    // Malformed. A FALSE `sudo-F01` on a line sudo accepts, which on the
    // sibling `alice "h=1" = NOPASSWD: ALL` also loses the passwordless grant
    // (#622/#630).
    //
    // Openers come from [`opens_principal`] (alternate pairing), and the arm is
    // gated `!in_cmnd_list`: past the structural `=` there are no more
    // principals until the next `:` re-clears it, so a quote in COMMAND text
    // never gains principal power. That gate is what keeps two quotes each
    // merely closing a DIFFERENT command from forming a span across the very
    // `=` being located -- on `alice h1 = /bin/sh -c f() CWD=" : h2 =
    // NOPASSWD: /bin/su "y` (rc 0, TWO host groups) a blind whole-line pairing
    // covers the genuine `h2 =` and suppresses it, which is the hazard
    // [`split_cmnd_specs`]'s doc comment records.
    //
    // [`structural_eq`] opens spans with the same predicate on an already-split
    // segment, minus the gate (it returns at the first unmasked `=`, so it never
    // reaches command text). Both exist because the splitter and its callers
    // locate that `=` independently.
    let mut principal_quotes: Vec<(usize, usize)> = Vec::new();
    // Quote spans of the RUNAS region, which `principal_quotes` structurally cannot
    // hold: its arm is gated `!in_cmnd_list`, and `in_cmnd_list` is already true
    // everywhere a runas group can open (a `(` only bumps `depth` at a `Cmnd_Spec`
    // start, which exists only past the structural `=`). A quoted runas principal is
    // legal -- `alice ALL = (root,"a)b") ...` is rc 0 with `runasusers ["root", "a)b"]`
    // (probe 2026-08-02) -- so its bytes, `)` included, are literal. Kept separate
    // from `principal_quotes` rather than merged into it because that vector also
    // gates the `'='` and `':'` arms, and widening those is a behaviour change this
    // registry does not need to make.
    let mut runas_quotes: Vec<(usize, usize)> = Vec::new();
    let mut segments = Vec::new();
    let mut seg_start = 0usize;
    // Start of the token immediately preceding the cursor, reset at each token-list
    // boundary (`,` / `)` / a consumed colon / the structural `Host_List =
    // Cmnd_Spec_List` `=` / a genuine `Option_Spec`'s own `=` - NOT whitespace, so a
    // tag keyword spaced away from its colon is still recognised, and NOT a
    // REJECTED `=` (a command argument's own, possibly chained: `X=CWD=...`;
    // #538): leaving it untouched on a rejection means a LATER `=` in
    // the same argument still measures its preceding token from the run's true last
    // boundary instead of from mid-argument. Used only to spot a tag keyword
    // sitting just before a colon. A genuine `Option_Spec`'s `=` moves this past the
    // option's whole `KEY=value` token rather than just past the `=`, so it can land
    // at `s.len()`; every read goes through `preceding_token`, which clamps.
    let mut tok_start = 0usize;
    let mut depth: i32 = 0;
    let mut escaped = false;
    // A `(` opens a runas group ONLY at a `Cmnd_Spec` START (the runas position), which
    // exists ONLY inside the Cmnd_Spec_List - i.e. AFTER the host-group's structural
    // `Host_List = Cmnd_Spec_List` `=`. `in_cmnd_list` tracks whether the cursor is past
    // that structural `=` within the current host-group: it starts false and resets false
    // at each top-level `:` (a `:` opens a new host-group whose Host_List comes first).
    // Only the FIRST top-level `=` per host-group is structural; a later `=` is a literal
    // byte inside a command argument (`X=(y`) and must NOT re-arm the runas position, else
    // its `(` desyncs `depth` and swallows the next top-level `:` -- the #416 colon-splitter
    // miss (a `(` right after a command-arg `=` was read as a runas opener).
    let mut in_cmnd_list = false;
    // `at_spec_start` is true from a `Cmnd_Spec` boundary (the structural `=`, or a
    // top-level `,` while in the command list) through leading whitespace until the first
    // non-whitespace char: a `(` there is a runas opener (bumps `depth`, so a `(u:g)`
    // runas colon is suppressed), any other char means the command word has begun so every
    // later `(` in the spec is a literal byte. This REPLACES the old quote tracking: in
    // valid sudoers a top-level `:` is never inside a balanced quote (`/bin/echo "a:b"` is
    // visudo-REJECTED), and a tag cannot precede the runas group (`NOPASSWD: (root) ...` is
    // visudo-REJECTED), so the runas `(` is always the spec's first non-whitespace char
    // (grounded on sudo 1.9.17p2, #416).
    let mut at_spec_start = false;

    for (i, c) in s.char_indices() {
        if escaped {
            // The previous char was a backslash; this char is a literal part of the
            // current token (`\:`, `\,`, ...). Never a separator or a boundary.
            escaped = false;
            continue;
        }
        if c == '\\' {
            escaped = true;
            at_spec_start = false;
            continue;
        }
        if c.is_whitespace() {
            // Leading whitespace keeps `at_spec_start`; interior whitespace is a no-op
            // (it never resets `tok_start`, so a tag keyword spaced from its colon is
            // still recognised).
            continue;
        }
        match c {
            '(' if at_spec_start => {
                depth += 1;
                at_spec_start = false;
            }
            ')' if depth > 0 && !inside_a_clean_quoted_region(&runas_quotes, i) => {
                // ONLY a `)` that actually closes a runas group this scan opened is a
                // token boundary. That takes TWO tests, structural and content, because
                // a `)` is literal in three different ways:
                //
                //  1. unquoted in ordinary command text,
                //  2. unquoted in an `Option_Spec` value (`alice ALL = CWD=/a)b
                //     NOPASSWD: /bin/ls` is rc 0 with value `/a)b`, probe 2026-08-02),
                //  3. quoted, anywhere -- including inside a runas principal.
                //
                // `depth > 0` covers 1 and 2 and is STRUCTURAL rather than positional on
                // purpose: in both, a `(` never opened anything, because `(` only bumps
                // `depth` at `at_spec_start`. So depth is 0 there and the `)` falls
                // through to `_` as the literal byte it is.
                //
                // It does NOT cover 3, and that gap was a live fail-open: on
                // `alice ALL = (root,"a)b") NOPASSWD: /bin/ls : h2 = NOPASSWD: /bin/su`
                // (rc 0, TWO User_Specs, `authenticate: false` on both) the quoted `)`
                // sits at depth 1, so the arm fired on it, dropped `depth` to 0, and
                // left the REAL closer to fall through without resetting `tok_start`.
                // The tag colon then measured `b") NOPASSWD`, `parse_tag` rejected it,
                // the colon became a host-group separator and the whole line was
                // discarded Malformed -- taking the independent `h2` grant with it.
                //
                // A guard of just `i >= tok_start` asks instead "is this `)`
                // past the value the `=` arm already consumed?". That covers
                // `CWD=/a)b` but NOT a `)` in plain command text, where
                // `tok_start` is legitimately behind the cursor: on
                // `alice ALL = /bin/echo a) CWD="/a, NOPASSWD: /bin/su"` it moved the
                // marker to just after the `)`, which made the following `CWD` look like
                // a whole preceding token, promoted a command ARGUMENT's `=` to a
                // genuine `Option_Spec` anchor, and opened a bogus quote span (#629).
                // The `XWD=` control probes identically, confirming the `)` and not the
                // keyword is what does the damage.
                //
                // WHICH separator that span then masks differs per splitter, and the
                // two must not be conflated: THIS function splits only on `:`, so here
                // the span covers the tag colon and the line wrongly stays one segment.
                // The dropped-grant half happens in [`split_cmnd_specs`], whose `,` arm
                // is the real `Cmnd_Spec` boundary - real sudo (rc 0) reads that line as
                // TWO `Cmnd_Spec`s with `NOPASSWD: /bin/su"` second, and masking the `,`
                // merges them and loses the passwordless grant.
                //
                // "Subsumes `i >= tok_start`" holds in one direction only. The
                // case `i >= tok_start` alone covers and this one does not is
                // `depth > 0 && i < tok_start`
                // -- a `)` inside an already-consumed option value while a runas group is
                // open, where this arm now decrements `depth` and drags `tok_start`
                // backwards. Reaching it needs an exact `Option_Spec` keyword inside a
                // runas list AND an UNQUOTED value (`alice ALL = (root,CWD=/a)b)
                // NOPASSWD: /bin/ls`); the QUOTED spelling is now excluded by
                // `runas_quotes` before it can reach this arm at all, which
                // real sudo rejects rc 1, so it is unreachable for valid input rather
                // than merely unlikely.
                depth -= 1;
                tok_start = i + c.len_utf8();
                at_spec_start = false;
            }
            ',' if !inside_a_clean_quoted_region(&quotes, i)
                && !inside_a_clean_quoted_region(&runas_quotes, i) =>
            {
                // The `runas_quotes` half: a comma inside a QUOTED runas principal
                // is a value byte (`("a,CWD=")` is rc 0 with ONE principal named
                // `a,CWD=`), so it must not advance `tok_start`. Letting it left
                // `preceding_token` at the following `=` equal exactly `CWD`, an
                // `Option_Spec` keyword harvested from inside a principal; the arm
                // below then read the principal's own CLOSING quote as a value
                // OPENER and pushed a bogus span that swallowed the real top-level
                // comma, losing a NOPASSWD-on-ALL grant.
                //
                // Note this is NOT the same test as the `depth > 0` one the `')'`
                // arm needs. An UNQUOTED comma in a runas list IS a token boundary
                // (`(u1,u2)` is rc 0), so depth alone would mask the wrong commas;
                // quoting is what makes this one literal.
                // A comma inside a CLEAN (closed) `Option_Spec` value quote
                // (`CWD="/a,b"`) is a value byte and must not touch `tok_start`; the
                // guard routes it to `_` below, exactly as the `:` arm does with its own
                // separator (#643). Dragging the marker into mid-value there left the
                // following tag colon measuring a span like `b" NOPASSWD`, which
                // `parse_tag` rejects, so the colon was read as a host-group separator
                // and the `NOPASSWD` grant vanished from the model.
                //
                // Content-based, and deliberately NOT the structural `depth > 0` the
                // `')'` arm uses, because for a comma
                // quoting is the ONLY thing that makes the byte literal: `CWD=/a,b`
                // UNQUOTED is rc 1 on real sudo (and so is `CWD=/a:b`), so a positional
                // guard would mask a comma in a value sudo actually rejects, converting
                // a loud fatal into a silent misparse. `CWD="/a,b"` is rc 0 with value
                // `/a,b` (probes 2026-08-02). This is why the two arms do not mirror
                // each other despite looking symmetric.
                tok_start = i + c.len_utf8();
                // A top-level (depth-0) comma starts the next `Cmnd_Spec` ONLY inside the
                // command list, whose runas `(` sits at the next non-whitespace char. A
                // comma in the Host_List (`h1, h2 = cmd`) has no runas position, and a
                // comma inside a runas group (depth > 0) is not a spec boundary - but it
                // IS still a token boundary there (`(u1,u2)` is rc 0), so `tok_start`
                // advances regardless of depth.
                if depth == 0 && in_cmnd_list {
                    at_spec_start = true;
                }
            }
            '"' if !in_cmnd_list && opens_principal(&principal_quotes, i) => {
                // Opens a quoted principal (see `principal_quotes` above). An
                // unterminated quote pairs into nothing and so protects nothing,
                // matching every other quote rule in this file.
                if let Some(close) = find_closing_quote(s, i + 1) {
                    principal_quotes.push((i, close));
                }
                at_spec_start = false;
            }
            '"' if depth > 0 && opens_principal(&runas_quotes, i) => {
                // Opens a quoted RUNAS principal (see `runas_quotes` above). Disjoint
                // from the arm above rather than merely ordered after it: `depth > 0`
                // implies `in_cmnd_list`, since a `(` only bumps `depth` at
                // `at_spec_start`, which is armed only past the structural `=`.
                //
                // `opens_principal` is what makes this alternate-pairing rather than
                // whole-line pairing: at the CLOSING quote of a recorded span the
                // predicate is false, so the closer cannot re-open and pair with some
                // later unrelated quote. Whole-line pairing is the hazard
                // [`split_cmnd_specs`]'s doc comment records.
                if let Some(close) = find_closing_quote(s, i + 1) {
                    runas_quotes.push((i, close));
                }
                at_spec_start = false;
            }
            '=' if !inside_a_clean_quoted_region(&principal_quotes, i)
                && !inside_a_clean_quoted_region(&runas_quotes, i) =>
            {
                // Both registries, for the same reason: an `=` inside a quoted
                // principal is a value byte and never an `Option_Spec` anchor. The
                // `principal_quotes` half has been here since the `=` face was
                // closed; the `runas_quotes` half is its runas-region twin, and its
                // absence is why the quoted-HOST-principal spelling
                // (`alice "h,CWD=" = ...`) was already protected while the quoted-
                // RUNAS-principal one was not.
                // An `Option_Spec`'s OWN `=` (`TIMEOUT=30`) is not a token boundary the
                // way a structural `=` is: the whole `KEY=value` is ONE `Cmnd_Spec`
                // prefix token, so `tok_start` must skip PAST the value. Leaving it just
                // after the `=` made the span at a following tag colon multi-word
                // (`"30 NOEXEC"` on `alice ALL = TIMEOUT=30 NOEXEC: /bin/ls`), so
                // `parse_tag` failed, the tag colon was read as a genuine host-group
                // separator, and the whole line - which `visudo -c -f -` accepts rc 0 -
                // was thrown away as Malformed (#538 gap C).
                //
                // POSITION-ANCHORED exactly like `parse_cmnd_spec`'s option scan, and
                // for the same reason: the candidate is the single token since the last
                // boundary (no `Option_Spec` keyword contains whitespace, so an exact
                // match already implies one word). A command's own `KEY=value` ARGUMENT
                // has a multi-word span (`"/usr/bin/env TIMEOUT"`) and is REJECTED here -
                // which is what real sudo does: on this host (1.9.17p2, 2026-07-30)
                // `cvtsudoers -f json` reads `alice h1 = /bin/echo NOPASSWD : h2 = ALL`
                // as TWO host groups with the first command `"/bin/echo NOPASSWD"`, i.e.
                // once the command word has begun, a later tag keyword is an ARGUMENT and
                // the colon really does separate. Requiring `in_cmnd_list` keeps the
                // structural `=` itself (span `"alice ALL"`, or `"ALL"` after a `,`) out
                // of the candidate set. `preceding_token` already trims, so whitespace
                // BEFORE this `=` (`CWD = 30`) is tolerated for free; whitespace AFTER it
                // is NOT (#538 - see the `skip_value_leading_whitespace` call below).
                //
                // A REJECTED `=` must NOT advance `tok_start` unless it IS the structural
                // `Host_List = Cmnd_Spec_List` `=` itself - the one rejection excluded by
                // the `in_cmnd_list` gate rather than by the keyword check, and a genuine
                // token-list boundary that must still be skipped. Any OTHER rejected `=`
                // is a command argument's own (possibly chained, `X=CWD=...`) and leaves
                // `tok_start` where it already was, so a LATER `=` in the same argument
                // still measures its preceding token from the run's true last boundary
                // rather than from mid-argument - advancing `tok_start` on EVERY
                // rejection would mean a chained second `=` (`X=CWD=...`) measures its own
                // preceding token as just `"CWD"` and gets wrongly accepted as a genuine
                // leading option (#538).
                let is_option_eq =
                    in_cmnd_list && parse_option_key(preceding_token(s, tok_start, i)).is_some();
                let after_eq = i + c.len_utf8();
                if is_option_eq {
                    // The value may itself be double-quoted or backslash-escaped
                    // (`CWD="/a b"`, `CWD=/a\ b`; #538 gap A/C), so a bare
                    // "next whitespace" scan would land INSIDE the value when it
                    // contains one. `option_value_end` is quote/escape-aware and
                    // returns `s.len()` when the value runs to the end of the string
                    // (no complete token follows it); `preceding_token` clamps the reads
                    // either way. `skip_value_leading_whitespace` first advances past any
                    // whitespace sudo allows AFTER the `=` (`TIMEOUT= 30`; #538)
                    // so `option_value_end` starts at the value's TRUE first byte
                    // rather than the separating space itself (which would otherwise
                    // read as an empty value and leave `tok_start` short of the real
                    // value - the same corruption `split_leading_option` had).
                    let value_start = skip_value_leading_whitespace(s, after_eq);
                    // This `=` is a genuine `Option_Spec` anchor (`is_option_eq`),
                    // so record its value's quote span, if it has one, right here -
                    // the SAME position-anchored point `is_option_eq` was decided at.
                    // A command argument merely SPELLED like a keyword never reaches
                    // this branch at all (9m regression fix; see
                    // `quoted_value_span`'s doc comment).
                    if let Some(span) = quoted_value_span(s, value_start) {
                        quotes.push(span);
                    }
                    tok_start = option_value_end(s, value_start);
                } else if !in_cmnd_list {
                    tok_start = after_eq;
                }
                // Only the FIRST top-level `=` of a host-group is the structural
                // `Host_List = Cmnd_Spec_List` separator; it opens the command list and
                // arms the first `Cmnd_Spec`'s runas position. A later `=` is an option's
                // or a command argument's and must NOT re-arm `at_spec_start` (the #416
                // colon-splitter fix).
                if !in_cmnd_list {
                    in_cmnd_list = true;
                    at_spec_start = true;
                }
            }
            ':' if depth == 0
                && !inside_a_clean_quoted_region(&quotes, i)
                && !inside_a_clean_quoted_region(&principal_quotes, i) =>
            {
                // A colon inside a CLEAN (closed) quoted `Option_Spec` value
                // (`CWD="/a:b"`) is a value byte, neither a tag colon nor a genuine
                // separator; the guard routes it to the `_` catch-all below instead
                // (#538 gap C). An unterminated quote pairs into no region at
                // all (`inside_a_clean_quoted_region`), so it does not gain this
                // protection -- matching `unterminated_quote_does_not_swallow_the_segment_colon`.
                //
                // The SAME is true of a colon inside a quoted PRINCIPAL, which is
                // why this arm consults both registries. `sudoers(5)` documents
                // quoting a name precisely "to avoid the need for escaping special
                // characters", and `:` is one of them: `alice "h:1" = NOPASSWD: ALL`
                // is rc 0 with `Host_List ["h:1"]` and `authenticate: false` (probe
                // 2026-08-02), while the unquoted `alice h:1 = ...` is rc 1. Reading
                // that quoted colon as a host-group separator left the first segment
                // with no `= command` part, so a line real sudo accepts was reported
                // Malformed and its passwordless grant was never linted.
                //
                // This arm was the sibling missed when the `'='` arm was routed
                // through `principal_quotes`: one registry, wired into one of the
                // arms that needed it.
                //
                // NOT swept here, and still open: a principal colon that needs no
                // quoting at all. `%:grp`, `%:#123` (`man 5 sudoers`, `User ::=
                // ... %:nonunix_group | %:#nonunix_gid`) and an IPv6 host literal
                // (`alice fe80::1 = ...`) are all rc 0 and still split wrongly.
                // Pre-existing, tracked separately - a green run of the quoted
                // cases says nothing about those.
                let preceding = preceding_token(s, tok_start, i);
                if skip_tag_colons && parse_tag(preceding).is_some() {
                    // A tag colon (`NOPASSWD:`): not a segment separator. The next token
                    // starts just after it (still mid-spec, so `at_spec_start` stays false).
                    tok_start = i + 1;
                } else {
                    // A genuine top-level segment separator. `tok_start = i + 1` resets
                    // the preceding-token start for the next segment; the next segment
                    // opens with a Host_List (not a `Cmnd_Spec`), so both `at_spec_start`
                    // and `in_cmnd_list` reset until that segment's structural `=`.
                    segments.push(s[seg_start..i].trim());
                    seg_start = i + 1;
                    tok_start = i + 1;
                    at_spec_start = false;
                    in_cmnd_list = false;
                }
            }
            _ => at_spec_start = false,
        }
    }
    segments.push(s[seg_start..].trim());
    segments
}

/// The first byte index at or after `start` that is not whitespace: `start`
/// advanced past any run of whitespace SEPARATING an `Option_Spec`'s `=` from
/// its value. `man 5 sudoers`'s own EBNF shows an `Option_Spec` glued with NO
/// space at all (`Chdir_Spec ::= 'CWD=directory'`, sudo 1.9.17p2 rendered
/// page) and states no general whitespace tolerance around it -- this is NOT
/// grounded in that grammar text. The shipping parser instead follows the
/// REAL parser's more permissive behavior: `visudo -c -f -` (sudo 1.9.17p2,
/// re-probed 2026-07-31) accepts whitespace on EITHER side of an
/// `Option_Spec`'s `=` (`alice ALL = CWD = "/a b" NOPASSWD: /bin/ls` and
/// `alice ALL = TIMEOUT= 30 NOEXEC: /bin/ls` are both rc 0) despite the
/// grammar's glued spelling being the only one it documents (#538) - every
/// test written before this fix happened to glue the value to the `=`
/// (`TIMEOUT=30`), which is why this gap sat unnoticed under a green suite.
/// Shared by [`split_leading_option`]'s own
/// value scan and [`split_top_level_segments`]'s `'='` arm, both of which must
/// find the value's TRUE first byte before calling [`option_value_end`] (which
/// itself still assumes `start` IS that first byte - see its doc comment).
fn skip_value_leading_whitespace(s: &str, start: usize) -> usize {
    s[start..]
        .char_indices()
        .find(|&(_, c)| !c.is_whitespace())
        .map_or(s.len(), |(i, _)| start + i)
}

/// Parse a comma-separated `Cmnd_Spec_List` into [`CmndSpec`]s.
///
/// Each `Cmnd_Spec` is `Runas_Spec? Option_Spec* (Tag_Spec ':')* Cmnd`. The options
/// and tags written EXPLICITLY on each spec are captured (NOT inheritance-resolved -
/// the #330 pass walks the list and applies tag inheritance). A leading `(runas)`
/// group is captured.
fn parse_cmnd_spec_list(s: &str) -> Vec<CmndSpec> {
    split_cmnd_specs(s)
        .into_iter()
        .filter(|spec| !spec.is_empty())
        .map(parse_cmnd_spec)
        .collect()
}

/// Split a `Cmnd_Spec_List` on TOP-LEVEL commas, honoring backslash escapes and runas
/// parens.
///
/// A `,` separates two `Cmnd_Spec`s ONLY when it is (1) not backslash-escaped and (2) at
/// paren-depth 0. This mirrors the depth + escape + positional-paren scanning in
/// [`split_top_level_segments`] (which splits on `:`), minus its tag-keyword / `:` logic,
/// and is grounded against `cvtsudoers -f json` (sudo 1.9.17p2, #370 / #416):
///   * a `\,` is an ESCAPED literal comma inside one command token (like `\:`), so the
///     char after a backslash is skipped;
///   * a `,` inside a runas group `(root, operator)` is at paren-depth > 0 and is part
///     of the runas user list, NOT a `Cmnd_Spec` separator - so `depth` tracks `(`/`)`;
///   * a `(` bumps `depth` ONLY at a `Cmnd_Spec` START (the runas position, `at_spec_start`
///     below). A bare mid-command `(` (e.g. `/bin/echo a(b`) is a literal byte and must
///     NOT desync `depth`, so `cvtsudoers -f json` keeps `/bin/echo a(b, /bin/su` as TWO
///     commands (#416). A GLOBAL paren-balance pre-scan would be WRONG: a valid
///     `(ALL) /bin/echo a(b` is globally unbalanced (2 `(`, 1 `)`) yet `(ALL)` is a real
///     runas group, so a leading/runas-position `(` must be told apart from a mid-token `(`.
///
/// A comma inside a value-ENCLOSING pair of unescaped `"` is masked (does not split;
/// #538 gap A, narrowed to [`quoted_value_span`]). This parser's
/// ORIGINAL premise here was "there is no quote tracking, because in a VALID config
/// a top-level `,` is never inside a balanced quote" - TRUE for a COMMAND (sudo
/// REJECTS an unescaped quoted comma there: `visudo -c` / `cvtsudoers` reject
/// `/bin/echo "a, b"`; a literal comma needs `\,`, per bullet 1) but FALSE for an
/// `Option_Spec` VALUE, where quoting a comma is exactly how sudo accepts one
/// (`alice ALL = CWD="/a,b" /bin/ls` is `visudo -c -f -` rc 0, host probe
/// 2026-07-31). So the premise held for the domain the parser originally shipped
/// for (commands only) and broke once options got their own quote-aware value
/// scanner.
///
/// Masking is scoped to an `Option_Spec` value's OWN enclosing pair only - an opener must
/// belong to that option's OWN `=` (#538; the `=` itself must be an option's, not just any
/// `=`, and whitespace between the `=` and the opener is tolerated - see
/// [`quoted_value_span`]): TWO quotes that
/// each merely CLOSE a different, unrelated command are NOT a pair, even when they are the
/// only two quotes in the whole `Cmnd_Spec_List` and would look "closed" under a blind
/// whole-string scan (`/bin/echo x", NOPASSWD: /bin/ls "y` still splits into two commands -
/// see `two_quotes_each_closing_a_different_command_do_not_mask_the_comma_separator`). An
/// UNTERMINATED (or non-`=`-anchored) quote still must not suppress the split (`cvtsudoers`
/// still splits `/bin/echo "x, /bin/su` into two commands - a lone `"` pairs with nothing,
/// so the comma after it is never masked; see
/// `unterminated_quote_does_not_swallow_comma_separator`). A `"` in ordinary command text is
/// otherwise a literal byte with NO pairing power at all, and a quoted `(` is mid-command so
/// it never reaches `depth` anyway. This preserves the #416 fix (which retired the OLD
/// quote tracker that merged two `Cmnd_Spec`s past an unbalanced quote, hiding a grant).
///
/// Unlike [`split_top_level_segments`], this splitter receives ONLY the `Cmnd_Spec_List`
/// (the `rhs` after the structural `=`), so its own `'='` arm never re-arms `at_spec_start`
/// and never itself becomes a segment boundary: a command-argument `=` (`X=(y`) is still a
/// plain literal byte for every purpose OTHER than recognizing an `Option_Spec`'s own value
/// (9m regression fix, #538 gaps A/C - see [`quoted_value_span`]). The runas position is
/// armed only at the string start and after a top-level `,`. (The colon splitter, which
/// DOES see the structural `=`, must instead re-arm only on the FIRST `=` per host-group -
/// see its `in_cmnd_list` - or the same `=(` would desync there; #416.)
///
/// The backslash is kept VERBATIM in the value, matching the `\:` precedent (the
/// lints do not inspect argument contents). Segments are trimmed, mirroring
/// `split_top_level_segments`; empties are dropped by the caller.
fn split_cmnd_specs(s: &str) -> Vec<&str> {
    // Byte-range PAIRS of every value-ENCLOSING quoted span in `s`, built
    // INCREMENTALLY by the `'='` arm below - mirrors
    // [`split_top_level_segments`]'s own inline span computation (#538 gap A,
    // 9m regression fix; see [`quoted_value_span`]): a comma INSIDE an
    // `Option_Spec` value's OWN enclosing quotes (`CWD="/a,b"`) is a value
    // byte, not a `Cmnd_Spec` separator - but a comma between two UNRELATED
    // quotes (each closing a different command) is a genuine separator and
    // must still split; see the `,` arm.
    let mut quotes: Vec<(usize, usize)> = Vec::new();
    // Quote spans of the RUNAS region, the twin of the registry
    // [`split_top_level_segments`] carries under the same name and for the same
    // reason: a quoted runas principal is legal, so a `)` inside it is a literal
    // byte and must not be mistaken for the group's closer. Distinct from `quotes`
    // above, which tracks only `Option_Spec` VALUE spans.
    //
    // No LINT-level input flips a grant through this splitter alone: #650's
    // truncation in `parse_cmnd_spec` intercepts every line with a quoted `)` in
    // a runas list before this splitter's `tok_start` can matter. That masking is
    // a property of one CALLER, not of the splitter, so the arm is witnessed
    // directly instead -- see `quoted_close_paren_in_a_runas_principal_keeps_the_
    // option_value_anchor` and `a_depth_zero_quote_never_shields_a_later_runas_
    // close_paren` in this file's test module, which call `split_cmnd_specs`
    // itself. Both halves of the guard below are killed by them; nothing here is
    // expected to survive the mutation gate. Do not read a survivor on this arm
    // as normal.
    let mut runas_quotes: Vec<(usize, usize)> = Vec::new();
    let mut segments = Vec::new();
    let mut seg_start = 0usize;
    // Start of the token immediately preceding the cursor, reset at each
    // token-list boundary (a depth-0 `,` outside a quoted option value / a `)` that
    // closes a runas group at depth > 0 / an `Option_Spec`'s own `=` - not
    // whitespace). Mirrors [`split_top_level_segments`]'s own `tok_start`,
    // narrowed to what THIS splitter needs it for: recognizing, at each `=`,
    // whether the token since the last boundary is EXACTLY an `Option_Spec`
    // keyword (see the `'='` arm below). No `in_cmnd_list` gate is needed
    // here (unlike the sibling splitter): `s` is already just the
    // `Cmnd_Spec_List` itself, so every position in it is already "in the
    // cmnd list".
    let mut tok_start = 0usize;
    let mut depth: i32 = 0;
    let mut escaped = false;
    // A `(` opens a runas group ONLY at a `Cmnd_Spec` START (the runas position, before
    // the command word); a `(` anywhere else is a literal command byte. `at_spec_start`
    // is true from each segment start through leading whitespace, until the first
    // non-whitespace char: a `(` there is a runas opener (bumps `depth`), any other char
    // means the command word has begun so every later `(` in this spec is literal (#416).
    let mut at_spec_start = true;
    for (i, c) in s.char_indices() {
        if escaped {
            // The previous char was a backslash; this char (`\,`, ...) is a literal
            // part of the current command token, never a separator or boundary.
            escaped = false;
            continue;
        }
        if c == '\\' {
            escaped = true;
            at_spec_start = false;
            continue;
        }
        if c.is_whitespace() {
            // Leading whitespace keeps `at_spec_start`; interior whitespace is a no-op.
            continue;
        }
        match c {
            '(' if at_spec_start => {
                depth += 1;
                at_spec_start = false;
            }
            ')' if depth > 0 && !inside_a_clean_quoted_region(&runas_quotes, i) => {
                // Mirrors `split_top_level_segments`'s own `')'` arm exactly - see
                // there for the grounding probes and for why this needs BOTH a
                // structural and a content test. ONLY a `)` closing a runas group
                // this scan opened is a token boundary; a literal `)` in command
                // text or in an unquoted `Option_Spec` value never had a matching
                // `(` (which only bumps `depth` at `at_spec_start`), so `depth` is
                // 0 and it falls through to `_` as the literal byte it is, while a
                // `)` quoted inside a RUNAS PRINCIPAL is at depth > 0 and needs
                // `runas_quotes` to exclude it. (A quoted `)` in ordinary command
                // text is at depth 0 and never reaches this arm at all.)
                //
                // This subsumes the `i >= tok_start` guard it replaces for every
                // input this arm can actually see - with the same one-directional
                // caveat the sibling arm records (`depth > 0 && i < tok_start`,
                // unreachable for valid input; see there). Its two recorded misses
                // (#538 gap C) were both `depth == 0`
                // anyway: on `CHROOT="/a)CWD="` the stray `)` let a glued `CWD=` be
                // read as a genuine option anchor, opening a bogus quote span that
                // masked the real top-level comma (MISS-B), or dragged `tok_start`
                // back far enough that a GENUINE later option's `=` was measured
                // against the wrong preceding token and wrongly REJECTED, spilling
                // its value into command text where its own comma and tag colon
                // were misread (MISS-C). What the positional guard did NOT cover is
                // a `)` in ordinary command text, where `tok_start` is legitimately
                // behind the cursor and the guard therefore passes - the #629
                // fail-open.
                depth -= 1;
                tok_start = i + c.len_utf8();
                at_spec_start = false;
            }
            '"' if depth > 0 && opens_principal(&runas_quotes, i) => {
                // Opens a quoted RUNAS principal, populating the registry the `')'`
                // arm above consults. The twin of the same arm in
                // [`split_top_level_segments`]; `opens_principal` is what keeps this
                // alternate-pairing, so a span's own CLOSING quote cannot re-open and
                // pair with a later unrelated one.
                if let Some(close) = find_closing_quote(s, i + 1) {
                    runas_quotes.push((i, close));
                }
                at_spec_start = false;
            }
            ',' if depth == 0 && !inside_a_clean_quoted_region(&quotes, i) => {
                segments.push(s[seg_start..i].trim());
                seg_start = i + c.len_utf8();
                tok_start = i + c.len_utf8();
                at_spec_start = true;
            }
            '=' => {
                // Recognizes an `Option_Spec`'s own `=` the SAME
                // position-anchored way `split_top_level_segments`'s sibling
                // arm does (`preceding_token`/`tok_start`), so this
                // splitter's own quote-span source agrees with it: a
                // command argument merely SPELLED like a keyword
                // (`/bin/echo CWD="..."`) is never mistaken for a genuine
                // leading `Option_Spec` here either (#538 gaps A/C). This
                // arm never re-arms `at_spec_start`
                // and never itself becomes a segment boundary - a
                // command-argument `=` (`X=(y`) stays a literal byte for
                // every OTHER purpose, exactly as before; the only thing
                // added is recording a quote span when the value the `=`
                // introduces really is an option's own.
                //
                // A REJECTED `=` must leave `tok_start` untouched - unlike the
                // sibling splitter, THIS one has no structural `=` in its domain at
                // all (see `tok_start`'s declaration comment above), so there is no
                // exception here: advancing `tok_start` on EVERY rejection would mean
                // a command argument with a SECOND `=` (`X=CWD=...`) measures
                // that second `=`'s preceding token as just `"CWD"` from the first
                // rejection's landing point and gets wrongly accepted as a genuine
                // leading option (#538).
                //
                // WHY THIS ARM CARRIES NO REGISTRY GUARD, unlike every other
                // boundary arm in either splitter. The sibling
                // `split_top_level_segments` gates its own `'='` on BOTH
                // `principal_quotes` and `runas_quotes`, and its `')'` and `','`
                // arms are registry-gated too; here `')'` and `','` are, and this
                // one is not. That asymmetry is deliberate but it was never written
                // down, and "a registry wired into SOME arms and not others" is
                // exactly the shape of the fail-opens this branch kept
                // reintroducing (#622, #629, #630, #631, #643).
                //
                // It is safe because this arm cannot fire at `depth > 0` AT ALL,
                // which rests on two facts that only hold TOGETHER:
                //   1. The `,` arm above is `depth == 0`-gated, so no comma inside
                //      a runas group advances `tok_start`. (The sibling splitter
                //      needs `runas_quotes` on its own `,` arm precisely because
                //      that one is NOT depth-gated - the two splitters buy the same
                //      safety by different means.)
                //   2. `tok_start` therefore still points at or before the group's
                //      opening `(` at every `=` inside it, so `preceding_token`
                //      returns a slice that still CONTAINS that `(`, and
                //      `parse_option_key` is an exact match against bare keywords,
                //      so it answers None.
                // The rejection is self-sustaining: a rejected `=` leaves
                // `tok_start` untouched (the paragraph above), so every later `=` in
                // the same group is still measured from the same pre-`(` anchor.
                //
                // EITHER fact re-arms this arm if it changes. Relaxing the `,` arm's
                // depth gate, or making `parse_option_key` tolerant of leading
                // punctuation, would let a quoted runas principal like
                // `(root, CWD="/a,b")` be read as a genuine option anchor: it pushes
                // a bogus span into `quotes` and desyncs the `,` arm's own
                // `inside_a_clean_quoted_region` test for the next REAL top-level
                // comma, dropping or merging a `Cmnd_Spec`. Add the `runas_quotes`
                // guard here if either moves.
                let is_option_eq = parse_option_key(preceding_token(s, tok_start, i)).is_some();
                if is_option_eq {
                    let after_eq = i + c.len_utf8();
                    let value_start = skip_value_leading_whitespace(s, after_eq);
                    if let Some(span) = quoted_value_span(s, value_start) {
                        quotes.push(span);
                    }
                    tok_start = option_value_end(s, value_start);
                }
                at_spec_start = false;
            }
            _ => at_spec_start = false,
        }
    }
    segments.push(s[seg_start..].trim());
    segments
}

/// Parse one `Cmnd_Spec`: an optional `(runas)` group, zero or more `=`-form
/// options, zero or more `TAG:` tags, then the command token (the rest of the
/// spec).
///
/// The three prefix loops run in the GRAMMAR's order, `Runas_Spec? Option_Spec*
/// (Tag_Spec ':')* Cmnd` (sudoers(5), sudo 1.9.17p2). They are deliberately kept
/// SEPARATE and ORDERED rather than merged into one interleaved matcher: real
/// sudo enforces the order, and an interleaved matcher would accept
/// `NOEXEC: TIMEOUT=30 /bin/ls`, which `visudo -c -f -` rejects rc 1
/// (`syntax error`) on this host while the correctly-ordered
/// `TIMEOUT=30 NOEXEC: /bin/ls` is rc 0 (#538). This function is TOTAL and has
/// no reject path, so nothing here can DIAGNOSE the wrong order; keeping the
/// loops separate is what stops the parser from silently modelling a shape sudo
/// does not accept.
fn parse_cmnd_spec(spec: &str) -> CmndSpec {
    let mut rest = spec.trim();

    // Optional leading run-as spec: `(...)`.
    let mut runas = None;
    if let Some(after_open) = rest.strip_prefix('(')
        && let Some(close) = unquoted_unescaped(after_open, ')')
    {
        runas = Some(parse_runas(&after_open[..close]));
        rest = after_open[close + 1..].trim_start();
    }

    // Zero or more `=`-form `Option_Spec`s (`ROLE=`, `TIMEOUT=`, ...). The scan
    // is POSITION-ANCHORED: it only ever inspects the token at the CURRENT head
    // of `rest` and stops at the first token that is not an option, so an option
    // keyword written AFTER the command word stays part of the command
    // (`/usr/bin/env TIMEOUT=30` is ONE command to `cvtsudoers -f json`, with no
    // `Options` entry - host probe, sudo 1.9.17p2, 2026-07-30). A position-BLIND
    // scan over every whitespace token would harvest that keyword and truncate
    // the command to `/usr/bin/env`, re-creating the very corruption #538 exists
    // to close - and no differential would catch it, because no projector reads
    // the option field.
    let mut options = Vec::new();
    loop {
        rest = rest.trim_start();
        let Some((option, remainder)) = split_leading_option(rest) else {
            break;
        };
        options.push(option);
        rest = remainder;
    }

    // Zero or more `TAG:` prefixes. A tag is an UPPERCASE keyword from the
    // Tag_Spec set followed by `:`. Consume them left-to-right.
    let mut tags = Vec::new();
    loop {
        rest = rest.trim_start();
        let Some(colon) = rest.find(':') else { break };
        let candidate = rest[..colon].trim();
        let Some(tag) = parse_tag(candidate) else {
            break;
        };
        tags.push(tag);
        rest = rest[colon + 1..].trim_start();
    }

    // The remainder is the command. The reserved `ALL` (case-sensitive in
    // sudoers) is the run-anything built-in; anything else is a named command /
    // directory / Cmnd_Alias reference, kept verbatim.
    let cmnd_token = rest.trim();
    let cmnd = if cmnd_token == "ALL" {
        CmndItem::All
    } else {
        CmndItem::Cmnd(cmnd_token.to_string())
    };

    CmndSpec {
        runas,
        options,
        tags,
        cmnd,
    }
}

/// If `rest` STARTS with an `=`-form `Option_Spec`, split it off and return it
/// plus the remaining text; otherwise return `None` so the caller stops scanning.
///
/// `rest` must already be leading-trimmed. A keyword contains no `=` or `"` of
/// its own (see [`CmndOptionKey`]), so the FIRST byte-level `=` in `rest`
/// unambiguously separates it from the value - no quote/escape awareness is
/// needed for THIS half of the split, only for the value that follows.
/// `parse_option_key` then requires an EXACT match against the closed set,
/// trimmed - live `visudo -c -f -` accepts whitespace BEFORE an
/// `Option_Spec`'s own `=` too (`CWD = "/a b"`; #538, no `man 5 sudoers`
/// grounding - see [`skip_value_leading_whitespace`]'s doc comment) - which
/// is what keeps this position-anchored: if the true first token has no `=`
/// before its own terminating whitespace, the slice up to a LATER `=` (from
/// some unrelated later token) necessarily contains INTERNAL whitespace as
/// well, so it can never equal a bare keyword once trimmed and safely fails
/// instead of mis-recognizing anything.
///
/// The value itself runs from [`skip_value_leading_whitespace`]'s boundary -
/// the `=`'s next non-whitespace byte, since sudo also accepts whitespace
/// AFTER an `Option_Spec`'s `=` (`TIMEOUT= 30`; #538 - every test written
/// before this fix happened to glue the value to the `=`, which is why this
/// half of the gap sat unnoticed under a green suite) - to
/// [`option_value_end`]'s boundary (or the end of `rest`) - NOT simply "up to
/// the next whitespace": there is no passage in `man 5 sudoers` documenting
/// `Option_Spec` value quoting (see [`quoted_value_span`]'s doc comment);
/// the shipping parser accepts a value's special characters
/// EITHER double-quoted or backslash-escaped (`CWD="/tmp/a b"`,
/// `CWD=/tmp/a\ b`), confirmed by live probe, so a bare whitespace scan would
/// split INSIDE such a value (#538 gap A). The value is kept VERBATIM -
/// quotes and backslashes included (a `TIMEOUT=30m` suffix, a path, a
/// timestamp - none of it is coerced or unescaped; see [`CmndOption`]). The
/// whitespace SEPARATING the `=` from the value is excluded from the captured
/// value itself (`TIMEOUT= 30` captures `"30"`, not `" 30"`).
///
/// Returning `None` (rather than skipping the token) is what keeps the scan
/// position-anchored, and returning `None` for an unknown keyword is what keeps
/// the set CLOSED: `/usr/bin/env FOO=bar` is a single valid command to real sudo,
/// so a generic `WORD=VALUE` matcher would corrupt it.
fn split_leading_option(rest: &str) -> Option<(CmndOption, &str)> {
    let eq = rest.find('=')?;
    let key = parse_option_key(rest[..eq].trim())?;
    let value_start = skip_value_leading_whitespace(rest, eq + 1);
    let value_end = option_value_end(rest, value_start);
    Some((
        CmndOption {
            key,
            value: rest[value_start..value_end].to_string(),
        },
        &rest[value_end..],
    ))
}

/// Map an uppercase `Option_Spec` keyword to its [`CmndOptionKey`]. Returns
/// `None` for anything outside the closed set (so `parse_cmnd_spec` stops
/// consuming options and treats the rest as tags + command), exactly as
/// [`parse_tag`] does for the `Tag_Spec` set.
///
/// The ten members and the evidence for each (including why the man page's
/// seven-keyword `Option_Spec` block is not the whole set, and why matching is
/// case-sensitive) are documented on [`CmndOptionKey`].
fn parse_option_key(keyword: &str) -> Option<CmndOptionKey> {
    Some(match keyword {
        "ROLE" => CmndOptionKey::Role,
        "TYPE" => CmndOptionKey::Type,
        "NOTBEFORE" => CmndOptionKey::NotBefore,
        "NOTAFTER" => CmndOptionKey::NotAfter,
        "TIMEOUT" => CmndOptionKey::Timeout,
        "CWD" => CmndOptionKey::Cwd,
        "CHROOT" => CmndOptionKey::Chroot,
        "PRIVS" => CmndOptionKey::Privs,
        "LIMITPRIVS" => CmndOptionKey::LimitPrivs,
        "APPARMOR_PROFILE" => CmndOptionKey::AppArmorProfile,
        _ => return None,
    })
}

/// Parse the inside of a `(runas_users[:runas_groups])` group.
fn parse_runas(inner: &str) -> RunasSpec {
    match inner.split_once(':') {
        Some((u, g)) => RunasSpec {
            users: comma_split(u.trim()),
            groups: comma_split(g.trim()),
        },
        None => RunasSpec {
            users: comma_split(inner.trim()),
            groups: Vec::new(),
        },
    }
}

/// Map an uppercase tag keyword to its [`Tag`]. Returns `None` for a non-tag token
/// (so `parse_cmnd_spec` stops consuming tags and treats the rest as the command).
fn parse_tag(token: &str) -> Option<Tag> {
    Some(match token {
        "EXEC" => Tag::Exec,
        "NOEXEC" => Tag::NoExec,
        "FOLLOW" => Tag::Follow,
        "NOFOLLOW" => Tag::NoFollow,
        "LOG_INPUT" => Tag::LogInput,
        "NOLOG_INPUT" => Tag::NoLogInput,
        "LOG_OUTPUT" => Tag::LogOutput,
        "NOLOG_OUTPUT" => Tag::NoLogOutput,
        "MAIL" => Tag::Mail,
        "NOMAIL" => Tag::NoMail,
        "INTERCEPT" => Tag::Intercept,
        "NOINTERCEPT" => Tag::NoIntercept,
        "PASSWD" => Tag::Passwd,
        "NOPASSWD" => Tag::NoPasswd,
        "SETENV" => Tag::Setenv,
        "NOSETENV" => Tag::NoSetenv,
        _ => return None,
    })
}

/// Split `s` on commas, trimming each part and dropping empties.
fn comma_split(s: &str) -> Vec<String> {
    s.split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(str::to_string)
        .collect()
}

/// Split a user-spec's pre-`=` text into `(User_List, Host_List)`.
///
/// `Host_List` is trimmed; `User_List` may carry trailing ESCAPED whitespace
/// (`a\ "b c"` splits as `a\ ` / `"b c"`), so callers trim - the sole caller
/// maps `comma_split`, which does. This said "both trimmed" until #651 and was
/// already false then for non-ASCII whitespace; four sweeps of this function
/// did not catch it because the caller's trim masks it.
///
/// `User_Spec ::= User_List Host_List '='...` and `User_List ::= User | User ','
/// User_List` (sudoers(5), sudo 1.9.17p2). The two lists are separated by
/// whitespace, but a `User_List` comma may itself carry whitespace on either side,
/// so the boundary is NOT simply the first space: the user list is the leading
/// COMMA-CONTINUED token run. A whitespace run ends the user list only when
/// neither side of it is a comma. All three comma spellings are `visudo -c -f -`
/// rc 0 on this host (sudo 1.9.17p2, probed 2026-07-30) and `cvtsudoers -f json`
/// reports the same `User_List [bob, ALL]` / `Host_List [ALL]` for each:
///
/// ```text
/// bob, ALL ALL=(ALL) ALL      trailing comma  (corpus accept-user-list-whitespace-bug)
/// bob , ALL ALL=(ALL) ALL     standalone comma
/// bob ,ALL ALL=(ALL) ALL      leading comma
/// ```
///
/// Using [`split_first_word`] here instead (the pre-#538 behavior) truncated the
/// list at its first internal space: `bob, ALL ALL=(ALL) ALL` yielded
/// `users = ["bob"]` and the garbage host token `"ALL ALL"`, dropping the reserved
/// `ALL` principal and with it `sudo-W06`, the DISA finding for `ALL` in a
/// `User_List`.
///
/// The run is comma-DRIVEN, so it stops at the end of the user list rather than
/// eating a comma-separated HOST list that follows: `alice, bob web1, web2 = ...`
/// is `User_List [alice, bob]` / `Host_List [web1, web2]`, and `alice bob = ...`
/// (no comma at all) still splits at the first space.
///
/// A pre-`=` text that is ONE comma-continued run has no host list at all, so the
/// `Host_List` comes back empty and the caller reports it Malformed - which is what
/// real sudo does with `alice, bob = /bin/ls` (rc 1, `syntax error`).
///
/// # Round 2: a principal may itself carry whitespace
///
/// `man 5 sudoers` (rendered page lines 399-402, sudo 1.9.17p2): a principal "may
/// be enclosed in double quotes to avoid the need for escaping special
/// characters", or escape them directly (`\x20` / a plain `\ `). Host probes
/// (2026-07-31, all `visudo -c -f -` rc 0): `"my user", ALL ALL = ALL`,
/// `"my user" ALL = ALL`, and `my\ user ALL = ALL` all keep the space-bearing
/// principal as ONE `User_List` member. Round 1's whitespace scan had no notion of
/// quotes or escapes, so it split INSIDE the quoted/escaped principal - exactly
/// the Gap A/C failure class, on the users axis. [`unquoted_whitespace_runs`]
/// finds only whitespace OUTSIDE a quoted span and not consumed by a backslash
/// escape; the comma-continuation logic below is unchanged.
///
/// # Round 3: a quote GLUED directly onto a bare word, with no whitespace at all
///
/// Real sudo's lexer starts a fresh token at a `"` whether or not whitespace
/// precedes it (`man 5 sudoers` grants quoting unconditionally, not just after a
/// separator). `alice" h1"` (no space before the quote) is `visudo -c -f -` rc 0
/// on this host (2026-07-31) and `cvtsudoers -f json` splits it into `alice` and
/// `" h1"` -
/// `a_quote_right_after_a_bare_word_starts_a_new_principal_token_with_no_whitespace_needed`.
/// A whitespace-run boundary alone can never place a split there (there is no
/// whitespace outside the quoted span to find at all - the single space sits
/// INSIDE the pair), so the loop below also treats the OPEN position of a
/// [`simple_quote_pairs`] pair as a candidate boundary whenever it is glued to a
/// preceding non-`,` char at a position where no whitespace RUN ends. A quote at
/// `lhs`'s own start, or one reached after a comma, is not "glued"; one reached
/// after whitespace is already reachable through the whitespace-run candidates,
/// which is why the guard ASKS the run set rather than testing the char.
///
/// That phrasing is deliberate. This said "non-whitespace byte" until #651, and
/// re-deciding "is this whitespace a separator" here instead of asking the one
/// function that models it produced two fail-opens in opposite directions - see
/// the guard's own comment.
///
/// # #651: the mirror-image CLOSING quote
///
/// The rule above is HALF of the token-boundary semantic, and shipping only that
/// half was a fail-open. A quoted principal also ENDS at its closing quote, with
/// the next token starting at `close + 1` whether or not whitespace follows, so
/// the loop treats `close + 1` as a candidate too.
///
/// Without it `"ab"ALL = NOPASSWD: ALL` had NO candidate boundary at all: the
/// whitespace runs are empty (no whitespace outside the pair) and the glued-OPENER
/// candidate is skipped because `open == 0`. `split_user_list` returned
/// `(lhs, "")`, the host part was empty, and the line died as a false `sudo-F01`
/// that took the `NOPASSWD` grant with it. `visudo -c -f -` gives rc 0 and
/// `cvtsudoers -f json` reports `User_List ["ab"]` / `Host_List ["ALL"]`
/// (re-derived on rs-oracle9, sudo 1.9.17p2, 2026-08-02).
///
/// The shared abstraction is "the next token starts one byte past the CLOSING
/// DELIMITER", and it is worth naming precisely rather than loosely:
///
///   * [`option_value_end`] is the same rule for the same delimiter - a closing
///     QUOTE (`return close + 1`, #631).
///   * [`parse_cmnd_spec`] is the same rule for a different delimiter: its
///     `close` comes from `after_open.find(')')`, a closing PAREN of the runas
///     group. Do NOT read it as a co-model of the quote rule - that `find(')')`
///     is quote-BLIND, stops at a quoted paren and truncates `"a)b"` to `"a`,
///     and is filed as #650.
///
/// So two quote recognizers and one paren recognizer, and until #651 the
/// principal-side quote one was the odd out. Recognizers of one concept
/// disagreeing is the recurring shape on this surface (#622, #629, #630, #631,
/// #643).
fn split_user_list(lhs: &str) -> (&str, &str) {
    let lhs = lhs.trim();

    // Candidate boundaries, each `(candidate_start, resume_after)`: the split is
    // `lhs[..candidate_start]` / `lhs[resume_after..]`. Whitespace-run candidates
    // resume after the run; a glued-OPENER candidate resumes AT the quote itself
    // (no whitespace to skip); a glued-CLOSER candidate (#651) resumes one byte
    // PAST the closing quote, which is where the next token begins.
    let runs = unquoted_whitespace_runs(lhs);
    let mut candidates: Vec<(usize, usize)> = runs.clone();
    for (open, close) in simple_quote_pairs(lhs) {
        // The whitespace half of this guard ASKS `unquoted_whitespace_runs`
        // whether a run actually ends here, rather than re-deciding it.
        //
        // Its purpose has always been "skip the candidate that a whitespace run
        // already supplies". Two attempts to express that as a PREDICATE both
        // shipped defects, in opposite directions:
        //
        //   `u8::is_ascii_whitespace` on `bytes[open - 1]` -
        //       too NARROW. On `alice,<U+00A0>"b c" ALL` it pushed a candidate
        //       the run already covered; that candidate won and swallowed the
        //       USER principal `"b c"` into a host token.
        //   `char::is_whitespace` on the char - too WIDE. It matched
        //       `unquoted_whitespace_runs`' predicate but not its CONTEXT: that
        //       function ignores whitespace which is backslash-escaped or inside
        //       a quoted region. On `a\<VT>"b c" = NOPASSWD: ALL` the escape
        //       meant no run existed, the guard suppressed the candidate anyway,
        //       and with NO candidate at all the line became a false `sudo-F01`
        //       that dropped a passwordless-ALL grant.
        //
        // Matching predicates is not matching recognizers. Asking the run set
        // directly inherits the escape and quote context from the one place that
        // models it, so there is nothing left to keep in sync.
        //
        // Pinned in both directions by
        // `a_non_ascii_whitespace_before_an_opening_quote_is_not_a_boundary`
        // (too-narrow) and `escaped_whitespace_before_an_opening_quote_still_reports_the_grant`
        // (too-wide), each carrying its own one-byte control.
        //
        // The `,` half is still a predicate and is still escape-BLIND: an
        // escaped `a\,"b"` is a literal comma that does not continue the user
        // list, and this suppresses the candidate anyway. Filed as #675, with
        // the sibling in the continuation filter below; unswept here because the
        // two must move together.
        //
        // `open > 0` makes `lhs[..open]` non-empty, so `next_back()` is `Some`.
        //
        // `prev != '!'` is #670. A leading `!` NEGATES the principal that
        // follows it, so `ALL,!"svc acct" ALL` is two users and one host, not a
        // boundary at the quote. Without this conjunct the candidate at the
        // quote won, the user list became `["ALL", "!"]`, the host list
        // swallowed `"svc acct" ALL`, and the line went silent on a full
        // ALL/ALL elevation - no F01, no F02, no W06. Grounded: that line is
        // `visudo` rc 0 with users `ALL` + `svc acct` NEGATED and host `ALL`.
        if open > 0
            && let Some(prev) = lhs[..open].chars().next_back()
            && prev != ','
            && prev != '!'
            && !runs.iter().any(|&(_, end)| end == open)
        {
            candidates.push((open, open));
        }
        // The MIRROR of the opener rule above, and the reason `close` is bound
        // rather than discarded (#651): a quoted principal ENDS at its closing
        // quote, with the next token starting at `close + 1`, whitespace or not.
        // `option_value_end` (`return close + 1`, #631) and `parse_cmnd_spec`
        // (`after_open[close + 1..]`) already model exactly this on the
        // value/command side; the principal side modelled only the glued OPENER,
        // and that asymmetry dropped the whole grant on `"ab"ALL = ...`.
        //
        // A `close` at the very end of `lhs` yields no candidate: the slice
        // `lhs[close + 1..]` is then empty and `chars().next()` is None.
        // A following `,` or whitespace is excluded for the same reasons as in
        // the opener rule: whitespace already yields a candidate via
        // `unquoted_whitespace_runs`, and a `,` means the run continues.
        //
        // The two exclusions are NOT equally load-bearing. Measured by
        // deleting each conjunct separately and running the whole suite:
        //
        //   whitespace exclusion deleted -> rc 101. TWO tests fail:
        //       `a_space_then_a_comma_after_a_closing_quote_is_not_a_boundary`
        //       and
        //       `a_non_ascii_whitespace_then_a_comma_after_a_closing_quote_is_not_a_boundary`.
        //       LOAD-BEARING, and individually observable.
        //   comma exclusion deleted      -> rc 0, fully green. REDUNDANT.
        //
        // The comma one is redundant against the continuation filter below by
        // construction, not by luck: any candidate it would admit has `after`
        // beginning with `,`, which that filter rejects unconditionally. It is
        // kept as defence-in-depth and as a statement of intent, and nothing
        // pins it - say so rather than implying a test would catch its removal.
        //
        // This tests the CHAR at `close + 1` with `char::is_whitespace`, the
        // SAME predicate `unquoted_whitespace_runs` uses, and that agreement is
        // deliberate. It first shipped as a byte-level `u8::is_ascii_whitespace`
        // and the mismatch was a real defect, not a stylistic one: a whitespace
        // char outside the ASCII set (any non-ASCII one, and ASCII `0x0B`
        // VERTICAL TAB, which `char::is_whitespace` accepts and the byte test
        // does not) was NOT excluded here while `unquoted_whitespace_runs` DID
        // emit a run for it. The candidate was pushed, sorted ahead of the run,
        // and won.
        //
        // On `"ab"<U+00A0>,alice ALL` that swallowed a principal: `after` began
        // with the NBSP rather than with `,`, so the continuation filter could
        // not fire, and `alice` - which belongs to the USER list - ended up
        // inside a host token. The fork point split it correctly. Two
        // recognizers of "where does whitespace end a token" disagreeing is the
        // exact shape of every prior regression on this surface, so the fix is
        // to make them the same predicate rather than to document the gap.
        // `a_non_ascii_whitespace_then_a_comma_after_a_closing_quote_is_not_a_boundary`
        // pins it.
        //
        // `close + 1` is always a char boundary: `close` indexes a one-byte `"`.
        if let Some(next) = lhs[close + 1..].chars().next()
            && next != ','
            && !next.is_whitespace()
        {
            candidates.push((close + 1, close + 1));
        }
    }
    // #672: an unquoted `!` glued to a principal is a THIRD boundary spelling,
    // alongside the whitespace run and the two glued-quote candidates. Before
    // this, `alice!h1` produced no candidate at all, fell through to
    // `(lhs, "")`, folded to `Malformed` and took its NOPASSWD grant with it,
    // on a line `visudo` accepts (rc 0, host `h1` NEGATED).
    //
    // Each guard below is grounded, and three of the four exist to PRESERVE a
    // correct answer rather than to add one:
    //
    //   i > 0            a leading sigil negates the first principal; it is not
    //                    a boundary. `!!alice ALL = ...` is rc 0.
    //   prev != '!'      the rest of a leading run, same reason. `(!!root)`,
    //                    `alice!!h1` and `!!alice` are all rc 0, so the run may
    //                    be longer than one - which is also why `runas.rs`
    //                    trims rather than strips a single sigil.
    //   prev != ','      a `!` after a comma CONTINUES the user list.
    //                    `alice,!bob ALL = ...` is rc 0 with users
    //                    `alice` + `bob` negated.
    //   !separator_escaped
    //                    `alice\!h1 = ...` is `visudo` rc 1. Splitting there
    //                    would parse an INVALID file as `alice\` / `!h1` and
    //                    silently drop a correct `sudo-F01`. This is the one
    //                    guard whose absence loses a true positive rather than
    //                    causing a fail-open, and it is why the separator-rule
    //                    predicate was added to `boundary.rs` instead of being
    //                    re-derived here.
    //
    // A `!` inside a closed quoted span is not a boundary either (`a"b!c" ALL`
    // is rc 1); `spans` covers that.
    let spans = simple_quote_pairs(lhs);
    for (i, c) in lhs.char_indices() {
        if c == '!'
            && i > 0
            && !inside_a_clean_quoted_region(&spans, i)
            && !separator_escaped(lhs, i)
            && let Some(prev) = lhs[..i].chars().next_back()
            && prev != ','
            && prev != '!'
            && !runs.iter().any(|&(_, end)| end == i)
        {
            candidates.push((i, i));
        }
    }
    candidates.sort_unstable();

    for (start, resume) in candidates {
        let before = &lhs[..start];
        let after = &lhs[resume..];
        // The run continues across this boundary if a comma sits on either side
        // of it (`bob, ALL`, `bob ,ALL`) or IS it (`bob , ALL`, where the comma is
        // its own token and both adjacent runs continue). Both glued candidates
        // always pass this check, but for DIFFERENT reasons, and stating one
        // reason for both was wrong once already: an OPENER candidate's `after`
        // literally starts with `"`, while a CLOSER candidate's `after` starts
        // with the next token's first byte, which is `,`-excluded at the push
        // site instead. Neither `before` ends with `,` (excluded above).
        if !before.ends_with(',') && !after.starts_with(',') {
            // `after` starts right after the boundary - a non-whitespace char,
            // a quote, or the string end - so the HOST half is trimmed. That
            // holds exhaustively over the three candidate producers:
            // whitespace-run candidates resume at the first non-whitespace char
            // (or at a `\`), opener candidates resume at `"`, and closer
            // candidates are excluded by `!next.is_whitespace()` above, the SAME
            // predicate `unquoted_whitespace_runs` uses. An intermediate version
            // of the closer guard tested the BYTE with `u8::is_ascii_whitespace`,
            // which broke it for non-ASCII whitespace and swallowed a principal;
            // do not restore it.
            //
            // `before` is NOT guaranteed trimmed, and #651 widened that rather
            // than keeping it: since the opener guard began delegating to the run
            // set, an opener candidate whose preceding whitespace is ESCAPED is
            // admitted, so `a\ "b c"` splits with `before == "a\ "`. That is the
            // intended fix (the fork point returned `(lhs, "")` there), but it
            // means the caller trims - `comma_split` maps `str::trim`. A second
            // caller must not assume otherwise.
            return (before, after);
        }
    }
    (lhs, "")
}

/// Split off the first whitespace-delimited word from `s`, returning
/// `(first_word, remainder)`. The remainder keeps its leading whitespace stripped
/// only by the caller as needed. Returns `("", "")` for an all-whitespace input.
///
/// Used for the `include` / `includedir` keyword and the `User_Alias` /
/// `Runas_Alias` / `Host_Alias` / `Cmnd_Alias` keyword, both of which really are
/// single words. A user-spec's `User_List` is NOT (see [`split_user_list`]).
fn split_first_word(s: &str) -> (&str, &str) {
    let s = s.trim_start();
    match s.find(char::is_whitespace) {
        Some(i) => (&s[..i], &s[i..]),
        None => (s, ""),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(src: &str) -> SudoersFile {
        parse(src, Path::new("/etc/sudoers"))
    }

    /// Returns the `LineKind`s of the logical lines, dropping a single trailing
    /// `Blank` (the empty segment a final `\n` produces), for terse asserts.
    fn kinds(src: &str) -> Vec<LineKind> {
        let mut k: Vec<LineKind> = p(src).lines.into_iter().map(|l| l.kind).collect();
        if matches!(k.last(), Some(LineKind::Blank)) {
            k.pop();
        }
        k
    }

    // ---- stage 1: physical-line join ----

    #[test]
    fn line_continuation_joins_into_one_logical_line() {
        // sudoers(5): a trailing `\` continues the logical line. `carol ALL = \`
        // + `NOPASSWD: ALL` is ONE user-spec (verified visudo -c accepts it).
        let file = p("carol ALL = \\\n    NOPASSWD: ALL\n");
        // Exactly one non-trailing logical line (the join collapses the two
        // physical lines), plus the trailing empty segment from the final `\n`.
        let specs: Vec<_> = file
            .lines
            .iter()
            .filter(|l| matches!(l.kind, LineKind::UserSpec(_)))
            .collect();
        assert_eq!(specs.len(), 1, "the two physical lines form ONE user-spec");
        // The logical line is numbered at its FIRST physical line (1).
        assert_eq!(specs[0].line, 1);
        // The joined user-spec carries the NOPASSWD tag and the ALL command.
        let LineKind::UserSpec(spec) = &specs[0].kind else {
            unreachable!()
        };
        assert_eq!(spec.host_groups[0].cmnd_specs.len(), 1);
        assert_eq!(spec.host_groups[0].cmnd_specs[0].tags, vec![Tag::NoPasswd]);
        assert_eq!(spec.host_groups[0].cmnd_specs[0].cmnd, CmndItem::All);
    }

    #[test]
    fn continuation_span_covers_both_physical_lines() {
        // The joined logical line's span runs from the first physical line's start
        // to the last physical line's end, so ariadne can render the whole thing.
        let src = "carol ALL = \\\n    NOPASSWD: ALL\n";
        let file = p(src);
        let spec = file
            .lines
            .iter()
            .find(|l| matches!(l.kind, LineKind::UserSpec(_)))
            .expect("a user-spec");
        // Start at byte 0, end at the end of `... NOPASSWD: ALL` (the byte before
        // the final newline).
        assert_eq!(spec.span.start, 0);
        assert_eq!(spec.span.end, src.len() - 1);
    }

    // ---- stage 2: comment disambiguation (#329 core) ----

    #[test]
    fn plain_hash_is_a_comment() {
        assert_eq!(kinds("# just a comment\n"), vec![LineKind::Comment]);
    }

    #[test]
    fn hash_include_is_a_directive_not_a_comment() {
        // `#include` / `#includedir` are legacy include directives, NOT comments.
        let k = kinds("#include /etc/sudoers.local\n");
        assert_eq!(
            k,
            vec![LineKind::Include(IncludeDirective {
                kind: IncludeKind::Include,
                legacy: true,
                path: "/etc/sudoers.local".to_string(),
            })]
        );
        let kd = kinds("#includedir /etc/sudoers.d\n");
        assert_eq!(
            kd,
            vec![LineKind::Include(IncludeDirective {
                kind: IncludeKind::IncludeDir,
                legacy: true,
                path: "/etc/sudoers.d".to_string(),
            })]
        );
    }

    #[test]
    fn at_include_is_a_modern_directive() {
        let k = kinds("@includedir /etc/sudoers.d\n");
        assert_eq!(
            k,
            vec![LineKind::Include(IncludeDirective {
                kind: IncludeKind::IncludeDir,
                legacy: false,
                path: "/etc/sudoers.d".to_string(),
            })]
        );
    }

    #[test]
    fn hash_digits_in_user_position_is_a_uid_subject_not_a_comment() {
        // `#1000 ALL=(ALL) ALL` -> the `#1000` is a UID subject of a user-spec,
        // NOT a comment (verified visudo -c accepts it).
        let k = kinds("#1000 ALL=(ALL) ALL\n");
        match &k[0] {
            LineKind::UserSpec(spec) => {
                assert_eq!(spec.users, vec!["#1000".to_string()]);
                assert_eq!(spec.host_groups[0].cmnd_specs[0].cmnd, CmndItem::All);
            }
            other => panic!("expected a user-spec for a #uid subject, got {other:?}"),
        }
    }

    #[test]
    fn hash_followed_by_nondigit_is_a_comment() {
        // `#!/bin/sh` and `# 1000` (space) are comments, not UID subjects.
        assert_eq!(kinds("#!/bin/sh\n"), vec![LineKind::Comment]);
        assert_eq!(kinds("# 1000 ALL=(ALL) ALL\n"), vec![LineKind::Comment]);
    }

    // ---- aliases (#331 surface) ----

    #[test]
    fn alias_definition_captures_kind_name_and_members() {
        let k = kinds("User_Alias ADMINS = alice, bob, %wheel\n");
        assert_eq!(
            k,
            vec![LineKind::Alias(AliasDef {
                kind: AliasKind::User,
                specs: vec![AliasSpec {
                    name: "ADMINS".to_string(),
                    members: vec!["alice".to_string(), "bob".to_string(), "%wheel".to_string()],
                }],
            })]
        );
    }

    #[test]
    fn cmd_alias_is_a_synonym_for_cmnd_alias() {
        // `Cmd_Alias` (>=1.9.0) is the synonym; it maps to AliasKind::Cmnd.
        let k = kinds("Cmd_Alias FOO = /bin/ls\n");
        match &k[0] {
            LineKind::Alias(a) => assert_eq!(a.kind, AliasKind::Cmnd),
            other => panic!("expected a Cmnd alias, got {other:?}"),
        }
    }

    #[test]
    fn alias_without_equals_is_malformed() {
        // `User_Alias ADMINS alice bob` (no `=`) is rejected by visudo -c.
        assert!(matches!(
            kinds("User_Alias ADMINS alice bob\n")[0],
            LineKind::Malformed(_)
        ));
    }

    // ---- Defaults (#333 surface) ----

    #[test]
    fn defaults_global_with_flag_and_value() {
        let k = kinds("Defaults !authenticate, secure_path=\"/usr/bin\"\n");
        match &k[0] {
            LineKind::Defaults(d) => {
                assert_eq!(d.scope, DefaultsScope::Global);
                assert_eq!(d.settings.len(), 2);
                assert_eq!(
                    d.settings[0],
                    DefaultSetting {
                        negated: true,
                        name: "authenticate".to_string(),
                        value: None,
                        value_double_quoted: false,
                    }
                );
                assert_eq!(
                    d.settings[1],
                    DefaultSetting {
                        negated: false,
                        name: "secure_path".to_string(),
                        value: Some("/usr/bin".to_string()),
                        // `secure_path="/usr/bin"` -- a clean surrounding
                        // double-quote pair was stripped (#423).
                        value_double_quoted: true,
                    }
                );
            }
            other => panic!("expected a Defaults entry, got {other:?}"),
        }
    }

    #[test]
    fn defaults_scoped_variants_capture_their_binding() {
        // The four scope sigils @ : ! > glue directly to `Defaults`.
        let cases = [
            (
                "Defaults@somehost env_reset\n",
                DefaultsScope::Host("somehost".into()),
            ),
            (
                "Defaults:alice !authenticate\n",
                DefaultsScope::User("alice".into()),
            ),
            (
                "Defaults!/bin/ls noexec\n",
                DefaultsScope::Cmnd("/bin/ls".into()),
            ),
            (
                "Defaults>root use_pty\n",
                DefaultsScope::Runas("root".into()),
            ),
        ];
        for (src, want_scope) in cases {
            match &kinds(src)[0] {
                LineKind::Defaults(d) => assert_eq!(d.scope, want_scope, "for {src:?}"),
                other => panic!("expected Defaults for {src:?}, got {other:?}"),
            }
        }
    }

    #[test]
    fn defaultsfoo_is_not_a_defaults_keyword() {
        // `Defaults` glued to a non-sigil word is NOT the keyword; it falls
        // through (and, lacking an `=`, is Malformed as a bare word).
        assert!(matches!(
            kinds("Defaultsfoo bar\n")[0],
            LineKind::Malformed(_)
        ));
    }

    // ---- #405: Defaults settings-list comma split is escape/quote-aware ----
    //
    // Grounded against visudo/cvtsudoers 1.9.17p2 (2026-07-03): a `,` inside a
    // Defaults value is NOT always a setting separator. It stays part of the
    // SAME setting's value when it is either (a) backslash-escaped in an
    // unquoted value (`Wrong\,ok` -> cvtsudoers `"Wrong,ok"`, ONE setting), or
    // (b) inside a double-quoted value, escaped or not (`"Wrong, try again"` ->
    // ONE setting, comma retained verbatim -- quoting alone protects it, no
    // backslash needed). A naive `s.split(',')` mis-parses both into extra
    // bogus settings. `split_cmnd_specs` (#370) already got escape-awareness
    // for the Cmnd_Spec_List; this is the Defaults-list analog, plus
    // quote-awareness that list never needed (commands are not quoted).
    //
    // Per the #370 precedent (`cmnd_token` is kept VERBATIM, no unescaping),
    // this fix corrects only the SPLIT BOUNDARY: an unquoted escaped comma's
    // backslash is retained verbatim in the parsed value (KISS, no new
    // unescaping semantics); a quoted comma's value already round-trips
    // exactly since the existing quote-strip only touches the outer pair.

    #[test]
    fn defaults_unquoted_escaped_comma_stays_in_one_setting_value() {
        // cvtsudoers: badpass_message="Wrong\,ok,logfile=/var/log/sudo" ->
        // 2 settings, NOT 3. The naive split.split(',') would wrongly cut this
        // into "badpass_message=Wrong\", "ok", "logfile=/var/log/sudo".
        let k = kinds("Defaults badpass_message=Wrong\\,ok,logfile=/var/log/sudo\n");
        match &k[0] {
            LineKind::Defaults(d) => {
                assert_eq!(d.settings.len(), 2, "settings: {:?}", d.settings);
                assert_eq!(d.settings[0].name, "badpass_message");
                // Verbatim retention (matches the #370 cmnd_token precedent): the
                // escape backslash stays in the value; only the split boundary is
                // fixed, not full escape-sequence decoding.
                assert_eq!(d.settings[0].value.as_deref(), Some("Wrong\\,ok"));
                assert_eq!(d.settings[1].name, "logfile");
                assert_eq!(d.settings[1].value.as_deref(), Some("/var/log/sudo"));
            }
            other => panic!("expected a Defaults entry, got {other:?}"),
        }
    }

    #[test]
    fn defaults_quoted_comma_stays_in_one_setting_value() {
        // cvtsudoers: badpass_message="Wrong, try again" -> ONE setting, the
        // comma retained in the value -- quoting alone protects it, no
        // backslash needed. Followed by a real comma-separated second setting.
        let k = kinds("Defaults badpass_message=\"Wrong, try again\",logfile=/var/log/sudo\n");
        match &k[0] {
            LineKind::Defaults(d) => {
                assert_eq!(d.settings.len(), 2, "settings: {:?}", d.settings);
                assert_eq!(d.settings[0].name, "badpass_message");
                assert_eq!(d.settings[0].value.as_deref(), Some("Wrong, try again"));
                assert_eq!(d.settings[1].name, "logfile");
                assert_eq!(d.settings[1].value.as_deref(), Some("/var/log/sudo"));
            }
            other => panic!("expected a Defaults entry, got {other:?}"),
        }
    }

    #[test]
    fn defaults_escaped_quote_inside_quoted_value_does_not_end_the_quote() {
        // cvtsudoers: badpass_message="a \" b, c" -> ONE setting (value keeps
        // the escaped quote and the comma both), followed by logfile=... . A
        // quote-blind splitter would end the quoted region at the escaped `\"`
        // and mis-split on the comma that follows.
        let k = kinds("Defaults badpass_message=\"a \\\" b, c\",logfile=/var/log/sudo\n");
        match &k[0] {
            LineKind::Defaults(d) => {
                assert_eq!(d.settings.len(), 2, "settings: {:?}", d.settings);
                assert_eq!(d.settings[0].name, "badpass_message");
                assert_eq!(d.settings[0].value.as_deref(), Some("a \\\" b, c"));
                assert_eq!(d.settings[1].name, "logfile");
                assert_eq!(d.settings[1].value.as_deref(), Some("/var/log/sudo"));
            }
            other => panic!("expected a Defaults entry, got {other:?}"),
        }
    }

    #[test]
    fn defaults_baseline_two_settings_still_split_on_plain_comma() {
        // No-regression baseline (cvtsudoers ground truth): a plain comma with
        // no escaping/quoting still separates two settings.
        let k = kinds("Defaults syslog=auth, logfile=/var/log/sudo\n");
        match &k[0] {
            LineKind::Defaults(d) => {
                assert_eq!(d.settings.len(), 2, "settings: {:?}", d.settings);
                assert_eq!(d.settings[0].name, "syslog");
                assert_eq!(d.settings[0].value.as_deref(), Some("auth"));
                assert_eq!(d.settings[1].name, "logfile");
                assert_eq!(d.settings[1].value.as_deref(), Some("/var/log/sudo"));
            }
            other => panic!("expected a Defaults entry, got {other:?}"),
        }
    }

    // ---- user-specs + tag-state-machine surface (#330) ----

    #[test]
    fn basic_user_spec_with_runas_and_all() {
        let k = kinds("root ALL=(ALL:ALL) ALL\n");
        match &k[0] {
            LineKind::UserSpec(s) => {
                assert_eq!(s.users, vec!["root".to_string()]);
                assert_eq!(s.host_groups[0].hosts, vec!["ALL".to_string()]);
                assert_eq!(s.host_groups[0].cmnd_specs.len(), 1);
                let cs = &s.host_groups[0].cmnd_specs[0];
                assert_eq!(
                    cs.runas,
                    Some(RunasSpec {
                        users: vec!["ALL".to_string()],
                        groups: vec!["ALL".to_string()],
                    })
                );
                assert_eq!(cs.cmnd, CmndItem::All);
            }
            other => panic!("expected a user-spec, got {other:?}"),
        }
    }

    #[test]
    fn cmnd_spec_list_records_explicit_tags_per_command_for_330() {
        // sudoers(5): `ray rushmore = NOPASSWD: /bin/kill, PASSWD: /bin/ls, /usr/bin/lprm`
        // - only /bin/kill is NOPASSWD; /bin/ls RESETS to PASSWD; lprm inherits PASSWD.
        // The parser records the EXPLICIT tags written on each spec (NOT
        // inheritance-resolved) so the #330 pass can apply the state machine.
        let k = kinds("ray rushmore = NOPASSWD: /bin/kill, PASSWD: /bin/ls, /usr/bin/lprm\n");
        let LineKind::UserSpec(s) = &k[0] else {
            panic!("expected a user-spec, got {:?}", k[0]);
        };
        assert_eq!(s.host_groups[0].cmnd_specs.len(), 3);
        // First command carries the explicit NOPASSWD.
        assert_eq!(s.host_groups[0].cmnd_specs[0].tags, vec![Tag::NoPasswd]);
        assert_eq!(
            s.host_groups[0].cmnd_specs[0].cmnd,
            CmndItem::Cmnd("/bin/kill".to_string())
        );
        // Second command carries the explicit PASSWD (the reset).
        assert_eq!(s.host_groups[0].cmnd_specs[1].tags, vec![Tag::Passwd]);
        assert_eq!(
            s.host_groups[0].cmnd_specs[1].cmnd,
            CmndItem::Cmnd("/bin/ls".to_string())
        );
        // Third command carries NO explicit tag (inheritance is #330's job).
        assert_eq!(s.host_groups[0].cmnd_specs[2].tags, Vec::<Tag>::new());
        assert_eq!(
            s.host_groups[0].cmnd_specs[2].cmnd,
            CmndItem::Cmnd("/usr/bin/lprm".to_string())
        );
    }

    #[test]
    fn user_spec_command_references_named_alias() {
        // A `Cmnd_Alias` reference appears as a named CmndItem; #331 resolves it.
        let k = kinds("ADMINS ALL = SERVICES\n");
        let LineKind::UserSpec(s) = &k[0] else {
            panic!("expected a user-spec, got {:?}", k[0]);
        };
        assert_eq!(
            s.host_groups[0].cmnd_specs[0].cmnd,
            CmndItem::Cmnd("SERVICES".to_string())
        );
    }

    // ---- malformed (#329 / sudo-F01) ----

    #[test]
    fn garbage_line_is_malformed() {
        // No `=`, not any valid kind -> Malformed (visudo -c rejects it).
        assert!(matches!(kinds("frobnicate\n")[0], LineKind::Malformed(_)));
        assert!(matches!(
            kinds("this is not valid sudoers\n")[0],
            LineKind::Malformed(_)
        ));
    }

    #[test]
    fn user_spec_without_command_is_malformed() {
        // `alice ALL=` has nothing after the `=` (visudo -c rejects it).
        assert!(matches!(kinds("alice ALL=\n")[0], LineKind::Malformed(_)));
    }

    #[test]
    fn good_lines_around_a_malformed_line_still_classify() {
        // The TOTAL parser keeps classifying after a malformed line.
        let file = p("root ALL=(ALL) ALL\nfrobnicate\nDefaults env_reset\n");
        let kinds: Vec<_> = file
            .lines
            .iter()
            .map(|l| std::mem::discriminant(&l.kind))
            .collect();
        // user-spec, malformed, defaults (+ trailing blank).
        assert!(matches!(file.lines[0].kind, LineKind::UserSpec(_)));
        assert!(matches!(file.lines[1].kind, LineKind::Malformed(_)));
        assert!(matches!(file.lines[2].kind, LineKind::Defaults(_)));
        let _ = kinds;
    }

    #[test]
    fn blank_and_comment_lines_are_classified() {
        let file = p("\n# c\n   \n");
        assert!(matches!(file.lines[0].kind, LineKind::Blank));
        assert!(matches!(file.lines[1].kind, LineKind::Comment));
        assert!(matches!(file.lines[2].kind, LineKind::Blank));
    }

    // ---- inline `#` comments (#329 part A; the W01 false-negative) ----
    //
    // Grounding (visudo 1.9.17p2, `visudo -c -f` + `visudo -x - -f`):
    //   `alice ALL = /bin/ls # note`        -> command token == "/bin/ls"  (comment stripped)
    //   `bob ALL=(ALL) NOPASSWD: ALL # ok`  -> command == ALL, authenticate:false (NOPASSWD survives)
    //   `Defaults passprompt="a # b"`       -> value == "a # b" (# inside double quotes is literal)
    // A `#` introduces a comment-to-EOL WHEREVER it appears (outside double quotes),
    // NOT only when it leads the line.

    /// Pull the single `UserSpec` out of a one-spec file, panicking otherwise.
    fn only_spec(src: &str) -> UserSpec {
        let k = kinds(src);
        match k.into_iter().next() {
            Some(LineKind::UserSpec(s)) => s,
            other => panic!("expected a single user-spec, got {other:?}"),
        }
    }

    #[test]
    fn inline_comment_after_command_is_stripped_not_folded() {
        // visudo: `alice ALL = /bin/ls # note` -> the command is "/bin/ls"; the
        // trailing `# note` is a comment, NOT part of the command token.
        let s = only_spec("alice ALL = /bin/ls # note\n");
        assert_eq!(s.host_groups[0].cmnd_specs.len(), 1);
        assert_eq!(
            s.host_groups[0].cmnd_specs[0].cmnd,
            CmndItem::Cmnd("/bin/ls".to_string())
        );
    }

    #[test]
    fn inline_comment_after_nopasswd_all_keeps_all_and_the_tag() {
        // visudo: `bob ALL=(ALL) NOPASSWD: ALL # ok` -> command is ALL (not the
        // string "ALL # ok"), and the NOPASSWD tag is retained so W01 can fire.
        let s = only_spec("bob ALL=(ALL) NOPASSWD: ALL # ok\n");
        assert_eq!(s.host_groups[0].cmnd_specs.len(), 1);
        assert_eq!(s.host_groups[0].cmnd_specs[0].cmnd, CmndItem::All);
        assert!(
            s.host_groups[0].cmnd_specs[0].tags.contains(&Tag::NoPasswd),
            "the NOPASSWD tag must survive the inline comment so W01 can fire; got {:?}",
            s.host_groups[0].cmnd_specs[0].tags
        );
    }

    #[test]
    fn hash_inside_double_quoted_defaults_value_is_literal() {
        // visudo: `Defaults passprompt="a # b"` -> the value is literally `a # b`
        // (the `#` inside double quotes is NOT a comment). Verified against
        // `visudo -x - -f`: { "passprompt": "a # b" }.
        let k = kinds("Defaults passprompt=\"a # b\"\n");
        match &k[0] {
            LineKind::Defaults(d) => {
                assert_eq!(d.settings.len(), 1);
                assert_eq!(d.settings[0].name, "passprompt");
                assert_eq!(d.settings[0].value, Some("a # b".to_string()));
            }
            other => panic!("expected a Defaults entry, got {other:?}"),
        }
    }

    #[test]
    fn inline_comment_after_a_closed_quoted_defaults_value_is_stripped() {
        // visudo: `Defaults secure_path="/usr/bin:/bin" # comment` -> value is
        // "/usr/bin:/bin"; the `#` AFTER the closed quote is a real comment.
        let k = kinds("Defaults secure_path=\"/usr/bin:/bin\" # comment\n");
        match &k[0] {
            LineKind::Defaults(d) => {
                assert_eq!(d.settings.len(), 1);
                assert_eq!(d.settings[0].name, "secure_path");
                assert_eq!(d.settings[0].value, Some("/usr/bin:/bin".to_string()));
            }
            other => panic!("expected a Defaults entry, got {other:?}"),
        }
    }

    #[test]
    fn line_leading_hash_behaviors_stay_green_with_inline_stripping() {
        // The pre-existing line-leading cases MUST remain unchanged once inline
        // comment stripping is added.
        assert_eq!(kinds("# just a comment\n"), vec![LineKind::Comment]);
        assert_eq!(kinds("#!/bin/sh\n"), vec![LineKind::Comment]);
        assert_eq!(kinds("# 1000 ALL=(ALL) ALL\n"), vec![LineKind::Comment]);
        // `#include` is still a directive, not a comment.
        assert_eq!(
            kinds("#include /etc/sudoers.local\n"),
            vec![LineKind::Include(IncludeDirective {
                kind: IncludeKind::Include,
                legacy: true,
                path: "/etc/sudoers.local".to_string(),
            })]
        );
        // `#1000` UID subject still a user-spec, even with a trailing inline comment
        // (visudo: `#1000 ALL=(ALL) ALL # uid spec` -> userid 1000).
        let s = only_spec("#1000 ALL=(ALL) ALL # uid spec\n");
        assert_eq!(s.users, vec!["#1000".to_string()]);
        assert_eq!(s.host_groups[0].cmnd_specs[0].cmnd, CmndItem::All);
    }

    #[test]
    fn hash_digits_uid_subject_after_comma_is_not_a_comment() {
        // visudo: `root,#1000 ALL=(ALL) ALL` -> User_List = [root, userid 1000]
        // (a `#<digits>` UID can appear mid-user-list after a comma). The inline
        // comment strip must NOT treat that `#1000` as a comment. (The fixture is
        // written with no space after the comma because the Phase-0 parser split the
        // `User_List` at its first internal space; #538 removed that simplification -
        // see `split_user_list` - so the spaced spelling would work too, but the
        // fixture is left as written since the point here is solely that the
        // post-comma `#1000` survives the comment strip.)
        let s = only_spec("root,#1000 ALL=(ALL) ALL\n");
        assert_eq!(s.users, vec!["root".to_string(), "#1000".to_string()]);
        assert_eq!(s.host_groups[0].cmnd_specs[0].cmnd, CmndItem::All);
    }

    // The 11 tests that used to follow here (strip_keeps_percent_hash_gid_-
    // token_but_strips_a_letter_prefixed_hash through strip_ignores_a_-
    // quoted_close_paren_for_runas_state) pinned the old in-crate
    // `strip_inline_comment`'s `#<digits>` UID/GID exception and the
    // `in_runas_paren` state machine at the unit level. Removed (#562):
    // `strip_inline_comment` was deleted and replaced by the shared
    // `rulesteward_core::comment` helper (`StripConfig::SUDOERS`,
    // `uid_gid_exception: true`, now called from `join_physical_lines`
    // above), and every assertion above is reproduced byte-for-byte in
    // `crates/rulesteward-core/src/comment.rs`'s `sudoers_table` unit tests
    // and in `crates/rulesteward-sudoers/tests/comment_strip_equivalence.rs`.
    // ---- continuation edges (#329 part B) ----

    #[test]
    fn comment_line_ending_in_backslash_does_not_continue_bad_token() {
        // visudo: `# disable \` <NL> `@@@bad@@@` -> the `# disable \` is a comment
        // (its trailing `\` is INSIDE the comment, so it does NOT continue); line 2
        // is an independent syntax error (rc 1). So line 2 must be Malformed (F01).
        let file = p("# disable \\\n@@@bad@@@\n");
        // Line 1 is a comment; line 2 (the `@@@bad@@@`) is Malformed.
        let comment = file
            .lines
            .iter()
            .find(|l| matches!(l.kind, LineKind::Comment))
            .expect("the `# disable \\` line stays a comment");
        assert_eq!(comment.line, 1);
        let malformed = file
            .lines
            .iter()
            .find(|l| matches!(l.kind, LineKind::Malformed(_)))
            .expect("the `@@@bad@@@` line on line 2 is Malformed (F01)");
        assert_eq!(
            malformed.line, 2,
            "the malformed token is line 2, NOT swallowed into the comment's continuation"
        );
    }

    #[test]
    fn comment_line_ending_in_backslash_leaves_next_rule_active() {
        // visudo: `# disable \` <NL> `bob ALL=(ALL) NOPASSWD: ALL` -> the bob rule
        // is ACTIVE (the comment does not swallow it). So line 2 is a live UserSpec.
        let file = p("# disable \\\nbob ALL=(ALL) NOPASSWD: ALL\n");
        let spec = file
            .lines
            .iter()
            .find_map(|l| match &l.kind {
                LineKind::UserSpec(s) if l.line == 2 => Some(s),
                _ => None,
            })
            .expect("bob's rule on line 2 is a live UserSpec, not swallowed");
        assert_eq!(spec.users, vec!["bob".to_string()]);
        assert_eq!(spec.host_groups[0].cmnd_specs[0].cmnd, CmndItem::All);
        assert!(
            spec.host_groups[0].cmnd_specs[0]
                .tags
                .contains(&Tag::NoPasswd)
        );
    }

    #[test]
    fn backslash_then_whitespace_then_newline_continues() {
        // RE-DERIVED against visudo 1.9.17p2 (line-1-invalid-alone probe
        // `carol ALL =\<ws>*<NL>NOPASSWD: ALL`, where line 1 alone is invalid so a
        // pass PROVES the join happened): a backslash followed by zero-or-more
        // whitespace then a newline continues. `\<TAB>` AND `\<SPACE>` both continue
        // on this version (the review's claimed SPACE asymmetry does not reproduce).
        for (label, src) in [
            ("bslash-NL", "carol ALL =\\\nNOPASSWD: ALL\n"),
            ("bslash-TAB-NL", "carol ALL =\\\t\nNOPASSWD: ALL\n"),
            ("bslash-SPACE-NL", "carol ALL =\\ \nNOPASSWD: ALL\n"),
            ("bslash-SP-SP-NL", "carol ALL =\\  \nNOPASSWD: ALL\n"),
        ] {
            let specs: Vec<_> = p(src)
                .lines
                .into_iter()
                .filter(|l| matches!(l.kind, LineKind::UserSpec(_)))
                .collect();
            assert_eq!(
                specs.len(),
                1,
                "{label}: the two physical lines join into ONE user-spec"
            );
            let LineKind::UserSpec(s) = &specs[0].kind else {
                unreachable!()
            };
            assert_eq!(s.host_groups[0].cmnd_specs.len(), 1, "{label}");
            assert_eq!(
                s.host_groups[0].cmnd_specs[0].cmnd,
                CmndItem::All,
                "{label}"
            );
            assert!(
                s.host_groups[0].cmnd_specs[0].tags.contains(&Tag::NoPasswd),
                "{label}: NOPASSWD from the continued physical line"
            );
        }
    }

    #[test]
    fn backslash_then_nonwhitespace_does_not_continue() {
        // visudo: `carol ALL =\x` <NL> `NOPASSWD: ALL` -> `\x` is literal text, so
        // the backslash does NOT continue; line 1 and line 2 are INDEPENDENT logical
        // lines. The grounded property tested here is the NON-JOIN: the `\x` stays
        // on line 1's own logical line and `NOPASSWD: ALL` is a SEPARATE logical
        // line on line 2 (not appended to line 1). (Phase 0 does not validate the
        // command token, so line 1 still classifies as a user-spec carrying the
        // literal `\x` command - that command-validation gap is out of scope; the
        // point is the continuation did not fire.)
        let file = p("carol ALL =\\x\nNOPASSWD: ALL\n");
        // Two distinct non-blank logical lines, starting at lines 1 and 2.
        let non_blank: Vec<_> = file
            .lines
            .iter()
            .filter(|l| !matches!(l.kind, LineKind::Blank))
            .collect();
        assert_eq!(
            non_blank.len(),
            2,
            "the `\\x` does NOT continue; the two physical lines stay TWO logical lines, got {non_blank:?}"
        );
        assert_eq!(non_blank[0].line, 1);
        assert_eq!(non_blank[1].line, 2);
        // Line 1 kept the literal `\x` (the backslash did not consume the newline).
        let LineKind::UserSpec(s1) = &non_blank[0].kind else {
            panic!(
                "expected line 1 to classify as a user-spec, got {:?}",
                non_blank[0].kind
            );
        };
        assert_eq!(
            s1.host_groups[0].cmnd_specs[0].cmnd,
            CmndItem::Cmnd("\\x".to_string())
        );
        // Line 2 (`NOPASSWD: ALL`) is its OWN separate logical line, NOT joined onto
        // line 1. Alone it is not a valid spec, so it is Malformed - the proof it
        // was parsed independently rather than appended to line 1.
        assert!(
            matches!(non_blank[1].kind, LineKind::Malformed(_)),
            "line 2 must be a separate (Malformed-alone) logical line, got {:?}",
            non_blank[1].kind
        );
    }

    // ---- mutation distinguishers (#329 part C) ----

    #[test]
    fn every_tag_keyword_maps_to_its_variant() {
        // Ground each Tag_Spec keyword (sudoers(5) grammar) to its Tag variant. Kills
        // the per-arm parse_tag match deletions. Parsed in a real Cmnd_Spec carrying
        // the `TAG: cmnd` form so the path through parse_cmnd_spec is exercised.
        let cases: &[(&str, Tag)] = &[
            ("EXEC", Tag::Exec),
            ("NOEXEC", Tag::NoExec),
            ("FOLLOW", Tag::Follow),
            ("NOFOLLOW", Tag::NoFollow),
            ("LOG_INPUT", Tag::LogInput),
            ("NOLOG_INPUT", Tag::NoLogInput),
            ("LOG_OUTPUT", Tag::LogOutput),
            ("NOLOG_OUTPUT", Tag::NoLogOutput),
            ("MAIL", Tag::Mail),
            ("NOMAIL", Tag::NoMail),
            ("INTERCEPT", Tag::Intercept),
            ("NOINTERCEPT", Tag::NoIntercept),
            ("PASSWD", Tag::Passwd),
            ("NOPASSWD", Tag::NoPasswd),
            ("SETENV", Tag::Setenv),
            ("NOSETENV", Tag::NoSetenv),
        ];
        for (kw, want) in cases {
            let src = format!("u h = {kw}: /bin/ls\n");
            let s = only_spec(&src);
            assert_eq!(
                s.host_groups[0].cmnd_specs[0].tags,
                vec![*want],
                "tag keyword {kw} must map to {want:?}"
            );
            assert_eq!(
                s.host_groups[0].cmnd_specs[0].cmnd,
                CmndItem::Cmnd("/bin/ls".to_string())
            );
        }
    }

    #[test]
    fn runas_and_host_alias_keywords_classify_to_their_kinds() {
        // Kills the classify_alias arm deletions for Runas_Alias / Host_Alias (and
        // keeps User / Cmnd covered alongside).
        let cases: &[(&str, AliasKind)] = &[
            ("User_Alias NAME = alice\n", AliasKind::User),
            ("Runas_Alias NAME = root\n", AliasKind::Runas),
            ("Host_Alias NAME = web1\n", AliasKind::Host),
            ("Cmnd_Alias NAME = /bin/ls\n", AliasKind::Cmnd),
        ];
        for (src, want) in cases {
            match &kinds(src)[0] {
                LineKind::Alias(a) => assert_eq!(a.kind, *want, "for {src:?}"),
                other => panic!("expected an alias for {src:?}, got {other:?}"),
            }
        }
    }

    #[test]
    fn user_spec_with_host_present_but_no_user_distinguishes_or_from_and() {
        // classify_user_spec rejects when EITHER the user list or the host list is
        // empty (the `||`). visudo rejects `alice = /bin/ls` (user present, host
        // EMPTY) with a syntax error -> it MUST be Malformed. With `&&` this input
        // would be wrongly accepted as a UserSpec (false && true = false), so it
        // distinguishes `||` from `&&`.
        assert!(
            matches!(kinds("alice = /bin/ls\n")[0], LineKind::Malformed(_)),
            "host-empty (`alice = /bin/ls`) must be Malformed; a `&&` mutant would make it a UserSpec"
        );
    }

    // ---- #345: top-level `:` segment splitting (grounded vs visudo -c / cvtsudoers) ----

    #[test]
    fn multi_host_user_spec_splits_into_host_groups() {
        // `alice h1 = NOPASSWD: ALL : h2 = /bin/id` (visudo -c rc 0) -> two host-groups
        // sharing the user list. cvtsudoers -f json confirms two User_Spec entries
        // {h1 -> NOPASSWD ALL} and {h2 -> /bin/id}; the h2 group is a FRESH
        // Cmnd_Spec_List, so NOPASSWD does not carry into it.
        let s = only_spec("alice h1 = NOPASSWD: ALL : h2 = /bin/id\n");
        assert_eq!(s.users, vec!["alice".to_string()]);
        assert_eq!(s.host_groups.len(), 2, "two `:`-separated host-groups");
        assert_eq!(s.host_groups[0].hosts, vec!["h1".to_string()]);
        assert_eq!(s.host_groups[0].cmnd_specs.len(), 1);
        assert_eq!(s.host_groups[0].cmnd_specs[0].tags, vec![Tag::NoPasswd]);
        assert_eq!(s.host_groups[0].cmnd_specs[0].cmnd, CmndItem::All);
        assert_eq!(s.host_groups[1].hosts, vec!["h2".to_string()]);
        assert_eq!(
            s.host_groups[1].cmnd_specs[0].tags,
            Vec::<Tag>::new(),
            "NOPASSWD does not cross the `:` into the next host-group"
        );
        assert_eq!(
            s.host_groups[1].cmnd_specs[0].cmnd,
            CmndItem::Cmnd("/bin/id".to_string())
        );
    }

    #[test]
    fn tag_colon_with_surrounding_space_is_not_a_segment_separator() {
        // `NOPASSWD : ALL` (space before the tag colon, visudo -c rc 0) stays ONE
        // host-group with the NOPASSWD tag: the splitter recognises the tag keyword
        // regardless of whitespace around the `:` (whitespace is not a token boundary
        // for the tag-keyword check).
        let s = only_spec("alice h1 = NOPASSWD : ALL\n");
        assert_eq!(s.host_groups.len(), 1, "a tag colon must not split");
        assert_eq!(s.host_groups[0].cmnd_specs[0].tags, vec![Tag::NoPasswd]);
        assert_eq!(s.host_groups[0].cmnd_specs[0].cmnd, CmndItem::All);
    }

    #[test]
    fn runas_group_colon_is_not_a_segment_separator() {
        // The `:` inside `(runas_users:runas_groups)` is at paren depth > 0 and must
        // not split. `alice h1 = (root:wheel) /bin/ls` (visudo -c rc 0) -> one
        // host-group, runas users=[root] groups=[wheel].
        let s = only_spec("alice h1 = (root:wheel) /bin/ls\n");
        assert_eq!(s.host_groups.len(), 1, "a runas colon must not split");
        let cs = &s.host_groups[0].cmnd_specs[0];
        let runas = cs.runas.as_ref().expect("runas group present");
        assert_eq!(runas.users, vec!["root".to_string()]);
        assert_eq!(runas.groups, vec!["wheel".to_string()]);
    }

    #[test]
    fn escaped_colon_in_command_is_not_a_segment_separator() {
        // sudo requires a literal `:` in a command to be backslash-escaped (`\:`); an
        // unescaped one is a syntax error. `alice h1 = /usr/bin/scp user@host\:/tmp`
        // (visudo -c rc 0) -> ONE host-group, ONE command token keeping the escaped
        // colon verbatim (the lints do not inspect argument contents).
        let s = only_spec("alice h1 = /usr/bin/scp user@host\\:/tmp\n");
        assert_eq!(s.host_groups.len(), 1, "an escaped colon must not split");
        assert_eq!(s.host_groups[0].cmnd_specs.len(), 1);
        assert_eq!(
            s.host_groups[0].cmnd_specs[0].cmnd,
            CmndItem::Cmnd("/usr/bin/scp user@host\\:/tmp".to_string())
        );
    }

    #[test]
    fn multi_spec_cmnd_alias_splits_into_specs() {
        // `Cmnd_Alias A = ALL : B = /bin/ls, /bin/id` (visudo -c rc 0, both unused) ->
        // two same-kind specs: A=[ALL], B=[/bin/ls, /bin/id]. The `,` still splits
        // members WITHIN a spec; the `:` splits specs.
        match &kinds("Cmnd_Alias A = ALL : B = /bin/ls, /bin/id\n")[0] {
            LineKind::Alias(a) => {
                assert_eq!(a.kind, AliasKind::Cmnd);
                assert_eq!(a.specs.len(), 2, "two `:`-separated alias specs");
                assert_eq!(a.specs[0].name, "A");
                assert_eq!(a.specs[0].members, vec!["ALL".to_string()]);
                assert_eq!(a.specs[1].name, "B");
                assert_eq!(
                    a.specs[1].members,
                    vec!["/bin/ls".to_string(), "/bin/id".to_string()]
                );
            }
            other => panic!("expected an alias def, got {other:?}"),
        }
    }

    #[test]
    fn continuation_segment_without_equals_is_malformed() {
        // A `: Host` continuation segment with no `= Cmnds` is rejected by visudo -c
        // (`alice h1 = /bin/ls : h2` -> syntax error), so it must be sudo-F01
        // Malformed, not a silently-accepted UserSpec.
        assert!(
            matches!(
                kinds("alice h1 = /bin/ls : h2\n")[0],
                LineKind::Malformed(_)
            ),
            "a continuation segment missing its `=` must be Malformed; got {:?}",
            kinds("alice h1 = /bin/ls : h2\n")[0]
        );
    }

    #[test]
    fn quoted_paren_in_command_does_not_desync_segment_split() {
        // #345 adversarial-review fix (now via the #416 positional-paren rule): a `(` in
        // the MIDDLE of a command (here inside a quoted argument) is a literal command
        // byte, not a runas open-paren, so it must not desync `depth` and swallow the
        // later real segment `:`. Because the `(` is past the runas position it never
        // bumps `depth` regardless of quotes. visudo -c rc 0 + cvtsudoers -f json (sudo
        // 1.9.17p2): `alice h1 = /bin/sh -c "a(b" : h2 = /bin/id` parses as TWO
        // host-groups {h1 -> /bin/sh -c "a(b"} and {h2 -> /bin/id}.
        let s = only_spec("alice h1 = /bin/sh -c \"a(b\" : h2 = /bin/id\n");
        assert_eq!(
            s.host_groups.len(),
            2,
            "an unbalanced `(` inside quotes must not swallow the `:` separator"
        );
        assert_eq!(s.host_groups[0].hosts, vec!["h1".to_string()]);
        assert_eq!(
            s.host_groups[0].cmnd_specs[0].cmnd,
            CmndItem::Cmnd("/bin/sh -c \"a(b\"".to_string())
        );
        assert_eq!(s.host_groups[1].hosts, vec!["h2".to_string()]);
        assert_eq!(
            s.host_groups[1].cmnd_specs[0].cmnd,
            CmndItem::Cmnd("/bin/id".to_string())
        );
    }

    #[test]
    fn runas_group_then_segment_colon_splits() {
        // A runas `(root)` in the FIRST segment then a real segment `:`: paren-depth
        // must return to 0 at `)` so the `:` splits. visudo -c rc 0 + cvtsudoers:
        // `alice h1 = (root) /bin/ls : h2 = /bin/id` -> {h1, runas root, /bin/ls},
        // {h2, /bin/id}. (Kills the depth `+=`/`-=` mutants and the `> 0` guard's
        // `<`/`<=`/`==` variants. The balanced `)` sits at depth 1, so the depth-0-only
        // `> 0` -> `>= 0` variant is killed instead by
        // `unbalanced_close_paren_clamps_depth_and_keeps_later_separator`.)
        let s = only_spec("alice h1 = (root) /bin/ls : h2 = /bin/id\n");
        assert_eq!(
            s.host_groups.len(),
            2,
            "depth must return to 0 after the runas `)` so the `:` splits"
        );
        let cs0 = &s.host_groups[0].cmnd_specs[0];
        assert_eq!(
            cs0.runas.as_ref().map(|r| r.users.clone()),
            Some(vec!["root".to_string()])
        );
        assert_eq!(cs0.cmnd, CmndItem::Cmnd("/bin/ls".to_string()));
        assert_eq!(s.host_groups[1].hosts, vec!["h2".to_string()]);
        assert_eq!(
            s.host_groups[1].cmnd_specs[0].cmnd,
            CmndItem::Cmnd("/bin/id".to_string())
        );
    }

    #[test]
    fn runas_group_then_tag_colon_stays_one_group() {
        // A runas `(root)` then a tag colon `NOPASSWD:` must stay ONE host-group with
        // the tag recognised (`tok_start` reset just after `)`). visudo -c rc 0 +
        // cvtsudoers: `alice h1 = (root) NOPASSWD: ALL` -> one group {h1, runas root,
        // NOPASSWD, ALL}. (Kills the `)`-arm `tok_start` offset mutants.)
        let s = only_spec("alice h1 = (root) NOPASSWD: ALL\n");
        assert_eq!(
            s.host_groups.len(),
            1,
            "a tag colon after a runas group must not split"
        );
        let cs = &s.host_groups[0].cmnd_specs[0];
        assert_eq!(
            cs.runas.as_ref().map(|r| r.users.clone()),
            Some(vec!["root".to_string()])
        );
        assert_eq!(cs.tags, vec![Tag::NoPasswd]);
        assert_eq!(cs.cmnd, CmndItem::All);
    }

    #[test]
    fn glued_equals_then_tag_colon_stays_one_group() {
        // `host=NOPASSWD:` (no spaces around `=`, the common glued `ALL=(ALL)` form):
        // the `=` resets the preceding-token start so `NOPASSWD` is still recognised as
        // a tag, not a segment. visudo -c rc 0: `alice h1=NOPASSWD: ALL` -> one group
        // with the NOPASSWD tag. (Kills the `,`/`=`-arm `tok_start` offset mutant.)
        let s = only_spec("alice h1=NOPASSWD: ALL\n");
        assert_eq!(s.host_groups.len(), 1);
        assert_eq!(s.host_groups[0].hosts, vec!["h1".to_string()]);
        assert_eq!(s.host_groups[0].cmnd_specs[0].tags, vec![Tag::NoPasswd]);
        assert_eq!(s.host_groups[0].cmnd_specs[0].cmnd, CmndItem::All);
    }

    #[test]
    fn unterminated_quote_does_not_swallow_the_segment_colon() {
        // #416 fix (was a documented #346-class limitation): an UNTERMINATED double-quote
        // is a literal command byte, not a quote that swallows the later top-level `:`.
        // Real sudo agrees - `cvtsudoers -f json` ACCEPTS (visudo -c rc 0)
        //   `alice h1 = /bin/sh -c "oops : h2 = ALL`
        // and splits it into TWO host-groups {h1 -> `/bin/sh -c "oops`} and {h2 -> ALL}.
        // Merging them hid the second grant -- a sudo-W05 FALSE
        // NEGATIVE. This does NOT mean valid configs never carry a separator inside
        // a "balanced" quote pair, nor that the fix drops quote-based separator
        // suppression entirely. TWO quotes that each merely CLOSE a DIFFERENT command
        // or host-group (not an `Option_Spec` value's own enclosing pair) form no real
        // pair at all and must not mask a separator between them -- see
        // `two_quotes_each_closing_a_different_host_groups_command_do_not_mask_the_segment_colon`,
        // the blind spot a single never-closed quote (this test's input) cannot
        // exercise. Quote-based suppression still exists, narrowed to protect ONLY an
        // `Option_Spec` value's own enclosing quotes (`quoted_value_span`, called from
        // the `'='` arms of `split_top_level_segments`/`split_cmnd_specs`)
        // - an opener must BELONG to that option's own `=`, tolerating whitespace on
        // either side; a bare command or principal quote never has this protecting power.
        let s = only_spec("alice h1 = /bin/sh -c \"oops : h2 = ALL\n");
        assert_eq!(
            s.host_groups.len(),
            2,
            "an unterminated quote must not swallow the `:` host-group separator (#416)"
        );
        assert_eq!(s.host_groups[0].hosts, vec!["h1".to_string()]);
        assert_eq!(
            s.host_groups[0].cmnd_specs[0].cmnd,
            CmndItem::Cmnd("/bin/sh -c \"oops".to_string())
        );
        assert_eq!(s.host_groups[1].hosts, vec!["h2".to_string()]);
        assert_eq!(s.host_groups[1].cmnd_specs[0].cmnd, CmndItem::All);
    }

    // These two assert the splitter's two DEFENSIVE internal contracts directly (the
    // private fn, not the public `only_spec`/`kinds` path): the depth-clamp on a stray
    // `)` and the separator-arm `tok_start` reset. The public path folds both edge
    // inputs into `Malformed` either way, so it cannot distinguish the mutated code -
    // hence the direct calls. (Nightly mutants run 28428445948 survivors.)

    #[test]
    fn unbalanced_close_paren_clamps_depth_and_keeps_later_separator() {
        // A stray unbalanced `)` at depth 0 (malformed; visudo rejects) must not drive
        // depth negative -- otherwise a later top-level `:` at the now negative depth is
        // no longer recognised as a separator and the segments collapse into one.
        // (Kills the `depth > 0` -> `depth >= 0` mutant on `split_top_level_segments`'s
        // `')'` MATCH GUARD, which would let a depth-0 `)` enter the arm and take
        // `depth -= 1` to -1. The
        // existing `runas_group_then_segment_colon_splits` uses BALANCED parens so its
        // `)` sits at depth 1 and never exercises this.)
        assert_eq!(
            split_top_level_segments("a) = b : c = d", false),
            vec!["a) = b", "c = d"],
            "a stray `)` must not push depth below 0 and swallow the later `:` separator"
        );
    }

    #[test]
    fn tag_keyword_opening_a_segment_after_a_separator_is_recognised() {
        // After a genuine top-level `:` separator, `tok_start` must point JUST AFTER the
        // colon so a tag keyword opening the next segment has preceding-token "NOPASSWD"
        // (a tag), not ":NOPASSWD" (not a tag). An off-by-one in the separator arm's
        // `tok_start = i + 1` reset (-> `i * 1` or `i - 1`) misreads the next tag colon as
        // another separator and over-splits "NOPASSWD: b" into "NOPASSWD" + "b". (Kills
        // both `i + 1` -> `i * 1` and `i + 1` -> `i - 1` mutants on the `tok_start`
        // resets in `split_top_level_segments`'s `':'` arm - cited by construct rather
        // than by line number, which two earlier revisions of this comment got wrong and
        // which any edit above here silently invalidates.)
        assert_eq!(
            split_top_level_segments("a : NOPASSWD: b", true),
            vec!["a", "NOPASSWD: b"],
            "a tag keyword opening the segment after a `:` separator must not re-split"
        );
    }

    // These two mirror the colon-splitter's `quoted_paren_in_command_does_not_desync_segment_split`
    // and `unbalanced_close_paren_clamps_depth_and_keeps_later_separator` onto the COMMA splitter
    // `split_cmnd_specs`, whose paren / depth-clamp contracts had no direct test (#406 mutation
    // survivors). Direct private-fn calls: the public path folds both edge inputs into `Malformed`,
    // so it cannot distinguish the mutated code.

    #[test]
    fn quoted_paren_in_cmnd_list_does_not_desync_comma_split() {
        // A `(` in the MIDDLE of a command (here inside a quoted argument) is a literal byte, not
        // a runas open-paren, so it must not desync `depth` and swallow the later `,` separating
        // the next `Cmnd_Spec`. Grounded: `cvtsudoers -f json` (sudo 1.9.17p2, host + rocky9)
        // parses `/bin/echo "a(", /bin/ls` as TWO commands. Since the `(` is past the runas
        // position it never reaches `depth += 1` (the #416 positional-paren rule), so the `,`
        // stays at depth 0 and splits.
        assert_eq!(
            split_cmnd_specs("/bin/echo \"a(\", /bin/ls"),
            vec!["/bin/echo \"a(\"", "/bin/ls"],
            "a mid-command `(` inside quotes must not swallow the `,` Cmnd_Spec separator"
        );
    }

    #[test]
    fn unbalanced_close_paren_in_cmnd_list_clamps_depth_and_keeps_later_comma_separator() {
        // A stray unbalanced `)` at depth 0 (malformed; visudo rejects) must CLAMP depth at 0,
        // not drive it negative -- otherwise a later top-level `,` at the now-negative depth is
        // no longer a separator and the two `Cmnd_Spec`s collapse into one. Kills the
        // `depth > 0` -> `depth >= 0` guard mutant (which lets `depth -= 1` reach -1).
        assert_eq!(
            split_cmnd_specs("a), b"),
            vec!["a)", "b"],
            "a stray `)` must not push depth below 0 and swallow the later `,` separator"
        );
    }

    // ---- #416: a visudo-VALID unbalanced quote or a bare MID-COMMAND `(` must NOT merge
    //      two `Cmnd_Spec`s (comma splitter) or two host-groups (colon splitter). Merging
    //      hides a later `NOPASSWD:` grant -- a sudo-W05 FALSE NEGATIVE. Every case below
    //      is `visudo -c` rc 0 and `cvtsudoers -f json` (sudo 1.9.17p2) splits it into the
    //      asserted number of segments (the 2nd spec passwordless). The fix makes a `(` a
    //      runas opener ONLY at a Cmnd_Spec start and drops the quote-based separator
    //      suppression (a valid top-level separator is never inside a balanced quote:
    //      `/bin/echo "a, b"` and `/bin/echo "a:b"` are visudo-REJECTED).

    #[test]
    fn unterminated_quote_does_not_swallow_comma_separator() {
        // `cvtsudoers -f json` on `alice ALL=(ALL) /bin/echo "x, NOPASSWD: /bin/su`
        // (visudo -c rc 0) yields TWO commands: `/bin/echo "x` and `/bin/su`. A lone
        // unbalanced `"` is a literal command byte, NOT a quote that swallows the
        // top-level `,` (#416). The `"` stays verbatim in the first spec.
        assert_eq!(
            split_cmnd_specs("(ALL) /bin/echo \"x, NOPASSWD: /bin/su"),
            vec!["(ALL) /bin/echo \"x", "NOPASSWD: /bin/su"],
            "an unterminated quote must not swallow the `,` Cmnd_Spec separator (#416)"
        );
    }

    #[test]
    fn bare_mid_command_paren_does_not_swallow_comma_separator() {
        // `cvtsudoers -f json` on `alice ALL=(ALL) /bin/echo a(b, NOPASSWD: /bin/su`
        // (visudo -c rc 0) yields TWO commands: `/bin/echo a(b` and `/bin/su`. A `(` in
        // the MIDDLE of a command (not the leading runas position) is a literal byte and
        // must NOT bump paren depth, so the top-level `,` still splits (#416).
        assert_eq!(
            split_cmnd_specs("(ALL) /bin/echo a(b, NOPASSWD: /bin/su"),
            vec!["(ALL) /bin/echo a(b", "NOPASSWD: /bin/su"],
            "a mid-command `(` must not swallow the `,` Cmnd_Spec separator (#416)"
        );
    }

    #[test]
    fn runas_user_list_comma_is_not_a_spec_separator() {
        // Regression guard for the positional-paren fix (#416): a `(` at a Cmnd_Spec START
        // (the runas position) still opens a runas group, so the comma inside
        // `(root, operator)` is paren-nested and does NOT split. `cvtsudoers -f json`
        // (sudo 1.9.17p2): `(root, operator) /bin/su, /bin/ls` is TWO commands sharing the
        // runas user list root+operator. Also guards a runas group opening a spec AFTER a
        // top-level comma (the trailing `/bin/ls` has none, so only the leading group).
        assert_eq!(
            split_cmnd_specs("(root, operator) /bin/su, /bin/ls"),
            vec!["(root, operator) /bin/su", "/bin/ls"],
            "a comma inside a leading runas group must stay paren-nested (#416 regression)"
        );
    }

    #[test]
    fn quoted_close_paren_in_a_runas_principal_keeps_the_option_value_anchor() {
        // WITNESS for this splitter's `runas_quotes` guard. The lint-level face of
        // this arm is masked by #650 (`parse_cmnd_spec`'s `after_open.find(')')`
        // truncates the runas token before the split can matter), so no CLI input
        // observes it and its mutants survive the diff-scoped gate. Calling the
        // splitter directly bypasses that masking.
        //
        // `alice ALL = (root,"a)b") CWD="/x,y" /bin/ls, NOPASSWD: /bin/su` is
        // `visudo -c -f -` rc 0 with TWO `Cmnd_Spec`s (sudo 1.9.17p2, 2026-08-02).
        //
        // Without the guard the QUOTED `)` fires the `')'` arm, drops `depth` to 0
        // and drags `tok_start` into the middle of the principal; `preceding_token`
        // at the following `=` is then no longer exactly `CWD`, no `Option_Spec`
        // value span is recorded, and the `,` INSIDE `"/x,y"` splits - yielding
        // THREE specs instead of two and tearing the option value in half.
        assert_eq!(
            split_cmnd_specs("(root,\"a)b\") CWD=\"/x,y\" /bin/ls, NOPASSWD: /bin/su"),
            vec!["(root,\"a)b\") CWD=\"/x,y\" /bin/ls", "NOPASSWD: /bin/su"],
            "a quoted `)` in a runas principal must not desync the option anchor"
        );
    }

    #[test]
    fn a_depth_zero_quote_never_shields_a_later_runas_close_paren() {
        // The `depth > 0` half of the same arm's guard. `runas_quotes` must record
        // ONLY spans opened inside a runas group: a quote opened in ordinary command
        // text at depth 0 has no principal power, and sudo splits on a quoted comma
        // in the Cmnd_Spec_List anyway.
        //
        // `alice ALL = /bin/echo "x, (root) /bin/ls", NOPASSWD: /bin/su` is
        // `visudo -c -f -` rc 0 with THREE `Cmnd_Spec`s (sudo 1.9.17p2, 2026-08-02).
        //
        // Widen the guard to `depth >= 0` and the leading `"` records a span running
        // past the `(root)` group. The group's real `)` is then inside that span and
        // gets masked, so `depth` never returns to 0 and the FINAL `,` - the one
        // separating the `NOPASSWD` spec - stops splitting: two specs instead of
        // three, with the passwordless grant swallowed into its predecessor.
        assert_eq!(
            split_cmnd_specs("/bin/echo \"x, (root) /bin/ls\", NOPASSWD: /bin/su"),
            vec!["/bin/echo \"x", "(root) /bin/ls\"", "NOPASSWD: /bin/su"],
            "a depth-0 quote must not shield a later runas `)`"
        );
    }

    #[test]
    fn bare_mid_command_paren_does_not_swallow_the_segment_colon() {
        // Colon-splitter twin of `bare_mid_command_paren_does_not_swallow_comma_separator`.
        // `cvtsudoers -f json` on `alice h1 = /bin/echo a(b : h2 = ALL` (visudo -c rc 0)
        // yields TWO host-groups {h1 -> `/bin/echo a(b`} and {h2 -> ALL}. A mid-command
        // `(` must not bump `depth` and swallow the top-level `:` (#416).
        assert_eq!(
            split_top_level_segments("h1 = /bin/echo a(b : h2 = ALL", false),
            vec!["h1 = /bin/echo a(b", "h2 = ALL"],
            "a mid-command `(` must not swallow the `:` host-group separator (#416)"
        );
    }

    #[test]
    fn runas_group_colon_after_top_level_comma_is_not_a_segment_separator() {
        // Regression guard for the positional-paren fix (#416): a `(` opening a runas
        // group at a Cmnd_Spec start AFTER a top-level comma still bumps `depth`, so the
        // `:` inside `(root:wheel)` is the runas-group colon and does NOT split. Grounded:
        // `alice ALL = /bin/echo x, (root:wheel) /bin/su : localhost = /bin/ls` (visudo -c
        // rc 0) is TWO host-groups (cvtsudoers -f json, sudo 1.9.17p2).
        assert_eq!(
            split_top_level_segments(
                "ALL = /bin/echo x, (root:wheel) /bin/su : localhost = /bin/ls",
                false
            ),
            vec![
                "ALL = /bin/echo x, (root:wheel) /bin/su",
                "localhost = /bin/ls"
            ],
            "a runas-group colon after a top-level comma must not split (#416 regression)"
        );
    }

    // ---- #416 (colon splitter): a `=` INSIDE a command argument must NOT
    //      re-arm the runas position. Only the FIRST top-level `=` of a host-group is the
    //      structural `Host_List = Cmnd_Spec_List` separator; a later `=(` in a command
    //      arg was re-arming `at_spec_start`, so the `(` bumped `depth` and swallowed the
    //      next top-level `:` -> two host-groups merged -> the 2nd group's `NOPASSWD:`
    //      grant was hidden (a sudo-W05 FALSE NEGATIVE). Every case is `visudo -c` rc 0
    //      and `cvtsudoers -f json` (sudo 1.9.17p2) yields TWO host-groups, the 2nd
    //      (`/bin/su`) passwordless.

    #[test]
    fn mid_command_eq_paren_does_not_swallow_the_segment_colon() {
        // `alice ALL = /bin/echo X=(y : ALL = NOPASSWD: /bin/su` (visudo -c rc 0):
        // cvtsudoers -f json = TWO host-groups {ALL -> `/bin/echo X=(y`} and {ALL ->
        // NOPASSWD /bin/su}. The `=` in the command arg `X=(y` must NOT re-arm the runas
        // position, so the `(` stays a literal byte and the top-level `:` still splits.
        assert_eq!(
            split_top_level_segments("h1 = /bin/echo X=(y : h2 = NOPASSWD: /bin/su", true),
            vec!["h1 = /bin/echo X=(y", "h2 = NOPASSWD: /bin/su"],
            "a mid-command `=(` must not desync depth and swallow the `:` separator (#416)"
        );
    }

    #[test]
    fn quoted_mid_command_eq_paren_does_not_swallow_the_segment_colon() {
        // Quoted twin: `alice ALL = /bin/echo "a=(b" : ALL = NOPASSWD: /bin/su` (visudo -c
        // rc 0): cvtsudoers -f json = TWO host-groups, the 2nd passwordless. With no quote
        // tracking, the `=` inside the quoted arg still must not re-arm the runas position
        // (the reason a quoted `(` here is harmless is that the preceding `=` no longer
        // re-arms, NOT that quotes are tracked).
        assert_eq!(
            split_top_level_segments("h1 = /bin/echo \"a=(b\" : h2 = NOPASSWD: /bin/su", true),
            vec!["h1 = /bin/echo \"a=(b\"", "h2 = NOPASSWD: /bin/su"],
            "a quoted mid-command `=(` must not swallow the `:` separator (#416)"
        );
    }

    #[test]
    fn real_runas_group_then_mid_command_eq_paren_still_splits() {
        // Regression guard: a REAL runas group at the Cmnd_Spec start followed by a
        // mid-command `=(` in the same command. `alice ALL = (root) /bin/echo X=(y : ALL =
        // NOPASSWD: /bin/su` (visudo -c rc 0) is TWO host-groups (cvtsudoers -f json). The
        // structural `=` arms the runas position, `(root)` is a real runas group (depth
        // 1->0), and the later `=(` inside the command arg must not re-arm it.
        assert_eq!(
            split_top_level_segments("h1 = (root) /bin/echo X=(y : h2 = ALL", false),
            vec!["h1 = (root) /bin/echo X=(y", "h2 = ALL"],
            "a mid-command `=(` after a real runas group must not swallow the `:` (#416)"
        );
    }

    #[test]
    fn host_region_comma_does_not_arm_the_runas_position() {
        // Design-intent of the `,` arm's `depth == 0 && in_cmnd_list` guard (#416): a
        // top-level `,` arms the runas position ONLY inside the Cmnd_Spec_List (past the
        // structural `=`). A `,` in the Host_List region (before that `=`) must NOT arm it,
        // so a following `(` there is a literal byte, stays at depth 0, and the later
        // top-level `:` still splits into two host-groups. A Host_List never legitimately
        // contains a `(` (host names have no parens), so this is a synthetic direct-splitter
        // edge input in the style of `unbalanced_close_paren_clamps_depth_and_keeps_later_separator`.
        // Kills the `&&` -> `||` mutant on the guard: under `||` the depth-0 Host_List comma
        // arms the runas position, the `(` bumps `depth`, and the `:` is suppressed -> the
        // two host-groups collapse into one (hiding the second's `NOPASSWD:` grant).
        assert_eq!(
            split_top_level_segments("h1, (x : h2 = NOPASSWD: /bin/su", true),
            vec!["h1, (x", "h2 = NOPASSWD: /bin/su"],
            "a `(` in the Host_List region (after a top-level `,`, before the structural \
             `=`) is not a runas opener, so it must not bump depth and swallow the `:` (#416)"
        );
    }

    // ---- #538 gap C (colon splitter): an `Option_Spec`'s own `=` must not desync the
    //      preceding-token marker. The `Option_Spec` case itself is pinned by the frozen
    //      barrier suite (`tests/iss538_parser_gaps.rs`); these two pin the boundaries of
    //      the fix at the splitter level, where the barrier suite does not reach.

    #[test]
    fn command_argument_tag_keyword_before_a_colon_still_splits() {
        // The over-reach guard on the gap C fix. The option-`=` skip is POSITION-ANCHORED
        // (`in_cmnd_list` + an exact single-token keyword match), so once the COMMAND word
        // has begun, a tag keyword written after it is a command ARGUMENT and the colon is
        // still a genuine host-group separator.
        //
        // Ground truth, host sudo 1.9.17p2 (2026-07-30): `alice h1 = /bin/echo NOPASSWD :
        // h2 = ALL` is `visudo -c -f -` rc 0, and `cvtsudoers -f json` reports TWO
        // `User_Specs` entries - `h1` with the single command `"/bin/echo NOPASSWD"`, and
        // `h2` with `ALL`. A naive gap C fix that just took the LAST word of the span
        // would read `NOPASSWD` as a tag here, merge the two host-groups, and hand the
        // whole tail to the command constructor as garbage.
        assert_eq!(
            split_top_level_segments("h1 = /bin/echo NOPASSWD : h2 = ALL", true),
            vec!["h1 = /bin/echo NOPASSWD", "h2 = ALL"],
            "a tag keyword used as a command ARGUMENT does not make the following colon a \
             tag colon (#538 gap C over-reach guard)"
        );
    }

    #[test]
    fn colon_inside_an_option_value_does_not_panic() {
        // Panic guard on the option-value skip. With no whitespace after the option's
        // `=`, the value runs to the end of the input and `tok_start` becomes `s.len()`,
        // which is PAST a colon sitting inside that value - an inverted slice range if it
        // were not clamped (see `preceding_token`).
        //
        // Real sudo REJECTS an UNQUOTED colon in an option value: `alice h1 =
        // TIMEOUT=30:x` is `visudo -c -f -` rc 1 (`stdin:1:22: syntax error`) on host
        // sudo 1.9.17p2 (2026-07-30), as is `CWD=/a:/b`. That premise is scoped to the
        // UNQUOTED spelling and does NOT extend to a quoted value - `alice h1 =
        // CWD="/a:b" /bin/ls` is rc 0 (2026-07-31 probe; see
        // `gap_c_quoted_colon_in_an_option_value_is_not_a_separator` in the barrier
        // suite, which `inside_a_clean_quoted_region` exists to satisfy) - so this
        // deliberately UNQUOTED input is the one case where no particular split is the
        // "right" one, and this asserts only the clamp's reading - the colon sits
        // INSIDE a token, so there is no complete preceding token, so it is not a tag
        // colon - and, above all, that the splitter does not panic on it.
        assert_eq!(
            split_top_level_segments("h1 = TIMEOUT=30:x", true),
            vec!["h1 = TIMEOUT=30", "x"],
            "a colon inside an option value must not panic the splitter (#538 gap C)"
        );
        assert_eq!(
            preceding_token("h1 = TIMEOUT=30:x", "h1 = TIMEOUT=30:x".len(), 15),
            "",
            "an overshot `tok_start` clamps to an empty token, never an inverted range"
        );
    }

    #[test]
    fn a_clean_quoted_region_excludes_its_own_two_quote_bytes() {
        // `inside_a_clean_quoted_region` answers "does byte `i` sit STRICTLY
        // between a matched pair of quotes", and the two quote bytes are NOT
        // inside: a separator is masked only when it lies between the quotes,
        // never when it IS one of them.
        //
        // Direct call, for the reason the `split_top_level_segments` tests
        // above give for theirs. Every current caller hands this predicate the
        // offset of a `,` / `)` / `=` / `:` / whitespace run, none of which can
        // coincide with a quote byte, so the public path cannot reach either
        // boundary -- which is exactly why the two comparison mutants
        // (`open < i` -> `open <= i` and `i < close` -> `i <= close`) survived
        // the nightly gate. The strictness is still the predicate's contract,
        // and pinning it here means a future caller that CAN land on a quote
        // byte inherits the boundary rather than rediscovering it.
        let spans = [(3usize, 7usize)];
        assert!(
            !inside_a_clean_quoted_region(&spans, 3),
            "the opening quote byte is not inside the region it opens"
        );
        assert!(
            !inside_a_clean_quoted_region(&spans, 7),
            "the closing quote byte is not inside the region it closes"
        );
        // Interior bytes ARE inside, so the assertions above are not vacuously
        // true of every input.
        assert!(inside_a_clean_quoted_region(&spans, 4));
        assert!(inside_a_clean_quoted_region(&spans, 6));
        // And a byte outside the pair on either side is not inside it.
        assert!(!inside_a_clean_quoted_region(&spans, 2));
        assert!(!inside_a_clean_quoted_region(&spans, 8));
    }
}
