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

use crate::ast::{
    AliasDef, AliasKind, AliasSpec, CmndItem, CmndSpec, DefaultSetting, DefaultsEntry,
    DefaultsScope, HostGroup, IncludeDirective, IncludeKind, LineKind, LogicalLine, RunasSpec,
    SudoersFile, Tag, UserSpec,
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
///   1. Strip the inline `#` comment to EOL (see [`strip_inline_comment`]). The
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
        let body = strip_inline_comment(raw);

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
/// been stripped by [`strip_inline_comment`] before this runs, so a `\` that was
/// inside a comment is already gone and cannot continue.
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

/// Strip an inline `#` comment (to end of the physical line) from `body`, honoring
/// the sudoers exceptions. Returns the text with any comment removed (trailing
/// whitespace before the comment is preserved; the caller trims as needed).
///
/// Grounding (visudo 1.9.17p2, `visudo -c` + `visudo -x -`): a `#` introduces a
/// comment-to-EOL WHEREVER it appears, EXCEPT:
///   1. `#include` / `#includedir` at the directive position (a line whose first
///      non-whitespace run is `#include[dir]`): the WHOLE line is a directive, not
///      a comment, so nothing is stripped.
///   2. `#<digits>` UID/GID token: a `#` immediately followed by an ASCII digit and
///      preceded by start-of-line / whitespace / `,` / `%` is a user-ID or group-ID
///      token, not a comment (`#1000`, `root,#1000`, `%#1000`). Grounded:
///      `visudo -x -` reports these as `userid` / `usergid` in user-list, runas-list
///      AND alias-member positions (which appear both BEFORE and AFTER the `=`, e.g.
///      `User_Alias FOO = #1000` -> userid 1000), so this exception is NOT gated on
///      the `=`.
///   3. A `#` INSIDE a double-quoted region is literal: a `"` toggles in/out of a
///      quoted region and a `#` seen while inside it is NOT a comment
///      (`Defaults passprompt="a # b"` -> value `a # b`). Single quotes do NOT
///      protect (verified: `'` is not a sudoers quote char).
///
/// Phase-0 contract note: this is a CLASSIFIER, not a command-token validator.
/// visudo treats `#<digits>` as a token EVERYWHERE in the lexer but then REJECTS it
/// as a syntax error in command / `Defaults`-value position (`alice ALL = /bin/ls #2`
/// and `Defaults env_reset #2 reasons` are `visudo -c` errors). This parser does
/// NOT do that command-token validation - just as it keeps a relative path like
/// `bin/ls` (also a visudo error) as a clean user-spec rather than rejecting it. So
/// a `#<digits>` glued in command/value position is kept on the (already
/// visudo-invalid) line rather than special-cased; faithful per-position token
/// validation is a documented Phase-1 extension. (An earlier `=`-gated attempt to
/// strip command/value `#<digits>` as comments WRONGLY stripped legitimate
/// alias-member UIDs after the `=`, so the un-gated token rule is the correct
/// Phase-0 behavior.)
///
/// KNOWN DIVERGENCE (documented, intentionally not handled here): sudo's COMMAND
/// lexer does not protect a `#` with double quotes the way its Defaults-value lexer
/// does, so a pathological `/bin/echo "a # b"` is truncated by real sudo at the `#`
/// but the quote-balance rule here keeps `a # b`. This OVER-protects (it never
/// corrupts a normal rule, and Phase-0 keeps command tokens verbatim), which is the
/// safe direction; a position-aware lexer is a documented Phase-1 extension point.
fn strip_inline_comment(body: &str) -> &str {
    // Exception 1: a leading `#include` / `#includedir` directive is never a
    // comment - leave the whole line intact for the include classifier.
    let lead = body.trim_start();
    if let Some(after) = lead.strip_prefix("#include") {
        // `#include` / `#includedir` followed by whitespace (the path) or `dir`.
        if after.starts_with("dir") || after.starts_with(char::is_whitespace) {
            return body;
        }
    }

    let bytes = body.as_bytes();
    let mut in_quotes = false;
    let mut prev: Option<u8> = None;
    for (i, &c) in bytes.iter().enumerate() {
        match c {
            b'"' => in_quotes = !in_quotes,
            b'#' if !in_quotes => {
                // Exception 2: a `#<digit>` preceded by start / whitespace / `,` /
                // `%` is a UID/GID token, not a comment.
                let next_is_digit = bytes.get(i + 1).is_some_and(u8::is_ascii_digit);
                let prev_allows_uid = match prev {
                    None => true,
                    Some(p) => p == b',' || p == b'%' || (p as char).is_whitespace(),
                };
                if next_is_digit && prev_allows_uid {
                    // A UID/GID token: NOT a comment. The digits that follow are
                    // ordinary bytes; the scan walks over them harmlessly (they
                    // never re-trigger this arm), so no separate digit-skip loop is
                    // needed (`for` over the bytes advances by exactly one each step).
                    prev = Some(c);
                    continue;
                }
                // A real comment: everything from here to EOL is dropped.
                return &body[..i];
            }
            _ => {}
        }
        prev = Some(c);
    }
    body
}

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
    } else if let Some(r) = trimmed.strip_prefix('#') {
        (true, r)
    } else {
        return None;
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
            // The scope binding runs from after the sigil to the first whitespace;
            // the rest is the settings list. Each sigil is a single-byte ASCII char.
            let after = &rest[sigil.len_utf8()..];
            let (binding, settings) = split_first_word(after);
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

/// Split a `Defaults` settings list (comma-separated) into [`DefaultSetting`]s.
/// Returns an empty vec when there is nothing parseable (the caller treats that as
/// Malformed).
fn parse_default_settings(s: &str) -> Vec<DefaultSetting> {
    s.split(',')
        .map(str::trim)
        .filter(|tok| !tok.is_empty())
        .map(parse_one_default_setting)
        .collect()
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
        // Strip surrounding double quotes from the value if present (common for
        // paths: `secure_path="/usr/bin"`).
        let value = value
            .strip_prefix('"')
            .and_then(|v| v.strip_suffix('"'))
            .unwrap_or(value);
        DefaultSetting {
            negated,
            name: name.trim().to_string(),
            value: Some(value.to_string()),
        }
    } else {
        DefaultSetting {
            negated,
            name: body.trim().to_string(),
            value: None,
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
        let Some(eq) = seg.find('=') else {
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
/// whitespace-run), and every later segment is `Host_List = Cmnd_Spec_List` sharing
/// that same user list. Each segment becomes one [`HostGroup`], so tag inheritance is
/// per-group and does not cross the `:` (the #345 fix; grounded against
/// `cvtsudoers -f json`, sudo 1.9.17p2).
fn classify_user_spec(trimmed: &str) -> LineKind {
    // A user-spec MUST contain an `=` (the User/Host = Cmnd boundary). Without one
    // it is not a valid spec - report the dispatcher's catch-all message.
    if !trimmed.contains('=') {
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
        let Some(eq) = seg.find('=') else {
            return LineKind::Malformed(
                "user specification segment is missing its `= command` part".to_string(),
            );
        };
        let lhs = seg[..eq].trim();
        let rhs = &seg[eq + 1..];

        let hosts = if idx == 0 {
            // First segment: `User_List Host_List`. The user list is the leading
            // whitespace-run; the rest is the host list. sudoers requires both.
            let (user_part, host_part) = split_first_word(lhs);
            let host_part = host_part.trim();
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
///   * the runas-group colon inside `(runas_users:runas_groups)` - tracked by paren
///     `depth`, so only a depth-0 colon can separate;
///   * a literal colon inside a command/argument - sudo REQUIRES it to be
///     backslash-escaped (`\:`; an unescaped `:` in a command is a syntax error), so
///     the char after a backslash is skipped;
///   * when `skip_tag_colons` (user-specs only), the `NOPASSWD:` / `PASSWD:` tag
///     colon - recognised because the token immediately before it (back to the last
///     `,` / `=` / `(` / `)` / consumed colon, with whitespace irrelevant) is a
///     [`Tag`] keyword. Alias defs carry no tags, so they pass `false`.
fn split_top_level_segments(s: &str, skip_tag_colons: bool) -> Vec<&str> {
    let mut segments = Vec::new();
    let mut seg_start = 0usize;
    // Start of the token immediately preceding the cursor, reset at each token-list
    // boundary (`,` / `=` / `(` / `)` / a consumed colon - NOT whitespace, so a tag
    // keyword spaced away from its colon is still recognised). Used only to spot a
    // tag keyword sitting just before a colon.
    let mut tok_start = 0usize;
    let mut depth: i32 = 0;
    let mut escaped = false;
    // Inside a `"..."` quoted command token nothing is structural: sudo groups the
    // token, so a `(` / `:` / `,` there is a literal command byte, not a runas paren /
    // segment colon / list comma (cvtsudoers keeps `/bin/sh -c "a(b"` as ONE command,
    // splitting only on the LATER unquoted `:`). Mirrors stage-1 `strip_inline_comment`'s
    // quote tracking; without it an unbalanced `(` in a quoted arg desyncs `depth` and a
    // real segment `:` is swallowed (#345 adversarial-review fix).
    let mut in_quotes = false;

    for (i, c) in s.char_indices() {
        if escaped {
            // The previous char was a backslash; this char is a literal part of the
            // current token (`\:`, `\,`, `\"`, ...). Never a separator or a boundary.
            escaped = false;
            continue;
        }
        if c == '\\' {
            escaped = true;
            continue;
        }
        if in_quotes {
            // Literal token content; only the closing quote is structural.
            if c == '"' {
                in_quotes = false;
            }
            continue;
        }
        match c {
            '"' => in_quotes = true,
            // No `tok_start` reset here: while `depth > 0` every colon is skipped, and
            // `tok_start` is overwritten at the matching `)` before any depth-0 colon
            // reads it, so resetting it on `(` would be dead.
            '(' => depth += 1,
            ')' => {
                // `if depth > 0` only guards a malformed UNBALANCED `)` (which visudo
                // rejects); for valid input depth is always >= 1 here.
                if depth > 0 {
                    depth -= 1;
                }
                tok_start = i + c.len_utf8();
            }
            ',' | '=' => tok_start = i + c.len_utf8(),
            ':' if depth == 0 => {
                let preceding = s[tok_start..i].trim();
                if skip_tag_colons && parse_tag(preceding).is_some() {
                    // A tag colon (`NOPASSWD:`): not a segment separator. The next
                    // token starts just after it.
                    tok_start = i + 1;
                } else {
                    // A genuine top-level segment separator. `tok_start = i + 1` resets
                    // the preceding-token start for the next segment; valid input always
                    // overwrites it at that segment's `=` before the next colon is seen.
                    segments.push(s[seg_start..i].trim());
                    seg_start = i + 1;
                    tok_start = i + 1;
                }
            }
            _ => {}
        }
    }
    segments.push(s[seg_start..].trim());
    segments
}

/// Parse a comma-separated `Cmnd_Spec_List` into [`CmndSpec`]s.
///
/// Each `Cmnd_Spec` is `Runas_Spec? Tag_Spec* Cmnd`. The tags written EXPLICITLY
/// on each spec are captured (NOT inheritance-resolved - the #330 pass walks the
/// list and applies inheritance). A leading `(runas)` group is captured.
fn parse_cmnd_spec_list(s: &str) -> Vec<CmndSpec> {
    s.split(',')
        .map(str::trim)
        .filter(|spec| !spec.is_empty())
        .map(parse_cmnd_spec)
        .collect()
}

/// Parse one `Cmnd_Spec`: an optional `(runas)` group, zero or more `TAG:` tags,
/// then the command token (the rest of the spec).
fn parse_cmnd_spec(spec: &str) -> CmndSpec {
    let mut rest = spec.trim();

    // Optional leading run-as spec: `(...)`.
    let mut runas = None;
    if let Some(after_open) = rest.strip_prefix('(')
        && let Some(close) = after_open.find(')')
    {
        runas = Some(parse_runas(&after_open[..close]));
        rest = after_open[close + 1..].trim_start();
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

    CmndSpec { runas, tags, cmnd }
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

/// Split off the first whitespace-delimited word from `s`, returning
/// `(first_word, remainder)`. The remainder keeps its leading whitespace stripped
/// only by the caller as needed. Returns `("", "")` for an all-whitespace input.
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
                    }
                );
                assert_eq!(
                    d.settings[1],
                    DefaultSetting {
                        negated: false,
                        name: "secure_path".to_string(),
                        value: Some("/usr/bin".to_string()),
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
        // comment strip must NOT treat that `#1000` as a comment. (No space after
        // the comma keeps the whole user list one whitespace-word, sidestepping the
        // documented Phase-0 user/host whitespace-split simplification; the point
        // here is solely that the post-comma `#1000` survives the comment strip.)
        let s = only_spec("root,#1000 ALL=(ALL) ALL\n");
        assert_eq!(s.users, vec!["root".to_string(), "#1000".to_string()]);
        assert_eq!(s.host_groups[0].cmnd_specs[0].cmnd, CmndItem::All);
    }

    // The next four tests pin `strip_inline_comment`'s `#<digits>` UID-token
    // handling at the unit level so the operator-meaningful predicate / loop
    // branches are each killed by a distinct grounded case (mutation adequacy).

    #[test]
    fn strip_keeps_percent_hash_gid_token_but_strips_a_letter_prefixed_hash() {
        // The `prev_allows_uid` predicate allows a UID/GID token only when the `#`
        // is preceded by start / whitespace / `,` / `%`.
        //
        // `%`-prefixed: visudo `%#1000 ALL=(ALL) ALL` -> usergid 1000, so the
        // `#1000` after `%` is a GID token, NOT a comment. Kills the `|| p == b'%'`
        // arm (a `&&`/dropped `%` arm would strip it as a comment).
        assert_eq!(
            strip_inline_comment("%#1000 ALL=(ALL) ALL"),
            "%#1000 ALL=(ALL) ALL",
            "a `#<digits>` after `%` is a GID token, not a comment"
        );
        // Letter-prefixed: visudo treats `foo#1000` as `foo` + comment (the `#`
        // preceded by a letter is a comment). Kills the `==`->`!=` inversions: if
        // `,`/`%` were DISallowed and other chars ALLOWED, this would wrongly keep
        // the `#1000`.
        assert_eq!(
            strip_inline_comment("Defaults passprompt=foo#1000"),
            "Defaults passprompt=foo",
            "a `#<digits>` glued to a letter is a comment, not a token"
        );
    }

    #[test]
    fn strip_skips_a_multi_digit_uid_then_strips_a_later_real_comment() {
        // visudo: `root,#1000 ALL=(ALL) ALL # real comment` parses OK with the
        // `# real comment` stripped. The digit-skip loop must advance over ALL of
        // `1000` and then keep scanning to find and strip the LATER real `#`.
        // Kills the inner `while i < len` bound mutations and the `i += 1`
        // increment mutations (a wrong bound/increment either leaks the comment or
        // never reaches the later `#`).
        assert_eq!(
            strip_inline_comment("root,#1000 ALL=(ALL) ALL # real comment"),
            "root,#1000 ALL=(ALL) ALL ",
            "skip the multi-digit UID, then strip the later real comment to EOL"
        );
    }

    #[test]
    fn strip_advances_past_uid_token_when_it_ends_the_line() {
        // A `#<digits>` UID token at end-of-line: the digit-skip loop must terminate
        // at the string end (not run off it) and return the whole line. Single and
        // multi digit both, to pin the loop boundary independent of digit count.
        assert_eq!(strip_inline_comment("root,#7"), "root,#7");
        assert_eq!(strip_inline_comment("root,#1000"), "root,#1000");
    }

    #[test]
    fn strip_handles_a_uid_token_then_a_normal_token_then_a_comment() {
        // A clean later `#` comment (preceded by whitespace, after the `=`) is still
        // stripped after a subject-position UID token: proves the scan resumes
        // correctly and the `=` flips out of subject position.
        assert_eq!(
            strip_inline_comment("u,#5 h = /bin/ls #c"),
            "u,#5 h = /bin/ls ",
            "scan resumes after the UID token and strips the trailing comment"
        );
    }

    #[test]
    fn alias_member_uid_after_equals_is_preserved_not_stripped() {
        // Grounded (visudo -x -): `User_Alias FOO = #1000` -> the `#1000` member
        // AFTER the `=` is a `userid` token, NOT a comment. The `#<digits>` UID
        // exception therefore must NOT be gated on the `=` (a UID/GID token is legal
        // in alias-member and runas-list positions, which sit after the `=`). This
        // pins that `strip_inline_comment` keeps a post-`=` `#<digits>` member.
        assert_eq!(
            strip_inline_comment("User_Alias FOO = #1000"),
            "User_Alias FOO = #1000",
            "a `#<digits>` alias member after the `=` is a UID token, not a comment"
        );
        let k = kinds("User_Alias FOO = #1000\n");
        match &k[0] {
            LineKind::Alias(a) => assert_eq!(a.specs[0].members, vec!["#1000".to_string()]),
            other => panic!("expected an alias def, got {other:?}"),
        }
    }

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
        // #345 adversarial-review fix: an unbalanced `(` INSIDE a double-quoted command
        // argument is a literal command byte, not a runas open-paren, so it must not
        // desync `depth` and swallow the later real segment `:`. visudo -c rc 0 +
        // cvtsudoers -f json (sudo 1.9.17p2): `alice h1 = /bin/sh -c "a(b" : h2 = /bin/id`
        // parses as TWO host-groups {h1 -> /bin/sh -c "a(b"} and {h2 -> /bin/id}.
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
        // {h2, /bin/id}. (Kills the depth `+=`/`-=`, `>` and `)`-arm mutants.)
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
}
