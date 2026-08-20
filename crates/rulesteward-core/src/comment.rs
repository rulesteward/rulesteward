//! Shared inline-comment stripping, parameterized per backend (#562).
//!
//! One parameterized stripper replacing the three line-level implementations
//! (fapolicyd `parser/inline.rs`, auditd `parser.rs`, sudoers `parser.rs`),
//! with each backend's quote rules expressed as explicit parameters. sshd's
//! token-level `algo_list_value` stripping stays separate by decision
//! (2026-07-23). Consumed via full path (`rulesteward_core::comment::...`);
//! `lib.rs` re-exports are consolidated at integration, not per-lane.

/// Which quote character (if any) opens a protected span where an embedded
/// `#` is never read as a comment marker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuoteChar {
    /// No quote protection at all (fapolicyd: `parser/inline.rs`).
    Unquoted,
    /// A single quote (`'`) protects (auditd: `parser.rs::strip_comment`,
    /// protects shell-style `-F 'auid>=1000'` arguments).
    Single,
    /// A double quote (`"`) protects (sudoers: `parser.rs::strip_inline_comment`,
    /// protects `Defaults passprompt="a # b"` values).
    Double,
}

/// Whether this backend's line grammar has a backslash escape, and therefore
/// whether a `\`-escaped byte is a literal token byte rather than a comment
/// marker or a quote toggle (#649).
///
/// Modelled as an enum rather than a `bool` for the same reason [`QuoteChar`]
/// is: the axis names a grammar property, and a two-variant enum says which
/// property at every call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EscapeRule {
    /// No backslash escape: a `\` is an ordinary byte. fapolicyd and auditd,
    /// whose tables each pin the escape-blind reading explicitly (the
    /// `allow \#x` row in `fapolicyd_table` and the `auid>=1000 \#x` row in
    /// `auditd_table`).
    ///
    /// Both are EQUIVALENCE pins on the pre-#562 implementations, NOT
    /// derivations of either subsystem's real grammar. Nothing in this tree
    /// derives whether `fapolicyd` rule files or `auditctl` rule files have a
    /// backslash escape at all; the auditd row says why deriving it needs the
    /// `rs-oracle` containers. If either grammar turns out to have one, that is
    /// a latent instance of the very defect #649 fixed for sudoers, not
    /// something these rows have ruled out.
    None,
    /// A `\` escapes, under BOTH of the rules documented at
    /// `rulesteward-sudoers/src/parser.rs:1114-1135`. They apply in different
    /// places and collapsing them regresses one:
    ///
    /// - OUTSIDE a quoted span, the SEPARATOR-finding rule: a `\` consumes
    ///   exactly the next byte, so parity matters (`\\"` opens a span, while
    ///   `\#` does not start a comment).
    /// - INSIDE a quoted span, the QUOTE-finding rule: a `\` escapes only the
    ///   quote byte immediately after it, regardless of its own parity, so
    ///   `"a\"b"` is a single span and a doubled backslash before a quote
    ///   still escapes it.
    Backslash,
}

/// Per-backend configuration for [`comment_index`] / [`strip`]. Every
/// behavioral nuance of the three old line-level strippers is expressed as
/// one of these fields; the three associated consts below reproduce each
/// backend's exact current behavior (see the per-field doc comments for the
/// ground-truth citation).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StripConfig {
    /// Which quote character (if any) protects an embedded `#`.
    pub quote: QuoteChar,
    /// fapolicyd only: a `#` counts as an inline comment marker ONLY after a
    /// preceding non-whitespace token has been seen earlier on the same
    /// line. A leading (column-0 or whitespace-only-prefixed) `#` is never
    /// inline (`parser/inline.rs:27-37`, `seen_token`). auditd and sudoers do
    /// not gate on this: an unquoted `#` at position 0 is a real comment for
    /// both of them.
    pub require_preceding_token: bool,
    /// sudoers only: a leading `#include` / `#includedir` directive bypasses
    /// stripping entirely - the whole line is returned unchanged regardless
    /// of any later `#` (`parser.rs:238-246`).
    pub include_bypass: bool,
    /// sudoers only: a glued `#<digits>` UID/GID token is kept (not read as
    /// a comment start) when it sits in a subject/runas position - governed
    /// by the preceding byte and, inside a runas `(...)` group, by
    /// `paren_opens_runas` (`parser.rs:261-315,324-335`, the `#407`/`#424`
    /// grounded exceptions).
    pub uid_gid_exception: bool,
    /// Whether a backslash escapes in this backend's grammar (#649).
    /// [`EscapeRule::Backslash`] for sudoers; [`EscapeRule::None`] for
    /// fapolicyd and auditd.
    pub escape: EscapeRule,
}

impl StripConfig {
    /// fapolicyd `parser/inline.rs::inline_comment_index` /
    /// `strip_inline_comment`: no quote awareness, no `#include` concept, no
    /// UID/GID exception; a `#` counts as inline only after a preceding
    /// non-whitespace token.
    pub const FAPOLICYD: Self = Self {
        quote: QuoteChar::Unquoted,
        require_preceding_token: true,
        include_bypass: false,
        uid_gid_exception: false,
        escape: EscapeRule::None,
    };

    /// auditd `parser.rs::strip_comment`: single-quote aware, no
    /// `#include` concept, no UID/GID exception; ANY unquoted `#` (including
    /// column 0 and glued) starts a comment.
    pub const AUDITD: Self = Self {
        quote: QuoteChar::Single,
        require_preceding_token: false,
        include_bypass: false,
        uid_gid_exception: false,
        escape: EscapeRule::None,
    };

    /// sudoers `parser.rs::strip_inline_comment`: double-quote aware, plus
    /// the `#include`/`#includedir` bypass and the `#<digits>` UID/GID
    /// exception (with runas-paren state tracking).
    pub const SUDOERS: Self = Self {
        quote: QuoteChar::Double,
        require_preceding_token: false,
        include_bypass: true,
        uid_gid_exception: true,
        escape: EscapeRule::Backslash,
    };
}

/// Byte index of the comment-starting `#` in `line` under `config`, or
/// `None` if `line` has no inline comment to strip (either no unquoted `#`
/// exists, or every candidate `#` is excepted by `config`).
///
/// This is the primitive both [`strip`] and each backend's lint-time
/// re-scan (e.g. fapolicyd's fapd-W03) are built on - fapolicyd's old
/// `inline_comment_index` is consumed directly by `lints/source_scan.rs`,
/// not just by the parser, so the index (not just the stripped slice) is
/// part of the shared surface.
///
/// One parameterized left-to-right byte scan, unifying the three old
/// line-level implementations (#562):
/// - `config.include_bypass`: a leading `#include`/`#includedir` directive
///   bypasses the whole scan (sudoers only; old `parser.rs:238-246`).
/// - `config.quote`: which byte (if any) toggles a protected span where an
///   embedded `#` is never a comment marker (auditd `'`, sudoers `"`).
/// - `config.require_preceding_token`: a `#` counts as inline only after a
///   preceding non-whitespace byte has been seen (fapolicyd only; old
///   `inline.rs:27-37`).
/// - `config.uid_gid_exception`: a `#<digits>` UID/GID token is kept rather
///   than read as a comment start, per the runas-paren state machine and
///   the `prev_allows_uid` byte-set (sudoers only; old `parser.rs:261-315`
///   + `paren_opens_runas`).
#[must_use]
pub fn comment_index(line: &str, config: StripConfig) -> Option<usize> {
    if config.include_bypass {
        let lead = line.trim_start();
        if let Some(after) = lead.strip_prefix("#include")
            && (after.starts_with("dir") || after.starts_with(char::is_whitespace))
        {
            return None;
        }
    }

    let bytes = line.as_bytes();
    let mut in_quote = false;
    let mut in_runas_paren = false;
    let mut seen_token = false;
    let mut prev: Option<u8> = None;
    // Separator-rule state: set by an unescaped `\` OUTSIDE a quoted span,
    // consumed by the byte after it. Never set inside a span, where the
    // quote-finding rule applies instead and reads `prev` directly.
    let mut escape_pending = false;

    for (i, &b) in bytes.iter().enumerate() {
        let matches_quote = match config.quote {
            QuoteChar::Unquoted => false,
            QuoteChar::Single => b == b'\'',
            QuoteChar::Double => b == b'"',
        };

        // Is this byte a literal one, escaped by a preceding backslash? See
        // `EscapeRule::Backslash` for why the two branches differ; they are
        // the two escape rules of
        // `rulesteward-sudoers/src/parser.rs:1114-1135`, each in the context
        // it was grounded for.
        let literal = if config.escape == EscapeRule::None {
            false
        } else if in_quote {
            matches_quote && prev == Some(b'\\')
        } else if escape_pending {
            escape_pending = false;
            true
        } else if b == b'\\' {
            escape_pending = true;
            true
        } else {
            false
        };

        let is_quote_byte = matches_quote && !literal;

        if is_quote_byte {
            in_quote = !in_quote;
        } else if config.uid_gid_exception && !in_quote && !literal {
            if b == b'(' {
                in_runas_paren |= paren_opens_runas(bytes, i);
            } else if b == b')' {
                in_runas_paren = false;
            }
        }

        if b == b'#' && !in_quote && !literal {
            let is_inline = !config.require_preceding_token || seen_token;
            if is_inline {
                if config.uid_gid_exception {
                    let next_is_digit = bytes.get(i + 1).is_some_and(u8::is_ascii_digit);
                    let prev_allows_uid = match prev {
                        None => true,
                        Some(p) => {
                            matches!(p, b',' | b'%' | b':' | b'(' | b'>' | b'@' | b'"')
                                || (p as char).is_whitespace()
                        }
                    };
                    if !(in_runas_paren || (next_is_digit && prev_allows_uid)) {
                        return Some(i);
                    }
                } else {
                    return Some(i);
                }
            }
        }

        if config.require_preceding_token {
            match b {
                b' ' | b'\t' => {}
                _ => seen_token = true,
            }
        }
        prev = Some(b);
    }
    None
}

/// True when the `(` at `paren_idx` opens a runas spec rather than sitting
/// inside a command token. A runas open-paren follows the `host =`
/// separator, a `,` command-list separator, or the start of the line
/// (skipping intervening whitespace); a MID-command `(` is preceded by a
/// command character. sudoers-only (`config.uid_gid_exception`); derived
/// from the old `parser.rs::paren_opens_runas` (324-335).
fn paren_opens_runas(bytes: &[u8], paren_idx: usize) -> bool {
    let mut k = paren_idx;
    while let Some(j) = k.checked_sub(1) {
        if (bytes[j] as char).is_whitespace() {
            k = j;
        } else {
            return bytes[j] == b'=' || bytes[j] == b',';
        }
    }
    // Only whitespace (or nothing) precedes the `(`: it is the line's first
    // token.
    true
}

/// Strip an inline trailing `#` comment for parse purposes, per `config`.
/// Returns `line` unchanged when [`comment_index`] finds nothing to strip.
#[must_use]
pub fn strip(line: &str, config: StripConfig) -> &str {
    comment_index(line, config).map_or(line, |idx| &line[..idx])
}

#[cfg(test)]
mod tests {
    use super::*;

    // ===================== fapolicyd table =====================
    // Ground truth: crates/rulesteward-fapolicyd/src/parser/inline.rs
    // `inline_comment_index` (lines 27-37) + `strip_inline_comment` (40-43).
    // No quote awareness; `#` counts as inline only after a preceding
    // non-whitespace token seen earlier in the same left-to-right scan.
    // (These rows are the sole record of this equivalence today; per-row
    // citations below point at the live function span (inline.rs:27-37 /
    // 40-43), not any deleted test's line numbers.)
    mod fapolicyd_table {
        use super::*;

        const STRIP_CASES: &[(&str, &str)] = &[
            // inline.rs:32 (`b'#' if seen_token`): trailing hash after a
            // seen token strips.
            ("allow uid=0 : all # comment", "allow uid=0 : all "),
            // inline.rs:32-33: column-0 `#` has no preceding token yet, so
            // the `_` arm sets seen_token instead of matching the `#` arm.
            ("# whole-line comment", "# whole-line comment"),
            // inline.rs:31 (`b' ' | b'\t' => {}`): leading whitespace does
            // not set seen_token, so a `#` after it is still not inline.
            ("   # leading ws", "   # leading ws"),
            ("\t# tab then hash", "\t# tab then hash"),
            // inline.rs:32-33 (glued `#`, no preceding whitespace needed -
            // only a preceding non-whitespace byte matters).
            ("allow uid=0 : all#nospace", "allow uid=0 : all"),
            // inline.rs:27-37 (no `#` anywhere -> `None` -> `strip` returns
            // the line unchanged, per `strip`'s `map_or`).
            ("allow uid=0 : all", "allow uid=0 : all"),
            // inline.rs:32 + `strip` (40-43): comment found -> sliced at its
            // byte index.
            ("allow uid=0 : all # tail", "allow uid=0 : all "),
            // No quote awareness (config.quote = Unquoted): a `#` after a `'`
            // is still read as inline once a token has been seen, cutting
            // inside the "quoted" span. Hand-traced: seen_token becomes true
            // at 'a' of "allow"; the `'` is an ordinary byte; the `#` right
            // after it is Some(idx) because seen_token is already true.
            ("allow uid='#100' : all", "allow uid='"),
            // No `#include` bypass: a leading `#include` is just a leading
            // `#`, caught by the same column-0/no-preceding-token rule, so
            // it is NOT inline and the line is unchanged.
            ("#include /etc/foo", "#include /etc/foo"),
            // No `#<digit>` UID/GID exception: `#123` after a seen token
            // strips exactly like any other inline `#`.
            ("allow #123", "allow "),
            // No escape handling: a backslash is an ordinary token byte, so
            // the `#` immediately after it is inline (seen_token already
            // true from "allow").
            (r"allow \#x", r"allow \"),
            // Empty line: the byte loop never executes -> None -> unchanged.
            ("", ""),
            // CONCERN row (author's discretion): a leading `#` sets
            // `seen_token = true` (inline.rs:33-34, the `_` wildcard arm
            // catches `#` too - `seen_token` is only gated on `' '`/`'\t'`,
            // not on "is this byte itself a `#`"), so a SECOND `#` later on
            // the same line IS read as inline even though the first `#`
            // made the line look like a whole-line comment. Hand-traced:
            // idx0 `#` -> guard `if seen_token` fails (still false) ->
            // falls to `_` -> seen_token=true; idx1 ` ` -> no-op; idx2 `#`
            // -> guard now true -> `Some(2)`.
            ("# #y", "# "),
        ];

        #[test]
        fn strip_matches_old_inline_rs_behavior() {
            for (i, (input, expected)) in STRIP_CASES.iter().enumerate() {
                assert_eq!(
                    strip(input, StripConfig::FAPOLICYD),
                    *expected,
                    "case {i}: input {input:?}"
                );
            }
        }

        #[test]
        fn comment_index_none_for_leading_hash_forms() {
            // inline.rs:31-33: any `#` with no preceding non-whitespace
            // token is None (the `_` arm sets seen_token instead of
            // matching the `#` arm), regardless of what follows it.
            assert_eq!(
                comment_index("# whole-line comment", StripConfig::FAPOLICYD),
                None
            );
            assert_eq!(
                comment_index("   # leading ws", StripConfig::FAPOLICYD),
                None
            );
            assert_eq!(comment_index("", StripConfig::FAPOLICYD), None);
        }

        #[test]
        fn comment_index_some_for_glued_hash() {
            // inline.rs:32-33: a glued `#` after a seen token is found at
            // its own byte index (this is also what fapd-W03's
            // lints/source_scan.rs consumes directly, not just the parser).
            let line = "allow uid=0 : all#nospace";
            assert_eq!(
                comment_index(line, StripConfig::FAPOLICYD),
                Some(line.find('#').unwrap())
            );
        }
    }

    // ===================== auditd table =====================
    // Ground truth: crates/rulesteward-auditd/src/parser.rs `strip_comment`
    // (lines 267-277). Single-quote aware; ANY unquoted `#` (including
    // column 0 and glued) starts a comment; no `#include` / no `#<digit>`
    // exception.
    mod auditd_table {
        use super::*;

        const STRIP_CASES: &[(&str, &str)] = &[
            // parser.rs:261-266 doc example: unquoted trailing comment.
            ("-F auid>=1000 # comment", "-F auid>=1000 "),
            // No `#` at all: unchanged.
            ("-F auid>=1000 -k audit_rule", "-F auid>=1000 -k audit_rule"),
            // Quote state: single quotes protect an embedded `#`
            // (parser.rs:271, toggled on every `'`); once closed, scanning
            // resumes, and here there is no later unquoted `#`, so the
            // whole line survives.
            ("-F 'auid>=1000#weird' -k x", "-F 'auid>=1000#weird' -k x"),
            // `#` at position 0: unlike fapolicyd, auditd has no
            // require_preceding_token gate - i=0 hits the `#` arm directly
            // and returns &line[..0].
            ("# whole line", ""),
            // Glued `#` (no preceding whitespace) strips exactly like a
            // whitespace-preceded one - the loop does not distinguish.
            ("-k rule#tag", "-k rule"),
            // No `#include` concept (n/a to auditd) - literal "#include"
            // text is just an ordinary column-0 `#` and strips to empty.
            ("#include /etc/foo", ""),
            // No `#<digit>` UID exception - `#123` strips like any other
            // unquoted `#`.
            ("-F auid=1000 #123", "-F auid=1000 "),
            // Escaped-quote is NOT honored (no backslash awareness): the
            // 3rd `'` (after the literal backslash) still toggles
            // in_single_quote back to true, so the `# tail` that follows
            // reads as "inside quotes" and the whole line survives
            // unchanged. Hand-traced against the plain per-`'` toggle loop.
            (r"-F 'a\'b' # tail", r"-F 'a\'b' # tail"),
            // Empty line: loop never executes -> whole (empty) line.
            ("", ""),
            // No backslash escape (`EscapeRule::None`): a `\` is an ordinary
            // byte, so the `#` immediately after it still starts a comment.
            //
            // This row is a NO-CHANGE regression pin added by #649, which
            // gave sudoers escape awareness. It asserts only that auditd was
            // NOT changed by that work; it is deliberately NOT a fresh
            // derivation of `auditctl` comment semantics. Grounding that
            // properly needs the `rs-oracle8/9/10` containers, because an
            // unprivileged `auditctl` bails BEFORE parsing (rc 4, identical
            // for a valid and an invalid rule) and `-R` against live netlink
            // would mutate the HOST ruleset. See #584 for the raw-reader
            // (`audit_strsplit`) modelling question that owns that answer.
            (
                r"-a always,exit -F auid>=1000 \#x",
                r"-a always,exit -F auid>=1000 \",
            ),
        ];

        #[test]
        fn strip_matches_old_parser_rs_behavior() {
            for (i, (input, expected)) in STRIP_CASES.iter().enumerate() {
                assert_eq!(
                    strip(input, StripConfig::AUDITD),
                    *expected,
                    "case {i}: input {input:?}"
                );
            }
        }
    }

    // ===================== sudoers table =====================
    // Ground truth: crates/rulesteward-sudoers/src/parser.rs
    // `strip_inline_comment` (lines 237-315) + `paren_opens_runas`
    // (324-335). Double-quote aware, plus the `#include`/`#includedir`
    // bypass and the `#<digits>` UID/GID-token exception (with runas-paren
    // state tracking). The first block below reproduces values already
    // grounded against real `visudo`/`cvtsudoers` behavior (the report
    // mapping named test cases to these rows lives in git history, since
    // `parser.rs`'s own `#[cfg(test)] mod tests` duplicating them was
    // removed once these rows made them redundant); per-row citations point
    // at the live `strip_inline_comment` function span (parser.rs:237-315)
    // rather than the deleted test line numbers. The rest are new cases
    // hand-traced against the same function for the required table shapes
    // (quote states, `#include`, empty line, `#` at position 0, escaped
    // chars).
    //
    // ONE EXCEPTION, added by #649: the escaped-quote row deliberately does NOT
    // follow `strip_inline_comment`. That function was wrong there, so the row
    // was re-grounded on sudo 1.9.17p2 directly; its own comment carries the
    // commands and the output.
    mod sudoers_table {
        use super::*;

        const STRIP_CASES: &[(&str, &str)] = &[
            // parser.rs:295 `,` prev-byte arm (was
            // `strip_keeps_percent_hash_gid_token_...`).
            ("%#1000 ALL=(ALL) ALL", "%#1000 ALL=(ALL) ALL"),
            ("Defaults passprompt=foo#1000", "Defaults passprompt=foo"),
            // parser.rs:295-299 (skip multi-digit UID, strip later real
            // comment).
            (
                "root,#1000 ALL=(ALL) ALL # real comment",
                "root,#1000 ALL=(ALL) ALL ",
            ),
            // parser.rs:295-299 (UID token at EOL, single + multi digit).
            ("root,#7", "root,#7"),
            ("root,#1000", "root,#1000"),
            // parser.rs:295-299 (UID token then a normal token then a
            // comment).
            ("u,#5 h = /bin/ls #c", "u,#5 h = /bin/ls "),
            // parser.rs:295-299 (post-`=` alias-member UID kept, not gated
            // on `=`).
            ("User_Alias FOO = #1000", "User_Alias FOO = #1000"),
            // parser.rs:263,295,299 (#407 colon / open-paren runas
            // positions).
            (
                "alice ALL=(root:#1000) /bin/su",
                "alice ALL=(root:#1000) /bin/su",
            ),
            ("alice ALL=(#1000) /bin/su", "alice ALL=(#1000) /bin/su"),
            // parser.rs:263,295,299 (malformed GID tail still kept -
            // classifier not validator).
            (
                "alice ALL=(root:#1000abc) /bin/su",
                "alice ALL=(root:#1000abc) /bin/su",
            ),
            (
                "alice ALL=(#1000abc) /bin/su",
                "alice ALL=(#1000abc) /bin/su",
            ),
            // parser.rs:264,299 (real comment still stripped after a closed
            // runas group).
            (
                "alice ALL=(root) /bin/su # comment",
                "alice ALL=(root) /bin/su ",
            ),
            // parser.rs:263,299 + `paren_opens_runas` (324-335): mid-command
            // paren does not open runas state .
            (
                "alice localhost = /bin/echo (#foo",
                "alice localhost = /bin/echo (",
            ),
            // parser.rs:262-263 (`b'(' if !in_quotes`): a `(` inside double
            // quotes is literal, does not open runas state (see report
            // mapping).
            (
                "Defaults passprompt=\"=(\" #abc",
                "Defaults passprompt=\"=(\" ",
            ),
            // parser.rs:262,264 (`b')' if !in_quotes`): a `)` inside double
            // quotes does not close runas state; the `#foo` inside the
            // still-open paren is a kept token .
            (
                "alice ALL=(root:\"a)\"#foo) /bin/su",
                "alice ALL=(root:\"a)\"#foo) /bin/su",
            ),
            // #include / #includedir bypass (parser.rs:238-246): the whole
            // line survives untouched regardless of any `#` later in it.
            ("#include /etc/sudoers.extra", "#include /etc/sudoers.extra"),
            ("#includedir /etc/sudoers.d", "#includedir /etc/sudoers.d"),
            // Pre-existing quirk, faithfully preserved (NOT a bug to fix
            // here): `after.starts_with("dir")` (parser.rs:243) has no
            // word-boundary check after "dir", so "#includedirty..." ALSO
            // bypasses even though it is not a real `#includedir` keyword.
            ("#includedirty stuff #tail", "#includedirty stuff #tail"),
            // `#` at position 0 with no digit/include match: a real
            // comment, stripped to empty (parser.rs:285-308: next_is_digit
            // is false, so the `&&` with prev_allows_uid is false either
            // way).
            ("#", ""),
            ("# whole line comment", ""),
            // Glued `#` after a plain letter: a real comment
            // (prev_allows_uid is false for a letter byte).
            ("foo#bar", "foo"),
            // Quote state: a double quote protects an embedded `#`; a LATER
            // unquoted `#` still strips normally (parser.rs:262 quote
            // toggle + 265-309 comment arm).
            (
                "Defaults env_keep=\"FOO#BAR\" # comment",
                "Defaults env_keep=\"FOO#BAR\" ",
            ),
            // Escaped quote inside a span, under the quote-finding rule
            // (`EscapeRule::Backslash`, #649). The middle `"` is escaped, so
            // it does NOT close the span; the span closes at the 3rd `"` and
            // trailing `#tail` is therefore an ordinary inline comment.
            //
            // CHANGED by #649. This row previously pinned the opposite
            // ("escaped-quote is NOT honored, the whole line survives"),
            // which was an equivalence pin on the pre-#562 implementation
            // rather than on sudo. Re-grounded against sudo 1.9.17p2 on
            // 2026-08-19:
            //
            //   printf 'Defaults passprompt="a\\"b" #tail\n'
            //     visudo -c -f -     -> rc 0 ("parsed OK")
            //     cvtsudoers -f json -> exactly one Options entry,
            //                           { "passprompt": "a\"b" }
            //
            // The backslash is DOUBLED in that `printf` on purpose: bash
            // `printf` consumes `\"`, so the single-backslash spelling emits
            // `passprompt="a"b"`, which cvtsudoers rejects with a syntax error
            // at rc 1. The doubled form is what actually produces the bytes
            // this row pins. (`\#` elsewhere in this file needs no doubling -
            // it is not a printf escape.)
            //
            // The value real sudo records is `a"b` with NO ` #tail` in it,
            // so sudo read the tail as a comment and the old expectation
            // was wrong. Keeping it would have made the escaped-`#` fix
            // below unreachable, since both need the same escape state.
            (
                r#"Defaults passprompt="a\"b" #tail"#,
                r#"Defaults passprompt="a\"b" "#,
            ),
            // Empty line: the byte loop never executes -> whole (empty)
            // line.
            ("", ""),
            // ---- Strengthening rows for the `prev_allows_uid` byte-set
            // (parser.rs:286-298): earlier rows in this table pin ',' '%'
            // and whitespace via the KEEP path, so a wrong impl that
            // dropped ':' '(' '>' '@' '"' from the set would still pass.
            // Each row below forces the byte immediately BEFORE `#` to be
            // one of those otherwise-undiscriminated bytes, with a digit
            // immediately after `#` so `next_is_digit` is unconditionally
            // true and only `prev_allows_uid` decides the outcome.
            //
            // parser.rs:295 `'>'` arm (the #407 `Defaults>` runas-userid
            // scope sigil): prev='>' before the digit -> KEEP, whole line
            // unchanged.
            ("Defaults>#1000", "Defaults>#1000"),
            // parser.rs:295 `'@'` arm (the #407 `Defaults@` host-named
            // scope sigil): prev='@' before the digit -> KEEP, unchanged.
            ("Defaults@#1000", "Defaults@#1000"),
            // parser.rs:295 `'"'` arm (the #424 case: a `#<digits>` glued
            // right after a Defaults value's CLOSING double quote is an
            // invalid token OUTSIDE the quote, not a comment). At the `#`,
            // `in_quotes` has already toggled back to false from the
            // closing `"`, so this exercises the QUOTE-CLOSE byte itself as
            // the `prev` arm (distinct from "inside an open quote", which
            // the earlier `passprompt="=(" #abc` row already covers) ->
            // KEEP, unchanged.
            ("Defaults passprompt=\"a\"#5", "Defaults passprompt=\"a\"#5"),
            // parser.rs:295 `'('` arm, discriminated from `in_runas_paren`
            // (parser.rs:299): this `(` is the SAME mid-command paren as
            // the `alice localhost = /bin/echo (#foo` row above (not a
            // runas paren per `paren_opens_runas` - it follows a command
            // token "echo ", not `host =` / `,` / line start), so
            // `in_runas_paren` stays false. But `prev_allows_uid` matches
            // `'('` UNCONDITIONALLY (the match arm does not check
            // `in_runas_paren`), so with a DIGIT after `#` (unlike the
            // `#foo` row's letter, which fails `next_is_digit` and strips)
            // this is KEPT even though it is not actually a runas
            // position - the exact under-discrimination the `#foo` row
            // alone could not catch (a wrong impl that only allows `'('`
            // when `in_runas_paren` is true would strip this; real
            // parser.rs keeps it).
            (
                "alice localhost = /bin/echo (#1000",
                "alice localhost = /bin/echo (#1000",
            ),
            // parser.rs:289-296 (#426): `char::is_whitespace` (NOT
            // `is_ascii_whitespace`) governs the whitespace half of
            // `prev_allows_uid`. `\u{000B}` (vertical tab) is NOT covered
            // by `u8::is_ascii_whitespace` (which excludes VT) but IS
            // Unicode `White_Space=Yes`, so `(p as char).is_whitespace()`
            // is true and this is KEPT, unchanged - narrowing the check to
            // ASCII whitespace would be the #426 regression.
            ("foo\u{000B}#1000", "foo\u{000B}#1000"),
            // ---- `':'` is the one `prev_allows_uid` byte NOT discriminated
            // by the rows above. Every existing `':'`-before-
            // `#` row in this table sits inside a runas paren
            // (`"alice ALL=(root:#1000) /bin/su"` etc.), so parser.rs:299's
            // `in_runas_paren ||` short-circuit KEEPs without the scan ever
            // reaching the `':'` arm at parser.rs:295 - a wrong impl that
            // dropped `b':'` from the `matches!` set would still pass every
            // prior row. This row forces `':'` to be the ONLY thing that can
            // KEEP the line: no paren at all (`in_runas_paren` stays false
            // for the whole line), so parser.rs:299 falls through to
            // `next_is_digit && prev_allows_uid`, and only the `':'` arm at
            // parser.rs:295 can make `prev_allows_uid` true here.
            ("foo:#1000", "foo:#1000"),
        ];

        #[test]
        fn strip_matches_old_parser_rs_behavior() {
            for (i, (input, expected)) in STRIP_CASES.iter().enumerate() {
                assert_eq!(
                    strip(input, StripConfig::SUDOERS),
                    *expected,
                    "case {i}: input {input:?}"
                );
            }
        }

        #[test]
        fn comment_index_none_for_include_bypass_despite_later_hash() {
            // parser.rs:238-246: `#include` bypasses entirely, even though a
            // later unquoted `#` exists further in the line - this is why
            // `comment_index` (not just `strip`'s output) must distinguish
            // "no comment" from "comment found at the end of the line".
            assert_eq!(
                comment_index("#include foo #real", StripConfig::SUDOERS),
                None
            );
        }

        // ---- Escape awareness (#649). Ground truth: sudo 1.9.17p2,
        // re-derived 2026-08-19 on this host, both files fed on stdin.
        //
        //   printf 'alice ALL = /bin/echo \#x, NOPASSWD: /bin/su\n'
        //     visudo -c -f -   -> rc 0 ("parsed OK")
        //     cvtsudoers -f json -> TWO Cmnd_Specs:
        //       { "command": "/bin/echo #x" }
        //       { "authenticate": false } + { "command": "/bin/su" }
        //
        //   printf 'alice ALL = /bin/echo a#b, NOPASSWD: /bin/su\n'
        //     visudo -c -f -   -> rc 0
        //     cvtsudoers -f json -> ONE Cmnd_Spec, { "command": "/bin/echo a" },
        //       and NO "authenticate": false anywhere.
        //
        // So the backslash is the discriminator: sudo genuinely truncates at
        // an UNESCAPED `#`, and genuinely does not at an escaped one. The two
        // tests below are each other's control; neither is meaningful alone.

        #[test]
        fn escaped_hash_is_a_literal_byte_not_a_comment_start() {
            // The escaped `#` must not start a comment, or everything after
            // it (here a live NOPASSWD grant) is discarded before parsing
            // and no diagnostic of any kind is emitted (#649).
            assert_eq!(
                comment_index(
                    r"alice ALL = /bin/echo \#x, NOPASSWD: /bin/su",
                    StripConfig::SUDOERS
                ),
                None
            );
        }

        #[test]
        fn unescaped_hash_still_starts_a_comment() {
            // The control for the row above. A fix that simply stopped
            // treating `#` as a comment marker would pass that test and fail
            // this one; real sudo truncates here.
            assert_eq!(
                strip(
                    "alice ALL = /bin/echo a#b, NOPASSWD: /bin/su",
                    StripConfig::SUDOERS
                ),
                "alice ALL = /bin/echo a"
            );
        }
    }
}
