//! Shared inline-comment stripping, parameterized per backend (#562).
//!
//! Phase-0 stub for the 9i fan-out: the module file exists so parallel lanes
//! never edit `lib.rs` concurrently. Lane 3 (#562) owns the body: one
//! parameterized stripper replacing the three line-level implementations
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
    };

    /// auditd `parser.rs::strip_comment`: single-quote aware, no
    /// `#include` concept, no UID/GID exception; ANY unquoted `#` (including
    /// column 0 and glued) starts a comment.
    pub const AUDITD: Self = Self {
        quote: QuoteChar::Single,
        require_preceding_token: false,
        include_bypass: false,
        uid_gid_exception: false,
    };

    /// sudoers `parser.rs::strip_inline_comment`: double-quote aware, plus
    /// the `#include`/`#includedir` bypass and the `#<digits>` UID/GID
    /// exception (with runas-paren state tracking).
    pub const SUDOERS: Self = Self {
        quote: QuoteChar::Double,
        require_preceding_token: false,
        include_bypass: true,
        uid_gid_exception: true,
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
#[must_use]
pub fn comment_index(_line: &str, _config: StripConfig) -> Option<usize> {
    todo!("lane-3-stripper: implement the unified comment_index (#562)")
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
    // (The rows below reproduce the values of what were EXISTING pinned
    // tests in inline.rs's own `#[cfg(test)] mod tests` -
    // finds_trailing_hash / ignores_column_0_hash / ignores_leading_ws_hash /
    // detects_hash_immediately_after_token / strip_preserves_when_no_inline_hash
    // / strip_cuts_at_inline_hash; those old tests were removed once the
    // barrier ruling made them obsolete duplicates of these rows - see
    // `/mnt/side-projects/9i-closeout/lane-3-stripper-report.md` "Barrier
    // rework" for the old-test -> row mapping. Per-row citations below point
    // at the live function span (inline.rs:27-37 / 40-43), not the deleted
    // test line numbers.)
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
            // Round-3 CONCERN row (author's discretion): a leading `#` sets
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
    // state tracking). The first block below reproduces the values of what
    // were EXISTING pinned tests in `parser.rs`'s own `#[cfg(test)] mod
    // tests`, already grounded against real `visudo`/`cvtsudoers` behavior;
    // those old tests were removed once the barrier ruling made them
    // obsolete duplicates of these rows (the full old-test -> row mapping
    // is recorded in `/mnt/side-projects/9i-closeout/lane-3-stripper-report.md`
    // "Barrier rework" section) - the per-row citations below now point at
    // the live `strip_inline_comment` function span (parser.rs:237-315)
    // rather than the deleted test line numbers. The rest are new cases
    // hand-traced against the same function for the required table shapes
    // (quote states, `#include`, empty line, `#` at position 0, escaped
    // chars).
    mod sudoers_table {
        use super::*;

        const STRIP_CASES: &[(&str, &str)] = &[
            // parser.rs:295 `,` prev-byte arm (was
            // `strip_keeps_percent_hash_gid_token_...`; see report mapping).
            ("%#1000 ALL=(ALL) ALL", "%#1000 ALL=(ALL) ALL"),
            ("Defaults passprompt=foo#1000", "Defaults passprompt=foo"),
            // parser.rs:295-299 (skip multi-digit UID, strip later real
            // comment; see report mapping).
            (
                "root,#1000 ALL=(ALL) ALL # real comment",
                "root,#1000 ALL=(ALL) ALL ",
            ),
            // parser.rs:295-299 (UID token at EOL, single + multi digit; see
            // report mapping).
            ("root,#7", "root,#7"),
            ("root,#1000", "root,#1000"),
            // parser.rs:295-299 (UID token then a normal token then a
            // comment; see report mapping).
            ("u,#5 h = /bin/ls #c", "u,#5 h = /bin/ls "),
            // parser.rs:295-299 (post-`=` alias-member UID kept, not gated
            // on `=`; see report mapping).
            ("User_Alias FOO = #1000", "User_Alias FOO = #1000"),
            // parser.rs:263,295,299 (#407 colon / open-paren runas
            // positions; see report mapping).
            (
                "alice ALL=(root:#1000) /bin/su",
                "alice ALL=(root:#1000) /bin/su",
            ),
            ("alice ALL=(#1000) /bin/su", "alice ALL=(#1000) /bin/su"),
            // parser.rs:263,295,299 (malformed GID tail still kept -
            // classifier not validator; see report mapping).
            (
                "alice ALL=(root:#1000abc) /bin/su",
                "alice ALL=(root:#1000abc) /bin/su",
            ),
            (
                "alice ALL=(#1000abc) /bin/su",
                "alice ALL=(#1000abc) /bin/su",
            ),
            // parser.rs:264,299 (real comment still stripped after a closed
            // runas group; see report mapping).
            (
                "alice ALL=(root) /bin/su # comment",
                "alice ALL=(root) /bin/su ",
            ),
            // parser.rs:263,299 + `paren_opens_runas` (324-335): mid-command
            // paren does not open runas state (see report mapping).
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
            // still-open paren is a kept token (see report mapping).
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
            // Escaped-quote is NOT honored (no backslash awareness, same
            // pattern as auditd): the 3rd `"` re-opens the quote state, so
            // the trailing `#tail` reads as inside quotes and the whole
            // line survives unchanged.
            (
                r#"Defaults passprompt="a\"b" #tail"#,
                r#"Defaults passprompt="a\"b" #tail"#,
            ),
            // Empty line: the byte loop never executes -> whole (empty)
            // line.
            ("", ""),
            // ---- Round-3 adversarial strengthening (killing rows for the
            // prev_allows_uid byte-set, parser.rs:286-298): the pre-rework
            // table only pinned ',' '%' and whitespace via the KEEP path
            // (strip_keeps_percent_hash_gid_token_...,
            // strip_handles_a_uid_token_then_a_normal_token...), so a wrong
            // impl that drops ':' '(' '>' '@' '"' from the set still passed.
            // Each row below forces the byte immediately BEFORE `#` to be
            // one of the previously-undiscriminated bytes, with a digit
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
            // ---- Round-4 residual: `':'` was the ONE prev_allows_uid byte
            // still undiscriminated by round 3. Every existing `':'`-before-
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
    }
}
