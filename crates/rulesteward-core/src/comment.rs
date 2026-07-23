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
    mod fapolicyd_table {
        use super::*;

        const STRIP_CASES: &[(&str, &str)] = &[
            // inline.rs:49-53 `finds_trailing_hash`.
            ("allow uid=0 : all # comment", "allow uid=0 : all "),
            // inline.rs:56-59 `ignores_column_0_hash`.
            ("# whole-line comment", "# whole-line comment"),
            // inline.rs:61-65 `ignores_leading_ws_hash`.
            ("   # leading ws", "   # leading ws"),
            ("\t# tab then hash", "\t# tab then hash"),
            // inline.rs:67-71 `detects_hash_immediately_after_token` (glued `#`).
            ("allow uid=0 : all#nospace", "allow uid=0 : all"),
            // inline.rs:73-77 `strip_preserves_when_no_inline_hash`.
            ("allow uid=0 : all", "allow uid=0 : all"),
            // inline.rs:79-85 `strip_cuts_at_inline_hash`.
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
            // inline.rs:56-65: any `#` with no preceding non-whitespace
            // token is None, regardless of what follows it.
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
            // inline.rs:67-71: a glued `#` after a seen token is found at
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
    // state tracking). The first block below reproduces EXISTING pinned
    // tests already grounded against real `visudo`/`cvtsudoers` behavior
    // (parser.rs's own `#[cfg(test)] mod tests`); the rest are new cases
    // hand-traced against the same function for the required table shapes
    // (quote states, `#include`, empty line, `#` at position 0, escaped
    // chars).
    mod sudoers_table {
        use super::*;

        const STRIP_CASES: &[(&str, &str)] = &[
            // parser.rs:1684-1697 `strip_keeps_percent_hash_gid_token_...`.
            ("%#1000 ALL=(ALL) ALL", "%#1000 ALL=(ALL) ALL"),
            ("Defaults passprompt=foo#1000", "Defaults passprompt=foo"),
            // parser.rs:1706-1712 (skip multi-digit UID, strip later real
            // comment).
            (
                "root,#1000 ALL=(ALL) ALL # real comment",
                "root,#1000 ALL=(ALL) ALL ",
            ),
            // parser.rs:1718-1722 (UID token at EOL, single + multi digit).
            ("root,#7", "root,#7"),
            ("root,#1000", "root,#1000"),
            // parser.rs:1727-1733 (UID token then a normal token then a
            // comment).
            ("u,#5 h = /bin/ls #c", "u,#5 h = /bin/ls "),
            // parser.rs:1741-1750 (post-`=` alias-member UID kept, not
            // gated on `=`).
            ("User_Alias FOO = #1000", "User_Alias FOO = #1000"),
            // parser.rs:1763-1780 (#407 colon / open-paren runas
            // positions).
            (
                "alice ALL=(root:#1000) /bin/su",
                "alice ALL=(root:#1000) /bin/su",
            ),
            ("alice ALL=(#1000) /bin/su", "alice ALL=(#1000) /bin/su"),
            // parser.rs:1787-1800 (malformed GID tail still kept -
            // classifier not validator).
            (
                "alice ALL=(root:#1000abc) /bin/su",
                "alice ALL=(root:#1000abc) /bin/su",
            ),
            (
                "alice ALL=(#1000abc) /bin/su",
                "alice ALL=(#1000abc) /bin/su",
            ),
            // parser.rs:1806-1813 (real comment still stripped after a
            // closed runas group).
            (
                "alice ALL=(root) /bin/su # comment",
                "alice ALL=(root) /bin/su ",
            ),
            // parser.rs:1830-1842 (mid-command paren does not open runas
            // state).
            (
                "alice localhost = /bin/echo (#foo",
                "alice localhost = /bin/echo (",
            ),
            // parser.rs:1849-1863 (a `(` inside double quotes is literal,
            // does not open runas state).
            (
                "Defaults passprompt=\"=(\" #abc",
                "Defaults passprompt=\"=(\" ",
            ),
            // parser.rs:1870-1886 (a `)` inside double quotes does not
            // close runas state; the `#foo` inside the still-open paren is
            // a kept token).
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
