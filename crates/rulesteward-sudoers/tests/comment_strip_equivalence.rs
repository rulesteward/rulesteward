//! #562 equivalence pin: the shared `rulesteward_core::comment` helper,
//! configured for sudoers, must match the OLD `parser::strip_inline_comment`
//! behavior byte-for-byte.
//!
//! EXCEPTION, added by #649: the FINAL row no longer does, and deliberately.
//! It pins real sudo 1.9.17p2 instead, because the old implementation was
//! simply wrong about an escaped quote and preserving that byte-for-byte would
//! have blocked the escape-awareness fix. Every other row is still an
//! equivalence pin, so the test name's `matches_old_` is accurate for all but
//! that one. Expected values are derived by READING
//! `src/parser.rs` (cited per case) - not by calling the old function,
//! which this refactor deletes. All cited cases reproduce EXISTING pinned
//! tests already in `src/parser.rs`'s own `#[cfg(test)] mod tests`, which
//! are themselves grounded against real `visudo -c` / `cvtsudoers` output.

use rulesteward_core::comment::{StripConfig, strip};

#[test]
fn matches_old_parser_rs_strip_inline_comment() {
    // Ground truth: crates/rulesteward-sudoers/src/parser.rs:237-315 +
    // paren_opens_runas (324-335).
    let cases: &[(&str, &str)] = &[
        // parser.rs:295 `,`/`%` prev-byte arms of `prev_allows_uid`.
        // Reproduces the value of the old
        // `strip_keeps_percent_hash_gid_token_...` test, removed (#562) once
        // superseded by this row and the `sudoers_table` rows in
        // `rulesteward-core/src/comment.rs`.
        ("%#1000 ALL=(ALL) ALL", "%#1000 ALL=(ALL) ALL"),
        ("Defaults passprompt=foo#1000", "Defaults passprompt=foo"),
        // parser.rs:263,295,299 (#407 runas colon / open-paren `#<digits>`
        // UID/GID exception, plus `paren_opens_runas` at 324-335).
        (
            "alice ALL=(root:#1000) /bin/su",
            "alice ALL=(root:#1000) /bin/su",
        ),
        // parser.rs:263,299 + `paren_opens_runas` (324-335): mid-command
        // paren does not open runas state, so the trailing `#foo` is a real
        // comment.
        (
            "alice localhost = /bin/echo (#foo",
            "alice localhost = /bin/echo (",
        ),
        // parser.rs:262-263 (`b'(' if !in_quotes`): a `(` inside double
        // quotes is literal, does not open runas state.
        (
            "Defaults passprompt=\"=(\" #abc",
            "Defaults passprompt=\"=(\" ",
        ),
        // #include bypass (parser.rs:238-246): the whole line survives
        // unchanged.
        ("#include /etc/sudoers.extra", "#include /etc/sudoers.extra"),
        // Escaped quote inside a span (#649). CHANGED from the pre-#649
        // expectation, which pinned the whole line surviving. That was an
        // equivalence pin on the old implementation, not on sudo:
        // `printf 'Defaults passprompt="a\\"b" #tail\n' | cvtsudoers -f json`
        // (backslash DOUBLED on purpose: bash printf eats `\"`, and the
        // single-backslash spelling emits a different, rc-1 file)
        // on sudo 1.9.17p2 (2026-08-19) records the value as `a"b` with no
        // ` #tail`, so the tail is a comment. See the matching row and its
        // full grounding in `rulesteward-core/src/comment.rs`.
        (
            r#"Defaults passprompt="a\"b" #tail"#,
            r#"Defaults passprompt="a\"b" "#,
        ),
    ];
    for (i, (input, expected)) in cases.iter().enumerate() {
        assert_eq!(
            strip(input, StripConfig::SUDOERS),
            *expected,
            "case {i}: input {input:?}"
        );
    }
}
