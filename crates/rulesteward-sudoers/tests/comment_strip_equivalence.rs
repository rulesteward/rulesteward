//! #562 equivalence pin: the shared `rulesteward_core::comment` helper,
//! configured for sudoers, must match the OLD `parser::strip_inline_comment`
//! behavior byte-for-byte. Expected values are derived by READING
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
        // parser.rs:1684-1697.
        ("%#1000 ALL=(ALL) ALL", "%#1000 ALL=(ALL) ALL"),
        ("Defaults passprompt=foo#1000", "Defaults passprompt=foo"),
        // parser.rs:1763-1780 (#407 runas colon / open-paren `#<digits>`
        // UID/GID exception).
        (
            "alice ALL=(root:#1000) /bin/su",
            "alice ALL=(root:#1000) /bin/su",
        ),
        // parser.rs:1830-1842 (mid-command paren does not open runas
        // state, so the trailing `#foo` is a real comment).
        (
            "alice localhost = /bin/echo (#foo",
            "alice localhost = /bin/echo (",
        ),
        // parser.rs:1849-1863 (a `(` inside double quotes is literal, does
        // not open runas state).
        (
            "Defaults passprompt=\"=(\" #abc",
            "Defaults passprompt=\"=(\" ",
        ),
        // #include bypass (parser.rs:238-246): the whole line survives
        // unchanged.
        ("#include /etc/sudoers.extra", "#include /etc/sudoers.extra"),
        // Escaped-quote is NOT honored (no backslash awareness): the 3rd
        // `"` re-opens the quote state, so the trailing `#tail` reads as
        // inside quotes and the whole line survives unchanged.
        (
            r#"Defaults passprompt="a\"b" #tail"#,
            r#"Defaults passprompt="a\"b" #tail"#,
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
