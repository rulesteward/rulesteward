//! #562 equivalence pin: the shared `rulesteward_core::comment` helper,
//! configured for fapolicyd, must match the OLD `parser::inline` behavior
//! byte-for-byte. Expected values are derived by READING
//! `src/parser/inline.rs` (cited per case) - not by calling the old
//! function, which this refactor deletes.

use rulesteward_core::comment::{StripConfig, strip};

#[test]
fn matches_old_inline_rs_strip_inline_comment() {
    // Ground truth: crates/rulesteward-fapolicyd/src/parser/inline.rs:27-43.
    let cases: &[(&str, &str)] = &[
        // inline.rs:49-53 `finds_trailing_hash`.
        ("allow uid=0 : all # comment", "allow uid=0 : all "),
        // inline.rs:56-59 `ignores_column_0_hash` (no `#include` bypass
        // needed for fapolicyd - a leading `#` is never inline at all).
        ("# whole-line comment", "# whole-line comment"),
        // inline.rs:67-71 `detects_hash_immediately_after_token` (glued
        // `#` after a seen token).
        ("allow uid=0 : all#nospace", "allow uid=0 : all"),
        // inline.rs:73-77 `strip_preserves_when_no_inline_hash`.
        ("allow uid=0 : all", "allow uid=0 : all"),
        // No quote awareness: a `#` inside `'...'` still cuts once a token
        // has been seen (hand-traced against inline.rs's seen_token loop -
        // there is no quote branch at all).
        ("allow uid='#100' : all", "allow uid='"),
    ];
    for (i, (input, expected)) in cases.iter().enumerate() {
        assert_eq!(
            strip(input, StripConfig::FAPOLICYD),
            *expected,
            "case {i}: input {input:?}"
        );
    }
}
