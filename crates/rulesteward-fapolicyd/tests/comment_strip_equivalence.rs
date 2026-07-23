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
        // inline.rs:27-37 `inline_comment_index` (`b'#' if seen_token`):
        // trailing hash after a seen token strips. Reproduces the value of
        // the old `finds_trailing_hash` test, removed by lane-3 (#562) once
        // superseded by this row and the `fapolicyd_table` row in
        // `rulesteward-core/src/comment.rs`; see the lane-3 report
        // ("Barrier rework") for the full old-test -> row mapping.
        ("allow uid=0 : all # comment", "allow uid=0 : all "),
        // inline.rs:27-37 (no `#include` bypass needed for fapolicyd - a
        // leading `#` is never inline at all, since the `_` arm sets
        // `seen_token` before any `#` guard can match). Reproduces the old
        // `ignores_column_0_hash` test (see lane-3 report mapping).
        ("# whole-line comment", "# whole-line comment"),
        // inline.rs:27-37 (glued `#` after a seen token, no preceding
        // whitespace required). Reproduces the old
        // `detects_hash_immediately_after_token` test (see lane-3 report
        // mapping).
        ("allow uid=0 : all#nospace", "allow uid=0 : all"),
        // inline.rs:27-37 + `strip` (40-43): no `#` at all -> `None` ->
        // `strip` returns the line unchanged via `map_or`. Reproduces the
        // old `strip_preserves_when_no_inline_hash` test (see lane-3 report
        // mapping).
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
