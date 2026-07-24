//! #562 equivalence pin: the shared `rulesteward_core::comment` helper,
//! configured for auditd, must match the OLD `parser::strip_comment`
//! behavior byte-for-byte. Expected values are derived by READING
//! `src/parser.rs` (cited per case) - not by calling the old function,
//! which this refactor deletes.

use rulesteward_core::comment::{StripConfig, strip};

#[test]
fn matches_old_parser_rs_strip_comment() {
    // Ground truth: crates/rulesteward-auditd/src/parser.rs:267-277.
    let cases: &[(&str, &str)] = &[
        // parser.rs:261-266 doc example: unquoted trailing comment.
        ("-F auid>=1000 # comment", "-F auid>=1000 "),
        ("-F auid>=1000 -k audit_rule", "-F auid>=1000 -k audit_rule"),
        // Single-quote protects an embedded `#` (parser.rs:271, toggled on
        // every `'`).
        ("-F 'auid>=1000#weird' -k x", "-F 'auid>=1000#weird' -k x"),
        // No require-preceding-token gate (unlike fapolicyd): column-0 `#`
        // strips to empty.
        ("# whole line", ""),
        // Escaped-quote is NOT honored (no backslash awareness): the 3rd
        // `'` (after the literal backslash) re-toggles in_single_quote back
        // to true, so the trailing `# tail` reads as "inside quotes" and
        // the whole line survives unchanged.
        (r"-F 'a\'b' # tail", r"-F 'a\'b' # tail"),
    ];
    for (i, (input, expected)) in cases.iter().enumerate() {
        assert_eq!(
            strip(input, StripConfig::AUDITD),
            *expected,
            "case {i}: input {input:?}"
        );
    }
}
