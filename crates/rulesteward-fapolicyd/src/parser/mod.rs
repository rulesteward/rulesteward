//! fapolicyd rule parser — per-line dispatch over a chumsky 0.13 grammar.
//!
//! Public surface: [`parse_rules_file`] consumes a `&str` source and returns
//! `Ok(Vec<Entry>)` when every line parses cleanly, `Err(Vec<Diagnostic>)`
//! when one or more lines fail. Diagnostics are accumulated across the
//! whole file — first-failure-only is explicitly avoided (see the
//! monotonicity proptest in `tests/proptest_test.rs`).
//!
//! W03 (inline trailing `# comment`) is emitted by [`crate::lints::lint`]
//! via source re-scan, not by the parser. The parser strips inline `#` text
//! before handing the line to chumsky so the grammar stays clean. A
//! leading-whitespace `#` is rejected as F01 — fapolicyd itself only
//! accepts `#` at column 0.

mod error;
mod grammar;
pub mod inline;

use chumsky::extra;
use chumsky::prelude::*;
use rulesteward_core::{Diagnostic, Severity};

use crate::ast::{Entry, Rule};

const UTF8_BOM: &str = "\u{feff}";

/// Parse a fapolicyd rules file source into a sequence of entries.
///
/// `Err(diagnostics)` carries one or more `F01` (Fatal) findings when any
/// line fails. The parser collects diagnostics from every failing line.
///
/// **Contract:** the parser emits ONLY `Severity::Fatal` (`F01`) diagnostics.
/// Warning-tier findings such as `W03` (inline trailing `#`) live in
/// [`crate::lints::lint`] and are produced from a source re-scan. The Ok
/// branch therefore intentionally carries no diagnostics. If a future change
/// adds a non-Fatal pass to the parser, the return type must be widened to
/// `(Vec<Entry>, Vec<Diagnostic>)` so warnings on the Ok path are not lost.
pub fn parse_rules_file(source: &str) -> Result<Vec<Entry>, Vec<Diagnostic>> {
    let mut entries: Vec<Entry> = Vec::new();
    let mut diagnostics: Vec<Diagnostic> = Vec::new();

    if source.is_empty() {
        return Ok(entries);
    }

    let lines: Vec<&str> = source.split('\n').collect();
    let last_idx = lines.len().saturating_sub(1);

    for (idx, raw_line) in lines.iter().enumerate() {
        // A file ending in `\n` produces a trailing empty chunk that is the
        // LF terminator, not an extra blank line — suppress it.
        if idx == last_idx && raw_line.is_empty() {
            break;
        }
        let lineno = idx + 1;
        let trimmed_cr = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        let no_bom = if idx == 0 {
            trimmed_cr.strip_prefix(UTF8_BOM).unwrap_or(trimmed_cr)
        } else {
            trimmed_cr
        };

        let (line_entries, line_diags) = parse_line(no_bom, lineno);
        entries.extend(line_entries);
        diagnostics.extend(line_diags);
    }

    if diagnostics.iter().any(|d| d.severity == Severity::Fatal) {
        Err(diagnostics)
    } else {
        Ok(entries)
    }
}

fn parse_line(line: &str, lineno: usize) -> (Vec<Entry>, Vec<Diagnostic>) {
    if line.bytes().all(|b| b == b' ' || b == b'\t') {
        return (vec![Entry::Blank { line: lineno }], Vec::new());
    }

    // Column-0 comment ONLY. Leading-whitespace `#` falls through to the
    // chumsky path below where every production fails — yielding an F01.
    if let Some(text) = line.strip_prefix('#') {
        return (
            vec![Entry::Comment {
                text: text.to_string(),
                line: lineno,
            }],
            Vec::new(),
        );
    }

    let body = inline::strip_inline_comment(line);
    let first_nonws = body.trim_start_matches([' ', '\t']).chars().next();

    if first_nonws == Some('%') {
        run_chumsky(grammar::set_definition(), body, lineno)
    } else {
        let (entries, modern_diags) = run_chumsky(grammar::modern_rule(), body, lineno);
        if modern_diags.is_empty() {
            (entries, modern_diags)
        } else {
            let (legacy_entries, legacy_diags) = run_chumsky(grammar::legacy_rule(), body, lineno);
            if legacy_diags.is_empty() {
                (legacy_entries, legacy_diags)
            } else {
                // Both failed — return modern's diagnostics. Modern is the
                // dominant case and chumsky's "expected colon" is the most
                // actionable hint.
                (Vec::new(), modern_diags)
            }
        }
    }
}

fn run_chumsky<'a, P>(parser: P, body: &'a str, lineno: usize) -> (Vec<Entry>, Vec<Diagnostic>)
where
    P: Parser<'a, &'a str, Entry, extra::Err<Rich<'a, char>>>,
{
    let (output, errors) = parser.parse(body).into_output_errors();
    if errors.is_empty() {
        if let Some(entry) = output {
            (vec![set_entry_line(entry, lineno)], Vec::new())
        } else {
            (
                Vec::new(),
                vec![Diagnostic::new(
                    Severity::Fatal,
                    "F01",
                    0..body.len(),
                    "parser produced neither an entry nor an error",
                    "<source>",
                    lineno,
                    1,
                )],
            )
        }
    } else {
        let diags = errors
            .into_iter()
            .map(|e| error::rich_to_diagnostic(&e, lineno))
            .collect();
        (Vec::new(), diags)
    }
}

fn set_entry_line(entry: Entry, lineno: usize) -> Entry {
    match entry {
        Entry::Rule(r) => Entry::Rule(Rule { line: lineno, ..r }),
        Entry::SetDefinition { name, values, .. } => Entry::SetDefinition {
            name,
            values,
            line: lineno,
        },
        Entry::Comment { text, .. } => Entry::Comment { text, line: lineno },
        Entry::Blank { .. } => Entry::Blank { line: lineno },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::{Decision, SyntaxFlavor};

    #[test]
    fn empty_source_parses_to_no_entries() {
        let entries = parse_rules_file("").expect("empty parses");
        assert!(entries.is_empty());
    }

    #[test]
    fn single_lf_yields_one_blank_entry() {
        let entries = parse_rules_file("\n").expect("blank parses");
        assert_eq!(entries.len(), 1);
        assert!(matches!(entries[0], Entry::Blank { line: 1 }));
    }

    #[test]
    fn whitespace_only_line_is_blank_entry() {
        // Mixed space and tab — the blank detector must accept any line
        // composed of only space-or-tab bytes, not only fully-empty lines.
        let entries = parse_rules_file("  \t  \n").expect("ws-only line is blank");
        assert_eq!(entries.len(), 1);
        assert!(matches!(entries[0], Entry::Blank { line: 1 }));
    }

    #[test]
    fn col0_comment_yields_comment_entry() {
        let entries = parse_rules_file("# hello\n").expect("comment parses");
        assert_eq!(entries.len(), 1);
        match &entries[0] {
            Entry::Comment { text, line } => {
                assert_eq!(text, " hello");
                assert_eq!(*line, 1);
            }
            other => panic!("expected Comment, got {other:?}"),
        }
    }

    #[test]
    fn leading_whitespace_comment_is_f01() {
        let diags = parse_rules_file("   # leading ws\n").expect_err("must fail");
        assert!(
            diags.iter().any(|d| d.code.as_ref() == "F01"),
            "expected F01 for leading-ws comment, got {diags:?}"
        );
    }

    #[test]
    fn modern_rule_assigns_modern_flavor_and_line() {
        let entries = parse_rules_file("allow uid=0 : all\n").expect("parses");
        match &entries[0] {
            Entry::Rule(r) => {
                assert_eq!(r.decision, Decision::Allow);
                assert_eq!(r.syntax, SyntaxFlavor::Modern);
                assert_eq!(r.line, 1);
            }
            other => panic!("expected Rule, got {other:?}"),
        }
    }

    #[test]
    fn legacy_rule_assigns_legacy_flavor() {
        let entries = parse_rules_file("allow uid=0 path=/usr/bin/sh\n").expect("parses");
        match &entries[0] {
            Entry::Rule(r) => assert_eq!(r.syntax, SyntaxFlavor::Legacy),
            other => panic!("expected Rule, got {other:?}"),
        }
    }

    #[test]
    fn accumulates_diagnostics_across_multiple_failing_lines() {
        let diags = parse_rules_file("!!!a\n!!!b\n!!!c\n").expect_err("three errors");
        assert!(
            diags.iter().filter(|d| d.code.as_ref() == "F01").count() >= 3,
            "expected ≥3 F01s, got {diags:?}"
        );
    }

    #[test]
    fn inline_comment_is_stripped_before_chumsky() {
        // The trailing `# comment` is stripped so the line parses cleanly.
        // W03 emission for this line is the lint walker's job — not the
        // parser's.
        let entries =
            parse_rules_file("allow uid=0 : all # trailing\n").expect("parses after strip");
        assert!(matches!(entries[0], Entry::Rule(_)));
    }

    #[test]
    fn crlf_terminated_line_parses() {
        let entries = parse_rules_file("allow uid=0 : all\r\n").expect("crlf parses");
        assert!(matches!(entries[0], Entry::Rule(_)));
    }

    #[test]
    fn bom_is_stripped_from_first_line() {
        let entries = parse_rules_file("\u{feff}allow uid=0 : all\n").expect("bom parses");
        assert!(matches!(entries[0], Entry::Rule(_)));
    }
}
