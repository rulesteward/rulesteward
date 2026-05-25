//! fapolicyd rule parser - per-line dispatch over a chumsky 0.13 grammar.
//!
//! Public surface: [`parse_rules_file`] consumes a `&str` source and returns
//! `Ok(Vec<Entry>)` when every line parses cleanly, `Err(Vec<Diagnostic>)`
//! when one or more lines fail. Diagnostics are accumulated across the
//! whole file - first-failure-only is explicitly avoided (see the
//! monotonicity proptest in `tests/proptest_test.rs`).
//!
//! W03 (inline trailing `# comment`) is emitted by [`crate::lints::lint`]
//! via source re-scan, not by the parser. The parser strips inline `#` text
//! before handing the line to chumsky so the grammar stays clean. A
//! leading-whitespace `#` is rejected as F01 - fapolicyd itself only
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

    // `line_byte_offset` tracks the byte position of the start of each raw
    // line within the original `source` string. We add `raw_line.len() + 1`
    // per iteration (the `+1` accounts for the LF separator that `split('\n')`
    // consumed). This lets us convert chumsky's line-relative byte spans into
    // file-relative spans.
    let mut line_byte_offset: usize = 0;

    for (idx, raw_line) in lines.iter().enumerate() {
        // A file ending in `\n` produces a trailing empty chunk that is the
        // LF terminator, not an extra blank line - suppress it.
        if idx == last_idx && raw_line.is_empty() {
            break;
        }
        let lineno = idx + 1;
        let trimmed_cr = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        let bom_stripped = idx == 0 && trimmed_cr.starts_with(UTF8_BOM);
        let no_bom = if bom_stripped {
            &trimmed_cr[UTF8_BOM.len()..]
        } else {
            trimmed_cr
        };

        // `body_start_in_file` is the byte offset of `no_bom[0]` within
        // `source`. For the first line with a BOM we skip 3 bytes.
        let body_start_in_file = if bom_stripped {
            line_byte_offset + UTF8_BOM.len()
        } else {
            line_byte_offset
        };

        let (line_entries, line_diags) = parse_line(no_bom, lineno, body_start_in_file);
        entries.extend(line_entries);
        diagnostics.extend(line_diags);

        // Advance past this raw line plus its LF separator.
        line_byte_offset += raw_line.len() + 1;
    }

    if diagnostics.iter().any(|d| d.severity == Severity::Fatal) {
        Err(diagnostics)
    } else {
        Ok(entries)
    }
}

fn parse_line(
    line: &str,
    lineno: usize,
    body_start_in_file: usize,
) -> (Vec<Entry>, Vec<Diagnostic>) {
    if line.bytes().all(|b| b == b' ' || b == b'\t') {
        return (vec![Entry::Blank { line: lineno }], Vec::new());
    }

    // Column-0 comment ONLY. Leading-whitespace `#` falls through to the
    // chumsky path below where every production fails - yielding an F01.
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
        run_chumsky(grammar::set_definition(), body, lineno, body_start_in_file)
    } else {
        let (entries, modern_diags) =
            run_chumsky(grammar::modern_rule(), body, lineno, body_start_in_file);
        if modern_diags.is_empty() {
            (entries, modern_diags)
        } else {
            let (legacy_entries, legacy_diags) =
                run_chumsky(grammar::legacy_rule(), body, lineno, body_start_in_file);
            if legacy_diags.is_empty() {
                (legacy_entries, legacy_diags)
            } else {
                // Both failed - return modern's diagnostics. Modern is the
                // dominant case and chumsky's "expected colon" is the most
                // actionable hint.
                (Vec::new(), modern_diags)
            }
        }
    }
}

fn run_chumsky<'a, P>(
    parser: P,
    body: &'a str,
    lineno: usize,
    body_start_in_file: usize,
) -> (Vec<Entry>, Vec<Diagnostic>)
where
    P: Parser<'a, &'a str, Entry, extra::Err<Rich<'a, char>>>,
{
    let (output, errors) = parser.parse(body).into_output_errors();
    if errors.is_empty() {
        if let Some(entry) = output {
            (
                vec![fixup_entry(entry, lineno, body_start_in_file)],
                Vec::new(),
            )
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

/// Set the line number and convert the span from line-relative to
/// file-relative coordinates. `body_start_in_file` is the byte offset of the
/// first character of the parsed body within the original source string.
///
/// Only `Entry::Rule` carries a span; all other entry kinds keep only the
/// line adjustment.
///
/// **Invariant:** both `modern_rule()` and `legacy_rule()` in `grammar.rs`
/// open with `ws0()`, so chumsky's `e.span().start` is always 0 within the
/// parsed body. We therefore offset only the end, not the start. The
/// `debug_assert` below catches future grammar changes that violate this
/// (and would silently produce incorrectly-shifted spans).
fn fixup_entry(entry: Entry, lineno: usize, body_start_in_file: usize) -> Entry {
    match entry {
        Entry::Rule(r) => {
            debug_assert_eq!(
                r.span.start, 0,
                "chumsky grammar invariant: Rule.span.start must be 0 within parsed body",
            );
            Entry::Rule(Rule {
                line: lineno,
                span: body_start_in_file..(body_start_in_file + r.span.end),
                ..r
            })
        }
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
    use crate::ast::{Attr, Decision, SyntaxFlavor};

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
        // Mixed space and tab - the blank detector must accept any line
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
        // W03 emission for this line is the lint walker's job - not the
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
        // Source layout: BOM (3 bytes) + "allow uid=0 : all" (17 bytes) + "\n"
        // (1 byte) = 21 bytes total. Rule body lives at bytes 3..20; the span
        // must be file-relative, NOT line-relative (which would be 0..17).
        // This assertion locks the BOM accounting in `body_start_in_file`.
        let entries = parse_rules_file("\u{feff}allow uid=0 : all\n").expect("bom parses");
        let Entry::Rule(rule) = &entries[0] else {
            panic!("entries[0] expected Rule, got {:?}", entries[0])
        };
        assert_eq!(
            rule.span.start, 3,
            "Rule.span.start must account for the 3-byte BOM"
        );
        assert_eq!(
            rule.span.end, 20,
            "Rule.span.end must reach just past `all`"
        );
    }

    // --- Integration tests: legacy rules with dir/ftype/trust as object anchors ---

    #[test]
    fn legacy_rule_with_trust_object_anchor_parses() {
        // Before Task 5's fix: trust was classified as Either, so positional_split
        // could not find an object-only attribute to anchor the legacy subject/object
        // split. The rule failed to parse. After Task 5: trust is legacy-classified
        // as Object, so the split fires at the `trust` attribute.
        let entries = parse_rules_file("allow uid=0 trust=1\n")
            .expect("legacy rule with trust as object anchor must parse");
        let Entry::Rule(r) = &entries[0] else {
            panic!("entries[0] expected Rule, got {:?}", entries[0])
        };
        assert_eq!(r.syntax, SyntaxFlavor::Legacy);
        assert_eq!(r.subject.len(), 1, "subject side should contain uid=0");
        assert_eq!(r.object.len(), 1, "object side should contain trust=1");
        assert!(
            matches!(&r.subject[0], Attr::Kv { key, .. } if key == "uid"),
            "subject[0] should be uid, got {:?}",
            r.subject[0]
        );
        assert!(
            matches!(&r.object[0], Attr::Kv { key, .. } if key == "trust"),
            "object[0] should be trust, got {:?}",
            r.object[0]
        );
    }

    #[test]
    fn legacy_rule_with_dir_object_anchor_parses() {
        let entries = parse_rules_file("allow uid=0 dir=/usr\n")
            .expect("legacy rule with dir as object anchor must parse");
        let Entry::Rule(r) = &entries[0] else {
            panic!("entries[0] expected Rule")
        };
        assert_eq!(r.syntax, SyntaxFlavor::Legacy);
        assert!(
            matches!(&r.object[0], Attr::Kv { key, .. } if key == "dir"),
            "object[0] should be dir, got {:?}",
            r.object[0]
        );
    }

    #[test]
    fn legacy_rule_with_ftype_object_anchor_parses() {
        let entries = parse_rules_file("allow uid=0 ftype=application/x-executable\n")
            .expect("legacy rule with ftype as object anchor must parse");
        let Entry::Rule(r) = &entries[0] else {
            panic!("entries[0] expected Rule")
        };
        assert_eq!(r.syntax, SyntaxFlavor::Legacy);
        assert!(
            matches!(&r.object[0], Attr::Kv { key, .. } if key == "ftype"),
            "object[0] should be ftype, got {:?}",
            r.object[0]
        );
    }

    #[test]
    fn three_line_file_assigns_file_relative_spans() {
        // Layout (byte offsets):
        //   "# comment\n"        = bytes 0..10  (9 chars + LF)
        //   "allow uid=0 : all\n" = bytes 10..28 (17 chars + LF)
        //   "allow uid=1 : all\n" = bytes 28..46 (17 chars + LF)
        let source = "# comment\nallow uid=0 : all\nallow uid=1 : all\n";
        let entries = parse_rules_file(source).expect("parses");
        // entries[0] = Comment (line 1), entries[1] = Rule (line 2), entries[2] = Rule (line 3)
        let Entry::Rule(rule1) = &entries[1] else {
            panic!("entries[1] expected Rule")
        };
        let Entry::Rule(rule2) = &entries[2] else {
            panic!("entries[2] expected Rule")
        };
        assert_eq!(rule1.line, 2);
        assert_eq!(
            rule1.span.start, 10,
            "rule1 span starts at the `a` of `allow uid=0`"
        );
        assert_eq!(
            rule1.span.end, 27,
            "rule1 span ends past `all` (byte 27 is where the LF starts)"
        );
        assert_eq!(rule2.line, 3);
        assert_eq!(
            rule2.span.start, 28,
            "rule2 span starts at the `a` of `allow uid=1`"
        );
        assert_eq!(rule2.span.end, 45, "rule2 span ends past `all`");
    }
}
