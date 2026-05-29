//! Post-parse lint passes.
//!
//! Code split:
//! * `walker` - AST-driven passes (fapd-F03, fapd-E01, fapd-W02).
//! * `validation` - AST-driven attribute-value validation (fapd-E02).
//! * `macros` - AST-driven macro-system passes (fapd-E03, fapd-E04, fapd-E05, fapd-S02).
//! * `deprecation` - AST-driven deprecated-attribute-name passes (fapd-W07).
//! * `reachability` - AST-driven rule-shadowing pass (fapd-W01).
//! * `subsume` - shared rule-subsumption engine reused by fapd-W01 and fapd-W04.
//! * `source_scan` - raw-source re-scan for fapd-W03.
//! * `layout` - filesystem-driven fapd-F02 check.
//! * `cross_file` - cross-`rules.d/` passes (fapd-W04 ordering, fapd-C01 filename convention).
//! * `dir_slash` - AST-driven per-attribute trailing-slash lint (fapd-W08).

mod cross_file;
mod deprecation;
mod dir_slash;
mod layout;
mod macros;
mod reachability;
mod source_scan;
mod subsume;
mod validation;
mod walker;

pub use layout::check_layout;

use std::path::Path;

use rulesteward_core::{Diagnostic, fill_columns};

use crate::ast::Entry;
use crate::parser;

/// Run every per-file lint pass and return the merged diagnostic list.
///
/// `source` is the raw rules-file text, needed for fapd-W03 (inline trailing
/// `# comment`) re-scan. `file` is the path used in every emitted
/// `Diagnostic::file`.
#[must_use]
pub fn lint(entries: &[Entry], source: &str, file: &Path) -> Vec<Diagnostic> {
    let mut diags = walker::walk(entries, file);
    diags.extend(validation::walk(entries, file));
    diags.extend(macros::walk(entries, file));
    diags.extend(reachability::walk(entries, file));
    diags.extend(deprecation::walk(entries, file));
    diags.extend(dir_slash::walk(entries, file));
    diags.extend(source_scan::w03_scan(source, file));
    // Backfill column from each diagnostic's byte span. Lint passes and the
    // parser historically hardcoded column = 1; this makes the column field
    // agree with the byte span the human renderer uses for its caret, so
    // JSON / plain / snapshot columns are consistent with the ariadne display.
    fill_columns(&mut diags, source);
    diags
}

/// Run cross-file lint passes over all rules.d files in fagenrules load order.
/// Directory-mode only (a single `--file` has no cross-file relationships).
#[must_use]
pub fn lint_cross_file(files: &[(std::path::PathBuf, Vec<Entry>)]) -> Vec<Diagnostic> {
    let mut diags = cross_file::w04(files);
    diags.extend(cross_file::c01(files));
    diags
}

/// Read a rules file, parse it, and run every per-file lint pass against it.
///
/// Returns `(entries, diagnostics)` on read success. `entries` is empty when
/// parsing failed; `diagnostics` always contains everything the parser and
/// lint walker found. The `io::Error` is propagated unchanged so the CLI
/// can map it to exit code 3 (tool failure).
#[must_use = "lint results contain parse and lint diagnostics that should be checked"]
pub fn lint_file(path: &Path) -> Result<(Vec<Entry>, Vec<Diagnostic>), std::io::Error> {
    let source = std::fs::read_to_string(path)?;
    let (entries, parse_diags) = match parser::parse_rules_file(&source, path) {
        Ok(entries) => (entries, Vec::new()),
        Err(diags) => (Vec::new(), diags),
    };
    // The parser now anchors fapd-F01 diagnostics to `path` (file + source_id)
    // at their origin, so no post-pass rewrite is needed here.
    let mut diags = parse_diags;
    diags.extend(lint(&entries, &source, path));
    Ok((entries, diags))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::io::Write;

    #[test]
    fn lint_aggregator_calls_all_walks_and_merges_diagnostics() {
        // Pins the invariant: `lint()` invokes ALL seven walks (walker,
        // validation, macros, reachability, deprecation, dir_slash, source_scan) and
        // merges their diagnostics into the returned Vec. A mutant that drops
        // one walk from the aggregator body silently loses the corresponding
        // code from the output; this test fails fast in that case.
        //
        // The source is constructed so each walk fires on its own code:
        //   walker::e01         -> `bogusattr=` (unknown attribute name)
        //   validation::e02     -> `sha256hash=abc` (3 chars, not 64 hex)
        //   macros::e03         -> `exe=%undefinedmacro` (unknown macro ref)
        //   macros::s02         -> `%latemacro=` defined AFTER the first rule
        //   deprecation::w07    -> `sha256hash=` (deprecated attribute name)
        //   source_scan::w03    -> trailing `# bad` (inline comment past tokens)
        //   reachability::w01   -> line 3 duplicates line 2's terminal rule,
        //                          so line 3 is unreachable (shadowed).
        //   dir_slash::w08      -> `dir=/no/slash` on the object (no trailing slash)
        //
        // The parser strips the inline `# bad` BEFORE chumsky sees the line,
        // so the rule itself parses cleanly; fapd-W03 is then re-detected from
        // the raw `source` string by the source_scan walk.
        //
        // Line 3 is an exact copy of line 2: `allow` is terminal and the
        // predicates are identical, so line 2 shadows line 3 -> fapd-W01 on
        // line 3. The duplicate also re-fires fapd-E03 (still an undefined
        // macro), but `codes` is a set so that does not perturb the other
        // assertions.
        //
        // Line 4 defines `%latemacro` AFTER the first rule, firing fapd-S02
        // (definition not at file top). The name is distinct from
        // `%undefinedmacro` (so it does not satisfy the line 2/3 reference,
        // leaving fapd-E03 intact) and unreferenced (so it adds no E03/E04),
        // and its single string value is homogeneous (so no fapd-E05). Being
        // a SetDefinition rather than a Rule, it cannot perturb fapd-W01.
        let source = "allow uid=0 bogusattr=x : sha256hash=abc dir=/no/slash # bad\nallow uid=0 : exe=%undefinedmacro\nallow uid=0 : exe=%undefinedmacro\n%latemacro=/usr/bin/foo\n";
        let mut f = tempfile::NamedTempFile::new().expect("tempfile");
        f.write_all(source.as_bytes()).expect("write");
        let path = f.path().to_path_buf();
        let entries = parser::parse_rules_file(source, &path).expect("source must parse");
        let diags = lint(&entries, source, &path);
        let codes: HashSet<&str> = diags.iter().map(|d| d.code.as_ref()).collect();
        assert!(
            codes.contains("fapd-E01"),
            "expected walker::e01 to fire (bogusattr= on subject side), got codes={codes:?} diags={diags:?}",
        );
        assert!(
            codes.contains("fapd-E02"),
            "expected validation::e02 to fire (sha256hash=abc -> 3 chars not 64), got codes={codes:?} diags={diags:?}",
        );
        assert!(
            codes.contains("fapd-E03"),
            "expected macros::e03 to fire (%undefinedmacro reference), got codes={codes:?} diags={diags:?}",
        );
        assert!(
            codes.contains("fapd-W07"),
            "expected deprecation::w07 to fire (sha256hash= deprecated), got codes={codes:?} diags={diags:?}",
        );
        assert!(
            codes.contains("fapd-W03"),
            "expected source_scan::w03 to fire (inline `# bad` comment), got codes={codes:?} diags={diags:?}",
        );
        assert!(
            codes.contains("fapd-W01"),
            "expected reachability::w01 to fire (line 3 duplicates line 2's terminal rule), got codes={codes:?} diags={diags:?}",
        );
        assert!(
            codes.contains("fapd-S02"),
            "expected macros::s02 to fire (macro after first rule), got codes={codes:?} diags={diags:?}",
        );
        assert!(
            codes.contains("fapd-W08"),
            "expected dir_slash::w08 to fire (dir=/no/slash on the object has no trailing slash), got codes={codes:?} diags={diags:?}",
        );
    }

    #[test]
    fn lint_file_returns_entries_and_no_diagnostics_for_clean_input() {
        let mut f = tempfile::NamedTempFile::new().expect("tempfile");
        writeln!(f, "allow uid=0 : all").expect("write");
        let (entries, diags) = lint_file(f.path()).expect("read");
        assert_eq!(entries.len(), 1);
        assert!(
            diags.is_empty(),
            "clean rule should produce no diagnostics, got {diags:?}"
        );
    }

    #[test]
    fn lint_file_returns_f01_on_parse_failure() {
        let mut f = tempfile::NamedTempFile::new().expect("tempfile");
        writeln!(f, "!!!garbage").expect("write");
        let (entries, diags) = lint_file(f.path()).expect("read");
        assert!(
            entries.is_empty(),
            "expected no entries on parse failure, got {entries:?}"
        );
        assert!(
            diags.iter().any(|d| d.code.as_ref() == "fapd-F01"),
            "garbage line must produce fapd-F01, got {diags:?}"
        );
        let f01 = diags
            .iter()
            .find(|d| d.code.as_ref() == "fapd-F01")
            .expect("fapd-F01 should be present");
        assert_eq!(
            f01.file,
            f.path(),
            "fapd-F01 diagnostic file should match input path, got {:?}",
            f01.file
        );
        // The parser anchors fapd-F01 to `path` (source_id = path.display()),
        // so the ariadne renderer can find the source text in the CLI's source
        // map without any post-pass rewrite. Without source_id, fapd-F01 would
        // silently fall back to plain rendering even though its span is a real
        // byte range.
        assert_eq!(
            f01.source_id.as_deref(),
            Some(f.path().display().to_string().as_str()),
            "fapd-F01 source_id must match the file path string used by the CLI source map",
        );
    }

    #[test]
    fn lint_file_propagates_io_error_for_missing_path() {
        let result = lint_file(std::path::Path::new("/nonexistent/path/to/nothing"));
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::NotFound);
    }

    // --- column backfill tests (A5: derive column from span) ---

    #[test]
    fn diagnostic_column_is_derived_from_span() {
        // Two-line file. Line 1 is a clean rule; line 2 references an undefined
        // macro. The E03 diagnostic's span.start is the byte offset of line 2's
        // rule start within the whole file (non-zero). Before the column backfill,
        // d.column was hardcoded to 1. After the backfill, it must equal
        // line_col(d.span, src).1.
        //
        // Line 1: "allow uid=0 : all\n"     = 18 bytes (line 1, col 1..17)
        // Line 2: "allow uid=0 : exe=%undef\n"  starts at byte offset 18 -> col 1
        //         BUT its span.start = 18, so line_col(18, src) = (2, 1).
        //
        // To get a non-1 column on a rule, we need a finding that anchors to a
        // mid-rule span, OR we use fapd-W03 (already anchors to the `#` position).
        // Here we use the `all_lint_diagnostics_have_column_matching_line_col`
        // test for the universal check, and this test specifically verifies the
        // key invariant: column == line_col(span, source).1 for at least one
        // non-trivially-placed diagnostic (E03 on line 2).
        let src = "allow uid=0 : all\nallow uid=0 : exe=%undef\n";
        let p = std::path::Path::new("t.rules");
        let entries = parser::parse_rules_file(src, p)
            .unwrap_or_else(|diags| panic!("fixture must parse, got parse errors: {diags:?}"));
        let diags = lint(&entries, src, p);
        let e03 = diags
            .iter()
            .find(|d| d.code.as_ref() == "fapd-E03")
            .unwrap_or_else(|| {
                let summary: Vec<_> = diags
                    .iter()
                    .map(|d| {
                        format!(
                            "[{}] col={} span={}..{}",
                            d.code, d.column, d.span.start, d.span.end
                        )
                    })
                    .collect();
                panic!("fapd-E03 expected for undefined macro %undef, diags={summary:?}")
            });
        // The E03 span should start at byte 18 (start of line 2).
        assert!(
            e03.span.start > 0,
            "E03 span.start must be non-zero (rule is on line 2): got span={}..{}",
            e03.span.start,
            e03.span.end
        );
        let (expected_line, expected_col) = rulesteward_core::span_util::line_col(&e03.span, src);
        assert_eq!(
            e03.line, expected_line,
            "line must match line_col: got {} expected {}",
            e03.line, expected_line
        );
        assert_eq!(
            e03.column, expected_col,
            "column must be span-derived (not hardcoded 1): got {} expected {} (span={}..{})",
            e03.column, expected_col, e03.span.start, e03.span.end
        );
    }

    #[test]
    fn all_lint_diagnostics_have_column_matching_line_col() {
        // Smoke test: every diagnostic returned by lint() must have d.column ==
        // line_col(d.span, source).1, confirming the backfill is universal.
        // Uses the same multi-code fixture as lint_aggregator_calls_all_walks.
        let src = "allow uid=0 bogusattr=x : sha256hash=abc dir=/no/slash # bad\nallow uid=0 : exe=%undefinedmacro\nallow uid=0 : exe=%undefinedmacro\n%latemacro=/usr/bin/foo\n";
        let p = std::path::Path::new("t.rules");
        let entries = parser::parse_rules_file(src, p).expect("should parse");
        let diags = lint(&entries, src, p);
        for d in &diags {
            // Skip unanchored diagnostics (0..0 span) - these are file-layout
            // fatals with no source byte range.
            if d.span.start == 0 && d.span.end == 0 {
                continue;
            }
            let (expected_line, expected_col) = rulesteward_core::span_util::line_col(&d.span, src);
            assert_eq!(
                d.column, expected_col,
                "[{}] line={} span={}..{}: column {} != line_col column {}",
                d.code, d.line, d.span.start, d.span.end, d.column, expected_col
            );
            let _ = expected_line; // line correctness is pre-existing
        }
    }

    #[test]
    fn parse_f01_column_matches_line_col() {
        // F01 parse errors should also have column == line_col(span, source).1
        // after the parse backfill. Uses a multi-line source where the failure
        // is on line 2 at a non-trivial column offset.
        let src = "allow uid=0 : all\n!!!garbage\n";
        let p = std::path::Path::new("t.rules");
        let diags = parser::parse_rules_file(src, p).expect_err("line 2 must fail");
        for d in &diags {
            if d.span.start == 0 && d.span.end == 0 {
                continue;
            }
            let (_, expected_col) = rulesteward_core::span_util::line_col(&d.span, src);
            assert_eq!(
                d.column, expected_col,
                "[{}] line={} span={}..{}: column {} != line_col column {}",
                d.code, d.line, d.span.start, d.span.end, d.column, expected_col
            );
        }
    }
}
