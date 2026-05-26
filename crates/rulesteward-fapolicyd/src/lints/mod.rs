//! Post-parse lint passes.
//!
//! Code split:
//! * `walker` - AST-driven passes (F03, E01, W02).
//! * `validation` - AST-driven attribute-value validation (E02).
//! * `macros` - AST-driven macro-system passes (E03, E04, E05).
//! * `deprecation` - AST-driven deprecated-attribute-name passes (W07).
//! * `source_scan` - raw-source re-scan for W03.
//! * `layout` - filesystem-driven F02 check.

mod deprecation;
mod layout;
mod macros;
mod source_scan;
mod validation;
mod walker;

pub use layout::check_layout;

use std::path::Path;

use rulesteward_core::Diagnostic;

use crate::ast::Entry;
use crate::parser;

/// Run every per-file lint pass and return the merged diagnostic list.
///
/// `source` is the raw rules-file text, needed for W03 (inline trailing
/// `# comment`) re-scan. `file` is the path used in every emitted
/// `Diagnostic::file`.
#[must_use]
pub fn lint(entries: &[Entry], source: &str, file: &Path) -> Vec<Diagnostic> {
    let mut diags = walker::walk(entries, file);
    diags.extend(validation::walk(entries, file));
    diags.extend(macros::walk(entries, file));
    diags.extend(deprecation::walk(entries, file));
    diags.extend(source_scan::w03_scan(source, file));
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
    let (entries, mut parse_diags) = match parser::parse_rules_file(&source) {
        Ok(entries) => (entries, Vec::new()),
        Err(diags) => (Vec::new(), diags),
    };
    // The parser emits diagnostics with file = "<source>" placeholder
    // (the parser doesn't know the path). Rewrite to the real path so
    // CI tooling that greps `file:line:col` sees the actual file.
    //
    // Also set `source_id` to the same path string the CLI uses as the
    // key in its `BTreeMap<String, String>` source cache (`Path::display`
    // formatting). With both `source_id` set and a real byte-range span
    // from the chumsky `Rich::span()`, F01 diagnostics now render with an
    // ariadne snippet just like E01 / F03 / W02 / W03.
    let source_id = path.display().to_string();
    for d in &mut parse_diags {
        d.file = path.to_path_buf();
        d.source_id = Some(source_id.clone());
    }
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
        // Pins the invariant: `lint()` invokes ALL five walks (walker,
        // validation, macros, deprecation, source_scan) and merges their
        // diagnostics into the returned Vec. A mutant that drops one walk
        // from the aggregator body silently loses the corresponding code
        // from the output; this test fails fast in that case.
        //
        // The source is constructed so each walk fires on its own code:
        //   walker::e01      -> `bogusattr=` (unknown attribute name)
        //   validation::e02  -> `sha256hash=abc` (3 chars, not 64 hex)
        //   macros::e03      -> `exe=%undefinedmacro` (unknown macro ref)
        //   deprecation::w07 -> `sha256hash=` (deprecated attribute name)
        //   source_scan::w03 -> trailing `# bad` (inline comment past tokens)
        //
        // The parser strips the inline `# bad` BEFORE chumsky sees the line,
        // so the rule itself parses cleanly; W03 is then re-detected from
        // the raw `source` string by the source_scan walk.
        let source =
            "allow uid=0 bogusattr=x : sha256hash=abc # bad\nallow uid=0 : exe=%undefinedmacro\n";
        let mut f = tempfile::NamedTempFile::new().expect("tempfile");
        f.write_all(source.as_bytes()).expect("write");
        let path = f.path().to_path_buf();
        let entries = parser::parse_rules_file(source).expect("source must parse");
        let diags = lint(&entries, source, &path);
        let codes: HashSet<&str> = diags.iter().map(|d| d.code.as_ref()).collect();
        assert!(
            codes.contains("E01"),
            "expected walker::e01 to fire (bogusattr= on subject side), got codes={codes:?} diags={diags:?}",
        );
        assert!(
            codes.contains("E02"),
            "expected validation::e02 to fire (sha256hash=abc -> 3 chars not 64), got codes={codes:?} diags={diags:?}",
        );
        assert!(
            codes.contains("E03"),
            "expected macros::e03 to fire (%undefinedmacro reference), got codes={codes:?} diags={diags:?}",
        );
        assert!(
            codes.contains("W07"),
            "expected deprecation::w07 to fire (sha256hash= deprecated), got codes={codes:?} diags={diags:?}",
        );
        assert!(
            codes.contains("W03"),
            "expected source_scan::w03 to fire (inline `# bad` comment), got codes={codes:?} diags={diags:?}",
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
            diags.iter().any(|d| d.code.as_ref() == "F01"),
            "garbage line must produce F01, got {diags:?}"
        );
        let f01 = diags
            .iter()
            .find(|d| d.code.as_ref() == "F01")
            .expect("F01 should be present");
        assert_eq!(
            f01.file,
            f.path(),
            "F01 diagnostic file should match input path, got {:?}",
            f01.file
        );
        // The lint_file post-emission rewrite must also set source_id so the
        // ariadne renderer can find the source text in the CLI's source map.
        // Without this, F01 silently falls back to plain rendering even
        // though its span is a real byte range.
        assert_eq!(
            f01.source_id.as_deref(),
            Some(f.path().display().to_string().as_str()),
            "F01 source_id must match the file path string used by the CLI source map",
        );
    }

    #[test]
    fn lint_file_propagates_io_error_for_missing_path() {
        let result = lint_file(std::path::Path::new("/nonexistent/path/to/nothing"));
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::NotFound);
    }
}
