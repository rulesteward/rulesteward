//! Post-parse lint passes.
//!
//! Code split:
//! * `walker` — AST-driven passes (F03, E01, W02).
//! * `source_scan` — raw-source re-scan for W03.
//! * `layout` — filesystem-driven F02 check.

mod layout;
mod source_scan;
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
    let (entries, parse_diags) = match parser::parse_rules_file(&source) {
        Ok(entries) => (entries, Vec::new()),
        Err(diags) => (Vec::new(), diags),
    };
    let mut diags = parse_diags;
    diags.extend(lint(&entries, &source, path));
    Ok((entries, diags))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

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
    }

    #[test]
    fn lint_file_propagates_io_error_for_missing_path() {
        let result = lint_file(std::path::Path::new("/nonexistent/path/to/nothing"));
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::NotFound);
    }
}
