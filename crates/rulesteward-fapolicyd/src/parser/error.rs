//! Map chumsky 0.13's `Rich<char>` parse errors into our cross-crate
//! [`Diagnostic`] type (code `"fapd-F01"`, severity `Fatal`).

use chumsky::error::Rich;
use rulesteward_core::{Diagnostic, Severity};
use std::path::Path;

/// Convert a single chumsky error into a fapd-F01 diagnostic anchored to `file`.
///
/// `lineno` is 1-based; the column is derived from `Rich::span().start`
/// (the byte offset within the line). `source_id` is set to `file`'s display
/// string so ariadne can render the snippet for ANY caller (not just `lint_file`).
pub fn rich_to_diagnostic(err: &Rich<'_, char>, lineno: usize, file: &Path) -> Diagnostic {
    let span = err.span();
    Diagnostic::new(
        Severity::Fatal,
        "fapd-F01",
        span.start..span.end,
        format!("{err}"),
        file,
        lineno,
        span.start + 1,
    )
    .with_source_id(file.display().to_string())
}
