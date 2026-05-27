//! Map chumsky 0.13's `Rich<char>` parse errors into our cross-crate
//! [`Diagnostic`] type (code `"fapd-F01"`, severity `Fatal`).

use chumsky::error::Rich;
use rulesteward_core::{Diagnostic, Severity};

/// Convert a single chumsky error into an fapd-F01 diagnostic.
///
/// `lineno` is 1-based; the column is derived from `Rich::span().start`
/// (which is the byte offset within the line).
pub fn rich_to_diagnostic(err: &Rich<'_, char>, lineno: usize) -> Diagnostic {
    let span = err.span();
    Diagnostic::new(
        Severity::Fatal,
        "fapd-F01",
        span.start..span.end,
        format!("{err}"),
        "<source>",
        lineno,
        span.start + 1,
    )
}
