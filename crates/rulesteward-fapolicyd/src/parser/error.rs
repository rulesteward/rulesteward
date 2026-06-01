//! Map chumsky 0.13's `Rich<char>` parse errors into our cross-crate
//! [`Diagnostic`] type (code `"fapd-F01"`, severity `Fatal`).

use chumsky::error::Rich;
use rulesteward_core::{Diagnostic, Severity};
use std::path::Path;

/// Convert a single chumsky error into a fapd-F01 diagnostic anchored to `file`.
///
/// `lineno` is 1-based; the column is derived from `Rich::span().start` (the
/// byte offset within the line, so it stays line-relative). `body_start_in_file`
/// is the byte offset of the parsed line body within the whole source; the
/// diagnostic span is shifted by it so it is FILE-relative (matching the spans
/// `fixup_entry` produces for successful entries), which is what ariadne needs to
/// render the caret on the correct line. `source_id` is `file`'s display string so
/// ariadne can render the snippet for ANY caller (not just `lint_file`).
///
/// The diagnostic message is prefixed with `"malformed rule syntax: "` so
/// operators see a plain-language context before the chumsky token hint (e.g.
/// `"malformed rule syntax: found 'u' expected 'w'"`). The code, span, and
/// severity are unchanged.
pub fn rich_to_diagnostic(
    err: &Rich<'_, char>,
    lineno: usize,
    body_start_in_file: usize,
    file: &Path,
) -> Diagnostic {
    let span = err.span();
    Diagnostic::new(
        Severity::Fatal,
        "fapd-F01",
        (body_start_in_file + span.start)..(body_start_in_file + span.end),
        format!("malformed rule syntax: {err}"),
        file,
        lineno,
        span.start + 1,
    )
    .with_source_id(file.display().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chumsky::prelude::*;

    /// Build a minimal Rich error for a known-bad input and assert the diagnostic
    /// message starts with the operator-friendly prefix.
    /// RED: fails if the prefix is absent (old format!("{err}") form).
    #[test]
    fn rich_to_diagnostic_message_has_operator_friendly_prefix() {
        // Parse a deliberately invalid input to get a real Rich<char> error.
        // `just('a')` expects exactly 'a'; feeding 'x' produces a Rich error.
        let parser = just::<_, _, extra::Err<Rich<char>>>('a');
        let (_, errors) = parser.parse("x").into_output_errors();
        let err = errors.into_iter().next().expect("one error");

        let diag = rich_to_diagnostic(&err, 1, 0, std::path::Path::new("t.rules"));

        assert!(
            diag.message.starts_with("malformed rule syntax: "),
            "fapd-F01 message must start with 'malformed rule syntax: '; got: {:?}",
            diag.message
        );
    }
}
