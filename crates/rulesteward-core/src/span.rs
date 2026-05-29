//! Byte-range spans for diagnostics.
//!
//! `Span` is a type alias for `core::ops::Range<usize>` so `ariadne` can
//! consume it directly via its native `Span` impl. A future session may
//! migrate this to a newtype (e.g., `pub struct Span { start, end }`) to
//! gain `Copy` semantics and named-field ergonomics. To keep that
//! migration cheap, downstream code follows three rules:
//!
//! 1. Refer to spans via [`Span`], never `Range<usize>` directly. The
//!    single line below is the migration's only point of impact for
//!    type-system identity.
//! 2. Construct spans via [`span`]. Under the future newtype this
//!    becomes a `Span::new(start, end)` shorthand; call sites do not
//!    change.
//! 3. Query spans via free functions in [`span_util`]. Extension-trait
//!    methods on `Range<usize>` would bind to the std type and have to
//!    be rewritten at migration time; free functions adapt.

pub type Span = core::ops::Range<usize>;

/// Construct a byte-range span.
///
/// Prefer this over the `start..end` syntax so a future migration to a
/// `Span` newtype touches no call sites.
#[must_use]
pub fn span(start: usize, end: usize) -> Span {
    start..end
}

pub mod span_util {
    //! Free-function helpers over [`super::Span`]. Kept as free functions
    //! (rather than extension-trait methods on `Range<usize>`) so a future
    //! migration to a `Span` newtype changes their internals only, not
    //! their public signature.

    use super::Span;

    /// Returns the number of bytes covered by the span.
    #[must_use]
    pub fn len(s: &Span) -> usize {
        s.len()
    }

    /// Returns `true` if `byte` falls within the span (half-open: start inclusive, end exclusive).
    #[must_use]
    pub fn contains(s: &Span, byte: usize) -> bool {
        byte >= s.start && byte < s.end
    }

    /// Returns the 1-based `(line, column)` of the span's start byte within `src`.
    ///
    /// Iterates the bytes before `s.start` counting newlines. Column resets
    /// to 1 after each newline. Both line and column are 1-based.
    ///
    /// **Column counts bytes, not Unicode code points or grapheme clusters.**
    /// This is consistent with the byte-offset spans the parser produces.
    /// The returned column equals `1 + (number of bytes on the current line
    /// before `s.start`)`.
    ///
    /// **Precondition:** `s.start` must be a valid byte boundary in `src` and
    /// `s.start <= src.len()`. Out-of-range or mid-codepoint inputs produce a
    /// defined but possibly confusing result; they do not panic.
    #[must_use]
    pub fn line_col(s: &Span, src: &str) -> (usize, usize) {
        debug_assert!(
            s.start <= src.len(),
            "line_col: span start {} exceeds source length {}",
            s.start,
            src.len()
        );
        let mut line = 1usize;
        let mut col = 1usize;
        for b in src.bytes().take(s.start) {
            if b == b'\n' {
                line += 1;
                col = 1;
            } else {
                col += 1;
            }
        }
        (line, col)
    }

    /// Backfill each diagnostic's 1-based `column` from its byte `span`
    /// against `source`, using [`line_col`].
    ///
    /// Diagnostics with an unanchored `0..0` span (file-layout fatals with no
    /// source byte range) are left untouched.
    ///
    /// Lint passes and the parser historically hardcoded `column = 1`; this
    /// makes the `column` field agree with the byte span the human renderer
    /// already uses for its caret position, so JSON / plain / snapshot columns
    /// match the ariadne caret.
    ///
    /// A `debug_assert` fires if the span-derived line disagrees with the
    /// diagnostic's stored line (which would indicate a span/line inconsistency
    /// introduced at the emit site). The assert is silent in release builds.
    pub fn fill_columns(diags: &mut [crate::diagnostic::Diagnostic], source: &str) {
        for d in diags.iter_mut() {
            if d.span.start == 0 && d.span.end == 0 {
                continue;
            }
            let (span_line, col) = line_col(&d.span, source);
            debug_assert_eq!(
                d.line, span_line,
                "fill_columns: line_col line {span_line} disagrees with diagnostic line {} for {}",
                d.line, d.code
            );
            d.column = col;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn span_constructor_returns_range() {
        let s = span(5, 10);
        assert_eq!(s.start, 5);
        assert_eq!(s.end, 10);
    }

    #[test]
    fn span_util_len_returns_byte_length() {
        assert_eq!(span_util::len(&span(5, 10)), 5);
        assert_eq!(span_util::len(&span(0, 0)), 0);
    }

    #[test]
    fn span_util_contains_is_half_open() {
        assert!(span_util::contains(&span(5, 10), 5));
        assert!(!span_util::contains(&span(5, 10), 4));
        assert!(!span_util::contains(&span(5, 10), 10));
        assert!(span_util::contains(&span(5, 10), 9));
    }

    #[test]
    fn span_util_line_col_at_start_of_file() {
        assert_eq!(span_util::line_col(&span(0, 0), "abc\ndef"), (1, 1));
    }

    #[test]
    fn span_util_line_col_after_one_newline() {
        assert_eq!(span_util::line_col(&span(4, 4), "abc\ndef"), (2, 1));
    }

    #[test]
    fn span_util_line_col_mid_line() {
        assert_eq!(span_util::line_col(&span(6, 6), "abc\ndef"), (2, 3));
    }

    #[test]
    fn span_util_line_col_mid_first_line() {
        // byte 2 is `c` in "abc\ndef" - line 1, column 3. Kills mutations
        // that disable the `col += 1` increment for non-newline bytes.
        assert_eq!(span_util::line_col(&span(2, 2), "abc\ndef"), (1, 3));
    }

    #[test]
    fn span_util_line_col_consecutive_newlines() {
        // Source "\n\na" - byte 2 (the `a`) sits on line 3 at column 1.
        // Kills mutations that change `col = 1` reset to `col = 0`.
        assert_eq!(span_util::line_col(&span(2, 2), "\n\na"), (3, 1));
    }

    // fill_columns tests

    #[test]
    fn fill_columns_backfills_column_from_span() {
        use crate::diagnostic::{Diagnostic, Severity};
        // Source "abc\ndefgh\n": byte 7 is `g` on line 2 at column 4.
        // A diagnostic with span=7..8 and hardcoded column=1 should get column=4.
        let src = "abc\ndefgh\n";
        let mut d = Diagnostic::new(
            Severity::Warning,
            "test-W01",
            7..8, // byte `g` on line 2, col 4
            "test message",
            "test.rules",
            2,
            1, // hardcoded placeholder
        );
        span_util::fill_columns(std::slice::from_mut(&mut d), src);
        assert_eq!(
            d.column, 4,
            "column should be 4 (byte 7 is 'd'+'e'+'f'+'g' = col 4)"
        );
    }

    #[test]
    fn fill_columns_skips_zero_zero_span() {
        use crate::diagnostic::{Diagnostic, Severity};
        // A file-layout fatal with 0..0 span should be left untouched.
        let mut d = Diagnostic::new(
            Severity::Fatal,
            "test-F02",
            0..0,
            "unanchored fatal",
            "test.rules",
            0,
            0,
        );
        span_util::fill_columns(std::slice::from_mut(&mut d), "anything");
        assert_eq!(d.column, 0, "0..0 span must not be modified");
    }

    #[test]
    fn fill_columns_column_one_preserved_for_line_start_span() {
        use crate::diagnostic::{Diagnostic, Severity};
        // A span starting at the beginning of its line gives column 1.
        let src = "first line\nsecond line\n";
        let mut d = Diagnostic::new(
            Severity::Warning,
            "test-W01",
            11..22, // byte 11 = start of "second line"
            "second line diagnostic",
            "t.rules",
            2,
            99, // wrong placeholder value; backfill must set to 1
        );
        span_util::fill_columns(std::slice::from_mut(&mut d), src);
        assert_eq!(d.column, 1, "start-of-line span gives column 1");
    }

    // -----------------------------------------------------------------
    // Layer-2 property tests for `fill_columns` and `byte_span_to_char_span`
    // (the span utility functions).
    //
    // Properties:
    // 1. For any in-bounds non-zero span in an ASCII source, after fill_columns
    //    the diagnostic's column agrees with line_col(span, source).1.
    // 2. A 0..0 span leaves column untouched (fill_columns skips it).
    // 3. `line_col` returns (1, 1) for span starting at byte 0.
    // 4. For any source with N lines, line_col returns line in 1..=N.
    //
    // Generators use ASCII-only sources to avoid mid-codepoint span issues.
    // -----------------------------------------------------------------

    mod proptest_span_util {
        use super::super::span_util;
        use crate::diagnostic::{Diagnostic, Severity};
        use proptest::prelude::*;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(512))]

            // Property 1: for any in-bounds non-zero span in an ASCII source,
            // fill_columns sets column == line_col(span, source).1.
            // `offset_idx` is used as a modulo index into the source bytes to pick
            // a valid byte offset without floating-point arithmetic.
            #[test]
            fn fill_columns_agrees_with_line_col(
                lines in proptest::collection::vec("[a-zA-Z0-9 ]{1,20}", 1..=4usize),
                offset_idx in 1usize..200,
            ) {
                let src = lines.join("\n") + "\n";
                // Map index into the source range [1, src.len()].
                let offset = (offset_idx % src.len()).max(1);
                // Derive line number by counting newlines before offset.
                let line_num = src.bytes().take(offset).filter(|&b| b == b'\n').count() + 1;
                let mut d = Diagnostic::new(
                    Severity::Warning,
                    "test-W01",
                    offset..offset, // zero-length but non-zero-start span
                    "msg",
                    "t.rules",
                    line_num,
                    99, // placeholder column to be replaced
                );
                span_util::fill_columns(std::slice::from_mut(&mut d), &src);
                let expected_col = span_util::line_col(&(offset..offset), &src).1;
                prop_assert_eq!(d.column, expected_col,
                    "fill_columns column mismatch: got {} expected {} at offset {} in {:?}",
                    d.column, expected_col, offset, src);
            }

            // Property 2: a 0..0 span is left untouched - column is unchanged.
            #[test]
            fn fill_columns_skips_zero_zero_span_prop(
                initial_col in 0usize..1000,
                src in "[a-zA-Z0-9 ]{1,30}",
            ) {
                let mut d = Diagnostic::new(
                    Severity::Fatal,
                    "test-F01",
                    0..0,
                    "unanchored",
                    "t.rules",
                    0,
                    initial_col,
                );
                span_util::fill_columns(std::slice::from_mut(&mut d), &src);
                prop_assert_eq!(d.column, initial_col,
                    "0..0 span must leave column unchanged: got {} expected {}",
                    d.column, initial_col);
            }

            // Property 3: line_col at byte 0 returns (1, 1) for any non-empty source.
            #[test]
            fn line_col_at_zero_is_line_1_col_1(src in "[a-zA-Z0-9 \n]{1,50}") {
                let (line, col) = span_util::line_col(&(0..0), &src);
                prop_assert_eq!(line, 1, "byte 0 must be on line 1");
                prop_assert_eq!(col, 1, "byte 0 must be column 1");
            }

            // Property 4: line_col.1 (column) is always >= 1 for any in-bounds offset.
            // Uses offset_idx (integer) to pick an offset without floating-point.
            #[test]
            fn line_col_column_always_positive(
                lines in proptest::collection::vec("[a-zA-Z0-9]{1,15}", 1..=3usize),
                offset_idx in 0usize..200,
            ) {
                let src = lines.join("\n") + "\n";
                let offset = offset_idx % (src.len() + 1);
                let (_, col) = span_util::line_col(&(offset..offset), &src);
                prop_assert!(col >= 1, "column must always be >= 1, got {}", col);
            }
        }
    }
}
