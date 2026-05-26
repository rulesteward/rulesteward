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
}
