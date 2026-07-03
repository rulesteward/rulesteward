//! Inline-comment detection. Used both by the parser (to strip the inline
//! `# ...` tail before chumsky runs) and by [`crate::lints`] (to re-scan
//! the source for fapd-W03 emission). Keeping the scanner in one place means
//! parser-strip and lint-emit can never drift.

// Cross-reference (#383): inline-`#` stripping exists in FOUR backends, each
// tuned to its own grammar and deliberately NOT unified (importing one grammar's
// quoting rule into another would be wrong for that file format). Peers:
//   - fapolicyd inline_comment_index (parser/inline.rs): `#` after any
//     non-whitespace token; no quote awareness.
//   - auditd    strip_comment        (parser.rs): first `#` outside a SINGLE-
//     quoted span (single quotes protect `-F 'auid>=1000'`).
//   - sudoers   strip_inline_comment (parser.rs): DOUBLE-quote aware, plus a
//     `#include` bypass and a `#<digits>` UID/GID-token exception.
//   - sshd      algo_list_value      (lints/crypto.rs): token-level; the first
//     `#`-prefixed arg ends an already-whitespace-split algorithm list.
// sysctld has NONE: sysctl.d(5) defines only whole-line `#`/`;` comments (a `#`
// mid-value is literal). If you fix an edge case in one stripper, check the peers.

/// Byte index of an inline `#` (one that follows at least one non-whitespace
/// token earlier on the line), or `None` if no inline `#` is present.
///
/// A leading-whitespace `#` is NOT inline - there's no preceding
/// non-whitespace token. Such a line is a comment (accepted by the parser),
/// not flagged by fapd-W03.
#[must_use]
pub fn inline_comment_index(line: &str) -> Option<usize> {
    let mut seen_token = false;
    for (idx, &b) in line.as_bytes().iter().enumerate() {
        match b {
            b' ' | b'\t' => {}
            b'#' if seen_token => return Some(idx),
            _ => seen_token = true,
        }
    }
    None
}

/// Strip an inline trailing `#` comment for parse purposes.
#[must_use]
pub fn strip_inline_comment(line: &str) -> &str {
    inline_comment_index(line).map_or(line, |idx| &line[..idx])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_trailing_hash() {
        let line = "allow uid=0 : all # comment";
        let idx = inline_comment_index(line).expect("inline # detected");
        assert_eq!(&line[idx..], "# comment");
    }

    #[test]
    fn ignores_column_0_hash() {
        assert_eq!(inline_comment_index("# whole-line comment"), None);
    }

    #[test]
    fn ignores_leading_ws_hash() {
        assert_eq!(inline_comment_index("   # leading ws"), None);
        assert_eq!(inline_comment_index("\t# tab then hash"), None);
    }

    #[test]
    fn detects_hash_immediately_after_token() {
        let line = "allow uid=0 : all#nospace";
        assert_eq!(inline_comment_index(line), Some(line.find('#').unwrap()));
    }

    #[test]
    fn strip_preserves_when_no_inline_hash() {
        let line = "allow uid=0 : all";
        assert_eq!(strip_inline_comment(line), line);
    }

    #[test]
    fn strip_cuts_at_inline_hash() {
        assert_eq!(
            strip_inline_comment("allow uid=0 : all # tail"),
            "allow uid=0 : all "
        );
    }
}
