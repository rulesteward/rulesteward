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

// The `#[cfg(test)] mod tests` that pinned `inline_comment_index` /
// `strip_inline_comment` (finds_trailing_hash, ignores_column_0_hash,
// ignores_leading_ws_hash, detects_hash_immediately_after_token,
// strip_preserves_when_no_inline_hash, strip_cuts_at_inline_hash) was removed
// by lane-3 (#562): both functions are being replaced by the shared
// `rulesteward_core::comment` helper (`StripConfig::FAPOLICYD`), and every
// assertion above is reproduced byte-for-byte in
// `crates/rulesteward-core/src/comment.rs`'s `fapolicyd_table` unit tests and
// in `crates/rulesteward-fapolicyd/tests/comment_strip_equivalence.rs`. See
// the lane-3 report for the old-test -> new-table-row mapping.
