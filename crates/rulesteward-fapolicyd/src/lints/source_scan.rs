//! Source-driven lint passes - re-scan the raw `&str` source to emit W03
//! (inline trailing `# comment`). The parser strips inline `#` text before
//! handing the line to chumsky; we re-detect it here so the warning surface
//! is owned by the lint module, not the parser.

use std::path::Path;

use rulesteward_core::{Diagnostic, Severity};

use crate::parser::inline;

/// W03 - inline trailing `# comment` past the first non-whitespace token.
/// fapolicyd silently fails to parse such lines, so we warn before they hit
/// production.
pub fn w03_scan(source: &str, file: &Path) -> Vec<Diagnostic> {
    let mut diags = Vec::new();
    if source.is_empty() {
        return diags;
    }

    let mut line_byte_offset = 0usize;
    let lines: Vec<&str> = source.split('\n').collect();
    let last_idx = lines.len().saturating_sub(1);

    for (idx, raw_line) in lines.iter().enumerate() {
        // Skip the LF terminator's trailing empty chunk.
        if idx == last_idx && raw_line.is_empty() {
            break;
        }
        let lineno = idx + 1;
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        if let Some(hash_col_in_line) = inline::inline_comment_index(line) {
            // Column is 1-based; span captures `#` through end-of-line in
            // file-relative byte coords.
            let span_start = line_byte_offset + hash_col_in_line;
            let span_end = line_byte_offset + line.len();
            diags.push(
                Diagnostic::new(
                    Severity::Warning,
                    "W03",
                    span_start..span_end,
                    "inline `# comment` after a rule line - fapolicyd silently drops this rule",
                    file,
                    lineno,
                    hash_col_in_line + 1,
                )
                .with_source_id(file.display().to_string()),
            );
        }
        line_byte_offset += raw_line.len() + 1;
    }

    diags
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn p() -> PathBuf {
        PathBuf::from("/tmp/test.rules")
    }

    #[test]
    fn w03_fires_on_canonical_inline_comment() {
        let diags = w03_scan("allow uid=0 : all # bad\n", &p());
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code.as_ref(), "W03");
        assert_eq!(diags[0].severity, Severity::Warning);
        assert_eq!(diags[0].line, 1);
        assert_eq!(diags[0].source_id, Some("/tmp/test.rules".to_string()));
    }

    #[test]
    fn w03_silent_on_column_0_comment() {
        assert!(w03_scan("# this is fine\n", &p()).is_empty());
    }

    #[test]
    fn w03_silent_on_leading_whitespace_comment() {
        // Leading-ws `#` is a parse failure (F01), not W03.
        assert!(w03_scan("   # leading ws\n", &p()).is_empty());
    }

    #[test]
    fn w03_fires_once_per_line_with_inline_hash() {
        let src = "allow uid=0 : all # a\ndeny uid=1 : all # b\n";
        let diags = w03_scan(src, &p());
        assert_eq!(diags.len(), 2);
        assert_eq!(diags[0].line, 1);
        assert_eq!(diags[1].line, 2);
    }

    #[test]
    fn w03_silent_on_blank_lines() {
        assert!(w03_scan("\n\n\n", &p()).is_empty());
    }

    #[test]
    fn w03_silent_on_empty_source() {
        assert!(w03_scan("", &p()).is_empty());
    }

    #[test]
    fn w03_continues_scanning_past_leading_blank_lines() {
        // The trailing-LF-suppression branch must only fire on the LAST
        // empty chunk, not on any blank line. If the loop bailed early on a
        // mid-file blank, the W03 on the following rule line would be lost.
        let src = "\nallow uid=0 : all # bad\n";
        let diags = w03_scan(src, &p());
        assert_eq!(diags.len(), 1, "blank-then-W03 must still report W03");
        assert_eq!(diags[0].line, 2);
    }
}
