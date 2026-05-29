//! Source-driven lint passes - re-scan the raw `&str` source to emit fapd-W03
//! (inline trailing `# comment`). The parser strips inline `#` text before
//! handing the line to chumsky; we re-detect it here so the warning surface
//! is owned by the lint module, not the parser.

use std::path::Path;

use rulesteward_core::{Diagnostic, Severity};

use crate::parser::inline;

/// fapd-W03 - inline trailing `# comment` past the first non-whitespace token.
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
        // Skip comment lines: first non-whitespace character is `#`.
        // Such lines are pure comments (fapolicyd accepts them), so
        // a second `#` inside the comment text is not an inline comment.
        if line.trim_start_matches([' ', '\t']).starts_with('#') {
            line_byte_offset += raw_line.len() + 1;
            continue;
        }
        if let Some(hash_col_in_line) = inline::inline_comment_index(line) {
            // Column is 1-based; span captures `#` through end-of-line in
            // file-relative byte coords.
            let span_start = line_byte_offset + hash_col_in_line;
            let span_end = line_byte_offset + line.len();
            diags.push(
                Diagnostic::new(
                    Severity::Warning,
                    "fapd-W03",
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
        assert_eq!(diags[0].code.as_ref(), "fapd-W03");
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
        // Leading-ws `#` is a comment (accepted by the parser), not fapd-W03.
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
        // mid-file blank, the fapd-W03 on the following rule line would be lost.
        let src = "\nallow uid=0 : all # bad\n";
        let diags = w03_scan(src, &p());
        assert_eq!(
            diags.len(),
            1,
            "blank-then-fapd-W03 must still report fapd-W03"
        );
        assert_eq!(diags[0].line, 2);
    }

    #[test]
    fn w03_not_emitted_on_comment_line_with_second_hash() {
        // A comment line whose text contains a second `#` must NOT fire W03.
        // The second `#` is part of the comment text, not an inline comment.
        let src = "allow perm=open all : path=/etc/hosts\n   # note about # hashes\n";
        let diags = w03_scan(src, &p());
        assert!(
            diags.iter().all(|d| d.code.as_ref() != "fapd-W03"),
            "comment line must not fire fapd-W03, got {diags:?}"
        );
    }

    #[test]
    fn w03_column0_comment_with_hash_no_w03() {
        // A column-0 comment line referencing a rule number must not fire W03.
        let src = "# header referencing rule #5\nallow perm=open all : path=/x\n";
        let diags = w03_scan(src, &p());
        assert!(
            diags.iter().all(|d| d.code.as_ref() != "fapd-W03"),
            "column-0 comment with second # must not fire fapd-W03, got {diags:?}"
        );
    }

    #[test]
    fn w03_still_fires_on_real_inline_comment_after_rule() {
        // Regression guard: a genuine rule with a trailing comment STILL warns.
        let src = "allow perm=open all : all # trailing\n";
        let diags = w03_scan(src, &p());
        assert!(
            diags.iter().any(|d| d.code.as_ref() == "fapd-W03"),
            "real inline comment after rule must still fire fapd-W03, got {diags:?}"
        );
    }

    // --- column field tests (kill hash_col_in_line +/- 1 mutants) ---

    #[test]
    fn w03_column_is_one_based_for_inline_hash() {
        // "allow uid=0 : all # bad\n" - '#' is at char/byte offset 18 (0-indexed).
        // column must be 18 + 1 = 19 (1-based).
        //
        // Kills mutants that replace `hash_col_in_line + 1` with:
        //   * `hash_col_in_line - 1` -> column 17 (wrong, off by two)
        //   * `hash_col_in_line * 1` -> column 18 (wrong, 0-based not 1-based)
        let src = "allow uid=0 : all # bad\n";
        let hash_pos = src.find('#').expect("hash present");
        let expected_col = hash_pos + 1; // 1-based
        let diags = w03_scan(src, &p());
        assert_eq!(diags.len(), 1);
        assert_eq!(
            diags[0].column, expected_col,
            "column must be 1-based (hash at byte {} -> column {}), got {}",
            hash_pos, expected_col, diags[0].column,
        );
    }

    // --- span offset tests (kill line-offset accumulation mutants) ---

    #[test]
    fn w03_span_start_correct_on_single_line() {
        // "allow uid=0 : all # bad\n"
        // The '#' is at byte index 18 (0-indexed). span_start must be 18.
        // Kills mutations to the `line_byte_offset += raw_line.len() + 1` on line 52
        // that would change the accumulated offset for single-line sources.
        let src = "allow uid=0 : all # bad\n";
        let hash_pos = src.find('#').expect("hash present");
        let diags = w03_scan(src, &p());
        assert_eq!(diags.len(), 1);
        assert_eq!(
            diags[0].span.start, hash_pos,
            "span.start must equal byte position of '#' ({}), got {}",
            hash_pos, diags[0].span.start,
        );
    }

    #[test]
    fn w03_span_start_correct_after_comment_line() {
        // A comment line followed by a rule with an inline comment.
        // The comment line is "# header comment\n" (18 bytes incl LF).
        // The rule line "allow uid=0 : all # bad\n" follows at byte 18.
        // The '#' is at offset 18 + 18 = 36 within the file.
        //
        // Kills the `line_byte_offset += raw_line.len() + 1` mutation on line 36
        // (the `continue` branch for comment lines). If that `+= ... + 1` were
        // replaced by `*=` or `+= ... - 1`, the offset for the second line would
        // be wrong, and span.start would differ from the expected file offset.
        let header = "# header comment\n"; // 18 bytes
        let rule = "allow uid=0 : all # bad\n";
        let src = format!("{header}{rule}");
        let expected_hash_pos = header.len() + rule.find('#').expect("hash present");
        let diags = w03_scan(&src, &p());
        assert_eq!(
            diags.len(), 1,
            "one W03 diagnostic expected, got: {diags:?}"
        );
        assert_eq!(
            diags[0].span.start, expected_hash_pos,
            "span.start must equal file-relative '#' position ({}), got {}",
            expected_hash_pos, diags[0].span.start,
        );
    }

    #[test]
    fn w03_span_end_correct_is_end_of_line() {
        // span_end = line_byte_offset + line.len() (not including LF).
        // "allow uid=0 : all # bad\n" has line.len() = 23 (no LF), so
        // span_end should be 23 (from byte 18 to 23 = the " bad" suffix).
        let src = "allow uid=0 : all # bad\n";
        let line_len = src.trim_end_matches('\n').len(); // 23
        let diags = w03_scan(src, &p());
        assert_eq!(diags.len(), 1);
        assert_eq!(
            diags[0].span.end, line_len,
            "span.end must equal line length {}, got {}",
            line_len, diags[0].span.end,
        );
    }

    #[test]
    fn w03_span_start_correct_after_rule_line() {
        // A clean rule line followed by a rule with an inline comment.
        // The first line "allow uid=0 : all\n" is 18 bytes (17 chars + LF).
        // The second line "allow uid=1 : exe=/x # bad\n" starts at byte 18.
        // The '#' in the second line is at relative offset 20, so file offset 38.
        //
        // Kills the `line_byte_offset += raw_line.len() + 1` mutation on line 57
        // (the end-of-loop increment for NON-comment lines). If that `+ 1` were
        // replaced by `* 1` (giving `raw_line.len()`) or `- 1`, the offset for
        // the second line would be off by one, and span.start would differ from
        // the expected file-relative '#' position.
        let line1 = "allow uid=0 : all\n"; // 18 bytes
        let line2 = "allow uid=1 : exe=/x # bad\n";
        let src = format!("{line1}{line2}");
        let expected_hash_pos = line1.len() + line2.find('#').expect("hash present");
        let diags = w03_scan(&src, &p());
        assert_eq!(diags.len(), 1, "expected 1 W03, got: {diags:?}");
        assert_eq!(
            diags[0].span.start, expected_hash_pos,
            "span.start for line-2 W03 must be file-relative offset {} (line1_len + line2_hash), got {}",
            expected_hash_pos, diags[0].span.start,
        );
    }
}
