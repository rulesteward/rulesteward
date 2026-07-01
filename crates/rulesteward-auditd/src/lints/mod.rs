//! Semantic lint passes over the concatenated `rules.d/` rule stream (#193).
//!
//! Code split (one file per semantic family, mirroring the fapolicyd crate):
//! * `duplicate` - au-W01 normalized-equal duplicate rules (pipeline P1).
//! * `ordering` - au-W02 shadow/subsumption, au-E01 post-`-e 2` unreachable,
//!   au-W03 exclude/never suppression conflict (pipeline P2).
//! * `operator_validity` - au-E02 operator invalid for field type (pipeline P3).
//! * `arch_coverage` - au-W04 a syscall rule pins one ABI (`arch=b32`/`b64`)
//!   with no companion on the opposite ABI, so its syscalls go unaudited on the
//!   other ABI (#261).
//! * `normalize` - the shared rule canonicalization both P1 and P2 consume
//!   (Phase-0 frozen; see [`normalize::canonical_key`]).
//! * `field_type` - the per-field type table au-E02 consumes (taxonomy frozen
//!   in Phase 0; the 46-arm match body is pipeline P3's, with per-arm
//!   citations to audit-userspace commit 3bfa048).
//! * `catalog` - machine-readable `au-` code catalog.
//!
//! Unlike fapolicyd's per-file `lint()`, the auditd dispatcher takes the WHOLE
//! concatenated stream (`&[LocatedRule]`): duplicate, shadowing, and ordering
//! are inherently cross-file properties under `augenrules(8)` lexical concat.
//!
//! Pass modules are `pub` so each pipeline's barrier tests call their OWN
//! entrypoint directly without tripping sibling `todo!()` stubs through the
//! dispatcher (the stubs are filled by the fan-out pipelines; the dispatcher
//! path is exercised by the integration-gate e2e tests).

pub mod arch_coverage;
pub mod catalog;
pub mod duplicate;
pub mod field_filter;
pub mod field_type;
pub mod normalize;
pub mod operator_validity;
pub mod ordering;
pub mod value;

use rulesteward_core::Diagnostic;

use crate::ast::LocatedRule;
pub use value::LintOptions;

/// Build a byte-anchored `Diagnostic` with the auditd emission convention:
/// column 1 and the source-id set to the file path's display string.
///
/// auditd rule spans cover the whole raw line (see
/// [`crate::parser::parse_rules_str_located`]), so the line-start anchor is
/// exact and no span-derived column backfill is needed (the fapolicyd
/// `fill_columns` pass has no auditd analogue by design). Re-exported from the
/// shared `rulesteward-core` helper (issue #289); the pass modules emit through
/// it via `super::anchored` / `crate::lints::anchored`.
pub use rulesteward_core::anchored;

/// Map a located parse error to an `au-F01` Fatal diagnostic.
///
/// Lives here (not in the CLI) because this crate OWNS the `au-` codes and is
/// inside the mutation `examine_globs`. Line-level parse errors (line != 0) are
/// anchored via `anchored(...)`: the `span` field carries the byte range of the
/// failing raw line (populated by the running-offset loop in the parser), and the
/// source-id is set so ariadne can render a snippet. File-level errors (line == 0,
/// e.g. unreadable file / missing path) stay unanchored (span 0..0, no source-id)
/// because no source byte range exists.
#[must_use]
pub fn parse_error_to_diagnostic(err: &crate::parser::LocatedParseError) -> Diagnostic {
    rulesteward_core::parse_error_diagnostic(
        "au-F01",
        err.file.clone(),
        err.line,
        err.span.clone(),
        err.message.clone(),
    )
}

/// Run every semantic lint pass over the concatenated rule stream and return
/// the merged diagnostic list.
///
/// `rules` is the full `rules.d/` stream in `augenrules(8)` load order (the
/// output of [`crate::parser::parse_target_located`]). Pass ordering is
/// load-bearing for byte-stable output and MUST be preserved: duplicates
/// (P1), then ordering/shadowing (P2), then operator validity (P3), then
/// ABI coverage (au-W04), appended last so existing output is unchanged.
///
/// `opts` controls opt-in folding behaviour (e.g. `include_apparmor`).
/// `LintOptions::default()` restores the pre-#230 behaviour exactly.
#[must_use]
pub fn lint(rules: &[LocatedRule], opts: LintOptions) -> Vec<Diagnostic> {
    let mut diags = duplicate::w01(rules, opts);
    diags.extend(ordering::w02(rules, opts));
    diags.extend(ordering::e01(rules));
    diags.extend(ordering::w03(rules, opts));
    diags.extend(operator_validity::e02(rules));
    diags.extend(arch_coverage::w04(rules));
    diags.extend(field_filter::e04(rules));
    diags
}

#[cfg(test)]
mod tests {
    use rulesteward_core::{Diagnostic, Severity};

    // --- helper parity anchors (GREEN immediately; behavior-preservation pins
    // mirroring the fapolicyd CLEAN-2 convention). If a refactor changes the
    // helpers' output shape relative to the hand-written form, these fail fast.

    #[test]
    fn anchored_equals_handwritten_diagnostic() {
        let file = std::path::Path::new("/etc/audit/rules.d/10-x.rules");
        let span = 3..9;
        let got = super::anchored(Severity::Warning, "au-W01", span.clone(), "dup", file, 7);
        let want = Diagnostic::new(Severity::Warning, "au-W01", span, "dup", file, 7, 1)
            .with_source_id(file.display().to_string());
        assert_eq!(got, want);
    }

    #[test]
    fn parse_error_maps_to_au_f01_fatal() {
        // Line 2 of "-D\n-Z bogus\n": "-D\n" = 3 bytes, so "-Z bogus" starts at
        // offset 3 and its raw line length is 8. The span must be 3..11.
        let err = crate::parser::LocatedParseError {
            file: "/etc/audit/rules.d/99-bad.rules".into(),
            line: 2,
            message: "unknown flag '-Z'".to_string(),
            span: 3..11,
        };
        let d = super::parse_error_to_diagnostic(&err);
        assert_eq!(d.severity, Severity::Fatal);
        assert_eq!(d.code, "au-F01");
        assert_eq!(d.message, "unknown flag '-Z'");
        assert_eq!(d.file, err.file);
        assert_eq!(d.line, 2);
        assert_eq!(d.column, 1, "line-level parse errors anchor at column 1");
        assert_eq!(
            d.span,
            3..11,
            "parse errors carry the real byte range of the failing line"
        );
        assert!(d.source_id.is_some(), "anchored: ariadne source-id is set");
        assert_eq!(
            d.source_id.as_deref(),
            Some("/etc/audit/rules.d/99-bad.rules"),
            "source-id is the file path display string"
        );
    }

    #[test]
    fn parse_error_span_matches_failing_line_byte_range() {
        // "-D\n-Z bogus\n": the bad line "-Z bogus" starts at byte 3 (after "-D\n")
        // and is 8 bytes long, so span = 3..11.
        let input = "-D\n-Z bogus\n";
        let file = std::path::Path::new("/etc/audit/rules.d/99-bad.rules");
        let errs = crate::parser::parse_rules_str_located(input, file).expect_err("-Z must fail");
        assert_eq!(errs.len(), 1, "exactly one error");
        assert_eq!(
            errs[0].span,
            3..11,
            "span must cover the raw '-Z bogus' line: starts at byte 3, length 8"
        );
        assert_eq!(
            &input[errs[0].span.clone()],
            "-Z bogus",
            "span must slice to the failing raw line"
        );
    }

    #[test]
    fn parse_error_span_is_byte_offsets_not_char_offsets() {
        // The failing line "-Z naive" (with a 2-byte UTF-8 char in place of the
        // i) makes BYTE length != CHAR count, so this test distinguishes the
        // correct `raw_line.len()` (bytes) span computation from a plausible
        // `raw_line.chars().count()` (chars) regression. With "-D\n" = 3 bytes,
        // the failing line starts at byte 3; the byte-correct span end is 3 + 9.
        let input = "-D\n-Z na\u{ef}ve\n"; // line 2 == "-Z naïve" (ï is 2 bytes)
        let failing_line = "-Z na\u{ef}ve";
        let file = std::path::Path::new("/etc/audit/rules.d/99-bad.rules");
        let errs = crate::parser::parse_rules_str_located(input, file)
            .expect_err("-Z must fail on the multibyte line");
        assert_eq!(errs.len(), 1, "exactly one error");
        assert_eq!(
            errs[0].span,
            3..12,
            "span must be BYTE offsets: failing line starts at byte 3, byte length 9"
        );
        assert_eq!(
            &input[errs[0].span.clone()],
            failing_line,
            "span must slice to the exact failing line text"
        );
        let span_len = errs[0].span.end - errs[0].span.start;
        assert_eq!(
            span_len,
            failing_line.len(),
            "span length must equal the failing line's BYTE length"
        );
        assert!(
            span_len > failing_line.chars().count(),
            "byte length ({span_len}) must exceed char count ({}); a chars()-based span \
             would be off by one here",
            failing_line.chars().count()
        );
    }

    #[test]
    fn file_level_parse_error_keeps_line_and_column_zero() {
        // File-level errors (line == 0, e.g. unreadable file) stay unanchored:
        // no meaningful byte range exists, so span stays 0..0 and source_id is None.
        let err = crate::parser::LocatedParseError {
            file: "/nonexistent".into(),
            line: 0,
            message: "path does not exist: /nonexistent".to_string(),
            span: 0..0,
        };
        let d = super::parse_error_to_diagnostic(&err);
        assert_eq!((d.line, d.column), (0, 0), "file-level errors stay 0/0");
        assert_eq!(d.code, "au-F01");
        assert_eq!(d.span, 0..0, "file-level errors carry no byte span");
        assert!(d.source_id.is_none(), "file-level errors are unanchored");
    }
}
