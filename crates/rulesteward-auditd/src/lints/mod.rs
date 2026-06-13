//! Semantic lint passes over the concatenated `rules.d/` rule stream (#193).
//!
//! Code split (one file per semantic family, mirroring the fapolicyd crate):
//! * `duplicate` - au-W01 normalized-equal duplicate rules (pipeline P1).
//! * `ordering` - au-W02 shadow/subsumption, au-E01 post-`-e 2` unreachable,
//!   au-W03 exclude/never suppression conflict, au-W04 mid-stream `-D`
//!   (pipeline P2).
//! * `operator_validity` - au-E02 operator invalid for field type (pipeline P3).
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

pub mod catalog;
pub mod duplicate;
pub mod field_type;
pub mod normalize;
pub mod operator_validity;
pub mod ordering;
pub mod value;

use rulesteward_core::{Diagnostic, Severity, Span};

use crate::ast::LocatedRule;

/// Build a byte-anchored `Diagnostic` with the auditd emission convention:
/// column 1 and the source-id set to the file path's display string.
///
/// auditd rule spans cover the whole raw line (see
/// [`crate::parser::parse_rules_str_located`]), so the line-start anchor is
/// exact and no span-derived column backfill is needed (the fapolicyd
/// `fill_columns` pass has no auditd analogue by design). `pub` because the
/// pass modules emit through it and the CLI render layer may anchor too.
#[must_use]
pub fn anchored(
    sev: Severity,
    code: &'static str,
    span: Span,
    msg: impl Into<String>,
    file: impl Into<std::path::PathBuf>,
    line: usize,
) -> Diagnostic {
    let file = file.into();
    let source_id = file.display().to_string();
    Diagnostic::new(sev, code, span, msg, file, line, 1).with_source_id(source_id)
}

/// Map a located parse error to an `au-F01` Fatal diagnostic.
///
/// Lives here (not in the CLI) because this crate OWNS the `au-` codes and is
/// inside the mutation `examine_globs`. Parse errors carry file + line but no
/// byte span (the failing line never became a rule), so the diagnostic is
/// unanchored: empty span, no source-id, plain rendering. `line == 0` marks a
/// file-level error (unreadable file / missing path) and keeps column 0; a
/// line-level error gets column 1.
#[must_use]
pub fn parse_error_to_diagnostic(err: &crate::parser::LocatedParseError) -> Diagnostic {
    let column = usize::from(err.line != 0);
    Diagnostic::new(
        Severity::Fatal,
        "au-F01",
        0..0,
        err.message.clone(),
        err.file.clone(),
        err.line,
        column,
    )
}

/// Run every semantic lint pass over the concatenated rule stream and return
/// the merged diagnostic list.
///
/// `rules` is the full `rules.d/` stream in `augenrules(8)` load order (the
/// output of [`crate::parser::parse_target_located`]). Pass ordering is
/// load-bearing for byte-stable output and MUST be preserved: duplicates
/// (P1), then ordering/shadowing (P2), then operator validity (P3).
#[must_use]
pub fn lint(rules: &[LocatedRule]) -> Vec<Diagnostic> {
    let mut diags = duplicate::w01(rules);
    diags.extend(ordering::w02(rules));
    diags.extend(ordering::e01(rules));
    diags.extend(ordering::w03(rules));
    diags.extend(operator_validity::e02(rules));
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
        let err = crate::parser::LocatedParseError {
            file: "/etc/audit/rules.d/99-bad.rules".into(),
            line: 7,
            message: "unknown flag '-Z'".to_string(),
        };
        let d = super::parse_error_to_diagnostic(&err);
        assert_eq!(d.severity, Severity::Fatal);
        assert_eq!(d.code, "au-F01");
        assert_eq!(d.message, "unknown flag '-Z'");
        assert_eq!(d.file, err.file);
        assert_eq!(d.line, 7);
        assert_eq!(d.column, 1, "line-level parse errors anchor at column 1");
        assert_eq!(d.span, 0..0, "parse errors carry no byte span");
        assert!(d.source_id.is_none(), "unanchored: plain rendering");
    }

    #[test]
    fn file_level_parse_error_keeps_line_and_column_zero() {
        let err = crate::parser::LocatedParseError {
            file: "/nonexistent".into(),
            line: 0,
            message: "path does not exist: /nonexistent".to_string(),
        };
        let d = super::parse_error_to_diagnostic(&err);
        assert_eq!((d.line, d.column), (0, 0), "file-level errors stay 0/0");
        assert_eq!(d.code, "au-F01");
    }
}
