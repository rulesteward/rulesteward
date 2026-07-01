//! Cross-crate diagnostic type emitted by every check and consumed by every
//! formatter (human / JSON / SARIF).
//!
//! The severity scheme is SELint-style: a single letter per tier
//! (Fatal / Error / Warning / Style / Convention / Extra → `F/E/W/S/C/X`).
//! Lint codes such as `"fapd-F01"`, `"fapd-W02"` pair a per-module prefix
//! (currently `fapd-` for fapolicyd) with the letter + 2-digit-number key.

use std::borrow::Cow;
use std::path::PathBuf;

use crate::span::Span;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Severity tier for a diagnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum Severity {
    Fatal,
    Error,
    Warning,
    Style,
    Convention,
    Extra,
}

impl Severity {
    /// Returns the single-letter tier abbreviation used in lint codes.
    #[must_use]
    pub const fn letter(self) -> char {
        match self {
            Severity::Fatal => 'F',
            Severity::Error => 'E',
            Severity::Warning => 'W',
            Severity::Style => 'S',
            Severity::Convention => 'C',
            Severity::Extra => 'X',
        }
    }
}

/// A single lint finding: where, what tier, what code, and operator-facing text.
///
/// `span` is a byte range into the original source, matching
/// `chumsky::Rich::span()` exactly so renderers can lift it straight into
/// `ariadne` reports.
///
/// `code` is `Cow<'static, str>` so emitter call-sites pay zero allocation
/// for the compile-time string constants (`"fapd-F01"`) while deserialize from
/// JSON/SARIF still works.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Diagnostic {
    pub severity: Severity,
    pub code: Cow<'static, str>,
    pub message: String,
    pub file: PathBuf,
    pub line: usize,
    pub column: usize,
    /// Byte range into the source file pointed at by `source_id`. See
    /// [`crate::span`] for the type-alias rationale and the path to a
    /// future newtype migration.
    pub span: Span,
    /// Stable identifier for the source the diagnostic references. Used by
    /// ariadne to key its `Source` cache. `None` for diagnostics that are
    /// not anchored to a specific source byte range (e.g., file-layout
    /// fatals).
    pub source_id: Option<String>,
}

impl Diagnostic {
    #[must_use]
    pub fn new(
        severity: Severity,
        code: impl Into<Cow<'static, str>>,
        span: Span,
        message: impl Into<String>,
        file: impl Into<PathBuf>,
        line: usize,
        column: usize,
    ) -> Self {
        Self {
            severity,
            code: code.into(),
            span,
            message: message.into(),
            file: file.into(),
            line,
            column,
            source_id: None,
        }
    }

    /// Set the source identifier for this diagnostic.
    ///
    /// This is a builder method that sets the `source_id` field and returns
    /// the modified `Diagnostic`. Used by ariadne to key its `Source` cache.
    #[must_use]
    pub fn with_source_id(mut self, id: impl Into<String>) -> Self {
        self.source_id = Some(id.into());
        self
    }
}

/// Build a byte-anchored [`Diagnostic`] at an explicit 1-based `column`, with the
/// source-id set to the file path's display string.
///
/// The shared emission helper for the per-backend lint passes: every anchored
/// lint site builds `Diagnostic::new(..).with_source_id(file.display())`. The
/// auditd / sshd backends only ever anchor at column 1 (see [`anchored`]); the
/// fapolicyd backend uses this explicit-column form for sub-rule-token carets
/// (fapd-E01, fapd-W03, fapd-F01).
#[must_use]
pub fn anchored_at(
    severity: Severity,
    code: impl Into<Cow<'static, str>>,
    span: Span,
    message: impl Into<String>,
    file: impl Into<PathBuf>,
    line: usize,
    column: usize,
) -> Diagnostic {
    let file = file.into();
    let source_id = file.display().to_string();
    Diagnostic::new(severity, code, span, message, file, line, column).with_source_id(source_id)
}

/// Build a byte-anchored [`Diagnostic`] at column 1, with the source-id set to
/// the file path's display string.
///
/// Thin wrapper over [`anchored_at`] with `column = 1`. Used by the bulk of the
/// anchored lint sites whose caret sits at the start of the line.
#[must_use]
pub fn anchored(
    severity: Severity,
    code: impl Into<Cow<'static, str>>,
    span: Span,
    message: impl Into<String>,
    file: impl Into<PathBuf>,
    line: usize,
) -> Diagnostic {
    anchored_at(severity, code, span, message, file, line, 1)
}

/// Build a `Fatal` parse-error [`Diagnostic`] with the shared per-backend F01
/// emission convention.
///
/// A line-level parse error (`line != 0`) is [`anchored`] at the failing line's
/// byte `span`, column 1, with the source-id set so ariadne can render a
/// snippet. A file-level error (`line == 0`, e.g. an unreadable file or missing
/// path) has no source byte range, so it stays unanchored (span `0..0`,
/// column 0, no source-id) and renders plainly.
///
/// Each backend's `parse_error_to_diagnostic` (which owns its `code` string and
/// destructures its own located-parse-error type) delegates here so the
/// anchored-vs-unanchored F01 rendering lives in one place (issue #289 family).
#[must_use]
pub fn parse_error_diagnostic(
    code: impl Into<Cow<'static, str>>,
    file: impl Into<PathBuf>,
    line: usize,
    span: Span,
    message: impl Into<String>,
) -> Diagnostic {
    if line == 0 {
        Diagnostic::new(Severity::Fatal, code, 0..0, message, file, 0, 0)
    } else {
        anchored(Severity::Fatal, code, span, message, file, line)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_letter_covers_every_tier() {
        assert_eq!(Severity::Fatal.letter(), 'F');
        assert_eq!(Severity::Error.letter(), 'E');
        assert_eq!(Severity::Warning.letter(), 'W');
        assert_eq!(Severity::Style.letter(), 'S');
        assert_eq!(Severity::Convention.letter(), 'C');
        assert_eq!(Severity::Extra.letter(), 'X');
    }

    #[test]
    fn diagnostic_new_assigns_every_field() {
        let d = Diagnostic::new(
            Severity::Warning,
            "fapd-W02",
            12..47,
            "broad allow on execute",
            "/etc/fapolicyd/rules.d/90-allow.rules",
            7,
            1,
        );
        assert_eq!(d.severity, Severity::Warning);
        assert_eq!(d.code, "fapd-W02");
        assert_eq!(d.span, 12..47);
        assert_eq!(d.message, "broad allow on execute");
        assert_eq!(d.line, 7);
        assert_eq!(d.column, 1);
        assert_eq!(
            d.file.to_str(),
            Some("/etc/fapolicyd/rules.d/90-allow.rules")
        );
        assert_eq!(d.source_id, None);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn diagnostic_serde_round_trip_is_lossless() {
        let original = Diagnostic::new(
            Severity::Error,
            "fapd-E01",
            5..10,
            "unknown attribute",
            "/tmp/sample.rules",
            3,
            12,
        )
        .with_source_id("/tmp/sample.rules");
        let json = serde_json::to_string(&original).expect("serialize");
        let parsed: Diagnostic = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.source_id, original.source_id);
        assert_eq!(parsed, original);
    }

    #[test]
    fn diagnostic_default_has_no_source_id() {
        let d = Diagnostic::new(
            Severity::Warning,
            "fapd-W02",
            0..5,
            "some message",
            "/etc/fapolicyd/rules.d/test.rules",
            1,
            1,
        );
        assert_eq!(d.source_id, None);
    }

    #[test]
    fn diagnostic_with_source_id_sets_field() {
        let d = Diagnostic::new(
            Severity::Warning,
            "fapd-W02",
            0..5,
            "some message",
            "/etc/fapolicyd/rules.d/test.rules",
            1,
            1,
        )
        .with_source_id("/etc/foo.rules");
        assert_eq!(d.source_id, Some("/etc/foo.rules".to_string()));
    }

    #[cfg(feature = "serde")]
    #[test]
    fn severity_serializes_to_named_variant() {
        let json = serde_json::to_string(&Severity::Fatal).expect("serialize");
        assert_eq!(json, "\"Fatal\"");
        let back: Severity = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, Severity::Fatal);
    }

    #[test]
    fn parse_error_diagnostic_file_level_is_unanchored() {
        // line == 0 (unreadable file / missing path): no source byte range, so
        // the diagnostic stays unanchored (span 0..0, column 0, no source_id)
        // and renders plainly. Pins the `line == 0` branch.
        let d = parse_error_diagnostic(
            "au-F01",
            "/etc/audit/rules.d/x.rules",
            0,
            0..0,
            "cannot read file",
        );
        assert_eq!(d.severity, Severity::Fatal);
        assert_eq!(d.code, "au-F01");
        assert_eq!(d.line, 0);
        assert_eq!(d.column, 0);
        assert_eq!(d.span, 0..0);
        assert_eq!(
            d.source_id, None,
            "a file-level parse error must stay unanchored"
        );
    }

    #[test]
    fn parse_error_diagnostic_line_level_is_anchored() {
        // line != 0: anchored at the failing line's byte span, column 1, with the
        // source_id set to the file path so ariadne renders a snippet. Pins the
        // `else` (anchored) branch and the column-1 / source_id contract.
        let d = parse_error_diagnostic("sshd-F01", "/etc/ssh/sshd_config", 7, 40..55, "bad token");
        assert_eq!(d.severity, Severity::Fatal);
        assert_eq!(d.code, "sshd-F01");
        assert_eq!(d.line, 7);
        assert_eq!(d.column, 1, "anchored parse errors sit at column 1");
        assert_eq!(d.span, 40..55);
        assert_eq!(
            d.source_id,
            Some("/etc/ssh/sshd_config".to_string()),
            "a line-level parse error is anchored to its source"
        );
    }
}
