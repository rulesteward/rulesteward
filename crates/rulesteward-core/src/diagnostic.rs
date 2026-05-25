//! Cross-crate diagnostic type emitted by every check and consumed by every
//! formatter (human / JSON / SARIF).
//!
//! The severity scheme is SELint-style: a single letter per tier
//! (Fatal / Error / Warning / Style / Convention / Extra → `F/E/W/S/C/X`).
//! Lint codes such as `"F01"`, `"W02"` pair the letter with a 2-digit number.

use core::ops::Range;
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
/// for the compile-time string constants (`"F01"`) while deserialize from
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
        span: Range<usize>,
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
            "W02",
            12..47,
            "broad allow on execute",
            "/etc/fapolicyd/rules.d/90-allow.rules",
            7,
            1,
        );
        assert_eq!(d.severity, Severity::Warning);
        assert_eq!(d.code, "W02");
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
            "E01",
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
            "W02",
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
            "W02",
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
}
