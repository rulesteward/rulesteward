//! Cross-crate diagnostic type emitted by every check and consumed by every
//! formatter (human / JSON / SARIF).
//!
//! The severity scheme is SELint-style: a single letter per tier
//! (Fatal / Error / Warning / Style / Convention / Extra → `F/E/W/S/C/X`).
//! Lint codes such as `"F01"`, `"W02"` pair the letter with a 2-digit number.

use core::ops::Range;
use std::borrow::Cow;
use std::path::PathBuf;

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
    pub span: Range<usize>,
    pub message: String,
    pub file: PathBuf,
    pub line: usize,
    pub column: usize,
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
        }
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
        );
        let json = serde_json::to_string(&original).expect("serialize");
        let parsed: Diagnostic = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, original);
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
