//! auditd rules file parser.
//!
//! Filled by pipeline P2 (issue #87).
//!
//! # Grounding
//! - Line-oriented format, `#` begins a comment: `man 7 audit.rules` section 2.
//! - `rules.d/` concat in filename order: `augenrules(8)` \[VM\].

use std::path::Path;

use crate::ast::AuditRule;

/// A parse error on a single line.
///
/// Carries the 1-based line number and a human-readable message.
/// Multiple errors may be returned for a single input.
#[derive(Debug, Clone, PartialEq)]
pub struct ParseError {
    pub line: usize,
    pub message: String,
}

/// Parse a single rules file from a string.
///
/// Comments (`#` and everything after), blank lines, and lines with only
/// whitespace are silently ignored. Each remaining line is one rule.
/// Returns `Ok(rules)` on full success, or `Err(errors)` if any line failed to
/// parse.
///
/// # Errors
/// Returns `Err` when one or more lines contain unknown flags or malformed syntax.
pub fn parse_rules_str(_input: &str) -> Result<Vec<AuditRule>, Vec<ParseError>> {
    todo!("P2 #87 fills parser")
}

/// Parse a single rules file from a file path.
///
/// # Errors
/// Returns `Err` with `ParseError { line: 0, message: <io error> }` when the
/// file cannot be read.
pub fn parse_rules_file(_path: &Path) -> Result<Vec<AuditRule>, Vec<ParseError>> {
    todo!("P2 #87 fills parser")
}

/// Resolve and parse a rules target.
///
/// Mirrors the fapolicyd target-resolution shape used by `lint`/`report`:
/// - If `path` is a file, parse that file.
/// - If `path` is a directory, collect all `*.rules` files in filename order
///   (matching `augenrules(8)` lexical concat), then parse them concatenated.
///
/// On any I/O error the offending file is reported as `ParseError { line: 0 }`.
///
/// # Errors
/// Returns `Err` when one or more rules contain parse errors.
pub fn parse_target(_path: &Path) -> Result<Vec<AuditRule>, Vec<ParseError>> {
    todo!("P2 #87 fills parser")
}
