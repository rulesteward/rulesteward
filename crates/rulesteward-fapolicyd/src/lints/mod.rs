//! Post-parse lint passes.
//!
//! Code split:
//! * `walker` — AST-driven passes (F03, E01, W02).
//! * `source_scan` — raw-source re-scan for W03.
//! * `layout` — filesystem-driven F02 check.

mod layout;
mod source_scan;
mod walker;

pub use layout::check_layout;

use std::path::Path;

use rulesteward_core::Diagnostic;

use crate::ast::Entry;

/// Run every per-file lint pass and return the merged diagnostic list.
///
/// `source` is the raw rules-file text, needed for W03 (inline trailing
/// `# comment`) re-scan. `file` is the path used in every emitted
/// `Diagnostic::file`.
#[must_use]
pub fn lint(entries: &[Entry], source: &str, file: &Path) -> Vec<Diagnostic> {
    let mut diags = walker::walk(entries, file);
    diags.extend(source_scan::w03_scan(source, file));
    diags
}
