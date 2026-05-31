//! Version-aware lint pass: fapolicyd checks whose verdict diverges by target
//! release (fapd-W07 hash-keyword advice, `device=` subject-side validity,
//! `pattern=` value set, hash-value length).
//!
//! Phase-0 stub: the version-target impl pipeline fills the per-check logic. The
//! signature is frozen here so the fan-out edits only this file's body, not the
//! shared `lints/mod.rs` dispatcher.

use std::path::Path;

use rulesteward_core::Diagnostic;

use crate::ast::Entry;
use crate::version::TargetVersion;

/// Run the version-divergent checks for `target`. Returns no diagnostics when
/// `target` is `None` (the implicit 1.4.x dialect, i.e. no `--target`) so a
/// default lint reproduces today's behavior exactly.
#[must_use]
pub(crate) fn walk(
    _entries: &[Entry],
    _file: &Path,
    _target: Option<TargetVersion>,
) -> Vec<Diagnostic> {
    Vec::new()
}
