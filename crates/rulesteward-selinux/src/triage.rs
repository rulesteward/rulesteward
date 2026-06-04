//! `SELinux` denial triage logic.
//!
//! Renderer signatures are frozen here; bodies are filled by pipeline P3 (issue #99).
//! The CLI command module (`commands/selinux.rs`) is frozen and calls these stubs.

use crate::denial::DenialGroup;
use serde::Serialize;

/// Machine-readable triage report (the JSON payload, wrapped by the CLI in the
/// #62 envelope). Pipeline P3 (#99) fills the fields and `build_report`.
///
/// `DenialGroup` already derives `Serialize`, so this struct is valid as an
/// envelope payload even in the stub state. P3 will reshape fields as needed.
#[derive(Debug, Serialize)]
pub struct TriageReport {
    /// Placeholder field so the empty stub is a valid serializable struct.
    /// P3 replaces this with the full per-group explanation + suggestions
    /// (per spec f4 6.2).
    pub groups: Vec<DenialGroup>,
}

/// Build the machine-readable triage report from grouped denials.
///
/// Pipeline P3 (#99) fills the body with per-group explanation + narrow
/// suggested allow + caveats.
#[must_use]
pub fn build_report(groups: &[DenialGroup]) -> TriageReport {
    let _ = groups;
    todo!("P3 #99 fills the triage JSON report builder")
}

/// Render the human-readable triage explanation and narrow suggested allow.
///
/// Pipeline P3 (#99) fills the body.
#[must_use]
pub fn render_human(groups: &[DenialGroup]) -> String {
    let _ = groups;
    todo!("P3 #99 fills the human triage renderer")
}
