//! `SELinux` Type Enforcement (.te) rule emitter.
//!
//! Emitter signature is frozen here; body is filled by pipeline P4 (issue #103).
//! The CLI command module (`commands/selinux.rs`) is frozen and calls this stub.

use crate::denial::DenialGroup;

/// Emit a self-contained base-module `.te` for the denial groups.
///
/// `module_name` defaults (naming heuristics, fallback) are P4's concern.
/// Pipeline P4 (#103) fills the body.
#[must_use]
pub fn emit_te(groups: &[DenialGroup], module_name: Option<&str>) -> String {
    let _ = (groups, module_name);
    todo!("P4 #103 fills the base-module .te emitter")
}
