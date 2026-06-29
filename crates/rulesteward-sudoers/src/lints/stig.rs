//! sudo STIG-baseline Defaults lint pass (#333): sudo-W04 (a `Defaults` setting
//! weaker than the DISA sudo STIG baseline).
//!
//! # Phase 0: STUB
//! Returns `Vec::new()` today. Filled by the #333 pipeline, which walks the
//! [`DefaultsEntry`](crate::ast::DefaultsEntry) settings and flags STIG findings
//! (e.g. `!authenticate`, `targetpw`/`rootpw`/`runaspw`, a missing `use_pty`).
//! The implementer MUST cite the exact STIG/SRG rule IDs in code comments + tests.
//! These findings are VERSION-AGNOSTIC, so there is no `--target` rail. The AST
//! already exposes each setting's negation + name + value, so the pass only EMITS.

use rulesteward_core::Diagnostic;

use crate::ast::SudoersFile;
use crate::lints::SudoersLintContext;

/// sudo-W04: a `Defaults` setting is weaker than the sudo STIG baseline. STUB in
/// Phase 0 (#333).
#[must_use]
pub fn w04(_files: &[SudoersFile], _ctx: &SudoersLintContext) -> Vec<Diagnostic> {
    Vec::new()
}
