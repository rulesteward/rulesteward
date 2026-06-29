//! Tag-state-machine lint passes: sudo-W01 (NOPASSWD applies to an ALL command -
//! passwordless run-anything; #330) and sudo-W02 (a `Cmnd_Alias` transitively
//! expands to ALL while under NOPASSWD; #332).
//!
//! # Phase 0: STUBS
//! Both passes return `Vec::new()` today. They are filled by the #330 / #332
//! pipelines,
//! which walks each user-spec's [`Cmnd_Spec_List`](crate::ast::UserSpec::cmnd_specs)
//! left-to-right, applying the sudoers tag-inheritance rule (once a tag is set it
//! inherits to subsequent commands until the opposite tag overrides it; PASSWD
//! resets NOPASSWD). When NOPASSWD is in effect on a [`CmndItem::All`](crate::ast::CmndItem::All)
//! command, W01 fires; W02 additionally walks `Cmnd_Alias` expansions to ALL. The
//! AST records the EXPLICIT per-command tags (not inheritance-resolved), so the
//! state machine lives here and the pass only EMITS - it never re-parses.

use rulesteward_core::Diagnostic;

use crate::ast::SudoersFile;
use crate::lints::SudoersLintContext;

/// sudo-W01: NOPASSWD (after tag inheritance) applies to an `ALL` command. STUB in
/// Phase 0 (#330).
#[must_use]
pub fn w01(_files: &[SudoersFile], _ctx: &SudoersLintContext) -> Vec<Diagnostic> {
    Vec::new()
}

/// sudo-W02: a `Cmnd_Alias` transitively expands to `ALL` while under NOPASSWD.
/// STUB in Phase 0 (#332).
#[must_use]
pub fn w02(_files: &[SudoersFile], _ctx: &SudoersLintContext) -> Vec<Diagnostic> {
    Vec::new()
}
