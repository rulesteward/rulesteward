//! Alias-reference lint passes (#331): sudo-E01 (reference to an undefined alias)
//! and sudo-W03 (alias defined but never referenced - a dead alias).
//!
//! # Phase 0: STUBS
//! Both passes return `Vec::new()` today. They are filled by the #331 pipeline,
//! which walks the alias DEFINITIONS ([`crate::ast::AliasDef`]) and the alias
//! REFERENCES (uppercase tokens in user-spec subject / host / run-as / command
//! position) to build the defined-vs-referenced sets. The rich AST already exposes
//! everything needed, so the pass only EMITS - it never re-parses.

use rulesteward_core::Diagnostic;

use crate::ast::SudoersFile;
use crate::lints::SudoersLintContext;

/// sudo-E01: a user-spec (or another alias) references an alias name that is never
/// defined. STUB in Phase 0 (#331).
#[must_use]
pub fn e01(_files: &[SudoersFile], _ctx: &SudoersLintContext) -> Vec<Diagnostic> {
    Vec::new()
}

/// sudo-W03: an alias is defined but never referenced anywhere (dead alias). STUB
/// in Phase 0 (#331).
#[must_use]
pub fn w03(_files: &[SudoersFile], _ctx: &SudoersLintContext) -> Vec<Diagnostic> {
    Vec::new()
}
