//! Deprecation lint: directives deprecated or removed in the target OpenSSH
//! version (`Protocol`, `RhostsRSAAuthentication`, `RSAAuthentication`,
//! `UseLogin`, ...). Consumes the per-OpenSSH-version deprecated-keyword table
//! from the Wave-B grounding task.
//!
//! Phase 0: the pass is a `Vec::new()` stub with a frozen signature. The tracking
//! issue is a child of epic #149.

use std::path::Path;

use rulesteward_core::Diagnostic;

use crate::ast::Block;
use crate::lints::SshdLintContext;

/// sshd-W04: a directive deprecated or removed in the target OpenSSH version.
///
/// TODO(#149, Wave B): gated on the per-version deprecated/removed keyword table.
#[must_use]
pub fn w04(_blocks: &[Block], _file: &Path, _ctx: &SshdLintContext) -> Vec<Diagnostic> {
    Vec::new()
}
