//! STIG-baseline lints: required-directive presence and value-vs-baseline
//! comparison. Both consume the DISA STIG required-directive baseline tables
//! (per `--target`) produced by the Wave-B grounding task, so these pipelines are
//! gated on that research landing.
//!
//! Phase 0: every pass is a `Vec::new()` stub with a frozen signature. The
//! tracking issues are children of epic #149.

use std::path::Path;

use rulesteward_core::Diagnostic;

use crate::ast::Block;
use crate::lints::SshdLintContext;

/// sshd-W01: a STIG-required directive is missing from the configuration.
///
/// TODO(#149, Wave B): emit one finding per missing required directive for
/// `ctx.target`; gated on the STIG required-directive baseline tables.
#[must_use]
pub fn w01(_blocks: &[Block], _file: &Path, _ctx: &SshdLintContext) -> Vec<Diagnostic> {
    Vec::new()
}

/// sshd-W02: a directive's value is weaker than the STIG baseline (e.g.
/// `MaxAuthTries 10` against a `<= 6` baseline).
///
/// TODO(#149, Wave B): gated on the per-target numeric baseline tables.
#[must_use]
pub fn w02(_blocks: &[Block], _file: &Path, _ctx: &SshdLintContext) -> Vec<Diagnostic> {
    Vec::new()
}
