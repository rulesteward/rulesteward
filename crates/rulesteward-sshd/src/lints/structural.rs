//! Structural lints: directive identity, duplication, Include resolution, and
//! Match-block legality. These need no STIG/crypto baseline tables, so the
//! parallel pipelines for sshd-E02/E03/E04 (Wave A) can start the moment the
//! Phase-0 foundation merges. sshd-E01 (registry-gated) and sshd-W05 (which
//! reuses the W01 required-set) are grouped here as the structural family.
//!
//! Phase 0: every pass is a `Vec::new()` stub with a frozen signature. The
//! tracking issues are children of epic #149.

use std::path::Path;

use rulesteward_core::Diagnostic;

use crate::ast::Block;
use crate::lints::SshdLintContext;

/// sshd-E01: unknown directive (not a recognized keyword for the target).
///
/// TODO(#149, Wave B): requires the per-OpenSSH-version directive registry from
/// the STIG/version grounding task.
#[must_use]
pub fn e01(_blocks: &[Block], _file: &Path, _ctx: &SshdLintContext) -> Vec<Diagnostic> {
    Vec::new()
}

/// sshd-E02: duplicate global directive (sshd's first-value-wins silently shadows
/// the later line for most keywords).
///
/// TODO(#149, Wave A): pure structural; no baseline data needed.
#[must_use]
pub fn e02(_blocks: &[Block], _file: &Path, _ctx: &SshdLintContext) -> Vec<Diagnostic> {
    Vec::new()
}

/// sshd-E03: `Include` references a path or glob that resolves to nothing.
///
/// TODO(#149, Wave A): resolves the literal `Include` argument against
/// `/etc/ssh/` (or the config's directory) and checks the glob matches.
#[must_use]
pub fn e03(_blocks: &[Block], _file: &Path, _ctx: &SshdLintContext) -> Vec<Diagnostic> {
    Vec::new()
}

/// sshd-E04: a directive not permitted inside a `Match` block (silently ignored
/// by sshd at runtime).
///
/// TODO(#149, Wave A): checks each Match body against the small static set of
/// Match-permitted keywords from `sshd_config(5)`.
#[must_use]
pub fn e04(_blocks: &[Block], _file: &Path, _ctx: &SshdLintContext) -> Vec<Diagnostic> {
    Vec::new()
}

/// sshd-W05: a `Match` block overrides a required global directive in a more
/// permissive direction (a STIG escape hatch).
///
/// TODO(#149, Wave C): depends on the W01 required-directive set.
#[must_use]
pub fn w05(_blocks: &[Block], _file: &Path, _ctx: &SshdLintContext) -> Vec<Diagnostic> {
    Vec::new()
}
