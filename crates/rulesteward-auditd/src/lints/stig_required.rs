//! au-W06: the ruleset is missing audit rules required by the applicable RHEL
//! STIG (issue #474). Version-aware: fires only under an explicit `--target`
//! (the portable default stays silent), mirroring the sysctld-W02 STIG
//! baseline pattern (#341).
//!
//! Phase-0 stub (session 7c): the entrypoint signature and the
//! [`TargetVersion`] enum are frozen here so the fan-out pipeline fills only
//! this file's body. The pinned per-RHEL-major required-rules tables are
//! derived from the DISA XCCDF benchmarks (RHEL 8 V2R4 / RHEL 9 V2R7 /
//! RHEL 10 V1R1) by `tools/auditd-stig-update`; matching is KEY-SENSITIVE
//! with a distinct present-but-key-differs message (locked decisions,
//! 2026-07-10).

use rulesteward_core::Diagnostic;

use super::LintOptions;
use crate::ast::LocatedRule;

/// RHEL release whose STIG audit-rule baseline to check against. Clap-free
/// (the CLI maps its `--target` value-enum into this via a `From` impl);
/// mirrors `rulesteward_sysctld::TargetVersion` so each domain crate stays
/// clap-free.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetVersion {
    Rhel8,
    Rhel9,
    Rhel10,
}

/// au-W06 missing-required-STIG-rules pass. Phase-0 stub, filled by pipeline
/// P2 (#474): returns no diagnostics, so dispatcher output is byte-identical
/// until the pass lands. `target == None` (portable mode) stays silent by
/// contract even in the real implementation.
#[must_use]
pub fn w06(
    _rules: &[LocatedRule],
    _opts: LintOptions,
    _target: Option<TargetVersion>,
) -> Vec<Diagnostic> {
    Vec::new()
}
