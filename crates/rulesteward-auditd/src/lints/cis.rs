//! Per-product CIS Benchmark control table for the auditd backend (issue #528),
//! milestone 9f-v0_8-wave3-cis. Mirrors the `stig_required.rs`
//! [`BaselineRule`](super::stig_required::BaselineRule) /
//! [`stig_baseline`](super::stig_required::stig_baseline) shape: one row per
//! `ComplianceAsCode` audit rule, carrying the CIS control id and the one-line
//! `CaC` title, keyed per RHEL major via [`cis_baseline`].
//!
//! Ground truth: `tools/cis-update derive`'s output at the `CaC` pin
//! `519b5fe8` (see `tools/cis-update/cis-refs.toml`). Upstream
//! `ComplianceAsCode`/content is BSD-3-Clause; only CIS control ids and `CaC`
//! rule titles ever cross into this repo -- never CIS benchmark prose (license
//! discipline, #524/#510).
//!
//! # RED scaffolding (test-author barrier)
//! The three per-product tables are intentionally left EMPTY for the
//! implementer to populate verbatim from `cis-update derive`, exactly as the
//! STIG `RHEL*_REQUIRED` tables were seeded empty at their barrier (see
//! `stig_required.rs`'s module doc). The frozen scenario tests in
//! `tests/test_lints_cis.rs` assert grounded per-product membership, counts,
//! and cross-product divergence against these tables, so they fail (RED) until
//! the tables are filled.

use super::TargetVersion;

/// One CIS-mapped audit rule row: the `ComplianceAsCode` rule name (the stable
/// join key back to a `CaC` audit rule / an au-W06 requirement), its CIS
/// Benchmark control id (e.g. `"6.3.2.1"`), and the one-line `CaC` title shown
/// as a [`ControlRef`](rulesteward_core::ControlRef) `name`.
///
/// Mirrors [`super::stig_required::BaselineRule`]: `Copy`, all fields
/// `&'static str`. The control id is PRODUCT-SPECIFIC -- the same `cac_rule`
/// can carry a different `control_id` on a different RHEL major (e.g.
/// `audit_rules_immutable` is `6.3.3.21` on rhel8, `6.3.3.20` on rhel9,
/// `6.3.3.36` on rhel10), so callers MUST read the row from the target's own
/// table via [`cis_baseline`] and never assume an id is stable across products.
#[derive(Debug, Clone, Copy)]
pub struct CisControl {
    /// CIS Benchmark control id for this rule under the row's product (e.g.
    /// `"6.3.2.1"`).
    pub control_id: &'static str,
    /// `ComplianceAsCode` rule name (e.g.
    /// `"auditd_data_retention_max_log_file"`); the join key back to a `CaC`
    /// audit rule / au-W06 requirement.
    pub cac_rule: &'static str,
    /// The one-line `CaC` recommendation title (e.g. `"Ensure audit log storage
    /// size is configured (Automated)"`). `CaC` titles only; never benchmark
    /// prose.
    pub title: &'static str,
}

/// The grounded per-RHEL-major CIS control tables: one [`CisControl`] literal
/// per derived rule mapping, transcribed verbatim from `cis-update derive`'s
/// output and kept drift-tethered to `ComplianceAsCode` by that tool's `check`
/// gate (do not hand-edit; re-derive on a `CaC` pin bump).
///
/// EMPTY at the test-author barrier -- the implementer fills them.
const RHEL8_CIS: &[CisControl] = &[];
const RHEL9_CIS: &[CisControl] = &[];
const RHEL10_CIS: &[CisControl] = &[];

/// The CIS control table for `target`. Mirrors
/// [`super::stig_required::stig_baseline`]: a pure per-product accessor over
/// the shipped grounded tables. The products DIVERGE (rhel10 is materially
/// larger and renumbers many controls), so the returned slice is
/// product-correct membership, not a shared superset.
#[must_use]
pub fn cis_baseline(target: TargetVersion) -> &'static [CisControl] {
    match target {
        TargetVersion::Rhel8 => RHEL8_CIS,
        TargetVersion::Rhel9 => RHEL9_CIS,
        TargetVersion::Rhel10 => RHEL10_CIS,
    }
}
