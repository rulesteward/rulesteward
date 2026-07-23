//! Machine-readable catalog of the `selinux` (`se-`) boot-configuration lint
//! codes: each code's id, severity tier, and a short operator-facing
//! description.
//!
//! Mirrors the sysctld catalog (the crate that OWNS the codes carries the
//! catalog, inside the mutation `examine_globs`): no `Condition` machinery
//! here. `selinux lint --format sarif` is offered (#511) and is
//! findings-only, so it needs no per-check run-condition gate; the
//! `--sarif-include-pass` coverage attestation that the `Condition` machinery
//! backs stays fapolicyd-only (locked CC-4).
//!
//! # Frozen taxonomy
//! Two passes: `se-W01` (SELINUX= not enforcing at boot; rhel9/rhel10 only)
//! and `se-W02` (SELINUXTYPE= not targeted; rhel8 only), both implemented in
//! [`super::boot`]. The catalog is frozen up front so the pass emits only an
//! already-catalogued code and never edits this shared file.

use rulesteward_core::Severity;

/// One catalogued `se-` lint code: its stable id, severity tier, and a short
/// operator-facing description. Aliased from the shared `rulesteward-core`
/// [`BaseLintCode`](rulesteward_core::BaseLintCode); the catalog-integrity
/// invariants live there too (issue #289).
pub use rulesteward_core::BaseLintCode as LintCode;

/// The catalog of every `se-` lint code, authored in sorted-by-code order for
/// deterministic, byte-stable output. Pinned against the frozen taxonomy by
/// `catalog_is_the_frozen_taxonomy`.
pub const SE_CODES: &[LintCode] = &[
    LintCode {
        code: "se-W01",
        severity: Severity::Warning,
        description: "SELinux is not configured to be enforcing at boot (SELINUX= in /etc/selinux/config; requires --target rhel9|rhel10)",
    },
    LintCode {
        code: "se-W02",
        severity: Severity::Warning,
        description: "SELinux is not configured to use the targeted policy (SELINUXTYPE= in /etc/selinux/config; requires --target rhel8)",
    },
];

#[cfg(test)]
mod tests {
    use super::SE_CODES;

    /// The frozen v1 selinux-lint taxonomy (Phase 0 of lane 2b). Every code
    /// the backend will emit is listed here in sorted order; the lint pass
    /// starts emitting an already-catalogued code rather than editing this
    /// shared file.
    const FROZEN_CODES: &[&str] = &["se-W01", "se-W02"];

    #[test]
    fn catalog_is_the_frozen_taxonomy() {
        let catalog: Vec<&str> = SE_CODES.iter().map(|c| c.code).collect();
        assert_eq!(
            catalog, FROZEN_CODES,
            "SE_CODES must list exactly the frozen se- taxonomy, sorted"
        );
    }

    /// The sorted-by-code / no-duplicate / letter-matches-severity /
    /// descriptions-non-empty invariants are shared across every backend
    /// catalog and live in `rulesteward-core` (issue #289).
    #[test]
    fn catalog_satisfies_shared_invariants() {
        rulesteward_core::lint_code::assert_catalog_invariants(SE_CODES);
    }
}
