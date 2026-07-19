//! Machine-readable catalog of the `sysctl.d`/`sysctl.conf` (`sysctld-`) lint
//! codes: each code's id, severity tier, and a short operator-facing description.
//!
//! Mirrors the auditd / sshd catalogs (the crate that OWNS the codes carries the
//! catalog, inside the mutation `examine_globs`): no `Condition` machinery, since
//! there is no SARIF for sysctld (locked CC-4: SARIF is `fapolicyd lint` only).
//!
//! # Frozen taxonomy
//! The catalog lists the FULL `sysctld-` taxonomy in sorted order. Four passes
//! are implemented - `sysctld-F01` (parse failure), `sysctld-W01` (last-wins
//! conflict), the version-aware `sysctld-W02` (STIG hardening baseline,
//! issue #335), and `sysctld-W03` (cross-directory precedence surprise, issue
//! #420, emitted by the `--system` scan [`crate::system::lint_system`]) - plus
//! the version-aware `sysctld-W04` (CIS-Benchmark hardening baseline, issue
//! #527), catalogued ahead of its Wave-3 CIS emit pass. The catalog was frozen
//! up front so the passes emit only already-catalogued codes and never edit this
//! shared file.

use rulesteward_core::Severity;

/// One catalogued `sysctld-` lint code: its stable id, severity tier, and a short
/// operator-facing description. Aliased from the shared `rulesteward-core`
/// [`BaseLintCode`](rulesteward_core::BaseLintCode); the catalog-integrity
/// invariants live there too (issue #289).
pub use rulesteward_core::BaseLintCode as LintCode;

/// The catalog of every `sysctld-` lint code, authored in sorted-by-code order
/// for deterministic, byte-stable output. Pinned against the frozen taxonomy by
/// `catalog_is_the_frozen_taxonomy`.
pub const SYSCTLD_CODES: &[LintCode] = &[
    LintCode {
        code: "sysctld-F01",
        severity: Severity::Fatal,
        description: "sysctl.d/sysctl.conf file does not parse",
    },
    LintCode {
        code: "sysctld-W01",
        severity: Severity::Warning,
        description: "last-wins conflict: the same key is assigned different effective values across the drop-in precedence order",
    },
    LintCode {
        code: "sysctld-W02",
        severity: Severity::Warning,
        description: "STIG-required kernel-hardening key is unset or set to an insecure value (version-aware; requires --target)",
    },
    LintCode {
        code: "sysctld-W03",
        severity: Severity::Warning,
        description: "cross-directory precedence surprise: a key's effective winner sits in a lower-precedence search directory, a same-basename drop-in silently masks another that drops a key, or the procps/systemd appliers disagree (requires --system)",
    },
    LintCode {
        code: "sysctld-W04",
        severity: Severity::Warning,
        description: "CIS-Benchmark-required kernel-hardening key is unset or set to a value outside the benchmark-accepted set (version-aware; requires --target)",
    },
];

#[cfg(test)]
mod tests {
    use super::SYSCTLD_CODES;

    /// The frozen v1 sysctld taxonomy (Phase 0). Every code the backend will emit
    /// in v1 is listed here in sorted order; the lint pipelines start emitting an
    /// already-catalogued code rather than editing this shared file. Update this
    /// list ONLY when the taxonomy itself changes.
    const FROZEN_CODES: &[&str] = &[
        "sysctld-F01",
        "sysctld-W01",
        "sysctld-W02",
        "sysctld-W03",
        "sysctld-W04",
    ];

    #[test]
    fn catalog_is_the_frozen_taxonomy() {
        let catalog: Vec<&str> = SYSCTLD_CODES.iter().map(|c| c.code).collect();
        assert_eq!(
            catalog, FROZEN_CODES,
            "SYSCTLD_CODES must list exactly the frozen sysctld- taxonomy, sorted"
        );
    }

    /// The sorted-by-code / no-duplicate / letter-matches-severity /
    /// descriptions-non-empty invariants are shared across every backend catalog
    /// and live in `rulesteward-core` (issue #289).
    #[test]
    fn catalog_satisfies_shared_invariants() {
        rulesteward_core::lint_code::assert_catalog_invariants(SYSCTLD_CODES);
    }
}
