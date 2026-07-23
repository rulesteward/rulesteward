//! Machine-readable catalog of the `sudoers(5)` (`sudo-`) lint codes: each code's
//! id, severity tier, and a short operator-facing description.
//!
//! Mirrors the auditd / sshd / sysctld catalogs (the crate that OWNS the codes
//! carries the catalog, inside the mutation `examine_globs`): no `Condition`
//! machinery here. `sudoers lint --format sarif` is offered (#511) and is
//! findings-only, so it needs no per-check run-condition gate; the
//! `--sarif-include-pass` coverage attestation that the `Condition` machinery
//! backs stays fapolicyd-only (locked CC-4).
//!
//! # Frozen in Phase 0
//! The catalog lists the FULL planned sudoers taxonomy now, even though only
//! `sudo-F01` (parse failure) is emitted today. Freezing the whole list here in
//! Phase 0 means the later lint pipelines (#330-#333) start emitting a code that
//! is ALREADY catalogued - they never edit this shared file, which keeps the
//! milestone fan-out conflict-free. The remaining codes land per the epic plan.

use rulesteward_core::Severity;

/// One catalogued `sudo-` lint code: its stable id, severity tier, and a short
/// operator-facing description. Aliased from the shared `rulesteward-core`
/// [`BaseLintCode`](rulesteward_core::BaseLintCode); the catalog-integrity
/// invariants live there too (issue #289).
pub use rulesteward_core::BaseLintCode as LintCode;

/// The catalog of every `sudo-` lint code, authored in sorted-by-code order for
/// deterministic, byte-stable output. Pinned against the frozen taxonomy by
/// `catalog_is_the_frozen_taxonomy`.
///
/// Severities follow the SELint-style letter scheme (`F`/`E`/`W`). The emitting
/// pass for each not-yet-implemented code is named in the per-family `lints/`
/// modules (#330/#332 tags, #331 aliases, #333 stig).
pub const SUDO_CODES: &[LintCode] = &[
    LintCode {
        code: "sudo-E01",
        severity: Severity::Error,
        description: "reference to an undefined alias",
    },
    LintCode {
        code: "sudo-F01",
        severity: Severity::Fatal,
        description: "sudoers file does not parse",
    },
    LintCode {
        code: "sudo-F02",
        severity: Severity::Fatal,
        description: "contains a token that visudo rejects (per-position invalid token)",
    },
    LintCode {
        code: "sudo-W01",
        severity: Severity::Warning,
        description: "NOPASSWD applies to an ALL command (passwordless run-anything)",
    },
    LintCode {
        code: "sudo-W02",
        severity: Severity::Warning,
        description: "a Cmnd_Alias transitively expands to ALL under NOPASSWD",
    },
    LintCode {
        code: "sudo-W03",
        severity: Severity::Warning,
        description: "alias defined but never referenced (dead alias)",
    },
    LintCode {
        code: "sudo-W04",
        severity: Severity::Warning,
        description: "Defaults setting weaker than, or required hardening absent from, the sudo security baseline",
    },
    LintCode {
        code: "sudo-W05",
        severity: Severity::Warning,
        description: "NOPASSWD grants passwordless sudo on a specific (non-ALL) command; STIG requires removing NOPASSWD entirely",
    },
    LintCode {
        code: "sudo-W06",
        severity: Severity::Warning,
        description: "a UserSpec grants the literal ALL user unrestricted sudo access to run ALL commands as ALL users/groups",
    },
];

#[cfg(test)]
mod tests {
    use super::SUDO_CODES;

    /// The frozen sudoers taxonomy (Phase 0). Every code the backend will ever
    /// emit is listed here in sorted order; the lint pipelines start emitting an
    /// already-catalogued code rather than editing this shared file. Update this
    /// list ONLY when the taxonomy itself changes.
    const FROZEN_CODES: &[&str] = &[
        "sudo-E01", "sudo-F01", "sudo-F02", "sudo-W01", "sudo-W02", "sudo-W03", "sudo-W04",
        "sudo-W05", "sudo-W06",
    ];

    #[test]
    fn catalog_is_the_frozen_taxonomy() {
        let catalog: Vec<&str> = SUDO_CODES.iter().map(|c| c.code).collect();
        assert_eq!(
            catalog, FROZEN_CODES,
            "SUDO_CODES must list exactly the frozen sudo- taxonomy, sorted"
        );
    }

    /// The sorted-by-code / no-duplicate / letter-matches-severity /
    /// descriptions-non-empty invariants are shared across every backend catalog
    /// and live in `rulesteward-core` (issue #289).
    #[test]
    fn catalog_satisfies_shared_invariants() {
        rulesteward_core::lint_code::assert_catalog_invariants(SUDO_CODES);
    }

    #[test]
    fn parse_failure_code_is_catalogued() {
        // Phase 0 emits exactly one code, sudo-F01 (parse failure). It MUST be in
        // the catalog (the emitted-subset-of-catalogued direction the milestone
        // relies on). The fan-out adds emitters for the rest, each already here.
        assert!(
            SUDO_CODES.iter().any(|c| c.code == "sudo-F01"),
            "the one Phase-0-emitted code must be catalogued"
        );
    }
}
