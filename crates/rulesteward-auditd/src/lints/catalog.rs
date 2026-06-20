//! Machine-readable catalog of the auditd (`au-`) lint codes: each code's id,
//! severity tier, and a short operator-facing description.
//!
//! Mirrors the fapolicyd catalog (the crate that OWNS the codes carries the
//! catalog, inside the mutation `examine_globs`), minus the `Condition`
//! machinery: every auditd pass runs unconditionally, and there is no SARIF
//! for auditd (locked CC-4: SARIF is `fapolicyd lint` only).

use rulesteward_core::Severity;

/// One catalogued `au-` lint code: its stable id, severity tier, and a short
/// operator-facing description. Aliased from the shared `rulesteward-core`
/// [`BaseLintCode`](rulesteward_core::BaseLintCode); the catalog-integrity
/// invariants live there too (issue #289).
pub use rulesteward_core::BaseLintCode as LintCode;

/// The catalog of every `au-` lint code, authored in sorted-by-code order for
/// deterministic, byte-stable output. Pinned against the authoritative emitted
/// set by `catalog_covers_exactly_the_authoritative_code_set`.
pub const AU_CODES: &[LintCode] = &[
    LintCode {
        code: "au-E01",
        severity: Severity::Error,
        description: "unreachable rule: it appears after the -e 2 lock line and will never load",
    },
    LintCode {
        code: "au-E02",
        severity: Severity::Error,
        description: "comparison operator is not valid for this field's type; auditctl rejects the rule at load time",
    },
    LintCode {
        code: "au-E03",
        severity: Severity::Error,
        description: "load-aborting duplicate: a structurally identical earlier rule makes auditctl -R abort, so every later rule silently fails to load",
    },
    LintCode {
        code: "au-E04",
        severity: Severity::Error,
        description: "field used on an illegal filter list: auditctl aborts the rule load because the kernel rejects this field on the specified list",
    },
    LintCode {
        code: "au-F01",
        severity: Severity::Fatal,
        description: "rules file does not parse",
    },
    LintCode {
        code: "au-W01",
        severity: Severity::Warning,
        description: "duplicate rule: normalized-equal to an earlier rule in the rules.d/ load order",
    },
    LintCode {
        code: "au-W02",
        severity: Severity::Warning,
        description: "shadowed rule: an earlier, broader rule on the same filter list subsumes it, so it never fires",
    },
    LintCode {
        code: "au-W03",
        severity: Severity::Warning,
        description: "suppression conflict: an exclude/never rule suppresses events an always rule intends to record",
    },
    LintCode {
        code: "au-W04",
        severity: Severity::Warning,
        description: "missing-ABI coverage: a syscall rule pins one ABI (arch=b32/b64) with no companion rule on the opposite ABI, so the other ABI's invocations of those syscalls go unaudited",
    },
];

#[cfg(test)]
mod tests {
    use super::AU_CODES;

    /// The authoritative emitted set. au-W04, originally the cut `-D` stretch
    /// lint (decision D6), was revived for issue #261 as the missing-ABI
    /// coverage warning, so the code number is now live again.
    const ALL_CODES: &[&str] = &[
        "au-E01", "au-E02", "au-E03", "au-E04", "au-F01", "au-W01", "au-W02", "au-W03", "au-W04",
    ];

    #[test]
    fn catalog_covers_exactly_the_authoritative_code_set() {
        let catalog: Vec<&str> = AU_CODES.iter().map(|c| c.code).collect();
        assert_eq!(
            catalog, ALL_CODES,
            "catalog must list exactly the authoritative au- codes, sorted"
        );
    }

    /// The sorted-by-code / no-duplicate / letter-matches-severity /
    /// descriptions-non-empty invariants are shared across every backend
    /// catalog and live in `rulesteward-core` (issue #289).
    #[test]
    fn catalog_satisfies_shared_invariants() {
        rulesteward_core::lint_code::assert_catalog_invariants(AU_CODES);
    }
}
