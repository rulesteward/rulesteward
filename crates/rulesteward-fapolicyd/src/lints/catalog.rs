//! Machine-readable catalog of the fapolicyd (`fapd-`) lint codes: each code's
//! id, severity tier, a short human description, and the run-condition that
//! gates whether the check actually evaluates for a given CLI invocation.
//!
//! Why this exists (issue #137): SARIF `--sarif-include-pass` emits a
//! `kind:"pass"` result for every check that RAN and was CLEAN. "Ran" is not
//! the same as "exists": several checks only evaluate under a flag or mode
//! (`--target`, `--check-identities`, `--against-trustdb` / `--report-orphans`,
//! single-file vs directory). A naive "all codes minus the ones that fired"
//! would falsely attest a check that never ran. [`evaluated`] is the single
//! source of truth for "which checks ran", keyed off the same inputs the lint
//! runner branches on.
//!
//! The catalog lives in this crate (not the CLI) on purpose: it is the crate
//! that OWNS the `fapd-` codes, and - unlike the CLI render layer, which is
//! excluded from `cargo mutants` - this crate is inside the mutation
//! `examine_globs`, so the gate logic in [`evaluated`] is mutation-covered.

use rulesteward_core::Severity;

use crate::version::TargetVersion;

/// When a `fapd-` check actually evaluates during a run. Used to decide whether
/// a clean check earns a SARIF `kind:"pass"` coverage attestation (issue #137).
///
/// Each variant corresponds to a real gate in the lint runner; see the
/// `condition_holds` match for the one-to-one mapping to [`EvalInputs`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Condition {
    /// Runs on every invocation (the default per-file pass list, or the parser
    /// for the `fapd-F0x` fatals). Always evaluated.
    Always,
    /// Runs only with an attached trust DB (`--against-trustdb`).
    RequiresTrustdb,
    /// Runs only with `--check-identities` (the opt-in `getent` check).
    RequiresIdentities,
    /// Runs only with `--report-orphans` AND an attached trust DB.
    RequiresOrphans,
    /// Runs only with an explicit `--target` (a fully version-gated check).
    RequiresTarget,
    /// Runs only against a fapolicyd >= 1.6 target. DORMANT BY CONSTRUCTION:
    /// [`TargetVersion`] is RHEL-keyed and its newest variant maps to fapolicyd
    /// 1.4.5 (`version.rs::fapolicyd_version`: Rhel8 -> 1.3.2, Rhel9/Rhel10 ->
    /// 1.4.5), so nothing reaches 1.6 and this condition holds for NO input.
    ///
    /// This variant exists precisely so a dormant check cannot be attested as
    /// having run: `RequiresTarget` would hold under every `--target` and make
    /// [`evaluated`] emit a SARIF `kind:"pass"` for a check whose gate returned
    /// early without looking (a false coverage attestation, issue #137). When a
    /// real 1.6-capable target variant lands, this arm in `condition_holds` is
    /// the ONE honest place to flip.
    RequiresFapolicyd16Plus,
    /// Runs on every target EXCEPT `--target rhel8`, where it is disabled.
    SuppressedUnderRhel8,
    /// Runs only in single-file (`--file`) mode.
    SingleFileOnly,
    /// Runs only in directory mode (the cross-file passes).
    DirectoryOnly,
}

/// One catalogued `fapd-` lint code: its stable id, severity tier, a short
/// human description (used for SARIF `tool.driver.rules[].shortDescription`),
/// and the run-condition that gates whether it evaluates.
#[derive(Debug, Clone, Copy)]
pub struct LintCode {
    /// The stable lint id, e.g. `"fapd-W05"`.
    pub code: &'static str,
    /// Severity tier; its letter (F/E/W/S/C/X) matches the code's letter.
    pub severity: Severity,
    /// One-line operator-facing description of what the check looks for.
    pub description: &'static str,
    /// When this check actually evaluates during a run.
    pub condition: Condition,
}

/// The run inputs that determine which checks evaluated. Mirrors the values the
/// CLI lint runner already branches on: [`crate::LintContext`] plus the two
/// CLI-only gates (`report_orphans` and `single_file`).
///
/// `Default` is "directory mode, no flags" (`single_file = false`,
/// `target = None`, all bools `false`), matching `LintContext::default()`.
// Each bool mirrors one independent CLI gate; 4 of them is the natural shape,
// so suppress the >3-bools lint rather than contrive an enum (KISS).
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy, Default)]
pub struct EvalInputs {
    /// A trust DB is attached (`--against-trustdb`).
    pub trustdb: bool,
    /// `--check-identities` is set (enables the opt-in fapd-W05 getent check).
    pub check_identities: bool,
    /// `--report-orphans` is set (fapd-X01, which also needs `trustdb`).
    pub report_orphans: bool,
    /// Selected RHEL target (`--target`); `None` is the implicit 1.4.x dialect.
    pub target: Option<TargetVersion>,
    /// True in single-file `--file` mode; false in directory mode.
    pub single_file: bool,
}

/// The catalog entries whose checks actually evaluated for `inputs`, in
/// `FAPD_CODES` order (deterministic, for byte-stable SARIF output). Callers
/// get the full [`LintCode`] (not just the id) so they can populate SARIF
/// `tool.driver.rules[]` metadata and emit pass results.
#[must_use]
pub fn evaluated(inputs: EvalInputs) -> Vec<&'static LintCode> {
    FAPD_CODES
        .iter()
        .filter(|c| condition_holds(c.condition, inputs))
        .collect()
}

/// Whether a single `Condition` is satisfied by the run `inputs`. This is the
/// mutation-critical gate: a wrong arm here is a false coverage attestation.
fn condition_holds(cond: Condition, inp: EvalInputs) -> bool {
    match cond {
        Condition::Always => true,
        Condition::RequiresTrustdb => inp.trustdb,
        Condition::RequiresIdentities => inp.check_identities,
        Condition::RequiresOrphans => inp.report_orphans && inp.trustdb,
        Condition::RequiresTarget => inp.target.is_some(),
        // Always false: no TargetVersion reaches fapolicyd 1.6, so a check
        // gated this way never runs and never earns a pass attestation. Flip
        // this when a 1.6-capable target variant lands (see the variant doc).
        Condition::RequiresFapolicyd16Plus => false,
        Condition::SuppressedUnderRhel8 => inp.target != Some(TargetVersion::Rhel8),
        Condition::SingleFileOnly => inp.single_file,
        Condition::DirectoryOnly => !inp.single_file,
    }
}

/// The catalog of every implemented `fapd-` lint code.
///
/// Authored in sorted-by-code order so [`evaluated`] yields a deterministic,
/// byte-stable sequence for SARIF output. The set is pinned against the
/// authoritative emitted set by `catalog_covers_exactly_the_authoritative_code_set`.
pub const FAPD_CODES: &[LintCode] = &[
    LintCode {
        code: "fapd-C01",
        severity: Severity::Convention,
        description: "rules.d/ filename does not follow the NN- numeric-prefix naming convention",
        condition: Condition::DirectoryOnly,
    },
    LintCode {
        code: "fapd-C02",
        severity: Severity::Convention,
        description: "cross-file duplicate: an identical rule appears in two different rules.d/ files",
        condition: Condition::DirectoryOnly,
    },
    LintCode {
        code: "fapd-E01",
        severity: Severity::Error,
        description: "unknown attribute key (not a recognized fapolicyd attribute name)",
        condition: Condition::Always,
    },
    LintCode {
        code: "fapd-E02",
        severity: Severity::Error,
        description: "invalid attribute value (e.g. a malformed sha256hash/filehash digest)",
        condition: Condition::Always,
    },
    LintCode {
        code: "fapd-E03",
        severity: Severity::Error,
        description: "reference to an undefined %setname macro",
        condition: Condition::Always,
    },
    LintCode {
        code: "fapd-E04",
        severity: Severity::Error,
        description: "%setname macro reference in a trust= or pattern= field, where it is not allowed",
        condition: Condition::Always,
    },
    LintCode {
        code: "fapd-E05",
        severity: Severity::Error,
        description: "integer-typed set contains an all-digit value that overflows its type",
        condition: Condition::Always,
    },
    LintCode {
        code: "fapd-E06",
        severity: Severity::Error,
        description: "construct diverges across the targeted fapolicyd/RHEL version",
        condition: Condition::RequiresTarget,
    },
    LintCode {
        code: "fapd-E07",
        severity: Severity::Error,
        description: "set or attribute value-type incompatibility",
        condition: Condition::Always,
    },
    LintCode {
        code: "fapd-F01",
        severity: Severity::Fatal,
        description: "rules file failed to parse",
        condition: Condition::Always,
    },
    LintCode {
        code: "fapd-F02",
        severity: Severity::Fatal,
        description: "compiled and source rules coexist (ambiguous active-policy layout)",
        condition: Condition::Always,
    },
    LintCode {
        code: "fapd-F03",
        severity: Severity::Fatal,
        description: "mixed modern and legacy rule syntax in one file",
        condition: Condition::Always,
    },
    LintCode {
        code: "fapd-S02",
        severity: Severity::Style,
        description: "%name= set definition appears after the first rule (definitions should precede rules)",
        condition: Condition::Always,
    },
    LintCode {
        code: "fapd-W01",
        severity: Severity::Warning,
        description: "rule is unreachable: an earlier same-file rule subsumes it",
        condition: Condition::Always,
    },
    LintCode {
        code: "fapd-W02",
        severity: Severity::Warning,
        description: "broad allow on execute (overly permissive execute decision)",
        condition: Condition::Always,
    },
    LintCode {
        code: "fapd-W03",
        severity: Severity::Warning,
        description: "inline trailing `# comment` past the first token (not treated as a comment)",
        condition: Condition::Always,
    },
    LintCode {
        code: "fapd-W04",
        severity: Severity::Warning,
        description: "rule unreachable: a deny in an earlier-loading rules.d/ file shadows it",
        condition: Condition::DirectoryOnly,
    },
    LintCode {
        code: "fapd-W05",
        severity: Severity::Warning,
        description: "uid=/gid= identity does not resolve via getent",
        condition: Condition::RequiresIdentities,
    },
    LintCode {
        code: "fapd-W06",
        severity: Severity::Warning,
        description: "path=/exe= literal is neither in the trust DB nor present on disk",
        condition: Condition::RequiresTrustdb,
    },
    LintCode {
        code: "fapd-W07",
        severity: Severity::Warning,
        description: "deprecated attribute name sha256hash= (use filehash=; fapolicyd 1.4.2+)",
        condition: Condition::SuppressedUnderRhel8,
    },
    LintCode {
        code: "fapd-W08",
        severity: Severity::Warning,
        description: "dir= value is missing its required trailing slash",
        condition: Condition::Always,
    },
    LintCode {
        code: "fapd-W09",
        severity: Severity::Warning,
        description: "macro reference may be defined in an unseen sibling file (single-file mode)",
        condition: Condition::SingleFileOnly,
    },
    LintCode {
        code: "fapd-W10",
        severity: Severity::Warning,
        description: "cross-file decision shadow: an earlier-loading allow shadows a later rule",
        condition: Condition::DirectoryOnly,
    },
    LintCode {
        code: "fapd-W11",
        severity: Severity::Warning,
        description: "weak hash digest (MD5/SHA1) in a rule value or the trust DB; prefer SHA-256",
        // Always: W11 has TWO emitters sharing this code. The per-rule
        // weak-digest check in `validation::walk` runs UNCONDITIONALLY in every
        // per-file lint (no trust DB needed); `trust_hash::lint_weak_digests`
        // ADDITIONALLY surfaces weak DB digests when `--against-trustdb` is set.
        // Because the per-rule emitter always runs, the W11 *check* is always
        // evaluated - it is NOT RequiresTrustdb (see `w11_is_always_evaluated_*`).
        condition: Condition::Always,
    },
    LintCode {
        code: "fapd-W12",
        severity: Severity::Warning,
        description: "deprecated dir=untrusted; will be removed in a future fapolicyd release",
        // Dormant: gated on fapolicyd >= 1.6, which no TargetVersion reaches.
        condition: Condition::RequiresFapolicyd16Plus,
    },
    LintCode {
        code: "fapd-X01",
        severity: Severity::Extra,
        description: "trust-DB orphan: a trusted path is absent from the loaded rules",
        condition: Condition::RequiresOrphans,
    },
];

#[cfg(test)]
mod tests {
    use super::*;
    use rulesteward_core::lint_code::{BaseLintCode, assert_catalog_invariants};
    use std::collections::BTreeSet;

    fn codes(inputs: EvalInputs) -> BTreeSet<&'static str> {
        evaluated(inputs).iter().map(|c| c.code).collect()
    }

    /// The authoritative set of `fapd-` codes the lints can emit, established by
    /// grepping the emission sites in `crates/rulesteward-fapolicyd/src`. If a
    /// new code is added without cataloguing it (or one is removed), this test
    /// fails - which is the point: the SARIF coverage attestation must not
    /// silently omit or invent a check. Keep sorted.
    const ALL_CODES: &[&str] = &[
        "fapd-C01", "fapd-C02", "fapd-E01", "fapd-E02", "fapd-E03", "fapd-E04", "fapd-E05",
        "fapd-E06", "fapd-E07", "fapd-F01", "fapd-F02", "fapd-F03", "fapd-S02", "fapd-W01",
        "fapd-W02", "fapd-W03", "fapd-W04", "fapd-W05", "fapd-W06", "fapd-W07", "fapd-W08",
        "fapd-W09", "fapd-W10", "fapd-W11", "fapd-W12", "fapd-X01",
    ];

    #[test]
    fn catalog_covers_exactly_the_authoritative_code_set() {
        let cataloged: BTreeSet<&str> = FAPD_CODES.iter().map(|c| c.code).collect();
        let expected: BTreeSet<&str> = ALL_CODES.iter().copied().collect();
        assert_eq!(
            cataloged,
            expected,
            "catalog code set must equal the authoritative emitted set; missing={:?} extra={:?}",
            expected.difference(&cataloged).collect::<Vec<_>>(),
            cataloged.difference(&expected).collect::<Vec<_>>(),
        );
    }

    #[test]
    fn catalog_satisfies_shared_invariants() {
        // Delegate the cross-backend catalog-integrity rules to the shared core
        // helper: strictly-sorted-by-code, no duplicates, severity-letter-
        // matches-code, AND descriptions-non-empty (the latter two of which this
        // catalog previously did not pin). fapolicyd's `LintCode` is a superset
        // of `BaseLintCode` - it adds the SARIF-only `condition` field - so map
        // each entry, dropping `condition` (#306, finishing the #289
        // de-triplication). The fapolicyd-specific membership and SARIF-condition
        // tests stay below.
        let base: Vec<BaseLintCode> = FAPD_CODES
            .iter()
            .map(|c| BaseLintCode {
                code: c.code,
                severity: c.severity,
                description: c.description,
            })
            .collect();
        assert_catalog_invariants(&base);
    }

    #[test]
    fn unconditional_checks_run_with_no_flags_in_directory_mode() {
        // The default EvalInputs is "directory mode, no flags": every Always
        // code must be present. Spot-check a representative subset.
        let c = codes(EvalInputs::default());
        for code in ["fapd-E01", "fapd-E02", "fapd-W02", "fapd-W08", "fapd-W11"] {
            assert!(
                c.contains(code),
                "{code} is unconditional and must be evaluated by default; got {c:?}",
            );
        }
    }

    #[test]
    fn identities_gate_controls_w05() {
        assert!(
            !codes(EvalInputs::default()).contains("fapd-W05"),
            "W05 must NOT be attested without --check-identities",
        );
        let on = EvalInputs {
            check_identities: true,
            ..Default::default()
        };
        assert!(
            codes(on).contains("fapd-W05"),
            "W05 must be attested with --check-identities",
        );
    }

    #[test]
    fn trustdb_gate_controls_w06() {
        assert!(!codes(EvalInputs::default()).contains("fapd-W06"));
        let on = EvalInputs {
            trustdb: true,
            ..Default::default()
        };
        assert!(codes(on).contains("fapd-W06"));
    }

    #[test]
    fn orphans_gate_needs_both_report_orphans_and_trustdb() {
        // X01 runs only with --report-orphans AND an attached trust DB.
        let orphans_only = EvalInputs {
            report_orphans: true,
            ..Default::default()
        };
        let trustdb_only = EvalInputs {
            trustdb: true,
            ..Default::default()
        };
        let both = EvalInputs {
            report_orphans: true,
            trustdb: true,
            ..Default::default()
        };
        assert!(!codes(EvalInputs::default()).contains("fapd-X01"));
        assert!(
            !codes(orphans_only).contains("fapd-X01"),
            "X01 needs a trust DB, not just --report-orphans",
        );
        assert!(
            !codes(trustdb_only).contains("fapd-X01"),
            "X01 needs --report-orphans, not just a trust DB",
        );
        assert!(codes(both).contains("fapd-X01"));
    }

    #[test]
    fn target_gate_controls_e06_but_not_e07() {
        // E06 (version_target) is fully gated on --target; E07 (type_compat) is
        // NOT - it runs under target=None for all-version-invariant mismatches
        // (issue #137 locked decision: E07 = Always).
        let no_target = EvalInputs::default();
        let with_target = EvalInputs {
            target: Some(TargetVersion::Rhel9),
            ..Default::default()
        };
        assert!(
            !codes(no_target).contains("fapd-E06"),
            "E06 must be gated on --target",
        );
        assert!(codes(with_target).contains("fapd-E06"));
        assert!(
            codes(no_target).contains("fapd-E07"),
            "E07 runs without --target (all-version-invariant mismatches); locked Always",
        );
        assert!(codes(with_target).contains("fapd-E07"));
    }

    #[test]
    fn w11_is_always_evaluated_even_without_a_trust_db() {
        // W11 has two emitters sharing the code: the per-rule weak-digest check
        // in `validation::walk` (runs in EVERY per-file lint, no trust DB) and
        // the DB-summary `trust_hash::lint_weak_digests` (only with
        // --against-trustdb). Because the per-rule emitter always runs, W11 is
        // Always-evaluated, NOT RequiresTrustdb. Regression guard against
        // re-classifying it as DB-gated, which would falsely withhold W11
        // coverage on a no-DB run where the per-rule check actually ran.
        assert!(
            codes(EvalInputs::default()).contains("fapd-W11"),
            "W11's per-rule validation check runs without a trust DB, so it is always evaluated",
        );
        let with_db = EvalInputs {
            trustdb: true,
            ..Default::default()
        };
        assert!(codes(with_db).contains("fapd-W11"));
    }

    #[test]
    fn w07_is_suppressed_only_under_rhel8() {
        // sha256hash= is canonical on 1.3.2 (rhel8), so W07 must not fire there;
        // it runs under None / rhel9 / rhel10.
        for t in [
            None,
            Some(TargetVersion::Rhel9),
            Some(TargetVersion::Rhel10),
        ] {
            let inp = EvalInputs {
                target: t,
                ..Default::default()
            };
            assert!(
                codes(inp).contains("fapd-W07"),
                "W07 must run for target={t:?}"
            );
        }
        let rhel8 = EvalInputs {
            target: Some(TargetVersion::Rhel8),
            ..Default::default()
        };
        assert!(
            !codes(rhel8).contains("fapd-W07"),
            "W07 must be suppressed under --target rhel8",
        );
    }

    #[test]
    fn w12_never_earns_a_pass_attestation_because_it_is_dormant() {
        // fapd-W12 (`dir=untrusted` deprecation) is gated on fapolicyd >= 1.6,
        // and NO TargetVersion reaches 1.6 (version.rs: Rhel8 -> 1.3.2,
        // Rhel9/Rhel10 -> 1.4.5). The check therefore never evaluates, so it
        // must never appear in `evaluated()` for ANY input combination.
        //
        // This is the #137 invariant, not a stylistic preference. `evaluated()`
        // feeds BOTH `PassInfo.rules` and `PassInfo.passes`
        // (cli/commands/fapolicyd/lint.rs:275-283), so a W12 entry whose
        // condition ever holds would emit a SARIF `kind:"pass"` result claiming
        // "we checked for dir=untrusted deprecation and found none" while the
        // gate returned early without looking. That is a false coverage
        // attestation - the exact defect the 8c/PR #508 senior review caught.
        //
        // Concretely: `Condition::RequiresTarget` (E06's condition) is WRONG for
        // W12, because it holds under --target rhel8/rhel9/rhel10. W12 needs its
        // OWN always-false condition variant.
        //
        // Precondition: W12 must actually BE in the catalog, otherwise every
        // assertion below passes vacuously against a catalog that simply never
        // heard of the code. (Paired with
        // `catalog_covers_exactly_the_authoritative_code_set`, this brackets the
        // implementer: catalogued, but never evaluated.)
        assert!(
            FAPD_CODES.iter().any(|c| c.code == "fapd-W12"),
            "precondition: fapd-W12 must be catalogued in FAPD_CODES, else the \
             dormancy sweep below is vacuous",
        );
        // Sweep every gate combination the CLI can produce.
        for target in [
            None,
            Some(TargetVersion::Rhel8),
            Some(TargetVersion::Rhel9),
            Some(TargetVersion::Rhel10),
        ] {
            for trustdb in [false, true] {
                for check_identities in [false, true] {
                    for report_orphans in [false, true] {
                        for single_file in [false, true] {
                            let inp = EvalInputs {
                                trustdb,
                                check_identities,
                                report_orphans,
                                target,
                                single_file,
                            };
                            assert!(
                                !codes(inp).contains("fapd-W12"),
                                "fapd-W12 is dormant (no target reaches fapolicyd 1.6), so it \
                                 must never be attested as evaluated: {inp:?}",
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn single_file_and_directory_modes_gate_disjoint_checks() {
        // W09 (macro maybe-defined-in-sibling) only in --file mode; the
        // cross-file checks (W04/W10/C01/C02) only in directory mode. Each is a
        // false attestation if emitted in the other mode.
        let dir = EvalInputs::default(); // single_file = false
        let file = EvalInputs {
            single_file: true,
            ..Default::default()
        };
        let dir_codes = codes(dir);
        let file_codes = codes(file);

        assert!(file_codes.contains("fapd-W09"), "W09 runs in --file mode");
        assert!(
            !dir_codes.contains("fapd-W09"),
            "W09 must NOT be attested in directory mode",
        );
        for cross in ["fapd-W04", "fapd-W10", "fapd-C01", "fapd-C02"] {
            assert!(dir_codes.contains(cross), "{cross} runs in directory mode");
            assert!(
                !file_codes.contains(cross),
                "{cross} must NOT be attested in --file mode",
            );
        }
    }
}
