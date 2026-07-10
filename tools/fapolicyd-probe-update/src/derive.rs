//! The comparison core: turn a parsed probe [`crate::transcript::Transcript`] into a
//! derived dataset value, and diff each derived value against the shipped
//! `rulesteward-fapolicyd` projection for a given
//! [`rulesteward_fapolicyd::TargetVersion`] (#478).
//!
//! Three datasets, three derivations:
//! - (a) `derive_version`: the `version` dataset's single `rpm_q` row -> a bare
//!   fapolicyd version string (`"1.3.2"`), compared against
//!   `TargetVersion::fapolicyd_version()`.
//! - (b) `derive_pattern`: the `pattern` dataset's per-value accept/reject rows -> the
//!   accepted `pattern=` value set, compared against the shipped
//!   `RHEL8_PATTERN_VALUES` / `RHEL9_PLUS_PATTERN_VALUES` (see the Cargo.toml header
//!   comment for the current private-visibility gap blocking that comparison).
//! - (c) `derive_e07`: the `e07` dataset's per-`<attr>_<shape>` accept/reject rows ->
//!   an `attr name -> AttrTypeCategory` map, compared against
//!   `attrs::type_category_for(name, target)`.
//!
//! Directions of the diff (mirrors `tools/sshd-probe-update/src/derive.rs`): probe =
//! the live daemon = source of truth; table = the shipped projection. `added` = a
//! probe-derived entry the shipped table lacks; `removed` = a shipped-table entry the
//! probe does not confirm. Both are drift.

use std::collections::{BTreeMap, BTreeSet};

use rulesteward_fapolicyd::TargetVersion;
use rulesteward_fapolicyd::attrs::AttrTypeCategory;

use crate::transcript::ProbeRow;

/// One dataset's drift for one target: entries the probe derived that the shipped
/// table lacks (`added`), and entries the shipped table asserts that the probe does
/// not confirm (`removed`). Mirrors `tools/sshd-probe-update`'s `FamilyDrift`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatasetDrift {
    /// Dataset tag: `"version"` | `"pattern"` | `"e07"`.
    pub dataset: &'static str,
    pub added: Vec<String>,
    pub removed: Vec<String>,
}

impl DatasetDrift {
    /// Whether this dataset is drift-free.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty()
    }

    /// Human-readable drift lines, each naming the dataset and the offending entry.
    #[must_use]
    pub fn lines(&self) -> Vec<String> {
        let mut out = Vec::new();
        for e in &self.added {
            out.push(format!(
                "+ {} {e}  (probe confirms it; absent from the shipped table)",
                self.dataset
            ));
        }
        for e in &self.removed {
            out.push(format!(
                "- {} {e}  (in the shipped table; probe does not confirm)",
                self.dataset
            ));
        }
        out
    }
}

/// The full drift report for one target: per-dataset drift across all three
/// datasets. Mirrors `tools/sshd-probe-update`'s `DriftReport`.
#[derive(Debug, Clone)]
pub struct CheckReport {
    pub target: TargetVersion,
    pub version: DatasetDrift,
    pub pattern: DatasetDrift,
    pub e07: DatasetDrift,
}

impl CheckReport {
    /// Whether ALL THREE datasets are drift-free. This is the final check VERDICT
    /// (not mere plumbing), so it is `todo!()`-stubbed with the rest of the check
    /// logic. (A single-dataset-drift case must flip this to `false` - see the
    /// frozen `is_in_sync_requires_every_dataset_empty` test below; a `||`-based
    /// implementation would wrongly report "in sync" when only two of three
    /// datasets are clean.)
    #[must_use]
    pub fn is_in_sync(&self) -> bool {
        todo!(
            "true iff self.version, self.pattern, AND self.e07 are all is_empty() \
             (conjunction, not disjunction - see the frozen test below)"
        )
    }

    /// The total number of drift entries across all three datasets.
    #[must_use]
    pub fn drift_count(&self) -> usize {
        todo!(
            "sum added.len() + removed.len() across all three datasets (6 fields \
             total) - see the frozen test below"
        )
    }

    /// Every drift line across the three datasets, in version, pattern, e07 order.
    #[must_use]
    pub fn drift_lines(&self) -> Vec<String> {
        let mut out = self.version.lines();
        out.extend(self.pattern.lines());
        out.extend(self.e07.lines());
        out
    }
}

/// Derive the fapolicyd version string from a `version`-dataset transcript (exactly
/// one `rpm_q` row, e.g. `fapolicyd-1.3.2-1.el8.x86_64` -> `"1.3.2"`).
///
/// # Errors
/// Returns `Err` if `rows` does not contain exactly one `version`-dataset row, or if
/// the row's `evidence` does not match the `rpm -q fapolicyd` NEVRA shape
/// (`fapolicyd-<version>-<release>...`).
pub fn derive_version(rows: &[ProbeRow]) -> Result<String, String> {
    let _ = rows;
    todo!(
        "extract the bare fapolicyd version (e.g. \"1.3.2\") from the version \
         dataset's single rpm_q evidence line; see derive::tests for the frozen \
         known-answer cases"
    )
}

/// Derive the accepted `pattern=` value set from a `pattern`-dataset transcript: every
/// row id whose verdict is [`crate::transcript::Verdict::Accept`].
///
/// # Errors
/// Returns `Err` if any row is not a `pattern`-dataset row.
pub fn derive_pattern(rows: &[ProbeRow]) -> Result<BTreeSet<String>, String> {
    let _ = rows;
    todo!(
        "collect every pattern-dataset row id whose verdict is Accept into a \
         BTreeSet; see derive::tests for the frozen known-answer cases (rhel8 = 3 \
         values, rhel9/rhel10 = 4 values)"
    )
}

/// Derive the fapd-E07 type-category map from an `e07`-dataset transcript: group rows
/// by `<attr>` (the part of `id` before the first `_`, e.g. `pid_signed_negfirst` ->
/// attr `pid`) and classify the attr's accept/reject shape pattern into an
/// [`AttrTypeCategory`]:
/// - `{int: accept, str: reject}` (no `signed_negfirst` shape tested) -> `Unsigned`.
/// - `{str: accept, int: reject}` -> `Str`.
/// - `{int: accept, signed_negfirst: reject, str: reject}` -> `Unsigned` (pid/ppid on
///   rhel8: a plain positive-int set types UNSIGNED).
/// - `{int: reject, signed_negfirst: accept, str: reject}` -> `Signed` (pid/ppid on
///   rhel9+: only a set with a negative member types SIGNED).
/// - `{str: accept, int: accept, mixed: accept}` -> `Permissive` (gid on rhel8).
/// - `{str: reject, int: accept, mixed: reject}` -> `Unsigned` (gid on rhel9+).
/// - `{set: reject}` (the single `<attr>_set` id, pattern/trust) -> `NoSet`.
///
/// # Errors
/// Returns `Err` if any row is not an `e07`-dataset row, or if an attr's observed
/// shape/verdict combination does not match any of the patterns above (an
/// unrecognized combination, e.g. from a corrupted fixture).
pub fn derive_e07(rows: &[ProbeRow]) -> Result<BTreeMap<String, AttrTypeCategory>, String> {
    let _ = rows;
    todo!(
        "group e07-dataset rows by attribute name and classify each attr's \
         accept/reject shape pattern into an AttrTypeCategory; see derive::tests for \
         the frozen known-answer cases (11 attrs, full map per fixture)"
    )
}

/// Compare the probe-derived version (from `version_rows`) against the shipped
/// `target.fapolicyd_version()`.
///
/// # Errors
/// Propagates any [`derive_version`] error.
pub fn check_version(
    version_rows: &[ProbeRow],
    target: TargetVersion,
) -> Result<DatasetDrift, String> {
    let _ = (version_rows, target);
    todo!(
        "diff derive_version(version_rows) against target.fapolicyd_version(); a \
         mismatch reports BOTH sides (added = the probed version, removed = the \
         shipped version) so `check` names what the daemon actually reports"
    )
}

/// Compare the probe-derived accepted `pattern=` set (from `pattern_rows`) against the
/// shipped table for `target`.
///
/// # Errors
/// Propagates any [`derive_pattern`] error, or (once implemented) any error from
/// resolving the shipped-table comparison side (see the Cargo.toml header comment:
/// `rulesteward-fapolicyd`'s pattern-value constants are not yet `pub`).
pub fn check_pattern(
    pattern_rows: &[ProbeRow],
    target: TargetVersion,
) -> Result<DatasetDrift, String> {
    let _ = (pattern_rows, target);
    todo!(
        "diff derive_pattern(pattern_rows) against the shipped accepted pattern= \
         value set for target (rulesteward_fapolicyd::lints::version_target's \
         RHEL8_PATTERN_VALUES / RHEL9_PLUS_PATTERN_VALUES are private today - a pub \
         accessor must be added to that crate as part of this implementation, \
         outside tools/fapolicyd-probe-update/)"
    )
}

/// Compare the probe-derived fapd-E07 type-category map (from `e07_rows`) against
/// `attrs::type_category_for(name, target)` for every attribute the probe covers.
///
/// # Errors
/// Propagates any [`derive_e07`] error.
pub fn check_e07(e07_rows: &[ProbeRow], target: TargetVersion) -> Result<DatasetDrift, String> {
    let _ = (e07_rows, target);
    todo!(
        "diff derive_e07(e07_rows) against rulesteward_fapolicyd::attrs::type_category_for \
         for every attr name the probe covers"
    )
}

/// Compare all three probe-derived datasets against the shipped tables for `target`,
/// producing a combined [`CheckReport`]. The CLI `check`/`derive` subcommands read
/// one `<target>-{version,pattern,e07}.tsv` fixture triple and call this.
///
/// # Errors
/// Propagates the first of [`check_version`], [`check_pattern`], or [`check_e07`] to
/// fail.
pub fn check_target(
    version_rows: &[ProbeRow],
    pattern_rows: &[ProbeRow],
    e07_rows: &[ProbeRow],
    target: TargetVersion,
) -> Result<CheckReport, String> {
    Ok(CheckReport {
        target,
        version: check_version(version_rows, target)?,
        pattern: check_pattern(pattern_rows, target)?,
        e07: check_e07(e07_rows, target)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transcript::parse_tsv;

    const RHEL8_VERSION: &str = include_str!("../tests/fixtures/fapolicyd8-version.tsv");
    const RHEL9_VERSION: &str = include_str!("../tests/fixtures/fapolicyd9-version.tsv");
    const RHEL10_VERSION: &str = include_str!("../tests/fixtures/fapolicyd10-version.tsv");
    const RHEL8_PATTERN: &str = include_str!("../tests/fixtures/fapolicyd8-pattern.tsv");
    const RHEL9_PATTERN: &str = include_str!("../tests/fixtures/fapolicyd9-pattern.tsv");
    const RHEL10_PATTERN: &str = include_str!("../tests/fixtures/fapolicyd10-pattern.tsv");
    const RHEL8_E07: &str = include_str!("../tests/fixtures/fapolicyd8-e07.tsv");
    const RHEL9_E07: &str = include_str!("../tests/fixtures/fapolicyd9-e07.tsv");
    const RHEL10_E07: &str = include_str!("../tests/fixtures/fapolicyd10-e07.tsv");

    fn set(items: &[&str]) -> BTreeSet<String> {
        items.iter().map(|s| (*s).to_string()).collect()
    }

    // -----------------------------------------------------------------------
    // derive_version known-answer.
    // -----------------------------------------------------------------------

    /// Source: `tests/fixtures/fapolicyd8-version.tsv` line 11 + shipped
    /// `crates/rulesteward-fapolicyd/src/version.rs` lines 46-53
    /// (`TargetVersion::Rhel8.fapolicyd_version() == "1.3.2"`).
    #[test]
    fn derive_version_rhel8_yields_bare_version() {
        let rows = parse_tsv(RHEL8_VERSION).expect("parse");
        assert_eq!(derive_version(&rows).expect("derive"), "1.3.2");
    }

    /// Source: `tests/fixtures/fapolicyd9-version.tsv` line 11.
    #[test]
    fn derive_version_rhel9_yields_bare_version() {
        let rows = parse_tsv(RHEL9_VERSION).expect("parse");
        assert_eq!(derive_version(&rows).expect("derive"), "1.4.5");
    }

    /// Source: `tests/fixtures/fapolicyd10-version.tsv` line 11.
    #[test]
    fn derive_version_rhel10_yields_bare_version() {
        let rows = parse_tsv(RHEL10_VERSION).expect("parse");
        assert_eq!(derive_version(&rows).expect("derive"), "1.4.5");
    }

    // -----------------------------------------------------------------------
    // derive_pattern known-answer: FULL set per target, not a spot value - a wrong
    // impl that hardcodes the shipped table (rather than deriving from the
    // transcript) is caught by the mutated-fixture RED cases further below.
    // -----------------------------------------------------------------------

    /// Source: `tests/fixtures/fapolicyd8-pattern.tsv`; grounded shipped table
    /// `crates/rulesteward-fapolicyd/src/lints/version_target.rs` line 20
    /// (`RHEL8_PATTERN_VALUES`).
    #[test]
    fn derive_pattern_rhel8_yields_exactly_three_values() {
        let rows = parse_tsv(RHEL8_PATTERN).expect("parse");
        assert_eq!(
            derive_pattern(&rows).expect("derive"),
            set(&["ld_so", "ld_preload", "static"]),
            "rhel8 must NOT include normal (rejected) or the bogus sentinel"
        );
    }

    /// Source: `tests/fixtures/fapolicyd9-pattern.tsv`; grounded shipped table
    /// `crates/rulesteward-fapolicyd/src/lints/version_target.rs` line 24
    /// (`RHEL9_PLUS_PATTERN_VALUES`).
    #[test]
    fn derive_pattern_rhel9_yields_exactly_four_values() {
        let rows = parse_tsv(RHEL9_PATTERN).expect("parse");
        assert_eq!(
            derive_pattern(&rows).expect("derive"),
            set(&["normal", "ld_so", "ld_preload", "static"]),
            "rhel9 must include normal (accepted on 1.4.x) but not the bogus sentinel"
        );
    }

    /// Source: `tests/fixtures/fapolicyd10-pattern.tsv`.
    #[test]
    fn derive_pattern_rhel10_matches_rhel9() {
        let rows = parse_tsv(RHEL10_PATTERN).expect("parse");
        assert_eq!(
            derive_pattern(&rows).expect("derive"),
            set(&["normal", "ld_so", "ld_preload", "static"])
        );
    }

    // -----------------------------------------------------------------------
    // derive_e07 known-answer: FULL map per target (all 11 attrs), grounded in
    // crates/rulesteward-fapolicyd/src/attrs.rs's AttrTypeCategory tables.
    // -----------------------------------------------------------------------

    /// Source: `tests/fixtures/fapolicyd8-e07.tsv`; shipped categories
    /// `crates/rulesteward-fapolicyd/src/attrs.rs` lines 94-115 (version-invariant
    /// baseline) with `type_category_for` lines 157-177 resolving pid/ppid/gid for
    /// rhel8 specifically (Unsigned / Permissive).
    #[test]
    fn derive_e07_rhel8_yields_full_category_map() {
        let rows = parse_tsv(RHEL8_E07).expect("parse");
        let m = derive_e07(&rows).expect("derive");
        assert_eq!(m.len(), 11, "11 distinct attributes must all be classified");
        for attr in ["uid", "auid", "sessionid"] {
            assert_eq!(m[attr], AttrTypeCategory::Unsigned, "{attr}");
        }
        assert_eq!(m["pid"], AttrTypeCategory::Unsigned, "pid on rhel8");
        assert_eq!(m["ppid"], AttrTypeCategory::Unsigned, "ppid on rhel8");
        assert_eq!(m["gid"], AttrTypeCategory::Permissive, "gid on rhel8");
        for attr in ["exe", "path", "mode"] {
            assert_eq!(m[attr], AttrTypeCategory::Str, "{attr}");
        }
        assert_eq!(m["pattern"], AttrTypeCategory::NoSet);
        assert_eq!(m["trust"], AttrTypeCategory::NoSet);
    }

    /// Source: `tests/fixtures/fapolicyd9-e07.tsv`; `attrs.rs` lines 157-177 resolving
    /// pid/ppid/gid for rhel9+ (Signed / Unsigned) - the version-divergent flip from
    /// the rhel8 case above.
    #[test]
    fn derive_e07_rhel9_flips_pid_ppid_and_gid() {
        let rows = parse_tsv(RHEL9_E07).expect("parse");
        let m = derive_e07(&rows).expect("derive");
        assert_eq!(m.len(), 11);
        assert_eq!(m["pid"], AttrTypeCategory::Signed, "pid on rhel9");
        assert_eq!(m["ppid"], AttrTypeCategory::Signed, "ppid on rhel9");
        assert_eq!(m["gid"], AttrTypeCategory::Unsigned, "gid on rhel9");
        // The invariant categories must NOT have flipped.
        for attr in ["uid", "auid", "sessionid"] {
            assert_eq!(m[attr], AttrTypeCategory::Unsigned, "{attr}");
        }
        for attr in ["exe", "path", "mode"] {
            assert_eq!(m[attr], AttrTypeCategory::Str, "{attr}");
        }
    }

    /// Source: `tests/fixtures/fapolicyd10-e07.tsv` - must match the rhel9 shape
    /// (both ship fapolicyd 1.4.5).
    #[test]
    fn derive_e07_rhel10_matches_rhel9() {
        let rows = parse_tsv(RHEL10_E07).expect("parse");
        let m = derive_e07(&rows).expect("derive");
        assert_eq!(m["pid"], AttrTypeCategory::Signed);
        assert_eq!(m["gid"], AttrTypeCategory::Unsigned);
    }

    // -----------------------------------------------------------------------
    // CheckReport structural properties (mirrors sshd-probe-update's non-vacuity
    // guards on is_in_sync / drift_count).
    // -----------------------------------------------------------------------

    fn drift(dataset: &'static str, added: &[&str], removed: &[&str]) -> DatasetDrift {
        DatasetDrift {
            dataset,
            added: added.iter().map(|s| (*s).to_string()).collect(),
            removed: removed.iter().map(|s| (*s).to_string()).collect(),
        }
    }

    fn report(version: DatasetDrift, pattern: DatasetDrift, e07: DatasetDrift) -> CheckReport {
        CheckReport {
            target: TargetVersion::Rhel9,
            version,
            pattern,
            e07,
        }
    }

    /// `is_in_sync` is true only when ALL THREE datasets are empty - a `||`-based
    /// mutant would wrongly report "in sync" with exactly one dataset drifting.
    #[test]
    fn is_in_sync_requires_every_dataset_empty() {
        assert!(
            report(
                drift("version", &[], &[]),
                drift("pattern", &[], &[]),
                drift("e07", &[], &[])
            )
            .is_in_sync()
        );
        assert!(
            !report(
                drift("version", &["1.9.9"], &["1.3.2"]),
                drift("pattern", &[], &[]),
                drift("e07", &[], &[])
            )
            .is_in_sync(),
            "version-only drift must NOT be in sync"
        );
        assert!(
            !report(
                drift("version", &[], &[]),
                drift("pattern", &["bogus"], &[]),
                drift("e07", &[], &[])
            )
            .is_in_sync(),
            "pattern-only drift must NOT be in sync"
        );
        assert!(
            !report(
                drift("version", &[], &[]),
                drift("pattern", &[], &[]),
                drift("e07", &[], &["gid"])
            )
            .is_in_sync(),
            "e07-only drift must NOT be in sync"
        );
    }

    /// `drift_count` sums all SIX fields (added+removed x 3 datasets) - pins the
    /// arithmetic so a whole-fn-replacement or `+`->`*` mutation is caught.
    #[test]
    fn drift_count_sums_all_six_fields_exactly() {
        let r = report(
            drift("version", &["a"], &["b"]),
            drift("pattern", &["c"], &["d"]),
            drift("e07", &["e"], &["f"]),
        );
        assert_eq!(r.drift_count(), 6);
        let empty = report(
            drift("version", &[], &[]),
            drift("pattern", &[], &[]),
            drift("e07", &[], &[]),
        );
        assert_eq!(empty.drift_count(), 0);
    }

    // -----------------------------------------------------------------------
    // Check GREEN-case: derived(real committed fixture) == shipped table, for all
    // three datasets, on all three targets. (they do today: zero drift, per
    // /var/tmp/7b-grounding/p2/drift-findings.md "Result: NO DRIFT in any of the
    // three shipped datasets".)
    // -----------------------------------------------------------------------

    #[test]
    fn check_version_rhel8_real_fixture_is_in_sync() {
        let rows = parse_tsv(RHEL8_VERSION).expect("parse");
        let d = check_version(&rows, TargetVersion::Rhel8).expect("check");
        assert!(d.is_empty(), "expected 0 drift, got {d:?}");
    }

    #[test]
    fn check_version_rhel9_real_fixture_is_in_sync() {
        let rows = parse_tsv(RHEL9_VERSION).expect("parse");
        let d = check_version(&rows, TargetVersion::Rhel9).expect("check");
        assert!(d.is_empty(), "expected 0 drift, got {d:?}");
    }

    #[test]
    fn check_version_rhel10_real_fixture_is_in_sync() {
        let rows = parse_tsv(RHEL10_VERSION).expect("parse");
        let d = check_version(&rows, TargetVersion::Rhel10).expect("check");
        assert!(d.is_empty(), "expected 0 drift, got {d:?}");
    }

    #[test]
    fn check_pattern_rhel8_real_fixture_is_in_sync() {
        let rows = parse_tsv(RHEL8_PATTERN).expect("parse");
        let d = check_pattern(&rows, TargetVersion::Rhel8).expect("check");
        assert!(d.is_empty(), "expected 0 drift, got {d:?}");
    }

    #[test]
    fn check_pattern_rhel9_real_fixture_is_in_sync() {
        let rows = parse_tsv(RHEL9_PATTERN).expect("parse");
        let d = check_pattern(&rows, TargetVersion::Rhel9).expect("check");
        assert!(d.is_empty(), "expected 0 drift, got {d:?}");
    }

    #[test]
    fn check_pattern_rhel10_real_fixture_is_in_sync() {
        let rows = parse_tsv(RHEL10_PATTERN).expect("parse");
        let d = check_pattern(&rows, TargetVersion::Rhel10).expect("check");
        assert!(d.is_empty(), "expected 0 drift, got {d:?}");
    }

    #[test]
    fn check_e07_rhel8_real_fixture_is_in_sync() {
        let rows = parse_tsv(RHEL8_E07).expect("parse");
        let d = check_e07(&rows, TargetVersion::Rhel8).expect("check");
        assert!(d.is_empty(), "expected 0 drift, got {d:?}");
    }

    #[test]
    fn check_e07_rhel9_real_fixture_is_in_sync() {
        let rows = parse_tsv(RHEL9_E07).expect("parse");
        let d = check_e07(&rows, TargetVersion::Rhel9).expect("check");
        assert!(d.is_empty(), "expected 0 drift, got {d:?}");
    }

    #[test]
    fn check_e07_rhel10_real_fixture_is_in_sync() {
        let rows = parse_tsv(RHEL10_E07).expect("parse");
        let d = check_e07(&rows, TargetVersion::Rhel10).expect("check");
        assert!(d.is_empty(), "expected 0 drift, got {d:?}");
    }

    /// `check_target` combining all three real (unmutated) fixtures for one target
    /// must report an overall in-sync report - the end-to-end GREEN case the CLI
    /// `check` subcommand relies on.
    #[test]
    fn check_target_rhel8_real_fixtures_is_in_sync() {
        let version = parse_tsv(RHEL8_VERSION).expect("parse");
        let pattern = parse_tsv(RHEL8_PATTERN).expect("parse");
        let e07 = parse_tsv(RHEL8_E07).expect("parse");
        let report =
            check_target(&version, &pattern, &e07, TargetVersion::Rhel8).expect("check_target");
        assert!(
            report.is_in_sync(),
            "expected 0 drift, got {:?}",
            report.drift_lines()
        );
    }

    // -----------------------------------------------------------------------
    // Check RED-cases: one synthetic mutated fixture per dataset must make `check`
    // report drift naming the dataset + the offending entry, non-zero outcome
    // (`is_in_sync() == false`, and the offending id appears in `drift_lines()`).
    // -----------------------------------------------------------------------

    /// Mutate the rhel8 version row's evidence to a DIFFERENT (still-parseable)
    /// fapolicyd version. The derived version ("9.9.9") no longer matches the
    /// shipped `TargetVersion::Rhel8.fapolicyd_version()` ("1.3.2") -> drift.
    #[test]
    fn check_version_mutated_fixture_reports_drift() {
        let mutated = RHEL8_VERSION.replace(
            "fapolicyd-1.3.2-1.el8.x86_64",
            "fapolicyd-9.9.9-1.el8.x86_64",
        );
        assert_ne!(mutated, RHEL8_VERSION, "the version evidence must be found");
        let rows = parse_tsv(&mutated).expect("parse");
        let d = check_version(&rows, TargetVersion::Rhel8).expect("check");
        assert!(!d.is_empty(), "expected drift, got none");
        assert_eq!(d.dataset, "version");
        assert!(
            d.lines().iter().any(|l| l.contains("9.9.9")),
            "drift lines must name the probed (wrong) version; got {:?}",
            d.lines()
        );
    }

    /// Flip the rhel8 `ld_so` row's verdict from accept to reject. The probe no
    /// longer confirms `ld_so`, which the shipped `RHEL8_PATTERN_VALUES` asserts ->
    /// `removed` drift naming `ld_so`.
    #[test]
    fn check_pattern_mutated_fixture_reports_drift_naming_the_value() {
        let mutated = RHEL8_PATTERN.replacen(
            "pattern\tld_so\taccept\t1\t",
            "pattern\tld_so\treject\t0\t",
            1,
        );
        assert_ne!(mutated, RHEL8_PATTERN, "the ld_so accept row must be found");
        let rows = parse_tsv(&mutated).expect("parse");
        let d = check_pattern(&rows, TargetVersion::Rhel8).expect("check");
        assert!(!d.is_empty(), "expected drift, got none");
        assert_eq!(d.dataset, "pattern");
        assert!(
            d.lines().iter().any(|l| l.contains("ld_so")),
            "drift lines must name ld_so; got {:?}",
            d.lines()
        );
    }

    /// Flip the rhel9 `gid_int` row's verdict from accept to reject. `derive_e07`
    /// would then see NO accepting shape for `gid`, an unrecognized shape/verdict
    /// combination relative to the Unsigned{str:reject,int:accept,mixed:reject}
    /// pattern -> either a `derive_e07` error OR (once fully classified as an
    /// "everything rejects" case) a category mismatch against the shipped
    /// `Unsigned`. Either way `check_e07` must NOT silently report in-sync.
    #[test]
    fn check_e07_mutated_fixture_reports_drift_or_error_never_silently_in_sync() {
        let mutated =
            RHEL9_E07.replacen("e07\tgid_int\taccept\t1\t", "e07\tgid_int\treject\t0\t", 1);
        assert_ne!(mutated, RHEL9_E07, "the gid_int accept row must be found");
        let rows = parse_tsv(&mutated).expect("parse");
        // An unrecognized shape combination erroring out is also acceptable; only a
        // silent Ok(empty) (falsely reporting in-sync) is disallowed.
        if let Ok(d) = check_e07(&rows, TargetVersion::Rhel9) {
            assert!(
                !d.is_empty(),
                "a gid_int verdict flip must not silently stay in sync"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Fail-closed propagation: check_* must propagate a parse-level fixture error,
    // never silently succeed with an empty/default drift report.
    // -----------------------------------------------------------------------

    #[test]
    fn check_pattern_on_wrong_dataset_rows_errors_rather_than_silently_passing() {
        // Feeding e07 rows into check_pattern (a plausible wiring bug: swapped file
        // arguments) must not silently report in-sync.
        let rows = parse_tsv(RHEL8_E07).expect("parse");
        if let Ok(d) = check_pattern(&rows, TargetVersion::Rhel8) {
            assert!(
                !d.is_empty(),
                "wrong-dataset rows must not silently report in-sync drift"
            );
        }
    }
}
