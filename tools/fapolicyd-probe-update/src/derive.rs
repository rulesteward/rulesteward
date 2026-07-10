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
//!   `RHEL8_PATTERN_VALUES` / `RHEL9_PLUS_PATTERN_VALUES` via the `pub`
//!   `rulesteward_fapolicyd::lints::version_target::accepted_pattern_values` accessor
//!   (made `pub` for this tool; see the Cargo.toml header comment for the prior gap).
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
use rulesteward_fapolicyd::attrs::{AttrTypeCategory, type_category_for};
use rulesteward_fapolicyd::lints::version_target::accepted_pattern_values;

use crate::transcript::{ProbeRow, Verdict};

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
    /// Whether ALL THREE datasets are drift-free (conjunction, not disjunction - a
    /// `||`-based implementation would wrongly report "in sync" when only two of
    /// three datasets are clean; see the frozen
    /// `is_in_sync_requires_every_dataset_empty` test below).
    #[must_use]
    pub fn is_in_sync(&self) -> bool {
        self.version.is_empty() && self.pattern.is_empty() && self.e07.is_empty()
    }

    /// The total number of drift entries across all three datasets.
    #[must_use]
    pub fn drift_count(&self) -> usize {
        self.version.added.len()
            + self.version.removed.len()
            + self.pattern.added.len()
            + self.pattern.removed.len()
            + self.e07.added.len()
            + self.e07.removed.len()
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
    let version_rows: Vec<&ProbeRow> = rows.iter().filter(|r| r.dataset == "version").collect();
    if version_rows.len() != 1 {
        return Err(format!(
            "expected exactly one version-dataset row, found {}",
            version_rows.len()
        ));
    }
    let evidence = version_rows[0].evidence.trim();
    let rest = evidence
        .strip_prefix("fapolicyd-")
        .ok_or_else(|| format!("version evidence {evidence:?} does not start with fapolicyd-"))?;
    let version = rest
        .split('-')
        .next()
        .filter(|v| !v.is_empty())
        .ok_or_else(|| {
            format!("version evidence {evidence:?} has no version segment after fapolicyd-")
        })?;
    Ok(version.to_string())
}

/// Derive the accepted `pattern=` value set from a `pattern`-dataset transcript: every
/// row id whose verdict is [`crate::transcript::Verdict::Accept`].
///
/// # Errors
/// Returns `Err` if any row is not a `pattern`-dataset row.
pub fn derive_pattern(rows: &[ProbeRow]) -> Result<BTreeSet<String>, String> {
    for r in rows {
        if r.dataset != "pattern" {
            return Err(format!(
                "expected only pattern-dataset rows, found dataset {:?} (id {:?})",
                r.dataset, r.id
            ));
        }
    }
    Ok(rows
        .iter()
        .filter(|r| r.verdict == Verdict::Accept)
        .map(|r| r.id.clone())
        .collect())
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
    for r in rows {
        if r.dataset != "e07" {
            return Err(format!(
                "expected only e07-dataset rows, found dataset {:?} (id {:?})",
                r.dataset, r.id
            ));
        }
    }

    let mut by_attr: BTreeMap<String, BTreeMap<String, Verdict>> = BTreeMap::new();
    for r in rows {
        let (attr, shape) =
            r.id.split_once('_')
                .ok_or_else(|| format!("e07 row id {:?} has no <attr>_<shape> separator", r.id))?;
        by_attr
            .entry(attr.to_string())
            .or_default()
            .insert(shape.to_string(), r.verdict);
    }

    let mut out = BTreeMap::new();
    for (attr, shapes) in &by_attr {
        let category = classify_e07_shapes(shapes).ok_or_else(|| {
            format!("attr {attr:?} has an unrecognized e07 shape/verdict combination: {shapes:?}")
        })?;
        out.insert(attr.clone(), category);
    }
    Ok(out)
}

/// Classify one attribute's observed `<shape> -> verdict` map into an
/// [`AttrTypeCategory`] per the seven patterns documented on [`derive_e07`], or
/// `None` if the shape/verdict combination matches none of them.
fn classify_e07_shapes(shapes: &BTreeMap<String, Verdict>) -> Option<AttrTypeCategory> {
    let get = |k: &str| shapes.get(k).copied();
    match (
        shapes.len(),
        get("int"),
        get("str"),
        get("signed_negfirst"),
        get("mixed"),
        get("set"),
    ) {
        (2, Some(Verdict::Accept), Some(Verdict::Reject), None, None, None) => {
            Some(AttrTypeCategory::Unsigned)
        }
        (2, Some(Verdict::Reject), Some(Verdict::Accept), None, None, None) => {
            Some(AttrTypeCategory::Str)
        }
        (3, Some(Verdict::Accept), Some(Verdict::Reject), Some(Verdict::Reject), None, None) => {
            Some(AttrTypeCategory::Unsigned)
        }
        (3, Some(Verdict::Reject), Some(Verdict::Reject), Some(Verdict::Accept), None, None) => {
            Some(AttrTypeCategory::Signed)
        }
        (3, Some(Verdict::Accept), Some(Verdict::Accept), None, Some(Verdict::Accept), None) => {
            Some(AttrTypeCategory::Permissive)
        }
        (3, Some(Verdict::Accept), Some(Verdict::Reject), None, Some(Verdict::Reject), None) => {
            Some(AttrTypeCategory::Unsigned)
        }
        (1, None, None, None, None, Some(Verdict::Reject)) => Some(AttrTypeCategory::NoSet),
        _ => None,
    }
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
    let probed = derive_version(version_rows)?;
    let shipped = target.fapolicyd_version();
    if probed == shipped {
        Ok(DatasetDrift {
            dataset: "version",
            added: Vec::new(),
            removed: Vec::new(),
        })
    } else {
        Ok(DatasetDrift {
            dataset: "version",
            added: vec![probed],
            removed: vec![shipped.to_string()],
        })
    }
}

/// Compare the probe-derived accepted `pattern=` set (from `pattern_rows`) against the
/// shipped table for `target`.
///
/// # Errors
/// Propagates any [`derive_pattern`] error.
pub fn check_pattern(
    pattern_rows: &[ProbeRow],
    target: TargetVersion,
) -> Result<DatasetDrift, String> {
    let probed = derive_pattern(pattern_rows)?;
    let shipped: BTreeSet<String> = accepted_pattern_values(target)
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    Ok(DatasetDrift {
        dataset: "pattern",
        added: probed.difference(&shipped).cloned().collect(),
        removed: shipped.difference(&probed).cloned().collect(),
    })
}

/// Compare the probe-derived fapd-E07 type-category map (from `e07_rows`) against
/// `attrs::type_category_for(name, target)` for every attribute the probe covers.
///
/// # Errors
/// Propagates any [`derive_e07`] error.
pub fn check_e07(e07_rows: &[ProbeRow], target: TargetVersion) -> Result<DatasetDrift, String> {
    let probed = derive_e07(e07_rows)?;
    let mut added = Vec::new();
    let mut removed = Vec::new();
    for (attr, probed_cat) in &probed {
        match type_category_for(attr, target) {
            Some(shipped_cat) if shipped_cat == *probed_cat => {}
            Some(shipped_cat) => {
                added.push(format!("{attr}={probed_cat:?}"));
                removed.push(format!("{attr}={shipped_cat:?}"));
            }
            None => {
                added.push(format!(
                    "{attr}={probed_cat:?} (unknown to the shipped table)"
                ));
            }
        }
    }
    Ok(DatasetDrift {
        dataset: "e07",
        added,
        removed,
    })
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
    // ATL strengthening round (post-GREEN): pins for check_e07's MISMATCH and
    // UNKNOWN-ATTR arms, which the impl-aware adversary (MISS 1 / MISS 2) and the
    // clean mutation run (survivor: `replace match guard shipped_cat == *probed_cat
    // with true`) independently flagged as unprotected. The gidflip test above
    // deliberately accepts EITHER an error or drift, so it never forces the
    // mismatch arm itself; these two do.
    // -----------------------------------------------------------------------

    /// ATL finding 1 (adversary MISS 1 + the derive.rs match-guard mutation
    /// survivor): a fixture whose pid rows flip to the rhel9+ shape (`pid_int` ->
    /// reject, `pid_signed_negfirst` -> accept) makes `derive_e07` classify `pid` as
    /// `Signed` while the shipped `type_category_for("pid", Rhel8)` says `Unsigned`
    /// (attrs.rs lines 157-167) - a CATEGORY MISMATCH, which must land in the
    /// mismatch arm as directional drift: probed category in `added`, shipped
    /// category in `removed`. A `guard -> true` mutant swallows the mismatch into
    /// the in-sync arm (empty drift); a swapped added/removed corruption reverses
    /// the direction. Both die on the directional asserts below. Repro verified by
    /// the adversary against the real impl under /var/tmp/7b-atl-p2/.
    #[test]
    fn check_e07_category_mismatch_reports_directional_drift_naming_both_categories() {
        let mutated = RHEL8_E07
            .replacen("e07\tpid_int\taccept\t1\t", "e07\tpid_int\treject\t0\t", 1)
            .replacen(
                "e07\tpid_signed_negfirst\treject\t0\t",
                "e07\tpid_signed_negfirst\taccept\t1\t",
                1,
            );
        assert_ne!(mutated, RHEL8_E07, "both pid rows must have been rewritten");
        let rows = parse_tsv(&mutated).expect("parse");
        let d = check_e07(&rows, TargetVersion::Rhel8).expect("check");
        assert!(!d.is_empty(), "a pid category flip must be drift");
        assert_eq!(d.dataset, "e07");
        // Direction: probed (Signed) is what the daemon now shows -> `added`;
        // shipped (Unsigned) is what the table asserts unconfirmed -> `removed`.
        assert!(
            d.added.iter().any(|e| e.contains("pid=Signed")),
            "added must carry the probed category pid=Signed; got {:?}",
            d.added
        );
        assert!(
            d.removed.iter().any(|e| e.contains("pid=Unsigned")),
            "removed must carry the shipped category pid=Unsigned; got {:?}",
            d.removed
        );
        let lines = d.lines();
        assert!(
            lines.iter().any(|l| l.contains("pid=Signed"))
                && lines.iter().any(|l| l.contains("pid=Unsigned")),
            "drift lines must name BOTH categories; got {lines:?}"
        );
    }

    /// ATL finding 2 (adversary MISS 2): an attribute the probe covers but the
    /// shipped table does not know (`type_category_for` -> `None`, attrs.rs lines
    /// 157-177 falling through to `type_category`'s `None` arm) must surface as
    /// drift flagged "unknown to the shipped table" - the arm that catches a future
    /// fapolicyd adding a brand-new attribute. Appends two synthetic `foobar` rows
    /// (int accept / str reject -> classifies `Unsigned`, mirroring
    /// /var/tmp/7b-atl-p2/unk/) to the otherwise in-sync rhel8 fixture so the ONLY
    /// drift is the unknown attr.
    #[test]
    fn check_e07_unknown_attr_reports_drift_flagged_unknown_to_the_shipped_table() {
        let mutated = format!(
            "{RHEL8_E07}e07\tfoobar_int\taccept\t1\tsynthetic\ne07\tfoobar_str\treject\t0\tsynthetic\n"
        );
        let rows = parse_tsv(&mutated).expect("parse");
        let d = check_e07(&rows, TargetVersion::Rhel8).expect("check");
        assert!(!d.is_empty(), "an unknown probed attr must be drift");
        assert_eq!(d.dataset, "e07");
        assert!(
            d.added
                .iter()
                .any(|e| e.contains("foobar") && e.contains("unknown to the shipped table")),
            "added must flag foobar as unknown to the shipped table; got {:?}",
            d.added
        );
        assert!(
            d.removed.is_empty(),
            "an unknown attr is probe-side only (nothing shipped to un-confirm); got {:?}",
            d.removed
        );
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
