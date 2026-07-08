//! The comparison core: classify a probe transcript into the three lint-family
//! probe sets, diff them against the shipped `rulesteward-sshd` projections, and
//! report drift. A faithful port of `validate_probe.py`'s `classify` + comparison,
//! using the crate's `known_keywords` / `match_permitted_keywords` /
//! `deprecated_keywords` projections (built from the same const arrays the python
//! regex-extracts) as the expected side. Empty drift sets == in sync.
//!
//! Directions of the diff (probe = the live daemon = source of truth; table = the
//! shipped projection): `+` a keyword the PROBE has that the TABLE lacks; `-` a
//! keyword the TABLE asserts that the PROBE does not confirm. Both are drift.

use std::collections::{BTreeMap, BTreeSet};

use rulesteward_sshd::TargetVersion;
use rulesteward_sshd::lints::deprecation::deprecated_keywords;
use rulesteward_sshd::lints::registry::known_keywords;
use rulesteward_sshd::lints::structural::match_permitted_keywords;

use crate::classify::{E04Class, e01_known, e04_class, w04_probe_deprecated};
use crate::overlay::{CLEAN_PARSE_OVERLAY, OverlayVerdict, verify_overlay};
use crate::transcript::{ProbeKind, Transcript};

/// The three probe-derived keyword sets for one product, plus the raw `opt`
/// stderr map (for overlay advisory-verification).
#[derive(Debug, Clone, Default)]
pub struct ProbeSets {
    /// E01: keywords the daemon recognizes (`opt` reply, not `Bad configuration option`).
    pub known: BTreeSet<String>,
    /// W04: keywords the daemon calls `Deprecated option`.
    pub deprecated: BTreeSet<String>,
    /// E04: known keywords permitted inside a `Match` block.
    pub permitted: BTreeSet<String>,
    /// kw -> `opt` stderr, for overlay clean-parse verification.
    opt_stderr: BTreeMap<String, String>,
}

/// One lint family's drift: keywords the probe added (`+`) and removed (`-`)
/// relative to the shipped table. Both `Vec`s are sorted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FamilyDrift {
    /// Family tag (`E01` / `W04` / `E04`).
    pub family: &'static str,
    /// `+`: in the probe, absent from the shipped table.
    pub added: Vec<String>,
    /// `-`: asserted by the shipped table, not confirmed by the probe.
    pub removed: Vec<String>,
}

impl FamilyDrift {
    /// Whether this family is drift-free.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty()
    }

    /// Human-readable drift lines, each naming the family and keyword.
    #[must_use]
    pub fn lines(&self) -> Vec<String> {
        let mut out = Vec::new();
        for k in &self.added {
            out.push(format!(
                "+ {} {k}  (probe recognizes it; absent from the shipped table)",
                self.family
            ));
        }
        for k in &self.removed {
            out.push(format!(
                "- {} {k}  (in the shipped table; probe does not confirm)",
                self.family
            ));
        }
        out
    }
}

/// The full drift report for one product: per-family drift, the advisory notes,
/// and the derived probe sets (for the `derive` paste-ready listing).
#[derive(Debug, Clone)]
pub struct DriftReport {
    /// The product this report is for.
    pub target: TargetVersion,
    /// sshd-E01 known-keyword drift.
    pub e01: FamilyDrift,
    /// sshd-W04 deprecated-keyword drift (probe-derivable entries only).
    pub w04: FamilyDrift,
    /// sshd-E04 Match-permitted drift.
    pub e04: FamilyDrift,
    /// Advisory (non-gate-failing) notes: overlay verdict changes, unprobed overlays.
    pub advisories: Vec<String>,
    /// The probe-derived sets (exposed for the `derive` subcommand).
    pub probe: ProbeSets,
}

impl DriftReport {
    /// Whether all three families are drift-free (advisories do NOT affect this).
    #[must_use]
    pub fn is_in_sync(&self) -> bool {
        self.e01.is_empty() && self.w04.is_empty() && self.e04.is_empty()
    }

    /// The total number of drift entries across all three families.
    #[must_use]
    pub fn drift_count(&self) -> usize {
        self.e01.added.len()
            + self.e01.removed.len()
            + self.w04.added.len()
            + self.w04.removed.len()
            + self.e04.added.len()
            + self.e04.removed.len()
    }

    /// Every drift line across the three families, in E01, W04, E04 order.
    #[must_use]
    pub fn drift_lines(&self) -> Vec<String> {
        let mut out = self.e01.lines();
        out.extend(self.w04.lines());
        out.extend(self.e04.lines());
        out
    }
}

/// Classify a transcript into the three probe sets, mirroring
/// `validate_probe.py::classify`. A keyword is `known` iff it has an `opt` reply
/// the daemon did not reject; `deprecated` iff its `opt` reply says `Deprecated
/// option`; `permitted` iff it is `known` AND its `match` reply (defaulting to an
/// empty string, exactly as the python does) classifies as `Permitted`.
#[must_use]
pub fn classify_transcript(transcript: &Transcript) -> ProbeSets {
    let mut opt: BTreeMap<String, String> = BTreeMap::new();
    let mut mtch: BTreeMap<String, String> = BTreeMap::new();
    for r in transcript {
        match r.probe {
            ProbeKind::Opt => {
                opt.insert(r.kw.clone(), r.stderr.clone());
            }
            ProbeKind::Match => {
                mtch.insert(r.kw.clone(), r.stderr.clone());
            }
        }
    }

    let known: BTreeSet<String> = opt
        .iter()
        .filter(|(_, e)| e01_known(e))
        .map(|(k, _)| k.clone())
        .collect();
    let deprecated: BTreeSet<String> = opt
        .iter()
        .filter(|(_, e)| w04_probe_deprecated(e))
        .map(|(k, _)| k.clone())
        .collect();
    let mut permitted = BTreeSet::new();
    for kw in &known {
        let e = mtch.get(kw).map_or("", String::as_str);
        if e04_class(e) == E04Class::Permitted {
            permitted.insert(kw.clone());
        }
    }

    ProbeSets {
        known,
        deprecated,
        permitted,
        opt_stderr: opt,
    }
}

/// Pure symmetric-difference of a probe set against an expected (table) set.
/// `added` = probe - expected (`+`); `removed` = expected - probe (`-`).
#[must_use]
fn family_diff(
    family: &'static str,
    probe: &BTreeSet<String>,
    expected: &BTreeSet<String>,
) -> FamilyDrift {
    FamilyDrift {
        family,
        added: probe.difference(expected).cloned().collect(),
        removed: expected.difference(probe).cloned().collect(),
    }
}

/// Widen a projection `Vec<&'static str>` into an owned `BTreeSet<String>`.
fn set_of(v: Vec<&'static str>) -> BTreeSet<String> {
    v.into_iter().map(str::to_string).collect()
}

/// Compare a probe transcript against the shipped `rulesteward-sshd` tables for
/// `target` and produce the drift report. Reproduces `validate_probe.py`'s
/// expected sides exactly:
/// - E01 expected = `known_keywords(target)`.
/// - W04 expected = `deprecated_keywords(target)` MINUS the clean-parse overlays.
/// - E04 expected = `match_permitted_keywords(target)` INTERSECT `known_keywords(target)`.
///
/// Overlays never appear as drift: they are subtracted from the W04 expected set,
/// and an overlay the probe DOES now flag deprecated is reported as an advisory
/// (verdict change), not gate-failing drift.
#[must_use]
pub fn diff_target(transcript: &Transcript, target: TargetVersion) -> DriftReport {
    let probe = classify_transcript(transcript);

    let known_set = set_of(known_keywords(target));
    let overlay_set: BTreeSet<String> = CLEAN_PARSE_OVERLAY
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    let exp_dep = &set_of(deprecated_keywords(target)) - &overlay_set;
    let exp_permitted = &set_of(match_permitted_keywords(target)) & &known_set;

    let e01 = family_diff("E01", &probe.known, &known_set);
    let mut w04 = family_diff("W04", &probe.deprecated, &exp_dep);
    let e04 = family_diff("E04", &probe.permitted, &exp_permitted);

    // Overlays must never surface as W04 drift: an overlay that flipped to
    // `Deprecated option` lands in `w04.added` (excluded from exp_dep); strip it
    // and record the flip as an advisory instead.
    w04.added.retain(|k| !overlay_set.contains(k));

    let mut advisories = Vec::new();
    for kw in CLEAN_PARSE_OVERLAY {
        match verify_overlay(probe.opt_stderr.get(*kw).map(String::as_str)) {
            OverlayVerdict::StillClean => {}
            OverlayVerdict::NowDeprecated => advisories.push(format!(
                "advisory: W04 overlay `{kw}` now emits `Deprecated option` (was clean-parse); \
                 consider reclassifying it as probe-derived"
            )),
            OverlayVerdict::NotProbed => advisories.push(format!(
                "advisory: W04 overlay `{kw}` was not in the transcript; clean-parse unverified"
            )),
        }
    }
    // man-page keyword discovery is a LIVE-only advisory pass (deferred; see
    // TODO(#372-followup) in probe.rs) and is intentionally not run over an
    // offline transcript, so no man-derived advisory is emitted here.

    DriftReport {
        target,
        e01,
        w04,
        e04,
        advisories,
        probe,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transcript::parse_jsonl;

    const RHEL9_FIXTURE: &str = include_str!("../tests/fixtures/rhel9_probe.jsonl");

    fn s(items: &[&str]) -> BTreeSet<String> {
        items.iter().map(|x| (*x).to_string()).collect()
    }

    /// Build a `FamilyDrift` from `+` (added) and `-` (removed) keyword lists.
    fn fam(family: &'static str, added: &[&str], removed: &[&str]) -> FamilyDrift {
        FamilyDrift {
            family,
            added: added.iter().map(|x| (*x).to_string()).collect(),
            removed: removed.iter().map(|x| (*x).to_string()).collect(),
        }
    }

    /// Build a `DriftReport` from three families (empty advisories + probe sets).
    fn mk_report(e01: FamilyDrift, w04: FamilyDrift, e04: FamilyDrift) -> DriftReport {
        DriftReport {
            target: TargetVersion::Rhel9,
            e01,
            w04,
            e04,
            advisories: Vec::new(),
            probe: ProbeSets::default(),
        }
    }

    /// `is_in_sync` is TRUE only when ALL THREE families are empty. The
    /// single-family-drift cases (exactly one non-empty, two empty) are what
    /// distinguish the conjunction from a disjunction: with `||`, one drifting
    /// family + two clean ones would flip the verdict to "in sync".
    #[test]
    fn is_in_sync_requires_every_family_empty() {
        assert!(
            mk_report(
                fam("E01", &[], &[]),
                fam("W04", &[], &[]),
                fam("E04", &[], &[])
            )
            .is_in_sync(),
            "all three empty must be in sync"
        );
        assert!(
            !mk_report(
                fam("E01", &["x"], &[]),
                fam("W04", &[], &[]),
                fam("E04", &[], &[])
            )
            .is_in_sync(),
            "E01-only drift must NOT be in sync"
        );
        assert!(
            !mk_report(
                fam("E01", &[], &[]),
                fam("W04", &["y"], &[]),
                fam("E04", &[], &[])
            )
            .is_in_sync(),
            "W04-only drift must NOT be in sync"
        );
        assert!(
            !mk_report(
                fam("E01", &[], &[]),
                fam("W04", &[], &[]),
                fam("E04", &[], &["z"])
            )
            .is_in_sync(),
            "E04-only drift must NOT be in sync"
        );
    }

    /// `drift_count` sums all SIX family fields. With each of the six fields
    /// holding exactly one keyword the sum must be exactly 6 - this pins the
    /// arithmetic so a whole-fn replacement (0 or 1) or any single `+`->`-`/`+`->`*`
    /// mutation yields a different total.
    #[test]
    fn drift_count_sums_all_six_fields_exactly() {
        let r = mk_report(
            fam("E01", &["a"], &["b"]),
            fam("W04", &["c"], &["d"]),
            fam("E04", &["e"], &["f"]),
        );
        assert_eq!(r.drift_count(), 6);
        let empty = mk_report(
            fam("E01", &[], &[]),
            fam("W04", &[], &[]),
            fam("E04", &[], &[]),
        );
        assert_eq!(empty.drift_count(), 0);
    }

    #[test]
    fn family_diff_reports_both_directions() {
        let probe = s(&["a", "b", "c"]);
        let table = s(&["b", "c", "d"]);
        let d = family_diff("E01", &probe, &table);
        assert_eq!(d.added, vec!["a".to_string()]); // in probe, not table
        assert_eq!(d.removed, vec!["d".to_string()]); // in table, not probe
        assert!(!d.is_empty());
    }

    #[test]
    fn family_diff_empty_when_equal() {
        let set = s(&["x", "y"]);
        assert!(family_diff("E01", &set, &set).is_empty());
    }

    #[test]
    fn classify_splits_opt_and_match() {
        let t = parse_jsonl(
            "{\"kw\":\"good\",\"probe\":\"opt\",\"rc\":0,\"stderr\":\"\"}\n\
             {\"kw\":\"good\",\"probe\":\"match\",\"rc\":0,\"stderr\":\"\"}\n\
             {\"kw\":\"bogus\",\"probe\":\"opt\",\"rc\":255,\"stderr\":\"Bad configuration option: bogus\"}\n\
             {\"kw\":\"bogus\",\"probe\":\"match\",\"rc\":255,\"stderr\":\"Bad configuration option: bogus\"}\n\
             {\"kw\":\"dep\",\"probe\":\"opt\",\"rc\":0,\"stderr\":\"Deprecated option Dep\"}\n\
             {\"kw\":\"dep\",\"probe\":\"match\",\"rc\":0,\"stderr\":\"\"}\n\
             {\"kw\":\"glob\",\"probe\":\"opt\",\"rc\":0,\"stderr\":\"\"}\n\
             {\"kw\":\"glob\",\"probe\":\"match\",\"rc\":255,\"stderr\":\"Directive glob is not allowed within a Match block\"}",
        )
        .unwrap();
        let sets = classify_transcript(&t);
        assert_eq!(sets.known, s(&["good", "dep", "glob"])); // bogus excluded
        assert_eq!(sets.deprecated, s(&["dep"]));
        assert_eq!(sets.permitted, s(&["good", "dep"])); // glob is global-only, not permitted
    }

    /// The committed rhel9 fixture must be 0-drift against the corrected tables -
    /// the same property `validate_probe.py` reports. This is the unit-level
    /// mirror of the cli.rs offline `check` gate.
    #[test]
    fn rhel9_fixture_is_in_sync() {
        let t = parse_jsonl(RHEL9_FIXTURE).unwrap();
        let report = diff_target(&t, TargetVersion::Rhel9);
        assert!(
            report.is_in_sync(),
            "rhel9 fixture must be 0-drift; drift={:?}",
            report.drift_lines()
        );
        // Sanity: the derived sets have the expected cardinalities from the oracle.
        assert_eq!(report.probe.known.len(), 138);
        assert_eq!(report.probe.deprecated.len(), 12);
        assert_eq!(report.probe.permitted.len(), 76);
    }

    /// Dropping a known keyword's recognition (flip its `opt` stderr to
    /// `Bad configuration option`) must produce an E01 `-` drift naming it.
    #[test]
    fn synthesized_e01_removal_is_drift() {
        // acceptenv is a known keyword in the rhel9 fixture; make the daemon
        // "reject" it so the probe no longer confirms the table's entry.
        let mutated = RHEL9_FIXTURE.replacen(
            "{\"kw\": \"acceptenv\", \"probe\": \"opt\", \"rc\": 0, \"stderr\": \"\"}",
            "{\"kw\": \"acceptenv\", \"probe\": \"opt\", \"rc\": 255, \"stderr\": \"command-line line 0: Bad configuration option: acceptenv\"}",
            1,
        );
        assert_ne!(
            mutated, RHEL9_FIXTURE,
            "the fixture line must have been found"
        );
        let report = diff_target(&parse_jsonl(&mutated).unwrap(), TargetVersion::Rhel9);
        assert!(!report.is_in_sync());
        assert!(
            report.e01.removed.contains(&"acceptenv".to_string()),
            "expected acceptenv in E01 removed; got {:?}",
            report.e01
        );
        assert!(report.drift_lines().iter().any(|l| l.contains("acceptenv")));
    }

    /// An overlay that flips to `Deprecated option` is an ADVISORY, not W04 drift:
    /// the report stays in sync and the flip appears in `advisories`.
    #[test]
    fn overlay_flip_is_advisory_not_drift() {
        let mutated = RHEL9_FIXTURE.replacen(
            "{\"kw\": \"protocol\", \"probe\": \"opt\", \"rc\": 0, \"stderr\": \"\"}",
            "{\"kw\": \"protocol\", \"probe\": \"opt\", \"rc\": 0, \"stderr\": \"command-line line 0: Deprecated option Protocol\"}",
            1,
        );
        assert_ne!(
            mutated, RHEL9_FIXTURE,
            "the protocol opt line must have been found"
        );
        let report = diff_target(&parse_jsonl(&mutated).unwrap(), TargetVersion::Rhel9);
        assert!(
            report.is_in_sync(),
            "overlay flip must NOT be gate-failing drift"
        );
        assert!(
            !report.w04.added.contains(&"protocol".to_string()),
            "overlay must not appear as W04 drift"
        );
        assert!(
            report
                .advisories
                .iter()
                .any(|a| a.contains("protocol") && a.contains("Deprecated")),
            "expected a protocol overlay advisory; got {:?}",
            report.advisories
        );
    }
}
