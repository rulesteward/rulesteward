//! Compare a derived attribute registry (from [`crate::parse`]) against the
//! shipped `rulesteward_fapolicyd::attrs` consts, per the two-part drift
//! contract fixed for issue #479:
//!
//! 1. NAME-LEVEL: the UNION of derived names across ALL pinned fapolicyd
//!    versions must equal the union of the shipped `SUBJECT_ONLY` /
//!    `OBJECT_ONLY` / `BOTH_SIDES` consts ([`name_drift`]).
//! 2. SIDE-LEVEL: the derived side classification at the NEWEST pinned version
//!    (1.4.5 today) must match the shipped split ([`side_drift`]).
//!
//! The side check is deliberately scoped to ONE version, not a union: fapolicyd
//! 1.3.2's `subject-attr.c` `table2` still carries `device` (via the
//! `EXE_DEVICE` alias row `{EXE_DEVICE, "device"}`), so on 1.3.2 `device` is
//! `Side::Both`, not the shipped `OBJECT_ONLY`. That row was DROPPED from
//! `table2` in 1.4.5 (see `src/library/subject-attr.c` at each pinned tag - the
//! 1.3.2 fixture has a 14-row `table2`, the 1.4.5 fixture has 13; the missing
//! row is exactly `{EXE_DEVICE, "device"}`). A union-across-versions side
//! comparison would therefore flag `device` as permanently drifted even though
//! the shipped `OBJECT_ONLY` classification is deliberately the CURRENT
//! (1.4.5-and-newer) view - see `device_1_3_2_nuance_is_deliberately_excluded_from_side_check`
//! below, which demonstrates the 1.3.2-vs-shipped side disagreement directly.

use std::collections::BTreeSet;

use crate::parse::DerivedAttr;

/// Project the shipped `rulesteward_fapolicyd::attrs` consts
/// (`SUBJECT_ONLY` / `OBJECT_ONLY` / `BOTH_SIDES`) into [`DerivedAttr`]s, for
/// comparison against a derived (parsed-from-C) registry.
pub fn shipped_registry() -> Vec<DerivedAttr> {
    todo!(
        "project rulesteward_fapolicyd::attrs SUBJECT_ONLY/OBJECT_ONLY/BOTH_SIDES into DerivedAttr"
    )
}

/// Symmetric difference of attribute NAMES between `derived` (already unioned
/// across every pinned version by the caller) and `shipped` (side-agnostic).
/// Empty == no name drift. Each returned line names the attribute and which
/// side of the comparison it is missing from.
#[must_use]
pub fn name_drift(derived: &BTreeSet<String>, shipped: &BTreeSet<String>) -> Vec<String> {
    let _ = (derived, shipped);
    todo!("symmetric set difference, one line per differing name")
}

/// For names present in BOTH `derived` and `shipped`, lines describing every
/// case where the derived side classification disagrees with the shipped one.
/// A name missing from one side entirely is [`name_drift`]'s concern, not this
/// function's - it is silently skipped here (deliberately: reporting it again
/// would double-report the same underlying drift under two different messages).
#[must_use]
pub fn side_drift(derived: &[DerivedAttr], shipped: &[DerivedAttr]) -> Vec<String> {
    let _ = (derived, shipped);
    todo!("for names present in both, report a line for every Side disagreement")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::{self, DerivedAttr, Side};

    const SUBJECT_1_3_2: &str = include_str!("../tests/fixtures/1.3.2/subject-attr.c");
    const OBJECT_1_3_2: &str = include_str!("../tests/fixtures/1.3.2/object-attr.c");
    const SUBJECT_1_4_5: &str = include_str!("../tests/fixtures/1.4.5/subject-attr.c");
    const OBJECT_1_4_5: &str = include_str!("../tests/fixtures/1.4.5/object-attr.c");

    /// Parse one pinned version's fixture pair into the final classified registry
    /// (mirrors `parse`'s own private `derive` test helper - duplicated here
    /// rather than shared across modules, matching `tools/stig-update`'s
    /// per-module `#[cfg(test)]` convention of self-contained test helpers).
    fn derive(subject_src: &str, object_src: &str) -> Vec<DerivedAttr> {
        let subject = parse::parse_subject_table2(subject_src).expect("subject parses");
        let object_literal = parse::parse_object_table(object_src).expect("object parses");
        let object = parse::apply_object_alias_exceptions(object_literal);
        parse::classify(&subject, &object)
    }

    fn mk(name: &str, side: Side) -> DerivedAttr {
        DerivedAttr {
            name: name.to_string(),
            side,
        }
    }

    /// Sanity check on [`shipped_registry`] itself: it must reproduce the exact
    /// 18-name / 9-5-4 split documented in `attrs.rs` (see
    /// `crates/rulesteward-fapolicyd/src/attrs.rs` lines 40-57). Guards against a
    /// wrong projection (e.g. swapping `SUBJECT_ONLY`/`OBJECT_ONLY`, or dropping
    /// `BOTH_SIDES` entirely).
    #[test]
    fn shipped_registry_matches_the_documented_split() {
        let shipped = shipped_registry();
        assert_eq!(shipped.len(), 18, "{shipped:?}");
        let subject_only: Vec<&str> = shipped
            .iter()
            .filter(|a| a.side == Side::Subject)
            .map(|a| a.name.as_str())
            .collect();
        let object_only: Vec<&str> = shipped
            .iter()
            .filter(|a| a.side == Side::Object)
            .map(|a| a.name.as_str())
            .collect();
        let both: Vec<&str> = shipped
            .iter()
            .filter(|a| a.side == Side::Both)
            .map(|a| a.name.as_str())
            .collect();
        assert_eq!(subject_only.len(), 9, "{subject_only:?}");
        assert_eq!(object_only.len(), 5, "{object_only:?}");
        assert_eq!(both.len(), 4, "{both:?}");
        assert!(subject_only.contains(&"pattern"));
        assert!(object_only.contains(&"filehash"));
        assert!(object_only.contains(&"sha256hash"));
        assert!(both.contains(&"trust"));
    }

    /// GREEN-case (design decision #1a): the union of derived NAMES across BOTH
    /// pinned versions (1.3.2's 17 + 1.4.5's 18, with 1.3.2 a strict subset)
    /// equals the shipped union exactly - reading the REAL `attrs.rs` consts via
    /// the path-dep, not a copy. A wrong impl that hardcodes an 18-name list
    /// independent of `attrs.rs` would pass today but silently stop catching a
    /// real future `attrs.rs` edit; this test's use of [`shipped_registry`]
    /// (which reads the real consts) is what makes it a genuine drift guard.
    #[test]
    fn name_union_across_1_3_2_and_1_4_5_matches_shipped() {
        let d132 = derive(SUBJECT_1_3_2, OBJECT_1_3_2);
        let d145 = derive(SUBJECT_1_4_5, OBJECT_1_4_5);
        let mut union = parse::names(&d132);
        union.extend(parse::names(&d145));

        let shipped_names: BTreeSet<String> = parse::names(&shipped_registry());

        let drift = name_drift(&union, &shipped_names);
        assert!(
            drift.is_empty(),
            "the derived name union must match the shipped registry with 0 drift: {drift:?}"
        );
    }

    /// GREEN-case (design decision #1b): the derived 1.4.5 SIDE classification
    /// matches the shipped `SUBJECT_ONLY`/`OBJECT_ONLY`/`BOTH_SIDES` split
    /// exactly (name-for-name, side-for-side). Deliberately uses ONLY 1.4.5 - see
    /// the module doc comment for why 1.3.2 is excluded from this check.
    #[test]
    fn side_drift_1_4_5_matches_shipped_exactly() {
        let d145 = derive(SUBJECT_1_4_5, OBJECT_1_4_5);
        let drift = side_drift(&d145, &shipped_registry());
        assert!(
            drift.is_empty(),
            "1.4.5's derived side split must match the shipped registry with 0 drift: {drift:?}"
        );
    }

    /// Documents (and pins) WHY the side-drift check is scoped to 1.4.5 only: run
    /// directly against 1.3.2, `side_drift` must find exactly the known
    /// `device` disagreement (derived `Both` vs shipped `Object`) - proving the
    /// scoping decision is deliberate and grounded, not an accidental omission.
    /// If upstream ever restores `EXE_DEVICE` to a future `table2`, or the
    /// shipped registry's `device` classification changes, this test's exact
    /// drift line will need revisiting (a signal to re-examine the scoping, not
    /// silently soften an assertion).
    #[test]
    fn device_1_3_2_nuance_is_deliberately_excluded_from_side_check() {
        let d132 = derive(SUBJECT_1_3_2, OBJECT_1_3_2);
        let drift = side_drift(&d132, &shipped_registry());
        assert!(
            drift.iter().any(|l| l.contains("device")),
            "1.3.2 vs shipped side_drift must name `device` (Both vs shipped Object): {drift:?}"
        );
    }

    /// `name_drift` on a synthetic renamed entry (one table row renamed, as if
    /// upstream dropped/renamed an attribute) must be non-empty and name the
    /// offending attribute - mirrors `tools/stig-update`'s
    /// `diff_tables_flags_hand_edited_stale_baseline_as_drift` precedent.
    /// Anti-vacuity: an identical pair must report ZERO drift, proving the
    /// non-empty result above detects the injected divergence and is not a
    /// `name_drift` bug that always reports drift regardless of input.
    #[test]
    fn name_drift_detects_a_renamed_attribute() {
        let shipped: BTreeSet<String> = ["all", "auid", "trust"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let mut mutated = shipped.clone();
        mutated.remove("trust");
        mutated.insert("trustx".to_string());

        let drift = name_drift(&mutated, &shipped);
        assert!(
            !drift.is_empty(),
            "a renamed attribute must produce non-empty drift"
        );
        assert!(
            drift.iter().any(|l| l.contains("trust")),
            "the drift must name the offending attribute (trust/trustx): {drift:?}"
        );
        assert!(
            name_drift(&shipped, &shipped).is_empty(),
            "an identical pair must report zero drift"
        );
    }

    /// `side_drift` on a synthetic side change (one attribute demoted from
    /// `Both` to `Subject`, as if a table row were dropped from the object side)
    /// must be non-empty and name the offending attribute. Anti-vacuity mirrors
    /// the name_drift test above.
    #[test]
    fn side_drift_detects_a_side_change() {
        let shipped = vec![
            mk("all", Side::Both),
            mk("trust", Side::Both),
            mk("uid", Side::Subject),
        ];
        let mut mutated = shipped.clone();
        let idx = mutated.iter().position(|a| a.name == "trust").unwrap();
        mutated[idx].side = Side::Subject; // simulates dropping the OBJ_TRUST object-table row

        let drift = side_drift(&mutated, &shipped);
        assert!(
            !drift.is_empty(),
            "a side change must produce non-empty drift"
        );
        assert!(
            drift.iter().any(|l| l.contains("trust")),
            "the drift must name the offending attribute: {drift:?}"
        );
        assert!(
            side_drift(&shipped, &shipped).is_empty(),
            "an identical pair must report zero side drift"
        );
    }
}
