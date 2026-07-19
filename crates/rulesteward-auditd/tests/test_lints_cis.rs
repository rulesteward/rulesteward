//! RED barrier tests for the per-product auditd CIS control table (issue #528),
//! milestone 9f-v0_8-wave3-cis.
//!
//! Behavior pinned: `lints::cis::cis_baseline(TargetVersion)` returns the
//! grounded per-RHEL-major CIS control rows -- one [`CisControl`] per
//! `ComplianceAsCode` audit rule, carrying the CIS control id, the `CaC` rule
//! name, and the one-line `CaC` title. Every id/title asserted below is
//! transcribed VERBATIM from the session grounding
//! (`derive-rhel{8,9,10}-auditd.txt`, `cis-update derive` at `CaC` pin
//! `519b5fe8`); none is from recall.
//!
//! # RED-state note
//! The three shipped tables (`RHEL8_CIS`/`RHEL9_CIS`/`RHEL10_CIS`) are seeded
//! EMPTY at the test-author barrier (see `src/lints/cis.rs`'s module doc),
//! exactly as the STIG `RHEL*_REQUIRED` tables were. Every test below therefore
//! FAILS until the implementer fills the tables verbatim from `cis-update
//! derive`. These tests only cover the TABLE (`cis_baseline`); the
//! `Framework::Cis` finding-attach layer is authored in a follow-up once its
//! join mechanism is resolved (see the lane's returned LOCAL question).
//!
//! Counts (grounding headers): rhel8 = 25 controls / 66 rule mappings,
//! rhel9 = 24 / 68, rhel10 = 40 / 75; 0 selections for every product.

use std::collections::BTreeSet;

use rulesteward_auditd::lints::TargetVersion;
use rulesteward_auditd::lints::cis::{CisControl, cis_baseline};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// The `(control_id, title)` for the single row whose `cac_rule` matches, or a
/// panic naming the missing rule (so a wrong/short table fails loudly rather
/// than silently skipping the assertion).
fn row_for_cac<'a>(table: &'a [CisControl], cac_rule: &str) -> &'a CisControl {
    table
        .iter()
        .find(|c| c.cac_rule == cac_rule)
        .unwrap_or_else(|| panic!("CIS table is missing the `{cac_rule}` rule mapping"))
}

fn control_ids(table: &[CisControl]) -> BTreeSet<&'static str> {
    table.iter().map(|c| c.control_id).collect()
}

// ---------------------------------------------------------------------------
// Per-product grounded membership (ids + titles straight from grounding)
// ---------------------------------------------------------------------------

#[test]
fn cis_baseline_rhel8_has_grounded_rows() {
    let t = cis_baseline(TargetVersion::Rhel8);
    assert!(!t.is_empty(), "rhel8 CIS table must be populated");

    let r = row_for_cac(t, "auditd_data_retention_max_log_file");
    assert_eq!(r.control_id, "6.3.2.1");
    assert_eq!(
        r.title,
        "Ensure audit log storage size is configured (Automated)"
    );

    let r = row_for_cac(t, "audit_rules_usergroup_modification_shadow");
    assert_eq!(r.control_id, "6.3.3.8");
    assert_eq!(
        r.title,
        "Ensure events that modify user/group information are collected (Automated)"
    );

    // Immutable-config control: rhel8 numbers it 6.3.3.21 (diverges per product).
    let r = row_for_cac(t, "audit_rules_immutable");
    assert_eq!(r.control_id, "6.3.3.21");
    assert_eq!(
        r.title,
        "Ensure the audit configuration is immutable (Automated)"
    );
}

#[test]
fn cis_baseline_rhel9_has_grounded_rows() {
    let t = cis_baseline(TargetVersion::Rhel9);
    assert!(!t.is_empty(), "rhel9 CIS table must be populated");

    let r = row_for_cac(t, "auditd_data_retention_max_log_file");
    assert_eq!(r.control_id, "6.3.2.1");
    assert_eq!(
        r.title,
        "Ensure audit log storage size is configured (Automated)"
    );

    let r = row_for_cac(t, "audit_rules_usergroup_modification_shadow");
    assert_eq!(r.control_id, "6.3.3.8");

    // Immutable-config control: rhel9 numbers it 6.3.3.20 (NOT rhel8's 6.3.3.21).
    let r = row_for_cac(t, "audit_rules_immutable");
    assert_eq!(r.control_id, "6.3.3.20");
    assert_eq!(
        r.title,
        "Ensure the audit configuration is immutable (Automated)"
    );
}

#[test]
fn cis_baseline_rhel10_has_grounded_rows() {
    let t = cis_baseline(TargetVersion::Rhel10);
    assert!(!t.is_empty(), "rhel10 CIS table must be populated");

    let r = row_for_cac(t, "auditd_data_retention_max_log_file");
    assert_eq!(r.control_id, "6.3.2.1");

    // Immutable-config control: rhel10 numbers it 6.3.3.36 (NOT 6.3.3.21/.20).
    let r = row_for_cac(t, "audit_rules_immutable");
    assert_eq!(r.control_id, "6.3.3.36");
    assert_eq!(
        r.title,
        "Ensure the audit configuration is immutable (Automated)"
    );

    // rhel10 renumbered the session-events control to 6.3.3.22 (rhel8/9 use
    // 6.3.3.11) and its DAC-modification control to 6.3.3.18.
    let r = row_for_cac(t, "audit_rules_session_events_utmp");
    assert_eq!(r.control_id, "6.3.3.22");
    assert_eq!(
        r.title,
        "Ensure session initiation information is collected (Automated)"
    );
}

// ---------------------------------------------------------------------------
// Cross-product divergence (a wrong impl that shares one table must FAIL)
// ---------------------------------------------------------------------------

#[test]
fn cis_baseline_immutable_control_id_diverges_per_product() {
    // Same CaC rule, three different CIS ids -- forces genuinely per-product
    // tables and forbids a shared/hardcoded id.
    let id = |t| row_for_cac(cis_baseline(t), "audit_rules_immutable").control_id;
    assert_eq!(id(TargetVersion::Rhel8), "6.3.3.21");
    assert_eq!(id(TargetVersion::Rhel9), "6.3.3.20");
    assert_eq!(id(TargetVersion::Rhel10), "6.3.3.36");
}

#[test]
fn cis_baseline_rhel10_only_session_events_control() {
    // 6.3.3.22 (session-events) exists ONLY in rhel10; rhel8/9 do not carry it.
    let r10 = control_ids(cis_baseline(TargetVersion::Rhel10));
    assert!(
        r10.contains("6.3.3.22"),
        "rhel10 CIS must include the 6.3.3.22 session-events control"
    );
    let r8 = control_ids(cis_baseline(TargetVersion::Rhel8));
    let r9 = control_ids(cis_baseline(TargetVersion::Rhel9));
    assert!(
        !r8.contains("6.3.3.22"),
        "6.3.3.22 is rhel10-only; it must be absent from rhel8"
    );
    assert!(
        !r9.contains("6.3.3.22"),
        "6.3.3.22 is rhel10-only; it must be absent from rhel9"
    );
}

#[test]
fn cis_baseline_rhel10_only_fchmodat2_rule_mapping() {
    // The fchmodat2 DAC-modification rule mapping is a rhel10-only cac_rule
    // (rhel8/9 predate the fchmodat2 syscall row).
    let has = |t| {
        cis_baseline(t)
            .iter()
            .any(|c| c.cac_rule == "audit_rules_dac_modification_fchmodat2")
    };
    assert!(has(TargetVersion::Rhel10), "rhel10 must carry fchmodat2");
    assert!(
        !has(TargetVersion::Rhel8),
        "fchmodat2 rule is rhel10-only; absent from rhel8"
    );
    assert!(
        !has(TargetVersion::Rhel9),
        "fchmodat2 rule is rhel10-only; absent from rhel9"
    );
}

// ---------------------------------------------------------------------------
// Counts + shape invariants (grounding headers; 0 selections)
// ---------------------------------------------------------------------------

#[test]
fn cis_baseline_rule_mapping_and_control_counts() {
    // Rule-mapping row counts and distinct-control counts, straight from the
    // grounding headers.
    let cases = [
        (TargetVersion::Rhel8, 66usize, 25usize),
        (TargetVersion::Rhel9, 68, 24),
        (TargetVersion::Rhel10, 75, 40),
    ];
    for (target, rows, controls) in cases {
        let t = cis_baseline(target);
        assert_eq!(t.len(), rows, "{target:?}: rule-mapping row count");
        assert_eq!(
            control_ids(t).len(),
            controls,
            "{target:?}: distinct control-id count"
        );
    }
}

#[test]
fn cis_baseline_title_is_consistent_within_a_control() {
    // Every rule mapping sharing a control_id shares one title (a CaC-derived
    // invariant that holds for all three products). Non-empty guard keeps this
    // RED pre-impl rather than vacuously green over an empty table.
    for target in [
        TargetVersion::Rhel8,
        TargetVersion::Rhel9,
        TargetVersion::Rhel10,
    ] {
        let t = cis_baseline(target);
        assert!(!t.is_empty(), "{target:?}: CIS table must be populated");
        for row in t {
            let mut titles = t
                .iter()
                .filter(|c| c.control_id == row.control_id)
                .map(|c| c.title);
            let first = titles.next().expect("at least this row");
            assert!(
                titles.all(|x| x == first),
                "{target:?}: control {} has inconsistent titles",
                row.control_id
            );
        }
    }
}
