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
//! exactly as the STIG `RHEL*_REQUIRED` tables were. Every table test below
//! therefore FAILS until the implementer fills the tables verbatim from
//! `cis-update derive`.
//!
//! Counts (grounding headers): rhel8 = 25 controls / 66 rule mappings,
//! rhel9 = 24 / 68, rhel10 = 40 / 75; 0 selections for every product.
//!
//! # Attach layer (the CIS->STIG join)
//! The second block of tests pins the `Framework::Cis` finding-attach layer:
//! `lints::cis::cis_controls_for_stig(target, stig_id)` returns the DISTINCT
//! CIS controls (as ready-to-attach `ControlRef`s, `.with_name`'d with the
//! `CaC` title) that join a STIG id under `target`, and every au-W06 finding
//! whose `BaselineRule.stig_id` joins carries exactly those `Framework::Cis`
//! refs ALONGSIDE its existing `Framework::Stig` ref. The join is transcribed
//! VERBATIM from the session's stig-refs grounding
//! (`stig-refs-rhel{8,9,10}-auditd.txt`, `cis-update` at `CaC` pin `519b5fe8`);
//! titles from `derive-rhel{8,9,10}-auditd.txt`. Ground-truth join rows cited
//! inline at each assertion. The accessor is seeded to return an empty `Vec`
//! and `w06` does not attach yet, so every attach test FAILS (RED) until the
//! implementer builds the join and wires it into `w06`.

use std::collections::BTreeSet;

use rulesteward_auditd::lints::cis::{CisControl, cis_baseline, cis_controls_for_stig};
use rulesteward_auditd::lints::stig_required::{stig_baseline, w06};
use rulesteward_auditd::lints::{LintOptions, TargetVersion};
use rulesteward_core::{ControlRef, Diagnostic, Framework};

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

// ===========================================================================
// Attach layer: the CIS->STIG join on au-W06 findings (issue #528, answers
// round 1). `cis_controls_for_stig(target, stig_id)` returns the DISTINCT
// `Framework::Cis` `ControlRef`s (`.with_name`'d with the CaC title) that join
// a STIG id under `target`; `w06(.., Some(target))` attaches them to each
// matching au-W06 finding ALONGSIDE its `Framework::Stig` ref. Every join row
// below is verbatim from `stig-refs-rhel{8,9,10}-auditd.txt`; every title from
// `derive-rhel{8,9,10}-auditd.txt` (both at CaC pin `519b5fe8`).
// ===========================================================================

/// The set of CIS control ids in `refs` (a wrong impl that repeats or drops an
/// id fails the `==` against the grounded set).
fn cis_ids(refs: &[ControlRef]) -> BTreeSet<&str> {
    refs.iter().map(|c| c.id.as_str()).collect()
}

// --- The accessor (pure join): sharp per-case pins ------------------------

#[test]
fn cis_join_rhel10_500810_maps_two_distinct_controls_with_their_titles() {
    // stig-refs-rhel10 rows 60-64: RHEL-10-500810 is joined by FIVE CaC rules
    // spanning TWO distinct CIS controls -- 6.3.3.24 (unlink/unlinkat) and
    // 6.3.3.25 (rename/renameat/renameat2). It is the ONLY multi-distinct-CIS
    // STIG id across all three products (answers round 1), so its finding
    // carries BOTH refs. Titles verbatim from derive-rhel10 rows 61 + 63.
    let refs = cis_controls_for_stig(TargetVersion::Rhel10, "RHEL-10-500810");
    assert_eq!(
        cis_ids(&refs),
        BTreeSet::from(["6.3.3.24", "6.3.3.25"]),
        "RHEL-10-500810 joins exactly 6.3.3.24 + 6.3.3.25: {refs:?}"
    );
    assert_eq!(
        refs.len(),
        2,
        "no duplicate control id -- exactly two distinct refs: {refs:?}"
    );
    for c in &refs {
        assert_eq!(c.framework, Framework::Cis, "{c:?}");
        assert!(c.alias.is_none(), "CIS refs carry no secondary id: {c:?}");
    }
    let title = |id| {
        refs.iter()
            .find(|c| c.id == id)
            .and_then(|c| c.name.as_deref())
    };
    assert_eq!(
        title("6.3.3.24"),
        Some("Ensure unlink file deletion events by users are collected (Automated)")
    );
    assert_eq!(
        title("6.3.3.25"),
        Some("Ensure rename file deletion events by users are collected (Automated)")
    );
}

#[test]
fn cis_join_dedups_multiple_rows_sharing_one_control() {
    // stig-refs-rhel8 rows 19-23: FIVE CaC rules
    // (creat/ftruncate/open/openat/truncate) all map RHEL-08-030420 to the
    // SAME CIS control 6.3.3.7, so the join dedups to ONE ref. Title verbatim
    // from derive-rhel8 row 20.
    let refs = cis_controls_for_stig(TargetVersion::Rhel8, "RHEL-08-030420");
    assert_eq!(
        refs.len(),
        1,
        "five join rows collapse to one distinct CIS control: {refs:?}"
    );
    assert_eq!(refs[0].framework, Framework::Cis);
    assert_eq!(refs[0].id, "6.3.3.7");
    assert!(refs[0].alias.is_none());
    assert_eq!(
        refs[0].name.as_deref(),
        Some("Ensure unsuccessful file access attempts are collected (Automated)")
    );
}

#[test]
fn cis_join_immutable_control_diverges_per_product() {
    // The audit_rules_immutable requirement joins a DIFFERENT CIS id per
    // product (the table divergence, now via the join):
    //   rhel8  RHEL-08-030121 -> 6.3.3.21 (stig-refs-rhel8 row 68)
    //   rhel9  RHEL-09-654275 -> 6.3.3.20 (stig-refs-rhel9 row 70)
    // Same CaC title both products (derive rows: rhel8 69 / rhel9 71).
    let r8 = cis_controls_for_stig(TargetVersion::Rhel8, "RHEL-08-030121");
    assert_eq!(r8.len(), 1, "{r8:?}");
    assert_eq!(r8[0].framework, Framework::Cis);
    assert_eq!(r8[0].id, "6.3.3.21");
    assert_eq!(
        r8[0].name.as_deref(),
        Some("Ensure the audit configuration is immutable (Automated)")
    );

    let r9 = cis_controls_for_stig(TargetVersion::Rhel9, "RHEL-09-654275");
    assert_eq!(r9.len(), 1, "{r9:?}");
    assert_eq!(r9[0].framework, Framework::Cis);
    assert_eq!(r9[0].id, "6.3.3.20");
    assert_eq!(
        r9[0].name.as_deref(),
        Some("Ensure the audit configuration is immutable (Automated)")
    );
}

#[test]
fn cis_join_is_product_specific() {
    // A rhel10-only STIG id joins under rhel10 (this positive anchor keeps the
    // test RED pre-impl) but is ABSENT from the rhel8/rhel9 joins -- the join
    // is read from the target's own controls/stig_<p>.yml, never a shared
    // superset.
    assert_eq!(
        cis_controls_for_stig(TargetVersion::Rhel10, "RHEL-10-500810").len(),
        2,
        "rhel10 RHEL-10-500810 joins two CIS controls"
    );
    assert!(
        cis_controls_for_stig(TargetVersion::Rhel8, "RHEL-10-500810").is_empty(),
        "a rhel10 STIG id must not join under rhel8"
    );
    assert!(
        cis_controls_for_stig(TargetVersion::Rhel9, "RHEL-10-500810").is_empty(),
        "a rhel10 STIG id must not join under rhel9"
    );
}

#[test]
fn cis_join_never_repeats_a_control_id_and_is_well_shaped() {
    // Over EVERY shipped au-W06 baseline row of every product: the join never
    // repeats a control id within one finding (the no-duplicate-cis_id
    // invariant), and every returned ref is a titled CIS ref with no secondary
    // id. The `total > 0` guard keeps this RED pre-impl (an empty stub joins
    // nothing) rather than vacuously green over an all-empty join.
    let mut total = 0usize;
    for target in [
        TargetVersion::Rhel8,
        TargetVersion::Rhel9,
        TargetVersion::Rhel10,
    ] {
        for r in stig_baseline(target) {
            let refs = cis_controls_for_stig(target, r.stig_id);
            total += refs.len();
            assert_eq!(
                cis_ids(&refs).len(),
                refs.len(),
                "{target:?} {}: CIS join must not repeat a control id: {refs:?}",
                r.stig_id
            );
            for c in &refs {
                assert_eq!(
                    c.framework,
                    Framework::Cis,
                    "join yields only CIS refs: {c:?}"
                );
                assert!(
                    c.name.is_some(),
                    "every CIS ref carries a .with_name title: {c:?}"
                );
                assert!(c.alias.is_none(), "CIS refs have no secondary id: {c:?}");
            }
        }
    }
    assert!(
        total > 0,
        "expected some au-W06 findings to join CIS controls across the three products"
    );
}

// --- End-to-end: the join flows through w06(.., Some(target)) -------------

/// Every au-W06 diagnostic from `w06` whose `Framework::Stig` `ControlRef` id
/// == `stig_id`. A bare (empty) ruleset makes every shipped required line
/// missing, so the finding for `stig_id` is present.
fn findings_for<'a>(diags: &'a [Diagnostic], stig_id: &str) -> Vec<&'a Diagnostic> {
    diags
        .iter()
        .filter(|d| {
            d.controls
                .iter()
                .any(|c| c.framework == Framework::Stig && c.id == stig_id)
        })
        .collect()
}

fn cis_of(d: &Diagnostic) -> Vec<&ControlRef> {
    d.controls
        .iter()
        .filter(|c| c.framework == Framework::Cis)
        .collect()
}

#[test]
fn w06_rhel10_500810_finding_carries_both_cis_refs_and_keeps_its_stig_ref() {
    // The real crate entrypoint: a bare ruleset is missing every shipped
    // RHEL10_REQUIRED line, so the RHEL-10-500810 finding fires. It must KEEP
    // its Framework::Stig ref AND gain BOTH joined Framework::Cis refs
    // (6.3.3.24 + 6.3.3.25) with their CaC titles -- proving the join wires
    // through w06 onto a real Diagnostic (not just the pure accessor). w06's
    // CIS attach must live in w06 (the only entrypoint with the target), not in
    // w06_with_baseline (the frozen control-ref tests in
    // test_lints_stig_required.rs assert controls.len()==1 there).
    let diags = w06(&[], LintOptions::default(), Some(TargetVersion::Rhel10));
    let findings = findings_for(&diags, "RHEL-10-500810");
    assert!(
        !findings.is_empty(),
        "the shipped RHEL10_REQUIRED table must yield a RHEL-10-500810 finding on a bare ruleset"
    );
    for d in findings {
        assert_eq!(d.code, "au-W06");
        let cis = cis_of(d);
        let ids: BTreeSet<&str> = cis.iter().map(|c| c.id.as_str()).collect();
        assert_eq!(
            ids,
            BTreeSet::from(["6.3.3.24", "6.3.3.25"]),
            "the RHEL-10-500810 finding must carry both joined CIS controls: {d:?}"
        );
        let title = |id| {
            cis.iter()
                .find(|c| c.id == id)
                .and_then(|c| c.name.as_deref())
        };
        assert_eq!(
            title("6.3.3.24"),
            Some("Ensure unlink file deletion events by users are collected (Automated)"),
            "{d:?}"
        );
        assert_eq!(
            title("6.3.3.25"),
            Some("Ensure rename file deletion events by users are collected (Automated)"),
            "{d:?}"
        );
        assert!(
            d.controls
                .iter()
                .any(|c| c.framework == Framework::Stig && c.id == "RHEL-10-500810"),
            "the finding must KEEP its Framework::Stig ref (CIS is added, not substituted): {d:?}"
        );
    }
}

#[test]
fn w06_rhel8_immutable_finding_carries_its_single_cis_ref() {
    // The common 1:1 case through the real entrypoint: RHEL-08-030121
    // (audit_rules_immutable) joins exactly 6.3.3.21 under rhel8. Every such
    // finding gains that one titled CIS ref alongside its Stig ref.
    let diags = w06(&[], LintOptions::default(), Some(TargetVersion::Rhel8));
    let findings = findings_for(&diags, "RHEL-08-030121");
    assert!(
        !findings.is_empty(),
        "the shipped RHEL8_REQUIRED table must yield a RHEL-08-030121 finding on a bare ruleset"
    );
    for d in findings {
        let cis = cis_of(d);
        assert_eq!(cis.len(), 1, "one joined CIS control: {d:?}");
        assert_eq!(cis[0].id, "6.3.3.21", "{d:?}");
        assert_eq!(
            cis[0].name.as_deref(),
            Some("Ensure the audit configuration is immutable (Automated)"),
            "{d:?}"
        );
    }
}
