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

    // Two rows whose grounding was regenerated clean (answers round 1). The
    // sysadmin-actions title carries NO stray "894" suffix (a source-fixed
    // transcription artifact) and phrases rhel8's exact wording ("changes to
    // system administration scope (sudoers)"), which rhel10 renumbers AND
    // rewords -- so a table copied from a sibling product fails here.
    // (derive-rhel8 row 10.)
    let r = row_for_cac(t, "audit_rules_sysadmin_actions");
    assert_eq!(r.control_id, "6.3.3.1");
    assert_eq!(
        r.title,
        "Ensure changes to system administration scope (sudoers) is collected (Automated)"
    );

    // usermod: rhel8 numbers it 6.3.3.18 (the upstream "6.6.3.18" typo was
    // corrected at source) and phrases the title "... are recorded ..."
    // (rhel9/rhel10 say "... collected ..."). (derive-rhel8 row 61.)
    let r = row_for_cac(t, "audit_rules_privileged_commands_usermod");
    assert_eq!(r.control_id, "6.3.3.18");
    assert_eq!(
        r.title,
        "Ensure successful and unsuccessful attempts to use the usermod command are recorded (Automated)"
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
fn cis_baseline_usermod_title_diverges_rhel8_vs_rhel10() {
    // The usermod control's CaC TITLE (not just its id) diverges per product:
    // rhel8 says "... are recorded ..."; rhel10 says "... are collected ...".
    // This forces the rhel8 table to carry rhel8's exact (regenerated) wording
    // rather than a copy of a sibling product's, complementing the immutable
    // test (same title, divergent id) with the mirror case (divergent title).
    // (derive-rhel8 row 61 vs derive-rhel10 row 71.)
    let title = |t| row_for_cac(cis_baseline(t), "audit_rules_privileged_commands_usermod").title;
    assert_eq!(
        title(TargetVersion::Rhel8),
        "Ensure successful and unsuccessful attempts to use the usermod command are recorded (Automated)"
    );
    assert_eq!(
        title(TargetVersion::Rhel10),
        "Ensure successful and unsuccessful attempts to use the usermod command are collected (Automated)"
    );
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
fn cis_join_one_control_maps_multiple_distinct_stig_ids() {
    // The complementary many-shape (answers round 1): ONE CIS control is the
    // join target of SEVERAL distinct STIG ids. rhel8 6.3.3.8 (user/group
    // modification) is joined by five separate STIG rules -- RHEL-08-030130 /
    // 030140 / 030150 / 030160 / 030170 (stig-refs-rhel8 rows 24-28). Each of
    // those findings therefore carries exactly the single 6.3.3.8 ref with the
    // one shared CaC title (derive-rhel8 row 25). Asserting three of them keeps
    // this a pure-accessor pin independent of baseline membership.
    for stig in ["RHEL-08-030130", "RHEL-08-030150", "RHEL-08-030170"] {
        let refs = cis_controls_for_stig(TargetVersion::Rhel8, stig);
        assert_eq!(
            refs.len(),
            1,
            "{stig} joins exactly one CIS control: {refs:?}"
        );
        assert_eq!(refs[0].framework, Framework::Cis);
        assert_eq!(refs[0].id, "6.3.3.8", "{stig} joins CIS 6.3.3.8: {refs:?}");
        assert_eq!(
            refs[0].name.as_deref(),
            Some("Ensure events that modify user/group information are collected (Automated)"),
            "{stig}"
        );
        assert!(refs[0].alias.is_none(), "{stig}");
    }
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
fn cis_join_rhel9_more_distinct_anchors() {
    // Two MORE distinct rhel9 join anchors beyond the immutable pin (answers
    // round-1 adversarial ask; rhel9 previously had exactly one pinned distinct
    // case). Each is a specific STIG id -> single CIS control with its verbatim
    // CaC title:
    //   RHEL-09-654015 -> 6.3.3.9  (dac chmod/fchmod/fchmodat all collapse to
    //     one control; stig-refs-rhel9 rows 35/37/38; title derive-rhel9 6.3.3.9)
    //   RHEL-09-654250 -> 6.3.3.12 (login/faillock; stig-refs-rhel9 row 52;
    //     title derive-rhel9 6.3.3.12)
    let a = cis_controls_for_stig(TargetVersion::Rhel9, "RHEL-09-654015");
    assert_eq!(a.len(), 1, "{a:?}");
    assert_eq!(a[0].framework, Framework::Cis);
    assert_eq!(a[0].id, "6.3.3.9");
    assert!(a[0].alias.is_none());
    assert_eq!(
        a[0].name.as_deref(),
        Some(
            "Ensure discretionary access control permission modification events are collected (Automated)"
        )
    );

    let b = cis_controls_for_stig(TargetVersion::Rhel9, "RHEL-09-654250");
    assert_eq!(b.len(), 1, "{b:?}");
    assert_eq!(b[0].framework, Framework::Cis);
    assert_eq!(b[0].id, "6.3.3.12");
    assert!(b[0].alias.is_none());
    assert_eq!(
        b[0].name.as_deref(),
        Some("Ensure login and logout events are collected (Automated)")
    );
}

#[test]
fn cis_join_rhel10_more_distinct_anchors() {
    // Two MORE distinct rhel10 join anchors beyond RHEL-10-500810 (answers
    // round-1 adversarial ask; rhel10 previously had exactly one pinned distinct
    // case). rhel10 renumbers these (dac=6.3.3.18, login=6.3.3.23) AND rewords
    // the dac title to enumerate the syscalls, so a table copied from rhel8/9
    // fails here:
    //   RHEL-10-500780 -> 6.3.3.18 (dac chmod/fchmod/fchmodat/fchmodat2 collapse
    //     to one control; stig-refs-rhel10 rows 40-43; title derive-rhel10 6.3.3.18)
    //   RHEL-10-500750 -> 6.3.3.23 (login/faillock; stig-refs-rhel10 row 58;
    //     title derive-rhel10 6.3.3.23)
    let a = cis_controls_for_stig(TargetVersion::Rhel10, "RHEL-10-500780");
    assert_eq!(a.len(), 1, "{a:?}");
    assert_eq!(a[0].framework, Framework::Cis);
    assert_eq!(a[0].id, "6.3.3.18");
    assert!(a[0].alias.is_none());
    assert_eq!(
        a[0].name.as_deref(),
        Some(
            "Ensure discretionary access control permission modification events chmod,fchmod,fchmodat,fchmodat2 are collected (Automated)"
        )
    );

    let b = cis_controls_for_stig(TargetVersion::Rhel10, "RHEL-10-500750");
    assert_eq!(b.len(), 1, "{b:?}");
    assert_eq!(b[0].framework, Framework::Cis);
    assert_eq!(b[0].id, "6.3.3.23");
    assert!(b[0].alias.is_none());
    assert_eq!(
        b[0].name.as_deref(),
        Some("Ensure login and logout events are collected (Automated)")
    );
}

#[test]
fn cis_join_is_grounded_complete_and_well_shaped() {
    // GROUNDED per-product completeness -- the backstop for the round-1
    // adversarial survivor. Over every DISTINCT au-W06 stig id shipped in
    // `stig_baseline`, both (a) the number of ids carrying a non-empty CIS join
    // and (b) the total distinct CIS refs across them must equal the numbers
    // derived mechanically by intersecting each product's
    // `stig-refs-rhel{8,9,10}-auditd.txt` joined ids with its `RHEL*_REQUIRED`
    // table (transcribed from that computation, never recalled):
    //   rhel8  : 21 joined stig ids, 21 CIS refs  (no multi-CIS id)
    //   rhel9  : 20 joined stig ids, 20 CIS refs  (no multi-CIS id)
    //   rhel10 : 21 joined stig ids, 22 CIS refs  (RHEL-10-500810 -> 2 controls)
    // A wrong impl that hardcodes only the individually-pinned stig ids and
    // returns empty for the rest passes every per-id attach test yet FAILS these
    // counts -- exactly the survivor the round-1 adversarial review flagged (no
    // other backstop exists: cis-check is ids-only and mutation cannot detect a
    // missing join entry). Per-finding well-shapedness (no repeated control id;
    // every ref is a titled CIS ref with no secondary id) is checked alongside.
    let cases = [
        (TargetVersion::Rhel8, 21usize, 21usize),
        (TargetVersion::Rhel9, 20, 20),
        (TargetVersion::Rhel10, 21, 22),
    ];
    for (target, want_joined_ids, want_total_refs) in cases {
        // Distinct so a stig id borne by several BaselineRule rows is counted
        // once (join is a pure fn of stig id), keeping the counts multiplicity-
        // robust.
        let stig_ids: BTreeSet<&str> = stig_baseline(target).iter().map(|r| r.stig_id).collect();
        let mut joined_ids = 0usize;
        let mut total_refs = 0usize;
        for &sid in &stig_ids {
            let refs = cis_controls_for_stig(target, sid);
            if refs.is_empty() {
                continue;
            }
            joined_ids += 1;
            total_refs += refs.len();
            assert_eq!(
                cis_ids(&refs).len(),
                refs.len(),
                "{target:?} {sid}: CIS join must not repeat a control id: {refs:?}"
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
        assert_eq!(
            joined_ids, want_joined_ids,
            "{target:?}: distinct au-W06 stig ids carrying a CIS join (grounded intersection count)"
        );
        assert_eq!(
            total_refs, want_total_refs,
            "{target:?}: total distinct CIS refs across joined au-W06 findings (grounded)"
        );
    }
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
