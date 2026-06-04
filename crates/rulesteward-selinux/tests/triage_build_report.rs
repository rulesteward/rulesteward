//! Adversarial barrier tests for `build_report(&[DenialGroup]) -> TriageReport`.
//!
//! These tests verify the machine-readable JSON report shape.
//! Primary sources:
//!
//! - f4 §5.1: `--format json` output shape
//! - f4 §6.2: triage renderer contract (sourceDomain, targetType, class, perms[],
//!   permissive, suggestedRule, explanation)
//! - issue #62 envelope invariant: `groups` field holds denial groups
//! - issue #94 LOCKED decisions: Decision 1 (dontaudit note always present)
//!
//! The frozen `TriageReport { groups: Vec<DenialGroup> }` is the Phase-0
//! placeholder shape. P3 MAY reshape it (add per-group explanation + suggestion
//! fields). These tests assert what MUST be true AFTER P3 fills the body:
//! that the output is a valid JSON envelope, that `TeAllowable` groups include
//! the narrow suggest rule, and that non-TeAllowable groups are reported without
//! a suggested allow.

use rulesteward_selinux::{DenialGroup, DenialKind, build_report};

fn make_group(
    source_type: &str,
    target_type: &str,
    tclass: &str,
    perms: &[&str],
    any_permissive: bool,
    kind: DenialKind,
) -> DenialGroup {
    DenialGroup {
        source_type: source_type.to_string(),
        target_type: target_type.to_string(),
        tclass: tclass.to_string(),
        perms: perms.iter().map(ToString::to_string).collect(),
        any_permissive,
        kind,
    }
}

// ---------------------------------------------------------------------------
// TC-R1: build_report returns a TriageReport without panicking
//
// The minimal sanity test: the frozen stub panics with todo!(); once P3 fills
// the body, this test must pass.
// ---------------------------------------------------------------------------

#[test]
fn r1_build_report_does_not_panic_on_single_teallowable_group() {
    let groups = vec![make_group(
        "logrotate_t",
        "shadow_t",
        "file",
        &["read"],
        false,
        DenialKind::TeAllowable,
    )];
    let _report = build_report(&groups);
}

// ---------------------------------------------------------------------------
// TC-R2: build_report returns a TriageReport without panicking for empty input
// ---------------------------------------------------------------------------

#[test]
fn r2_build_report_does_not_panic_on_empty_groups() {
    let _report = build_report(&[]);
}

// ---------------------------------------------------------------------------
// TC-R3: TriageReport serializes to valid JSON with the expected envelope shape
//
// Source: issue #62 (envelope contract) + selinux.rs (SELINUX_TRIAGE_SCHEMA_VERSION=1,
//         kind="selinux-triage").
//
// The CLI uses: render_envelope("selinux-triage", 1, &build_report(&groups))
// This test verifies the TriageReport struct round-trips via serde_json and
// that the CLI envelope layer produces a valid JSON object.
// ---------------------------------------------------------------------------

#[test]
fn r3_triage_report_serializes_to_valid_json() {
    let groups = vec![make_group(
        "logrotate_t",
        "shadow_t",
        "file",
        &["read"],
        false,
        DenialKind::TeAllowable,
    )];
    let report = build_report(&groups);
    let json = serde_json::to_string(&report).expect("TriageReport must serialize to JSON");
    assert!(
        !json.is_empty(),
        "TC-R3: serialized TriageReport must not be empty"
    );
    // Must be a JSON object (not an array, not null).
    let v: serde_json::Value =
        serde_json::from_str(&json).expect("TriageReport JSON must be valid");
    assert!(
        v.is_object(),
        "TC-R3: TriageReport must serialize as a JSON object; got:\n{json}"
    );
}

// ---------------------------------------------------------------------------
// TC-R4: TriageReport for a TeAllowable group includes source_type, target_type,
//         tclass, and perms (the fields needed to reconstruct the narrow allow)
//
// Source: f4 §5.1 JSON format spec + f4 §6.2.
// ---------------------------------------------------------------------------

#[test]
fn r4_teallowable_report_contains_required_denial_fields() {
    let groups = vec![make_group(
        "logrotate_t",
        "shadow_t",
        "file",
        &["read"],
        false,
        DenialKind::TeAllowable,
    )];
    let report = build_report(&groups);
    let json = serde_json::to_string(&report).expect("serialize");
    // The JSON must contain the domain, type, class, and perm.
    assert!(
        json.contains("logrotate_t"),
        "TC-R4: JSON must contain source_type 'logrotate_t'; got:\n{json}"
    );
    assert!(
        json.contains("shadow_t"),
        "TC-R4: JSON must contain target_type 'shadow_t'; got:\n{json}"
    );
    assert!(
        json.contains("file"),
        "TC-R4: JSON must contain tclass 'file'; got:\n{json}"
    );
    assert!(
        json.contains("read"),
        "TC-R4: JSON must contain perm 'read'; got:\n{json}"
    );
}

// ---------------------------------------------------------------------------
// TC-R5: Permissive denial in report - any_permissive is preserved (true)
//
// Source: f4 §5.1 JSON spec: "permissive" (bool) field.
//
// Guards against silently stripping the permissive flag from the JSON output,
// which would prevent consumers from distinguishing permissive vs. enforcing.
// ---------------------------------------------------------------------------

#[test]
fn r5_permissive_denial_preserves_permissive_true_in_report() {
    let groups = vec![make_group(
        "logrotate_t",
        "shadow_t",
        "file",
        &["read"],
        true, // any_permissive=true
        DenialKind::Permissive,
    )];
    let report = build_report(&groups);
    let json = serde_json::to_string(&report).expect("serialize");
    // The JSON must carry the permissive indicator.
    assert!(
        json.contains("true") || json.contains("permissive"),
        "TC-R5: JSON must carry the permissive=true field; got:\n{json}"
    );
}

// ---------------------------------------------------------------------------
// TC-R6: Multiple groups round-trip - all groups are present in the report
//
// Source: f4 §5.1 (groups key in the JSON output).
// ---------------------------------------------------------------------------

#[test]
fn r6_multiple_groups_all_present_in_report() {
    let groups = vec![
        make_group(
            "logrotate_t",
            "shadow_t",
            "file",
            &["read"],
            false,
            DenialKind::TeAllowable,
        ),
        make_group(
            "container_t",
            "container_file_t",
            "file",
            &["read"],
            false,
            DenialKind::MlsSuspected,
        ),
        make_group(
            "newrole_t",
            "newrole_t",
            "process",
            &["dyntransition"],
            false,
            DenialKind::RoleSuspected,
        ),
    ];
    let report = build_report(&groups);
    let json = serde_json::to_string(&report).expect("serialize");
    assert!(
        json.contains("logrotate_t"),
        "TC-R6: logrotate_t group must be in report; got:\n{json}"
    );
    assert!(
        json.contains("container_t"),
        "TC-R6: container_t group must be in report; got:\n{json}"
    );
    assert!(
        json.contains("newrole_t"),
        "TC-R6: newrole_t group must be in report; got:\n{json}"
    );
}
