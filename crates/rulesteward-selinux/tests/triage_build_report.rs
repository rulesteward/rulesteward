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
//!
//! ## `TriageReport` renderer contract (pinned by these tests)
//!
//! The JSON produced by `serde_json::to_string(&build_report(&groups))` must
//! include per-group rendered output. The minimum required shape per group is:
//!
//! - `suggested_rule`: present and non-null for `TeAllowable` groups; absent or
//!   null for `Permissive` / `MlsSuspected` / `RoleSuspected` groups.
//! - `explanation`: present and non-empty for every group (f4 §6.2).
//! - `any_permissive`: the literal boolean `true` or `false` (not just the
//!   field name substring in a key).
//! - `dontaudit` note: present somewhere in the JSON (as a field value or
//!   within the explanation string) for `TeAllowable` groups (issue #94 Decision 1).
//!
//! The exact field names and nesting are up to P3; these tests parse the JSON
//! with `serde_json::Value` and check the semantics, not the field names.

use rulesteward_selinux::{DenialGroup, DenialKind, build_report};

/// Walk a `serde_json::Value` tree looking for any field whose key contains
/// "permissive" and whose value is the boolean `true`.
///
/// Used by TC-R5 to assert the actual boolean value rather than a key-name
/// substring match (the vacuous `json.contains("permissive")` trap).
fn has_permissive_true(val: &serde_json::Value) -> bool {
    match val {
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                if k.contains("permissive") && v == &serde_json::Value::Bool(true) {
                    return true;
                }
                if has_permissive_true(v) {
                    return true;
                }
            }
            false
        }
        serde_json::Value::Array(arr) => arr.iter().any(has_permissive_true),
        _ => false,
    }
}

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
//
// ADVERSARIAL NOTE: a trivial passthrough `TriageReport { groups: g.to_vec() }`
// passes this test because `DenialGroup` already serializes as a JSON object.
// TC-R4a / TC-R5 / TC-R7 / TC-R8 are the tests that defeat that passthrough.
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
// TC-R4a: TeAllowable report JSON contains the narrow suggested allow rule string
//          AND a dontaudit note - defeats the trivial passthrough survivor
//
// Source: f4 §6.2 contract (suggestedRule field); issue #94 Decision 1 (dontaudit).
//
// ADVERSARIAL NOTE: `TriageReport { groups: g.to_vec() }` (the Phase-0 shape)
// serializes only DenialGroup fields - it has no suggested_rule or dontaudit
// field. This test requires the implementer to extend the report shape with
// rendered per-group content. The exact form of the suggested rule must match
// the narrow `allow <src> <tgt>:<cls> { <perms> };` or
// `allow <src> <tgt>:<cls> <perm>;` canon forms.
//
// f4 §1.2 anchor: `allow logrotate_t shadow_t:file read;`
// ---------------------------------------------------------------------------

#[test]
fn r4a_teallowable_report_json_contains_suggested_rule_and_dontaudit() {
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

    // The JSON must contain the BARE single-perm allow rule (no braces).
    // M1 kill (JSON path): the `!=` mutant in format_narrow_allow renders the
    // single-perm group with braces, producing `allow ... { read };` in the JSON.
    // This assertion requires the bare form, so the mutant fails.
    assert!(
        json.contains("allow logrotate_t shadow_t:file read;"),
        "TC-R4a: TeAllowable report JSON must contain the bare single-perm allow rule \
         'allow logrotate_t shadow_t:file read;' (no braces); got:\n{json}"
    );
    // Confirm the brace form does NOT appear for a single-perm group in JSON.
    assert!(
        !json.contains("allow logrotate_t shadow_t:file { read }"),
        "TC-R4a: JSON must NOT contain brace form for single-perm allow; got:\n{json}"
    );

    // The JSON must also mention dontaudit (issue #94 Decision 1: always note
    // dontaudit as the safer option for TeAllowable denials).
    assert!(
        json.contains("dontaudit"),
        "TC-R4a: TeAllowable report JSON must contain 'dontaudit' note \
         (issue #94 Decision 1); got:\n{json}"
    );
}

// ---------------------------------------------------------------------------
// TC-R5: Permissive denial in report - any_permissive is preserved as boolean true
//
// Source: f4 §5.1 JSON spec: "permissive" (bool) field.
//
// Guards against silently stripping the permissive flag from the JSON output,
// which would prevent consumers from distinguishing permissive vs. enforcing.
//
// ADVERSARIAL FIX (was vacuous): the old assertion `json.contains("true") ||
// json.contains("permissive")` was always true because the serialized field
// name `any_permissive` contains the substring "permissive". This version
// parses the JSON and asserts the ACTUAL boolean value == true.
//
// Specifically: with `any_permissive: false` the old assertion still passed
// because the field name alone triggered `json.contains("permissive")`.
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

    // Parse the JSON and find the permissive boolean field.
    // has_permissive_true() (module-level) walks the tree looking for a key
    // that contains "permissive" with the literal boolean value `true`.
    let v: serde_json::Value = serde_json::from_str(&json).expect("must parse as JSON");

    assert!(
        has_permissive_true(&v),
        "TC-R5: report JSON must carry a permissive-keyed field with boolean value \
         `true` for a Permissive denial (any_permissive=true); \
         got:\n{json}"
    );
}

// ---------------------------------------------------------------------------
// TC-R5b: Permissive denial report does NOT contain a suggested allow rule
//
// Source: f4 §2.5 invariant 6 (permissive=1 -> report only, no allow).
//
// Companion to TC-R5: verifies the permissive flag actually suppresses the
// suggested allow in the JSON output, not just that the flag is carried.
// ---------------------------------------------------------------------------

#[test]
fn r5b_permissive_denial_report_has_no_suggested_allow() {
    let groups = vec![make_group(
        "logrotate_t",
        "shadow_t",
        "file",
        &["read"],
        true,
        DenialKind::Permissive,
    )];
    let report = build_report(&groups);
    let json = serde_json::to_string(&report).expect("serialize");

    // The JSON must NOT contain a suggested allow rule for this triple.
    assert!(
        !json.contains("allow logrotate_t shadow_t:file read;")
            && !json.contains("allow logrotate_t shadow_t:file { read };"),
        "TC-R5b: Permissive denial report must NOT contain a suggested allow rule \
         (f4 §2.5 inv.6); got:\n{json}"
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

// ---------------------------------------------------------------------------
// TC-R7: Non-TeAllowable groups (MlsSuspected, RoleSuspected) have NO suggested
//         allow rule in the JSON - defeats the trivial passthrough on the
//         non-TeAllowable side
//
// Source: f4 §6.2 contract + f4 §2.5 inv.6 (permissive) + H5/H6 decline path.
//
// ADVERSARIAL NOTE: the trivial passthrough `TriageReport { groups: g.to_vec() }`
// does not contain a suggested allow string for any group (it has no renderer
// output at all), so this test is not itself a survivor defeater for the
// passthrough. It is the COMPANION to TC-R4a: R4a proves TeAllowable DOES
// produce the string; R7 proves non-TeAllowable does NOT. Together they pin
// both sides of the suggestion logic. A wrong impl that suggests allows for all
// groups (regardless of kind) fails TC-R7.
// ---------------------------------------------------------------------------

#[test]
fn r7_non_teallowable_groups_have_no_suggested_allow_in_json() {
    // MlsSuspected group: container_t / container_file_t / file
    let mls_group = make_group(
        "container_t",
        "container_file_t",
        "file",
        &["read"],
        false,
        DenialKind::MlsSuspected,
    );
    let report = build_report(&[mls_group]);
    let json = serde_json::to_string(&report).expect("serialize");

    assert!(
        !json.contains("allow container_t container_file_t:file read;")
            && !json.contains("allow container_t container_file_t:file { read };"),
        "TC-R7: MlsSuspected group must NOT have a suggested allow rule in JSON; \
         got:\n{json}"
    );

    // RoleSuspected group: newrole_t / newrole_t / process
    let role_group = make_group(
        "newrole_t",
        "newrole_t",
        "process",
        &["dyntransition"],
        false,
        DenialKind::RoleSuspected,
    );
    let report2 = build_report(&[role_group]);
    let json2 = serde_json::to_string(&report2).expect("serialize");

    assert!(
        !json2.contains("allow newrole_t newrole_t:process dyntransition;")
            && !json2.contains("allow newrole_t newrole_t:process { dyntransition };")
            && !json2.contains("allow newrole_t self:process dyntransition;")
            && !json2.contains("allow newrole_t"),
        "TC-R7: RoleSuspected group must NOT have a suggested allow rule in JSON; \
         got:\n{json2}"
    );
}
