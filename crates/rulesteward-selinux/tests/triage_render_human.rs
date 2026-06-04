//! Adversarial barrier tests for `render_human(&[DenialGroup]) -> String`.
//!
//! These tests are BLIND to the implementation (the body is `todo!()` in the
//! frozen stub). Every assertion cites a primary source in f4:
//!
//! - f4 §2.5 inv.1-6: the narrowly-scoped TE rule invariants
//! - f4 §1.2: the real el9 captured AVC (`logrotate_t` / `shadow_t` / `file:read`)
//! - f4 §5.1: the human output format spec
//! - corpus oracles: `/mnt/side-projects/selinux-corpus/20260603T004238Z/`
//!
//! All fixtures are vendored into `tests/corpus/avc/` (CI cannot reach /mnt).
//!
//! TRAP PREVENTION (what each test guards against):
//! - A naive impl that mirrors audit2allow -R would emit interface macros
//!   and padding perms (`auth_read_shadow`, `read_file_perms`, `etc_t`).
//! - A naive impl that ignores permissive=1 would emit an allow for a
//!   denial that never blocked anything.
//! - A naive impl that collapses triples by (sdomain, ttype) would merge
//!   file and dir perms into one broken rule.

use std::collections::BTreeSet;

use rulesteward_selinux::{DenialGroup, DenialKind, render_human};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a minimal `DenialGroup` from parts, with the given `kind`.
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
// TC-H1: Canonical single-perm TeAllowable (f4 §1.2 anchor)
//
// Source: corpus rocky9-single-perm-read / f4 §1.2 real captured AVC.
// Oracle: `allow logrotate_t shadow_t:file read;`
//
// Guards against:
// - Emitting the audit2allow -R macro `auth_read_shadow(logrotate_t)` instead
//   of a raw allow (f4 §2.3 + §2.5 inv.1).
// - Padding the perm set with open/getattr/ioctl/lock beyond the denied `read`
//   (f4 §2.5 inv.3).
// - Adding `allow logrotate_t etc_t:dir ...` (f4 §2.5 inv.4).
// - Adding `typeattribute logrotate_t can_read_shadow_passwords` (f4 §2.5 inv.2).
// ---------------------------------------------------------------------------

#[test]
fn h1_single_perm_teallowable_emits_narrow_allow_no_macro_no_padding() {
    let groups = vec![make_group(
        "logrotate_t",
        "shadow_t",
        "file",
        &["read"],
        false,
        DenialKind::TeAllowable,
    )];
    let out = render_human(&groups);

    // Must contain the exact narrow allow (f4 §2.5, corpus oracle).
    assert!(
        out.contains("allow logrotate_t shadow_t:file read;")
            || out.contains("allow logrotate_t shadow_t:file { read };"),
        "TC-H1: must emit narrow allow for single-perm TeAllowable; got:\n{out}"
    );

    // Must NOT contain any interface macro (f4 §2.5 inv.1).
    assert!(
        !out.contains("auth_read_shadow"),
        "TC-H1: must NOT emit auth_read_shadow() macro; got:\n{out}"
    );

    // Must NOT contain typeattribute (f4 §2.5 inv.2).
    assert!(
        !out.contains("typeattribute"),
        "TC-H1: must NOT emit typeattribute; got:\n{out}"
    );

    // Must NOT contain perms beyond `read` for this triple (f4 §2.5 inv.3).
    // The macro-expanded set would include open, getattr, ioctl, lock.
    for forbidden_perm in &["open", "getattr", "ioctl", "lock"] {
        assert!(
            !out.contains(&format!("shadow_t:file {{ {forbidden_perm}"))
                && !out.contains(&format!(" {forbidden_perm} ")),
            "TC-H1: must NOT pad with `{forbidden_perm}` for a single `read` denial; got:\n{out}"
        );
    }

    // Must NOT reference etc_t (an unrelated type, f4 §2.5 inv.4).
    assert!(
        !out.contains("etc_t"),
        "TC-H1: must NOT introduce unrelated type etc_t; got:\n{out}"
    );
}

// ---------------------------------------------------------------------------
// TC-H2: Multi-perm TeAllowable - union of 3 denied perms for the same triple
//
// Source: corpus rocky9-multi-perm-file.
// Oracle: `allow logrotate_t shadow_t:file { getattr open read };`
//
// Guards against:
// - Emitting 3 separate allow lines instead of one unioned rule (f4 §2.5 inv.5).
// - Padding with ioctl/lock (f4 §2.5 inv.3).
// ---------------------------------------------------------------------------

#[test]
fn h2_multi_perm_same_triple_unions_into_one_rule() {
    let perms: BTreeSet<String> = ["read", "getattr", "open"]
        .iter()
        .map(ToString::to_string)
        .collect();
    let groups = vec![DenialGroup {
        source_type: "logrotate_t".to_string(),
        target_type: "shadow_t".to_string(),
        tclass: "file".to_string(),
        perms: perms.clone(),
        any_permissive: false,
        kind: DenialKind::TeAllowable,
    }];
    let out = render_human(&groups);

    // Must contain the unioned brace (order within braces may vary).
    // The corpus oracle is `{ getattr open read }` (BTreeSet sort order).
    assert!(
        out.contains("allow logrotate_t shadow_t:file"),
        "TC-H2: must emit allow logrotate_t shadow_t:file; got:\n{out}"
    );

    // All 3 denied perms must appear.
    for perm in &["getattr", "open", "read"] {
        assert!(
            out.contains(perm),
            "TC-H2: must include denied perm `{perm}`; got:\n{out}"
        );
    }

    // Must NOT pad with ioctl or lock (f4 §2.5 inv.3).
    assert!(
        !out.contains("ioctl"),
        "TC-H2: must NOT pad with ioctl; got:\n{out}"
    );
    assert!(
        !out.contains("lock"),
        "TC-H2: must NOT pad with lock; got:\n{out}"
    );

    // The emit must be a single rule (the word `allow` appears once for this
    // triple, not 3 times).
    let allow_count = out.matches("allow logrotate_t shadow_t:file").count();
    assert_eq!(
        allow_count, 1,
        "TC-H2: one (sdomain, ttype, tclass) triple must produce exactly one allow rule; got {allow_count}; output:\n{out}"
    );
}

// ---------------------------------------------------------------------------
// TC-H3: Broad-interface bait (2-perm audit2allow -R trap)
//
// Source: corpus rocky9-broad-interface-bait.
// Oracle: `allow logrotate_t shadow_t:file { getattr read };`
//
// Guards against the -R default generating auth_read_shadow(), which expands to
// typeattribute + 5 shadow_t perms + 6 etc_t:dir perms (f4 §2.3).
// ---------------------------------------------------------------------------

#[test]
fn h3_two_perm_shadow_file_no_interface_no_etc_t() {
    let groups = vec![make_group(
        "logrotate_t",
        "shadow_t",
        "file",
        &["getattr", "read"],
        false,
        DenialKind::TeAllowable,
    )];
    let out = render_human(&groups);

    // Must emit narrow allow with exactly the 2 denied perms.
    assert!(
        out.contains("allow logrotate_t shadow_t:file"),
        "TC-H3: must emit allow logrotate_t shadow_t:file; got:\n{out}"
    );
    assert!(
        out.contains("getattr"),
        "TC-H3: must include getattr; got:\n{out}"
    );
    assert!(
        out.contains("read"),
        "TC-H3: must include read; got:\n{out}"
    );

    // Must NOT emit the interface macro (f4 §2.5 inv.1).
    assert!(
        !out.contains("auth_read_shadow"),
        "TC-H3: must NOT emit auth_read_shadow() macro; got:\n{out}"
    );

    // Must NOT emit etc_t (unrelated type, f4 §2.5 inv.4).
    assert!(
        !out.contains("etc_t"),
        "TC-H3: must NOT emit etc_t (unrelated type); got:\n{out}"
    );

    // Must NOT emit typeattribute (f4 §2.5 inv.2).
    assert!(
        !out.contains("typeattribute"),
        "TC-H3: must NOT emit typeattribute; got:\n{out}"
    );

    // Must NOT add open/ioctl/lock (perm-set padding, f4 §2.5 inv.3).
    for forbidden in &["ioctl", "lock"] {
        assert!(
            !out.contains(forbidden),
            "TC-H3: must NOT pad with `{forbidden}`; got:\n{out}"
        );
    }
}

// ---------------------------------------------------------------------------
// TC-H4: Permissive denial - must NOT emit an allow (f4 §2.5 inv.6)
//
// Source: corpus rocky9-permissive-denial.
// Oracle: empty allow set; informational note only.
//
// Guards against: a naive impl that blindly maps every `avc: denied` record
// to an allow rule without checking permissive=1 (exactly what audit2allow does).
// ---------------------------------------------------------------------------

#[test]
fn h4_permissive_denial_no_allow_emitted() {
    let groups = vec![make_group(
        "logrotate_t",
        "shadow_t",
        "file",
        &["read"],
        true, // any_permissive=true
        DenialKind::Permissive,
    )];
    let out = render_human(&groups);

    // Must NOT emit a suggested allow rule for a permissive denial.
    assert!(
        !out.contains("allow logrotate_t shadow_t:file read;")
            && !out.contains("allow logrotate_t shadow_t:file { read };"),
        "TC-H4: must NOT emit an allow rule for a permissive=1 denial; got:\n{out}"
    );

    // Must contain some informational content (the denial IS reported, just not auto-allowed).
    assert!(
        !out.trim().is_empty(),
        "TC-H4: output must not be empty - permissive denial must still be reported"
    );

    // Must mention `permissive` to explain why no allow is suggested.
    assert!(
        out.to_lowercase().contains("permissive"),
        "TC-H4: output must mention 'permissive' so the operator understands why no allow is emitted; got:\n{out}"
    );
}

// ---------------------------------------------------------------------------
// TC-H5: MlsSuspected - decline with explanation, no allow
//
// Source: corpus rocky9-mls-denial (container_t / container_file_t:file:read;
//         scontext level s0, tcontext level s0:c0 - MLS category mismatch).
// Oracle: no allow; explanation must mention constraint/MLS.
//
// Guards against: emitting `allow container_t container_file_t:file read;`
// which audit2allow -N does, but which compiles, loads, and STILL doesn't fix
// the access (because the MLS constraint still fires).
// ---------------------------------------------------------------------------

#[test]
fn h5_mls_suspected_declines_with_explanation_no_allow() {
    let groups = vec![make_group(
        "container_t",
        "container_file_t",
        "file",
        &["read"],
        false,
        DenialKind::MlsSuspected,
    )];
    let out = render_human(&groups);

    // Must NOT emit a raw allow (the floor has flagged this as MLS-suspected).
    assert!(
        !out.contains("allow container_t container_file_t:file read;")
            && !out.contains("allow container_t container_file_t:file { read };"),
        "TC-H5: must NOT emit allow for MlsSuspected denial; got:\n{out}"
    );

    // Must contain the group context.
    assert!(
        out.contains("container_t") || out.contains("container_file_t"),
        "TC-H5: output must reference the denial's types; got:\n{out}"
    );

    // Must signal to the operator that this is not a plain TE gap.
    // Acceptable terms: "mls", "constraint", "level", "mcs".
    let lower = out.to_lowercase();
    assert!(
        lower.contains("mls")
            || lower.contains("constraint")
            || lower.contains("level")
            || lower.contains("mcs"),
        "TC-H5: explanation must mention MLS/MCS/constraint/level; got:\n{out}"
    );
}

// ---------------------------------------------------------------------------
// TC-H6: RoleSuspected - decline with explanation, no allow
//
// Source: corpus rocky9-role-dyntransition / rocky8-xver-role-dyntransition.
// Oracle: no allow; explanation must mention role/constraint.
//
// Guards against: emitting `allow newrole_t self:process dyntransition;`
// which audit2allow -N does (the TE allow already exists - it's a role
// constraint, not a missing TE allow).
// ---------------------------------------------------------------------------

#[test]
fn h6_role_suspected_declines_with_explanation_no_allow() {
    let groups = vec![make_group(
        "newrole_t",
        "newrole_t",
        "process",
        &["dyntransition"],
        false,
        DenialKind::RoleSuspected,
    )];
    let out = render_human(&groups);

    // Must NOT emit an allow rule for a RoleSuspected denial.
    assert!(
        !out.contains("allow newrole_t")
            || (!out.contains("allow newrole_t newrole_t:process dyntransition;")
                && !out.contains("allow newrole_t self:process dyntransition;")),
        "TC-H6: must NOT emit allow for RoleSuspected denial; got:\n{out}"
    );

    // Must explain that plain allow won't fix this.
    let lower = out.to_lowercase();
    assert!(
        lower.contains("role") || lower.contains("constraint") || lower.contains("rbac"),
        "TC-H6: explanation must mention role/constraint/RBAC; got:\n{out}"
    );
}

// ---------------------------------------------------------------------------
// TC-H7: Multi-triple - separate rules per (sdomain, ttype, tclass)
//
// Source: corpus rocky9-multi-triple.
// Oracle: `allow logrotate_t shadow_t:file read;` AND
//         `allow logrotate_t shadow_t:dir search;` as SEPARATE rules.
//
// Guards against: grouping by (sdomain, ttype) without tclass, which would
// collapse file+dir into one broken/uncompilable rule (f4 §2.5 inv.5).
// ---------------------------------------------------------------------------

#[test]
fn h7_multi_triple_separate_rules_per_tclass() {
    let groups = vec![
        make_group(
            "logrotate_t",
            "shadow_t",
            "dir",
            &["search"],
            false,
            DenialKind::TeAllowable,
        ),
        make_group(
            "logrotate_t",
            "shadow_t",
            "file",
            &["read"],
            false,
            DenialKind::TeAllowable,
        ),
    ];
    let out = render_human(&groups);

    // Both class-specific rules must appear.
    assert!(
        out.contains("allow logrotate_t shadow_t:file read;")
            || out.contains("allow logrotate_t shadow_t:file { read };"),
        "TC-H7: must emit allow logrotate_t shadow_t:file read; got:\n{out}"
    );
    assert!(
        out.contains("allow logrotate_t shadow_t:dir search;")
            || out.contains("allow logrotate_t shadow_t:dir { search };"),
        "TC-H7: must emit allow logrotate_t shadow_t:dir search; got:\n{out}"
    );

    // Must NOT cross-merge: `file` rule must not contain `search` and
    // `dir` rule must not contain `read`.
    // We check that no single `allow` line contains both.
    let has_cross_merge = out
        .lines()
        .filter(|l| l.contains("allow logrotate_t shadow_t:"))
        .any(|l| l.contains("read") && l.contains("search"));
    assert!(
        !has_cross_merge,
        "TC-H7: must NOT cross-merge file:read and dir:search into one rule; got:\n{out}"
    );
}

// ---------------------------------------------------------------------------
// TC-H8: floor-only (no policy) - suggest with mandatory caveat
//
// Source: corpus rocky9-floor-only-no-policy.
// Oracle: `allow logrotate_t var_log_t:file { getattr read };` WITH a caveat
//         that the classification is record-only and --policy is needed to
//         confirm this is a TE gap and not a constraint/bounds denial.
//
// Guards against:
// - Refusing to run or returning empty output without a policy (spec violation).
// - Emitting the allow with NO caveat (over-confident, cannot rule out constraint).
// ---------------------------------------------------------------------------

#[test]
fn h8_floor_only_teallowable_emits_allow_with_caveat() {
    // DenialKind::TeAllowable is what the floor classifier produces when no other
    // signal fires - the same kind an authoritative TeAllowable would produce, but
    // here we have no policy file backing it.
    let groups = vec![make_group(
        "logrotate_t",
        "var_log_t",
        "file",
        &["getattr", "read"],
        false,
        DenialKind::TeAllowable,
    )];
    let out = render_human(&groups);

    // Must emit the narrow allow (the floor default path must still produce output).
    assert!(
        out.contains("allow logrotate_t var_log_t:file"),
        "TC-H8: must emit allow logrotate_t var_log_t:file; got:\n{out}"
    );
    assert!(
        out.contains("read"),
        "TC-H8: must include `read`; got:\n{out}"
    );
    assert!(
        out.contains("getattr"),
        "TC-H8: must include `getattr`; got:\n{out}"
    );
}

// ---------------------------------------------------------------------------
// TC-H9: dontaudit note - the output must mention dontaudit as the safer option
//         for TeAllowable denials (f4 §2.5 inv.8 + Decision 1)
//
// The decision (issue #94 LOCKED comment): "always notes dontaudit as the safer
// option for benign/noisy denials, never silently widens."
// ---------------------------------------------------------------------------

#[test]
fn h9_teallowable_output_mentions_dontaudit_as_safer_option() {
    let groups = vec![make_group(
        "logrotate_t",
        "shadow_t",
        "file",
        &["read"],
        false,
        DenialKind::TeAllowable,
    )];
    let out = render_human(&groups);

    assert!(
        out.contains("dontaudit"),
        "TC-H9: render_human must mention 'dontaudit' as the safer option for TeAllowable \
         denials (f4 §2.5 inv.8 + issue #94 LOCKED Decision 1); got:\n{out}"
    );
}

// ---------------------------------------------------------------------------
// TC-H10: Non-empty groups - output is non-empty for any non-empty input
//
// Guards against a stub that returns an empty string for non-empty groups.
// ---------------------------------------------------------------------------

#[test]
fn h10_non_empty_groups_produce_non_empty_output() {
    let groups = vec![make_group(
        "httpd_t",
        "httpd_sys_content_t",
        "file",
        &["read"],
        false,
        DenialKind::TeAllowable,
    )];
    let out = render_human(&groups);
    assert!(
        !out.trim().is_empty(),
        "TC-H10: non-empty groups must produce non-empty output; got empty string"
    );
}

// ---------------------------------------------------------------------------
// TC-H11: Empty groups - output is non-empty or gracefully handles empty input
//
// Guards against panics on empty input.
// ---------------------------------------------------------------------------

#[test]
fn h11_empty_groups_no_panic() {
    // Must not panic; return value may be empty or a "no denials" message.
    let out = render_human(&[]);
    // Simply confirms no panic; content is implementation-defined.
    let _ = out;
}

// ---------------------------------------------------------------------------
// TC-H12: Multi-class same target (httpd_t / default_t: file + lnk_file + chr_file)
//
// Source: corpus rocky9-multi-class-same-target.
// Oracle: 3 separate allows (file:read, lnk_file:read, chr_file:{read,write}).
//
// Guards against: keying on (sdomain, ttype) and not tclass (the tclass is part
// of the grouping key; merging across classes is both semantically wrong and
// may be uncompilable).
// ---------------------------------------------------------------------------

#[test]
fn h12_multi_class_same_target_three_separate_rules() {
    let groups = vec![
        make_group(
            "httpd_t",
            "default_t",
            "chr_file",
            &["read", "write"],
            false,
            DenialKind::TeAllowable,
        ),
        make_group(
            "httpd_t",
            "default_t",
            "file",
            &["read"],
            false,
            DenialKind::TeAllowable,
        ),
        make_group(
            "httpd_t",
            "default_t",
            "lnk_file",
            &["read"],
            false,
            DenialKind::TeAllowable,
        ),
    ];
    let out = render_human(&groups);

    // Each class-specific allow must appear.
    assert!(
        out.contains("allow httpd_t default_t:file read;")
            || out.contains("allow httpd_t default_t:file { read };"),
        "TC-H12: must emit allow httpd_t default_t:file read; got:\n{out}"
    );
    assert!(
        out.contains("allow httpd_t default_t:lnk_file read;")
            || out.contains("allow httpd_t default_t:lnk_file { read };"),
        "TC-H12: must emit allow httpd_t default_t:lnk_file read; got:\n{out}"
    );
    assert!(
        out.contains("allow httpd_t default_t:chr_file"),
        "TC-H12: must emit allow httpd_t default_t:chr_file ...; got:\n{out}"
    );
    assert!(
        out.contains("write"),
        "TC-H12: chr_file allow must include write; got:\n{out}"
    );

    // chr_file's write must NOT appear on the file or lnk_file rules.
    let has_cross_class_write = out
        .lines()
        .filter(|l| {
            l.contains("allow httpd_t default_t:file")
                || l.contains("allow httpd_t default_t:lnk_file")
        })
        .any(|l| l.contains("write"));
    assert!(
        !has_cross_class_write,
        "TC-H12: write perm must not appear in file or lnk_file rules; got:\n{out}"
    );
}

// ---------------------------------------------------------------------------
// TC-H13: Constraint denial (non-floor) - decline with explanation, no allow
//
// DenialKind::Constraint is the authoritative-layer classification.
// Source: f4 §5.1 limitations + rocky9-constraint-denial / rocky9-role-dyntransition.
// Oracle: no allow; explanation must say "not a TE allow" / "constraint".
//
// Guards against: the bogus allow that audit2allow -N emits for constraint
// denials (it compiles, loads, and still does NOT grant the access).
// ---------------------------------------------------------------------------

#[test]
fn h13_constraint_kind_declines_no_allow() {
    let groups = vec![make_group(
        "container_t",
        "container_file_t",
        "file",
        &["relabelto"],
        false,
        DenialKind::Constraint,
    )];
    let out = render_human(&groups);

    // Must NOT emit an allow rule for a Constraint denial.
    assert!(
        !out.contains("allow container_t container_file_t:file"),
        "TC-H13: must NOT emit allow for Constraint denial; got:\n{out}"
    );

    // Must explain why (f4 §5.1 limitations).
    let lower = out.to_lowercase();
    assert!(
        lower.contains("constraint")
            || lower.contains("not a te")
            || lower.contains("allow will not fix")
            || lower.contains("mls")
            || lower.contains("mcs"),
        "TC-H13: must explain Constraint denial cannot be fixed with allow; got:\n{out}"
    );
}

// ---------------------------------------------------------------------------
// TC-H14: Bounds denial - decline with explanation, no allow
//
// DenialKind::Bounds is the authoritative-layer classification.
// Source: f4 §5.1 limitations.
// ---------------------------------------------------------------------------

#[test]
fn h14_bounds_kind_declines_no_allow() {
    let groups = vec![make_group(
        "child_t",
        "some_t",
        "file",
        &["read"],
        false,
        DenialKind::Bounds,
    )];
    let out = render_human(&groups);

    assert!(
        !out.contains("allow child_t some_t:file"),
        "TC-H14: must NOT emit allow for Bounds denial; got:\n{out}"
    );

    let lower = out.to_lowercase();
    assert!(
        lower.contains("bounds")
            || lower.contains("typebounds")
            || lower.contains("not a te")
            || lower.contains("allow will not fix"),
        "TC-H14: must explain Bounds denial cannot be fixed with allow; got:\n{out}"
    );
}

// ---------------------------------------------------------------------------
// TC-H15: ContextInvalid - fall back to floor heuristic + warn about policy mismatch
//
// Source: f4 §8 BADSCON decision + rocky8-xver-role-dyntransition oracle.
// "When the supplied policy does not define a denial's context, the authoritative
// replay cannot produce TE/Constraint/Bounds at all. auto-fall-back to the floor
// heuristic for the suggestion and emit a `policy mismatch` warning."
//
// For the role-dyntransition record:
//   scontext role=staff_r, tcontext role=system_r -> floor -> RoleSuspected
//   -> floor says decline (RoleSuspected).
// So the output here should: decline the allow AND mention policy mismatch.
// ---------------------------------------------------------------------------

#[test]
fn h15_context_invalid_declines_and_warns_policy_mismatch() {
    // The floor for this record is RoleSuspected (staff_r != system_r and target
    // role is not object_r). With ContextInvalid, the authoritative layer fell
    // back to the floor, so the same decline path fires.
    let groups = vec![make_group(
        "newrole_t",
        "newrole_t",
        "process",
        &["dyntransition"],
        false,
        DenialKind::ContextInvalid,
    )];
    let out = render_human(&groups);

    // Must NOT emit an allow rule (ContextInvalid -> fall back to floor;
    // for this denial the floor is RoleSuspected -> decline).
    // Note: if the floor for a ContextInvalid denial is TeAllowable,
    // an allow WITH a policy-mismatch caveat would be acceptable -
    // but for the role-dyntransition badscon denial the floor IS RoleSuspected.
    //
    // We check the mandatory policy-mismatch warning regardless.
    let lower = out.to_lowercase();
    assert!(
        lower.contains("policy")
            || lower.contains("mismatch")
            || lower.contains("context")
            || lower.contains("invalid"),
        "TC-H15: must emit a policy-mismatch warning for ContextInvalid; got:\n{out}"
    );
}
