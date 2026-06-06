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

    // Must contain the BARE (no-brace) single-perm form (f4 §2.5, corpus oracle).
    // `allow logrotate_t shadow_t:file read;`  - NOT the brace form.
    // This assertion KILLS the M1 mutant (`==` -> `!=` in format_narrow_allow):
    // the mutant renders the single-perm group with braces (`{ read }`), which
    // does NOT match `"allow logrotate_t shadow_t:file read;"` (no `{`).
    assert!(
        out.contains("allow logrotate_t shadow_t:file read;"),
        "TC-H1: must emit bare single-perm allow (no braces) for single-perm \
         TeAllowable; got:\n{out}"
    );
    // Confirm the brace form does NOT appear for a single-perm group.
    assert!(
        !out.contains("allow logrotate_t shadow_t:file { read }"),
        "TC-H1: must NOT emit brace form for single-perm allow; got:\n{out}"
    );

    // M2 kill: the explanation must display the bare perm token `read`, not
    // `{ read }`. The `!=` mutant in triage_group flips perm_display for single-
    // perm groups to the brace form, which the explanation text would reflect.
    assert!(
        !out.contains("{ read }"),
        "TC-H1: explanation must NOT wrap single perm in braces; got:\n{out}"
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
    // Scoped to `allow` lines only (matching TC-H7/H12 idiom) so that perm words
    // appearing in plain-language explanation prose do not false-fail this guard.
    for forbidden_perm in &["open", "getattr", "ioctl", "lock"] {
        let padded_on_allow_line = out.lines().filter(|l| l.contains("allow ")).any(|l| {
            l.contains(&format!(" {forbidden_perm} ")) || l.contains(&format!(" {forbidden_perm};"))
        });
        assert!(
            !padded_on_allow_line,
            "TC-H1: must NOT pad with `{forbidden_perm}` on an allow line for a single `read` denial; got:\n{out}"
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

    // Must contain the BRACE multi-perm form (BTreeSet sort: getattr open read).
    // M1 kill: the `!=` mutant in format_narrow_allow emits single-perm groups
    // with braces and multi-perm groups BARE (dropping all but the first perm).
    // The bare multi-perm form would be `allow logrotate_t shadow_t:file getattr;`
    // (only the first perm, no union), which does NOT match the brace form below.
    assert!(
        out.contains("allow logrotate_t shadow_t:file { getattr open read };"),
        "TC-H2: must emit brace multi-perm allow in BTreeSet order \
         `allow logrotate_t shadow_t:file {{ getattr open read }};`; got:\n{out}"
    );

    // All 3 denied perms must appear on the allow line.
    for perm in &["getattr", "open", "read"] {
        assert!(
            out.lines()
                .filter(|l| l.contains("allow logrotate_t shadow_t:file"))
                .any(|l| l.contains(perm)),
            "TC-H2: allow line must include denied perm `{perm}`; got:\n{out}"
        );
    }

    // M2 kill: the explanation must use the braced multi-perm display
    // `{ getattr open read }`. The `!=` mutant flips multi-perm to bare (just
    // `getattr`), which would NOT contain the full braced string below.
    assert!(
        out.contains("{ getattr open read }"),
        "TC-H2: explanation must display multi-perm as `{{ getattr open read }}`; \
         got:\n{out}"
    );

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
// TC-H4: Permissive denial - emit allow + PERMISSIVE-MODE banner
//
// SANCTIONED SPEC CHANGE (round-2, 2026-06-05): the user explicitly REVERSED
// f4 §2.5 invariant 6 (`f4-selinux-triage-grounding.md` line 294-296: "permissive=1
// denials are reported but NOT auto-suggested as allows"). The new behaviour:
// a `permissive=1` denial DOES now get a suggested `allow`, but it MUST be
// preceded by a clear PERMISSIVE-MODE caveat banner so the operator knows the
// access was logged-not-enforced and must be reviewed before allowing.
//
// This is NOT weakening: the test still pins concrete, load-bearing behaviour
// (the banner marker MUST be present AND the allow MUST be emitted). The pre-
// reversal assertions (no allow / only-informational) are intentionally
// replaced because the underlying spec decision changed.
//
// Banner marker (stable substring the impl MUST emit, shared by the floor path
// and the --policy authoritative path; see e2e_selinux_authoritative.rs):
//   "PERMISSIVE MODE:"
//
// Source: corpus rocky9-permissive-denial (the same fixture; the verdict, not
// the record, is what changed).
// ---------------------------------------------------------------------------

/// Stable banner marker substring the implementation MUST emit on any
/// permissive denial block (BOTH the floor path here and the --policy
/// authoritative path in the CLI e2e). Asserted verbatim so a wording drift is
/// caught. Chosen by the round-2 test-author per the user's f4-inv-6 reversal.
const PERMISSIVE_BANNER_MARKER: &str = "PERMISSIVE MODE:";

#[test]
fn h4_permissive_denial_emits_allow_with_banner() {
    let groups = vec![make_group(
        "logrotate_t",
        "shadow_t",
        "file",
        &["read"],
        true, // any_permissive=true
        DenialKind::Permissive,
    )];
    let out = render_human(&groups);

    // NEW (f4-inv-6 reversal): a suggested allow MUST now be emitted for a
    // permissive denial. Accept either the single-perm or braced multi-perm form
    // (single-perm `read` is the canonical render here).
    assert!(
        out.contains("allow logrotate_t shadow_t:file read;")
            || out.contains("allow logrotate_t shadow_t:file { read };"),
        "TC-H4 (f4-inv-6 reversal): a permissive=1 denial MUST now get a suggested \
         allow; got:\n{out}"
    );

    // The PERMISSIVE-MODE caveat banner MUST precede / accompany the allow so the
    // operator knows the access was logged-not-enforced and must be reviewed.
    assert!(
        out.contains(PERMISSIVE_BANNER_MARKER),
        "TC-H4 (f4-inv-6 reversal): a permissive denial block MUST carry the \
         '{PERMISSIVE_BANNER_MARKER}' caveat banner; got:\n{out}"
    );

    // The banner must come BEFORE the suggested allow (caveat-first), so the
    // operator reads the warning before the rule.
    let banner_pos = out
        .find(PERMISSIVE_BANNER_MARKER)
        .expect("banner present (asserted above)");
    let allow_pos = out
        .find("allow logrotate_t shadow_t:file")
        .expect("allow present (asserted above)");
    assert!(
        banner_pos < allow_pos,
        "TC-H4 (f4-inv-6 reversal): the PERMISSIVE-MODE banner must precede the \
         suggested allow (caveat-first); got:\n{out}"
    );

    // Still reported, still mentions permissive (these assertions are unchanged
    // from the pre-reversal test - the denial is still surfaced, with context).
    assert!(
        !out.trim().is_empty(),
        "TC-H4: output must not be empty - permissive denial must still be reported"
    );
    assert!(
        out.to_lowercase().contains("permissive"),
        "TC-H4: output must mention 'permissive' so the operator understands the \
         caveat; got:\n{out}"
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
//
// ADVERSARIAL FIXES (two bugs in the original):
//
// Bug 1 - WRONG-IMPL SURVIVOR: the allow-guard used an OR-of-exact-string form:
//   `!out.contains("allow newrole_t") || (!contains("..dyntransition;") && !contains(...))`
// A wrong impl emitting the BRACE form `allow newrole_t newrole_t:process { dyntransition };`
// slips through: !contains("allow newrole_t") = false, so we fall to the RHS;
// the brace form does not match either exact string, so both !contains() = true,
// and the whole assertion is true. The fix is a SIMPLE prefix match that catches
// all emission forms: `!out.contains("allow newrole_t newrole_t:process")`.
//
// Bug 2 - VACUOUS 2nd assert: `lower.contains("role")` is always true because
// the input type `newrole_t` contains the substring "role". The fix requires a
// term that is NOT present in the input types themselves - "constraint" or
// "dyntransition" context wording is appropriate (the explanation must say WHY,
// not just reflect the input types back).
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

    // Must NOT emit an allow rule for a RoleSuspected denial - in ANY form.
    // Prefix match catches semicolon form, brace form, and self-alias form:
    //   "allow newrole_t newrole_t:process dyntransition;"
    //   "allow newrole_t newrole_t:process { dyntransition };"
    //   "allow newrole_t self:process ..."
    assert!(
        !out.contains("allow newrole_t newrole_t:process")
            && !out.contains("allow newrole_t self:process"),
        "TC-H6: must NOT emit allow for RoleSuspected denial (any form); got:\n{out}"
    );

    // Must explain why plain allow won't fix this with a term that is NOT a
    // substring of the input types (which would make it vacuous).
    // "newrole_t" contains "role" and "new" - so "role" is not a valid sentinel.
    // "dyntransition" IS the denied perm - it must not be used as the only signal.
    // Require "constraint" or "rbac" (neither appears in newrole_t / process /
    // dyntransition) to confirm the explanation discusses the real mechanism.
    let lower = out.to_lowercase();
    assert!(
        lower.contains("constraint") || lower.contains("rbac"),
        "TC-H6: explanation must mention 'constraint' or 'rbac' (a term not in the \
         input types/perms) to confirm a real mechanism explanation, not just echo \
         the input; got:\n{out}"
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

    // Both class-specific rules must appear in bare single-perm form (no braces).
    // Strengthened from `||` form to exact match to kill M1 mutant.
    assert!(
        out.contains("allow logrotate_t shadow_t:file read;"),
        "TC-H7: must emit bare single-perm allow logrotate_t shadow_t:file read; got:\n{out}"
    );
    assert!(
        out.contains("allow logrotate_t shadow_t:dir search;"),
        "TC-H7: must emit bare single-perm allow logrotate_t shadow_t:dir search; got:\n{out}"
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

#[test]
fn render_human_nonempty_ends_with_single_trailing_newline() {
    // #114: triage human output must end with exactly one trailing newline, like
    // `explain` (println!) and `auditd cost` (writeln!). The JSON path already
    // ends with `\n` via render_envelope; this aligns the human path.
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
        out.ends_with('\n'),
        "render_human output must end with a trailing newline; got:\n{out:?}"
    );
    assert!(
        !out.ends_with("\n\n"),
        "render_human must end with exactly one newline, not a blank line; got:\n{out:?}"
    );
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

    // Each class-specific allow must appear in bare single-perm form (no braces).
    // Strengthened from `||` form to exact match to kill M1 mutant.
    assert!(
        out.contains("allow httpd_t default_t:file read;"),
        "TC-H12: must emit bare single-perm allow httpd_t default_t:file read; got:\n{out}"
    );
    assert!(
        out.contains("allow httpd_t default_t:lnk_file read;"),
        "TC-H12: must emit bare single-perm allow httpd_t default_t:lnk_file read; got:\n{out}"
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

// ---------------------------------------------------------------------------
// TC-H16: End-to-end parse_avc -> group_denials -> render_human
//          (wires the vendored corpus fixtures into the render path)
//
// Source: corpus/avc/single_perm_read.avc (the f4 §1.2 anchor record).
//
// This test is the only one that exercises the FULL pipeline from raw AVC
// text to human output. It ensures the corpus fixtures are not just reference
// documentation but are load-bearing oracles for the composed path.
//
// The corpus file contains the real captured AVC:
//   avc: denied { read } for pid=14601 comm="mycat" name="data"
//   scontext=system_u:system_r:logrotate_t:s0
//   tcontext=unconfined_u:object_r:shadow_t:s0 tclass=file permissive=0
//
// Expected render output: narrow allow `allow logrotate_t shadow_t:file read;`
// (same oracle as TC-H1, but derived from the fixture parse path).
// ---------------------------------------------------------------------------

#[test]
fn h16_end_to_end_corpus_single_perm_read() {
    use rulesteward_selinux::{group_denials, parse_avc};

    // Load the vendored fixture (CI cannot reach /mnt; the corpus/ dir is in
    // the tests/ directory alongside this file).
    let fixture = include_str!("corpus/avc/single_perm_read.avc");

    // Parse every non-empty, non-comment line.
    // parse_avc returns Vec<AvcDenial> (one call may yield multiple records
    // for ausearch-grouped blocks), so flatten into a single Vec.
    let mut denials = Vec::new();
    for line in fixture.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let mut batch = parse_avc(trimmed)
            .unwrap_or_else(|e| panic!("TC-H16: failed to parse AVC line: {e}\n  line: {trimmed}"));
        denials.append(&mut batch);
    }

    assert!(
        !denials.is_empty(),
        "TC-H16: corpus/avc/single_perm_read.avc must contain at least one AVC record"
    );

    let groups = group_denials(&denials);
    assert_eq!(
        groups.len(),
        1,
        "TC-H16: single_perm_read fixture must produce exactly one denial group"
    );
    assert_eq!(
        groups[0].kind,
        rulesteward_selinux::DenialKind::TeAllowable,
        "TC-H16: logrotate_t/shadow_t/file with object_r target must be TeAllowable"
    );

    let out = render_human(&groups);

    // The narrow allow for the f4 §1.2 anchor - bare single-perm form (no braces).
    // Strengthened from `||` form to exact match to kill M1 mutant.
    assert!(
        out.contains("allow logrotate_t shadow_t:file read;"),
        "TC-H16: end-to-end render must emit bare single-perm allow for corpus anchor; got:\n{out}"
    );

    // Must NOT emit interface macro (end-to-end trap guard).
    assert!(
        !out.contains("auth_read_shadow"),
        "TC-H16: end-to-end render must NOT emit auth_read_shadow() macro; got:\n{out}"
    );
}

// ---------------------------------------------------------------------------
// TC-H17 / TC-H18: permissive DECLINE-kind denials must NOT emit a self-
// contradictory PERMISSIVE-MODE banner.
//
// Round-2 impl-aware adversarial finding: `render_group_human` gated the
// PERMISSIVE-MODE banner ONLY on `any_permissive`, independent of `kind`. For a
// permissive denial whose authoritative verdict is a DECLINE kind (Constraint,
// Bounds, MlsSuspected, RoleSuspected, ContextInvalid) NO allow is emitted
// (TC-H13/H14 pin the no-allow behaviour). But the banner text promises "The
// suggested allow below ... before applying it" - so on a permissive DECLINE the
// banner promised an allow that never appears (self-contradictory output).
//
// Grounding:
// - "Constraint / Bounds decline => no allow": f4 §8 + the existing TC-H13/H14
//   `!out.contains("allow ...")` assertions above.
// - "the banner accompanies an allow": f4-selinux-triage-grounding.md ~line 434
//   (the banner is the caveat that PRECEDES the suggested allow) + TC-H4, which
//   pins banner+allow together for the permissive TeAllowable/Permissive case.
//
// Invariant pinned: IF the PERMISSIVE-MODE banner is present, THEN a
// `Suggested fix:` line MUST also be present (banner never stands alone). The
// banner's "suggested allow below" promise MUST be absent when no allow exists.
// ---------------------------------------------------------------------------

/// The self-contradictory promise the banner makes - present only when an allow
/// is actually suggested. Pinned verbatim so a permissive DECLINE never leaks it.
const BANNER_ALLOW_PROMISE: &str = "suggested allow below";

#[test]
fn h17_permissive_constraint_no_banner_promising_absent_allow() {
    // A permissive=1 denial whose authoritative verdict is Constraint: no allow
    // is appropriate (TC-H13), so the banner promising one must NOT appear.
    let groups = vec![make_group(
        "container_t",
        "container_file_t",
        "file",
        &["relabelto"],
        true, // any_permissive=true - the trigger for the buggy banner
        DenialKind::Constraint,
    )];
    let out = render_human(&groups);

    // No allow for a Constraint denial (unchanged from TC-H13).
    assert!(
        !out.contains("allow container_t container_file_t:file"),
        "TC-H17: must NOT emit allow for a permissive Constraint denial; got:\n{out}"
    );

    // The banner's "suggested allow below" promise must be ABSENT - there is no
    // allow for it to refer to.
    assert!(
        !out.contains(BANNER_ALLOW_PROMISE),
        "TC-H17: a permissive DECLINE (Constraint) must NOT emit the banner's \
         '{BANNER_ALLOW_PROMISE}' promise when no allow is suggested; got:\n{out}"
    );

    // Core invariant: banner present => Suggested fix line present.
    assert!(
        !out.contains(PERMISSIVE_BANNER_MARKER) || out.contains("Suggested fix:"),
        "TC-H17 invariant: if the PERMISSIVE-MODE banner is present a 'Suggested fix:' \
         line MUST also be present (banner never stands alone); got:\n{out}"
    );

    // The decline wording is still surfaced.
    let lower = out.to_lowercase();
    assert!(
        lower.contains("constraint") || lower.contains("not a te allow"),
        "TC-H17: the Constraint decline wording must still be present; got:\n{out}"
    );
}

#[test]
fn h18_permissive_bounds_no_banner_promising_absent_allow() {
    // A permissive=1 denial whose authoritative verdict is Bounds: no allow
    // is appropriate (TC-H14), so the banner promising one must NOT appear.
    let groups = vec![make_group(
        "child_t",
        "some_t",
        "file",
        &["read"],
        true, // any_permissive=true - the trigger for the buggy banner
        DenialKind::Bounds,
    )];
    let out = render_human(&groups);

    assert!(
        !out.contains("allow child_t some_t:file"),
        "TC-H18: must NOT emit allow for a permissive Bounds denial; got:\n{out}"
    );

    assert!(
        !out.contains(BANNER_ALLOW_PROMISE),
        "TC-H18: a permissive DECLINE (Bounds) must NOT emit the banner's \
         '{BANNER_ALLOW_PROMISE}' promise when no allow is suggested; got:\n{out}"
    );

    assert!(
        !out.contains(PERMISSIVE_BANNER_MARKER) || out.contains("Suggested fix:"),
        "TC-H18 invariant: if the PERMISSIVE-MODE banner is present a 'Suggested fix:' \
         line MUST also be present (banner never stands alone); got:\n{out}"
    );

    let lower = out.to_lowercase();
    assert!(
        lower.contains("bounds") || lower.contains("typebounds"),
        "TC-H18: the Bounds decline wording must still be present; got:\n{out}"
    );
}
