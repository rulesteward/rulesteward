//! Crate-level tests for `sysctld-W02` (the version-aware STIG kernel-hardening
//! baseline, issue #335), authored at the test-author barrier BEFORE the W02 impl.
//! They call the frozen public entries `parser::lint_str_with_target` /
//! `parser::lint_dir_with_target` directly and are RED against the empty-table stub
//! (which emits no W02): only the grounded tables + the missing/insecure logic turn
//! them green. Mirrors how `tests/lints.rs` structures the F01/W01 tests.
//!
//! # Ground truth
//! Every key + accepted value asserted here is transcribed from
//! `rulesteward-docs/sysctld-stig-baseline-grounding.md`, grounded against
//! ComplianceAsCode/content at the pinned commit
//! `519b5fe8ce338cfa25d53065bcb3759aafe8d36d` and gated by the
//! source-adversarial-reviewer. The load-bearing divergences pinned below:
//! * `kernel.kptr_restrict`: rhel8 accepts ONLY `1`; rhel9/rhel10 accept `1` OR `2`.
//! * `net.ipv4.conf.all.rp_filter`: rhel8/rhel10 accept `1` OR `2`; rhel9 accepts ONLY `1`.
//! * `user.max_user_namespaces`: required on rhel8/rhel9; ABSENT from rhel10's baseline.

use std::path::Path;

use rulesteward_core::{Diagnostic, Severity};
use rulesteward_sysctld::TargetVersion;
use rulesteward_sysctld::parser::{lint_dir_with_target, lint_str_with_target};
use tempfile::tempdir;

const PATH: &str = "/etc/sysctl.d/99-test.conf";

fn lint(source: &str, target: TargetVersion) -> Vec<Diagnostic> {
    lint_str_with_target(source, Path::new(PATH), Some(target))
}

/// All `sysctld-W02` (Warning STIG-baseline) diagnostics, asserting the tier.
fn w02s(diags: &[Diagnostic]) -> Vec<&Diagnostic> {
    diags
        .iter()
        .filter(|d| d.code == "sysctld-W02")
        .inspect(|d| {
            assert_eq!(
                d.severity,
                Severity::Warning,
                "sysctld-W02 must be Warning, got {:?}",
                d.severity
            );
        })
        .collect()
}

/// The W02 findings whose message names `key` (the dotted sysctl key).
fn w02_for<'a>(diags: &'a [Diagnostic], key: &str) -> Vec<&'a Diagnostic> {
    w02s(diags)
        .into_iter()
        .filter(|d| d.message.contains(key))
        .collect()
}

// ---------------------------------------------------------------------------
// MISSING key -> W02 anchored at the file (line 0, no source line)
// ---------------------------------------------------------------------------

#[test]
fn w02_fires_for_a_missing_required_key() {
    // A config that sets only an unrelated key leaves every STIG key unset; each
    // unset required key is a W02. Pin one concrete key (kernel.dmesg_restrict)
    // and that a missing finding anchors at line 0 (no source line to point at).
    let diags = lint("vm.swappiness = 10\n", TargetVersion::Rhel9);
    let found = w02_for(&diags, "kernel.dmesg_restrict");
    assert_eq!(
        found.len(),
        1,
        "exactly one W02 for the unset kernel.dmesg_restrict: {diags:?}"
    );
    assert_eq!(
        found[0].line, 0,
        "a MISSING-key W02 anchors at line 0 (no source line): {:?}",
        found[0]
    );
    assert!(
        found[0].source_id.is_none(),
        "a MISSING-key W02 carries no source_id (renders as a plain file:0:0 line): {:?}",
        found[0]
    );
}

#[test]
fn w02_missing_message_names_the_key_and_stig_id() {
    let diags = lint("vm.swappiness = 10\n", TargetVersion::Rhel9);
    let d = w02_for(&diags, "kernel.dmesg_restrict");
    assert_eq!(d.len(), 1, "{diags:?}");
    assert!(
        d[0].message.contains("RHEL-09-213010"),
        "the W02 message cites the STIG id; was: {:?}",
        d[0].message
    );
}

// ---------------------------------------------------------------------------
// PRESENT but insecure -> W02 anchored at the real assignment line/span
// ---------------------------------------------------------------------------

#[test]
fn w02_fires_for_a_present_but_insecure_value_anchored_at_the_line() {
    // kernel.dmesg_restrict requires 1; the config sets it to 0 -> insecure. This
    // W02 anchors at the assignment's real line (1), NOT at line 0, and names both
    // the found value (0) and the required value (1).
    let diags = lint("kernel.dmesg_restrict = 0\n", TargetVersion::Rhel9);
    let found = w02_for(&diags, "kernel.dmesg_restrict");
    assert_eq!(
        found.len(),
        1,
        "a present-but-insecure key fires exactly one W02 (not also a missing one): {diags:?}"
    );
    assert_eq!(
        found[0].line, 1,
        "a present-but-insecure W02 anchors at the assignment's real line, not 0: {:?}",
        found[0]
    );
    assert_ne!(
        found[0].span,
        0..0,
        "a present-but-insecure W02 carries the assignment's real byte span: {:?}",
        found[0]
    );
    assert!(
        found[0].source_id.is_some(),
        "a present-but-insecure W02 sets source_id (ariadne snippet path): {:?}",
        found[0]
    );
    assert!(
        found[0].message.contains('0') && found[0].message.contains('1'),
        "the W02 names the insecure found value (0) and the required value (1): {:?}",
        found[0].message
    );
}

#[test]
fn w02_clean_when_present_at_the_secure_value() {
    // kernel.dmesg_restrict = 1 satisfies the requirement: no W02 for that key
    // (other unset keys still fire, but not this one).
    let diags = lint("kernel.dmesg_restrict = 1\n", TargetVersion::Rhel9);
    assert!(
        w02_for(&diags, "kernel.dmesg_restrict").is_empty(),
        "a key set to its secure value must not fire W02: {diags:?}"
    );
}

// ---------------------------------------------------------------------------
// Version-agnostic gate: no target -> no W02 at all
// ---------------------------------------------------------------------------

#[test]
fn w02_silent_when_target_is_none() {
    // With no --target, the STIG baseline does not run: a config that would fire
    // many W02 under a target emits ZERO sysctld-W02 (only F01/W01 apply, and
    // there are none here -> no diagnostics at all).
    let diags = lint_str_with_target("kernel.dmesg_restrict = 0\n", Path::new(PATH), None);
    assert!(
        diags.iter().all(|d| d.code != "sysctld-W02"),
        "no --target means no W02: {diags:?}"
    );
    assert!(
        diags.is_empty(),
        "a single clean (non-conflicting) assignment with no target yields nothing: {diags:?}"
    );
}

// ---------------------------------------------------------------------------
// Set-valued acceptance + per-target divergence (the sharpest tests)
// ---------------------------------------------------------------------------

#[test]
fn w02_kptr_restrict_accepts_both_1_and_2_on_rhel9() {
    // rhel9/rhel10 accept EITHER 1 or 2 for kernel.kptr_restrict (set-valued).
    assert!(
        w02_for(
            &lint("kernel.kptr_restrict = 2\n", TargetVersion::Rhel9),
            "kernel.kptr_restrict"
        )
        .is_empty(),
        "rhel9 accepts kptr_restrict=2"
    );
    assert!(
        w02_for(
            &lint("kernel.kptr_restrict = 1\n", TargetVersion::Rhel9),
            "kernel.kptr_restrict"
        )
        .is_empty(),
        "rhel9 accepts kptr_restrict=1"
    );
}

#[test]
fn w02_kptr_restrict_value_2_is_insecure_on_rhel8() {
    // DIVERGENCE: rhel8 accepts ONLY 1 for kptr_restrict, so =2 is insecure on
    // rhel8 while clean on rhel9 (above). Kills a "same table for every target"
    // mutant.
    let diags = lint("kernel.kptr_restrict = 2\n", TargetVersion::Rhel8);
    let found = w02_for(&diags, "kernel.kptr_restrict");
    assert_eq!(
        found.len(),
        1,
        "rhel8 rejects kptr_restrict=2 (accepts only 1): {found:?}"
    );
    assert_eq!(found[0].line, 1, "anchored at the assignment line");
}

#[test]
fn w02_rp_filter_value_2_insecure_on_rhel9_but_clean_on_rhel8() {
    // The sharpest divergence: net.ipv4.conf.all.rp_filter accepts {1,2} on
    // rhel8/rhel10 but ONLY {1} on rhel9 (rhel9's rule.yml excludes the [1,2]
    // branch; the var default is 1, and OCIL forbids 2).
    let src = "net.ipv4.conf.all.rp_filter = 2\n";
    assert_eq!(
        w02_for(
            &lint(src, TargetVersion::Rhel9),
            "net.ipv4.conf.all.rp_filter"
        )
        .len(),
        1,
        "rhel9 rejects all.rp_filter=2"
    );
    assert!(
        w02_for(
            &lint(src, TargetVersion::Rhel8),
            "net.ipv4.conf.all.rp_filter"
        )
        .is_empty(),
        "rhel8 accepts all.rp_filter=2"
    );
}

#[test]
fn w02_presence_divergence_max_user_namespaces() {
    // user.max_user_namespaces is required on rhel8/rhel9 but ABSENT from rhel10's
    // baseline: an unset config fires the missing W02 on rhel9 but not on rhel10.
    let src = "vm.swappiness = 10\n";
    assert_eq!(
        w02_for(&lint(src, TargetVersion::Rhel9), "user.max_user_namespaces").len(),
        1,
        "rhel9 requires user.max_user_namespaces"
    );
    assert!(
        w02_for(
            &lint(src, TargetVersion::Rhel10),
            "user.max_user_namespaces"
        )
        .is_empty(),
        "rhel10 does not list user.max_user_namespaces"
    );
}

// ---------------------------------------------------------------------------
// Canonicalization + all/default independence
// ---------------------------------------------------------------------------

#[test]
fn w02_canonicalizes_a_slash_form_key() {
    // The operator may write the key with `/` separators; it canonicalizes to the
    // same /proc/sys path as the dotted table key, so it satisfies the check.
    assert!(
        w02_for(
            &lint("kernel/dmesg_restrict = 1\n", TargetVersion::Rhel9),
            "kernel.dmesg_restrict"
        )
        .is_empty(),
        "a slash-form key set securely must satisfy the dotted table key"
    );
}

#[test]
fn w02_checks_all_and_default_variants_independently() {
    // Setting net.ipv4.conf.all.rp_filter securely but NOT the paired
    // .default. variant fires W02 for default only (separate STIG IDs).
    let diags = lint("net.ipv4.conf.all.rp_filter = 1\n", TargetVersion::Rhel9);
    assert_eq!(
        w02_for(&diags, "net.ipv4.conf.default.rp_filter").len(),
        1,
        "the unset .default. variant fires W02: {diags:?}"
    );
    assert!(
        w02_for(&diags, "net.ipv4.conf.all.rp_filter").is_empty(),
        "the satisfied .all. variant must NOT fire W02: {diags:?}"
    );
}

// ---------------------------------------------------------------------------
// Directory mode anchoring (missing -> dir, insecure -> the drop-in file)
// ---------------------------------------------------------------------------

#[test]
fn w02_dir_mode_anchors_missing_at_dir_and_insecure_at_the_dropin() {
    // One drop-in sets kernel.dmesg_restrict insecurely (=0). The insecure W02
    // anchors at that drop-in file (line 1); a MISSING key (kptr_restrict) anchors
    // at the directory (line 0).
    let dir = tempdir().expect("temp dir");
    let dropin = dir.path().join("10-a.conf");
    std::fs::write(&dropin, "kernel.dmesg_restrict = 0\n").expect("write drop-in");

    let (diags, _sources) = lint_dir_with_target(dir.path(), Some(TargetVersion::Rhel9));

    let insecure = w02_for(&diags, "kernel.dmesg_restrict");
    assert_eq!(
        insecure.len(),
        1,
        "the insecure dmesg_restrict fires W02: {diags:?}"
    );
    assert_eq!(
        insecure[0].line, 1,
        "insecure anchors at the drop-in's line"
    );
    assert_eq!(
        insecure[0].file, dropin,
        "insecure anchors at the real drop-in file, not the directory"
    );

    let missing = w02_for(&diags, "kernel.kptr_restrict");
    assert_eq!(
        missing.len(),
        1,
        "the unset kptr_restrict fires a missing W02: {diags:?}"
    );
    assert_eq!(missing[0].line, 0, "a missing-key W02 anchors at line 0");
    assert_eq!(
        missing[0].file.as_path(),
        dir.path(),
        "a missing-key W02 anchors at the directory (no single source line)"
    );
}

// ---------------------------------------------------------------------------
// Strengthening (adversarial-impl-reviewer): int-typed values are compared by
// their kernel EFFECTIVE value, not by raw string. The kernel parses an int
// sysctl with base-0 radix (`strtoul_lenient(p, &p, 0, val)` in kernel/sysctl.c
// `proc_get_long`, verified), so `0x1` / `01` are the SAME effective value as `1`;
// flagging them is a false positive. `kernel.core_pattern` is STRING-typed and
// must stay exact-match (its OVAL datatype is `string`).
// ---------------------------------------------------------------------------

#[test]
fn w02_accepts_hex_and_leading_zero_forms_of_a_compliant_int() {
    // 0x1 == 1 and 01 == 1 under the kernel's base-0 parse: a key required to be 1
    // is satisfied by either form (RED today: exact-string compare over-flags them).
    for src in [
        "kernel.dmesg_restrict = 0x1\n",
        "kernel.dmesg_restrict = 01\n",
    ] {
        assert!(
            w02_for(&lint(src, TargetVersion::Rhel9), "kernel.dmesg_restrict").is_empty(),
            "the kernel-equivalent radix form of the compliant value must not fire W02: {src:?}"
        );
    }
    // 0x2 == 2 is in the rhel9 kptr_restrict accepted set {1,2}.
    assert!(
        w02_for(
            &lint("kernel.kptr_restrict = 0x2\n", TargetVersion::Rhel9),
            "kernel.kptr_restrict"
        )
        .is_empty(),
        "0x2 == 2 is accepted for kptr_restrict on rhel9"
    );
}

#[test]
fn w02_still_flags_an_int_whose_effective_value_is_wrong() {
    // Normalizing must not blindly accept: 0x0 == 0 != required 1 stays insecure,
    // and a value that is not a parseable int at all is also flagged.
    assert_eq!(
        w02_for(
            &lint("kernel.dmesg_restrict = 0x0\n", TargetVersion::Rhel9),
            "kernel.dmesg_restrict"
        )
        .len(),
        1,
        "0x0 == 0 is still insecure for a key requiring 1"
    );
    assert_eq!(
        w02_for(
            &lint("kernel.dmesg_restrict = enabled\n", TargetVersion::Rhel9),
            "kernel.dmesg_restrict"
        )
        .len(),
        1,
        "a non-integer value for an int key is insecure"
    );
}

#[test]
fn w02_core_pattern_is_exact_string_not_numeric() {
    // core_pattern is STRING-typed: the exact STIG value is clean, a different
    // string fires, and it is NOT numeric-normalized (a regression that treated it
    // as int would parse-fail `|/bin/false` and wrongly flag the compliant value).
    assert!(
        w02_for(
            &lint("kernel.core_pattern = |/bin/false\n", TargetVersion::Rhel9),
            "kernel.core_pattern"
        )
        .is_empty(),
        "the exact required core_pattern is compliant"
    );
    assert_eq!(
        w02_for(
            &lint("kernel.core_pattern = |/bin/true\n", TargetVersion::Rhel9),
            "kernel.core_pattern"
        )
        .len(),
        1,
        "a different core_pattern string is insecure (exact-match, not numeric)"
    );
}
