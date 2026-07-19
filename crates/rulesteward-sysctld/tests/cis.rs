//! Crate-level RED tests for the sysctld CIS baseline TABLE (issue #527, Wave-3
//! CIS), authored at the test-author barrier BEFORE the impl. They call the frozen
//! public accessor `rulesteward_sysctld::cis_baseline` and are RED against its
//! `todo!()` scaffold: only the grounded per-product tables turn them green.
//! Mirrors how `tests/baseline.rs` structures the STIG `stig_baseline` tests.
//!
//! # Ground truth
//! Every key + control id + title + accepted value asserted here is transcribed
//! from the merged `tools/cis-update derive --values` grounding at the pinned
//! commit `519b5fe8` (SELECTION-AWARE: inline `sysctlval` -> the SELECTED variable
//! option -> `options.default`). Control ids + `ComplianceAsCode` titles ONLY; NO CIS
//! benchmark prose (license discipline). Per-product family sizes:
//! rhel8 33 keys, rhel9 25 keys, rhel10 33 keys.
//!
//! The load-bearing divergences pinned below (a wrong "one table for every product"
//! impl cannot pass all of these at once):
//! * rhel8/rhel10 carry 33 keys; rhel9 carries only 25 (a much smaller benchmark).
//! * `fs.suid_dumpable` is present on rhel8+rhel10 but ABSENT from rhel9.
//! * `kernel.kptr_restrict` accepts {1} on rhel8, {1,2} on rhel10, ABSENT on rhel9.
//! * `net.ipv4.conf.all.rp_filter` accepts {1,2} on rhel8/rhel10 but ONLY {1} on rhel9.
//! * Control ids diverge: `kernel.randomize_va_space` = 1.5.8 (rhel8/10) vs 1.5.1
//!   (rhel9); `net.ipv4.ip_forward` = 3.3.1.1 (rhel8/10) vs 3.3.1 (rhel9).
//! * Titles diverge: rhel9 uses descriptive `ComplianceAsCode` titles ("Ensure IP
//!   forwarding is disabled") where rhel8/rhel10 use "Ensure <key> is configured".
//!
//! This file has TWO halves:
//! * The TABLE tests (below) pin the public `cis_baseline` accessor + per-product
//!   `CisControl` rows.
//! * The EMIT tests (second half of this file) pin the resolved design (user DECISION,
//!   Option B): a standalone version-aware CIS baseline pass wired into
//!   `parser::lint_str_with_target` / `lint_dir_with_target` (exactly like the STIG
//!   W02 wiring) that emits the NEW lint code `sysctld-W04` - one finding per
//!   CIS-required key that is unset or set outside the benchmark-accepted set - each
//!   carrying exactly ONE `Framework::Cis` `ControlRef` whose id is the CIS control
//!   id and whose `.with_name(...)` is the `ComplianceAsCode` title. W04 runs ONLY
//!   under a `--target` product; no target => no W04. The STIG `sysctld-W02`
//!   semantics are UNTOUCHED - W02 and W04 coexist as distinct codes/frameworks.
//!   These emit tests drive the public pipeline (not a crate-private fn), so they
//!   pin both the emit logic AND the in-crate wiring; they are RED until the
//!   implementer adds the pass + wires it. (Scope: single-file + single-directory
//!   modes, mirroring `tests/baseline.rs`; `--system` W04 is out of this lane.)

use std::path::Path;

use rulesteward_core::{Diagnostic, Framework, Severity};
use rulesteward_sysctld::parser::{lint_dir_with_target, lint_str_with_target};
use rulesteward_sysctld::{CisControl, TargetVersion, cis_baseline};
use tempfile::tempdir;

/// The CIS entry for `key` in `table`, if the benchmark lists it for this product.
fn entry<'a>(table: &'a [CisControl], key: &str) -> Option<&'a CisControl> {
    table.iter().find(|e| e.key == key)
}

/// The CIS entry for `key`, panicking with a product-labelled message if absent.
fn require<'a>(table: &'a [CisControl], t: TargetVersion, key: &str) -> &'a CisControl {
    entry(table, key).unwrap_or_else(|| panic!("{t:?} CIS baseline must list {key:?}"))
}

// ---------------------------------------------------------------------------
// Per-product table sizes (the coarsest divergence)
// ---------------------------------------------------------------------------

#[test]
fn cis_baseline_tables_have_the_grounded_sizes() {
    // One CisControl per benchmark sysctl key. rhel8 (cis v4.0.0) / rhel10 (v1.0.1)
    // carry 33 keys; rhel9 (v2.0.0) is a sharply smaller benchmark at 25.
    assert_eq!(
        cis_baseline(TargetVersion::Rhel8).len(),
        33,
        "rhel8 CIS sysctl key count"
    );
    assert_eq!(
        cis_baseline(TargetVersion::Rhel9).len(),
        25,
        "rhel9 CIS sysctl key count"
    );
    assert_eq!(
        cis_baseline(TargetVersion::Rhel10).len(),
        33,
        "rhel10 CIS sysctl key count"
    );
}

// ---------------------------------------------------------------------------
// Presence divergence: a key in rhel8+rhel10 but ABSENT from rhel9 (required)
// ---------------------------------------------------------------------------

#[test]
fn cis_baseline_fs_suid_dumpable_present_on_rhel8_rhel10_absent_on_rhel9() {
    // fs.suid_dumpable is CIS 1.5.4 = 0 on rhel8 and rhel10, but is NOT in the
    // rhel9 benchmark at all. The mandatory rhel8+rhel10-present / rhel9-absent pin.
    for t in [TargetVersion::Rhel8, TargetVersion::Rhel10] {
        let table = cis_baseline(t);
        let e = require(table, t, "fs.suid_dumpable");
        assert_eq!(e.accepted, ["0"], "{t:?} fs.suid_dumpable accepts 0");
        assert_eq!(e.cis_id, "1.5.4", "{t:?} fs.suid_dumpable control id");
    }
    let r9 = cis_baseline(TargetVersion::Rhel9);
    assert!(
        entry(r9, "fs.suid_dumpable").is_none(),
        "rhel9 CIS does NOT list fs.suid_dumpable: {:?}",
        r9.iter().map(|e| e.key).collect::<Vec<_>>()
    );
}

// ---------------------------------------------------------------------------
// SET-valued acceptance + per-product value divergence (the sharpest tests)
// ---------------------------------------------------------------------------

#[test]
fn cis_baseline_all_rp_filter_is_set_valued_on_rhel8_rhel10_single_on_rhel9() {
    // net.ipv4.conf.all.rp_filter accepts {1,2} on rhel8/rhel10 (SET-valued) but
    // ONLY {1} on rhel9. Pins SET-valued acceptance AND the value divergence.
    for t in [TargetVersion::Rhel8, TargetVersion::Rhel10] {
        let table = cis_baseline(t);
        let e = require(table, t, "net.ipv4.conf.all.rp_filter");
        assert_eq!(e.accepted, ["1", "2"], "{t:?} all.rp_filter accepts 1 or 2");
        assert!(e.numeric, "{t:?} all.rp_filter is integer-typed");
    }
    let r9 = cis_baseline(TargetVersion::Rhel9);
    let e9 = require(r9, TargetVersion::Rhel9, "net.ipv4.conf.all.rp_filter");
    assert_eq!(e9.accepted, ["1"], "rhel9 all.rp_filter accepts ONLY 1");
}

#[test]
fn cis_baseline_kptr_restrict_diverges_and_is_absent_on_rhel9() {
    // kernel.kptr_restrict: {1} on rhel8, {1,2} on rhel10, and ABSENT from rhel9.
    // A second present/absent + value divergence, orthogonal to rp_filter.
    let r8 = cis_baseline(TargetVersion::Rhel8);
    assert_eq!(
        require(r8, TargetVersion::Rhel8, "kernel.kptr_restrict").accepted,
        ["1"],
        "rhel8 kptr_restrict accepts only 1"
    );
    let r10 = cis_baseline(TargetVersion::Rhel10);
    assert_eq!(
        require(r10, TargetVersion::Rhel10, "kernel.kptr_restrict").accepted,
        ["1", "2"],
        "rhel10 kptr_restrict accepts 1 or 2"
    );
    let r9 = cis_baseline(TargetVersion::Rhel9);
    assert!(
        entry(r9, "kernel.kptr_restrict").is_none(),
        "rhel9 CIS does NOT list kernel.kptr_restrict"
    );
}

// ---------------------------------------------------------------------------
// Per-product control-id divergence (same key, different CIS id per product)
// ---------------------------------------------------------------------------

#[test]
fn cis_baseline_control_ids_diverge_per_product() {
    // kernel.randomize_va_space: 1.5.8 on rhel8/rhel10 vs 1.5.1 on rhel9.
    for (t, id) in [
        (TargetVersion::Rhel8, "1.5.8"),
        (TargetVersion::Rhel10, "1.5.8"),
        (TargetVersion::Rhel9, "1.5.1"),
    ] {
        let table = cis_baseline(t);
        assert_eq!(
            require(table, t, "kernel.randomize_va_space").cis_id,
            id,
            "{t:?} kernel.randomize_va_space control id"
        );
    }
    // net.ipv4.ip_forward: 3.3.1.1 on rhel8/rhel10 vs 3.3.1 on rhel9.
    for (t, id) in [
        (TargetVersion::Rhel8, "3.3.1.1"),
        (TargetVersion::Rhel10, "3.3.1.1"),
        (TargetVersion::Rhel9, "3.3.1"),
    ] {
        let table = cis_baseline(t);
        assert_eq!(
            require(table, t, "net.ipv4.ip_forward").cis_id,
            id,
            "{t:?} net.ipv4.ip_forward control id"
        );
    }
}

// ---------------------------------------------------------------------------
// Per-product CaC title divergence (the `.with_name(<CaC title>)` data source)
// ---------------------------------------------------------------------------

#[test]
fn cis_baseline_titles_are_the_per_product_cac_titles() {
    // net.ipv4.ip_forward: rhel8/rhel10 use the "is configured" phrasing; rhel9
    // uses the descriptive "IP forwarding is disabled" title.
    let ip_fwd_configured = "Ensure net.ipv4.ip_forward is configured (Automated)";
    for t in [TargetVersion::Rhel8, TargetVersion::Rhel10] {
        let table = cis_baseline(t);
        assert_eq!(
            require(table, t, "net.ipv4.ip_forward").title,
            ip_fwd_configured,
            "{t:?} net.ipv4.ip_forward title"
        );
    }
    let r9 = cis_baseline(TargetVersion::Rhel9);
    assert_eq!(
        require(r9, TargetVersion::Rhel9, "net.ipv4.ip_forward").title,
        "Ensure IP forwarding is disabled (Automated)",
        "rhel9 net.ipv4.ip_forward title"
    );

    // kernel.randomize_va_space: rhel8 "is configured" vs rhel9 "address space
    // layout randomization is enabled".
    let r8 = cis_baseline(TargetVersion::Rhel8);
    assert_eq!(
        require(r8, TargetVersion::Rhel8, "kernel.randomize_va_space").title,
        "Ensure kernel.randomize_va_space is configured (Automated)",
        "rhel8 kernel.randomize_va_space title"
    );
    assert_eq!(
        require(r9, TargetVersion::Rhel9, "kernel.randomize_va_space").title,
        "Ensure address space layout randomization is enabled (Automated)",
        "rhel9 kernel.randomize_va_space title"
    );
}

// ---------------------------------------------------------------------------
// Well-formedness + uniqueness + every sysctld CIS key is integer-typed
// ---------------------------------------------------------------------------

#[test]
fn cis_baseline_entries_are_wellformed_unique_and_numeric_per_product() {
    for t in [
        TargetVersion::Rhel8,
        TargetVersion::Rhel9,
        TargetVersion::Rhel10,
    ] {
        let table = cis_baseline(t);
        let mut seen = std::collections::HashSet::new();
        for e in table {
            assert!(!e.key.is_empty(), "{t:?} has an empty key");
            assert!(
                !e.cis_id.is_empty(),
                "{t:?} key {:?} has an empty CIS id",
                e.key
            );
            assert!(
                !e.title.is_empty(),
                "{t:?} key {:?} has an empty title",
                e.key
            );
            assert!(
                !e.accepted.is_empty(),
                "{t:?} key {:?} has no accepted values",
                e.key
            );
            assert!(
                e.accepted.iter().all(|v| !v.is_empty()),
                "{t:?} key {:?} has an empty accepted value",
                e.key
            );
            // Every sysctld CIS key is integer-typed: the CIS sysctl set has no
            // string-typed key (unlike the STIG baseline's kernel.core_pattern).
            assert!(
                e.numeric,
                "{t:?} key {:?}: every sysctld CIS key is integer-typed",
                e.key
            );
            assert!(seen.insert(e.key), "{t:?} has a duplicate key {:?}", e.key);
        }
    }
}

// ===========================================================================
// EMIT tests (sysctld-W04): the version-aware CIS baseline pass (user DECISION,
// Option B). RED until the implementer adds the pass + wires it into
// parser::lint_str_with_target / lint_dir_with_target (exactly like STIG W02).
// They drive the public pipeline and filter to `code == "sysctld-W04"`, so they
// pin BOTH the emit logic and the wiring. Ground truth: the merged
// `tools/cis-update derive --values` grounding at pin 519b5fe8 (control ids +
// ComplianceAsCode titles ONLY; no CIS benchmark prose). Structured like
// tests/baseline.rs (the STIG W02 pipeline tests).
// ===========================================================================

const PATH: &str = "/etc/sysctl.d/99-cis-test.conf";

fn lint(source: &str, target: TargetVersion) -> Vec<Diagnostic> {
    lint_str_with_target(source, Path::new(PATH), Some(target))
}

/// All `sysctld-W04` (Warning CIS-baseline) diagnostics, asserting the tier.
fn w04s(diags: &[Diagnostic]) -> Vec<&Diagnostic> {
    diags
        .iter()
        .filter(|d| d.code == "sysctld-W04")
        .inspect(|d| {
            assert_eq!(
                d.severity,
                Severity::Warning,
                "sysctld-W04 must be Warning, got {:?}",
                d.severity
            );
        })
        .collect()
}

/// The W04 findings whose message names `key` (the dotted sysctl key).
fn w04_for<'a>(diags: &'a [Diagnostic], key: &str) -> Vec<&'a Diagnostic> {
    w04s(diags)
        .into_iter()
        .filter(|d| d.message.contains(key))
        .collect()
}

// ---------------------------------------------------------------------------
// Version-aware gate: W04 runs ONLY under a --target product
// ---------------------------------------------------------------------------

#[test]
fn w04_runs_only_under_a_target() {
    // With a --target product the CIS baseline runs and fires W04 for the unset
    // keys; with NO target it never runs. The positive half (>=1 W04 under a
    // target) is the control that makes the negative half meaningful (a vacuous
    // "no W04" is indistinguishable from "the pass never ran").
    let comment_only = "# no keys set\n";
    let with_target = lint(comment_only, TargetVersion::Rhel9);
    assert!(
        !w04s(&with_target).is_empty(),
        "a --target product must run the CIS baseline and fire W04 for unset keys: {with_target:?}"
    );
    let no_target = lint_str_with_target(comment_only, Path::new(PATH), None);
    assert!(
        no_target.iter().all(|d| d.code != "sysctld-W04"),
        "with no --target the CIS baseline must not run (no W04): {no_target:?}"
    );
}

// ---------------------------------------------------------------------------
// One finding per missing required key + the sharp per-product size divergence
// ---------------------------------------------------------------------------

#[test]
fn w04_empty_config_fires_one_finding_per_cis_key_per_product() {
    // A config that sets no CIS key leaves EVERY benchmark key unset, so the pass
    // fires exactly one missing-key W04 per key: rhel8 33, rhel9 25, rhel10 33.
    // Pins "one finding per missing required key" AND the sharp per-product size
    // divergence on the EMIT path (rhel9 is a much smaller benchmark).
    let comment_only = "# no keys set\n";
    for (t, n) in [
        (TargetVersion::Rhel8, 33),
        (TargetVersion::Rhel9, 25),
        (TargetVersion::Rhel10, 33),
    ] {
        let diags = lint(comment_only, t);
        assert_eq!(
            w04s(&diags).len(),
            n,
            "{t:?}: one W04 per unset CIS key ({n} total): {diags:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// The central Option-B contract: exactly ONE Framework::Cis control with the
// CaC title via .with_name(...), on both the missing and the insecure branch
// ---------------------------------------------------------------------------

#[test]
fn w04_missing_key_carries_exactly_one_cis_control_with_name() {
    // Missing branch: a missing CIS key fires ONE W04, anchored at the file (line
    // 0, no source line), carrying EXACTLY ONE Framework::Cis ControlRef whose id
    // is the CIS control id and whose .with_name(...) is the ComplianceAsCode
    // title. rhel9 net.ipv4.ip_forward: id 3.3.1, title "Ensure IP forwarding is
    // disabled (Automated)".
    let diags = lint("# nothing set\n", TargetVersion::Rhel9);
    let found = w04_for(&diags, "net.ipv4.ip_forward");
    assert_eq!(
        found.len(),
        1,
        "exactly one W04 for the unset net.ipv4.ip_forward: {diags:?}"
    );
    let d = found[0];
    assert_eq!(d.line, 0, "a MISSING-key W04 anchors at line 0: {d:?}");
    assert!(
        d.source_id.is_none(),
        "a MISSING-key W04 carries no source_id: {d:?}"
    );
    assert_eq!(
        d.controls.len(),
        1,
        "a W04 finding carries EXACTLY ONE control: {:?}",
        d.controls
    );
    assert_eq!(
        d.controls[0].framework,
        Framework::Cis,
        "the control is CIS"
    );
    assert_eq!(d.controls[0].id, "3.3.1", "rhel9 ip_forward CIS id");
    assert_eq!(
        d.controls[0].name.as_deref(),
        Some("Ensure IP forwarding is disabled (Automated)"),
        "the CIS control carries the ComplianceAsCode title via .with_name(...)"
    );
}

#[test]
fn w04_present_value_fires_when_insecure_and_is_clean_when_compliant() {
    // Insecure branch: net.ipv4.ip_forward requires 0 on rhel9; set to 1 => one
    // W04, anchored at the assignment's REAL line (1), NOT also a missing finding,
    // carrying the same single Cis control (id + title). And set to the compliant
    // value 0 => NO W04 for that key.
    let diags = lint("net.ipv4.ip_forward = 1\n", TargetVersion::Rhel9);
    let found = w04_for(&diags, "net.ipv4.ip_forward");
    assert_eq!(
        found.len(),
        1,
        "a present-but-insecure key fires exactly one W04 (not also a missing one): {diags:?}"
    );
    let d = found[0];
    assert_eq!(
        d.line, 1,
        "a present-but-insecure W04 anchors at the assignment's real line: {d:?}"
    );
    assert_ne!(
        d.span,
        0..0,
        "it carries the assignment's real byte span: {d:?}"
    );
    assert!(
        d.source_id.is_some(),
        "a present-but-insecure W04 sets source_id (ariadne snippet path): {d:?}"
    );
    assert_eq!(
        d.controls.len(),
        1,
        "still exactly one control: {:?}",
        d.controls
    );
    assert_eq!(d.controls[0].framework, Framework::Cis);
    assert_eq!(d.controls[0].id, "3.3.1");
    assert_eq!(
        d.controls[0].name.as_deref(),
        Some("Ensure IP forwarding is disabled (Automated)")
    );

    // Compliant value => clean (positively gated by the insecure half above, so
    // this is not a vacuous pass).
    let clean = lint("net.ipv4.ip_forward = 0\n", TargetVersion::Rhel9);
    assert!(
        w04_for(&clean, "net.ipv4.ip_forward").is_empty(),
        "a key set to its compliant value must not fire W04: {clean:?}"
    );
}

// ---------------------------------------------------------------------------
// SET-valued acceptance + per-product value divergence (the sharpest emit test)
// ---------------------------------------------------------------------------

#[test]
fn w04_set_valued_acceptance_diverges_rhel8_rhel9() {
    // net.ipv4.conf.all.rp_filter accepts the SET {1,2} on rhel8/rhel10 but ONLY
    // {1} on rhel9. So =2 is compliant on rhel8/rhel10 (no W04) yet non-compliant
    // on rhel9 (one W04). Pins SET-valued acceptance + the value divergence on the
    // EMIT path; kills a "one table for every product" mutant.
    let src = "net.ipv4.conf.all.rp_filter = 2\n";
    for t in [TargetVersion::Rhel8, TargetVersion::Rhel10] {
        assert!(
            w04_for(&lint(src, t), "net.ipv4.conf.all.rp_filter").is_empty(),
            "{t:?} accepts all.rp_filter=2 (set {{1,2}})"
        );
    }
    assert_eq!(
        w04_for(
            &lint(src, TargetVersion::Rhel9),
            "net.ipv4.conf.all.rp_filter"
        )
        .len(),
        1,
        "rhel9 rejects all.rp_filter=2 (accepts only 1)"
    );
}

// ---------------------------------------------------------------------------
// Int values compare by the kernel's base-0 effective value (mirrors W02)
// ---------------------------------------------------------------------------

#[test]
fn w04_int_compare_uses_kernel_base0_radix() {
    // net.ipv4.ip_forward requires 0 on rhel9: 0x0 == 0 is compliant (no W04);
    // 0x1 == 1 != 0 is non-compliant (one W04). Pins the base-0 numeric compare on
    // the emit path (a raw-string compare would mis-handle both).
    assert!(
        w04_for(
            &lint("net.ipv4.ip_forward = 0x0\n", TargetVersion::Rhel9),
            "net.ipv4.ip_forward"
        )
        .is_empty(),
        "0x0 == 0 is the compliant value (base-0 compare)"
    );
    assert_eq!(
        w04_for(
            &lint("net.ipv4.ip_forward = 0x1\n", TargetVersion::Rhel9),
            "net.ipv4.ip_forward"
        )
        .len(),
        1,
        "0x1 == 1 != required 0 stays non-compliant"
    );
}

// ---------------------------------------------------------------------------
// Presence divergence: a key required on rhel8+rhel10 but ABSENT from rhel9
// (the mandatory divergence pin, on the emit path)
// ---------------------------------------------------------------------------

#[test]
fn w04_presence_divergence_fs_suid_dumpable_rhel8_rhel10_not_rhel9() {
    // fs.suid_dumpable is a CIS key on rhel8 + rhel10 (id 1.5.4, accepts 0) but is
    // ABSENT from the rhel9 benchmark. So an unset config fires a missing W04 for
    // it on rhel8/rhel10 but NEVER on rhel9.
    let comment_only = "# nothing set\n";
    for t in [TargetVersion::Rhel8, TargetVersion::Rhel10] {
        let diags = lint(comment_only, t);
        let found = w04_for(&diags, "fs.suid_dumpable");
        assert_eq!(found.len(), 1, "{t:?} requires fs.suid_dumpable: fires W04");
        assert_eq!(
            found[0].controls[0].id, "1.5.4",
            "{t:?} fs.suid_dumpable CIS id"
        );
        assert_eq!(
            found[0].controls[0].name.as_deref(),
            Some("Ensure fs.suid_dumpable is configured (Automated)"),
            "{t:?} fs.suid_dumpable title"
        );
    }
    assert!(
        w04_for(
            &lint(comment_only, TargetVersion::Rhel9),
            "fs.suid_dumpable"
        )
        .is_empty(),
        "rhel9 does NOT list fs.suid_dumpable: no W04 for it"
    );
}

// ---------------------------------------------------------------------------
// Per-product control id AND CaC title divergence for the SAME key
// ---------------------------------------------------------------------------

#[test]
fn w04_control_id_and_title_diverge_per_product() {
    // net.ipv4.ip_forward: rhel8/rhel10 => id 3.3.1.1 + the "is configured"
    // title; rhel9 => id 3.3.1 + the descriptive "IP forwarding is disabled"
    // title. Kills a mutant that hardcodes one product's id/title for all.
    for t in [TargetVersion::Rhel8, TargetVersion::Rhel10] {
        let diags = lint("# nothing\n", t);
        let found = w04_for(&diags, "net.ipv4.ip_forward");
        assert_eq!(found.len(), 1, "{t:?} requires net.ipv4.ip_forward");
        assert_eq!(
            found[0].controls[0].id, "3.3.1.1",
            "{t:?} ip_forward CIS id"
        );
        assert_eq!(
            found[0].controls[0].name.as_deref(),
            Some("Ensure net.ipv4.ip_forward is configured (Automated)"),
            "{t:?} ip_forward title (the 'is configured' phrasing)"
        );
    }
    let r9_diags = lint("# nothing\n", TargetVersion::Rhel9);
    let r9 = w04_for(&r9_diags, "net.ipv4.ip_forward");
    assert_eq!(r9.len(), 1, "rhel9 requires net.ipv4.ip_forward");
    assert_eq!(r9[0].controls[0].id, "3.3.1", "rhel9 ip_forward CIS id");
    assert_eq!(
        r9[0].controls[0].name.as_deref(),
        Some("Ensure IP forwarding is disabled (Automated)"),
        "rhel9 ip_forward title (the descriptive phrasing)"
    );
}

// ---------------------------------------------------------------------------
// W04 is ADDITIVE: it coexists with the untouched STIG W02, distinct frameworks
// ---------------------------------------------------------------------------

#[test]
fn w04_and_w02_coexist_with_distinct_frameworks() {
    // A key required by BOTH baselines fires one W02 (Stig) and one W04 (Cis),
    // each with its own per-framework control. kernel.randomize_va_space on rhel9:
    // STIG id RHEL-09-213070; CIS id 1.5.1, title "Ensure address space layout
    // randomization is enabled (Automated)". Pins that W04 does NOT replace W02.
    let diags = lint("# nothing set\n", TargetVersion::Rhel9);

    let w02 = diags
        .iter()
        .filter(|d| d.code == "sysctld-W02" && d.message.contains("kernel.randomize_va_space"))
        .collect::<Vec<_>>();
    assert_eq!(
        w02.len(),
        1,
        "the STIG W02 still fires (untouched by the CIS lane): {diags:?}"
    );
    assert_eq!(
        w02[0].controls[0].framework,
        Framework::Stig,
        "W02 control is STIG"
    );
    assert_eq!(w02[0].controls[0].id, "RHEL-09-213070");

    let w04 = w04_for(&diags, "kernel.randomize_va_space");
    assert_eq!(w04.len(), 1, "the CIS W04 also fires: {diags:?}");
    assert_eq!(
        w04[0].controls[0].framework,
        Framework::Cis,
        "W04 control is CIS"
    );
    assert_eq!(
        w04[0].controls[0].id, "1.5.1",
        "rhel9 randomize_va_space CIS id"
    );
    assert_eq!(
        w04[0].controls[0].name.as_deref(),
        Some("Ensure address space layout randomization is enabled (Automated)")
    );
}

// ---------------------------------------------------------------------------
// Directory mode anchoring (missing -> dir, insecure -> the drop-in file)
// ---------------------------------------------------------------------------

#[test]
fn w04_dir_mode_anchors_missing_at_dir_and_insecure_at_the_dropin() {
    // Mirrors W02 dir mode: a MISSING CIS key anchors at the directory (line 0, no
    // single source line); a present-but-insecure key anchors at the real drop-in
    // file + line. One drop-in sets net.ipv4.ip_forward insecurely (=1).
    let dir = tempdir().expect("temp dir");
    let dropin = dir.path().join("10-a.conf");
    std::fs::write(&dropin, "net.ipv4.ip_forward = 1\n").expect("write drop-in");

    let (diags, _sources) = lint_dir_with_target(dir.path(), Some(TargetVersion::Rhel9));

    let insecure = w04_for(&diags, "net.ipv4.ip_forward");
    assert_eq!(
        insecure.len(),
        1,
        "the insecure ip_forward fires W04: {diags:?}"
    );
    assert_eq!(
        insecure[0].line, 1,
        "insecure anchors at the drop-in's line"
    );
    assert_eq!(
        insecure[0].file, dropin,
        "insecure anchors at the real drop-in file, not the directory"
    );
    assert_eq!(insecure[0].controls[0].framework, Framework::Cis);

    let missing = w04_for(&diags, "net.ipv4.conf.all.rp_filter");
    assert_eq!(
        missing.len(),
        1,
        "the unset all.rp_filter fires a missing W04: {diags:?}"
    );
    assert_eq!(missing[0].line, 0, "a missing-key W04 anchors at line 0");
    assert_eq!(
        missing[0].file.as_path(),
        dir.path(),
        "a missing-key W04 anchors at the directory (no single source line)"
    );
}
