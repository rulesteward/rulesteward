//! Crate-level tests for the sysctld CIS baseline TABLE (issue #527). They call
//! the frozen public accessor `rulesteward_sysctld::cis_baseline` and are RED
//! against its `todo!()` scaffold: only the grounded per-product tables turn
//! them green.
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
//! * The EMIT tests (second half of this file) pin the design: a standalone
//!   version-aware CIS baseline pass wired into
//!   `parser::lint_str_with_target` / `lint_dir_with_target` (exactly like the STIG
//!   W02 wiring) that emits the NEW lint code `sysctld-W04` - one finding per
//!   CIS-required key that is unset or set outside the benchmark-accepted set - each
//!   carrying exactly ONE `Framework::Cis` `ControlRef` whose id is the CIS control
//!   id and whose `.with_name(...)` is the `ComplianceAsCode` title. W04 runs ONLY
//!   under a `--target` product; no target => no W04. The STIG `sysctld-W02`
//!   semantics are UNTOUCHED - W02 and W04 coexist as distinct codes/frameworks.
//!   These emit tests drive the public pipeline (not a crate-private fn), so they
//!   pin both the emit logic AND the in-crate wiring. (Scope: single-file +
//!   single-directory modes, mirroring `tests/baseline.rs`.)
//!
//! # `--system` wiring (issue #576)
//! RULING: the cross-directory `--system` scan (`system::lint_system`) reruns
//! `sysctld-F01`/`W01`/`W02` AND the `sysctld-W04` CIS pass over its
//! precedence-merged effective set, mirroring the existing `W02` wiring exactly
//! (same `merged` list, same `effective_values` winner-takes-it lookup, same
//! fixed `prefix.join("etc/sysctl.d")` anchor for a MISSING key). The
//! `--system` mode reflects a real host's ACTUAL configuration, so it must not
//! be the less thorough one.
//! Rationale + evidence: #576. See the "SYSTEM MODE" test section at the end of
//! this file for the tests plus the studied W02 attribution precedent they pin.

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
// EMIT tests (sysctld-W04): the version-aware CIS baseline pass, wired into
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

// ===========================================================================
// SYSTEM MODE (issue #576): `sysctl lint --system`
// must ALSO run the `sysctld-W04` CIS baseline over its precedence-merged
// effective set, mirroring how `system::lint_system` already wires the STIG
// `sysctld-W02` pass.
//
// # The studied W02 attribution precedent (`crates/rulesteward-sysctld/src/system.rs`)
// `lint_system` (around line 526) does:
//     diags.extend(w03a_and_w01(&merged, &ranks));
//     if let Some(t) = target {
//         diags.extend(w02_baseline(&merged, t, &prefix.join("etc/sysctl.d")));
//     }
// `merged` is the precedence-ordered assignment list `lint_system` already
// builds: surviving drop-ins in GLOBAL lexicographic basename order (module doc
// point 2 - same-basename masking is resolved earlier, by `enumerate()`, so a
// masked file's assignments never enter `merged` at all), then
// `/etc/sysctl.conf` appended dead-last. `w02_baseline`/`w04_baseline` both
// call the SHARED `effective_values` helper on that list - a plain
// last-occurrence-wins scan - so "which file wins a given key" is entirely a
// property of `merged`'s ORDER, not of anything W02/W04-specific. Concretely:
// * A MISSING key has no real assignment (masked or otherwise) to anchor to,
//   so it anchors at the FIXED `prefix.join("etc/sysctl.d")` reference path -
//   exactly W02's missing-branch choice. This is not a new design decision for
//   W04; it is a direct reuse of the one W02 already made.
// * A present-but-out-of-set key anchors at the WINNING assignment - the file
//   `effective_values` resolves as the LAST-occurrence winner for that
//   canonical key over `merged` - never "every file that sets it" and never
//   "the last one read from disk".
// Because this rule is fully determined by the existing W02 precedent (and
// the "absence has no file" case the task flagged as a possible design fork
// is ALSO already answered by W02's identical missing-branch anchor), no
// `[QUESTION FOR USER]` is needed here - wiring is `w04_baseline(&merged, t,
// &prefix.join("etc/sysctl.d"))`, verbatim alongside the `w02_baseline` call.
// ===========================================================================

use rulesteward_sysctld::system::lint_system;

/// Write `body` into `<root>/<rel>`, creating parent directories as needed.
/// Mirrors `tests/system.rs`'s identical helper - each integration-test binary
/// compiles as its own separate crate, so there is no shared test-support
/// module to import it from.
fn write_at(root: &Path, rel: &str, body: &str) {
    let path = root.join(rel);
    std::fs::create_dir_all(path.parent().expect("has parent")).expect("mkdir -p");
    std::fs::write(&path, body).expect("write fixture file");
}

/// All `sysctld-W04` diagnostics from a `--system` scan, asserting the tier.
fn system_w04s(diags: &[Diagnostic]) -> Vec<&Diagnostic> {
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

// ---------------------------------------------------------------------------
// 1. Core test: --system emits W04 over the merged effective set, gated
//    positively/negatively by --target (mirrors `w04_runs_only_under_a_target`
//    above, ported to `lint_system`, so a vacuous "no W04" cannot be confused
//    with "the pass never ran"). ALL THREE products are pinned (an impl that
//    hardcodes/defaults to
//    `TargetVersion::Rhel9` internally - discarding the resolved `t` argument
//    `lint_system` passes through - would satisfy a rhel9-only assertion here
//    while silently reporting 25 for rhel8/rhel10, where the grounded answer
//    is 33).
// ---------------------------------------------------------------------------

#[test]
fn system_w04_fires_over_the_merged_effective_set_only_under_a_target() {
    let root = tempdir().expect("temp root");
    write_at(root.path(), "etc/sysctl.conf", "# no keys set\n");

    for (t, n) in [
        (TargetVersion::Rhel8, 33),
        (TargetVersion::Rhel9, 25),
        (TargetVersion::Rhel10, 33),
    ] {
        let (with_target, _sources) = lint_system(Some(root.path()), Some(t));
        assert_eq!(
            system_w04s(&with_target).len(),
            n,
            "a --target {t:?} --system scan must run the CIS baseline over the \
             (empty) merged set and fire one W04 per unset key ({n} for {t:?}): \
             {with_target:?}"
        );
    }

    let (no_target, _sources2) = lint_system(Some(root.path()), None);
    assert!(
        no_target.iter().all(|d| d.code != "sysctld-W04"),
        "with no --target, --system must not run the CIS baseline (no W04): \
         {no_target:?}"
    );
}

// ---------------------------------------------------------------------------
// 2. Precedence correctness (the sharpest pin): a key set noncompliantly in
//    the file that LOSES the merge, compliantly in the file that WINS, must
//    NOT fire - a naive "run W04 over every surviving file individually, then
//    union the results" implementation fires here anyway (it flags the losing
//    file's own noncompliant value in isolation, never consulting the merged
//    effective value at all). The converse (the WINNING file is the
//    noncompliant one) must fire exactly once, anchored at the winner - this
//    direction instead catches a REVERSED winner-selection bug (an impl that
//    picks the first-occurrence file rather than `effective_values`' real
//    last-occurrence winner).
//
//    Fixture: two DIFFERENT basenames (same-basename masking is a SEPARATE
//    mechanism, covered by test 6 below), chosen so the /etc/sysctl.d file's
//    basename sorts LEXICOGRAPHICALLY AFTER the /usr/lib/sysctl.d file's
//    ("10-a.conf" < "50-b.conf" bytewise, matching `system.rs` module doc
//    point 2's GLOBAL basename merge) - so /etc wins, and /etc also happens to
//    be the higher-precedence directory, matching the "low-precedence dir" /
//    "high-precedence dir" framing directly (no W03-a surprise: the
//    higher-precedence directory winning is the UNSURPRISING order).
// ---------------------------------------------------------------------------

#[test]
fn system_w04_precedence_low_dir_noncompliant_high_dir_compliant_does_not_fire() {
    let root = tempdir().expect("temp root");
    write_at(
        root.path(),
        "usr/lib/sysctl.d/10-a.conf",
        "net.ipv4.ip_forward = 1\n",
    );
    write_at(
        root.path(),
        "etc/sysctl.d/50-b.conf",
        "net.ipv4.ip_forward = 0\n",
    );

    let (diags, _sources) = lint_system(Some(root.path()), Some(TargetVersion::Rhel9));

    assert!(
        system_w04s(&diags)
            .iter()
            .all(|d| !d.message.contains("net.ipv4.ip_forward")),
        "the effective (winning) value of net.ipv4.ip_forward is 0 (from \
         etc/sysctl.d/50-b.conf, which sorts after and wins over \
         usr/lib/sysctl.d/10-a.conf in the global basename merge) - compliant, \
         so NO W04 may fire, even though the LOSING usr/lib file's own value \
         (1) is noncompliant in isolation (the naive per-file-union failure \
         mode this test kills); got: {diags:?}"
    );
    // Positive control: an unrelated unset CIS key
    // must still fire, so "no W04 for ip_forward" here is not indistinguishable
    // from "the pass never ran at all".
    assert!(
        system_w04s(&diags)
            .iter()
            .any(|d| d.message.contains("net.ipv4.tcp_syncookies")),
        "positive control: an unrelated unset CIS key must still fire a \
         missing W04: {diags:?}"
    );
}

#[test]
fn system_w04_precedence_low_dir_compliant_high_dir_noncompliant_fires_once_at_the_winner() {
    let root = tempdir().expect("temp root");
    write_at(
        root.path(),
        "usr/lib/sysctl.d/10-a.conf",
        "net.ipv4.ip_forward = 0\n",
    );
    write_at(
        root.path(),
        "etc/sysctl.d/50-b.conf",
        "net.ipv4.ip_forward = 1\n",
    );

    let (diags, _sources) = lint_system(Some(root.path()), Some(TargetVersion::Rhel9));

    let hits: Vec<&Diagnostic> = system_w04s(&diags)
        .into_iter()
        .filter(|d| d.message.contains("net.ipv4.ip_forward"))
        .collect();
    assert_eq!(
        hits.len(),
        1,
        "the effective (winning) value of net.ipv4.ip_forward is 1 (from \
         etc/sysctl.d/50-b.conf, which sorts after and wins the global \
         basename merge) - noncompliant, so exactly ONE W04 must fire (a \
         reversed-winner bug that picked the LOSING usr/lib file's compliant \
         value instead would wrongly suppress it - never zero); got: {diags:?}"
    );
    let hit = hits[0];
    assert_eq!(
        hit.file,
        root.path().join("etc/sysctl.d/50-b.conf"),
        "the finding anchors at the WINNING assignment's real file (the \
         studied W02 precedent), not the losing usr/lib file and not a fixed \
         directory reference: {hit:?}"
    );
    assert_eq!(
        hit.line, 1,
        "the finding anchors at the winning assignment's real line: {hit:?}"
    );
    assert_ne!(
        hit.span,
        0..0,
        "a present-but-out-of-set W04 carries the real assignment's byte span \
         (not the degenerate 0..0 a missing-key finding uses): {hit:?}"
    );
    // The span alone doesn't prove a snippet renders: `Diagnostic::new` leaves
    // `source_id: None` even with the right span; only `anchored`/
    // `with_source_id` set it.
    assert!(
        hit.source_id.is_some(),
        "a present-but-out-of-set W04 sets source_id, the actual ariadne \
         snippet path: {hit:?}"
    );
    // The insecure branch's ControlRef; test 6 below pins the missing branch
    // only.
    assert_eq!(
        hit.controls.len(),
        1,
        "a present-but-out-of-set W04 carries exactly one control: {hit:?}"
    );
    assert_eq!(hit.controls[0].framework, Framework::Cis);
    assert_eq!(
        hit.controls[0].id, "3.3.1",
        "rhel9 net.ipv4.ip_forward CIS id, pinned on the PRESENT-but-noncompliant \
         branch"
    );
    assert_eq!(
        hit.controls[0].name.as_deref(),
        Some("Ensure IP forwarding is disabled (Automated)"),
        "the ComplianceAsCode title, pinned on the present-but-noncompliant branch"
    );
}

// ---------------------------------------------------------------------------
// 3. Attribution: the MISSING-key branch anchors at the FIXED `etc/sysctl.d`
//    reference path (mirrors W02's identical choice exactly; a missing key has
//    no real assignment - masked or otherwise - to anchor to, so this is a
//    direct reuse of the established rule, not a new decision) - no
//    `source_id`, no ariadne snippet, exactly like single-file/dir mode's
//    missing branch (`w04_missing_key_carries_exactly_one_cis_control_with_name`
//    above).
// ---------------------------------------------------------------------------

#[test]
fn system_w04_missing_key_anchors_at_the_fixed_sysctl_d_reference_path() {
    let root = tempdir().expect("temp root");
    write_at(root.path(), "etc/sysctl.conf", "# nothing set\n");

    let (diags, _sources) = lint_system(Some(root.path()), Some(TargetVersion::Rhel9));

    let missing = system_w04s(&diags)
        .into_iter()
        .find(|d| d.message.contains("net.ipv4.ip_forward"))
        .expect("net.ipv4.ip_forward is unset -> a missing W04 must fire");
    assert_eq!(
        missing.file,
        root.path().join("etc/sysctl.d"),
        "a MISSING-key --system W04 anchors at the fixed etc/sysctl.d \
         reference path, mirroring the W02 anchor exactly: {missing:?}"
    );
    assert_eq!(
        missing.line, 0,
        "a MISSING-key W04 anchors at line 0: {missing:?}"
    );
    assert_eq!(
        missing.span,
        0..0,
        "a MISSING-key W04 carries the degenerate 0..0 span: {missing:?}"
    );
    assert!(
        missing.source_id.is_none(),
        "a MISSING-key W04 carries no source_id: {missing:?}"
    );
}

// ---------------------------------------------------------------------------
// 4. No double-reporting: a key set (noncompliantly) in THREE different
//    surviving files fires exactly ONE W04 - anchored at whichever wins the
//    merge - never three. A naive per-file-union implementation fires three.
// ---------------------------------------------------------------------------

#[test]
fn system_w04_key_set_in_three_files_fires_exactly_once() {
    let root = tempdir().expect("temp root");
    write_at(
        root.path(),
        "etc/sysctl.d/10-a.conf",
        "net.ipv4.ip_forward = 1\n",
    );
    write_at(
        root.path(),
        "etc/sysctl.d/20-b.conf",
        "net.ipv4.ip_forward = 1\n",
    );
    write_at(
        root.path(),
        "etc/sysctl.d/90-c.conf",
        "net.ipv4.ip_forward = 1\n",
    );

    let (diags, _sources) = lint_system(Some(root.path()), Some(TargetVersion::Rhel9));

    let hits: Vec<&Diagnostic> = system_w04s(&diags)
        .into_iter()
        .filter(|d| d.message.contains("net.ipv4.ip_forward"))
        .collect();
    assert_eq!(
        hits.len(),
        1,
        "net.ipv4.ip_forward is set (noncompliantly) in THREE surviving files, \
         but the CIS baseline reasons over ONE effective (merged) value per \
         key, so exactly ONE W04 must fire - not three (the naive per-file \
         union failure mode); got: {diags:?}"
    );
    assert_eq!(
        hits[0].file,
        root.path().join("etc/sysctl.d/90-c.conf"),
        "the single finding anchors at the effective winner (the \
         lexicographically-last basename, 90-c.conf): {:?}",
        hits[0]
    );
}

// ---------------------------------------------------------------------------
// 5. W04 is additive in --system mode too (regression guard for the existing
//    --system W02 wiring, requirement 6): a key required by BOTH baselines
//    fires one W02 (Stig) and one W04 (Cis), neither replacing the other.
// ---------------------------------------------------------------------------

#[test]
fn system_w04_and_w02_coexist_with_distinct_frameworks() {
    let root = tempdir().expect("temp root");
    write_at(root.path(), "etc/sysctl.conf", "# nothing set\n");

    let (diags, _sources) = lint_system(Some(root.path()), Some(TargetVersion::Rhel9));

    let w02: Vec<&Diagnostic> = diags
        .iter()
        .filter(|d| d.code == "sysctld-W02" && d.message.contains("kernel.randomize_va_space"))
        .collect();
    assert_eq!(
        w02.len(),
        1,
        "the STIG W02 pass must still fire in --system mode, untouched by the \
         W04 wiring: {diags:?}"
    );
    assert_eq!(w02[0].controls[0].framework, Framework::Stig);

    let w04: Vec<&Diagnostic> = system_w04s(&diags)
        .into_iter()
        .filter(|d| d.message.contains("kernel.randomize_va_space"))
        .collect();
    assert_eq!(
        w04.len(),
        1,
        "the CIS W04 pass must ALSO fire in --system mode, additively: \
         {diags:?}"
    );
    assert_eq!(w04[0].controls[0].framework, Framework::Cis);
}

// ---------------------------------------------------------------------------
// 6. Same-basename SAME-KEY overwrite ordering. SCOPE: this fixture sets the
//    SAME key in both files with the
//    survivor compliant, so ordering ALONE - not masking-awareness - rescues
//    an impl that walks all five directories with NO same-basename masking at
//    all: appending the higher-precedence etc/ assignment LAST after
//    usr/lib's (masked or not) still makes it win via plain
//    last-occurrence-wins, and even anchors a diagnostic AT the masked path
//    without failing this test. This test is a same-key overwrite
//    regression guard; the REAL masking-awareness pin - where a masking-blind
//    impl fires the WRONG finding (present-insecure instead of missing) at the
//    WRONG anchor (the masked file instead of the fixed directory reference) -
//    is test 9 below
//    (`system_w04_masked_dropin_setting_a_different_key_never_leaks_as_a_present_finding`).
// ---------------------------------------------------------------------------

#[test]
fn system_w04_masked_dropin_never_contributes_to_the_effective_value() {
    let root = tempdir().expect("temp root");
    write_at(
        root.path(),
        "etc/sysctl.d/50-x.conf",
        "net.ipv4.ip_forward = 0\n",
    );
    // Same basename in a LOWER-precedence directory: masked entirely, never
    // parsed into the merged set, regardless of its (noncompliant) value.
    write_at(
        root.path(),
        "usr/lib/sysctl.d/50-x.conf",
        "net.ipv4.ip_forward = 1\n",
    );

    let (diags, _sources) = lint_system(Some(root.path()), Some(TargetVersion::Rhel9));

    assert!(
        system_w04s(&diags)
            .iter()
            .all(|d| !d.message.contains("net.ipv4.ip_forward")),
        "the surviving /etc copy sets net.ipv4.ip_forward = 0 (compliant); the \
         same-basename masked /usr/lib copy's noncompliant value (1) must \
         never contribute to the effective value, so NO W04 may fire; \
         got: {diags:?}"
    );
    // Belt-and-suspenders: the masked file must never anchor ANY diagnostic
    // (of any code), matching the invisibility guarantee `tests/system.rs`
    // already pins for F01/W01/W03.
    assert!(
        diags.iter().all(|d| {
            !d.file
                .display()
                .to_string()
                .contains("usr/lib/sysctl.d/50-x.conf")
        }),
        "the masked usr/lib/sysctl.d/50-x.conf must be entirely invisible - \
         never the anchor of any diagnostic; got: {diags:?}"
    );
    // Positive control: an unrelated unset CIS key
    // must still fire, so "no W04 for ip_forward" here is not indistinguishable
    // from "the pass never ran at all".
    assert!(
        system_w04s(&diags)
            .iter()
            .any(|d| d.message.contains("net.ipv4.tcp_syncookies")),
        "positive control: an unrelated unset CIS key must still fire a \
         missing W04: {diags:?}"
    );
}

// ---------------------------------------------------------------------------
// 7. The `/etc/sysctl.conf` tier: tests 1-6 above
//    all either omit `etc/sysctl.conf` or use a comment-only body, so
//    `etc_conf_asgns` is EMPTY and `merged == surviving_asgns` identically in
//    every one of them - none exercise the dead-last tier at all. `system.rs`
//    module doc point 3 / `lint_system` (around line 520-523): `merged` is
//    built as `surviving_asgns` THEN `merged.extend(etc_conf_asgns)` -
//    `/etc/sysctl.conf` is appended DEAD LAST, so it always wins procps's
//    effective value regardless of any drop-in. An impl that places the W04
//    call BEFORE that `.extend()` (mirroring where `w03b_divergence` is
//    computed pre-merge in `lint_system`, an easy copy-paste trap) would build
//    `merged` from drop-ins only and silently miss this - a false negative on
//    the single most common place an operator sets sysctls.
// ---------------------------------------------------------------------------

#[test]
fn system_w04_etc_sysctl_conf_wins_dead_last_over_a_compliant_dropin() {
    let root = tempdir().expect("temp root");
    write_at(
        root.path(),
        "etc/sysctl.d/10-a.conf",
        "net.ipv4.ip_forward = 0\n",
    );
    write_at(root.path(), "etc/sysctl.conf", "net.ipv4.ip_forward = 1\n");

    let (diags, _sources) = lint_system(Some(root.path()), Some(TargetVersion::Rhel9));

    let hits: Vec<&Diagnostic> = system_w04s(&diags)
        .into_iter()
        .filter(|d| d.message.contains("net.ipv4.ip_forward"))
        .collect();
    assert_eq!(
        hits.len(),
        1,
        "/etc/sysctl.conf's dead-last value (1, noncompliant) must win over the \
         compliant drop-in (0), firing exactly one W04 - an impl that computes \
         the effective value BEFORE appending etc_conf_asgns would see only the \
         compliant drop-in and miss this false negative entirely; got: {diags:?}"
    );
    assert_eq!(
        hits[0].file,
        root.path().join("etc/sysctl.conf"),
        "the finding anchors at /etc/sysctl.conf, the real dead-last winner: {:?}",
        hits[0]
    );
    assert_eq!(
        hits[0].line, 1,
        "the finding anchors at /etc/sysctl.conf's real line: {:?}",
        hits[0]
    );
}

#[test]
fn system_w04_etc_sysctl_conf_alone_satisfies_the_baseline() {
    // Converse of the test above: /etc/sysctl.conf ALONE (no drop-ins at all)
    // sets a compliant value. An impl that computes the effective value BEFORE
    // appending `etc_conf_asgns` would see a COMPLETELY EMPTY assignment list
    // here (there are no drop-ins to fall back on either) and wrongly report
    // the key "unset" - a false positive.
    let root = tempdir().expect("temp root");
    write_at(root.path(), "etc/sysctl.conf", "net.ipv4.ip_forward = 0\n");

    let (diags, _sources) = lint_system(Some(root.path()), Some(TargetVersion::Rhel9));

    assert!(
        system_w04s(&diags)
            .iter()
            .all(|d| !d.message.contains("net.ipv4.ip_forward")),
        "net.ipv4.ip_forward = 0 in /etc/sysctl.conf alone is COMPLIANT (no \
         drop-in at all), so no W04 may fire for it - an impl that never \
         appends etc_conf_asgns before computing the effective value would see \
         an empty merged set and wrongly report it 'unset'; got: {diags:?}"
    );
    // Positive control: an unrelated unset CIS key must still fire.
    assert!(
        system_w04s(&diags)
            .iter()
            .any(|d| d.message.contains("net.ipv4.tcp_syncookies")),
        "positive control: an unrelated unset CIS key must still fire a \
         missing W04, proving the pass genuinely ran: {diags:?}"
    );
}

// ---------------------------------------------------------------------------
// 8. Masking with a DIFFERENT key per file: the masked file sets a
//    key the surviving same-basename file does NOT set at all, so the key's
//    canonical identity is entirely ABSENT from the merged set - not merely
//    outvoted. A masking-BLIND impl (walks the five search directories without
//    applying same-basename masking at all) would see the masked file's
//    assignment as real and fire the WRONG finding (present-but-noncompliant)
//    at the WRONG anchor (the masked file) instead of the correct
//    missing-key finding at the fixed directory reference.
// ---------------------------------------------------------------------------

#[test]
fn system_w04_masked_dropin_setting_a_different_key_never_leaks_as_a_present_finding() {
    let root = tempdir().expect("temp root");
    // Surviving file: sets a DIFFERENT key (kernel.dmesg_restrict), not
    // net.ipv4.ip_forward at all.
    write_at(
        root.path(),
        "etc/sysctl.d/50-x.conf",
        "kernel.dmesg_restrict = 1\n",
    );
    // Masked (same basename, lower-precedence dir): sets net.ipv4.ip_forward,
    // which NO surviving file touches anywhere.
    write_at(
        root.path(),
        "usr/lib/sysctl.d/50-x.conf",
        "net.ipv4.ip_forward = 1\n",
    );

    let (diags, _sources) = lint_system(Some(root.path()), Some(TargetVersion::Rhel9));

    let hits: Vec<&Diagnostic> = system_w04s(&diags)
        .into_iter()
        .filter(|d| d.message.contains("net.ipv4.ip_forward"))
        .collect();
    assert_eq!(
        hits.len(),
        1,
        "net.ipv4.ip_forward's canonical identity is ABSENT from the merged \
         set (the only file that sets it is masked), so exactly one MISSING \
         W04 must fire - not a present-but-noncompliant one; got: {diags:?}"
    );
    assert!(
        hits[0].message.contains("is unset"),
        "a masking-blind impl would see the masked file's value 1 and report \
         it 'outside the benchmark-accepted set' instead of 'unset' - the \
         message must say the key is unset: {:?}",
        hits[0]
    );
    assert!(
        !hits[0]
            .message
            .contains("outside the benchmark-accepted set"),
        "must NOT be a present-but-noncompliant finding: {:?}",
        hits[0]
    );
    assert_eq!(
        hits[0].file,
        root.path().join("etc/sysctl.d"),
        "a MISSING-key finding anchors at the fixed directory reference, NEVER \
         at the masked file (a masking-blind impl anchors here instead): {:?}",
        hits[0]
    );
    assert_eq!(
        hits[0].line, 0,
        "a MISSING-key W04 anchors at line 0: {:?}",
        hits[0]
    );
}

// ---------------------------------------------------------------------------
// 9. Directory precedence vs. basename order DISAGREE: tests 2/3 above chose
//    fixtures where the higher-precedence
//    directory ALSO wins the global basename merge, so nothing in them can
//    tell "highest-precedence directory always wins" (the naive sysctl.d(5)
//    misreading) apart from "the real global lexicographic merge"
//    (`system.rs` module doc point 2). This fixture is the repo's own
//    canonical W03-a shape (mirrors
//    `w03a_fires_when_a_lower_precedence_directory_wins_on_a_later_basename`
//    in `tests/system.rs`), reused with a CIS-relevant key so the two rules
//    are forced to disagree: the LOWEST-precedence directory wins because its
//    basename sorts later.
// ---------------------------------------------------------------------------

#[test]
fn system_w04_lower_precedence_directory_wins_on_a_later_basename_the_w03a_shape() {
    let root = tempdir().expect("temp root");
    write_at(
        root.path(),
        "etc/sysctl.d/10-early.conf",
        "net.ipv4.ip_forward = 0\n",
    );
    write_at(
        root.path(),
        "usr/lib/sysctl.d/90-late.conf",
        "net.ipv4.ip_forward = 1\n",
    );

    let (diags, _sources) = lint_system(Some(root.path()), Some(TargetVersion::Rhel9));

    // Confirm this really is the canonical W03-a shape (not an accident of
    // this fixture's own construction) - a direct regression check that W03
    // still fires here too (requirement 6).
    assert!(
        diags.iter().any(|d| {
            d.code == "sysctld-W03" && d.message.contains("cross-directory precedence surprise")
        }),
        "this fixture must ALSO be the canonical W03-a shape (a \
         lower-precedence directory winning on a later basename): {diags:?}"
    );

    let hits: Vec<&Diagnostic> = system_w04s(&diags)
        .into_iter()
        .filter(|d| d.message.contains("net.ipv4.ip_forward"))
        .collect();
    assert_eq!(
        hits.len(),
        1,
        "the GLOBAL basename merge makes usr/lib/sysctl.d/90-late.conf \
         (rank 3, LOWEST-precedence directory) the real winner over \
         etc/sysctl.d/10-early.conf (rank 0, highest) because its basename \
         sorts later - a 'highest-precedence directory always wins' impl \
         would instead pick the compliant etc/ value and miss this entirely; \
         got: {diags:?}"
    );
    assert_eq!(
        hits[0].file,
        root.path().join("usr/lib/sysctl.d/90-late.conf"),
        "the finding anchors at the REAL winner (the lower-precedence \
         directory's file, per the global basename merge), not the \
         higher-precedence etc/ file: {:?}",
        hits[0]
    );
}

// ---------------------------------------------------------------------------
// 10. The resolved --target product's accepted set is actually used, not a
//     hardcoded default (the value-divergence half):
//     mirrors the single-file `w04_set_valued_acceptance_diverges_rhel8_rhel9`
//     emit test above, ported to `--system`. `net.ipv4.conf.all.rp_filter`
//     accepts the SET {1,2} on rhel8/rhel10 but ONLY {1} on rhel9. An impl
//     that hardcodes/defaults to `TargetVersion::Rhel9` internally would
//     wrongly flag a COMPLIANT rhel8 host (rp_filter = 2) as noncompliant.
// ---------------------------------------------------------------------------

#[test]
fn system_w04_uses_the_resolved_target_product_not_a_hardcoded_default() {
    let root = tempdir().expect("temp root");
    write_at(
        root.path(),
        "etc/sysctl.d/10-a.conf",
        "net.ipv4.conf.all.rp_filter = 2\n",
    );

    let (rhel8, _sources) = lint_system(Some(root.path()), Some(TargetVersion::Rhel8));
    assert!(
        system_w04s(&rhel8)
            .iter()
            .all(|d| !d.message.contains("net.ipv4.conf.all.rp_filter")),
        "rhel8 accepts net.ipv4.conf.all.rp_filter = 2 (the set {{1,2}}); a \
         hardcoded-rhel9 impl would wrongly flag it: {rhel8:?}"
    );

    let (rhel9, _sources2) = lint_system(Some(root.path()), Some(TargetVersion::Rhel9));
    assert_eq!(
        system_w04s(&rhel9)
            .into_iter()
            .filter(|d| d.message.contains("net.ipv4.conf.all.rp_filter"))
            .count(),
        1,
        "rhel9 accepts ONLY net.ipv4.conf.all.rp_filter = 1, so = 2 must fire \
         exactly one W04: {rhel9:?}"
    );
}

// ---------------------------------------------------------------------------
// 11. Full regression scope (test 5's coexistence check alone only shows W02
//     "still appears" for one key). One fixture
//     produces all four --system-only/base codes at once (F01, a plain W01, a
//     W03-a, and a W03-b), built from keys in NEITHER the rhel9 STIG nor CIS
//     tables so the target-gated W02/W04 passes can only ADD their own
//     diagnostics, never change these four. Rendered with target=None and
//     target=Some(Rhel9); `Diagnostic` derives `PartialEq`/`Eq`, so the
//     non-W02/non-W04 diagnostic sequence is asserted BYTE-IDENTICAL - the
//     strong version of "existing --system F01/W01/W02/W03 output is
//     unperturbed".
// ---------------------------------------------------------------------------

#[test]
fn system_non_cis_non_stig_diagnostics_are_unperturbed_by_the_target_gate() {
    let root = tempdir().expect("temp root");
    // F01: a malformed line (no `=`, not a comment, not a bare `-key`).
    write_at(root.path(), "etc/sysctl.d/05-bad.conf", "kernel.foo\n");
    // Plain W01: SAME rank (both /etc/sysctl.d), different basenames, so
    // `win_rank > dead_rank` is never true - no W03-a suppression.
    write_at(root.path(), "etc/sysctl.d/10-p.conf", "kernel.sysrq = 1\n");
    write_at(root.path(), "etc/sysctl.d/20-p.conf", "kernel.sysrq = 2\n");
    // W03-a: a lower-precedence directory wins on a later basename.
    write_at(
        root.path(),
        "etc/sysctl.d/10-early.conf",
        "net.core.somaxconn = 100\n",
    );
    write_at(
        root.path(),
        "usr/lib/sysctl.d/90-late.conf",
        "net.core.somaxconn = 200\n",
    );
    // W03-b: no 99-sysctl.conf symlink, so systemd never applies this key.
    write_at(
        root.path(),
        "etc/sysctl.conf",
        "net.ipv4.tcp_window_scaling = 1\n",
    );

    let non_w02_w04 = |diags: Vec<Diagnostic>| -> Vec<Diagnostic> {
        diags
            .into_iter()
            .filter(|d| d.code != "sysctld-W02" && d.code != "sysctld-W04")
            .collect()
    };
    let base = non_w02_w04(lint_system(Some(root.path()), None).0);
    let targeted = non_w02_w04(lint_system(Some(root.path()), Some(TargetVersion::Rhel9)).0);

    // Non-vacuous: all three base codes actually fired, including BOTH a W03-a
    // and a W03-b (at least 2 total sysctld-W03 findings).
    for code in ["sysctld-F01", "sysctld-W01", "sysctld-W03"] {
        assert!(
            base.iter().any(|d| d.code == code),
            "fixture must produce a {code} diagnostic (target=None): {base:?}"
        );
    }
    assert!(
        base.iter().filter(|d| d.code == "sysctld-W03").count() >= 2,
        "fixture must produce BOTH a W03-a and a W03-b: {base:?}"
    );

    assert_eq!(
        base, targeted,
        "adding the target-gated W02/W04 passes must not perturb the \
         F01/W01/W03 diagnostic sequence AT ALL - same codes, messages, \
         anchors, and order, with target=None vs target=Some(Rhel9)"
    );
}
