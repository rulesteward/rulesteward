//! RED barrier tests for fapd-E01's attribute-SIDE check (issue #545,
//! [CRITICAL] fail-open).
//!
//! Grounded in the overnight audit lane report (2026-07-17,
//! `research-notes/overnight/2026-07-17/lane1-fapolicyd.md` in the docs tree,
//! Finding F1), which reproduces all five fixtures below LIVE against
//! fapolicyd 1.3.2 (rhel8 container) and 1.4.5 (rhel9/rhel10 containers): the
//! real daemon rejects every wrong-side attribute with "Field type (X) is
//! unknown in line N" plus a follow-up "Subject is missing" / "Object is
//! missing", and the daemon PROCESS EXITS(1) - fapolicyd never starts, so the
//! host loses all execution-control enforcement until an operator manually
//! diagnoses the crash from raw daemon logs with no `RuleSteward` diagnostic
//! to point at it.
//!
//! Today `fapd-E01` (`lints::walker::e01`) only calls `attrs::is_known(key)`,
//! which is side-blind (true for a name in ANY of `SUBJECT_ONLY` / `OBJECT_ONLY` /
//! `BOTH_SIDES` regardless of which side it was found on). `attrs::classify`
//! (which DOES return a side) is never consulted from `e01`.
//!
//! Driven through the PUBLIC `lint_with_context` seam (not the private
//! `walker::e01`) so these tests hold regardless of exactly where the side
//! check lands in the pass list, and swept across all three `--target`
//! values to pin that the fix is target-INVARIANT: `attrs::AttrSide` has no
//! per-version variant at all (unlike `attrs::AttrTypeCategory`, which fapd-E07
//! genuinely versions), so a naive implementation that copies fapd-E06's
//! `let Some(target) = target else { return Vec::new() }` gating pattern
//! would wrongly suppress this check under `--target None` - exactly the
//! default (no-flag) invocation an operator is most likely to run.

use std::path::Path;

use rulesteward_fapolicyd::{LintContext, TargetVersion, lint_with_context, parse_rules_file};

/// (fixture source, attribute name) - all five grounded verbatim against
/// fapolicyd8/9/10 in the audit lane report Finding F1 evidence section.
const WRONG_SIDE_FIXTURES: &[(&str, &str)] = &[
    ("allow perm=any mode=0755 : all\n", "mode"),
    ("allow perm=any all : uid=0\n", "uid"),
    ("allow perm=any path=/bin/sh : all\n", "path"),
    ("allow perm=any all : exe=/bin/sh\n", "exe"),
    ("allow perm=any all : pattern=ld_so\n", "pattern"),
];

fn targets() -> [Option<TargetVersion>; 3] {
    [None, Some(TargetVersion::Rhel8), Some(TargetVersion::Rhel9)]
}

/// 5 wrong-side fixtures x 3 targets = 15 assertions: every wrong-side
/// attribute must fire fapd-E01, on every `--target` value, matching the real
/// daemon's version-invariant rejection.
#[test]
fn wrong_side_attribute_fires_e01_on_every_target() {
    let file = Path::new("wrong-side.rules");
    for (src, attr_name) in WRONG_SIDE_FIXTURES {
        let entries = parse_rules_file(src, file)
            .unwrap_or_else(|d| panic!("fixture `{src}` must parse cleanly: {d:?}"));
        for target in targets() {
            let ctx = LintContext {
                target,
                ..Default::default()
            };
            let diags = lint_with_context(&entries, src, file, &ctx);
            assert!(
                diags.iter().any(|d| d.code.as_ref() == "fapd-E01"),
                "attribute `{attr_name}` on its wrong side (fixture `{src}`) must fire \
                 fapd-E01 under --target {target:?}, matching the real daemon's rejection \
                 (audit lane report 2026-07-17 Finding F1: fapolicyd 1.3.2/1.4.5 both reject \
                 and exit(1)); got {diags:?}",
            );
        }
    }
}

/// Negative control: a rule with every attribute on its CORRECT side must NOT
/// fire fapd-E01, on any target - proves the side check is precise, not a
/// blanket false-positive on every known attribute.
#[test]
fn correct_side_attributes_do_not_fire_e01_on_any_target() {
    let file = Path::new("correct-side.rules");
    let src = "allow uid=0 comm=bash : path=/usr/bin/sh trust=1\n";
    let entries =
        parse_rules_file(src, file).unwrap_or_else(|d| panic!("must parse cleanly: {d:?}"));
    for target in targets() {
        let ctx = LintContext {
            target,
            ..Default::default()
        };
        let diags = lint_with_context(&entries, src, file, &ctx);
        assert!(
            !diags.iter().any(|d| d.code.as_ref() == "fapd-E01"),
            "correct-side attributes must never fire fapd-E01 under --target {target:?}; \
             got {diags:?}",
        );
    }
}
