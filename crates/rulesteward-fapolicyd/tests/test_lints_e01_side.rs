//! RED barrier tests for fapd-E01's attribute-SIDE check (issue #545,
//! [CRITICAL] fail-open).
//!
//! Grounded in the overnight audit lane report (2026-07-17,
//! `research-notes/overnight/2026-07-17/lane1-fapolicyd.md` in the docs tree,
//! Finding F1), which reproduces the first five fixtures below LIVE against
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
//!
//! ## Adversarial review strengthening (2026-07-17)
//!
//! The impl-BLIND adversarial-test review of the original commit
//! (5 fixtures: mode/uid/path/exe/pattern) returned `NEEDS_REWORK`:
//!
//! - **Finding 1 [BLOCKER]:** a wrong impl could hardcode exactly those five
//!   attribute NAMES and still pass all 15 assertions. `gid` and
//!   `sha256hash` were added below - different names, confirmed
//!   version-invariant in side via a FRESH live differential this round
//!   (fapolicyd8 1.3.2 AND fapolicyd9 1.4.5, 2026-07-17): `gid=100` on the
//!   object side -> both versions "Field type (gid) is unknown in line 2" +
//!   "Object is missing"; `sha256hash=<hex>` on the subject side -> both
//!   versions "Field type (sha256hash) is unknown in line 2" + "Subject is
//!   missing".
//! - **Finding 2 [BLOCKER]:** `device` and `filehash` are version-DIVERGENT
//!   (device in SIDE, filehash in EXISTENCE - see
//!   `version_target.rs::check_subject_device` / `check_filehash`). A naive
//!   general E01 side check that did not exclude them would break the 4
//!   frozen `version-target__device-subject-side__*.snap` snapshots (which
//!   pin `diagnostics=0` on none/rhel8 and E06-ONLY, not E01+E06, on
//!   rhel9/rhel10) and mis-flag a construct that is genuinely valid on
//!   rhel8. `device_on_subject_side_never_fires_e01_on_any_target_e06_exclusive`
//!   and its filehash sibling below pin that E01 defers both attributes
//!   entirely to fapd-E06.

use std::path::Path;

use rulesteward_fapolicyd::{LintContext, TargetVersion, lint_with_context, parse_rules_file};

/// (fixture source, attribute name). The first five are grounded verbatim
/// against fapolicyd8/9/10 in the audit lane report Finding F1 evidence
/// section; `gid`/`sha256hash` were added in the adversarial-review
/// strengthening pass (grounded via a fresh live differential, see the
/// module doc and the mirrored `walker.rs` unit tests).
const WRONG_SIDE_FIXTURES: &[(&str, &str)] = &[
    ("allow perm=any mode=0755 : all\n", "mode"),
    ("allow perm=any all : uid=0\n", "uid"),
    ("allow perm=any path=/bin/sh : all\n", "path"),
    ("allow perm=any all : exe=/bin/sh\n", "exe"),
    ("allow perm=any all : pattern=ld_so\n", "pattern"),
    ("allow perm=any all : gid=100\n", "gid"),
    (
        "allow perm=any sha256hash=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef : all\n",
        "sha256hash",
    ),
];

fn targets() -> [Option<TargetVersion>; 3] {
    [None, Some(TargetVersion::Rhel8), Some(TargetVersion::Rhel9)]
}

/// 7 wrong-side fixtures x 3 targets = 21 assertions: every wrong-side
/// attribute must fire fapd-E01, on every `--target` value, matching the real
/// daemon's version-invariant rejection. Deliberately spans more than the
/// original 5 hardcodable names (Finding 1).
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
                 (audit lane report 2026-07-17 Finding F1 / adversarial-review live \
                 differential); got {diags:?}",
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

// ---------------------------------------------------------------------------
// Adversarial review strengthening (2026-07-17), Finding 2 [BLOCKER]:
// device/filehash exclusion pins.
//
// Both tests PASS TODAY (E01 has no side check at all yet) and MUST KEEP
// PASSING after the #545 fix - they pin the exclusion boundary the fix must
// respect, not a RED regression. Both are driven at 4 targets (including
// rhel10, unlike the 3-target sweep above) to match the 4 frozen
// `version-target__device-subject-side__*.snap` snapshots exactly.
// ---------------------------------------------------------------------------

/// `device` is version-DIVERGENT in SIDE: `version_target.rs::
/// check_subject_device` documents (and the audit lane report's live
/// confirmation shows: `allow perm=any device=/dev/sda : all` -> fapolicyd8
/// 1.3.2 "Loaded 1 rules" clean; fapolicyd9 1.4.5 rejects with fapd-E06) that
/// `device=` is valid on EITHER side on rhel8 but object-only from
/// rhel9/1.4.x onward. The frozen snapshots
/// `version-target__device-subject-side__{none,rhel8,rhel9,rhel10}.snap` pin
/// `diagnostics=0` for none/rhel8 and E06-ONLY (not E01+E06) for
/// rhel9/rhel10 - a naive general E01 side check (one that treats
/// `attrs::classify("device") == Object` as version-invariant, matching
/// `attrs.rs`'s baseline table) would break ALL FOUR. Confirming: under the
/// intended fix (E01 excludes `device`), these 4 snapshots need NO change.
#[test]
fn device_on_subject_side_never_fires_e01_on_any_target_e06_exclusive() {
    let file = Path::new("device-subject-side.rules");
    let src = "allow perm=any device=/dev/sda : all\n";
    let entries =
        parse_rules_file(src, file).unwrap_or_else(|d| panic!("must parse cleanly: {d:?}"));
    for target in [
        None,
        Some(TargetVersion::Rhel8),
        Some(TargetVersion::Rhel9),
        Some(TargetVersion::Rhel10),
    ] {
        let ctx = LintContext {
            target,
            ..Default::default()
        };
        let diags = lint_with_context(&entries, src, file, &ctx);
        assert!(
            !diags.iter().any(|d| d.code.as_ref() == "fapd-E01"),
            "device= on the subject side is version-DIVERGENT (valid on rhel8, \
             invalid on rhel9+) and must stay fapd-E06-exclusive, never fapd-E01, \
             under --target {target:?}; got {diags:?}",
        );
    }
}

/// `filehash` is version-DIVERGENT in EXISTENCE (not side):
/// `version_target.rs::check_filehash` documents that `filehash=` does not
/// exist at all on fapolicyd 1.3.2 (rhel8) - confirmed live 2026-07-17:
/// `filehash=<hex>` on EITHER side rejects "Field type (filehash) is
/// unknown" on fapolicyd8. Per the adversarial review's directed exclusion
/// set (mirroring `device`'s ownership boundary), E01 defers filehash's
/// wrong-side placement entirely to `version_target.rs` rather than
/// double-reporting alongside `check_filehash`.
///
/// FLAGGED GAP (out of #545/#546/#567 scope, not fixed by this test): the
/// SAME live differential also showed fapolicyd9 (1.4.5) rejects
/// subject-side filehash too ("Field type (filehash) is unknown" + "Subject
/// is missing"), meaning filehash's SIDE is actually version-INVARIANT once
/// it exists at all (unlike `device`'s SIDE, which truly flips across
/// versions) - only its EXISTENCE is version-divergent (rhel8-only). Under
/// this blanket exclusion, a subject-side filehash on rhel9/rhel10/None is
/// not flagged by ANY check today (`check_filehash` only fires under
/// `--target rhel8`). Recorded transparently rather than silently
/// papered over: closing that gap is a `version_target.rs` / fapd-E06
/// change, out of scope for #545/#546/#567.
#[test]
fn filehash_on_subject_side_never_fires_e01_on_any_target_e06_exclusive() {
    let file = Path::new("filehash-subject-side.rules");
    let src = "allow perm=any filehash=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef : all\n";
    let entries =
        parse_rules_file(src, file).unwrap_or_else(|d| panic!("must parse cleanly: {d:?}"));
    for target in [
        None,
        Some(TargetVersion::Rhel8),
        Some(TargetVersion::Rhel9),
        Some(TargetVersion::Rhel10),
    ] {
        let ctx = LintContext {
            target,
            ..Default::default()
        };
        let diags = lint_with_context(&entries, src, file, &ctx);
        assert!(
            !diags.iter().any(|d| d.code.as_ref() == "fapd-E01"),
            "filehash= on the subject side must stay fapd-E06-exclusive \
             (existence-check ownership), never fapd-E01, under --target \
             {target:?}; got {diags:?}",
        );
    }
}
