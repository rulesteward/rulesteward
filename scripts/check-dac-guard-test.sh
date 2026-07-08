#!/usr/bin/env bash
# RED test suite for scripts/check-dac-guard.sh (#467).
#
# FROZEN INVOCATION CONTRACT for the gate script (the implementer inherits this):
#
#   scripts/check-dac-guard.sh [DIR...]
#
#   - With no DIR arguments: scans the "crates" directory relative to the
#     caller's current working directory (the gate is always invoked from the
#     repo root, by `just` and by CI, so this resolves to the real crates/
#     tree in normal use).
#   - With one or more DIR arguments: scans each given DIR instead of the
#     default, using the same rule below.
#   - Scan rule: recursively find every *.rs file that lives under a `src`
#     or `tests` path component somewhere below DIR (mirrors the real
#     workspace layout: crates/<name>/src/**/*.rs and
#     crates/<name>/tests/**/*.rs). Files outside src/ or tests/ (e.g. a
#     crate-root build.rs) are not scanned.
#   - For every scanned file, grep for the literal substrings
#     `from_mode(0o000` and `from_mode(0o555` (restrictive/deny chmod
#     modes). Non-deny modes such as 0o644 or 0o755 are never matched and
#     never require a guard.
#   - Each hit is a VIOLATION unless EITHER:
#       (a) a `CAP_DAC_OVERRIDE` marker (comment or string literal, any
#           case-sensitive occurrence of that exact token) appears
#           somewhere within the SAME enclosing `fn ... { ... }` body as the
#           from_mode(...) call - not merely within N lines of it, and not
#           in a different function even if that function is textually
#           adjacent; or
#       (b) a `dac-override-exempt: <reason>` line comment appears near the
#           from_mode(...) call.
#   - Exit 1 if ANY unguarded/unexempted violation is found. The message
#     (stdout or stderr) must point at the guard convention, i.e. contain
#     the literal token `CAP_DAC_OVERRIDE` so an operator knows what to add.
#   - Exit 0 if the scanned tree is clean (no violations, including the
#     trivial case where no from_mode(0o000/0o555) calls exist at all).
#
# Reference implementation of the guard convention this gate enforces:
#   crates/rulesteward-sysctld/tests/system.rs:753-777 (and the 7 guards
#   added in #465 across crates/rulesteward-cli/{src,tests}/...).
#
# This test script is self-contained: it builds synthetic .rs fixtures in a
# mktemp dir per case, invokes the (not-yet-implemented) gate against them,
# and asserts the exit code (and, for violation cases, that the message
# names the convention). Run with no arguments; safe to run locally or in CI.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
GATE="${REPO_ROOT}/scripts/check-dac-guard.sh"

TMPROOT="$(mktemp -d)"
trap 'rm -rf "${TMPROOT}"' EXIT

pass=0
fail=0
failures=()

note_fail() {
    fail=$((fail + 1))
    failures+=("$1")
    echo "FAIL: $1"
}

note_pass() {
    pass=$((pass + 1))
    echo "PASS: $1"
}

# run_case NAME DIR EXPECT_RC
# Invokes the gate against DIR, captures combined stdout+stderr to
# TMPROOT/NAME.out, and asserts the exit code equals EXPECT_RC. Returns 0
# always (failures are recorded, not raised) so the harness can run every
# case even if earlier ones fail.
run_case() {
    local name="$1" dir="$2" expect_rc="$3"
    local out="${TMPROOT}/${name}.out"
    local rc=0
    "${GATE}" "${dir}" >"${out}" 2>&1 || rc=$?
    if [[ "${rc}" -eq "${expect_rc}" ]]; then
        note_pass "${name} (exit ${rc})"
    else
        note_fail "${name}: expected exit ${expect_rc}, got ${rc}"
        sed 's/^/    | /' "${out}" || true
    fi
}

# assert_mentions_convention NAME
# For a case that is expected to be a violation, require the captured
# output to contain the literal CAP_DAC_OVERRIDE token so the failure
# message actually points the operator at the fix.
assert_mentions_convention() {
    local name="$1"
    local out="${TMPROOT}/${name}.out"
    if grep -q "CAP_DAC_OVERRIDE" "${out}" 2>/dev/null; then
        note_pass "${name}: message names the CAP_DAC_OVERRIDE convention"
    else
        note_fail "${name}: message does not mention CAP_DAC_OVERRIDE (got: $(cat "${out}" 2>/dev/null || echo '<no output>'))"
    fi
}

write_fixture() {
    local rel="$1"
    local path="${TMPROOT}/${rel}"
    mkdir -p "$(dirname "${path}")"
    cat >"${path}"
}

# ---------------------------------------------------------------------------
# Case 1: unguarded from_mode(0o000) (read-deny) inside a src/ file, in a
# test fn with no CAP_DAC_OVERRIDE marker anywhere -> exit 1.
# ---------------------------------------------------------------------------
write_fixture "case1/crates/fakecrate1/src/probes.rs" <<'EOF'
#[cfg(test)]
mod tests {
    #[test]
    fn case1_unguarded_read_deny() {
        use std::os::unix::fs::PermissionsExt;
        let f = std::path::Path::new("/tmp/case1-fixture");
        std::fs::set_permissions(f, std::fs::Permissions::from_mode(0o000)).unwrap();
        assert!(true);
    }
}
EOF

# ---------------------------------------------------------------------------
# Case 2: unguarded from_mode(0o555) (write-deny on a dir) inside a tests/
# file, no marker anywhere -> exit 1.
# ---------------------------------------------------------------------------
write_fixture "case2/crates/fakecrate2/tests/it.rs" <<'EOF'
#[test]
fn case2_unguarded_write_deny() {
    use std::os::unix::fs::PermissionsExt;
    let d = std::path::Path::new("/tmp/case2-fixture-dir");
    std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o555)).unwrap();
    assert!(true);
}
EOF

# ---------------------------------------------------------------------------
# Case 3: from_mode(0o000) guarded by a CAP_DAC_OVERRIDE comment inside the
# SAME fn -> exit 0.
# ---------------------------------------------------------------------------
write_fixture "case3/crates/fakecrate3/tests/it.rs" <<'EOF'
#[test]
fn case3_guarded_same_fn() {
    use std::os::unix::fs::PermissionsExt;
    let f = std::path::Path::new("/tmp/case3-fixture");
    std::fs::set_permissions(f, std::fs::Permissions::from_mode(0o000)).unwrap();

    // Root bypasses DAC (CAP_DAC_OVERRIDE): probe and skip rather than
    // false-fail when the deny cannot be exercised in this environment.
    if std::fs::File::open(f).is_ok() {
        let _ = std::fs::set_permissions(f, std::fs::Permissions::from_mode(0o644));
        return;
    }

    assert!(true);
}
EOF

# ---------------------------------------------------------------------------
# Case 4: from_mode(0o000) covered by a dac-override-exempt escape-hatch
# comment -> exit 0.
# ---------------------------------------------------------------------------
write_fixture "case4/crates/fakecrate4/src/probes.rs" <<'EOF'
#[cfg(test)]
mod tests {
    #[test]
    fn case4_exempt() {
        use std::os::unix::fs::PermissionsExt;
        let f = std::path::Path::new("/tmp/case4-fixture");
        // dac-override-exempt: illustrative chmod only, no assertion in this
        // fixture depends on the denial actually being enforced.
        std::fs::set_permissions(f, std::fs::Permissions::from_mode(0o000)).unwrap();
        assert!(true);
    }
}
EOF

# ---------------------------------------------------------------------------
# Case 5: only benign modes (0o644 / 0o755) present, no restrictive
# from_mode call at all -> exit 0.
# ---------------------------------------------------------------------------
write_fixture "case5/crates/fakecrate5/tests/it.rs" <<'EOF'
#[test]
fn case5_benign_modes_only() {
    use std::os::unix::fs::PermissionsExt;
    let f = std::path::Path::new("/tmp/case5-fixture");
    std::fs::set_permissions(f, std::fs::Permissions::from_mode(0o644)).unwrap();
    let d = std::path::Path::new("/tmp/case5-fixture-dir");
    std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(true);
}
EOF

# ---------------------------------------------------------------------------
# Case 6: a CAP_DAC_OVERRIDE marker exists, but in a DIFFERENT (textually
# adjacent, few lines away) fn than the unguarded from_mode(0o000) call.
# Per-function scoping is the point: a naive "N nearby lines" window would
# wrongly treat this as guarded; correct per-function scoping must not
# credit a marker from a sibling function -> exit 1.
# ---------------------------------------------------------------------------
write_fixture "case6/crates/fakecrate6/tests/it.rs" <<'EOF'
#[test]
fn case6_unguarded_neighbor_has_marker() {
    use std::os::unix::fs::PermissionsExt;
    let f = std::path::Path::new("/tmp/case6-fixture");
    std::fs::set_permissions(f, std::fs::Permissions::from_mode(0o000)).unwrap();
    assert!(true);
}

#[test]
fn case6_neighbor_fn_with_marker() {
    // CAP_DAC_OVERRIDE noted here, but this is a DIFFERENT function than
    // the from_mode(0o000) call above; per-function scoping must not
    // credit this as a guard for it.
    assert!(true);
}
EOF

# ---------------------------------------------------------------------------
# Case 8: a raw string literal (r#"..."#) with an ODD number of interior
# double-quote characters appears earlier in the file, ahead of an
# unrelated, genuinely unguarded from_mode(0o555) violation in a LATER fn
# (same shadowing shape as case6: a CAP_DAC_OVERRIDE marker exists only in
# a textually adjacent SIBLING fn, never in the deny fn's own body). Raw
# strings are not ordinary double-quoted strings; a scanner that is only
# aware of ordinary double-quoted strings must not let this raw string
# desync its fn-boundary tracking for the rest of the file in a way that
# causes it to miss the later violation -> exit 1, message must still name
# CAP_DAC_OVERRIDE.
# ---------------------------------------------------------------------------
write_fixture "case8/crates/fakecrate8/tests/it.rs" <<'EOF'
fn holds_raw_string() {
    let s = r#"he said "hi to the world"#;
    let _ = s;
}

fn sibling_with_marker() {
    // CAP_DAC_OVERRIDE
    let _ = 1;
}

fn unguarded_deny() {
    std::fs::set_permissions(".", std::fs::Permissions::from_mode(0o555)).unwrap();
}
EOF

# ---------------------------------------------------------------------------
# Case 9: the same raw-string shape as case8 (an earlier r#"..."# with an
# odd interior double-quote count), this time ahead of a CORRECTLY guarded
# deny site using the real repo idiom: from_mode(0o000) followed several
# lines later, in the SAME fn, by an eprintln! naming CAP_DAC_OVERRIDE
# (mirrors crates/rulesteward-sysctld/tests/system.rs:753-777, where the
# marker sits ~13 lines after the from_mode call in the same fn). The
# earlier raw string must not cause this already-guarded site to be
# false-flagged -> exit 0 (guarded, no violation).
# ---------------------------------------------------------------------------
write_fixture "case9/crates/fakecrate9/tests/it.rs" <<'EOF'
fn holds_raw_string() {
    let s = r#"pattern: "x { y"#;
    let _ = s;
}

#[test]
fn case9_guarded_real_idiom() {
    use std::os::unix::fs::PermissionsExt;
    let f = std::path::Path::new("/tmp/case9-fixture");
    std::fs::set_permissions(f, std::fs::Permissions::from_mode(0o000)).unwrap();

    if std::fs::File::open(f).is_ok() {
        let _ = std::fs::set_permissions(f, std::fs::Permissions::from_mode(0o644));
        eprintln!(
            "SKIP case9_guarded_real_idiom: mode 0o000 is readable here \
             (running as root / with CAP_DAC_OVERRIDE); cannot exercise the deny path"
        );
        return;
    }

    assert!(true);
}
EOF

# ---------------------------------------------------------------------------
# Case 10: round-2 adversarial finding 1 (fail-open). Clones case6's shape
# (an unguarded deny fn followed by a textually adjacent sibling fn that
# carries a CAP_DAC_OVERRIDE marker), but this time the marker sits in the
# GAP between the deny fn's closing brace and the sibling fn's OWN header -
# i.e. in the sibling's lead-in (a doc comment, an attribute, or a
# freestanding // comment), not inside either fn's body. The fn-header-
# anchored region for the deny fn's hit is
# [nearest-preceding-fn-header, next-fn-header - 1]; a lead-in line sitting
# just above the sibling's header line is (next-fn-header - 1) or earlier,
# so an untrimmed region wrongly credits it to the deny fn -> exit 0
# (fail-open bug). The frozen contract requires the marker within the SAME
# fn body (check-dac-guard-test.sh's own contract comment above, and
# CONTRIBUTING.md's "DAC guard" section); a sibling's lead-in is not that,
# so the correct behavior is exit 1. Exercises all three lead-in shapes
# (doc comment, attribute, freestanding comment) as separate fixture files
# in the same case so a fix that only trims one comment style is still
# caught.
# ---------------------------------------------------------------------------
write_fixture "case10/crates/fakecrate10_doc_comment_gap/tests/it.rs" <<'EOF'
#[test]
fn case10_doc_comment_gap_unguarded() {
    use std::os::unix::fs::PermissionsExt;
    let f = std::path::Path::new("/tmp/case10-doc-fixture");
    std::fs::set_permissions(f, std::fs::Permissions::from_mode(0o000)).unwrap();
    assert!(true);
}

/// CAP_DAC_OVERRIDE noted here in a doc comment sitting in the GAP between
/// this fn's own header and the deny fn's closing brace above - this is the
/// sibling's lead-in, not the deny fn's body, and must not be credited.
#[test]
fn case10_doc_comment_gap_sibling() {
    assert!(true);
}
EOF

write_fixture "case10/crates/fakecrate10_attribute_gap/tests/it.rs" <<'EOF'
#[test]
fn case10_attribute_gap_unguarded() {
    use std::os::unix::fs::PermissionsExt;
    let f = std::path::Path::new("/tmp/case10-attr-fixture");
    std::fs::set_permissions(f, std::fs::Permissions::from_mode(0o000)).unwrap();
    assert!(true);
}

#[doc = "CAP_DAC_OVERRIDE noted in an attribute in the sibling's lead-in gap"]
#[test]
fn case10_attribute_gap_sibling() {
    assert!(true);
}
EOF

write_fixture "case10/crates/fakecrate10_freestanding_comment_gap/tests/it.rs" <<'EOF'
#[test]
fn case10_freestanding_comment_gap_unguarded() {
    use std::os::unix::fs::PermissionsExt;
    let f = std::path::Path::new("/tmp/case10-free-fixture");
    std::fs::set_permissions(f, std::fs::Permissions::from_mode(0o000)).unwrap();
    assert!(true);
}

// CAP_DAC_OVERRIDE noted here as a freestanding comment in the sibling's
// lead-in gap, not inside either fn's body.
#[test]
fn case10_freestanding_comment_gap_sibling() {
    assert!(true);
}
EOF

# ---------------------------------------------------------------------------
# Case 11: round-2 adversarial finding 2 (nested-fn fail-closed - PINNED).
# An outer test fn makes the deny call, then declares a nested `fn helper()
# {}` item, then (still lexically inside the outer fn's braces, after the
# nested item) has a comment naming CAP_DAC_OVERRIDE. The fn-header-anchored
# scanner treats the nested fn's header as its own region boundary, so the
# outer fn's body is split into two regions at that point; the marker (in
# the second sub-region) is never credited to the from_mode hit (in the
# first sub-region) -> exit 1.
#
# RULING (orchestrator, round 3): this fail-closed behavior is PINNED as the
# contract, not a bug to fix. It can force a spurious/over-strict guard
# requirement in the rare case of a nested fn item, but it can never hide a
# real violation (narrowing the search region only removes credit, never
# grants it) - the opposite failure mode from case10's fail-open gap, which
# is why case10 must be fixed and this must not be "fixed" into matching
# case10's leniency. The remedy for a real guard in this shape is to place
# the CAP_DAC_OVERRIDE marker BEFORE the nested item (in the same
# sub-region as the from_mode call), or to use the dac-override-exempt:
# hatch instead.
# ---------------------------------------------------------------------------
write_fixture "case11/crates/fakecrate11/tests/it.rs" <<'EOF'
#[test]
fn case11_nested_fn_splits_region() {
    use std::os::unix::fs::PermissionsExt;
    let f = std::path::Path::new("/tmp/case11-fixture");
    std::fs::set_permissions(f, std::fs::Permissions::from_mode(0o000)).unwrap();

    fn helper() {}

    // probe still succeeds (running as root / CAP_DAC_OVERRIDE)
    assert!(true);
}
EOF

run_case "case1_unguarded_read_deny" "${TMPROOT}/case1/crates" 1
assert_mentions_convention "case1_unguarded_read_deny"

run_case "case2_unguarded_write_deny" "${TMPROOT}/case2/crates" 1
assert_mentions_convention "case2_unguarded_write_deny"

run_case "case3_guarded_same_fn" "${TMPROOT}/case3/crates" 0

run_case "case4_exempt" "${TMPROOT}/case4/crates" 0

run_case "case5_benign_modes_only" "${TMPROOT}/case5/crates" 0

run_case "case6_unguarded_neighbor_has_marker" "${TMPROOT}/case6/crates" 1
assert_mentions_convention "case6_unguarded_neighbor_has_marker"

run_case "case8_raw_string_desync_still_catches_violation" "${TMPROOT}/case8/crates" 1
assert_mentions_convention "case8_raw_string_desync_still_catches_violation"

run_case "case9_raw_string_desync_no_false_positive" "${TMPROOT}/case9/crates" 0

run_case "case10_gap_marker_excluded" "${TMPROOT}/case10/crates" 1
assert_mentions_convention "case10_gap_marker_excluded"
case10_out="${TMPROOT}/case10_gap_marker_excluded.out"
for variant in doc_comment_gap attribute_gap freestanding_comment_gap; do
    if grep -q "${variant}" "${case10_out}" 2>/dev/null; then
        note_pass "case10_gap_marker_excluded: ${variant} variant flagged as violation"
    else
        note_fail "case10_gap_marker_excluded: ${variant} variant NOT flagged (gap marker wrongly credited to the deny fn)"
    fi
done

run_case "case11_nested_fn_splits_region" "${TMPROOT}/case11/crates" 1
assert_mentions_convention "case11_nested_fn_splits_region"

# ---------------------------------------------------------------------------
# Case 7: the real repo tree, invoked with NO arguments (default "crates/"),
# from the repo root -> exit 0. As of 2026-07-08 there are exactly 8
# restrictive from_mode sites across 5 files, all guarded via the
# CAP_DAC_OVERRIDE convention; the gate must not false-positive on any of
# them.
# ---------------------------------------------------------------------------
case7_out="${TMPROOT}/case7_real_tree.out"
case7_rc=0
(cd "${REPO_ROOT}" && "${GATE}") >"${case7_out}" 2>&1 || case7_rc=$?
if [[ "${case7_rc}" -eq 0 ]]; then
    note_pass "case7_real_tree (exit 0)"
else
    note_fail "case7_real_tree: expected exit 0, got ${case7_rc}"
    sed 's/^/    | /' "${case7_out}" || true
fi

echo ""
echo "----------------------------------------"
echo "${pass} passed, ${fail} failed"
if [[ "${fail}" -gt 0 ]]; then
    echo ""
    echo "Failures:"
    for f in "${failures[@]}"; do
        echo "  - ${f}"
    done
    exit 1
fi

exit 0
