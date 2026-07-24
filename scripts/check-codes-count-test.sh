#!/usr/bin/env bash
# RED test suite for scripts/check-codes-count.sh (#586).
#
# FROZEN INVOCATION CONTRACT for the gate script (the implementer inherits
# this; it is authored here, before the real implementation exists, in the
# same test-first spirit as scripts/check-dac-guard-test.sh for #467):
#
#   scripts/check-codes-count.sh [REPO_ROOT]
#
#   - With no argument: REPO_ROOT defaults to the caller's current working
#     directory (the gate is always invoked from the repo root, by `just`
#     and by CI, so this resolves to the real repo tree in normal use).
#   - With one argument: REPO_ROOT is that directory instead.
#
#   Scanned files (relative to REPO_ROOT), exactly two, IF PRESENT:
#     - README.md
#     - crates/rulesteward-cli/src/cli/mod.rs
#   A scanned file that does not exist under REPO_ROOT contributes zero
#   mentions and is NOT itself an error (keeps the contract testable
#   against minimal synthetic fixtures that only need a README.md).
#
#   OUT OF SCOPE (verified, deliberately NOT scanned):
#     - CHANGELOG.md - release notes are point-in-time historical claims
#       ("sudoers shipped with 8 `sudo-` codes in 0.3.0"), correct for the
#       release they describe even after the catalog has since grown.
#       Scanning it would flag every past release note as a permanent,
#       unfixable violation.
#     - Rust `//` comments anywhere (e.g.
#       crates/rulesteward-cli/tests/cli_help.rs's comment recalling the
#       #414 drift bug, "still claimed \"All 12 sshd- codes\"") - these
#       recall PAST drift as documentation of a fixed bug, they are not
#       live doc-truth claims. The file's actual live assertion
#       (`.stdout(predicate::str::contains("13 sshd-"))`) already checks
#       the current count independently of this gate.
#   Both exclusions were confirmed by a repo-wide grep during test
#   authoring (see PR/commit description), not assumed.
#
#   Six backends, each with a code-prefix, a catalog source file (relative
#   to REPO_ROOT), and a display name used by the third mention shape below:
#
#     prefix     catalog file                                          display name
#     ------     ------------                                          ------------
#     fapd-      crates/rulesteward-fapolicyd/src/lints/catalog.rs      fapolicyd
#     au-        crates/rulesteward-auditd/src/lints/catalog.rs         auditd
#     sshd-      crates/rulesteward-sshd/src/lints/catalog.rs           sshd_config
#     sudo-      crates/rulesteward-sudoers/src/lints/catalog.rs        sudoers
#     sysctld-   crates/rulesteward-sysctld/src/catalog.rs              sysctl.d
#     se-        crates/rulesteward-selinux/src/lints/catalog.rs        SELinux
#
#   A backend's CATALOG LENGTH is the count of lines matching the literal
#   substring `code: "<prefix>` in its catalog file (one entry per line,
#   matching the repo's one-field-per-line struct-literal style).
#
#   A "codes mention" is any of these three shapes, found anywhere in the
#   scanned files, tied to one of the six prefixes/display names (real
#   examples from the current README.md / cli/mod.rs, quoted verbatim):
#     (a) `<N> `<prefix>-`? codes` (backtick-wrapping optional) -
#         "28 `fapd-` codes", "9 au- codes", "All 13 `sshd-` codes are active"
#     (b) `` `<prefix>-`, <N> codes) `` - the README heading form -
#         "### fapolicyd (`fapd-`, 28 codes)"
#     (c) `<N> <display-name> codes` - "28 fapolicyd codes"
#   Each mention's stated N must equal that backend's catalog length.
#
#   VIOLATION reporting: each unmatched mention is reported as
#   `<file>:<line>` plus the stated N and the actual catalog length, so an
#   operator can find and fix it without re-deriving the diff themselves.
#
#   ANTI-VACUITY: a scan that finds ZERO "codes" mentions across both
#   files combined is ALSO a violation (exit non-zero) - a rewritten doc
#   set that silently drops every prose mention must not silently satisfy
#   this gate ("nothing fired" == "nothing ran"). On every invocation
#   (clean or not), the script's stdout MUST include a summary line of the
#   exact literal form:
#       scanned N "codes" mention(s)
#   (N = decimal count) so tooling (and this test harness) can assert N
#   mechanically rather than trusting a bare exit code.
#
#   EXIT CODE: 0 only when at least one mention was found AND every
#   mention's stated N equals its backend's catalog length. 1 otherwise
#   (any mismatch, or zero mentions found).
#
# This test script is self-contained: it builds synthetic README.md (+ one
# synthetic catalog) fixtures in a mktemp dir per case, invokes the
# (not-yet-implemented) gate against them, and asserts the exit code and,
# where relevant, that the output names the right file:line or reports a
# positive scanned-mentions count. It ALSO runs the gate against the real
# repo tree and asserts it catches the three counts that are ACTUALLY wrong
# there today (verified independently during test authoring, not merely
# copied from the issue): README.md:127 (`9 au- codes`, actual 11),
# README.md:139 (`8 sudo- codes`, actual 9), and README.md:286
# (`### sysctl.d (\`sysctld-\`, 4 codes)`, actual 5). Run with no arguments;
# safe to run locally or in CI.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
GATE="${REPO_ROOT}/scripts/check-codes-count.sh"

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

# assert_output_contains NAME PATTERN DESC
# Requires TMPROOT/NAME.out (already captured by run_case, or by a manual
# case) to contain the literal fixed-string PATTERN.
assert_output_contains() {
    local name="$1" pattern="$2" desc="$3"
    local out="${TMPROOT}/${name}.out"
    if grep -qF -- "${pattern}" "${out}" 2>/dev/null; then
        note_pass "${name}: ${desc}"
    else
        note_fail "${name}: ${desc} (pattern '${pattern}' not found; got: $(cat "${out}" 2>/dev/null || echo '<no output>'))"
    fi
}

# assert_scanned_count_positive NAME
# The anti-vacuity check: parses the "scanned N \"codes\" mention(s)"
# summary line out of TMPROOT/NAME.out and asserts N is a positive
# integer. A guard that silently finds nothing while still exiting 0, or
# that never prints the summary line at all, fails this check.
assert_scanned_count_positive() {
    local name="$1"
    local out="${TMPROOT}/${name}.out"
    local n=""
    n="$(grep -oE 'scanned [0-9]+ "codes" mention' "${out}" 2>/dev/null | grep -oE '[0-9]+' | head -1 || true)"
    if [[ -n "${n}" ]] && [[ "${n}" -gt 0 ]]; then
        note_pass "${name}: anti-vacuity - scanned ${n} > 0 mention(s)"
    else
        note_fail "${name}: anti-vacuity - no positive scanned-mentions count found (got: $(cat "${out}" 2>/dev/null || echo '<no output>'))"
    fi
}

write_fixture() {
    local rel="$1"
    local path="${TMPROOT}/${rel}"
    mkdir -p "$(dirname "${path}")"
    cat >"${path}"
}

# ---------------------------------------------------------------------------
# Shared synthetic catalog: a 3-entry sysctld- catalog, reused by case1 and
# case2 below. It deliberately uses different numbers than the real repo's
# SYSCTLD_CODES (which has 5) so a synthetic-case failure can never be
# confused with the real README.md:286 bug asserted in case4.
# ---------------------------------------------------------------------------
synthetic_catalog() {
    cat <<'EOF'
pub const SYSCTLD_CODES: &[LintCode] = &[
    LintCode {
        code: "sysctld-F01",
        severity: Severity::Fatal,
        description: "fixture: parse failure",
    },
    LintCode {
        code: "sysctld-W01",
        severity: Severity::Warning,
        description: "fixture: last-wins conflict",
    },
    LintCode {
        code: "sysctld-W02",
        severity: Severity::Warning,
        description: "fixture: baseline gap",
    },
];
EOF
}

# ---------------------------------------------------------------------------
# Case 1: a seeded WRONG count (heading shape (b), stated 5, actual 3) ->
# exit 1, naming the fixture README's file:line (line 5).
# ---------------------------------------------------------------------------
synthetic_catalog | write_fixture "case1/crates/rulesteward-sysctld/src/catalog.rs"
write_fixture "case1/README.md" <<'EOF'
# Fixture repo for scripts/check-codes-count-test.sh

Unrelated prose line.

### sysctl.d (`sysctld-`, 5 codes)

More prose describing the sysctld backend.
EOF

run_case "case1_seeded_wrong_count" "${TMPROOT}/case1" 1
assert_output_contains "case1_seeded_wrong_count" "README.md:5" \
    "names the fixture README's file:line for the seeded mismatch"

# ---------------------------------------------------------------------------
# Case 2: the SAME fixture with the CORRECT count (stated 3, actual 3) ->
# exit 0. Also the anti-vacuity positive check: the scan (one real mention)
# must report a positive scanned-mentions count, not silence.
# ---------------------------------------------------------------------------
synthetic_catalog | write_fixture "case2/crates/rulesteward-sysctld/src/catalog.rs"
write_fixture "case2/README.md" <<'EOF'
# Fixture repo for scripts/check-codes-count-test.sh

Unrelated prose line.

### sysctl.d (`sysctld-`, 3 codes)

More prose describing the sysctld backend.
EOF

run_case "case2_correct_count" "${TMPROOT}/case2" 0
assert_scanned_count_positive "case2_correct_count"

# ---------------------------------------------------------------------------
# Case 3: ANTI-VACUITY. A fixture repo whose README.md contains ZERO "N
# codes" mentions (plain prose only, no catalog needed since nothing refers
# to one) -> exit 1, NOT 0. A guard that scans, matches nothing, and exits
# 0 ("nothing to complain about") would pass every other case in this file
# vacuously and is exactly the failure mode #586 exists to close.
# ---------------------------------------------------------------------------
write_fixture "case3/README.md" <<'EOF'
# Fixture repo with no codes mentions at all

This README intentionally says nothing about lint code counts.
EOF

run_case "case3_zero_mentions_is_a_failure" "${TMPROOT}/case3" 1

# ---------------------------------------------------------------------------
# Case 4: the REAL repo tree, invoked with NO arguments (default CWD),
# from the repo root. As of this writing README.md has THREE genuine
# mismatches (verified independently by grepping the catalogs and the
# doc prose, not merely copied from the issue description):
#   README.md:127  "9 au- codes"                    stated 9,  actual 11
#   README.md:139  "8 sudo- codes"                  stated 8,  actual 9
#   README.md:286  "### sysctl.d (`sysctld-`, 4 codes)"  stated 4, actual 5
# The gate must exit non-zero and name all three. It must also report a
# positive scanned-mentions count (there are 14 real "N codes" mentions
# across README.md and cli/mod.rs today).
# ---------------------------------------------------------------------------
case4_out="${TMPROOT}/case4_real_tree.out"
case4_rc=0
(cd "${REPO_ROOT}" && "${GATE}") >"${case4_out}" 2>&1 || case4_rc=$?
if [[ "${case4_rc}" -ne 0 ]]; then
    note_pass "case4_real_tree_catches_known_live_bugs (exit ${case4_rc}, non-zero as expected)"
else
    note_fail "case4_real_tree_catches_known_live_bugs: expected non-zero exit (real README.md drift exists today), got 0"
fi

for hit in "README.md:127" "README.md:139" "README.md:286"; do
    if grep -qF -- "${hit}" "${case4_out}" 2>/dev/null; then
        note_pass "case4_real_tree_catches_known_live_bugs: names ${hit}"
    else
        note_fail "case4_real_tree_catches_known_live_bugs: does not name ${hit} (a real, currently-live count mismatch)"
    fi
done

n="$(grep -oE 'scanned [0-9]+ "codes" mention' "${case4_out}" 2>/dev/null | grep -oE '[0-9]+' | head -1 || true)"
if [[ -n "${n}" ]] && [[ "${n}" -gt 0 ]]; then
    note_pass "case4_real_tree_catches_known_live_bugs: anti-vacuity - scanned ${n} > 0 mention(s) in the real tree"
else
    note_fail "case4_real_tree_catches_known_live_bugs: anti-vacuity - no positive scanned-mentions count against the real tree (got: $(cat "${case4_out}" 2>/dev/null || echo '<no output>'))"
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
