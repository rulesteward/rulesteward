#!/usr/bin/env bash
# RED test suite for scripts/check-no-mnt-paths.sh (session 9k-0, #572).
#
# FROZEN INVOCATION CONTRACT for the gate script (the implementer inherits this):
#
#   scripts/check-no-mnt-paths.sh [PATH...]
#
#   WHY THIS GATE EXISTS
#   The wave3 fapolicyd corpus lived at an absolute /mnt path and was destroyed
#   in the 2026-07-13 NFS rebuild (#572). `just diff-fapolicyd` then exited 0
#   with a skip message on every run: it reported success while checking
#   nothing. The root cause is not "the NFS mount died", it is "a repo-invoked
#   command depended on an input that could vanish". This gate makes that class
#   impossible: no repo-invoked command may reference a path outside the repo.
#
#   SCAN SET
#   - With no PATH arguments: scans, relative to the caller's CWD (the gate is
#     always invoked from the repo root by `just` and by CI):
#       * the `justfile` at the root, if present
#       * every *.rs and *.sh under crates/, tools/ and scripts/
#       * every *.yml and *.yaml under .github/workflows/
#   - With one or more PATH arguments: scans each PATH instead of the default.
#     A PATH may be a file (scanned directly, whatever its extension) or a
#     directory (walked with the same extension rule as above).
#
#   VIOLATION RULE
#   A line containing the literal substring `/mnt/` is a VIOLATION unless
#   EITHER:
#     (a) the line is a COMMENT - optional leading whitespace, then `#` or
#         `//` (this covers `#`, `//`, `///` and `//!`); or
#     (b) the line contains the literal marker `mnt-path-exempt:`.
#
#   The comment carve-out is deliberate and was measured, not assumed. On the
#   tree at 34d18ac there are 40 `/mnt/` references; exactly ONE
#   (justfile:16, `validate_sh := "/mnt/..."`) is a load-bearing path that
#   tooling actually reads. The other ~39 are provenance citations in doc
#   comments and PROVENANCE.md files recording where corpus data came from at
#   generation time, plus a handful of genuine fixture paths like
#   `/mnt/usb/file` inside simulate scenarios. A gate that flagged all 40 would
#   need ~39 exemption markers, and a gate that is 90% exemptions trains people
#   to blanket-add them. Provenance is not the defect; an operative path is.
#
#   DATA FILES ARE NOT SCANNED. *.md, *.json, *.rules, *.toml and corpus
#   fixtures are outside the scan set by construction, so PROVENANCE.md
#   "NFS source:" lines and fixture workloads need no exemption.
#
#   ANTI-VACUITY (the point of the whole session)
#   A run that scanned ZERO eligible files MUST NOT report clean. "Nothing
#   fired" and "nothing ran" have to be distinguishable, so the success line
#   carries the file count and a zero count is a tool error, not a pass. This
#   mirrors the repo's `OK (0 drift, 3 controls)` idiom.
#
#   EXIT CODES (the rc 0/1/2/3 convention this session introduces)
#     0 - clean. MUST print a line containing `0 violations` AND the number of
#         files scanned, e.g. `check-no-mnt-paths: OK (0 violations, 214 files scanned)`.
#     1 - at least one violation. MUST name each violating file and line, and
#         MUST mention the literal token `mnt-path-exempt:` so an operator can
#         see the escape hatch.
#     2 - tool/environment error: a PATH argument that does not exist, or a
#         scan that matched zero eligible files.
#
# This test script is self-contained: it builds synthetic fixtures in a mktemp
# dir per case, invokes the (not-yet-implemented) gate against them, and
# asserts the exit code and message content. Run with no arguments; safe to run
# locally or in CI.
#
# NOTE: this file necessarily contains the very substring it is testing for, so
# its own operative lines carry the `mnt-path-exempt:` marker. That is
# deliberate dogfooding: the escape hatch is exercised by the real tree, not
# only by fixtures.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
GATE="${REPO_ROOT}/scripts/check-no-mnt-paths.sh"

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

# run_case NAME TARGET EXPECT_RC
# Invokes the gate against TARGET, captures combined stdout+stderr to
# TMPROOT/NAME.out, and asserts the exit code equals EXPECT_RC. Returns 0
# always (failures are recorded, not raised) so every case runs even if an
# earlier one fails.
run_case() {
    local name="$1" target="$2" expect_rc="$3"
    local out="${TMPROOT}/${name}.out"
    local rc=0
    "${GATE}" "${target}" >"${out}" 2>&1 || rc=$?
    if [[ "${rc}" -eq "${expect_rc}" ]]; then
        note_pass "${name} (exit ${rc})"
    else
        note_fail "${name}: expected exit ${expect_rc}, got ${rc}"
        sed 's/^/    | /' "${out}" || true
    fi
}

# assert_output_contains NAME NEEDLE DESC
assert_output_contains() {
    local name="$1" needle="$2" desc="$3"
    local out="${TMPROOT}/${name}.out"
    if grep -qF "${needle}" "${out}" 2>/dev/null; then
        note_pass "${name}: ${desc}"
    else
        note_fail "${name}: ${desc} (got: $(cat "${out}" 2>/dev/null || echo '<no output>'))"
    fi
}

write_fixture() {
    local rel="$1"
    local path="${TMPROOT}/${rel}"
    mkdir -p "$(dirname "${path}")"
    cat >"${path}"
}

# The literals this suite is about. Each marker must sit on the SAME line as
# the match: the gate scans scripts/*.sh, so these fixture literals would
# otherwise make the test suite itself a violation (they did, on the first run).
# Referencing them through variables keeps the heredocs below free of any bare
# occurrence, so the fixtures stay byte-faithful to what they imitate.
BAD="/mnt/side-projects/gone"        # mnt-path-exempt: synthetic fixture literal
BAD_USB="/mnt/usb/file"              # mnt-path-exempt: synthetic fixture literal
BAD_EXE="/mnt/py-tmpfs/python3"      # mnt-path-exempt: synthetic fixture literal

# ---------------------------------------------------------------------------
# Case 1: an operative /mnt/ path in a justfile -> exit 1.
# This is the exact shape of the real defect (justfile:16).
# ---------------------------------------------------------------------------
mkdir -p "${TMPROOT}/case1"
printf 'validate_sh := "%s/tools/validate.sh"\n' "${BAD}" >"${TMPROOT}/case1/justfile"
run_case "case1_operative_justfile" "${TMPROOT}/case1/justfile" 1
assert_output_contains "case1_operative_justfile" "mnt-path-exempt:" \
    "message names the escape hatch"
assert_output_contains "case1_operative_justfile" "justfile" \
    "message names the violating file"

# ---------------------------------------------------------------------------
# Case 2: a COMMENTED /mnt/ path in a justfile -> exit 0.
# Provenance and examples in comments are not the defect.
# ---------------------------------------------------------------------------
mkdir -p "${TMPROOT}/case2"
{
    printf '# Example: just diff-fapolicyd %s/wave3 \x27adversarial/*\x27\n' "${BAD}"
    printf 'somevar := "harmless"\n'
} >"${TMPROOT}/case2/justfile"
run_case "case2_comment_justfile" "${TMPROOT}/case2/justfile" 0

# ---------------------------------------------------------------------------
# Case 3: Rust doc comments (//!, ///, //) carrying provenance -> exit 0.
# This is ~36 of the 40 real references; flagging them would be pure noise.
# ---------------------------------------------------------------------------
write_fixture "case3/crates/fake/src/lints.rs" <<EOF
//! Grounded in \`${BAD}/grounding/g1.md\`
/// values from \`${BAD}/grounding/g7.md\`
// see \`${BAD}/lane-b-grounding.md\` section 4a
pub fn thing() -> u8 {
    7
}
EOF
run_case "case3_rust_doc_comments" "${TMPROOT}/case3" 0

# ---------------------------------------------------------------------------
# Case 4: an operative /mnt/ path in a Rust string literal -> exit 1.
# A comment is provenance; a string literal is something the code opens.
# ---------------------------------------------------------------------------
write_fixture "case4/crates/fake/src/loader.rs" <<EOF
pub fn corpus_root() -> &'static str {
    "${BAD}/corpus"
}
EOF
run_case "case4_operative_rust" "${TMPROOT}/case4" 1

# ---------------------------------------------------------------------------
# Case 5: the mnt-path-exempt: marker suppresses an operative line -> exit 0.
# ---------------------------------------------------------------------------
write_fixture "case5/tools/faketool/src/main.rs" <<EOF
pub fn legacy_root() -> &'static str {
    "${BAD}/corpus" // mnt-path-exempt: historical, read only by an archived tool
}
EOF
run_case "case5_exempt_marker" "${TMPROOT}/case5" 0

# ---------------------------------------------------------------------------
# Case 6: an operative /mnt/ path in a workflow yml -> exit 1.
# ---------------------------------------------------------------------------
write_fixture "case6/.github/workflows/drift.yml" <<EOF
jobs:
  drift:
    steps:
      - run: bash ${BAD}/tools/validate.sh
EOF
run_case "case6_operative_workflow" "${TMPROOT}/case6" 1

# ---------------------------------------------------------------------------
# Case 7: an operative /mnt/ path in a shell script -> exit 1.
# ---------------------------------------------------------------------------
write_fixture "case7/scripts/capture.sh" <<EOF
#!/usr/bin/env bash
CORPUS="${BAD}/corpus"
echo "\${CORPUS}"
EOF
run_case "case7_operative_shell" "${TMPROOT}/case7" 1

# ---------------------------------------------------------------------------
# Case 8: DATA files are not scanned -> exit 0.
# PROVENANCE.md "NFS source:" lines and corpus fixtures (workload.json,
# *.rules) legitimately carry /mnt/ paths and must never need an exemption.
# The directory also holds one eligible .rs file so the run is not vacuous.
# ---------------------------------------------------------------------------
write_fixture "case8/crates/fake/tests/corpus/PROVENANCE.md" <<EOF
NFS source: \`${BAD}/auditd-corpus/20260603T004238Z/\`
EOF
write_fixture "case8/crates/fake/tests/corpus/scenario/workload.json" <<EOF
{ "path": "${BAD_USB}", "exe": "${BAD_EXE}" }
EOF
write_fixture "case8/crates/fake/tests/corpus/scenario/rules.d/10-base.rules" <<EOF
deny_audit perm=execute exe=${BAD_EXE} : all
EOF
write_fixture "case8/crates/fake/src/real.rs" <<'EOF'
pub fn ok() -> u8 { 1 }
EOF
run_case "case8_data_files_unscanned" "${TMPROOT}/case8" 0

# ---------------------------------------------------------------------------
# Case 9 (THE ANTI-VACUITY CASE): a scan matching ZERO eligible files must be
# a TOOL ERROR (exit 2), never a pass. "Nothing fired" and "nothing ran" have
# to be distinguishable, or this gate reproduces the exact bug it exists to
# prevent.
# ---------------------------------------------------------------------------
write_fixture "case9/notes/README.md" <<'EOF'
Just prose. No eligible source files anywhere in this tree.
EOF
run_case "case9_zero_files_scanned_is_error" "${TMPROOT}/case9" 2

# ---------------------------------------------------------------------------
# Case 10: a PATH that does not exist -> exit 2 (tool error, not "clean").
# ---------------------------------------------------------------------------
run_case "case10_missing_path" "${TMPROOT}/definitely-not-here" 2

# ---------------------------------------------------------------------------
# Case 11: a clean tree reports a NON-ZERO file count, so an operator can tell
# "scanned 3 files, all clean" from "scanned nothing".
# ---------------------------------------------------------------------------
write_fixture "case11/crates/fake/src/a.rs" <<'EOF'
pub fn a() -> u8 { 1 }
EOF
write_fixture "case11/crates/fake/src/b.rs" <<'EOF'
pub fn b() -> u8 { 2 }
EOF
run_case "case11_clean_reports_count" "${TMPROOT}/case11" 0
assert_output_contains "case11_clean_reports_count" "0 violations" \
    "success line states 0 violations"
assert_output_contains "case11_clean_reports_count" "2 files" \
    "success line states how many files were scanned"

# ---------------------------------------------------------------------------
# Case 12: THE REAL TREE, with no arguments, must be clean.
#
# This case is RED until Phase 0b deletes justfile:16. That failing run is the
# gate's own positive control: it proves the instrument sees the real defect
# before the defect is removed. Do not "fix" this by weakening the gate.
# ---------------------------------------------------------------------------
case12_out="${TMPROOT}/case12_real_tree.out"
case12_rc=0
(cd "${REPO_ROOT}" && "${GATE}") >"${case12_out}" 2>&1 || case12_rc=$?
if [[ "${case12_rc}" -eq 0 ]]; then
    note_pass "case12_real_tree (exit 0)"
else
    note_fail "case12_real_tree: expected exit 0, got ${case12_rc}"
    sed 's/^/    | /' "${case12_out}" || true
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
