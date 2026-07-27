#!/usr/bin/env bash
# Self-test for scripts/rs-capture-guard.sh (session 9k-1), the SOURCED
# write-discipline helper every Tier-2 capture script uses. See that file's
# own header for the "Disk quota exceeded" incident this helper exists to
# prevent, and CONTRIBUTING.md's "Differential oracle contract" for the rc
# table (a failed write here is always rc 2 - "tool/environment error" -
# never rc 1 "drift" and never rc 3 "legitimate skip").
#
# CONTRACT UNDER TEST (rs-capture-guard.sh's own header is authoritative;
# summarized here for these cases):
#
#   rs_capture_guard_init <label>   - names the sourcing script in messages
#   rs_capture_context [<text>]     - set (or with no arg, clear) a breadcrumb
#   rs_capture_die <msg...>         - print label[/context]: msg, exit 2
#   rs_checked <cmd> [args...]      - run cmd; exit 2 if it fails or rc==0 args
#   rs_checked_write <dest>         - write stdin to dest; exit 2 on failure
#   rs_checked_append_write <dest>  - append stdin to dest; exit 2 on failure
#   rs_capture_verify_output <dir> <min_entries>
#                                   - count regular files under dir
#                                     (recursively); exit 2 if fewer than
#                                     min_entries, if min_entries is 0 or
#                                     non-numeric, or if dir does not exist
#
# Every case below runs the function under test in a SUBSHELL, because
# rs_checked / rs_checked_write / rs_checked_append_write /
# rs_capture_verify_output / rs_capture_die all call `exit` on failure -
# calling them directly in this script's own process would abort the whole
# suite on the first failing case instead of recording it.
#
# Run with no arguments; safe to run locally or in CI.

# shellcheck disable=SC1090 # every `source "${GUARD}"` below resolves a
# path built from BASH_SOURCE at runtime; shellcheck cannot follow it
# statically, and it is intentionally not a literal path (the whole point of
# this suite is exercising the REAL scripts/rs-capture-guard.sh next to it).
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
GUARD="${REPO_ROOT}/scripts/rs-capture-guard.sh"

TMPROOT="$(mktemp -d)"
trap 'rm -rf "${TMPROOT}"' EXIT

pass=0
fail=0
failures=()

note_pass() {
    pass=$((pass + 1))
    echo "PASS: $1"
}

note_fail() {
    fail=$((fail + 1))
    failures+=("$1")
    echo "FAIL: $1"
}

# assert_rc NAME EXPECT_RC GOT_RC OUTFILE
assert_rc() {
    local name="$1" expect="$2" got="$3" outfile="$4"
    if [[ "${got}" -eq "${expect}" ]]; then
        note_pass "${name} (exit ${got})"
    else
        note_fail "${name}: expected exit ${expect}, got ${got}"
        [[ -f "${outfile}" ]] && sed 's/^/    | /' "${outfile}"
    fi
}

# ---------------------------------------------------------------------------
# Case: rs_checked on a SUCCEEDING command returns 0 and does NOT exit - the
# calling script must be able to keep running afterward.
# ---------------------------------------------------------------------------
out="${TMPROOT}/case1.out"
rc=0
(
    source "${GUARD}"
    rs_capture_guard_init "case1"
    rs_checked true
    echo "reached-after-rs_checked"
) >"${out}" 2>&1 || rc=$?
assert_rc "case1_rs_checked_success_returns_0" 0 "${rc}" "${out}"
if grep -qF "reached-after-rs_checked" "${out}"; then
    note_pass "case1_rs_checked_success_does_not_exit: control flow continued past rs_checked"
else
    note_fail "case1_rs_checked_success_does_not_exit: script never reached the line after rs_checked (got: $(cat "${out}"))"
fi

# ---------------------------------------------------------------------------
# Case: rs_checked on a FAILING command exits 2 and never reaches the next
# line.
# ---------------------------------------------------------------------------
out="${TMPROOT}/case2.out"
rc=0
(
    source "${GUARD}"
    rs_capture_guard_init "case2"
    rs_checked false
    echo "MUST-NOT-PRINT"
) >"${out}" 2>&1 || rc=$?
assert_rc "case2_rs_checked_failure_exits_2" 2 "${rc}" "${out}"
if grep -qF "MUST-NOT-PRINT" "${out}"; then
    note_fail "case2_rs_checked_failure_aborts: the line after a failing rs_checked call ran"
else
    note_pass "case2_rs_checked_failure_aborts: the line after a failing rs_checked call did not run"
fi

# ---------------------------------------------------------------------------
# Case: rs_checked with NO arguments exits 2 (usage error, not a silent no-op).
# ---------------------------------------------------------------------------
out="${TMPROOT}/case3.out"
rc=0
(
    source "${GUARD}"
    rs_capture_guard_init "case3"
    rs_checked
) >"${out}" 2>&1 || rc=$?
assert_rc "case3_rs_checked_no_args_exits_2" 2 "${rc}" "${out}"

# ---------------------------------------------------------------------------
# Case: rs_checked_write writes the exact bytes given on stdin.
# ---------------------------------------------------------------------------
dest="${TMPROOT}/case4-out.txt"
out="${TMPROOT}/case4.out"
rc=0
(
    source "${GUARD}"
    rs_capture_guard_init "case4"
    printf 'exact-bytes-42' | rs_checked_write "${dest}"
) >"${out}" 2>&1 || rc=$?
assert_rc "case4_rs_checked_write_succeeds" 0 "${rc}" "${out}"
if [[ -f "${dest}" ]] && [[ "$(cat "${dest}")" == "exact-bytes-42" ]]; then
    note_pass "case4_rs_checked_write_writes_exact_bytes"
else
    note_fail "case4_rs_checked_write_writes_exact_bytes: got '$(cat "${dest}" 2>/dev/null || echo '<missing>')'"
fi

# ---------------------------------------------------------------------------
# Case: rs_checked_write to an unwritable path exits 2. Uses a NONEXISTENT
# parent directory rather than chmod 000, so the case is root-safe: a missing
# parent (ENOENT) fails the write for root exactly as it does for anyone
# else, unlike a permission-denied (EACCES) fixture, which CAP_DAC_OVERRIDE
# bypasses when this suite runs as root (RHEL-family CI does).
# ---------------------------------------------------------------------------
out="${TMPROOT}/case5.out"
rc=0
(
    source "${GUARD}"
    rs_capture_guard_init "case5"
    printf 'x' | rs_checked_write "${TMPROOT}/no-such-dir/out.txt"
) >"${out}" 2>&1 || rc=$?
assert_rc "case5_rs_checked_write_unwritable_path_exits_2" 2 "${rc}" "${out}"

# ---------------------------------------------------------------------------
# Case: rs_capture_verify_output passes when the file count meets the floor.
# ---------------------------------------------------------------------------
d6="${TMPROOT}/case6-dir"
mkdir -p "${d6}"
touch "${d6}/a.txt" "${d6}/b.txt"
out="${TMPROOT}/case6.out"
rc=0
(
    source "${GUARD}"
    rs_capture_guard_init "case6"
    rs_capture_verify_output "${d6}" 2
) >"${out}" 2>&1 || rc=$?
assert_rc "case6_verify_output_meets_floor" 0 "${rc}" "${out}"

# ---------------------------------------------------------------------------
# Case: rs_capture_verify_output exits 2 when the count is SHORT of the
# floor - the capture must not be trusted if it wrote less than expected.
# ---------------------------------------------------------------------------
d7="${TMPROOT}/case7-dir"
mkdir -p "${d7}"
touch "${d7}/a.txt"
out="${TMPROOT}/case7.out"
rc=0
(
    source "${GUARD}"
    rs_capture_guard_init "case7"
    rs_capture_verify_output "${d7}" 5
) >"${out}" 2>&1 || rc=$?
assert_rc "case7_verify_output_short_count_exits_2" 2 "${rc}" "${out}"

# ---------------------------------------------------------------------------
# Case: rs_capture_verify_output exits 2 for a min_entries of 0 - a capture
# that expects to write nothing has nothing to verify, so 0 is a usage error
# rather than a trivially-satisfied floor.
# ---------------------------------------------------------------------------
d8="${TMPROOT}/case8-dir"
mkdir -p "${d8}"
out="${TMPROOT}/case8.out"
rc=0
(
    source "${GUARD}"
    rs_capture_guard_init "case8"
    rs_capture_verify_output "${d8}" 0
) >"${out}" 2>&1 || rc=$?
assert_rc "case8_verify_output_zero_floor_exits_2" 2 "${rc}" "${out}"

# ---------------------------------------------------------------------------
# Case: rs_capture_verify_output exits 2 for a non-numeric min_entries.
# ---------------------------------------------------------------------------
d9="${TMPROOT}/case9-dir"
mkdir -p "${d9}"
out="${TMPROOT}/case9.out"
rc=0
(
    source "${GUARD}"
    rs_capture_guard_init "case9"
    rs_capture_verify_output "${d9}" abc
) >"${out}" 2>&1 || rc=$?
assert_rc "case9_verify_output_non_numeric_floor_exits_2" 2 "${rc}" "${out}"

# ---------------------------------------------------------------------------
# Case: rs_capture_verify_output exits 2 for a MISSING directory.
# ---------------------------------------------------------------------------
out="${TMPROOT}/case10.out"
rc=0
(
    source "${GUARD}"
    rs_capture_guard_init "case10"
    rs_capture_verify_output "${TMPROOT}/does-not-exist-dir" 1
) >"${out}" 2>&1 || rc=$?
assert_rc "case10_verify_output_missing_dir_exits_2" 2 "${rc}" "${out}"

# ---------------------------------------------------------------------------
# Case: rs_capture_verify_output COUNTS FILES IN NESTED SUBDIRECTORIES (it is
# documented to use bash globstar rather than `find`, specifically so the
# helper adds no PATH dependency in a minimal container - this case confirms
# that recursive counting actually works, not just that it compiles).
# ---------------------------------------------------------------------------
d11="${TMPROOT}/case11-dir"
mkdir -p "${d11}/a/b/c"
touch "${d11}/top.txt" "${d11}/a/one.txt" "${d11}/a/b/two.txt" "${d11}/a/b/c/three.txt"
out="${TMPROOT}/case11.out"
rc=0
(
    source "${GUARD}"
    rs_capture_guard_init "case11"
    rs_capture_verify_output "${d11}" 4
) >"${out}" 2>&1 || rc=$?
assert_rc "case11_verify_output_counts_nested_subdirs_exact" 0 "${rc}" "${out}"

# The regression pin: if nested counting silently degraded to depth-1 only,
# the real count would be 1 (top.txt), which would ALSO satisfy a floor of 1
# but would wrongly FAIL a floor of 4 with "wrote 1 file(s)". Assert the
# message names 4, not some smaller number, so a depth-1 regression is caught
# even though both cases above already require rc 0.
out2="${TMPROOT}/case11b.out"
rc2=0
(
    source "${GUARD}"
    rs_capture_guard_init "case11b"
    rs_capture_verify_output "${d11}" 5
) >"${out2}" 2>&1 || rc2=$?
assert_rc "case11b_verify_output_short_by_one_exits_2" 2 "${rc2}" "${out2}"
if grep -qF "wrote 4 file(s)" "${out2}"; then
    note_pass "case11b_verify_output_nested_count_is_exactly_4"
else
    note_fail "case11b_verify_output_nested_count_is_exactly_4: expected 'wrote 4 file(s)' in message, got: $(cat "${out2}")"
fi

# ---------------------------------------------------------------------------
# Case: the context breadcrumb set via rs_capture_context appears in a
# subsequent failure message - a failure inside a per-scenario loop is
# useless without knowing WHICH scenario failed.
# ---------------------------------------------------------------------------
out="${TMPROOT}/case12.out"
rc=0
(
    source "${GUARD}"
    rs_capture_guard_init "case12"
    rs_capture_context "scenario-42"
    rs_checked false
) >"${out}" 2>&1 || rc=$?
assert_rc "case12_context_breadcrumb_present_rc" 2 "${rc}" "${out}"
if grep -qF "[scenario-42]" "${out}"; then
    note_pass "case12_context_breadcrumb_appears_in_message"
else
    note_fail "case12_context_breadcrumb_appears_in_message: got: $(cat "${out}")"
fi

# Clearing the breadcrumb (rs_capture_context with no argument) must remove
# it from later messages, not just add a second one.
out="${TMPROOT}/case12b.out"
rc=0
(
    source "${GUARD}"
    rs_capture_guard_init "case12b"
    rs_capture_context "scenario-99"
    rs_capture_context
    rs_checked false
) >"${out}" 2>&1 || rc=$?
if grep -qF "[scenario-99]" "${out}"; then
    note_fail "case12b_context_breadcrumb_clears: stale breadcrumb still present after clearing: $(cat "${out}")"
else
    note_pass "case12b_context_breadcrumb_clears"
fi

# ---------------------------------------------------------------------------
# Case: rs_capture_verify_output RESTORES the caller's nullglob / dotglob /
# globstar shopt settings rather than leaving them enabled. It flips all
# three on internally to do the recursive count; if it left them on, a
# capture script relying on the caller's PRE-existing (default: all three
# off) settings for its own later globs would silently start behaving
# differently after the first verify_output call.
#
# Sets a NON-default caller state deliberately (nullglob off, dotglob ON,
# globstar off) so this is not just "everything ends up off again by
# coincidence" - the restore must reproduce whatever the caller actually had.
# ---------------------------------------------------------------------------
d13="${TMPROOT}/case13-dir"
mkdir -p "${d13}"
touch "${d13}/f1"
out="${TMPROOT}/case13.out"
rc=0
(
    source "${GUARD}"
    rs_capture_guard_init "case13"
    shopt -u nullglob
    shopt -s dotglob
    shopt -u globstar
    before_n="$(shopt -p nullglob)"
    before_d="$(shopt -p dotglob)"
    before_g="$(shopt -p globstar)"
    rs_capture_verify_output "${d13}" 1
    after_n="$(shopt -p nullglob)"
    after_d="$(shopt -p dotglob)"
    after_g="$(shopt -p globstar)"
    if [[ "${before_n}" == "${after_n}" && "${before_d}" == "${after_d}" && "${before_g}" == "${after_g}" ]]; then
        echo "SHOPT_RESTORED"
    else
        echo "SHOPT_NOT_RESTORED before=[${before_n} | ${before_d} | ${before_g}] after=[${after_n} | ${after_d} | ${after_g}]"
    fi
) >"${out}" 2>&1 || rc=$?
if [[ "${rc}" -eq 0 ]] && grep -qF "SHOPT_RESTORED" "${out}"; then
    note_pass "case13_verify_output_restores_shopt_state"
else
    note_fail "case13_verify_output_restores_shopt_state: rc=${rc}, output: $(cat "${out}")"
fi

# ---------------------------------------------------------------------------
# Bonus case: rs_capture_guard_init itself rejects a missing or empty label -
# every diagnostic in this helper is useless without knowing which capture
# script emitted it.
# ---------------------------------------------------------------------------
out="${TMPROOT}/case14.out"
rc=0
( source "${GUARD}"; rs_capture_guard_init ) >"${out}" 2>&1 || rc=$?
assert_rc "case14_guard_init_no_args_exits_2" 2 "${rc}" "${out}"

out="${TMPROOT}/case14b.out"
rc=0
( source "${GUARD}"; rs_capture_guard_init "" ) >"${out}" 2>&1 || rc=$?
assert_rc "case14b_guard_init_empty_label_exits_2" 2 "${rc}" "${out}"

# ---------------------------------------------------------------------------
# Case (session 9k-1 integration remediation): rs_checked_append_write
# APPENDS rather than truncating - two calls against the same destination
# must both survive in the file, in order. This is the append-mode sibling
# of rs_checked_write, added because a Tier-2 capture that emits one row per
# loop iteration cannot use the truncating form for every row.
# ---------------------------------------------------------------------------
dest15="${TMPROOT}/case15-out.txt"
out="${TMPROOT}/case15.out"
rc=0
(
    source "${GUARD}"
    rs_capture_guard_init "case15"
    printf 'first\n' | rs_checked_append_write "${dest15}"
    printf 'second\n' | rs_checked_append_write "${dest15}"
) >"${out}" 2>&1 || rc=$?
assert_rc "case15_rs_checked_append_write_succeeds" 0 "${rc}" "${out}"
if [[ -f "${dest15}" ]] && [[ "$(cat "${dest15}")" == $'first\nsecond' ]]; then
    note_pass "case15_rs_checked_append_write_appends_both_calls"
else
    note_fail "case15_rs_checked_append_write_appends_both_calls: got '$(cat "${dest15}" 2>/dev/null || echo '<missing>')'"
fi

# ---------------------------------------------------------------------------
# Case: rs_checked_append_write to an unwritable path exits 2. Same
# ENOENT-not-EACCES reasoning as case5 (root-safe).
# ---------------------------------------------------------------------------
out="${TMPROOT}/case16.out"
rc=0
(
    source "${GUARD}"
    rs_capture_guard_init "case16"
    printf 'x' | rs_checked_append_write "${TMPROOT}/no-such-dir/out.txt"
) >"${out}" 2>&1 || rc=$?
assert_rc "case16_rs_checked_append_write_unwritable_path_exits_2" 2 "${rc}" "${out}"

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
