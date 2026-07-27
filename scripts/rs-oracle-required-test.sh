#!/usr/bin/env bash
# RED test suite for scripts/rs-oracle-required.sh (session 9k-1).
#
# FROZEN INVOCATION CONTRACT for the predicate script (the implementer inherits
# this; do not widen it without updating this file in the same commit):
#
#   scripts/rs-oracle-required.sh <ORACLE>
#
#   WHY THIS PREDICATE EXISTS
#   CONTRIBUTING.md's differential oracle contract gives rc 3 the meaning
#   "precondition unmet, a legitimate skip". rc 3 is only safe because CI can
#   promote it to a hard failure wherever the oracle really is installed. That
#   promotion is driven by an environment variable, so the variable's parse is
#   the hinge the whole contract hangs on: parse it fail-OPEN and CI silently
#   returns to skipping, which is the exact #572 failure the program exists to
#   eliminate.
#
#   THE PARSE MUST BE FAIL-CLOSED
#   Any non-empty value that is not an explicit off-switch means REQUIRED.
#   Comparing against the literal "1" is fail-OPEN and has already been written
#   and caught once in this program: a later session writing
#   `RS_REQUIRE_X: true` in YAML (unquoted, so it arrives as the string `true`,
#   and ci.yml already uses that unquoted scalar style elsewhere) would silently
#   get a fully green run in which nothing ran. Ambiguous means required.
#
#   OFF-SWITCHES (case-insensitive, after trimming surrounding whitespace):
#     unset, "", whitespace-only, "0", "false", "no", "off"
#   Everything else non-empty is REQUIRED, including "true", "yes", "on", "1",
#   and arbitrary words such as "required".
#
#   TWO VARIABLES, OR-COMBINED
#     RS_ORACLE_REQUIRED        - the program-wide switch
#     RS_REQUIRE_<ORACLE>       - the per-harness switch
#   The oracle is required if EITHER declares it required. OR is the fail-closed
#   reading and needs no precedence rule. To exempt one lane in a CI job, set
#   only the per-lane variables in that job rather than the global one.
#
#   ORACLE ARGUMENT
#   Used verbatim to build the RS_REQUIRE_<ORACLE> name, and validated against
#   ^[A-Z][A-Z0-9_]*$. A lowercase or hyphenated argument is a USAGE ERROR (rc 2)
#   rather than being silently upcased: a typo that never matches any variable
#   would otherwise read as "not required" forever, which is fail-open by
#   another route.
#
#   EXIT CODES
#     0 - the oracle IS required
#     1 - the oracle is NOT required
#     2 - usage error (missing, empty, extra, or malformed ORACLE argument)
#
#   Note 0-means-required is deliberate: the caller is a `just` recipe asking
#   "should I promote my rc 3 to rc 2?", and `if bash rs-oracle-required.sh X;
#   then exit 2; fi` reads correctly with shell truthiness.
#
# SELF-PROVING (this suite's own positive control)
# The final case synthesizes the known-bad fail-OPEN implementation (the
# `[ "$v" = "1" ]` comparison) and runs the SAME case table against it, then
# asserts the table REJECTS it. An instrument that cannot fail has not been
# shown to measure anything, and this file is itself an instrument. Per the
# session rule: one positive control on known-bad input before any green from
# it is trusted.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GATE="${REPO_ROOT}/scripts/rs-oracle-required.sh"

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

# run_case <name> <script> <expected-rc> <oracle-arg...> with the environment
# supplied by the caller via `env` assignments in ENVSPEC.
#
# ENVSPEC is a newline-free, space-separated list of VAR=VALUE pairs, passed to
# `env`. An empty ENVSPEC means "inherit nothing extra". `env -u` entries are
# supported so a case can prove the UNSET behaviour rather than the empty one.
run_case() {
    local name="$1" script="$2" expected="$3" envspec="$4" oracle="${5-}"
    local out="${TMPROOT}/${name}.out"
    local rc=0

    # shellcheck disable=SC2086 # envspec is deliberately word-split
    if [[ -n "${oracle}" ]]; then
        env -i PATH="${PATH}" ${envspec} bash "${script}" "${oracle}" >"${out}" 2>&1 || rc=$?
    else
        env -i PATH="${PATH}" ${envspec} bash "${script}" >"${out}" 2>&1 || rc=$?
    fi

    if [[ "${rc}" -eq "${expected}" ]]; then
        note_pass "${name} (rc ${rc})"
        return 0
    fi
    note_fail "${name}: expected rc ${expected}, got ${rc}"
    sed 's/^/    | /' "${out}" || true
    return 1
}

# The frozen case table. Every case is (name, expected-rc, envspec, oracle).
# Kept as a function so the positive control below can replay it verbatim
# against a known-bad implementation.
#
# Fields are '|'-separated, NOT tab-separated. Tab is IFS *whitespace*, so bash
# collapses a run of consecutive tabs into a single delimiter and an empty
# middle field silently shifts every later field left by one. That bug was
# written here first: the empty-envspec case sent the oracle name into the
# envspec slot, where `env` tried to execute it as a command (rc 126). A
# non-whitespace delimiter preserves empty fields, which is the property this
# table needs. Do not "simplify" back to tabs.
CASES='both_unset|1||AUDITCTL
global_1|0|RS_ORACLE_REQUIRED=1|AUDITCTL
global_0|1|RS_ORACLE_REQUIRED=0|AUDITCTL
global_empty|1|RS_ORACLE_REQUIRED=|AUDITCTL
global_false_lower|1|RS_ORACLE_REQUIRED=false|AUDITCTL
global_false_upper|1|RS_ORACLE_REQUIRED=FALSE|AUDITCTL
global_false_mixed|1|RS_ORACLE_REQUIRED=False|AUDITCTL
global_no|1|RS_ORACLE_REQUIRED=no|AUDITCTL
global_NO|1|RS_ORACLE_REQUIRED=NO|AUDITCTL
global_off|1|RS_ORACLE_REQUIRED=off|AUDITCTL
global_OFF|1|RS_ORACLE_REQUIRED=OFF|AUDITCTL
global_true|0|RS_ORACLE_REQUIRED=true|AUDITCTL
global_True|0|RS_ORACLE_REQUIRED=True|AUDITCTL
global_TRUE|0|RS_ORACLE_REQUIRED=TRUE|AUDITCTL
global_yes|0|RS_ORACLE_REQUIRED=yes|AUDITCTL
global_on|0|RS_ORACLE_REQUIRED=on|AUDITCTL
global_word|0|RS_ORACLE_REQUIRED=required|AUDITCTL
perlane_alone|0|RS_REQUIRE_AUDITCTL=1|AUDITCTL
perlane_true|0|RS_REQUIRE_AUDITCTL=true|AUDITCTL
perlane_wins_over_global_off|0|RS_ORACLE_REQUIRED=0 RS_REQUIRE_AUDITCTL=1|AUDITCTL
global_wins_over_perlane_off|0|RS_ORACLE_REQUIRED=1 RS_REQUIRE_AUDITCTL=0|AUDITCTL
both_off|1|RS_ORACLE_REQUIRED=0 RS_REQUIRE_AUDITCTL=off|AUDITCTL
other_lane_does_not_leak|1|RS_REQUIRE_VISUDO=1|AUDITCTL
sysctl_lane_named|0|RS_REQUIRE_SYSTEMD_SYSCTL=1|SYSTEMD_SYSCTL
visudo_lane_named|0|RS_REQUIRE_VISUDO=1|VISUDO'

run_table() {
    local script="$1" prefix="$2"
    local table_rc=0
    local name expected envspec oracle
    local rows=0
    while IFS='|' read -r name expected envspec oracle; do
        [[ -z "${name}" ]] && continue
        rows=$((rows + 1))
        # Guard against the field-splitting bug this table was born with: every
        # row MUST yield a non-empty oracle in the 4th field. If a delimiter
        # change ever shifts fields again, fail loudly here instead of silently
        # running a differently-shaped command.
        if [[ -z "${oracle}" ]]; then
            note_fail "${prefix}${name}: TABLE PARSE ERROR - the oracle field is empty, so the row was mis-split. Check the CASES delimiter."
            table_rc=1
            continue
        fi
        if run_case "${prefix}${name}" "${script}" "${expected}" "${envspec}" "${oracle}"; then
            :
        else
            table_rc=1
        fi
    done <<<"${CASES}"

    # Anti-vacuity: a table that parsed NOTHING must not report clean. Zero rows
    # would otherwise make run_table return success having run no cases at all.
    if [[ "${rows}" -eq 0 ]]; then
        note_fail "${prefix}TABLE EMPTY - run_table parsed 0 rows and therefore proved nothing."
        return 1
    fi
    return "${table_rc}"
}

echo "=== rs-oracle-required.sh: the frozen case table ==="
run_table "${GATE}" "" || true

echo ""
echo "=== usage errors ==="
run_case "usage_missing_arg" "${GATE}" 2 "" "" || true
run_case "usage_lowercase" "${GATE}" 2 "" "auditctl" || true
run_case "usage_hyphenated" "${GATE}" 2 "" "SYSTEMD-SYSCTL" || true
run_case "usage_leading_digit" "${GATE}" 2 "" "8ORACLE" || true

# An explicitly empty argument is distinct from a missing one and must also be
# rejected: `bash rs-oracle-required.sh "$ORACLE"` with an unset ORACLE under
# `set -u` is the realistic way this happens in a recipe.
empty_arg_rc=0
env -i PATH="${PATH}" bash "${GATE}" "" >"${TMPROOT}/usage_empty.out" 2>&1 || empty_arg_rc=$?
if [[ "${empty_arg_rc}" -eq 2 ]]; then
    note_pass "usage_empty_arg (rc 2)"
else
    note_fail "usage_empty_arg: expected rc 2, got ${empty_arg_rc}"
fi

# A whitespace-only value must read as unset, not as the truthy string "   ".
# `VAR="$SOMETHING_UNSET "` is a realistic way a recipe produces one. This case
# cannot ride the envspec mechanism (which word-splits, destroying the spaces),
# so it is spelled out directly.
ws_rc=0
env -i PATH="${PATH}" RS_ORACLE_REQUIRED="   " bash "${GATE}" AUDITCTL \
    >"${TMPROOT}/ws_only.out" 2>&1 || ws_rc=$?
if [[ "${ws_rc}" -eq 1 ]]; then
    note_pass "global_whitespace_only (rc 1)"
else
    note_fail "global_whitespace_only: expected rc 1, got ${ws_rc}"
    sed 's/^/    | /' "${TMPROOT}/ws_only.out" || true
fi

ws_perlane_rc=0
env -i PATH="${PATH}" RS_REQUIRE_AUDITCTL=$'\t\t' bash "${GATE}" AUDITCTL \
    >"${TMPROOT}/ws_perlane.out" 2>&1 || ws_perlane_rc=$?
if [[ "${ws_perlane_rc}" -eq 1 ]]; then
    note_pass "perlane_tabs_only (rc 1)"
else
    note_fail "perlane_tabs_only: expected rc 1, got ${ws_perlane_rc}"
    sed 's/^/    | /' "${TMPROOT}/ws_perlane.out" || true
fi

# Surrounding whitespace must be TRIMMED, not treated as making the value
# truthy: " off " is still an off-switch, and " true " is still required.
padded_off_rc=0
env -i PATH="${PATH}" RS_ORACLE_REQUIRED="  off  " bash "${GATE}" AUDITCTL \
    >"${TMPROOT}/padded_off.out" 2>&1 || padded_off_rc=$?
if [[ "${padded_off_rc}" -eq 1 ]]; then
    note_pass "global_padded_off (rc 1)"
else
    note_fail "global_padded_off: expected rc 1, got ${padded_off_rc}"
    sed 's/^/    | /' "${TMPROOT}/padded_off.out" || true
fi

padded_true_rc=0
env -i PATH="${PATH}" RS_ORACLE_REQUIRED="  true  " bash "${GATE}" AUDITCTL \
    >"${TMPROOT}/padded_true.out" 2>&1 || padded_true_rc=$?
if [[ "${padded_true_rc}" -eq 0 ]]; then
    note_pass "global_padded_true (rc 0)"
else
    note_fail "global_padded_true: expected rc 0, got ${padded_true_rc}"
    sed 's/^/    | /' "${TMPROOT}/padded_true.out" || true
fi

extra_arg_rc=0
env -i PATH="${PATH}" bash "${GATE}" AUDITCTL VISUDO >"${TMPROOT}/usage_extra.out" 2>&1 || extra_arg_rc=$?
if [[ "${extra_arg_rc}" -eq 2 ]]; then
    note_pass "usage_extra_args (rc 2)"
else
    note_fail "usage_extra_args: expected rc 2, got ${extra_arg_rc}"
fi

# ---------------------------------------------------------------------------
# POSITIVE CONTROL: the case table must REJECT the known-bad fail-open script.
#
# This is the instrument proving it can see something. If the table passes a
# `== "1"` implementation, the table is decorative and every green above is
# meaningless. Run in a subshell with counters saved/restored so the control's
# own deliberate failures do not pollute the real tally.
# ---------------------------------------------------------------------------
echo ""
echo "=== positive control: a fail-OPEN implementation must be REJECTED ==="

BAD="${TMPROOT}/fail-open.sh"
cat >"${BAD}" <<'BADEOF'
#!/usr/bin/env bash
# Deliberately WRONG: the fail-open `== "1"` comparison this program already
# wrote and caught once. Exists only so the test table can prove it rejects it.
set -uo pipefail
oracle="${1-}"
[[ -z "${oracle}" ]] && exit 2
global="${RS_ORACLE_REQUIRED-}"
perlane_var="RS_REQUIRE_${oracle}"
perlane="${!perlane_var-}"
if [[ "${global}" == "1" || "${perlane}" == "1" ]]; then
    exit 0
fi
exit 1
BADEOF

saved_pass="${pass}"
saved_fail="${fail}"
saved_failures=("${failures[@]+"${failures[@]}"}")

pass=0
fail=0
failures=()
run_table "${BAD}" "control_" >"${TMPROOT}/control.log" 2>&1 || true
control_caught=("${failures[@]+"${failures[@]}"}")

pass="${saved_pass}"
fail="${saved_fail}"
failures=("${saved_failures[@]+"${saved_failures[@]}"}")

# A COUNT is not the pass condition. "Some case failed" could be satisfied for an
# incidental reason (a missing script exits 127 and fails everything), which would
# let this control report green while proving nothing about fail-OPEN detection
# specifically. Require the NAMED cases that isolate the `== "1"` bug: each is a
# truthy non-"1" value that a fail-open implementation wrongly reads as not-required.
CONTROL_MUST_CATCH=(
    "control_global_true"
    "control_global_True"
    "control_global_TRUE"
    "control_global_yes"
    "control_global_on"
    "control_global_word"
    "control_perlane_true"
)

control_missing=()
for expected_case in "${CONTROL_MUST_CATCH[@]}"; do
    found=0
    for caught in "${control_caught[@]+"${control_caught[@]}"}"; do
        if [[ "${caught}" == "${expected_case}:"* ]]; then
            found=1
            break
        fi
    done
    [[ "${found}" -eq 0 ]] && control_missing+=("${expected_case}")
done

if [[ "${#control_missing[@]}" -eq 0 ]]; then
    note_pass "positive_control (the table caught all ${#CONTROL_MUST_CATCH[@]} fail-open cases against a known-bad script)"
else
    note_fail "positive_control: the case table did NOT catch these fail-open cases against a deliberately fail-OPEN script: ${control_missing[*]}. The table cannot detect the bug it exists to detect; every other result in this run is meaningless."
    sed 's/^/    | /' "${TMPROOT}/control.log" || true
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
