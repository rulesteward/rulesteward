#!/usr/bin/env bash
#
# Positive-controlled test suite for scripts/rs-oracle-diff.sh.
#
# The driver's job is to map a mess of exit codes onto the four-value dev-tooling
# contract, and EVERY wrong branch in it fails toward "clean". A green run of the
# real recipe therefore proves nothing about the driver: it exercises one path.
# So the driver is run here against a stubbed cargo, a stubbed docker and a
# stubbed test binary, once per interesting outcome.
#
# The suite ends with a positive control that seeds the single most dangerous bug
# back into a COPY of the driver (removing the sentinel guard) and asserts that a
# NAMED case catches it. Without that, this file could pass while testing nothing,
# which is the exact failure class the whole session exists to eliminate.
#
# Usage: bash scripts/rs-oracle-diff-test.sh
# Exit:  0 all cases pass, 1 a case failed, 2 the suite could not run.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)" || exit 2
DRIVER="${REPO_ROOT}/scripts/rs-oracle-diff.sh"
REQUIRED_SH="${REPO_ROOT}/scripts/rs-oracle-required.sh"

[ -f "${DRIVER}" ] || {
    echo "SUITE ERROR: ${DRIVER} not found" >&2
    exit 2
}
[ -f "${REQUIRED_SH}" ] || {
    echo "SUITE ERROR: ${REQUIRED_SH} not found" >&2
    exit 2
}

SANDBOX_BASE="$(mktemp -d "${TMPDIR:-/tmp}/rs-oracle-diff-test-XXXXXX")" || exit 2
trap 'rm -rf "${SANDBOX_BASE}"' EXIT

PASS=0
FAIL=0
FAILED_CASES=()

# ---------------------------------------------------------------------------
# Sandbox construction.
#
# Builds a fake repo root containing the driver under test, the real
# rs-oracle-required.sh (its fail-closed parsing is part of what we exercise), a
# lane capture script, and a PATH directory holding stub cargo/docker binaries.
# ---------------------------------------------------------------------------
make_sandbox() {
    local driver_src="$1"
    local hide_docker="${2:-0}"
    local box
    box="$(mktemp -d "${SANDBOX_BASE}/box-XXXXXX")" || return 2

    mkdir -p "${box}/scripts" "${box}/bin" "${box}/sysbin" "${box}/tmp" \
        "${box}/crates/rulesteward-auditd/tests/corpus/auditd-oracle"
    cp "${driver_src}" "${box}/scripts/rs-oracle-diff.sh"
    cp "${REQUIRED_SH}" "${box}/scripts/rs-oracle-required.sh"

    # A curated system PATH rather than /usr/bin, for two reasons: the
    # `no_docker_skips` case must be able to make docker genuinely absent (this
    # machine has a real one in /usr/bin), and a hermetic PATH stops the suite
    # from passing or failing for reasons outside the sandbox.
    local tool
    for tool in mktemp mkdir rm tail grep cut env bash dirname cat; do
        local resolved
        resolved="$(command -v "${tool}")" || {
            echo "SUITE ERROR: required tool '${tool}' not found" >&2
            return 2
        }
        ln -s "${resolved}" "${box}/sysbin/${tool}"
    done

    # Stub cargo. Honours STUB_CARGO_RC, and emits a cargo-JSON artifact line
    # naming the stub test binary when asked for --message-format=json.
    cat >"${box}/bin/cargo" <<'STUB'
#!/usr/bin/env bash
for a in "$@"; do
    if [ "$a" = "--message-format=json" ]; then
        # A non-test artifact carries "executable":null and must be ignored; a
        # build-script artifact must be filtered by name. Both are emitted here
        # so the driver's filtering is genuinely exercised.
        printf '{"reason":"compiler-artifact","executable":null}\n'
        printf '{"reason":"compiler-artifact","executable":"/nonexistent/build-script-build"}\n'
        printf '{"reason":"compiler-artifact","executable":"%s"}\n' "${STUB_TEST_BIN}"
        [ -n "${STUB_CARGO_EXTRA_EXE:-}" ] && \
            printf '{"reason":"compiler-artifact","executable":"%s"}\n' "${STUB_CARGO_EXTRA_EXE}"
        exit "${STUB_CARGO_JSON_RC:-0}"
    fi
done
[ -n "${STUB_CARGO_MSG:-}" ] && echo "${STUB_CARGO_MSG}" >&2
exit "${STUB_CARGO_RC:-0}"
STUB

    # Stub docker. `image inspect` honours STUB_DOCKER_INSPECT_RC. Omitted
    # entirely when the case wants docker to be absent.
    if [ "${hide_docker}" != "1" ]; then
        cat >"${box}/bin/docker" <<'STUB'
#!/usr/bin/env bash
if [ "${1-}" = "image" ] && [ "${2-}" = "inspect" ]; then
    exit "${STUB_DOCKER_INSPECT_RC:-0}"
fi
exit 0
STUB
        chmod +x "${box}/bin/docker"
    fi

    # Stub capture script: creates one file so the corpus dir is non-empty.
    #
    # Two knobs model the real "reported success, produced nothing" failure:
    # STUB_CAPTURE_WRITES_NOTHING leaves the directory bare, and
    # STUB_CAPTURE_ONLY_DIRS leaves a tree of subdirectories with no regular file
    # in it - the subtler shape a mere "is the directory non-empty" check misses.
    cat >"${box}/crates/rulesteward-auditd/tests/corpus/auditd-oracle/capture_auditd.sh" <<'STUB'
#!/usr/bin/env bash
out="${1-}"
[ -n "${out}" ] || exit 2
rc="${STUB_CAPTURE_RC:-0}"
if [ "${rc}" -eq 0 ] &&
    [ "${STUB_CAPTURE_WRITES_NOTHING:-0}" != "1" ] &&
    [ "${STUB_CAPTURE_ONLY_DIRS:-0}" != "1" ]; then
    : >"${out}/captured.tsv"
fi
if [ "${STUB_CAPTURE_ONLY_DIRS:-0}" = "1" ]; then
    mkdir -p "${out}/scenario-a/nested"
fi
exit "${rc}"
STUB

    # Stub test binary. Announces mode/corpus exactly as a real replay test must,
    # via the same banner shape rulesteward_core::oracle_corpus renders.
    cat >"${box}/bin/stub-test-bin" <<'STUB'
#!/usr/bin/env bash
SENTINEL="RS-DIFF-AUDITD"
root="${RS_ORACLE_CORPUS_AUDITD:-}"
if [ -n "${root}" ] && [ "${STUB_TEST_IGNORES_ENV:-0}" != "1" ]; then
    mode="fresh"
    rc="${STUB_TEST_FRESH_RC:-0}"
    scen="${STUB_TEST_FRESH_SCENARIOS:-7}"
else
    mode="committed"
    root="/committed/corpus"
    rc="${STUB_TEST_COMMITTED_RC:-0}"
    scen="${STUB_TEST_FRESH_SCENARIOS:-7}"
fi
if [ "${mode}" = "fresh" ]; then
    suppress_banner="${STUB_TEST_NO_BANNER:-0}"
else
    suppress_banner="${STUB_TEST_NO_COMMITTED_BANNER:-0}"
fi
[ "${suppress_banner}" = "1" ] || echo "${SENTINEL}: mode=${mode} corpus=${root}"
[ "${STUB_TEST_NO_COUNT:-0}" = "1" ] || echo "${SENTINEL}: scenarios=${scen}"
[ "${STUB_TEST_ORACLE_BROKEN:-0}" = "1" ] && \
    echo "${SENTINEL}: ORACLE-BROKEN accept and reject controls returned the same verdict"
exit "${rc}"
STUB

    chmod +x "${box}/bin/cargo" "${box}/bin/stub-test-bin" \
        "${box}/crates/rulesteward-auditd/tests/corpus/auditd-oracle/capture_auditd.sh"
    printf '%s' "${box}"
}

# run_case <name> <expected_rc> <expected_substring|-> [VAR=VAL ...]
#
# Runs the driver for lane `auditd` inside a fresh sandbox with the given stub
# knobs, and asserts BOTH the exit code and (unless `-`) a substring of output.
# The substring matters: several distinct defects all produce rc 2, and a case
# that only checked the number would pass for the wrong reason.
run_case() {
    local name="$1" want_rc="$2" want_sub="$3"
    shift 3

    # A case asks for docker to be absent by passing STUB_HIDE_DOCKER=1; that is
    # a property of the sandbox, not of the environment, so it is read here.
    local hide=0 kv
    for kv in "$@"; do
        [ "${kv}" = "STUB_HIDE_DOCKER=1" ] && hide=1
    done

    local box
    box="$(make_sandbox "${DRIVER_UNDER_TEST}" "${hide}")" || {
        echo "SUITE ERROR: sandbox creation failed" >&2
        exit 2
    }

    local out rc
    out="$(
        env -i \
            PATH="${box}/bin:${box}/sysbin" \
            TMPDIR="${box}/tmp" \
            STUB_TEST_BIN="${box}/bin/stub-test-bin" \
            "$@" \
            bash "${box}/scripts/rs-oracle-diff.sh" auditd 2>&1
    )"
    rc=$?

    local ok=1
    [ "${rc}" -eq "${want_rc}" ] || ok=0
    if [ "${want_sub}" != "-" ] && [[ "${out}" != *"${want_sub}"* ]]; then
        ok=0
    fi

    if [ "${ok}" -eq 1 ]; then
        PASS=$((PASS + 1))
    else
        FAIL=$((FAIL + 1))
        FAILED_CASES+=("${name}")
        printf 'FAIL %s: want rc=%s sub=%q; got rc=%s\n' \
            "${name}" "${want_rc}" "${want_sub}" "${rc}" >&2
        printf '     output: %s\n' "${out}" >&2
    fi
}

# run_argcase <name> <expected_rc> <expected_substring> [args...]
# For the argument-validation cases, which take a lane other than `auditd`.
run_argcase() {
    local name="$1" want_rc="$2" want_sub="$3"
    shift 3

    local box
    box="$(make_sandbox "${DRIVER_UNDER_TEST}" 0)" || exit 2

    local out rc
    out="$(env -i PATH="${box}/bin:${box}/sysbin" TMPDIR="${box}/tmp" \
        bash "${box}/scripts/rs-oracle-diff.sh" "$@" 2>&1)"
    rc=$?

    if [ "${rc}" -eq "${want_rc}" ] && [[ "${out}" == *"${want_sub}"* ]]; then
        PASS=$((PASS + 1))
    else
        FAIL=$((FAIL + 1))
        FAILED_CASES+=("${name}")
        printf 'FAIL %s: want rc=%s sub=%q; got rc=%s\n' \
            "${name}" "${want_rc}" "${want_sub}" "${rc}" >&2
        printf '     output: %s\n' "${out}" >&2
    fi
}

run_all_cases() {
    # --- argument validation -------------------------------------------------
    run_argcase no_lane 2 "no lane given"
    run_argcase unknown_lane 2 "unknown lane 'fapolicyd'" fapolicyd

    # --- the happy path ------------------------------------------------------
    run_case clean_run 0 "OK (0 drift, 7 scenarios)"

    # --- drift is rc 1, and ONLY from a libtest failure in the fresh run ------
    run_case drift 1 "DRIFT (7 scenarios compared)" STUB_TEST_FRESH_RC=101

    # --- THE guard: a variable-name typo makes the fresh run replay the -------
    #     committed corpus. Exit code 0, count 7, controls fine: only the
    #     banner's corpus path can reveal it.
    run_case env_var_typo_caught 2 "did not read the freshly captured corpus" \
        STUB_TEST_IGNORES_ENV=1
    run_case no_banner_at_all 2 "did not read the freshly captured corpus" \
        STUB_TEST_NO_BANNER=1
    # The baseline has its own banner guard, and it is the one that proves the
    # binary cargo handed us is the test this recipe believes it is running.
    run_case no_committed_banner 2 "the test is not the one this recipe thinks it is" \
        STUB_TEST_NO_COMMITTED_BANNER=1

    # --- vacuity -------------------------------------------------------------
    run_case zero_scenarios 2 "'nothing fired' and 'nothing ran' are not the same" \
        STUB_TEST_FRESH_SCENARIOS=0
    run_case missing_count_line 2 "printed no 'RS-DIFF-AUDITD: scenarios=' line" \
        STUB_TEST_NO_COUNT=1
    run_case unparseable_count 2 "unparseable scenario count" \
        STUB_TEST_FRESH_SCENARIOS=many

    # A capture that exits 0 having written nothing must be rc 2, not rc 1. The
    # stub test binary is indifferent to the corpus contents, so with the guard
    # removed these two report `OK (0 drift, 7 scenarios)`: a clean verdict from
    # a run that compared nothing. Only the driver inspecting the directory it
    # just handed the test can tell the difference.
    run_case capture_wrote_nothing 2 "exited 0 but wrote no files under" \
        STUB_CAPTURE_WRITES_NOTHING=1
    run_case capture_wrote_only_empty_dirs 2 "exited 0 but wrote no files under" \
        STUB_CAPTURE_ONLY_DIRS=1

    # --- a broken oracle is neither clean nor drift --------------------------
    run_case oracle_broken_beats_clean 2 "the oracle itself is broken" \
        STUB_TEST_ORACLE_BROKEN=1
    run_case oracle_broken_beats_drift 2 "the oracle itself is broken" \
        STUB_TEST_ORACLE_BROKEN=1 STUB_TEST_FRESH_RC=101

    # --- build errors are rc 2, never drift ----------------------------------
    # cargo exits 101 for a compile error AND for a missing --test target, the
    # same code libtest uses for a failed assertion. Reporting that as drift is
    # the mistake the --no-run phase exists to make impossible.
    run_case build_failure_is_not_drift 2 "this is a build error, not oracle drift" \
        STUB_CARGO_RC=101
    run_case json_phase_failure 2 "--message-format=json exited" STUB_CARGO_JSON_RC=1
    run_case ambiguous_executables 2 "expected exactly 1 test binary" \
        STUB_CARGO_EXTRA_EXE=/bin/true

    # --- a red committed corpus cannot yield an attributable drift verdict ----
    run_case red_committed_corpus 2 "fix 'just test' before reading a drift result" \
        STUB_TEST_COMMITTED_RC=101

    # --- legitimate skips, and the CI promotion of those same conditions ------
    run_case no_docker_skips 3 "SKIP - docker is not on PATH" STUB_HIDE_DOCKER=1
    run_case images_absent_skips 3 "SKIP - images rs-oracle8" STUB_DOCKER_INSPECT_RC=1
    run_case capture_precondition_skips 3 "unmet precondition (rc 3)" STUB_CAPTURE_RC=3
    run_case capture_tool_error 2 "capture script" STUB_CAPTURE_RC=2

    run_case images_absent_required_fails 2 "declared REQUIRED" \
        STUB_DOCKER_INSPECT_RC=1 RS_ORACLE_REQUIRED=1
    # Fail-closed word forms: `true` / `yes` must count as required. Comparing
    # against the literal "1" is the fail-OPEN bug this project already shipped
    # and caught once, so the interior points are pinned here too.
    run_case required_word_true 2 "declared REQUIRED" \
        STUB_DOCKER_INSPECT_RC=1 RS_REQUIRE_AUDITCTL=true
    run_case required_word_yes 2 "declared REQUIRED" \
        STUB_DOCKER_INSPECT_RC=1 RS_REQUIRE_AUDITCTL=yes
    run_case required_off_still_skips 3 "SKIP - images rs-oracle8" \
        STUB_DOCKER_INSPECT_RC=1 RS_ORACLE_REQUIRED=off
    run_case capture_precondition_required_fails 2 "declared REQUIRED" \
        STUB_CAPTURE_RC=3 RS_ORACLE_REQUIRED=1
}

# ---------------------------------------------------------------------------
# Pass 1: the real driver.
# ---------------------------------------------------------------------------
DRIVER_UNDER_TEST="${DRIVER}"
run_all_cases

if [ "${FAIL}" -ne 0 ]; then
    printf '\nrs-oracle-diff-test: %d passed, %d FAILED (%s)\n' \
        "${PASS}" "${FAIL}" "${FAILED_CASES[*]}" >&2
    exit 1
fi

# A suite that parsed nothing must not report clean.
if [ "${PASS}" -eq 0 ]; then
    echo "SUITE ERROR: zero cases ran; the case table is empty or unreachable" >&2
    exit 2
fi
BASELINE_PASS="${PASS}"

# ---------------------------------------------------------------------------
# Pass 2: the positive controls.
#
# Each control seeds ONE real defect back into a COPY of the driver and requires
# that NAMED cases catch it. Asserting merely that "some case failed" would be
# satisfied by a typo in the sandbox builder, which is the
# count-as-the-pass-condition mistake this project has already made once.
#
# One control per guard, rather than one copy with every guard removed: a single
# multiply-broken driver could have one case failing for another guard's reason,
# and the suite would still call the control satisfied.
#
# run_positive_control <label> <sed-expression> <must-catch-case>...
# ---------------------------------------------------------------------------
run_positive_control() {
    local label="$1" sed_expr="$2"
    shift 2
    local must_catch=("$@")

    local broken="${SANDBOX_BASE}/rs-oracle-diff-FAIL-OPEN-${label}.sh"
    sed "${sed_expr}" "${DRIVER}" >"${broken}"
    if cmp -s "${DRIVER}" "${broken}"; then
        echo "SUITE ERROR: positive control '${label}' edited nothing; its guard's source line moved" >&2
        exit 2
    fi

    PASS=0
    FAIL=0
    FAILED_CASES=()
    DRIVER_UNDER_TEST="${broken}"
    run_all_cases

    local missed=() want got found
    for want in "${must_catch[@]}"; do
        found=0
        for got in "${FAILED_CASES[@]+"${FAILED_CASES[@]}"}"; do
            [ "${got}" = "${want}" ] && found=1
        done
        [ "${found}" -eq 1 ] || missed+=("${want}")
    done

    if [ "${#missed[@]}" -ne 0 ]; then
        printf 'SUITE ERROR: positive control %s did not catch: %s\n' "${label}" "${missed[*]}" >&2
        printf '             a fail-open driver passed these cases, so a green result\n' >&2
        printf '             from this suite proves nothing.\n' >&2
        exit 2
    fi
    printf '  control %-28s caught %s\n' "${label}" "${must_catch[*]}"
}

printf 'rs-oracle-diff-test: %d cases passed against the real driver.\n' "${BASELINE_PASS}"

# Both sed patterns below are matched against the DRIVER'S SOURCE, where the
# shell variable names appear unexpanded, so they must stay single-quoted.
# Double-quoting would expand them in THIS shell and the pattern would match
# nothing - which the `cmp` check inside run_positive_control then catches.
# shellcheck disable=SC2016
run_positive_control sentinel-guard-removed \
    's|^if ! grep -qF "${SENTINEL}: mode=fresh corpus=${FRESH}" "${LOG_FRESH}"; then|if false; then|' \
    env_var_typo_caught no_banner_at_all

# shellcheck disable=SC2016
run_positive_control empty-capture-guard-removed \
    's|^if \[ "${#FRESH_FILES\[@\]}" -eq 0 \]; then|if false; then|' \
    capture_wrote_nothing capture_wrote_only_empty_dirs

exit 0
