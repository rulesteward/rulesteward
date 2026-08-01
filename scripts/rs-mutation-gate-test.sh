#!/usr/bin/env bash
#
# Positive-controlled test suite for scripts/rs-mutation-gate.sh.
#
# The gate's whole job is to refuse a VACUOUS green: a cargo-mutants run that
# mutated nothing exits 0 and prints "0 survivors", which is byte-identical to a
# real pass. Every guard in the gate therefore fails toward "clean" if it is
# wrong, and a green run of the real recipe proves nothing about the guards --
# it exercises one path, the one where everything already worked.
#
# So the gate is run here against a stubbed cargo and a stubbed rtk, once per
# interesting outcome, in a hermetic sandbox with a curated PATH.
#
# The suite ends with positive controls that seed each guard's removal back into
# a COPY of the gate and require that NAMED cases catch it. Without that, this
# file could pass while testing nothing, which is the exact failure class the
# gate itself exists to eliminate.
#
# Usage: bash scripts/rs-mutation-gate-test.sh
# Exit:  0 all cases pass, 1 a case failed, 2 the suite could not run.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)" || exit 2
GATE="${REPO_ROOT}/scripts/rs-mutation-gate.sh"

[ -f "${GATE}" ] || {
    echo "SUITE ERROR: ${GATE} not found" >&2
    exit 2
}

SANDBOX_BASE="$(mktemp -d "${TMPDIR:-/tmp}/rs-mutation-gate-test-XXXXXX")" || exit 2
trap 'rm -rf "${SANDBOX_BASE}"' EXIT

PASS=0
FAIL=0
FAILED_CASES=()

# ---------------------------------------------------------------------------
# Sandbox construction.
#
# Builds a box holding the gate under test, a fake worktree, and a PATH
# directory with stub cargo/rtk binaries. The system PATH is curated rather
# than inherited so the suite cannot pass or fail for reasons outside the box.
# ---------------------------------------------------------------------------
make_sandbox() {
    local gate_src="$1"
    local box
    box="$(mktemp -d "${SANDBOX_BASE}/box-XXXXXX")" || return 2

    mkdir -p "${box}/scripts" "${box}/bin" "${box}/sysbin" "${box}/tmp" "${box}/wt"
    cp "${gate_src}" "${box}/scripts/rs-mutation-gate.sh"

    local tool resolved
    for tool in mkdir rm grep sed wc cat head tail env bash dirname cd true; do
        resolved="$(command -v "${tool}")" || continue
        ln -s "${resolved}" "${box}/sysbin/${tool}" 2>/dev/null || true
    done

    # Stub rtk. The gate uses exactly one form: `rtk proxy git diff <a> <b>`.
    # STUB_DIFF_KIND selects the shape of the diff it emits.
    cat >"${box}/bin/rtk" <<'STUB'
#!/usr/bin/env bash
[ "${1:-}" = "proxy" ] || exit 0
case "${STUB_DIFF_KIND:-rust}" in
  rust)
    printf 'diff --git a/crates/x/src/parser.rs b/crates/x/src/parser.rs\n'
    printf -- '--- a/crates/x/src/parser.rs\n'
    printf -- '+++ b/crates/x/src/parser.rs\n'
    printf '@@ -1 +1 @@\n-old\n+new\n'
    ;;
  norust)
    printf 'diff --git a/docs/notes.md b/docs/notes.md\n'
    printf -- '--- a/docs/notes.md\n'
    printf -- '+++ b/docs/notes.md\n'
    printf '@@ -1 +1 @@\n-old\n+new\n'
    ;;
  mangled)
    # What the rtk compacting filter emits in place of a real diff: a summary
    # with no `diff --git` and no `+++ b/` lines. cargo-mutants fed this says
    # "Diff changes no Rust source files" and exits 0. That is 3c-trustdb's
    # measured false pass, re-seeded here.
    printf ' crates/x/src/parser.rs | 2 +-\n'
    printf ' 1 file changed, 1 insertion(+), 1 deletion(-)\n'
    ;;
  empty) : ;;
esac
exit 0
STUB

    # Stub cargo. The gate uses exactly one form: `cargo mutants ...`.
    # STUB_MUTANTS_KIND selects which outcome files appear; STUB_CARGO_RC is
    # the exit code cargo-mutants itself would return.
    cat >"${box}/bin/cargo" <<'STUB'
#!/usr/bin/env bash
MO="${STUB_WT}/mutants.out"
mkdir -p "${MO}"
: >"${MO}/caught.txt"; : >"${MO}/missed.txt"
: >"${MO}/timeout.txt"; : >"${MO}/unviable.txt"
case "${STUB_MUTANTS_KIND:-clean}" in
  clean)
    echo 'crates/x/src/parser.rs:10:5: replace foo -> bar' >"${MO}/caught.txt"
    ;;
  none)
    # A run that mutated NOTHING. cargo-mutants exits 0 and this is
    # indistinguishable from a real pass without a guard.
    :
    ;;
  otherfile)
    # Mutants were generated, but not for the file the diff changed. The
    # denominator is non-zero, so vacuity guard 1 is satisfied and only a
    # per-file check can catch it.
    echo 'crates/y/src/other.rs:3:1: replace a -> b' >"${MO}/caught.txt"
    ;;
  survivor)
    echo 'crates/x/src/parser.rs:10:5: replace foo -> bar' >"${MO}/caught.txt"
    echo 'crates/x/src/parser.rs:22:9: replace baz -> qux' >"${MO}/missed.txt"
    ;;
  nodir)
    rm -rf "${MO}"
    ;;
esac
exit "${STUB_CARGO_RC:-0}"
STUB

    chmod +x "${box}/bin/rtk" "${box}/bin/cargo"
    printf '%s\n' "${box}"
}

# run_case <name> <expected_rc> <expected_substring|-> [ENV=VAL...]
#
# Asserts BOTH the exit code and (unless `-`) a substring of the output. The
# substring matters: four distinct defects all produce rc 2, and a case that
# only checked the number would pass for the wrong reason.
run_case() {
    local name="$1" want_rc="$2" want_sub="$3"
    shift 3

    local box
    box="$(make_sandbox "${GATE_UNDER_TEST}")" || {
        echo "SUITE ERROR: sandbox creation failed" >&2
        exit 2
    }

    # A distinct crate name per case, because the gate derives its scratch dir
    # from the crate name and concurrent cases must not share it.
    local crate="stubcrate-${name}"

    local out rc
    out="$(
        env -i \
            PATH="${box}/bin:${box}/sysbin" \
            TMPDIR="${box}/tmp" \
            HOME="${box}" \
            STUB_WT="${box}/wt" \
            "$@" \
            bash "${box}/scripts/rs-mutation-gate.sh" \
            "${box}/wt" "${crate}" BASESHA IMPLSHA 2>&1
    )"
    rc=$?

    local ok=1
    [ "${rc}" -eq "${want_rc}" ] || ok=0
    if [ "${want_sub}" != "-" ] && [[ "${out}" != *"${want_sub}"* ]]; then
        ok=0
    fi

    if [ "${ok}" -eq 1 ]; then
        PASS=$((PASS + 1))
        printf 'ok   %s (rc=%s)\n' "${name}" "${rc}"
    else
        FAIL=$((FAIL + 1))
        FAILED_CASES+=("${name}")
        printf 'FAIL %s: want rc=%s sub=%q; got rc=%s\n' \
            "${name}" "${want_rc}" "${want_sub}" "${rc}" >&2
        printf '     output: %s\n' "${out}" >&2
    fi
}

# ---------------------------------------------------------------------------
# The case table.
#
# case0 is the NEGATIVE control and is not optional: without a case that must
# return 0, a gate that exited 2 unconditionally would satisfy every other case
# here and the suite would call it green.
# ---------------------------------------------------------------------------
run_all_cases() {
    run_case case0_clean_run_exits_0 0 'GATE-RESULT' \
        STUB_DIFF_KIND=rust STUB_MUTANTS_KIND=clean STUB_CARGO_RC=0

    run_case case1_diff_with_no_rust_hunks_exits_2 2 'no Rust hunks' \
        STUB_DIFF_KIND=norust STUB_MUTANTS_KIND=clean STUB_CARGO_RC=0

    run_case case2_zero_total_mutants_exits_2 2 'VACUOUS' \
        STUB_DIFF_KIND=rust STUB_MUTANTS_KIND=none STUB_CARGO_RC=0

    run_case case3_target_file_absent_from_caught_and_missed_exits_2 2 'not among the mutated' \
        STUB_DIFF_KIND=rust STUB_MUTANTS_KIND=otherfile STUB_CARGO_RC=0

    run_case case4_survivor_exits_nonzero 1 'GATE-RESULT' \
        STUB_DIFF_KIND=rust STUB_MUTANTS_KIND=survivor STUB_CARGO_RC=1

    run_case case5_rtk_mangled_diff_is_rejected 2 'no Rust hunks' \
        STUB_DIFF_KIND=mangled STUB_MUTANTS_KIND=clean STUB_CARGO_RC=0

    run_case case6_missing_mutants_out_exits_2 2 'no mutants.out' \
        STUB_DIFF_KIND=rust STUB_MUTANTS_KIND=nodir STUB_CARGO_RC=0

    run_case case7_scratch_honours_tmpdir 0 '-' \
        STUB_DIFF_KIND=rust STUB_MUTANTS_KIND=clean STUB_CARGO_RC=0
    assert_no_hardcoded_tmp case7_scratch_honours_tmpdir
}

# The gate must not write its scratch to a hardcoded /tmp path. The per-UID
# /tmp tmpfs QUOTA (not the filesystem) is what fills on this machine, and it
# caused 80 of one session's 146 unique errors while `df` still looked healthy.
# A gate that ignores TMPDIR is the one instrument guaranteed to be running when
# that happens.
assert_no_hardcoded_tmp() {
    local name="$1"
    local stray
    stray="$(echo /tmp/mutgate-stubcrate-"${name}" 2>/dev/null)"
    if [ -e "${stray}" ]; then
        FAIL=$((FAIL + 1))
        FAILED_CASES+=("${name}")
        printf 'FAIL %s: gate created %s, ignoring TMPDIR\n' "${name}" "${stray}" >&2
        rm -rf "${stray}"
    else
        PASS=$((PASS + 1))
        printf 'ok   %s (no hardcoded /tmp scratch)\n' "${name}"
    fi
}

# ---------------------------------------------------------------------------
# Pass 1: the real gate.
# ---------------------------------------------------------------------------
GATE_UNDER_TEST="${GATE}"
run_all_cases

if [ "${FAIL}" -ne 0 ]; then
    printf '\nrs-mutation-gate-test: %d passed, %d FAILED (%s)\n' \
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
# Each control seeds ONE real defect back into a COPY of the gate and requires
# that NAMED cases catch it. Asserting merely that "some case failed" would be
# satisfied by a typo in the sandbox builder, which is the
# count-as-the-pass-condition mistake this project has already made once.
#
# run_positive_control <label> <sed-expression> <must-catch-case>...
# ---------------------------------------------------------------------------
run_positive_control() {
    local label="$1" sed_expr="$2"
    shift 2
    local must_catch=("$@")

    local broken="${SANDBOX_BASE}/rs-mutation-gate-FAIL-OPEN-${label}.sh"
    sed "${sed_expr}" "${GATE}" >"${broken}"
    if cmp -s "${GATE}" "${broken}"; then
        echo "SUITE ERROR: positive control '${label}' edited nothing; its guard's source line moved" >&2
        exit 2
    fi

    PASS=0
    FAIL=0
    FAILED_CASES=()
    GATE_UNDER_TEST="${broken}"
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
        printf 'SUITE ERROR: positive control %q was NOT caught by: %s\n' \
            "${label}" "${missed[*]}" >&2
        exit 2
    fi
    printf 'ok   positive-control %s caught by %s\n' "${label}" "${must_catch[*]}"
}

# Each range deletes a WHOLE `if ... fi` block. Deleting only the echo and the
# `exit` inside one would leave `if cond; then` with an empty body, which is a
# bash syntax error: every case would then fail, the named ones among them, and
# the control would report itself satisfied while having proved nothing about
# the guard. The `cmp -s` above is what catches an anchor that has moved.
run_positive_control no-rust-hunks-guard \
    '/^if \[ "\$hunks" -eq 0 \]/,/^fi$/d' \
    case1_diff_with_no_rust_hunks_exits_2 case5_rtk_mangled_diff_is_rejected

run_positive_control zero-mutants-guard \
    '/^if \[ "\$((c + m + t))" -eq 0 \]/,/^fi$/d' \
    case2_zero_total_mutants_exits_2

run_positive_control changed-file-not-mutated-guard \
    '/^if \[ -n "\$unmutated" \]/,/^fi$/d' \
    case3_target_file_absent_from_caught_and_missed_exits_2

printf '\nrs-mutation-gate-test: %d cases passed, %d positive controls\n' \
    "${BASELINE_PASS}" 3
echo "RS-MUTATION-GATE TEST PASSED"
exit 0
