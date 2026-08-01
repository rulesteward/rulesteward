#!/usr/bin/env bash
#
# Positive-controlled test suite for scripts/check-doc-citations.sh.
#
# The gate reads a tree and reports violations, so its dangerous failure is the
# usual one for this family: reporting clean because it looked at nothing, or
# because a regex stopped matching. Both look exactly like a healthy tree.
#
# Every case builds a throwaway git repo (the gate reads `git ls-files`, so a
# real index is required) and runs the gate against it.
#
# Usage: bash scripts/check-doc-citations-test.sh
# Exit:  0 all cases pass, 1 a case failed, 2 the suite could not run.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)" || exit 2
GATE="${REPO_ROOT}/scripts/check-doc-citations.sh"

[ -f "${GATE}" ] || { echo "SUITE ERROR: ${GATE} not found" >&2; exit 2; }

SANDBOX_BASE="$(mktemp -d "${TMPDIR:-/tmp}/check-doc-citations-test-XXXXXX")" || exit 2
trap 'rm -rf "${SANDBOX_BASE}"' EXIT

PASS=0
FAIL=0
FAILED_CASES=()

# make_repo <name> - a git repo with a 3-line target file. Echoes its path.
make_repo() {
    local box="${SANDBOX_BASE}/$1"
    mkdir -p "${box}/crates/thing/src"
    printf 'fn a() {}\nfn b() {}\nfn c() {}\n' >"${box}/crates/thing/src/target.rs"
    git -C "${box}" init -q 2>/dev/null
    git -C "${box}" config user.email t@t
    git -C "${box}" config user.name t
    printf '%s\n' "${box}"
}

# run_case <name> <expected_rc> <expected_substring|-> <comment-line>
run_case() {
    local name="$1" want_rc="$2" want_sub="$3" comment="$4"
    local box
    box="$(make_repo "${name}")" || { echo "SUITE ERROR: repo build failed" >&2; exit 2; }
    printf '%s\nfn user() {}\n' "${comment}" >"${box}/crates/thing/src/user.rs"
    git -C "${box}" add -A >/dev/null 2>&1
    local out rc
    out="$(bash "${GATE_UNDER_TEST}" "${box}" 2>&1)"
    rc=$?
    local ok=1
    [ "${rc}" -eq "${want_rc}" ] || ok=0
    if [ "${want_sub}" != "-" ] && [[ "${out}" != *"${want_sub}"* ]]; then ok=0; fi
    if [ "${ok}" -eq 1 ]; then
        PASS=$((PASS + 1))
        printf 'ok   %s (rc=%s)\n' "${name}" "${rc}"
    else
        FAIL=$((FAIL + 1))
        FAILED_CASES+=("${name}")
        printf 'FAIL %s: want rc=%s sub=%q; got rc=%s\n     output: %s\n' \
            "${name}" "${want_rc}" "${want_sub}" "${rc}" "${out}" >&2
    fi
}

run_all_cases() {
    run_case case1_dead_file_is_violation 1 'DEAD-FILE' \
        '// see gone.rs:2 for the shape'

    run_case case2_live_citation_in_range_passes 0 'citations scanned' \
        '// see target.rs:2 for the shape'

    run_case case3_line_past_eof_is_violation 1 'OUT-OF-RANGE' \
        '// see target.rs:99 for the shape'

    run_case case4_range_upper_bound_past_eof_is_violation 1 'OUT-OF-RANGE' \
        '// see target.rs:2-99 for the shape'

    # The historical-reference hatch, which must appear BEFORE the citation.
    run_case case5_historical_prefix_exempts 0 'citations scanned' \
        '// the old gone.rs:2 did this differently'

    # The deliberate marker. It must work ANYWHERE on the line: the gate documents
    # it as "on the same line", and an implementation that only honours it before
    # the citation makes the documented escape hatch silently not work.
    run_case case6_exempt_marker_after_citation_exempts 0 'citations scanned' \
        '// see gone.rs:2 (doc-citation-exempt: file was removed in #146)'

    run_case case7_citation_outside_a_comment_is_ignored 2 'scanned 0 citations' \
        'fn f() { let s = "target.rs:99"; }'

    run_case case8_no_citations_at_all_is_vacuous 2 'scanned 0 citations' \
        '// nothing to see here'

    # The historical hatch must apply to the citation it PRECEDES, not to every
    # citation on a line that happens to contain the word somewhere. Otherwise
    # any comment mentioning the old anything silently exempts a live dead
    # citation - and this gate is destined for `just ci`, where that is a
    # permanent blind spot rather than a one-off miss.
    run_case case9_historical_word_far_from_the_citation_does_not_exempt 1 'OUT-OF-RANGE' \
        '// the old parser is gone now; see target.rs:99 for the shape'
}

GATE_UNDER_TEST="${GATE}"
run_all_cases

if [ "${FAIL}" -ne 0 ]; then
    printf '\ncheck-doc-citations-test: %d passed, %d FAILED (%s)\n' \
        "${PASS}" "${FAIL}" "${FAILED_CASES[*]}" >&2
    exit 1
fi
if [ "${PASS}" -eq 0 ]; then
    echo "SUITE ERROR: zero cases ran" >&2
    exit 2
fi
BASELINE_PASS="${PASS}"

# ---------------------------------------------------------------------------
# Positive controls: seed one real defect into a COPY and require NAMED cases to
# catch it. "Some case failed" would be satisfied by a typo in the repo builder.
# ---------------------------------------------------------------------------
run_positive_control() {
    local label="$1" sed_expr="$2"
    shift 2
    local must_catch=("$@")
    local broken="${SANDBOX_BASE}/check-doc-citations-FAIL-OPEN-${label}.sh"
    sed "${sed_expr}" "${GATE}" >"${broken}"
    if cmp -s "${GATE}" "${broken}"; then
        echo "SUITE ERROR: positive control '${label}' edited nothing; its anchor moved" >&2
        exit 2
    fi
    PASS=0; FAIL=0; FAILED_CASES=()
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

# Dead-file detection silenced: the DEAD-FILE branch stops counting a violation.
run_positive_control dead-file-detection \
    "s/^                    viol += 1; continue$/                    continue/" \
    case1_dead_file_is_violation

# The zero-citations vacuity guard removed: a tree the gate never parsed would
# then exit 0 and be indistinguishable from a clean one.
run_positive_control vacuity-guard \
    "s/^    sys.exit(2)$/    pass/" \
    case7_citation_outside_a_comment_is_ignored case8_no_citations_at_all_is_vacuous

printf '\ncheck-doc-citations-test: %d cases passed, 2 positive controls\n' "${BASELINE_PASS}"
echo "CHECK-DOC-CITATIONS TEST PASSED"
exit 0
