#!/usr/bin/env bash
#
# Positive-controlled test suite for scripts/check-corpus-growth.sh.
#
# The gate reads a COMMIT RANGE rather than a tree, which gives it two silent
# failure modes the tree-walking guards do not have: a base that resolves to the
# wrong commit produces an empty diff and therefore a clean report, and a
# per-crate coupling that is written as a global check passes on exactly the
# change it exists to catch (a sudoers parser edit "paid for" by an unrelated
# selinux corpus file). Both look like a healthy branch.
#
# Every case builds a throwaway two-crate git repo with a real BASE commit and a
# real HEAD commit, then runs the gate from inside it.
#
# Usage: bash scripts/check-corpus-growth-test.sh
# Exit:  0 all cases pass, 1 a case failed, 2 the suite could not run.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)" || exit 2
GATE="${REPO_ROOT}/scripts/check-corpus-growth.sh"

[ -f "${GATE}" ] || { echo "SUITE ERROR: ${GATE} not found" >&2; exit 2; }

SANDBOX_BASE="$(mktemp -d "${TMPDIR:-/tmp}/check-corpus-growth-test-XXXXXX")" || exit 2
trap 'rm -rf "${SANDBOX_BASE}"' EXIT

PASS=0
FAIL=0
FAILED_CASES=()
# 1 while a positive-control phase is running; see case_marker().
CONTROL_PHASE=0

# The per-case marker for a case that did NOT meet its expectation.
#
# During a positive-control phase the cases are SUPPOSED not to meet it - that is
# how the control proves the guard is load-bearing - so printing `FAIL` there
# announces SUCCESS using the word for failure (#641). `just instrument-test`
# asserts a suite exiting 0 prints no `FAIL` token, and `CAUGHT` is also the
# accurate word: the sabotaged gate was caught by this case.
case_marker() {
    if [ "${CONTROL_PHASE}" -eq 1 ]; then printf 'CAUGHT'; else printf 'FAIL'; fi
}

# Monotonic, so every make_repo call gets its OWN directory.
#
# Keying the sandbox on the case NAME instead looks fine and is not: the positive
# controls re-run `run_all_cases` with the same case names, so the second run
# would `git commit` on top of the history the FIRST run built. A corpus file the
# baseline phase added is then already present at the control phase's base, so
# re-writing it is a modify rather than an add, and every case looks as though its
# corpus never grew. That is invisible in the baseline phase (which runs first,
# against clean directories) and it silently disarmed the per-crate coupling
# control, which is a control that exists precisely to catch a gate that stopped
# distinguishing crates.
REPO_SEQ=0

# make_repo <name> [--no-corpus]
# A git repo with two crates, `alpha` and `beta`, each with a src file and a
# seeded corpus, committed as the BASE. Sets the global BOX to its path.
#
# It sets a GLOBAL rather than echoing a path the caller captures, because
# `box="$(make_repo c1)"` would run this whole function in a SUBSHELL: `REPO_SEQ`
# would increment and be discarded, every call would land on `-1`, and - far
# worse - the `exit 2` below would leave only the subshell. The first cut of this
# suite did exactly that and printed 27 `SUITE ERROR` lines while still exiting 0
# with `TEST PASSED`. A suite error that cannot fail the suite is the
# suppression-looks-like-success shape these instruments exist to refuse.
#
# The corpus seed matters: the gate's in-scope set is "crates whose corpus was
# non-empty AT THE BASE COMMIT", so a repo with no seeded corpus has an EMPTY
# in-scope set and must be a tool error rather than a pass.
make_repo() {
    REPO_SEQ=$((REPO_SEQ + 1))
    BOX="${SANDBOX_BASE}/$1-${REPO_SEQ}"
    local box="${BOX}" seed_corpus=1
    [ "${2:-}" = "--no-corpus" ] && seed_corpus=0
    # Fail closed on the fixture-reuse trap above rather than silently inheriting
    # another phase's commits.
    if [ -e "${box}" ]; then
        echo "SUITE ERROR: ${box} already exists; a reused fixture would inherit its commits" >&2
        exit 2
    fi
    mkdir -p "${box}/crates/alpha/src" "${box}/crates/beta/src"
    printf 'fn a() {}\n' >"${box}/crates/alpha/src/parser.rs"
    printf 'fn b() {}\n' >"${box}/crates/beta/src/lib.rs"
    if [ "${seed_corpus}" -eq 1 ]; then
        mkdir -p "${box}/crates/alpha/tests/corpus" "${box}/crates/beta/tests/corpus"
        printf 'seed\n' >"${box}/crates/alpha/tests/corpus/seed-0.txt"
        printf 'seed\n' >"${box}/crates/beta/tests/corpus/seed-0.txt"
    fi
    git -C "${box}" init -q 2>/dev/null
    git -C "${box}" config user.email t@t
    git -C "${box}" config user.name t
    git -C "${box}" add -A >/dev/null 2>&1
    git -C "${box}" commit -q -m "base" >/dev/null 2>&1

}

# commit_head <box> <subject-and-body>
commit_head() {
    local box="$1" msg="$2"
    git -C "${box}" add -A >/dev/null 2>&1
    git -C "${box}" commit -q -m "${msg}" >/dev/null 2>&1
}

# run_case <name> <expected_rc> <expected_substring|-> <base-ref> <box>
# The repo is built and mutated by the CALLER, because each case needs a
# different shape of change; this helper only runs the gate and scores it.
run_case() {
    local name="$1" want_rc="$2" want_sub="$3" base="$4" box="$5"
    local out rc
    out="$(cd "${box}" && bash "${GATE_UNDER_TEST}" "${base}" 2>&1)"
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
        printf '%s %s: want rc=%s sub=%q; got rc=%s\n     output: %s\n' \
            "$(case_marker)" "${name}" "${want_rc}" "${want_sub}" "${rc}" "${out}" >&2
    fi
}

run_all_cases() {
    local box

    # The shape a healthy branch has: parser churn paid for with new evidence in
    # the SAME crate's corpus.
    make_repo c1; box="${BOX}"
    printf 'fn a() { }\n' >"${box}/crates/alpha/src/parser.rs"
    printf 'new\n' >"${box}/crates/alpha/tests/corpus/case-1.txt"
    commit_head "${box}" "fix(alpha): a thing"
    run_case case1_src_change_with_same_crate_corpus_add_passes 0 '0 violations' HEAD~1 "${box}"

    # The session-9o shape: five rounds of parser churn, zero corpus growth.
    make_repo c2; box="${BOX}"
    printf 'fn a() { }\n' >"${box}/crates/alpha/src/parser.rs"
    commit_head "${box}" "fix(alpha): a thing"
    run_case case2_src_change_without_corpus_add_is_violation 1 'crates/alpha' HEAD~1 "${box}"

    # THE VACUITY HOLE this design closes. A global "was any corpus file added"
    # check passes here, because beta's corpus grew. Alpha's did not, and alpha
    # is what changed.
    make_repo c3; box="${BOX}"
    printf 'fn a() { }\n' >"${box}/crates/alpha/src/parser.rs"
    printf 'new\n' >"${box}/crates/beta/tests/corpus/case-1.txt"
    commit_head "${box}" "fix(alpha): a thing"
    run_case case3_cross_crate_corpus_add_does_not_pay_for_it 1 'crates/alpha' HEAD~1 "${box}"

    # A range that proposes no src change at all is legitimately clean. It is NOT
    # the same as a range that could not be computed, which is rc 2.
    make_repo c4; box="${BOX}"
    printf 'doc\n' >"${box}/README.md"
    commit_head "${box}" "docs: a thing"
    run_case case4_no_src_change_is_clean 0 '0 violations' HEAD~1 "${box}"

    # The escape hatch, which lives in a COMMIT BODY because that is the only
    # place a reviewer sees it alongside the change it excuses.
    make_repo c5; box="${BOX}"
    printf 'fn a() { }\n' >"${box}/crates/alpha/src/parser.rs"
    commit_head "${box}" "$(printf 'refactor(alpha): rename only\n\n# skip-corpus: pure rename, no semantic surface\n')"
    run_case case5_skip_corpus_marker_in_commit_body_exempts 0 'skip-corpus' HEAD~1 "${box}"

    # The marker must not match its own DOCUMENTATION. This gate's very first run
    # against the real repo SKIPPED, because the commit body introducing it
    # describes the hatch as `# skip-corpus: <reason>` and the substring test read
    # that description as an invocation. Same self-reference trap
    # check-no-mnt-paths.sh records hitting on ITS first run. The sandbox could not
    # have found this; running the gate against the real repo did.
    make_repo c5b; box="${BOX}"
    printf 'fn a() { }\n' >"${box}/crates/alpha/src/parser.rs"
    commit_head "${box}" "$(printf 'docs: describe the gate\n\nIts `# skip-corpus: <reason>` escape lives in a commit body.\n')"
    run_case case5b_an_inline_mention_of_the_marker_does_not_skip 1 'crates/alpha' HEAD~1 "${box}"

    # A base that does not resolve is a TOOL ERROR. Reported as clean it would be
    # the worst failure this gate has, because an empty diff has no violations.
    make_repo c6; box="${BOX}"
    printf 'fn a() { }\n' >"${box}/crates/alpha/src/parser.rs"
    commit_head "${box}" "fix(alpha): a thing"
    run_case case6_unresolvable_base_is_tool_error 2 'cannot resolve' deadbeefdeadbeef "${box}"

    # No crate has a corpus at the base, so the in-scope set is EMPTY and the gate
    # checked nothing. "0 violations" from a gate that examined 0 crates is the
    # vacuous pass the whole instrument family exists to refuse.
    make_repo c7 --no-corpus; box="${BOX}"
    printf 'fn a() { }\n' >"${box}/crates/alpha/src/parser.rs"
    commit_head "${box}" "fix(alpha): a thing"
    run_case case7_empty_in_scope_set_is_tool_error 2 'in scope' HEAD~1 "${box}"

    # Growth means NEW evidence. Editing an existing corpus file is how a branch
    # can appear to add coverage while replacing it, which is exactly what a
    # re-rolled adversarial corpus does.
    make_repo c8; box="${BOX}"
    printf 'fn a() { }\n' >"${box}/crates/alpha/src/parser.rs"
    printf 'edited\n' >"${box}/crates/alpha/tests/corpus/seed-0.txt"
    commit_head "${box}" "fix(alpha): a thing"
    run_case case8_modifying_a_corpus_file_is_not_growth 1 'crates/alpha' HEAD~1 "${box}"

    # Both crates changed, only one paid. The report must name the unpaid one and
    # not be satisfied by the paid one.
    make_repo c9; box="${BOX}"
    printf 'fn a() { }\n' >"${box}/crates/alpha/src/parser.rs"
    printf 'fn b() { }\n' >"${box}/crates/beta/src/lib.rs"
    printf 'new\n' >"${box}/crates/alpha/tests/corpus/case-1.txt"
    commit_head "${box}" "fix: two crates"
    run_case case9_partial_payment_still_names_the_unpaid_crate 1 'crates/beta' HEAD~1 "${box}"
}

GATE_UNDER_TEST="${GATE}"
run_all_cases

if [ "${FAIL}" -ne 0 ]; then
    printf '\ncheck-corpus-growth-test: %d passed, %d FAILED (%s)\n' \
        "${PASS}" "${FAIL}" "${FAILED_CASES[*]}" >&2
    exit 1
fi
if [ "${PASS}" -eq 0 ]; then
    echo "SUITE ERROR: zero cases ran" >&2
    exit 2
fi
BASELINE_PASS="${PASS}"

# ---------------------------------------------------------------------------
# Positive controls: seed one real defect into a COPY of the gate and require
# NAMED cases to catch it. "Some case failed" would be satisfied by a typo in the
# repo builder.
# ---------------------------------------------------------------------------
run_positive_control() {
    local label="$1" sed_expr="$2"
    shift 2
    local must_catch=("$@")
    local broken="${SANDBOX_BASE}/check-corpus-growth-FAIL-OPEN-${label}.sh"
    sed "${sed_expr}" "${GATE}" >"${broken}"
    if cmp -s "${GATE}" "${broken}"; then
        echo "SUITE ERROR: positive control '${label}' edited nothing; its anchor moved" >&2
        exit 2
    fi
    PASS=0; FAIL=0; FAILED_CASES=()
    GATE_UNDER_TEST="${broken}"
    CONTROL_PHASE=1
    run_all_cases
    CONTROL_PHASE=0
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

# The violation counter silenced: the gate still walks every crate and still
# prints its summary, but never counts. This is the shape a gate rots into.
run_positive_control violation-counting \
    's/^    violations=\$((violations + 1))$/    :/' \
    case2_src_change_without_corpus_add_is_violation \
    case3_cross_crate_corpus_add_does_not_pay_for_it \
    case8_modifying_a_corpus_file_is_not_growth \
    case9_partial_payment_still_names_the_unpaid_crate

# The empty-in-scope-set vacuity guard removed. A gate that examined zero crates
# would then report `0 violations` and be indistinguishable from a clean branch.
run_positive_control in-scope-vacuity-guard \
    's/^    exit 2$/    exit 0/' \
    case7_empty_in_scope_set_is_tool_error

# Per-crate coupling collapsed to a global "did ANY corpus grow" test. This is
# the exact defect the design note in the gate's header describes, and only
# case3 can see it: every other case has a single changed crate.
run_positive_control per-crate-coupling \
    's|^    if corpus_grew "\${crate}"; then|    if [ -n "${growth_crates}" ]; then|' \
    case3_cross_crate_corpus_add_does_not_pay_for_it \
    case9_partial_payment_still_names_the_unpaid_crate

printf '\ncheck-corpus-growth-test: %d cases passed, 3 positive controls\n' "${BASELINE_PASS}"
echo "CHECK-CORPUS-GROWTH TEST PASSED"
exit 0
