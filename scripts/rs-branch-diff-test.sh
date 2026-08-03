#!/usr/bin/env bash
#
# Positive-controlled test suite for scripts/rs-branch-diff.sh.
#
# The driver holds the CORPUS fixed and varies the PRODUCT: it replays one
# committed corpus against a binary built at a base sha and a binary built at
# HEAD. Like its sibling rs-oracle-diff.sh, every wrong branch in it fails toward
# "clean" - two binaries that agree because NEITHER ran look exactly like two
# binaries that agree because the code is correct. So the driver is exercised
# here against a stubbed cargo, a stubbed git and two stubbed test binaries, once
# per interesting outcome.
#
# The suite ends with positive controls that seed NINE of the driver's guards
# back into a COPY of the driver and assert that NAMED cases catch it. Without
# those, this file could pass while testing nothing.
#
# NINE, not "each": the driver has 28 `die 2` sites and they are not all
# controlled. Saying "each" invited the next person to skip adding a control for
# a new guard because the comment claimed one already existed.
#
# Usage: bash scripts/rs-branch-diff-test.sh
# Exit:  0 all cases pass, 1 a case failed, 2 the suite could not run.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)" || exit 2
DRIVER="${REPO_ROOT}/scripts/rs-branch-diff.sh"

[ -f "${DRIVER}" ] || {
    echo "SUITE ERROR: ${DRIVER} not found" >&2
    exit 2
}

SANDBOX_BASE="$(mktemp -d "${TMPDIR:-/tmp}/rs-branch-diff-test-XXXXXX")" || exit 2
trap 'rm -rf "${SANDBOX_BASE}"' EXIT

PASS=0
FAIL=0
FAILED_CASES=()
# 1 while a positive-control phase is running; see case_marker().
CONTROL_PHASE=0
# Every exit code pass 1 observed, so the "there is no rc 3" contract is asserted
# against real behaviour rather than merely documented.
OBSERVED_RCS=""

# The per-case marker for a case that did NOT meet its expectation.
#
# During a positive-control phase the cases are SUPPOSED not to meet it - that is
# how the control proves the guard is load-bearing - so printing `FAIL` there
# announces SUCCESS using the word for failure (#641). `just instrument-test`
# asserts that a suite exiting 0 prints no `FAIL` token, and `EXPECTED-FAIL`
# would still trip a log scrape keyed on it.
case_marker() {
    if [ "${CONTROL_PHASE}" -eq 1 ]; then printf 'CAUGHT'; else printf 'FAIL'; fi
}

# Print a case's captured driver output, EXCEPT during a positive-control phase.
#
# This suite differs from its sibling in one way that matters here: the driver's
# divergence table legitimately contains libtest's own `FAILED` verdict in its
# R1/R2/R3 columns. During a control phase every case is SUPPOSED to mismatch, so
# echoing those tables sprays the token `FAIL` across a run that then exits 0 -
# which `just instrument-test` rejects (#641), and rightly: it arms every log
# scrape keyed on that token to fire on a healthy run.
#
# Suppressed rather than rewritten, because mangling the token would put a line
# in the transcript that the driver never printed. The `CAUGHT` line above still
# names the case and both exit codes, and a control that fails to catch reports
# exactly which cases it missed.
dump_output() {
    [ "${CONTROL_PHASE}" -eq 1 ] && return 0
    printf '     output: %s\n' "$1" >&2
}

# ---------------------------------------------------------------------------
# Sandbox construction.
#
# Builds a fake repo root holding the driver under test, a committed HEAD corpus,
# and a PATH directory with stub cargo / git / test binaries.
#
# The two stub test binaries are the heart of this suite. The BASE binary is run
# TWICE, against two different corpora, and it decides its verdicts from the
# corpus path it was handed - which is exactly the discrimination the driver
# exists to measure, and exactly what a broken driver would fail to distinguish.
# ---------------------------------------------------------------------------
make_sandbox() {
    local driver_src="$1"
    local box
    box="$(mktemp -d "${SANDBOX_BASE}/box-XXXXXX")" || return 2

    mkdir -p "${box}/scripts" "${box}/bin" "${box}/sysbin" "${box}/tmp" \
        "${box}/crates/rulesteward-auditd/tests/corpus/auditd-oracle"
    cp "${driver_src}" "${box}/scripts/rs-branch-diff.sh"

    # The driver's repo-root sanity check looks for a known sibling, so the
    # sandbox must carry one (a `cd "/.."` collapse otherwise resolves every
    # relative path against `/` and succeeds).
    : >"${box}/scripts/rs-oracle-diff.sh"

    # A committed HEAD corpus with at least one regular file in it. An empty one
    # is its own case (STUB_HEAD_CORPUS_EMPTY).
    if [ "${STUB_HEAD_CORPUS_EMPTY:-0}" != "1" ]; then
        : >"${box}/crates/rulesteward-auditd/tests/corpus/auditd-oracle/scenario-a.tsv"
    fi

    # A PRE-EXISTING cache directory, which is the driver's common path (the ATL
    # runs it every round against one fork point) and had zero coverage: every
    # sandbox got a fresh TMPDIR, so the reuse branch was never taken. Built here
    # WITHOUT going through the stub `git worktree add`, which is exactly the
    # state that made the creation path's failure unobservable.
    if [ "${STUB_PRECREATE_WT:-0}" = "1" ]; then
        local wt="${box}/tmp/rs-branch-diff/aaaaaaaabbbbbbbbccccccccdddddddd00000000"
        mkdir -p "${wt}/crates/rulesteward-auditd/tests/corpus/auditd-oracle"
        : >"${wt}/crates/rulesteward-auditd/tests/corpus/auditd-oracle/scenario-a.tsv"
    fi

    # A curated system PATH rather than /usr/bin, so the suite cannot pass or fail
    # for reasons outside the sandbox. (Its sibling suite also uses this to make
    # docker genuinely absent; no case here needs a missing tool, so that is a
    # property of the design rather than something exercised.)
    local tool resolved
    for tool in mktemp mkdir rm tail grep cut env bash dirname cat cp; do
        resolved="$(command -v "${tool}")" || {
            echo "SUITE ERROR: required tool '${tool}' not found" >&2
            return 2
        }
        ln -s "${resolved}" "${box}/sysbin/${tool}"
    done

    # Stub cargo. Which test binary it reports depends on the working directory:
    # the driver builds the base side inside the cached worktree, whose path
    # contains `/rs-branch-diff/`, and the HEAD side at the repo root. A driver
    # that built the same tree twice would get the same binary here and every
    # comparison would be a self-comparison - which is why the marker is the
    # working directory rather than a knob the driver could satisfy by accident.
    cat >"${box}/bin/cargo" <<'STUB'
#!/usr/bin/env bash
case "${PWD}" in
*/rs-branch-diff/*) which_bin="${STUB_BASE_TEST_BIN}"; rc="${STUB_CARGO_BASE_RC:-0}" ;;
*)                  which_bin="${STUB_HEAD_TEST_BIN}"; rc="${STUB_CARGO_HEAD_RC:-0}" ;;
esac
for a in "$@"; do
    if [ "$a" = "--message-format=json" ]; then
        # A non-test artifact carries "executable":null and must be ignored; a
        # build-script artifact must be filtered by name. Both are emitted so the
        # driver's filtering is genuinely exercised.
        printf '{"reason":"compiler-artifact","executable":null}\n'
        printf '{"reason":"compiler-artifact","executable":"/nonexistent/build-script-build"}\n'
        printf '{"reason":"compiler-artifact","executable":"%s"}\n' "${which_bin}"
        [ -n "${STUB_CARGO_EXTRA_EXE:-}" ] &&
            printf '{"reason":"compiler-artifact","executable":"%s"}\n' "${STUB_CARGO_EXTRA_EXE}"
        exit "${STUB_CARGO_JSON_RC:-0}"
    fi
done
[ -n "${STUB_CARGO_MSG:-}" ] && echo "${STUB_CARGO_MSG}" >&2
exit "${rc}"
STUB

    # Stub git. Only the two subcommands the driver uses.
    #
    # `worktree add` materialises a base tree carrying its own committed corpus,
    # so that R1 (base binary against the BASE corpus) has something real to read.
    # STUB_BASE_CORPUS_MISSING models a base sha that predates the corpus.
    cat >"${box}/bin/git" <<'STUB'
#!/usr/bin/env bash
# Stub git. Distinguishes calls made INSIDE the cached base worktree (`git -C
# <dir> ...`) from calls against the repo, because the driver now validates the
# cache and those two must be able to disagree.
in_worktree=0
if [ "${1-}" = "-C" ]; then
    in_worktree=1
    shift 2
fi

BASE_DEFAULT="aaaaaaaabbbbbbbbccccccccdddddddd00000000"
HEAD_DEFAULT="1111111122222222333333334444444455555555"

if [ "${1-}" = "rev-parse" ]; then
    if [ "${in_worktree}" -eq 1 ]; then
        # What the CACHED worktree reports it is checked out at.
        echo "${STUB_WT_SHA:-${STUB_BASE_SHA:-$BASE_DEFAULT}}"
        exit 0
    fi
    rc="${STUB_GIT_REVPARSE_RC:-0}"
    [ "${rc}" -ne 0 ] && { echo "fatal: stub rev-parse failure" >&2; exit "${rc}"; }
    # HEAD resolves separately from the base ref, so "is there anything to vary?"
    # is expressible. Defaults differ, so ordinary cases are unaffected.
    case "${3-}" in
    'HEAD^{commit}') echo "${STUB_HEAD_SHA:-$HEAD_DEFAULT}" ;;
    *) echo "${STUB_BASE_SHA:-$BASE_DEFAULT}" ;;
    esac
    exit 0
fi

if [ "${1-}" = "status" ]; then
    # Does the caller want untracked files suppressed? The driver passes -uno,
    # because an untracked path is not part of the build and must not read as a
    # modified tree.
    uno=0
    for a in "$@"; do case "${a}" in -uno|--untracked-files=no) uno=1 ;; esac; done
    if [ "${in_worktree}" -eq 1 ]; then
        [ -n "${STUB_WT_DIRTY:-}" ] && echo " M crates/rulesteward-auditd/src/lib.rs"
        # UNTRACKED inside the cached base worktree. The corpus is enumerated from
        # the filesystem, so an untracked scenario dir IS part of the base's
        # replay input - which is why this site must NOT pass -uno.
        [ -n "${STUB_WT_UNTRACKED:-}" ] && [ "${uno}" -eq 0 ] &&
            echo "?? crates/rulesteward-auditd/tests/corpus/auditd-oracle/zz-extra/"
    else
        [ -n "${STUB_TREE_DIRTY:-}" ] && echo " M crates/rulesteward-auditd/src/lib.rs"
        # Untracked-only: visible to a bare `status --porcelain`, invisible to -uno.
        [ -n "${STUB_TREE_UNTRACKED:-}" ] && [ "${uno}" -eq 0 ] && echo "?? .serena/"
    fi
    exit 0
fi

if [ "${1-}" = "diff" ]; then
    # `git diff --quiet <base> <head> -- <paths>`: 0 = identical, 1 = they differ.
    [ -n "${STUB_TREES_IDENTICAL:-}" ] && exit 0
    exit 1
fi

if [ "${1-}" = "worktree" ] && [ "${2-}" = "add" ]; then
    rc="${STUB_GIT_WORKTREE_RC:-0}"
    if [ "${rc}" -eq 0 ]; then
        # `worktree add --detach <dir> <sha>`: the directory is the absolute arg.
        for arg in "$@"; do case "${arg}" in /*) dest="${arg}" ;; esac; done
        mkdir -p "${dest}"
        if [ "${STUB_BASE_CORPUS_MISSING:-0}" != "1" ]; then
            mkdir -p "${dest}/crates/rulesteward-auditd/tests/corpus/auditd-oracle"
            : >"${dest}/crates/rulesteward-auditd/tests/corpus/auditd-oracle/scenario-a.tsv"
        fi
    else
        echo "fatal: stub worktree add failure" >&2
    fi
    exit "${rc}"
fi
exit 0
STUB

    # Stub replay binaries.
    #
    # Verdict lists are `name:ok name:FAILED` strings. The exit code is DERIVED
    # from them the way libtest derives its own (101 if any test failed), so a
    # case cannot accidentally set up an rc that disagrees with its own table -
    # disagreement is its own case, via STUB_FORCE_RC.
    cat >"${box}/bin/stub-replay-base" <<'STUB'
#!/usr/bin/env bash
SENTINEL="RS-DIFF-AUDITD"
root="${RS_ORACLE_CORPUS_AUDITD:-}"

# Which of the three runs is this?
#
# The SIDE comes from the stub's own filename, because that is the only thing the
# driver actually varies between R2 and R3: both are handed HEAD's corpus, and
# only the binary differs. Deriving it from anything the two runs share would
# make R3 indistinguishable from R2, and every case that needs them to differ
# would then pass or fail for the wrong reason.
case "$0" in
*-head) run=3 ;;
*)
    # The BASE binary is invoked twice and tells its two runs apart by the
    # corpus it was handed.
    case "${root}" in
    */rs-branch-diff/*) run=1 ;;
    *) run=2 ;;
    esac
    ;;
esac
eval "tests=\"\${STUB_R${run}_TESTS-replay_alpha:ok replay_beta:ok}\""
eval "scen=\"\${STUB_R${run}_SCENARIOS:-7}\""

# A binary that ignores the override reads its OWN corpus and announces
# `mode=committed`. That is the silent failure the sentinel guard exists for: it
# agrees with itself and exits 0.
if [ -n "${root}" ] && [ "${STUB_IGNORES_ENV:-0}" != "${run}" ]; then
    mode="fresh"
else
    mode="committed"
    root="/its/own/corpus"
fi
# Announcements go to STDERR and the per-test table to STDOUT, exactly as a real
# replay binary does it: libtest writes its own progress to stdout, and the replay
# tests announce with `eprintln!`. The driver relies on that split, so the stub
# must honour it or the suite would be testing a shape that does not occur.
[ "${STUB_NO_BANNER:-0}" = "${run}" ] || echo "${SENTINEL}: mode=${mode} corpus=${root}" >&2

# An extra vacuous announcement BEFORE the real one models a suite whose parallel
# libtest threads each announce, one of which compared nothing. The healthy count
# lands last on purpose: that is the ordering under which a `tail -1` sampler
# reports success.
[ "${STUB_ZERO_COUNT_FIRST:-0}" = "${run}" ] && echo "${SENTINEL}: scenarios=0" >&2
[ "${STUB_NO_COUNT:-0}" = "${run}" ] || echo "${SENTINEL}: scenarios=${scen}" >&2
[ "${STUB_ORACLE_BROKEN:-0}" = "${run}" ] &&
    echo "${SENTINEL}: ORACLE-BROKEN accept and reject controls returned the same verdict" >&2

failed=0
total=0
mangled=0
for entry in ${tests}; do
    name="${entry%%:*}"
    verdict="${entry##*:}"
    total=$((total + 1))
    if [ "${STUB_MANGLE_ROW:-0}" = "${run}" ] && [ "${mangled}" -eq 0 ]; then
        # Models what libtest ACTUALLY does under --nocapture when a test writes
        # to the same stream as the progress line: `test <name> ... ` is printed
        # BEFORE the test body runs, so the body's output lands mid-line and the
        # verdict never appears. This is not invented - it is the line the first
        # real sudoers run produced. The row must go missing rather than parse to
        # a bogus verdict, and the summary cross-check must then refuse the run.
        printf 'test %s ... %s: mode=fresh corpus=%s\n' "${name}" "${SENTINEL}" "${root}"
        mangled=1
    else
        echo "test ${name} ... ${verdict}"
    fi
    [ "${verdict}" = "FAILED" ] && failed=$((failed + 1))
done

# libtest's own tally, the independent second count the driver reconciles against.
if [ "${STUB_NO_SUMMARY:-0}" != "${run}" ]; then
    if [ "${STUB_SUMMARY_BAD:-0}" = "${run}" ]; then
        echo "test result: ok. 99 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s"
    else
        if [ "${failed}" -eq 0 ]; then word="ok"; else word="FAILED"; fi
        echo "test result: ${word}. $((total - failed)) passed; ${failed} failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s"
    fi
fi

if [ -n "${STUB_FORCE_RC:-}" ] && [ "${STUB_FORCE_RC_RUN:-0}" = "${run}" ]; then
    exit "${STUB_FORCE_RC}"
fi
[ "${failed}" -eq 0 ] && exit 0
exit 101
STUB

    # The HEAD-side stub is a byte-identical copy under a different NAME: the two
    # sides must behave identically except for which verdict list they read, and
    # a second hand-maintained copy would drift.
    cp "${box}/bin/stub-replay-base" "${box}/bin/stub-replay-head"

    chmod +x "${box}/bin/cargo" "${box}/bin/git" \
        "${box}/bin/stub-replay-base" "${box}/bin/stub-replay-head"
    printf '%s' "${box}"
}

# run_case <name> <expected_rc> <expected_substring> [VAR=VAL ...]
#
# Runs the driver for lane `auditd` against base ref `BASEREF` inside a fresh
# sandbox, asserting BOTH the exit code and a substring of output.
# The substring matters: many distinct defects all produce rc 2, and a case that
# only checked the number would pass for the wrong reason.
run_case() {
    local name="$1" want_rc="$2" want_sub="$3"
    shift 3

    # Sandbox-shaping knobs are properties of the box, not the run, so they are
    # read here before it is built.
    local kv
    local head_corpus_empty=0 precreate_wt=0
    for kv in "$@"; do
        [ "${kv}" = "STUB_HEAD_CORPUS_EMPTY=1" ] && head_corpus_empty=1
        [ "${kv}" = "STUB_PRECREATE_WT=1" ] && precreate_wt=1
    done

    local box
    box="$(STUB_HEAD_CORPUS_EMPTY="${head_corpus_empty}" STUB_PRECREATE_WT="${precreate_wt}" \
        make_sandbox "${DRIVER_UNDER_TEST}")" || {
        echo "SUITE ERROR: sandbox creation failed" >&2
        exit 2
    }

    local out rc
    out="$(
        env -i \
            PATH="${box}/bin:${box}/sysbin" \
            TMPDIR="${box}/tmp" \
            STUB_BASE_TEST_BIN="${box}/bin/stub-replay-base" \
            STUB_HEAD_TEST_BIN="${box}/bin/stub-replay-head" \
            "$@" \
            bash "${box}/scripts/rs-branch-diff.sh" auditd BASEREF 2>&1
    )"
    rc=$?
    OBSERVED_RCS="${OBSERVED_RCS} ${rc}"

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
        printf '%s %s: want rc=%s sub=%q; got rc=%s\n' \
            "$(case_marker)" "${name}" "${want_rc}" "${want_sub}" "${rc}" >&2
        dump_output "${out}"
    fi
}

# run_argcase <name> <expected_rc> <expected_substring> [args...]
# For argument validation, which passes something other than `auditd BASEREF`.
run_argcase() {
    local name="$1" want_rc="$2" want_sub="$3"
    shift 3

    local box
    box="$(make_sandbox "${DRIVER_UNDER_TEST}")" || exit 2

    local out rc
    out="$(env -i PATH="${box}/bin:${box}/sysbin" TMPDIR="${box}/tmp" \
        bash "${box}/scripts/rs-branch-diff.sh" "$@" 2>&1)"
    rc=$?
    OBSERVED_RCS="${OBSERVED_RCS} ${rc}"

    if [ "${rc}" -eq "${want_rc}" ] && [[ "${out}" == *"${want_sub}"* ]]; then
        PASS=$((PASS + 1))
    else
        FAIL=$((FAIL + 1))
        FAILED_CASES+=("${name}")
        printf '%s %s: want rc=%s sub=%q; got rc=%s\n' \
            "$(case_marker)" "${name}" "${want_rc}" "${want_sub}" "${rc}" >&2
        dump_output "${out}"
    fi
}

# The three verdict sets, named for readability at the call sites below.
#   R1 = base binary against the BASE corpus   (baseline)
#   R2 = base binary against HEAD's corpus     (does the new corpus discriminate?)
#   R3 = HEAD binary against HEAD's corpus     (does HEAD still agree?)
ALL_OK='replay_alpha:ok replay_beta:ok'

# Cases every positive control's seeded driver must STILL pass. Each removes one
# guard, and none of these three inputs reaches any of those guards, so a seeded
# driver that fails them is broken rather than merely weakened. See
# run_positive_control for why this matters more than it looks.
CONTROL_MUST_STILL_PASS=(clean_no_discrimination discrimination_reported regression_is_rc1)

run_all_cases() {
    # --- argument validation -------------------------------------------------
    run_argcase no_lane 2 "no lane given"
    run_argcase unknown_lane 2 "unknown lane 'fapolicyd'" fapolicyd HEAD
    run_argcase no_base_ref 2 "no base ref given" auditd

    # --- the happy paths -----------------------------------------------------
    # Nothing discriminated: a branch that did not touch this lane. Reported
    # loudly but rc 0, because failing it would fail every unrelated branch.
    run_case clean_no_discrimination 0 "OK (0 regressions, 0 discriminated" \
        "STUB_R1_TESTS=${ALL_OK}" "STUB_R2_TESTS=${ALL_OK}" "STUB_R3_TESTS=${ALL_OK}"

    # THE payload case. Base was green on its own corpus, goes red on HEAD's, and
    # HEAD is green: the corpus this branch added actually catches the old code.
    run_case discrimination_reported 0 "OK (0 regressions, 1 discriminated" \
        "STUB_R1_TESTS=${ALL_OK}" \
        "STUB_R2_TESTS=replay_alpha:FAILED replay_beta:ok" \
        "STUB_R3_TESTS=${ALL_OK}"

    # --- regressions are rc 1 ------------------------------------------------
    run_case regression_is_rc1 1 "REGRESSION" \
        "STUB_R1_TESTS=${ALL_OK}" "STUB_R2_TESTS=${ALL_OK}" \
        "STUB_R3_TESTS=replay_alpha:ok replay_beta:FAILED"

    # A regression must still be rc 1 when the same round also discriminated.
    # A driver that returned early on the good news would ship the bad news.
    run_case regression_beats_discrimination 1 "REGRESSION" \
        "STUB_R1_TESTS=${ALL_OK}" \
        "STUB_R2_TESTS=replay_alpha:FAILED replay_beta:ok" \
        "STUB_R3_TESTS=replay_alpha:FAILED replay_beta:ok"

    # --- THE guard: a run that read its OWN corpus instead of the one handed --
    #     to it. Exit code 0, counts fine, table fully populated; only the
    #     banner's corpus path can reveal that nothing was actually compared.
    run_case base_baseline_ignores_override 2 "did not read the corpus it was handed" \
        STUB_IGNORES_ENV=1
    run_case base_on_head_corpus_ignores_override 2 "did not read the corpus it was handed" \
        STUB_IGNORES_ENV=2
    run_case head_run_ignores_override 2 "did not read the corpus it was handed" \
        STUB_IGNORES_ENV=3
    run_case no_banner_at_all 2 "did not read the corpus it was handed" \
        STUB_NO_BANNER=2

    # --- vacuity -------------------------------------------------------------
    run_case zero_scenarios 2 "'nothing fired' and 'nothing ran' are not the same" \
        STUB_R2_SCENARIOS=0
    # A GREEN run with no announcement is still vacuous and still rc 2. Paired
    # with failing_run_may_lack_a_count below, these two pin the exact boundary:
    # the count is required where, and only where, its absence is unfalsifiable.
    run_case missing_count_line 2 "for a green run" STUB_NO_COUNT=3
    run_case unparseable_count 2 "unparseable scenario count" \
        STUB_R1_SCENARIOS=many

    # One vacuous announcement among several live ones must still be rc 2, and
    # the zero line is emitted FIRST with a healthy count LAST: exactly the
    # thread ordering under which sampling only the final line reports success.
    run_case zero_count_among_live_ones 2 "an announcement reported 0 scenarios" \
        STUB_ZERO_COUNT_FIRST=3

    # A run that produced no parseable per-test line executed nothing. An empty
    # table is not a clean table.
    run_case no_test_lines_at_all 2 "printed no parseable 'test <name> ... ' line" \
        "STUB_R3_TESTS="
    run_case no_test_lines_in_baseline 2 "printed no parseable 'test <name> ... ' line" \
        "STUB_R1_TESTS="

    # --- the table must reconcile with libtest's own tally --------------------
    # THE regression test for the defect the first real run hit: a row whose
    # progress line was mangled by the test's own output simply does not match
    # the anchored pattern, so it goes MISSING rather than wrong. Silence and
    # absence are indistinguishable without a second count, and a silently
    # narrowed table would draw a verdict from fewer rows than it claims.
    run_case mangled_row_is_caught 2 "the table is incomplete" STUB_MANGLE_ROW=2
    run_case mangled_row_in_baseline 2 "the table is incomplete" STUB_MANGLE_ROW=1
    run_case summary_disagrees 2 "the table is incomplete" STUB_SUMMARY_BAD=3
    run_case no_summary_line 2 "printed no 'test result:' summary line" STUB_NO_SUMMARY=1

    # R3 is the direction where the cross-check is the SOLE guard. A mangled row
    # in R1 or R2 is double-covered by the R1/R2 cardinality assertion, so those
    # two cases pass even with the cross-check removed and credit it with catches
    # it did not make. Here the row would silently vanish from R3 and be filed as
    # `base-only (removed at HEAD)`, a reported NON-failing verdict: a HEAD test
    # that really ran, relabelled "removed", and the run reported clean.
    run_case mangled_row_in_HEAD 2 "the table is incomplete" STUB_MANGLE_ROW=3

    # --- a FAILING run need not have announced a count -----------------------
    # The instrument's own payload case. Three of the four lanes announce the
    # scenario count AFTER parsing the corpus, so a base binary that chokes on
    # HEAD's GROWN corpus during enumeration never reaches the announcement.
    # Demanding the count unconditionally turned exactly that - the R2-FAILED
    # signal this driver exists to report - into rc 2. A green run still must
    # announce, because there "nothing fired" and "nothing ran" are one transcript.
    run_case failing_run_may_lack_a_count 0 "DISCRIMINATED" \
        "STUB_R2_TESTS=replay_alpha:FAILED replay_beta:ok" STUB_NO_COUNT=2

    # --- attribution ---------------------------------------------------------
    # A base that was already red on its OWN corpus cannot attribute anything:
    # its failure predates the branch. Those rows are excluded, and if EVERY row
    # is excluded nothing was compared at all.
    run_case all_rows_unattributable 2 "every comparable row is UNATTRIBUTABLE" \
        "STUB_R1_TESTS=replay_alpha:FAILED replay_beta:FAILED"

    # One unattributable row must NOT poison the others: the remaining row is
    # still a real comparison, so this is rc 0 with the exclusion reported.
    run_case partial_unattributable_still_compares 0 "UNATTRIBUTABLE" \
        "STUB_R1_TESTS=replay_alpha:FAILED replay_beta:ok" \
        "STUB_R2_TESTS=${ALL_OK}" "STUB_R3_TESTS=${ALL_OK}"

    # An unattributable row must not be counted as a regression even when HEAD
    # also fails it: base was already red there, so the branch did not break it.
    run_case unattributable_is_not_a_regression 0 "0 regressions" \
        "STUB_R1_TESTS=replay_alpha:FAILED replay_beta:ok" \
        "STUB_R2_TESTS=replay_alpha:FAILED replay_beta:ok" \
        "STUB_R3_TESTS=replay_alpha:FAILED replay_beta:ok"

    # --- test sets that do not line up ---------------------------------------
    # A branch that RENAMED every test leaves nothing to compare. That is rc 2
    # and it must NOT be reported as "the base was already red", which is a
    # different cause pointing at a different file.
    run_case disjoint_test_sets 2 "no test name appears in BOTH" \
        "STUB_R3_TESTS=renamed_alpha:ok renamed_beta:ok"

    # A branch that ADDED a test still compares the rows it shares, and reports
    # the new one rather than silently dropping it.
    run_case head_added_a_test 0 "HEAD-only (added by the branch)" \
        "STUB_R3_TESTS=replay_alpha:ok replay_beta:ok replay_gamma:ok"

    # A branch that REMOVED a test likewise: the survivor is still comparable.
    run_case head_removed_a_test 0 "base-only (removed at HEAD)" \
        "STUB_R3_TESTS=replay_alpha:ok"

    # A test the branch ADDED and left RED has no base counterpart, so it cannot
    # be a REGRESSION by definition - and it was therefore collected under the
    # neutral "added by the branch" label and never consulted for the verdict.
    # rc 0 while R3's libtest exited 101.
    run_case head_only_test_that_fails 1 "exist only at HEAD and are FAILING" \
        "STUB_R3_TESTS=replay_alpha:ok replay_beta:ok replay_gamma:FAILED"

    # The same shape with R3 red BEFORE it announces: rc 0 with a ZERO count on
    # the success line, contradicting the rc-0 contract stated in this driver's
    # header, in the justfile, and in CONTRIBUTING.
    run_case rc_zero_must_carry_a_nonzero_count 1 "exist only at HEAD and are FAILING" \
        "STUB_R3_TESTS=replay_alpha:ok replay_beta:ok replay_gamma:FAILED" STUB_NO_COUNT=3

    # --- rc must agree with the table ----------------------------------------
    # rc IS the gate and a derived count is never the pass condition; a count
    # that disagrees with rc is a defect in the INSTRUMENT, not a detail to wave
    # through. Both directions are wrong and neither may be interpreted.
    run_case rc_zero_but_table_failed 2 "disagrees with its own per-test table" \
        "STUB_R3_TESTS=replay_alpha:FAILED replay_beta:ok" \
        STUB_FORCE_RC=0 STUB_FORCE_RC_RUN=3
    run_case rc_101_but_table_clean 2 "disagrees with its own per-test table" \
        STUB_FORCE_RC=101 STUB_FORCE_RC_RUN=3
    run_case unexpected_rc 2 "which is neither 0 nor 101" \
        STUB_FORCE_RC=134 STUB_FORCE_RC_RUN=1

    # --- a broken oracle is neither clean nor a regression -------------------
    run_case oracle_broken_beats_clean 2 "the oracle itself is broken" \
        STUB_ORACLE_BROKEN=2
    run_case oracle_broken_beats_regression 2 "the oracle itself is broken" \
        STUB_ORACLE_BROKEN=3 \
        "STUB_R3_TESTS=replay_alpha:ok replay_beta:FAILED"

    # --- base resolution and builds are rc 2, never a skip and never clean ---
    run_case unresolvable_base 2 "cannot resolve base ref" STUB_GIT_REVPARSE_RC=128
    run_case worktree_add_failure 2 "could not create the base worktree" \
        STUB_GIT_WORKTREE_RC=128

    # --- there must be something to vary -------------------------------------
    # A base ref resolving to this tree's own commit builds the same source
    # twice and compares it with itself. Every anti-vacuity guard passes on that
    # run - sentinels fire with the exact paths, counts are healthy, tables
    # reconcile - and it prints OK. That is #572 in a new file, one step away via
    # `just diff-<lane>-branch HEAD`.
    run_case base_equals_head_is_refused 2 "there is nothing to vary" \
        STUB_HEAD_SHA=aaaaaaaabbbbbbbbccccccccdddddddd00000000
    # A DIRTY tree at the same sha is the legitimate "diff my uncommitted work"
    # mode and must keep working.
    run_case base_equals_head_but_dirty_is_allowed 0 "OK (0 regressions" \
        STUB_HEAD_SHA=aaaaaaaabbbbbbbbccccccccdddddddd00000000 STUB_TREE_DIRTY=1
    # UNTRACKED files are not part of the build, so they must not read as "dirty"
    # and thereby disable the guard. Found by running the real recipe on a tree
    # that looked clean and getting rc 0: a single `?? .serena/` was enough.
    run_case base_equals_head_untracked_only_is_refused 2 "there is nothing to vary" \
        STUB_HEAD_SHA=aaaaaaaabbbbbbbbccccccccdddddddd00000000 STUB_TREE_UNTRACKED=1
    # DIFFERENT shas, IDENTICAL sources. The guard always claimed "identical
    # sources" and tested sha equality, so this sibling walked straight through:
    # on this very branch, two commits differing only under scripts/ produced
    # three runs of the same computation at rc 0.
    run_case identical_trees_different_shas_refused 2 "there is nothing to vary" \
        STUB_TREES_IDENTICAL=1

    # --- the cached base worktree must BE the base ---------------------------
    # Directory existence was the whole reuse predicate, while the report kept
    # printing `base=<sha>`. All three of these were rc 0 before the cache
    # validation landed.
    run_case cached_worktree_at_wrong_sha 2 "not the requested base" \
        STUB_PRECREATE_WT=1 STUB_WT_SHA=deadbeefdeadbeefdeadbeefdeadbeef00000000
    run_case cached_worktree_is_dirty 2 "has uncommitted changes" \
        STUB_PRECREATE_WT=1 STUB_WT_DIRTY=1
    # An UNTRACKED file in the cached base worktree is part of the base's replay
    # input, because the corpus is read from the filesystem and not from git.
    # Measured on the real driver: one untracked scenario dir dropped into the
    # cached base turned "2 discriminated" into "0 discriminated" at rc 0.
    run_case cached_worktree_has_untracked_corpus_file 2 "has uncommitted changes" \
        STUB_PRECREATE_WT=1 STUB_WT_UNTRACKED=1
    # A hand-made directory at the cache path means `git worktree add` never runs,
    # so even its failure is unobservable. Pairing the pre-created tree with a
    # creation failure proves the driver is validating rather than trusting.
    run_case cached_worktree_never_created_by_git 2 "not the requested base" \
        STUB_PRECREATE_WT=1 STUB_WT_SHA=deadbeefdeadbeefdeadbeefdeadbeef00000000 \
        STUB_GIT_WORKTREE_RC=128
    run_case base_build_failure 2 "cannot compare" STUB_CARGO_BASE_RC=101
    run_case head_build_failure 2 "cannot compare" STUB_CARGO_HEAD_RC=101
    run_case json_phase_failure 2 "--message-format=json exited" STUB_CARGO_JSON_RC=1
    run_case ambiguous_executables 2 "expected exactly 1 test binary" \
        STUB_CARGO_EXTRA_EXE=/bin/true

    # --- corpus preconditions ------------------------------------------------
    # A base predating the corpus cannot be replayed against it. That is the
    # issue's "cannot compare" path and it is rc 2, never a silent skip: a
    # harness that exits 0 with a skip message on every run is #572.
    run_case base_corpus_missing 2 "corpus is missing at the base" \
        STUB_BASE_CORPUS_MISSING=1
    run_case head_corpus_empty 2 "no regular files" STUB_HEAD_CORPUS_EMPTY=1
}

# ---------------------------------------------------------------------------
# Pass 1: the real driver.
# ---------------------------------------------------------------------------
DRIVER_UNDER_TEST="${DRIVER}"
run_all_cases

if [ "${FAIL}" -ne 0 ]; then
    printf '\nrs-branch-diff-test: %d passed, %d FAILED (%s)\n' \
        "${PASS}" "${FAIL}" "${FAILED_CASES[*]}" >&2
    exit 1
fi

# A suite that parsed nothing must not report clean.
if [ "${PASS}" -eq 0 ]; then
    echo "SUITE ERROR: zero cases ran; the case table is empty or unreachable" >&2
    exit 2
fi
BASELINE_PASS="${PASS}"

# The rc contract says this instrument has NO rc 3. It is OFFLINE tier - no
# docker, no root, no live oracle - so it has no legitimate precondition to skip
# on, and inventing one would rebuild #572, where a harness exited 0 with a skip
# message on every run while checking nothing. Asserted against observed
# behaviour rather than left as a comment.
case " ${OBSERVED_RCS} " in
*" 3 "*)
    echo "SUITE ERROR: the driver exited 3; this instrument has no legitimate skip path" >&2
    exit 2
    ;;
esac

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

    local broken="${SANDBOX_BASE}/rs-branch-diff-FAIL-OPEN-${label}.sh"
    sed "${sed_expr}" "${DRIVER}" >"${broken}"
    if cmp -s "${DRIVER}" "${broken}"; then
        echo "SUITE ERROR: positive control '${label}' edited nothing; its guard's source line moved" >&2
        exit 2
    fi

    PASS=0
    FAIL=0
    FAILED_CASES=()
    DRIVER_UNDER_TEST="${broken}"
    CONTROL_PHASE=1
    run_all_cases
    CONTROL_PHASE=0

    # THE CONTROL NEEDS ITS OWN CONTROL.
    #
    # `must_catch` asserts only that named cases FAILED, and a case fails when
    # either rc or the substring mismatches. A driver that cannot run at all -
    # a sed anchor that moved and now breaks syntax, a quoting slip - exits 2 for
    # every case, mismatches every substring, and is therefore credited with
    # catching everything. `cmp -s` proves sed edited a byte, not that the result
    # is still a driver.
    #
    # Reproduced: injecting a bash syntax error into `usage()` while leaving the
    # sentinel guard fully intact made all six controls report "caught" and the
    # suite exit 0, with `just instrument-test` unable to see it (the control
    # phase prints CAUGHT, not FAIL). That is this project's own "positive-control
    # any instrument you write" rule, left unapplied to the controls themselves.
    #
    # Two cheap assertions close it: some cases must still PASS, and specifically
    # the ones the removed guard cannot see must still behave correctly.
    if [ "${PASS}" -eq 0 ]; then
        printf 'SUITE ERROR: positive control %s left ZERO cases passing.\n' "${label}" >&2
        printf '             A driver with one guard removed still classifies every input that\n' >&2
        printf '             guard does not see; zero passes means the seeded driver cannot run,\n' >&2
        printf '             so "caught" here certifies nothing.\n' >&2
        exit 2
    fi
    local still want got found
    for still in "${CONTROL_MUST_STILL_PASS[@]}"; do
        for got in "${FAILED_CASES[@]+"${FAILED_CASES[@]}"}"; do
            if [ "${got}" = "${still}" ]; then
                printf 'SUITE ERROR: positive control %s broke %s, which its guard does not touch.\n' \
                    "${label}" "${still}" >&2
                printf '             The seeded driver is not merely missing one guard; it is broken,\n' >&2
                printf '             so every "caught" it produced is an artefact.\n' >&2
                exit 2
            fi
        done
    done

    local missed=() found
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
    printf '  control %-30s caught %s\n' "${label}" "${must_catch[*]}"
}

printf 'rs-branch-diff-test: %d cases passed against the real driver.\n' "${BASELINE_PASS}"

# Every sed pattern below is matched against the DRIVER'S SOURCE, where the shell
# variable names appear unexpanded, so they must stay single-quoted. Double
# quoting would expand them in THIS shell and match nothing - which the `cmp`
# check inside run_positive_control then catches.

# shellcheck disable=SC2016
run_positive_control sentinel-guard-removed \
    's|^    if ! grep -qF "${SENTINEL}: mode=fresh corpus=${want_corpus}" "${err}" "${out}"; then|    if false; then|' \
    base_baseline_ignores_override base_on_head_corpus_ignores_override \
    head_run_ignores_override no_banner_at_all

# shellcheck disable=SC2016
run_positive_control zero-count-guard-removed \
    's|^        if \[ "${one}" -eq 0 \]; then|        if false; then|' \
    zero_scenarios zero_count_among_live_ones

# shellcheck disable=SC2016
run_positive_control test-line-guard-removed \
    's|^    if \[ "${seen}" -eq 0 \]; then|    if false; then|' \
    no_test_lines_at_all no_test_lines_in_baseline

# One `if`, two diagnostics, so both of its causes are named here: removing the
# guard must let BOTH a fully-red baseline and a disjoint test set through.
# shellcheck disable=SC2016
run_positive_control unattributable-guard-removed \
    's|^if \[ "${COMPARABLE}" -eq 0 \]; then|if false; then|' \
    all_rows_unattributable disjoint_test_sets

# shellcheck disable=SC2016
run_positive_control rc-consistency-guard-removed \
    's|^    if \[ "${inconsistent}" -eq 1 \]; then|    if false; then|' \
    rc_zero_but_table_failed rc_101_but_table_clean

# The cross-check against libtest's own tally. Without it, a row the anchored
# pattern skipped is indistinguishable from a row that never ran, and the driver
# would report a confident verdict over a silently narrowed table.
# shellcheck disable=SC2016
run_positive_control summary-crosscheck-removed \
    's|^    if \[ "$((lt_passed + lt_failed))" -ne "${seen}" \]; then|    if false; then|' \
    mangled_row_is_caught mangled_row_in_baseline summary_disagrees mangled_row_in_HEAD

# The two guards that stop the driver comparing something with itself. Both were
# absent until an adversarial review reproduced a green `OK (0 regressions, 0
# discriminated, 228 scenarios)` from two builds of identical source.
# shellcheck disable=SC2016
run_positive_control nothing-to-vary-guard-removed \
    's|^if \[ "${same_sources}" -eq 1 \] && \[ -z "$(git status --porcelain -uno -- crates/ Cargo.toml Cargo.lock)" \]; then|if false; then|' \
    base_equals_head_is_refused base_equals_head_untracked_only_is_refused \
    identical_trees_different_shas_refused

# shellcheck disable=SC2016
run_positive_control cache-sha-guard-removed \
    's|^if \[ "${wt_sha}" != "${BASE_SHA}" \]; then|if false; then|' \
    cached_worktree_at_wrong_sha cached_worktree_never_created_by_git

# shellcheck disable=SC2016
run_positive_control cache-dirty-guard-removed \
    's|^if \[ -n "${wt_dirty}" \]; then|if false; then|' \
    cached_worktree_is_dirty cached_worktree_has_untracked_corpus_file

exit 0
