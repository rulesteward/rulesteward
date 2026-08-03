#!/usr/bin/env bash
#
# Shared driver for the branch-vs-fork-point differential replays:
# `just diff-{auditd,selinux,sudoers,sysctld}-branch <base-ref>`.
#
# Usage: bash scripts/rs-branch-diff.sh <auditd|selinux|sudoers|sysctld> <base-ref>
#
# THE AXIS, AND WHY IT IS THE OPPOSITE OF ITS SIBLING
#
# scripts/rs-oracle-diff.sh builds ONE binary and replays it against TWO corpora
# (the committed one, then a fresh capture from the live oracle images): it holds
# the BINARY fixed and varies the CORPUS, which answers "has the real subsystem
# drifted away from what we recorded?".
#
# This driver holds the CORPUS fixed and varies the BINARY, which answers a
# question no other gate in the chain asks: "would the corpus this branch added
# have caught the bug this branch fixed?".
#
# That question exists because of #658. The corpus-growth gate forces a branch
# touching `crates/X/src/**` to ADD a file under `crates/X/tests/corpus/**`, but
# nothing checks the added file DISCRIMINATES anything. A branch can satisfy the
# gate with a scenario the old code already passed: evidence that accumulates
# without proving anything. Session 9o is the case in point - a round declared
# DRY certified a fail-open regression, because each round's adversary drew a
# fresh corpus, so dryness measured the draw rather than the code.
#
# WHY THREE RUNS RATHER THAN TWO
#
# A base/HEAD pair cannot separate "the branch's NEW corpus material caught the
# old code" from "the base was already failing on OLD material". A baseline run
# of the base binary against its OWN corpus does, because then the only delta
# between R1 and R2 is the corpus the branch added:
#
#   R1  base binary, base worktree's committed corpus  (baseline)
#   R2  base binary, HEAD's committed corpus           (does the growth discriminate?)
#   R3  HEAD binary, HEAD's committed corpus           (does HEAD still agree?)
#
#   R1      R2      R3      verdict
#   FAILED  *       *       UNATTRIBUTABLE - base was already red, excluded
#   ok      FAILED  ok      DISCRIMINATED  - the growth catches the old code
#   ok      ok      ok      clean          - this lane's corpus did not discriminate
#   ok      *       FAILED  REGRESSION     - HEAD diverges where the base did not
#
# GRANULARITY, STATED HONESTLY
#
# Rows are libtest TEST NAMES, not corpus scenario ids, because libtest already
# reports per-test pass/fail and continues past a panic. That needs no change to
# the replay crates. It cannot separate a regression from residual defects INSIDE
# one test, which is session 9o's exact shape; scenario granularity needs the
# replay tests to accumulate instead of panicking at the first divergence (~35
# assertion sites across four files) and is tracked as its own issue.
#
# Exit codes (the dev-tooling contract, NOT the rulesteward binary's own):
#   0  no regressions; the success line carries a non-zero scenario count
#   1  one or more REGRESSION rows
#   2  tool/environment error, including "these two builds cannot be compared"
#
# THERE IS DELIBERATELY NO rc 3. This is an OFFLINE-tier instrument: no docker,
# no root, no live oracle, so per CONTRIBUTING's differential contract it has no
# legitimate precondition to skip on. Inventing one would rebuild #572, where
# `just diff-fapolicyd` exited 0 with a skip message on every run for six weeks
# while checking nothing. Its self-test asserts no case ever yields 3.

set -uo pipefail

usage() {
    cat >&2 <<'EOF'
usage: bash scripts/rs-branch-diff.sh <lane> <base-ref>

  lane        auditd | selinux | sudoers | sysctld
  base-ref    any git revision (sha, tag, branch) to compare against

Replays the CURRENT tree's committed corpus against a binary built at <base-ref>
and a binary built at HEAD, plus a baseline of the base binary against the base
tree's own corpus. Reports which rows the branch fixed, which its corpus growth
newly discriminates, and which it regressed.
EOF
}

LANE="${1-}"
BASE_REF="${2-}"

# ---------------------------------------------------------------------------
# Frozen per-lane table.
#
# Phase-0 shared surface, in one place so that landing a lane does not require
# editing a file the other lanes also touch.
#
# selinux appears HERE but not in rs-oracle-diff.sh's table: it has no live
# capture script, so it is an offline-only lane. That asymmetry is intentional
# and is why the two tables are not factored into one.
# ---------------------------------------------------------------------------
case "${LANE}" in
auditd)
    PKG="rulesteward-auditd"
    TEST_TARGET="auditd_corpus_oracle"
    CORPUS_VAR="RS_ORACLE_CORPUS_AUDITD"
    SENTINEL="RS-DIFF-AUDITD"
    CORPUS_SUBPATH="crates/rulesteward-auditd/tests/corpus/auditd-oracle"
    ;;
selinux)
    PKG="rulesteward-selinux"
    TEST_TARGET="selinux_corpus_oracle"
    CORPUS_VAR="RS_ORACLE_CORPUS_SELINUX"
    SENTINEL="RS-DIFF-SELINUX"
    CORPUS_SUBPATH="crates/rulesteward-selinux/tests/corpus/selinux"
    ;;
sudoers)
    PKG="rulesteward-sudoers"
    TEST_TARGET="sudoers_corpus_oracle"
    CORPUS_VAR="RS_ORACLE_CORPUS_SUDOERS"
    SENTINEL="RS-DIFF-SUDOERS"
    CORPUS_SUBPATH="crates/rulesteward-sudoers/tests/corpus/sudoers-oracle"
    ;;
sysctld)
    PKG="rulesteward-sysctld"
    TEST_TARGET="sysctld_corpus_oracle"
    CORPUS_VAR="RS_ORACLE_CORPUS_SYSCTLD"
    SENTINEL="RS-DIFF-SYSCTLD"
    CORPUS_SUBPATH="crates/rulesteward-sysctld/tests/corpus/sysctld-oracle"
    ;;
"")
    echo "rs-branch-diff: no lane given" >&2
    usage
    exit 2
    ;;
*)
    echo "rs-branch-diff: unknown lane '${LANE}'" >&2
    usage
    exit 2
    ;;
esac

LABEL="diff-${LANE}-branch"

if [ -z "${BASE_REF}" ]; then
    echo "rs-branch-diff: no base ref given" >&2
    usage
    exit 2
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)" || exit 2
cd "${REPO_ROOT}" || exit 2

# Confirm we actually landed in the repo root before running anything relative to
# it. If `dirname` is unavailable the expansion above collapses to `cd "/.."`,
# which SUCCEEDS, and every relative path would then resolve against `/`.
if [ ! -f "scripts/rs-oracle-diff.sh" ]; then
    echo "${LABEL}: resolved repo root '${REPO_ROOT}' does not contain scripts/rs-oracle-diff.sh" >&2
    exit 2
fi

# `rs-bd-`, not `rs-branch-diff-`: the cached worktree root below is
# `<cache>/rs-branch-diff/<sha>`, and a log directory sharing that prefix would
# make any path-based reasoning about which tree a command ran in ambiguous.
WORK="$(mktemp -d "${TMPDIR:-/tmp}/rs-bd-${LANE}-XXXXXX")" || {
    echo "${LABEL}: could not create a working directory" >&2
    exit 2
}

# Deliberately NOT an EXIT trap that always deletes: on a regression (rc 1) or a
# tool error (rc 2) the three run logs ARE the evidence, and discarding them
# would leave the operator with a verdict and nothing to inspect.
finish() {
    local rc="$1"
    if [ "${rc}" -eq 0 ]; then
        rm -rf "${WORK}"
    else
        echo "${LABEL}: evidence retained in ${WORK}" >&2
    fi
    exit "${rc}"
}

die() {
    local rc="$1"
    shift
    printf '%s: %s\n' "${LABEL}" "$*" >&2
    finish "${rc}"
}

# ---------------------------------------------------------------------------
# Resolve the base commit.
# ---------------------------------------------------------------------------
if ! BASE_SHA="$(git rev-parse --verify "${BASE_REF}^{commit}" 2>/dev/null)"; then
    die 2 "cannot resolve base ref '${BASE_REF}' to a commit"
fi
# A `rev-parse` that succeeds while printing nothing would leave every path below
# built from an empty sha, which resolves to the cache root itself.
[ -n "${BASE_SHA}" ] || die 2 "cannot resolve base ref '${BASE_REF}' to a commit (git printed nothing)"

# ---------------------------------------------------------------------------
# Cached detached worktree at the base sha.
#
# Keyed BY SHA and reused, because the Adversarial Testing Loop runs this every
# round against the same fork point: paying a full base build per round is how
# this instrument's one-shot ancestor died (issue #661, risk 2). Placed under
# TMPDIR, which the project points off the /tmp tmpfs - the per-UID tmpfs quota
# is what fills, and `df` reports the filesystem and looks healthy while every
# shell dies.
# ---------------------------------------------------------------------------
CACHE_ROOT="${RS_BRANCH_DIFF_CACHE:-${TMPDIR:-/tmp}}/rs-branch-diff"
WT="${CACHE_ROOT}/${BASE_SHA}"
BASE_TARGET_DIR="${CACHE_ROOT}/target-${BASE_SHA}"

if [ ! -d "${WT}" ]; then
    mkdir -p "${CACHE_ROOT}" || die 2 "could not create the worktree cache root ${CACHE_ROOT}"
    git worktree add --detach "${WT}" "${BASE_SHA}" >"${WORK}/worktree.log" 2>&1
    wt_rc=$?
    if [ "${wt_rc}" -ne 0 ]; then
        tail -20 "${WORK}/worktree.log" >&2
        die 2 "could not create the base worktree at ${WT} (git worktree add exited ${wt_rc})"
    fi
fi

# ---------------------------------------------------------------------------
# Corpus preconditions.
#
# A base predating this lane's corpus cannot be replayed against it. That is the
# issue's "cannot compare" path and it is rc 2, never a skip.
# ---------------------------------------------------------------------------
HEAD_CORPUS="${REPO_ROOT}/${CORPUS_SUBPATH}"
BASE_CORPUS="${WT}/${CORPUS_SUBPATH}"

# Counted with bash globbing rather than `find` so the driver keeps working on a
# minimal PATH (and so its own suite can stay hermetic). `dir/**` under globstar
# yields the directory itself plus every descendant, so the `-f` filter is what
# makes this "at least one REGULAR FILE, at any depth": a tree of empty
# subdirectories is still an empty corpus.
count_regular_files() {
    local dir="$1" entry n=0
    shopt -s nullglob dotglob globstar
    for entry in "${dir}"/**; do
        [ -f "${entry}" ] && n=$((n + 1))
    done
    shopt -u nullglob dotglob globstar
    printf '%s' "${n}"
}

[ -d "${BASE_CORPUS}" ] || die 2 "the ${LANE} corpus is missing at the base (${BASE_CORPUS}); ${BASE_SHA} predates it, so the two builds cannot be compared"
[ -d "${HEAD_CORPUS}" ] || die 2 "the ${LANE} corpus is missing at HEAD (${HEAD_CORPUS})"
[ "$(count_regular_files "${BASE_CORPUS}")" -gt 0 ] || die 2 "the base corpus ${BASE_CORPUS} contains no regular files"
[ "$(count_regular_files "${HEAD_CORPUS}")" -gt 0 ] || die 2 "the HEAD corpus ${HEAD_CORPUS} contains no regular files"

# ---------------------------------------------------------------------------
# Build both sides.
#
# `--no-run` first, so that every cargo-level error class (compile error, missing
# target, lock drift) is consumed HERE and a later 101 can only mean a failing
# test. The base build additionally proves the two trees are comparable at all.
# ---------------------------------------------------------------------------
cargo_in() {
    local dir="$1" tdir="$2"
    shift 2
    if [ -n "${tdir}" ]; then
        (cd "${dir}" && CARGO_TARGET_DIR="${tdir}" cargo "$@")
    else
        (cd "${dir}" && cargo "$@")
    fi
}

cargo_in "${WT}" "${BASE_TARGET_DIR}" test -p "${PKG}" --test "${TEST_TARGET}" --locked --no-run \
    >"${WORK}/base-build.log" 2>&1
base_build_rc=$?
if [ "${base_build_rc}" -ne 0 ]; then
    tail -30 "${WORK}/base-build.log" >&2
    die 2 "cargo could not build ${PKG} --test ${TEST_TARGET} at base ${BASE_SHA} (exit ${base_build_rc}); the two trees cannot compare"
fi

cargo_in "${REPO_ROOT}" "" test -p "${PKG}" --test "${TEST_TARGET}" --locked --no-run \
    >"${WORK}/head-build.log" 2>&1
head_build_rc=$?
if [ "${head_build_rc}" -ne 0 ]; then
    tail -30 "${WORK}/head-build.log" >&2
    die 2 "cargo could not build ${PKG} --test ${TEST_TARGET} at HEAD (exit ${head_build_rc}); the two trees cannot compare"
fi

# ---------------------------------------------------------------------------
# Resolve each side's test binary.
#
# Sets RESOLVED_BIN / RESOLVE_ERR rather than echoing, because `exit` inside a
# command substitution leaves only the subshell: a `die` there would print its
# message and let the driver carry on with an empty path.
# ---------------------------------------------------------------------------
resolve_bin() {
    local dir="$1" tdir="$2" logj="$3"
    RESOLVED_BIN=""
    RESOLVE_ERR=""

    cargo_in "${dir}" "${tdir}" test -p "${PKG}" --test "${TEST_TARGET}" --locked --no-run \
        --message-format=json >"${logj}" 2>/dev/null
    local json_rc=$?
    if [ "${json_rc}" -ne 0 ]; then
        RESOLVE_ERR="cargo --message-format=json exited ${json_rc} on a build that had just succeeded"
        return 1
    fi

    # `"executable":null` for non-test artifacts does not match the quoted form,
    # so only real binaries survive; build scripts are excluded by name. The
    # count is then required to be EXACTLY one: picking the first of several
    # would silently run whichever artifact cargo happened to emit first.
    local execs=()
    mapfile -t execs < <(
        grep -o '"executable":"[^"]*"' "${logj}" |
            cut -d'"' -f4 |
            grep -v 'build-script' || true
    )
    if [ "${#execs[@]}" -ne 1 ]; then
        RESOLVE_ERR="expected exactly 1 test binary from cargo's JSON output, found ${#execs[@]}: ${execs[*]-none}"
        return 1
    fi
    if [ ! -x "${execs[0]}" ]; then
        RESOLVE_ERR="cargo reported test binary ${execs[0]}, which is not executable"
        return 1
    fi
    RESOLVED_BIN="${execs[0]}"
    return 0
}

resolve_bin "${WT}" "${BASE_TARGET_DIR}" "${WORK}/base-build.json" || die 2 "base side: ${RESOLVE_ERR}"
BASE_BIN="${RESOLVED_BIN}"
resolve_bin "${REPO_ROOT}" "" "${WORK}/head-build.json" || die 2 "HEAD side: ${RESOLVE_ERR}"
HEAD_BIN="${RESOLVED_BIN}"

# ---------------------------------------------------------------------------
# The three runs.
# ---------------------------------------------------------------------------
declare -A R1 R2 R3
SCEN=(0 0 0 0) # 1-indexed by run; SCEN[0] unused

# validate_run <run 1|2|3> <log> <corpus handed in> <exit code>
#
# Every guard here runs BEFORE any verdict is read out of the log, because each
# one describes a way the run's exit code and table can be entirely meaningless.
validate_run() {
    local run="$1" out="$2" err="$3" want_corpus="$4" rc="$5"
    # A nameref onto the global R1 / R2 / R3 for this run.
    local -n results="R${run}"

    # THE anti-vacuity guard.
    #
    # If this driver and the test disagree about the override variable's name, or
    # the base binary predates the override entirely, the run reads its OWN
    # corpus, agrees with itself, and exits 0. Every row would be `ok`, the count
    # would be healthy, and the table would be a self-comparison. Only confirming
    # the run announced the exact path we handed it can detect that.
    if ! grep -qF "${SENTINEL}: mode=fresh corpus=${want_corpus}" "${err}" "${out}"; then
        tail -30 "${err}" "${out}" >&2
        die 2 "run R${run} did not read the corpus it was handed (${want_corpus}); its exit code and per-test table therefore mean nothing"
    fi

    # A two-sided positive control that comes back one-sided means the ORACLE is
    # broken, not the product. Neither 'clean' nor 'regression' would be true.
    if grep -qF "${SENTINEL}: ORACLE-BROKEN" "${err}" "${out}"; then
        grep -hF "${SENTINEL}: ORACLE-BROKEN" "${err}" "${out}" >&2
        die 2 "run R${run}: the corpus positive control failed, so the oracle itself is broken"
    fi

    # libtest exits 0 when every test passed and 101 when one failed. Anything
    # else (a signal, a harness abort, a panic before main) is a tool error, and
    # guessing which of the two it resembles is how a crash becomes a verdict.
    case "${rc}" in
    0 | 101) ;;
    *)
        tail -30 "${err}" "${out}" >&2
        die 2 "run R${run} exited ${rc}, which is neither 0 nor 101; treating it as a tool error rather than guessing what it meant"
        ;;
    esac

    # EVERY `scenarios=` announcement is checked, not just the last one.
    #
    # A suite with several announcing tests emits several lines in a
    # nondeterministic order (sudoers emits five). `tail -1` would sample a
    # RANDOM one of N, so a test that compared NOTHING slips past whenever some
    # sibling's line happens to land last. Refusing on ANY zero (not just a zero
    # sum) is deliberate: one vacuous test among live ones is exactly what a sum
    # would hide.
    #
    # The loop is fed by a heredoc, NOT a pipe: a `while read` on the right of a
    # pipe runs in a subshell, so the accumulator would be discarded at `done`
    # and `die` would exit only that subshell.
    local count_lines count_line one count_seen=0
    count_lines="$(grep -hF "${SENTINEL}: scenarios=" "${err}" "${out}")"
    while IFS= read -r count_line; do
        [ -n "${count_line}" ] || continue
        one="${count_line##*=}"
        case "${one}" in
        '' | *[!0-9]*)
            die 2 "run R${run}: unparseable scenario count '${one}' in a '${SENTINEL}: scenarios=' line"
            ;;
        esac
        if [ "${one}" -eq 0 ]; then
            die 2 "run R${run}: an announcement reported 0 scenarios; 'nothing fired' and 'nothing ran' are not the same verdict"
        fi
        SCEN[run]=$((SCEN[run] + one))
        count_seen=$((count_seen + 1))
    done <<EOF
${count_lines}
EOF
    if [ "${count_seen}" -eq 0 ]; then
        die 2 "run R${run} printed no '${SENTINEL}: scenarios=' line; the scenario count cannot be confirmed non-zero"
    fi

    # The per-test table, read from STDOUT ONLY and anchored at both ends.
    #
    # Both of those are load-bearing, and the reason is empirical. libtest prints
    # `test <name> ... ` BEFORE running the test and the verdict after it, so
    # under `--nocapture` anything the test writes lands in the middle of that
    # line. Capturing both streams into one file produced exactly this on the
    # first real run:
    #
    #   test l1_f01_matches_visudo_verdict_per_target ... RS-DIFF-SUDOERS: mode=fresh corpus=/...
    #
    # `--nocapture` is not optional (without it libtest swallows the sentinel on a
    # passing run, and the sentinel guard above is the whole anti-vacuity story),
    # so the streams are kept apart instead: libtest's progress goes to stdout,
    # the replay tests announce with `eprintln!` to stderr.
    #
    # The `$` anchor is the second layer, for a lane that ever prints to STDOUT:
    # a mangled line then fails to match rather than yielding a bogus verdict, and
    # the summary cross-check below turns that silence into a hard error.
    local test_lines line rest name verdict seen=0 failed=0
    test_lines="$(grep -E '^test .+ \.\.\. (ok|FAILED|ignored)$' "${out}")"
    while IFS= read -r line; do
        [ -n "${line}" ] || continue
        rest="${line#test }"
        name="${rest%% ...*}"
        verdict="${rest##*... }"
        case "${verdict}" in
        ok) ;;
        FAILED) failed=$((failed + 1)) ;;
        ignored) continue ;;
        *)
            die 2 "run R${run}: unrecognised libtest verdict '${verdict}' for test '${name}'"
            ;;
        esac
        # shellcheck disable=SC2034  # nameref: this write lands in R1 / R2 / R3
        results["${name}"]="${verdict}"
        seen=$((seen + 1))
    done <<EOF
${test_lines}
EOF
    if [ "${seen}" -eq 0 ]; then
        die 2 "run R${run} printed no parseable 'test <name> ... ' line; a run that executed nothing is not a clean run"
    fi

    # Cross-check the parsed table against libtest's OWN tally.
    #
    # This is a second instrument counting the same quantity by a different route,
    # which is the only thing that catches a parser whose blind spot it shares
    # with nothing else. Anchoring the regex above makes a mangled line invisible
    # rather than wrong; without this check, invisible is indistinguishable from
    # absent, and a dropped row would silently narrow the comparison.
    local summary lt_passed lt_failed
    summary="$(grep -m1 -E '^test result: ' "${out}")"
    if [ -z "${summary}" ]; then
        die 2 "run R${run} printed no 'test result:' summary line; libtest's own tally is what confirms this driver parsed every row"
    fi
    # `test result: ok. 15 passed; 0 failed; 0 ignored; 0 measured; ...`
    lt_passed="${summary#*. }"
    lt_passed="${lt_passed%% passed;*}"
    lt_failed="${summary#* passed; }"
    lt_failed="${lt_failed%% failed;*}"
    case "${lt_passed}${lt_failed}" in
    '' | *[!0-9]*)
        die 2 "run R${run}: could not read pass/fail counts out of libtest's summary line: ${summary}"
        ;;
    esac
    if [ "$((lt_passed + lt_failed))" -ne "${seen}" ]; then
        die 2 "run R${run}: libtest reports ${lt_passed} passed + ${lt_failed} failed but this driver parsed ${seen} row(s); the table is incomplete, so any verdict from it would be drawn from a narrower comparison than it claims"
    fi
    if [ "${lt_failed}" -ne "${failed}" ]; then
        die 2 "run R${run}: libtest reports ${lt_failed} failed but this driver parsed ${failed}; the table disagrees with libtest's own tally"
    fi

    # rc IS the gate, and a derived count is never the pass condition. A table
    # that disagrees with rc means the parse is wrong, and a wrong parse that
    # happens to look clean is the worst outcome available here.
    local inconsistent=0
    [ "${rc}" -eq 0 ] && [ "${failed}" -ne 0 ] && inconsistent=1
    [ "${rc}" -eq 101 ] && [ "${failed}" -eq 0 ] && inconsistent=1
    if [ "${inconsistent}" -eq 1 ]; then
        die 2 "run R${run} exited ${rc} but its per-test table reports ${failed} failed; the exit code disagrees with its own per-test table, which is an instrument defect rather than a result to interpret"
    fi
}

# stdout and stderr go to SEPARATE files. See the parsing block above: merging
# them puts the replay test's own sentinel inside libtest's half-written
# `test <name> ... ` progress line, which is not a hypothetical - it is what the
# first real sudoers run produced.
#
# `--test-threads=1` keeps the transcript in a deterministic order so the
# retained evidence reads the same way twice.
replay() {
    local bin="$1" corpus="$2" out="$3" err="$4"
    env "${CORPUS_VAR}=${corpus}" "${bin}" --nocapture --test-threads=1 >"${out}" 2>"${err}"
    REPLAY_RC=$?
}

# R1 sets the override explicitly rather than leaving it unset, so that the
# baseline is covered by the same sentinel guard as the other two. An unset
# baseline would be the one run whose corpus nothing confirmed.
replay "${BASE_BIN}" "${BASE_CORPUS}" "${WORK}/r1-base-on-base.out" "${WORK}/r1-base-on-base.err"
validate_run 1 "${WORK}/r1-base-on-base.out" "${WORK}/r1-base-on-base.err" "${BASE_CORPUS}" "${REPLAY_RC}"

replay "${BASE_BIN}" "${HEAD_CORPUS}" "${WORK}/r2-base-on-head.out" "${WORK}/r2-base-on-head.err"
validate_run 2 "${WORK}/r2-base-on-head.out" "${WORK}/r2-base-on-head.err" "${HEAD_CORPUS}" "${REPLAY_RC}"

replay "${HEAD_BIN}" "${HEAD_CORPUS}" "${WORK}/r3-head-on-head.out" "${WORK}/r3-head-on-head.err"
validate_run 3 "${WORK}/r3-head-on-head.out" "${WORK}/r3-head-on-head.err" "${HEAD_CORPUS}" "${REPLAY_RC}"

# R1 and R2 are the SAME binary, so their test-name sets are identical by
# construction. Asserted rather than assumed: if they differ, one of the two runs
# is not the process this driver believes it invoked.
if [ "${#R1[@]}" -ne "${#R2[@]}" ]; then
    die 2 "the base binary reported ${#R1[@]} tests against the base corpus but ${#R2[@]} against HEAD's; the same binary must report the same test set"
fi

# ---------------------------------------------------------------------------
# Classify.
# ---------------------------------------------------------------------------
REGRESSIONS=()
DISCRIMINATED=()
UNATTRIBUTABLE=()
ONLY_BASE=()
ONLY_HEAD=()
CLEAN=0
COMPARABLE=0

for name in "${!R1[@]}"; do
    if [ -z "${R3[${name}]+set}" ]; then
        ONLY_BASE+=("${name}")
        continue
    fi
    # A base already red on its OWN corpus cannot attribute anything: that
    # failure predates the branch, so the row is excluded rather than counted as
    # a regression the branch caused.
    if [ "${R1[${name}]}" = "FAILED" ]; then
        UNATTRIBUTABLE+=("${name}")
        continue
    fi
    COMPARABLE=$((COMPARABLE + 1))
    if [ "${R3[${name}]}" = "FAILED" ]; then
        REGRESSIONS+=("${name}")
    elif [ "${R2[${name}]-}" = "FAILED" ]; then
        DISCRIMINATED+=("${name}")
    else
        CLEAN=$((CLEAN + 1))
    fi
done

for name in "${!R3[@]}"; do
    [ -z "${R1[${name}]+set}" ] && ONLY_HEAD+=("${name}")
done

# Zero comparable rows has two distinct causes and they point at different files,
# so they get different messages. Reporting one as the other sends the reader to
# the wrong place, which is most of the cost of a bad diagnostic.
if [ "${COMPARABLE}" -eq 0 ]; then
    if [ "${#UNATTRIBUTABLE[@]}" -ne 0 ]; then
        die 2 "every comparable row is UNATTRIBUTABLE (the base was already red against its own corpus); nothing was actually compared, so neither 'clean' nor 'regression' would be truthful"
    fi
    die 2 "no test name appears in BOTH the base and HEAD runs (${#ONLY_BASE[@]} base-only, ${#ONLY_HEAD[@]} HEAD-only); there is nothing to compare, so neither 'clean' nor 'regression' would be truthful"
fi

# ---------------------------------------------------------------------------
# Report.
# ---------------------------------------------------------------------------
printf '%s: base=%s (%s)  corpus=%s\n' "${LABEL}" "${BASE_SHA:0:12}" "${BASE_REF}" "${HEAD_CORPUS}"
# Disclosed on every run, because the worktree and its target dir are CACHED and
# nothing here ever removes them. An instrument that silently accretes gigabytes
# under a path the operator was never told about is its own kind of defect.
# Reclaim with: git worktree remove <path> && rm -rf <path>-target
printf '%s: base worktree %s (cached; set RS_BRANCH_DIFF_CACHE to relocate)\n\n' "${LABEL}" "${WT}"
printf '%-56s %-8s %-8s %-8s %s\n' "TEST" "R1base" "R2base" "R3HEAD" "VERDICT"
printf '%-56s %-8s %-8s %-8s %s\n' \
    "--------------------------------------------------------" \
    "------" "------" "------" "-------"

row() {
    # Bound to a local first: a libtest name can carry spaces (`foo - should
    # panic`), and reusing "$1" directly as a subscript reads badly enough that
    # it invites a later edit which does split it.
    local n="$1" verdict="$2"
    printf '%-56s %-8s %-8s %-8s %s\n' \
        "${n:0:56}" "${R1[${n}]-.}" "${R2[${n}]-.}" "${R3[${n}]-.}" "${verdict}"
}
for name in "${REGRESSIONS[@]+"${REGRESSIONS[@]}"}"; do row "${name}" "REGRESSION"; done
for name in "${DISCRIMINATED[@]+"${DISCRIMINATED[@]}"}"; do row "${name}" "DISCRIMINATED"; done
for name in "${UNATTRIBUTABLE[@]+"${UNATTRIBUTABLE[@]}"}"; do row "${name}" "UNATTRIBUTABLE"; done
for name in "${ONLY_BASE[@]+"${ONLY_BASE[@]}"}"; do row "${name}" "base-only (removed at HEAD)"; done
for name in "${ONLY_HEAD[@]+"${ONLY_HEAD[@]}"}"; do row "${name}" "HEAD-only (added by the branch)"; done
printf '\n%d clean row(s) not listed. Scenario announcements: R1=%d R2=%d R3=%d.\n' \
    "${CLEAN}" "${SCEN[1]}" "${SCEN[2]}" "${SCEN[3]}"

if [ "${#REGRESSIONS[@]}" -ne 0 ]; then
    printf '%s: REGRESSION (%d row(s)); HEAD diverges where base %s did not: %s\n' \
        "${LABEL}" "${#REGRESSIONS[@]}" "${BASE_SHA:0:12}" "${REGRESSIONS[*]}" >&2
    finish 1
fi

# A discrimination count of zero is reported loudly but is NOT a failure: a
# branch that did not touch this lane legitimately has none, and failing it here
# would fail every unrelated branch. What it means is that this lane's corpus
# growth, if any, would not have caught the code the base shipped.
printf '%s: OK (%d regressions, %d discriminated, %d scenarios against HEAD'"'"'s corpus)\n' \
    "${LABEL}" 0 "${#DISCRIMINATED[@]}" "${SCEN[3]}"
finish 0
