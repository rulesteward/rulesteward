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
# replay tests to accumulate instead of panicking at the first divergence, and is
# tracked as #681. No count is quoted here on purpose: the cost depends entirely
# on the counting rule (divergence sites in the replay path, all assertions in the
# file, assertions inside loops) and those differ by a factor of five, so #681
# carries the per-lane breakdown together with the rule it used.
#
# Exit codes (the dev-tooling contract, NOT the rulesteward binary's own):
#   0  no regressions; the success line carries a non-zero announcement count
#   1  one or more REGRESSION rows
#   2  tool/environment error, including "these two builds cannot be compared"
#
# THERE IS DELIBERATELY NO rc 3. This is an OFFLINE-tier instrument: no docker,
# no root, no live oracle, so per CONTRIBUTING's differential contract it has no
# legitimate precondition to skip on. Inventing one would rebuild #572, where
# `just diff-fapolicyd` exited 0 with a skip message on every run while checking
# nothing, from the 2026-07-13 NFS rebuild that destroyed its corpus until the
# recipe was retired on 2026-07-25: 12 days. Its self-test asserts no case ever yields 3.

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

# Declared up here, not at the classification step, because `finish` reads
# DISCRIMINATED to decide whether to keep the evidence and every early `die`
# reaches `finish` long before classification runs. Under `set -u` an undeclared
# array there would abort with an expansion error instead of the real diagnosis.
REGRESSIONS=()
DISCRIMINATED=()
UNATTRIBUTABLE=()
ONLY_BASE=()
ONLY_HEAD=()

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
# Evidence is retained on every rc EXCEPT a genuinely uneventful clean run.
#
# `rm -rf` on rc 0 alone deleted the logs for the DISCRIMINATED case, which is rc
# 0 and is this instrument's entire reason for existing: the run that says "your
# new corpus catches the old code" was throwing away the only record of WHICH
# assertion diverged and how. For the documented per-round ATL use, R2's stderr
# is the artifact you actually want.
finish() {
    local rc="$1"
    if [ "${rc}" -eq 0 ] && [ "${#DISCRIMINATED[@]}" -eq 0 ]; then
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
# stderr is CAPTURED, not discarded. `2>/dev/null` here sent the operator to
# inspect their ref for what was actually an environment failure: `GIT_DIR`
# pointing at a non-repository, or a `safe.directory` refusal, which is routine on
# the NFS worktrees this project uses. Both produce "cannot resolve base ref",
# and the retained evidence directory was then empty because the reason had gone
# to /dev/null.
if ! BASE_SHA="$(git rev-parse --verify "${BASE_REF}^{commit}" 2>"${WORK}/rev-parse.err")"; then
    tail -5 "${WORK}/rev-parse.err" >&2
    die 2 "cannot resolve base ref '${BASE_REF}' to a commit (git's own message is above)"
fi
# A `rev-parse` that succeeds while printing nothing would leave every path below
# built from an empty sha, which resolves to the cache root itself.
[ -n "${BASE_SHA}" ] || die 2 "cannot resolve base ref '${BASE_REF}' to a commit (git printed nothing)"

# THERE MUST BE SOMETHING TO VARY.
#
# This driver's whole premise is two DIFFERENT builds. Given a base ref that
# resolves to the working tree's own commit, it happily builds the same source
# twice, compares it with itself, and prints `OK (0 regressions, 0 discriminated,
# 228 scenarios)`. Every anti-vacuity guard passes on that run: the sentinels fire
# with the exact paths, the counts are healthy, the tables reconcile with libtest.
# It is a green line carrying real-looking evidence for a comparison that compared
# nothing, which is #572 wearing a different hat, and `just diff-<lane>-branch HEAD`
# reaches it in one step.
#
# A DIRTY tree at the same sha is a different and legitimate case: "diff my
# uncommitted work against the commit I am sitting on". Only the clean-tree
# coincidence is refused.
if ! HEAD_SHA="$(git rev-parse --verify "HEAD^{commit}" 2>"${WORK}/rev-parse-head.err")"; then
    tail -5 "${WORK}/rev-parse-head.err" >&2
    die 2 "could not resolve HEAD to a commit; cannot confirm the base differs from this tree"
fi
# `-uno`: UNTRACKED files are not part of the build and must not count as
# "dirty". Without it a single stray untracked path silently disabled this whole
# guard - caught by running it on what looked like a clean tree and getting rc 0,
# because `?? .serena/` was enough to make the tree read as modified. A guard that
# has never been observed firing is not known to be a guard.
# Two different shas can still produce two identical binaries. The guard's own
# message has always claimed "identical SOURCES"; testing sha equality was a
# narrower question that let the sibling case through. Measured on this branch:
# `diff-sudoers-branch 31ad4564` from 744bded differs only under `scripts/`, so
# `crates/` is byte-identical, and the driver built the same source twice and
# reported `OK (0 regressions, 0 discriminated, 362 ...)` at rc 0.
#
# `--quiet` exits 0 when there is NO difference. rc 1 means they differ (proceed);
# anything else is git failing, and "git could not say" must not become "they
# differ", so it is refused.
#
# RESIDUE, stated rather than papered over: this compares the whole of `crates/`,
# not the specific lane's dependency closure. `just diff-sudoers-branch <ref>`
# where <ref> differs only in `crates/rulesteward-selinux/` still varies nothing
# for the sudoers binary and will not be caught here. Narrowing it to the lane's
# closure needs a cargo-metadata walk; that is a design decision, not an oversight.
same_sources=0
if [ "${BASE_SHA}" = "${HEAD_SHA}" ]; then
    same_sources=1
else
    git diff --quiet "${BASE_SHA}" "${HEAD_SHA}" -- crates/ Cargo.toml Cargo.lock 2>"${WORK}/tree-diff.err"
    tree_rc=$?
    case "${tree_rc}" in
    0) same_sources=1 ;;
    1) ;;
    *)
        tail -5 "${WORK}/tree-diff.err" >&2
        die 2 "could not compare the base and HEAD trees (git diff exited ${tree_rc}); refusing to assume they differ"
        ;;
    esac
fi
# The dirty check is scoped to the SAME paths as the tree comparison above.
# Scanning the whole tree while comparing only crates/ was inconsistent: an
# uncommitted edit under scripts/ made the tree read as "varying" when the two
# binaries were still byte-identical, so the guard silently stood down. Found by
# running it - the identical-tree witness returned rc 0 because this file itself
# was uncommitted at the time.
if [ "${same_sources}" -eq 1 ] && [ -z "$(git status --porcelain -uno -- crates/ Cargo.toml Cargo.lock)" ]; then
    die 2 "base ref '${BASE_REF}' (${BASE_SHA:0:12}) and this tree carry identical sources under crates/, Cargo.toml and Cargo.lock, and the tree has no uncommitted changes, so both builds would come from identical sources; there is nothing to vary and a verdict from that run would mean nothing"
fi

# ---------------------------------------------------------------------------
# Cached detached worktree at the base sha.
#
# Keyed BY SHA and reused, because the Adversarial Testing Loop runs this every
# round against the same fork point.
#
# #661 records the ancestor's actual cause of death, and it was NOT cost: "the
# sweep lived entirely inside a subagent's turn. Nothing in the repo or the rules
# named it, so it could not be re-run." Build cost is risk 2 in that issue, which
# is prospective ("IF a round becomes too slow to run, it dies the same death").
# Caching is how this design answers that risk; it is not a post-mortem.
#
# CACHE_ROOT defaults to TMPDIR, which is ORDINARILY /tmp. No `just` recipe sets
# TMPDIR, so a plain `just diff-<lane>-branch <ref>` puts ~180 MB per lane per sha
# on the per-UID tmpfs quota - the thing that fills while `df` reports the
# filesystem and looks healthy, and every shell then dies. Set
# RS_BRANCH_DIFF_CACHE to somewhere off tmpfs before running this repeatedly.
# ---------------------------------------------------------------------------
CACHE_ROOT="${RS_BRANCH_DIFF_CACHE:-${TMPDIR:-/tmp}}/rs-branch-diff"
WT="${CACHE_ROOT}/${BASE_SHA}"
BASE_TARGET_DIR="${CACHE_ROOT}/target-${BASE_SHA}"

if [ ! -d "${WT}" ]; then
    mkdir -p "${CACHE_ROOT}" || die 2 "could not create the worktree cache root ${CACHE_ROOT}"
    # Self-heal a registration left behind by a swept /tmp: git refuses to re-add a
    # path it still has registered but that no longer exists.
    #
    # GATED on the cache ROOT existing, and that gate is the whole point. `prune`
    # deregisters every worktree whose path is currently unreachable, and this
    # project's cache lives on an NFS mount - so running it unconditionally meant
    # that one invocation while /mnt was down would deregister every OTHER cached
    # worktree too, permanently (`fatal: not a git repository` thereafter, even
    # once the mount returns). git's own manual names this exact hazard and its
    # remedy: "If the working tree ... is stored on a portable device or network
    # share which is not always mounted, you can prevent its administrative files
    # from being pruned by issuing the `git worktree lock` command." So: prune only
    # when the cache root is actually present, and LOCK what we create.
    if [ -d "${CACHE_ROOT}" ]; then
        git worktree prune --verbose >"${WORK}/worktree-prune.log" 2>&1
        prune_rc=$?
        if [ "${prune_rc}" -ne 0 ]; then
            tail -10 "${WORK}/worktree-prune.log" >&2
            die 2 "git worktree prune exited ${prune_rc}; refusing to continue with an unknown registration state"
        fi
    fi
    git worktree add --detach "${WT}" "${BASE_SHA}" >"${WORK}/worktree.log" 2>&1
    wt_rc=$?
    if [ "${wt_rc}" -ne 0 ]; then
        tail -20 "${WORK}/worktree.log" >&2
        die 2 "could not create the base worktree at ${WT} (git worktree add exited ${wt_rc})"
    fi
    # git's documented remedy for a worktree on a share that is not always
    # mounted. Advisory only, and deliberately non-fatal: failing to lock is not a
    # reason to refuse a comparison, but leaving it unlocked is how an unrelated
    # `prune` silently deregisters the cache.
    git worktree lock "${WT}" >/dev/null 2>&1 || true
fi

# VALIDATE THE CACHE, every run, including the run that just created it.
#
# Directory existence was the entire reuse predicate, and the cache is a live,
# writable checkout that this driver deliberately keeps for the whole life of a
# branch ("the ATL runs this every round against the same fork point"). Nothing
# stopped it drifting from the sha it is named after, while the report kept
# printing `base=<sha>` as though it had not.
#
# Two ways that goes wrong, both reproduced against the real driver: editing the
# cached tree's `src/` silently changes what "the base" means, and a
# hand-created directory at that path makes `git worktree add` never run at all,
# so even its failure is unobservable. In the worst version someone applies the
# branch's fix into the cached base while debugging, every DISCRIMINATED row
# evaporates, and the instrument reports "your new corpus proves nothing" at
# rc 0 - the exact inversion of its purpose.
#
# This is the driver's own standard applied to itself. It already refuses to
# interpret a run that did not announce the corpus it was handed; a base binary
# built from an unverified tree deserves no more trust.
wt_sha="$(git -C "${WT}" rev-parse --verify HEAD 2>"${WORK}/wt-verify.err")"
if [ -z "${wt_sha}" ]; then
    tail -5 "${WORK}/wt-verify.err" >&2
    die 2 "the cached base worktree ${WT} is not a git checkout; remove it and re-run"
fi
if [ "${wt_sha}" != "${BASE_SHA}" ]; then
    die 2 "the cached base worktree ${WT} is at ${wt_sha:0:12}, not the requested base ${BASE_SHA:0:12}; refusing to report a comparison against a sha nothing established (remove that directory to rebuild it)"
fi
# NO `-uno` HERE, and that is the opposite of the nothing-to-vary guard above.
#
# The two checks ask different questions of the same command. Up there the
# question is "would these two commits BUILD differently", and an untracked file
# is not a build input, so `-uno` is right. Here the question is "is this worktree
# still the base", and the corpus is enumerated with `std::fs::read_dir` (see
# every lane's `scenarios()` / `target_files()`), which does not consult git at
# all. An UNTRACKED scenario directory dropped into the cached base worktree is
# therefore part of the base's replay input.
#
# Measured: copying one untracked scenario dir into the cached base's corpus
# turned `2 discriminated, rc 0` into `0 discriminated, rc 0` with this guard
# silent - the instrument reporting "your new corpus proves nothing" when it
# proves everything. A previous commit applied "the identical fix" to both sites;
# that sentence was the defect.
#
# rc is CHECKED and stderr CAPTURED: a `git status` that FAILS (corrupt index,
# safe.directory refusal on the NFS cache) prints nothing, and "git could not say"
# is not "the tree is clean".
wt_dirty="$(git -C "${WT}" status --porcelain 2>"${WORK}/wt-status.err")"
wt_status_rc=$?
if [ "${wt_status_rc}" -ne 0 ]; then
    tail -5 "${WORK}/wt-status.err" >&2
    die 2 "could not read the cached base worktree's status (git exited ${wt_status_rc}); refusing to treat 'git could not say' as 'the tree is clean'"
fi
if [ -n "${wt_dirty}" ]; then
    printf '%s\n' "${wt_dirty}" | head -10 >&2
    die 2 "the cached base worktree ${WT} has uncommitted changes, so the binary built from it is not ${BASE_SHA:0:12}; remove that directory to rebuild it"
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
    # NOTE: the "no announcement at all" case is judged AFTER the per-test table
    # is parsed, because whether it is vacuous depends on whether anything failed.
    # See the count_seen check below the summary cross-check.

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

    # The scenario count is required on a GREEN run, and ONLY there.
    #
    # Its job is anti-vacuity: when nothing failed, "nothing fired" and "nothing
    # ran" are the same transcript, and only a non-zero comparison count tells
    # them apart. A run that FAILED is not in that position - it has failing rows,
    # already reconciled against libtest's own tally, which is direct evidence it
    # executed.
    #
    # Demanding it unconditionally broke this instrument's own payload case, and
    # the reason generalises. Three of the four lanes announce the count AFTER
    # parsing the corpus; only sudoers obeys the invariant its own `announce` doc
    # states ("call this FIRST, before anything that could panic, with a fixed
    # count known upfront"). So when the base binary chokes on HEAD's GROWN corpus
    # during enumeration - exactly the R2-FAILED signal this driver exists to
    # report - it never reaches the announcement, and an unconditional guard
    # turned a DISCRIMINATED row into rc 2. Measured by running the real auditd
    # and selinux binaries against an override tree carrying one scenario the base
    # cannot parse.
    #
    # The BANNER stays mandatory for every run regardless: it is what proves which
    # corpus was read, and nothing else can establish that.
    if [ "${rc}" -eq 0 ] && [ "${count_seen}" -eq 0 ]; then
        die 2 "run R${run} passed but printed no '${SENTINEL}: scenarios=' line; for a green run 'nothing fired' and 'nothing ran' are the same transcript, so the count cannot be confirmed non-zero"
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
# Equal SIZE is not equal SET. Two same-size, differently-keyed tables passed the
# check above, and a name present in R1 but absent from R2 then read as CLEAN via
# the `${R2[...]-}` default at the classification step. Same cardinality plus
# total containment is set equality.
for name in "${!R1[@]}"; do
    [ -n "${R2[${name}]+set}" ] || die 2 "the base binary reported test '${name}' against the base corpus but not against HEAD's; the same binary must report the same test set"
done

# ---------------------------------------------------------------------------
# Classify.
# ---------------------------------------------------------------------------
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

ONLY_HEAD_FAILING=()
for name in "${!R3[@]}"; do
    if [ -z "${R1[${name}]+set}" ]; then
        # Split by verdict. A test the branch ADDED and left RED is not a neutral
        # "added by the branch" note: it has no base counterpart, so it cannot be
        # a REGRESSION by this driver's definition, but reporting it under the
        # same reassuring label as a passing addition is how a red new test rode
        # out at rc 0.
        if [ "${R3[${name}]}" = "FAILED" ]; then
            ONLY_HEAD_FAILING+=("${name}")
        else
            ONLY_HEAD+=("${name}")
        fi
    fi
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
# under a path the operator was never told about is its own kind of defect - and
# the first version of this very line got the reclaim path wrong, telling the
# operator to delete `<path>-target` when the directory is `target-<sha>`. Both
# paths are interpolated now rather than described, so they cannot drift again.
# Measured: 24 MB worktree + 157 MB target dir for ONE lane at ONE sha.
printf '%s: base worktree %s (cached)\n' "${LABEL}" "${WT}"
printf '%s: reclaim with: git worktree remove %s && rm -rf %s\n\n' "${LABEL}" "${WT}" "${BASE_TARGET_DIR}"
printf '%-56s %-8s %-8s %-8s %s\n' "TEST" "R1base" "R2base" "R3HEAD" "VERDICT"
printf '%-56s %-8s %-8s %-8s %s\n' \
    "--------------------------------------------------------" \
    "------" "------" "------" "-------"

row() {
    # Bound to a local first. A Rust test path cannot contain a space, but libtest
    # APPENDS ` - should panic` to the printed name, and this driver's key is the
    # printed form - so keys really do contain spaces. Reusing "$1" directly as a
    # subscript reads badly enough that it invites a later edit which splits it.
    local n="$1" verdict="$2"
    printf '%-56s %-8s %-8s %-8s %s\n' \
        "${n:0:56}" "${R1[${n}]-.}" "${R2[${n}]-.}" "${R3[${n}]-.}" "${verdict}"
}
for name in "${REGRESSIONS[@]+"${REGRESSIONS[@]}"}"; do row "${name}" "REGRESSION"; done
for name in "${DISCRIMINATED[@]+"${DISCRIMINATED[@]}"}"; do row "${name}" "DISCRIMINATED"; done
for name in "${UNATTRIBUTABLE[@]+"${UNATTRIBUTABLE[@]}"}"; do row "${name}" "UNATTRIBUTABLE"; done
for name in "${ONLY_BASE[@]+"${ONLY_BASE[@]}"}"; do row "${name}" "base-only (removed at HEAD)"; done
for name in "${ONLY_HEAD[@]+"${ONLY_HEAD[@]}"}"; do row "${name}" "HEAD-only (added by the branch)"; done
for name in "${ONLY_HEAD_FAILING[@]+"${ONLY_HEAD_FAILING[@]}"}"; do row "${name}" "HEAD-only and FAILING"; done
printf '\n%d clean row(s) not listed. Scenario announcements: R1=%d R2=%d R3=%d.\n' \
    "${CLEAN}" "${SCEN[1]}" "${SCEN[2]}" "${SCEN[3]}"

# A test the branch added and left RED is a failure of the branch even though it
# has no base counterpart to regress against. Silence here would let `just test`
# be the only thing standing between it and a merge.
if [ "${#ONLY_HEAD_FAILING[@]}" -ne 0 ]; then
    printf '%s: %d test(s) exist only at HEAD and are FAILING: %s\n' \
        "${LABEL}" "${#ONLY_HEAD_FAILING[@]}" "${ONLY_HEAD_FAILING[*]}" >&2
    finish 1
fi

if [ "${#REGRESSIONS[@]}" -ne 0 ]; then
    printf '%s: REGRESSION (%d row(s)); HEAD diverges where base %s did not: %s\n' \
        "${LABEL}" "${#REGRESSIONS[@]}" "${BASE_SHA:0:12}" "${REGRESSIONS[*]}" >&2
    finish 1
fi

# The rc-0 contract, restated in this file's header, in the justfile and in
# CONTRIBUTING: a success line MUST carry a non-zero count.
#
# Placed LAST, so it guards the OK path and only that path. The per-run count
# requirement in validate_run is green-run-only (a red run has failing rows as its
# evidence instead), which left the OK line reachable with SCEN[3] = 0 when the
# run was red for a reason outside the comparison. A real failure above must be
# reported as itself, not converted into "no announcements".
if [ "${SCEN[3]}" -eq 0 ]; then
    die 2 "about to report OK, but no run announced a scenario count; the rc-0 contract requires the success line to carry a non-zero count, and a clean verdict over zero announced comparisons is exactly the vacuous pass this instrument exists to refuse"
fi

# A discrimination count of zero is reported loudly but is NOT a failure: a
# branch that did not touch this lane legitimately has none, and failing it here
# would fail every unrelated branch. What it means is that this lane's corpus
# growth, if any, would not have caught the code the base shipped.
# `announcements`, not `scenarios`: SCEN[n] SUMS every `scenarios=` line, and a
# lane whose helper announces once per test emits several. selinux announces 3x69
# and would read "207 scenarios" for a 69-scenario corpus. The line above already
# calls these announcements; the two outputs used to contradict each other in one
# transcript, and the misleading one was what the rc contract pointed at.
printf '%s: OK (%d regressions, %d discriminated, %d scenario announcements in R3)\n' \
    "${LABEL}" 0 "${#DISCRIMINATED[@]}" "${SCEN[3]}"
finish 0
