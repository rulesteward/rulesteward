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
#   R2  base binary, THIS WORKING TREE's corpus        (does the growth discriminate?)
#   R3  HEAD binary, THIS WORKING TREE's corpus        (does HEAD still agree?)
#
# "working tree", not "committed", and the distinction is not pedantry. R2 and R3
# read `${REPO_ROOT}/${CORPUS_SUBPATH}` and R3's binary is built from
# `${REPO_ROOT}`, so uncommitted work is INCLUDED on both. That is deliberate: it
# is what makes "diff my uncommitted work against the commit I am sitting on" a
# supported mode. It is also why the nothing-to-vary guard below asks git a
# one-ref question; three earlier versions of this header said "committed" and a
# guard written to match that word compared a pair the driver never builds.
#
# EXHAUSTIVE over the verdicts libtest can report, and THE ROWS ARE TESTED IN
# ORDER: the first matching row wins. That ordering is not decoration. `R3 absent`
# is tested before anything else, so it takes precedence over the R1 column
# entirely - which is what made two rows of the previous version of this table
# false. That version said `FAILED * *` -> UNATTRIBUTABLE and `ignored * other`
# -> ignored-at-base, while the code classifies BOTH as base-only when the test is
# absent at HEAD. Round 5 added the word EXHAUSTIVE and a `*` legend to a table
# that already had that gap, which turned a quiet omission into a provable
# falsehood: asserting exhaustiveness without re-deriving it against the code is
# strictly worse than not asserting it. Three round-6 reviewers found it.
#
# `*` means the run's verdict does not affect the classification AT THAT ROW.
# `(absent, absent)` cannot occur - a name reaches this table from R1 or R3.
#
#   R1      R2      R3        verdict
#   *       *       absent    base-only      - removed at HEAD (rc 0; a rename is
#                                              indistinguishable from a deletion
#                                              at this granularity)
#   FAILED  *       present   UNATTRIBUTABLE - base was already red, excluded
#   ok      FAILED  ok        DISCRIMINATED  - the growth catches the old code
#   ok      ok      ok        clean          - this lane's corpus did not discriminate
#   ok      *       FAILED    REGRESSION     - HEAD diverges where the base did not
#   ok      *       ignored   SILENCED       - the base ran it, HEAD skips it (rc 1)
#   ignored *       FAILED    no baseline and FAILING - un-parked, left red (rc 1)
#   ignored *       ok        ignored at base - no baseline to compare, excluded
#   ignored *       ignored   ignored at base - no baseline to compare, excluded
#   absent  *       FAILED    no baseline and FAILING - added, left red (rc 1)
#   absent  *       ignored   HEAD-only and PARKED    - added already parked (rc 0)
#   absent  *       ok        HEAD-only      - added and passing (rc 0)
#
# The two `ignored` rows are asymmetric on purpose. A test the base RAN that HEAD
# skips is a loss of coverage and fails. A test the branch ADDS already parked is
# this repo's documented convention for pinning a known-open bug (#669/#677), so
# it gets its own label and passes.
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
#   1  one or more REGRESSION rows, a test with no baseline verdict left FAILING
#      at HEAD (added by the branch, or #[ignore]d at the base and un-parked), or
#      a test the base ran and PASSED that HEAD SILENCES with #[ignore]
#
#      Both halves of that sentence were wrong until round 7, and both for the
#      same reason: it was written in round 3 and the code moved underneath it.
#      Round 4 gave ONLY_HEAD_FAILING a second population (rows PRESENT at the
#      base, un-parked and left red), so "HEAD-only" stopped being true; and the
#      SILENCED arm sits behind the `R1 == FAILED` check, so a base row that ran
#      and FAILED is UNATTRIBUTABLE at rc 0 no matter what HEAD does with it.
#      The first half had already been repaired in the printf, the justfile and
#      CONTRIBUTING.md - this header was the fourth site and was never revisited,
#      with the ruling explaining why sitting 1000 lines below it in this file.
#   2  tool/environment error, including "these two builds cannot be compared"
#
# rc 1 is also what bash itself exits on a `set -u` unbound-variable abort, so a
# driver that dies mid-flight would be read as "the branch regressed". Nothing is
# known to reach that today, but the property is narrower than an earlier version
# of this line claimed: every array that `finish` or an early `die` can reach is
# declared in the block below, and every `[@]` VALUE expansion is `+`-guarded.
# `${#name[@]}` on a DECLARED array is safe unguarded, which is why the count
# expansions carry no `+`. A new array must therefore go in that block, not at its
# first use. The collision is real and the justfile gates on rc alone, so rc 1 is
# only meaningful ALONGSIDE the report line naming what failed; a bare rc 1 with
# no such line is a driver defect, not a verdict about the branch.
#
# THERE IS DELIBERATELY NO rc 3. This is an OFFLINE-tier instrument: no docker,
# no root, no live oracle, so per CONTRIBUTING's differential contract it has no
# legitimate precondition to skip on. Inventing one would rebuild #572, where
# `just diff-fapolicyd` exited 0 with a skip message on every run while checking
# nothing, from the 2026-07-13 NFS rebuild that destroyed its corpus until the
# recipe was retired on 2026-07-25: 12 days.
#
# Its self-test asserts that no case in its FIRST pass yields 3 (the suite scopes
# this correctly; an earlier version of this line dropped the scope). Exit codes
# from the positive-control phases, where the driver is deliberately sabotaged,
# are not covered and should not be.

set -uo pipefail

usage() {
    cat >&2 <<'EOF'
usage: bash scripts/rs-branch-diff.sh <lane> <base-ref>

  lane        auditd | selinux | sudoers | sysctld
  base-ref    any git revision (sha, tag, branch) to compare against

Replays THIS WORKING TREE's corpus, uncommitted work included, against a binary
built at <base-ref> and a binary built from this working tree, plus a baseline of
the base binary against the base tree's own corpus. Reports which rows this
lane's corpus growth newly discriminates against the old code, and which rows
HEAD regressed, silenced, or left failing with no baseline.
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
ONLY_HEAD_PARKED=()
ONLY_HEAD_FAILING=()
SILENCED=()
BASE_IGNORED=()

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
# resolves to the same sources this tree already carries, it happily builds the
# same source twice, compares it with itself, and prints `OK (0 regressions,
# 0 discriminated, ...)`. Every anti-vacuity guard passes on that run: the
# sentinels fire with the exact paths, the counts are healthy, the tables
# reconcile with libtest. It is a green line carrying real-looking evidence for a
# comparison that compared nothing, which is #572 wearing a different hat, and
# `just diff-<lane>-branch HEAD` reaches it in one step.
#
# ONE REF, NOT TWO, AND THE PAIR IS THE WHOLE POINT. This guard was repaired four
# times (sha equality, then untracked handling, then `-uno` placement, then a
# commit-to-commit tree compare) and every one of those repairs argued about how
# to compare BASE_SHA with the HEAD COMMIT. The driver does not build the HEAD
# commit. It builds the WORKING TREE (`cargo_in "${REPO_ROOT}" ""` below) and
# reads the working tree's corpus (`HEAD_CORPUS="${REPO_ROOT}/${CORPUS_SUBPATH}"`),
# so the only question that matters is whether the base COMMIT differs from this
# WORKING TREE. That is the one-ref form: `git diff <commit> -- <paths>`.
#
# The two-ref form reported OK at rc 0 on this instrument's own documented use
# case. `git checkout <base> -- crates/` is how an operator asks "would my new
# corpus really have caught the old code?"; it leaves the tree byte-identical to
# the base while the two COMMITS still differ, so the guard stood down and the
# driver compared a tree with itself. An in-flight `git stash` has the same shape.
#
# The one-ref form also SUBSUMES the two checks that used to sit beside it, which
# is why they are gone rather than moved:
#   - the `BASE_SHA = HEAD_SHA` special case. Equal shas plus a clean tree gives
#     rc 0 and is refused; equal shas plus a DIRTY tree gives rc 1 and proceeds,
#     which is the legitimate "diff my uncommitted work against the commit I am
#     sitting on" mode. The distinction now falls out of the comparison instead of
#     being re-derived by a second command.
#   - the `-uno` dirty scan. `git diff` compares TRACKED content only, so an
#     untracked path cannot make this tree read as varying. The `?? .serena/`
#     case that silently disabled the guard from 31ad456 until 744bded repaired it
#     cannot recur here, and the
#     unchecked `git status` rc that used to sit at the end of this block (where
#     "git could not say" became "the tree is clean") is gone with it.
#
# `--quiet` exits 0 when there is NO difference. rc 1 means they differ (proceed);
# anything else is git failing, and "git could not say" must not become "they
# differ", so it is refused.
#
# RESIDUE, stated rather than papered over, two of them:
#   - This compares the whole of `crates/`, not the specific lane's dependency
#     closure. `just diff-sudoers-branch <ref>` where <ref> differs only in
#     `crates/rulesteward-selinux/` still varies nothing for the sudoers binary
#     and will not be caught here. Narrowing it to the lane's closure needs a
#     cargo-metadata walk; that is a design decision, not an oversight.
#   - An UNTRACKED corpus scenario directory is invisible to `git diff`, so a
#     tree differing from the base ONLY by an untracked scenario is refused here
#     as "nothing to vary" when the corpora do in fact differ. That direction is
#     fail-closed (a refused comparison, never a false clean) and is the price of
#     asking git the build-input question; commit the scenario and it proceeds.
git diff --quiet "${BASE_SHA}" -- crates/ Cargo.toml Cargo.lock 2>"${WORK}/tree-diff.err"
tree_rc=$?
case "${tree_rc}" in
0)
    die 2 "base ref '${BASE_REF}' (${BASE_SHA:0:12}) and this WORKING TREE carry identical sources under crates/, Cargo.toml and Cargo.lock, so both builds would come from identical sources; there is nothing to vary and a verdict from that run would mean nothing"
    ;;
1) ;;
*)
    tail -5 "${WORK}/tree-diff.err" >&2
    die 2 "could not compare base ref '${BASE_REF}' against this working tree (git diff exited ${tree_rc}); refusing to assume they differ"
    ;;
esac

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

# Captured BEFORE the `mkdir -p` below, because the mkdir is what makes the answer
# useless. See the prune gate for why the ordering is the entire protection.
cache_root_existed=0
[ -d "${CACHE_ROOT}" ] && cache_root_existed=1

if [ ! -d "${WT}" ]; then
    mkdir -p "${CACHE_ROOT}" || die 2 "could not create the worktree cache root ${CACHE_ROOT}"
    # Self-heal a registration left behind by a swept /tmp: git refuses to re-add a
    # path it still has registered but that no longer exists.
    #
    # GATED on the cache root having existed BEFORE the mkdir above. `prune`
    # deregisters every worktree whose path is currently unreachable, and this
    # project's cache lives on an NFS mount - so running it unconditionally meant
    # that one invocation while /mnt was down would deregister every OTHER cached
    # worktree too, permanently (`fatal: not a git repository` thereafter, even
    # once the mount returns).
    #
    # The previous version of this gate tested `[ -d "${CACHE_ROOT}" ]` AFTER the
    # `mkdir -p` that creates it, so it could never be false and the protection
    # described here did not exist. With the mount down, `mkdir -p` succeeds
    # against the bare mountpoint and the gate waved the prune straight through.
    # Capture the answer before running the thing that changes it.
    if [ "${cache_root_existed}" -eq 1 ]; then
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
        # A LOCKED worktree whose directory has since been swept is the one case
        # the prune above cannot heal, because refusing to prune is exactly what
        # the lock is for. Without this retry the driver refuses that base sha
        # forever, with a message naming neither the cause nor the remedy.
        # git's manual gives the recovery verbatim: "To add a missing but locked
        # worktree path, specify --force twice." Only reached after a plain add
        # has already failed, so it cannot mask an ordinary failure.
        git worktree add --force --force --detach "${WT}" "${BASE_SHA}" \
            >>"${WORK}/worktree.log" 2>&1
        wt_rc=$?
    fi
    if [ "${wt_rc}" -ne 0 ]; then
        tail -20 "${WORK}/worktree.log" >&2
        die 2 "could not create the base worktree at ${WT} (git worktree add exited ${wt_rc}, including the --force --force retry that recovers a locked-but-missing registration)"
    fi
fi

# LOCKED OUTSIDE the creation branch, so every run re-asserts it.
#
# Inside that branch it reached only worktrees created by the same invocation, so
# a cache built before this line was added stayed unprotected forever. Measured on
# this repo while the lock was in the creation branch: two cache worktrees, many
# driver runs, and `git worktree list --porcelain | grep -c locked` returned 0. A
# protection that only ever applies to brand-new worktrees does not protect the
# cache it was added for.
#
# git's documented remedy for a worktree on a share that is not always mounted:
# "If the working tree ... is stored on a portable device or network share which
# is not always mounted, you can prevent its administrative files from being
# pruned by issuing the `git worktree lock` command."
#
# Advisory, and deliberately non-fatal: failing to lock is not a reason to refuse
# a comparison. It is NOT silent, though. The previous `|| true` meant there was
# no way to tell whether the protection had taken. Re-locking an already-locked
# worktree is the normal steady state and is not worth a word.
if ! git worktree lock "${WT}" >"${WORK}/worktree-lock.log" 2>&1; then
    if ! grep -qF 'already locked' "${WORK}/worktree-lock.log"; then
        printf '%s: warning: could not lock the cached worktree %s, so an unrelated "git worktree prune" while the mount is down can deregister it\n' \
            "${LABEL}" "${WT}" >&2
        tail -3 "${WORK}/worktree-lock.log" >&2
    fi
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

# CAN GIT SEE THIS TREE AT ALL? A precondition for BOTH `status` calls below,
# which is why it is asked first: each of them reports what git can see, and
# neither can report what git has been told to stop looking at.
#
# `core.ignoreStat` is a documented performance knob, motivated in git-config(1)
# by "systems where lstat() calls are very slow, such as CIFS" - the family this
# project's mandated NFS worktree cache belongs to, so it is a plausible thing
# for an operator to have set. When it is true AT `git worktree add` TIME, git
# burns the assume-unchanged bit into the NEW linked worktree's own index. A
# tracked file modified afterwards is then invisible to `status`: ZERO BYTES at
# rc 0, so neither the rc guard nor the `-n` guard below fires. Git said nothing
# SUCCESSFULLY, which is round 9's `status.showUntrackedFiles` finding reached by
# a second mechanism.
#
# Measured on git 2.55.0, one tracked file modified inside a linked worktree:
#
#   ignoreStat unset at add time  -> status ` M src/main.rs`   ls-files `H`
#   ignoreStat true  at add time  -> status ZERO BYTES rc 0    ls-files `h`
#
# THE REASON THIS IS NOT ANOTHER PINNED FLAG, unlike `-unormal` below. The bit is
# STATE, not configuration: it is written into the index once, at add time, and
# read from there forever after. Both measured on the already-built worktree:
#
#   git config --unset core.ignoreStat        -> still ZERO BYTES
#   git -c core.ignoreStat=false ... status   -> still ZERO BYTES
#
# So no flag at either `status` call site can undo it, and pinning the config at
# `worktree add` would protect only caches created afterwards - the identical
# failure this file already records at the `worktree lock` call above, where a
# cache built before the line was added stayed unprotected forever.
#
# It is also not the only route to these two bits. `git sparse-checkout` sets
# `skip-worktree`, which produces byte-identical blindness (`ls-files` flag `S`,
# status ZERO BYTES at rc 0), and a hand-run `git update-index --assume-unchanged`
# needs no config at all. So this guard is agnostic about HOW either bit was set,
# which is what guarding `core.ignoreStat` by name would not be.
#
# IT IS NOT AGNOSTIC ABOUT WHICH BITS IT READS, and an earlier version of this
# sentence claimed it was. `git update-index --help` exposes THREE per-entry
# suppression bits, and `git ls-files --help` names their flags on adjacent lines:
#
#   -v   use lowercase letters for 'assume unchanged' files
#   -f   use lowercase letters for 'fsmonitor clean' files
#
# `-v` covers assume-unchanged; `S` in the base tag set covers skip-worktree;
# NOTHING in `-v`'s output can express `CE_FSMONITOR_VALID`. That third bit is
# handled by the `-c core.fsmonitor=` pins on the two `status` calls below,
# because it is re-derived per run rather than burned into the index.
#
# `-f` IS NOT THE ANSWER HERE, measured rather than assumed: on a CLEAN worktree
# with a healthy fsmonitor, `ls-files -f` lowercases EVERY tracked entry (3 of 3
# on the fixture, 11 of 11 on another), so a `-v -f` guard would `die 2` on every
# run for any fsmonitor user - the deterministic-denial shape this file rejects
# two paragraphs down. Recorded so a later round does not "fix" this the obvious
# way.
#
# `ls-files -v` flags: uppercase `H` is the normal cached entry; any LOWERCASE
# letter means assume-unchanged, and `S` means skip-worktree. Measured across the
# three fixtures: 0 suppressed entries on a healthy worktree, 1 under
# `core.ignoreStat`, 1 under `skip-worktree`.
wt_lsfiles="$(git -C "${WT}" ls-files -v 2>"${WORK}/wt-lsfiles.err")"
wt_lsfiles_rc=$?
if [ "${wt_lsfiles_rc}" -ne 0 ]; then
    tail -5 "${WORK}/wt-lsfiles.err" >&2
    die 2 "could not read the cached base worktree's index flags (git exited ${wt_lsfiles_rc}); refusing to treat 'git could not say' as 'git can see this tree'"
fi
# EMPTY IS NOT CLEAN, and this guard would otherwise re-create the exact defect it
# was added to close: a zero count out of a zero-line answer reads as "nothing is
# suppressed" when it means "nothing was examined".
if [ -z "${wt_lsfiles}" ]; then
    die 2 "the cached base worktree ${WT} reports no tracked files at all, so an index-flag check over it would pass vacuously; that is a broken worktree, not a clean one (remove that directory to rebuild it)"
fi
wt_suppressed="$(printf '%s\n' "${wt_lsfiles}" | grep -cE '^[a-z]|^S' || true)"
if [ "${wt_suppressed}" -ne 0 ]; then
    printf '%s\n' "${wt_lsfiles}" | grep -E '^[a-z]|^S' | head -10 >&2
    die 2 "the cached base worktree ${WT} has index entries marked assume-unchanged or skip-worktree (${wt_suppressed} of them, listed above), so \`git status\` cannot see a modified tracked file there and the two cleanliness checks below would pass on a contaminated tree; the binary built from it may not be ${BASE_SHA:0:12} (remove that directory to rebuild it)"
fi

# NO `-uno` HERE, and the reason is not the one an earlier version of this comment
# gave. It described the nothing-to-vary guard as a `git status --porcelain -uno`
# scan and called this site "the opposite" of it. Round 3 replaced that guard with
# a one-ref `git diff`, which has no `-uno` flag at all, so all three of that
# comment's claims went stale at once. Round 4 repaired the suite's copy of the
# same claim and not this one.
#
# The two checks use DIFFERENT COMMANDS to ask different questions. Up there the
# question is "would the base COMMIT and this WORKING TREE build differently", and
# `git diff` answers it over tracked content by construction, so no untracked
# handling arises. Here the question is "is this worktree
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
#
# `-unormal` IS PINNED, on this call and on the `--ignored` one below, because
# neither question survives `status.showUntrackedFiles=no`. That is a documented
# performance knob, and it is honoured from `~/.gitconfig`,
# `$XDG_CONFIG_HOME/git/config`, `/etc/gitconfig` and the MAIN CLONE's
# `.git/config` - which reaches every cached worktree here for the same reason
# `.git/info/exclude` does, since config resolves through the common dir. All
# unversioned, exactly like the exclude files the `--ignored` guard below exists
# for.
#
# Measured on git 2.55.0, one worktree contaminated three ways at once (a tracked
# modification, an untracked scenario dir, and an ignored-name scenario dir):
#
#   default config          -> ` M src/main.rs` + `?? corpus/zz-untracked/`
#   showUntrackedFiles=no   -> ` M src/main.rs`                    <- ?? LOST
#   ...and the --ignored call below, under that same config, returns ZERO BYTES:
#   it loses the ignored half AND the untracked half, because with `-uno` git
#   does not walk untracked directories at all and so cannot find the ignored
#   ones inside them.
#
# Both calls then return empty AT RC 0, so neither rc guard helps: git said
# nothing SUCCESSFULLY. That is the precise inversion of the sentence in the
# `--ignored` guard's own `die` below ("refusing to treat 'git could not say' as
# 'the corpus is uncontaminated'"), and it is #572's shape - a harness reporting
# success while checking nothing.
#
# It does NOT re-open the widening this file rejects. Measured with a `target/`
# present and default config: `--porcelain` and `--porcelain -unormal` are
# byte-identical and both silent, while whole-tree `--porcelain --ignored` prints
# `!! target/`. `-unormal` restores what the config suppressed; it does not add a
# question.
#
# `-c core.fsmonitor=` IS PINNED for a THIRD mechanism, found in round 11 and
# distinct from both of the above. `core.fsmonitor` names a file-system monitor
# (a hook, or the builtin daemon) that git asks "what changed?" instead of
# stat-ing the tree. When the monitor UNDER-REPORTS - its documented failure
# mode, and what a watchman watch scoped to the main clone does when asked about
# a linked worktree, which is exactly the topology this driver creates - git
# marks the entries fsmonitor-clean and `status` returns ZERO BYTES at rc 0 with
# a tracked file modified on disk.
#
# Measured on git 2.55.0 with a v2 hook returning an empty change list:
#
#   contaminated, no fsmonitor       -> ` M src/f3.rs`
#   contaminated, fsmonitor primed   -> ZERO BYTES rc 0      <- the fail-open
#   same tree, -c core.fsmonitor=    -> ` M src/f3.rs`       <- the remedy
#
# This is round 9's shape and NOT round 10's, which is why it is a flag here and
# an index-flag read up there: the fsmonitor bit is RE-DERIVED each run, so a
# call-site override cures it, whereas `core.ignoreStat`'s bit is written into
# the index once and survives any flag. The two remedies are not interchangeable
# and neither replaces the other.
#
# It suppresses ONLY the ` M` row; `??` and `!!` still appear. The pin is
# repeated on the `--ignored` call below for consistency, but see the note there
# about why only this one is separately controlled.
wt_dirty="$(git -C "${WT}" -c core.fsmonitor= status --porcelain -unormal 2>"${WORK}/wt-status.err")"
wt_status_rc=$?
if [ "${wt_status_rc}" -ne 0 ]; then
    tail -5 "${WORK}/wt-status.err" >&2
    die 2 "could not read the cached base worktree's status (git exited ${wt_status_rc}); refusing to treat 'git could not say' as 'the tree is clean'"
fi
if [ -n "${wt_dirty}" ]; then
    printf '%s\n' "${wt_dirty}" | head -10 >&2
    die 2 "the cached base worktree ${WT} has uncommitted changes, so the binary built from it is not ${BASE_SHA:0:12}; remove that directory to rebuild it"
fi

# SECOND CHECK, and the paragraph above is worth much less without it.
#
# `git status --porcelain` OMITS IGNORED PATHS (git-status(1): `--ignored` is what
# "show ignored files as well" takes). The comment above is therefore correct about
# `read_dir` and still under-implemented: `read_dir` does not consult git, which is
# exactly as true of an IGNORED path as of an untracked one, and only the untracked
# half was ever checked.
#
# Measured on git 2.55.0, in a throwaway repo whose `.gitignore` is one line
# reading `docs`, with a scenario dir dropped in as `corpus/docs/`:
#
#   git status --porcelain            -> ZERO bytes      <- the guard's whole input
#   git status --porcelain --ignored  -> !! corpus/docs/
#   ls corpus/                        -> docs  real      <- what read_dir sees
#
# Reproduced end to end against the real driver: the SAME directory named
# `zz-adversary-probe` gives rc 2, and named `docs` gives rc 0 with `0
# discriminated`, because the contaminating scenario turns R1 red for exactly the
# tests that would otherwise have been DISCRIMINATED. That is the identical
# inversion the paragraph above records, reached by a different route.
#
# The load-bearing point is NOT that anyone will name a scenario `docs`. It is that
# a fail-closed guard's coverage would otherwise be decided by `.gitignore` - which
# carries NINE bare unanchored names matching at any depth (`debug`, `target`,
# `rust_out`, `librust_out.rlib`, `.claude`, `.private-docs`, `.rtk`, `.wolf`,
# `docs`), and which is extended per-developer through `.git/info/exclude` and
# `$XDG_CONFIG_HOME/git/ignore`, both unversioned. `rev-parse --git-common-dir`
# resolves to the main clone, so a local exclude there applies inside every cached
# worktree. Adding a tenth bare name is a one-line change nobody would connect to a
# differential instrument's false-clean surface.
#
# SCOPED to the corpus, and the whole-tree check above is deliberately NOT given
# `--ignored`. Widening that one instead would make a `target/` left behind by any
# manual `cargo build` inside the cached worktree read as "uncommitted changes",
# locking that base sha out at rc 2 until an operator deleted it - the same
# deterministic-denial shape round 4 routed as a defect. Narrowing it instead would
# drop detection of a modified tracked `src/` file, which builds a WRONG BASE BINARY
# and is worse than corpus contamination. Two questions, two commands: the tree
# must be clean, and the replay input must contain nothing git is not tracking.
# `-unormal` for the reason given at the whole-tree call above, which bites HARDER
# here: under `status.showUntrackedFiles=no` this call returns ZERO BYTES at rc 0,
# losing both the `!!` rows it is here for and the `??` rows the call above would
# otherwise have caught.
# `-c core.fsmonitor=` for the reason given at the whole-tree call, with ONE
# honest qualification: this pin gets no positive control of its own, and that is
# a deliberate ruling rather than an oversight. This call is SCOPED to the corpus
# and the call above is not, so the tree it examines is a SUBSET: any ` M` row
# fsmonitor could hide from this call is also hidden from that one, where the
# guard fires first. Its absence therefore cannot produce a false clean, which is
# the bar standing ruling 3 sets. Modelling one in the stub would mean modelling
# a transcript real git cannot emit, which is the mistake round 7 recorded.
wt_ignored="$(git -C "${WT}" -c core.fsmonitor= status --porcelain --ignored -unormal -- "${CORPUS_SUBPATH}" 2>"${WORK}/wt-ignored.err")"
wt_ignored_rc=$?
if [ "${wt_ignored_rc}" -ne 0 ]; then
    tail -5 "${WORK}/wt-ignored.err" >&2
    die 2 "could not read the cached base worktree's ignored-path status (git exited ${wt_ignored_rc}); refusing to treat 'git could not say' as 'the corpus is uncontaminated'"
fi
if [ -n "${wt_ignored}" ]; then
    printf '%s\n' "${wt_ignored}" | head -10 >&2
    die 2 "the cached base worktree's corpus (${WT}/${CORPUS_SUBPATH}) contains path(s) git is ignoring; the lanes enumerate it with read_dir, which ignores nothing, so the base would replay a corpus that is not ${BASE_SHA:0:12}'s (remove that directory to rebuild it)"
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

    # stderr is CAPTURED, not discarded, and this file's header names the reason:
    # a `2>/dev/null` here once sent the operator to inspect their ref for what was
    # actually an environment failure, and the retained evidence directory was
    # empty because the only explanation had gone to /dev/null. This is the one
    # path where the message IS the whole diagnosis - the rc alone says a build
    # that had just succeeded has now failed, which is not a story the operator
    # can act on. Kept out of ${logj}, which is parsed for the artifact JSON.
    cargo_in "${dir}" "${tdir}" test -p "${PKG}" --test "${TEST_TARGET}" --locked --no-run \
        --message-format=json >"${logj}" 2>"${logj}.err"
    local json_rc=$?
    if [ "${json_rc}" -ne 0 ]; then
        RESOLVE_ERR="cargo --message-format=json exited ${json_rc} on a build that had just succeeded; cargo said: $(tail -3 "${logj}.err" | tr '\n' ' ')"
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

# validate_run <run 1|2|3> <stdout> <stderr> <corpus handed in> <exit code>
#
# Every guard here runs BEFORE any verdict is read out of the log, because each
# one describes a way the run's exit code and table can be entirely meaningless.
validate_run() {
    local run="$1" out="$2" err="$3" want_corpus="$4" rc="$5"
    # A nameref onto the global R1 / R2 / R3 for this run.
    local -n results="R${run}"

    # DID ANY TEST BODY RUN? The two announcement guards below both assume one
    # did, and that assumption is false for a lane whose replay tests are all
    # `#[ignore]`d.
    #
    # Every lane resolves its corpus inside a `#[test]` fn (via `corpus_root()` or
    # `scenarios()`), so a parked test announces NOTHING. Measured on rustc 1.97.0
    # rather than recalled: a binary whose every test is `#[ignore]`d prints a
    # complete per-test table, emits `test result: ok. 0 passed; 0 failed; N
    # ignored`, exits 0, and writes ZERO bytes to stderr.
    #
    # Before this carve-out the sentinel guard fired first and returned rc 2, "its
    # exit code and per-test table therefore mean nothing" - about a table that is
    # complete and entirely meaningful. That contradicted three separate
    # specifications (this file's SILENCED-wins paragraph, its verdict table's
    # `ok * ignored` row, and CONTRIBUTING's SILENCED row, all of which promise
    # rc 1), and it reported a branch that switched off every replay test as an
    # environment fault. Operator ruling: classify from the table.
    #
    # NARROW BY CONSTRUCTION, in BOTH directions. It stands down only on positive
    # evidence that no test body executed, and a run with even one non-ignored row
    # still owes a banner, so the anti-vacuity story is intact for every transcript
    # that has one.
    #
    # Derived from libtest's own SUMMARY TALLY, not from a second pass over the
    # per-test rows. The row form was `grep -qE '^test .+ \.\.\. (ok|FAILED)$'`, and
    # `.+` is greedy and unanchored in the middle, so an ignore REASON containing
    # " ... ok" satisfied a predicate that is supposed to mean "a test body ran":
    #
    #   $ printf 'test a ... ignored, blocked on #677 ... ok\n' | \
    #       grep -E '^test .+ \.\.\. (ok|FAILED)$'
    #   test a ... ignored, blocked on #677 ... ok          <- MATCHED
    #
    # An all-parked lane whose reason happened to contain " ... ok" then returned
    # rc 2 instead of the rc 1 SILENCED that this file's header, its verdict table's
    # `ok * ignored` row and CONTRIBUTING all promise - the exact pre-carve-out
    # behaviour, restored by a reason string. Same shape as the `ignored, <reason>`
    # lockout an earlier round already routed: a second, weaker parse of something
    # the driver reads correctly elsewhere.
    #
    # The summary line cannot express that ambiguity: `0 passed; 0 failed` is the
    # only state in which no body ran, whatever any reason string says.
    #
    # DEFAULTS TO 1, so an absent or unreadable summary leaves every guard ARMED
    # rather than standing them down on a transcript nobody could read. Both of
    # those states are refused below on their own terms (no `test result:` line, or
    # counts that will not parse), and both are rc 2 either way.
    local ran_any=1 ran_tally
    ran_tally="$(grep -m1 -E '^test result: ' "${out}" || true)"
    case "${ran_tally#*. }" in
    '0 passed; 0 failed;'*) ran_any=0 ;;
    esac

    # THE anti-vacuity guard.
    #
    # If this driver and the test disagree about the override variable's name, or
    # the base binary predates the override entirely, the run reads its OWN
    # corpus, agrees with itself, and exits 0. Every row would be `ok`, the count
    # would be healthy, and the table would be a self-comparison. Only confirming
    # the run announced the exact path we handed it can detect that.
    if [ "${ran_any}" -eq 1 ] &&
        ! grep -qF "${SENTINEL}: mode=fresh corpus=${want_corpus}" "${err}" "${out}"; then
        # `-n 30`, NOT `-30`. The obsolete `-N` form is rejected outright when
        # there is more than one FILE operand: GNU coreutils 9.10 prints
        # "tail: option used in invalid context -- 3" and exits 1, emitting NOTHING.
        # These are the only two multi-operand tails in this file, and they are
        # the two paths where the transcript IS the diagnosis - the header spends
        # a paragraph on exactly that ("the retained evidence directory was then
        # empty because the only explanation had gone to /dev/null"). Measured,
        # not recalled: `tail -30 a b` -> rc 1 and no output; `tail -n 30 a b` ->
        # both files with `==>` headers, rc 0.
        tail -n 30 "${err}" "${out}" >&2
        die 2 "run R${run} did not read the corpus it was handed (${want_corpus}); its exit code and per-test table therefore mean nothing"
    fi

    # THE OTHER HALF, and the guard above is worth much less without it.
    #
    # `grep -qF` asks an EXISTENTIAL question: it proves something read the tree we
    # handed over, never that nothing read a different one. A binary that resolves
    # the corpus correctly in one place and from a compiled-in CARGO_MANIFEST_DIR
    # in another satisfies it completely, and the comparison silently becomes part
    # self-comparison.
    #
    # That is not hypothetical. `rulesteward-selinux`'s `policy_corpus::archive_path`
    # was exactly that shape until this branch: `_policies/policies.tar.zst` came
    # from the manifest dir while `scenarios()` honoured the override, so R2 and R3
    # would have replayed HEAD's scenarios against the BASE tree's policy fixtures
    # with this guard reporting nothing. It was caught by reading the code.
    #
    # WHAT THIS ACTUALLY CATCHES, stated narrowly because the first version of
    # this comment over-claimed it: a resolution that DOES call
    # `resolve_corpus_root` but with an env var the driver did not set. That
    # announces `mode=committed` and lands here.
    #
    # It does NOT close the bypass class. A corpus read that never calls
    # `resolve_corpus_root` at all - the exact shape `policy_corpus::archive_path`
    # had - announces NOTHING, so it matches neither half and the run passes.
    # Nothing mechanically forces a read through the resolver. A new corpus read
    # has to be routed through it by hand.
    if grep -qF "${SENTINEL}: mode=committed" "${err}" "${out}"; then
        grep -F "${SENTINEL}: mode=committed" "${err}" "${out}" | head -5 >&2
        die 2 "run R${run} was handed ${want_corpus} but ALSO resolved a corpus in committed mode; part of this run read a different tree, so the comparison is partly a self-comparison and its verdict cannot be trusted"
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
        # `-n 30`, NOT `-30`. The obsolete `-N` form is rejected outright when
        # there is more than one FILE operand: GNU coreutils 9.10 prints
        # "tail: option used in invalid context -- 3" and exits 1, emitting NOTHING.
        # These are the only two multi-operand tails in this file, and they are
        # the two paths where the transcript IS the diagnosis - the header spends
        # a paragraph on exactly that ("the retained evidence directory was then
        # empty because the only explanation had gone to /dev/null"). Measured,
        # not recalled: `tail -30 a b` -> rc 1 and no output; `tail -n 30 a b` ->
        # both files with `==>` headers, rc 0.
        tail -n 30 "${err}" "${out}" >&2
        die 2 "run R${run} exited ${rc}, which is neither 0 nor 101; treating it as a tool error rather than guessing what it meant"
        ;;
    esac

    # EVERY `scenarios=` announcement is checked, not just the last one.
    #
    # A suite with several announcing tests emits several lines (sudoers emits
    # five). `tail -1` samples exactly one of N, DETERMINISTICALLY - `replay()`
    # passes `--test-threads=1` precisely so the transcript reads the same way
    # twice - and that is worse rather than better: a test that compared NOTHING
    # then slips past PERMANENTLY whenever a sibling's line is the one that lands
    # last, instead of intermittently. An earlier version of this comment blamed
    # nondeterministic parallel threads, which this driver disables.
    # Refusing on ANY zero (not just a zero
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
    # `ignored(, .*)?`, because `#[ignore = "reason"]` renders as
    # `test <name> ... ignored, <reason>` and the `$` anchor rejects it.
    #
    # MEASURED on rustc 1.97.0 rather than recalled, by running a real test binary:
    #
    #   test bare_ignore        ... ignored
    #   test ignore_with_reason ... ignored, flaky under NFS
    #   test result: ok. 1 passed; 0 failed; 2 ignored; ...
    #
    # This is the form the repo actually uses. Every `#[ignore]` attribute under
    # `crates/` carries a reason, and `boundary_substrate.rs` states the convention:
    # "`#[ignore]`d rather than deleted, per this repo's convention: removing the
    # `#[ignore]` is how the fix gets demonstrated."
    #
    # Anchoring against the bare form alone was a deterministic denial of service,
    # not merely a missed feature. The reasoned row failed to match, so `seen`
    # under-counted while libtest still tallied it, and the three-column
    # cross-check below fired with a message blaming this parser. A base ref that
    # merely CARRIED such a test killed R1, making that lane's differential
    # permanently unusable at a fork point no branch can change.
    local test_lines line rest name verdict seen=0 failed=0 ignored_n=0
    test_lines="$(grep -E '^test .+ \.\.\. (ok|FAILED|ignored(, .*)?)$' "${out}")"
    while IFS= read -r line; do
        [ -n "${line}" ] || continue
        rest="${line#test }"
        name="${rest%% ...*}"
        # Sliced by the name's length rather than `${rest##*... }`, which takes the
        # LONGEST match and would swallow the verdict whole for a reason that itself
        # contains " ... ".
        verdict="${rest:${#name}}"
        verdict="${verdict# ... }"
        case "${verdict}" in
        ok) ;;
        FAILED) failed=$((failed + 1)) ;;
        # RECORDED, not skipped. `continue` here dropped the row from the table
        # entirely, so a test the branch put `#[ignore]` on simply vanished from
        # R3, was then filed as present-in-base-only, and printed as "removed at
        # HEAD" at rc 0 - asserting a deletion that never happened. The regex
        # above proves the code SEES the distinction before discarding it.
        #
        # `cargo test` skips `#[ignore]` by default, so neither `just test` nor
        # `just ci` sees an ok -> ignored transition either. This driver is the
        # last instrument that could notice a replay test being silenced.
        #
        # NORMALISED to bare `ignored` before it reaches the table, so every
        # downstream comparison stays a fixed-string equality and no classifier
        # has to know reasons exist.
        ignored | ignored,*)
            verdict="ignored"
            ignored_n=$((ignored_n + 1))
            ;;
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
    local summary lt_passed lt_failed lt_ignored
    summary="$(grep -m1 -E '^test result: ' "${out}")"
    if [ -z "${summary}" ]; then
        die 2 "run R${run} printed no 'test result:' summary line; libtest's own tally is what confirms this driver parsed every row"
    fi
    # `test result: ok. 15 passed; 0 failed; 0 ignored; 0 measured; ...`
    #
    # All THREE columns are reconciled, not two. The table now records `ignored`
    # rows instead of dropping them, so `passed + failed` would under-count `seen`
    # by exactly the number of silenced tests - which is the population this
    # cross-check most needs to see.
    lt_passed="${summary#*. }"
    lt_passed="${lt_passed%% passed;*}"
    lt_failed="${summary#* passed; }"
    lt_failed="${lt_failed%% failed;*}"
    lt_ignored="${summary#* failed; }"
    lt_ignored="${lt_ignored%% ignored;*}"
    case "${lt_passed}${lt_failed}${lt_ignored}" in
    '' | *[!0-9]*)
        die 2 "run R${run}: could not read pass/fail/ignored counts out of libtest's summary line: ${summary}"
        ;;
    esac
    if [ "$((lt_passed + lt_failed + lt_ignored))" -ne "${seen}" ]; then
        die 2 "run R${run}: libtest reports ${lt_passed} passed + ${lt_failed} failed + ${lt_ignored} ignored but this driver parsed ${seen} row(s); the table is incomplete, so any verdict from it would be drawn from a narrower comparison than it claims"
    fi
    if [ "${lt_ignored}" -ne "${ignored_n}" ]; then
        die 2 "run R${run}: libtest reports ${lt_ignored} ignored but this driver parsed ${ignored_n}; the table disagrees with libtest's own tally"
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
    # the reason generalises. When the base binary chokes on HEAD's GROWN corpus
    # during enumeration - exactly the R2-FAILED signal this driver exists to
    # report - a lane that announces its count after parsing never reaches the
    # announcement, and an unconditional guard turned a DISCRIMINATED row into
    # rc 2. Measured against a real auditd binary and an override tree carrying
    # one scenario it cannot parse: banner emitted, no `scenarios=` line, rc 101.
    #
    # As of this commit that is auditd and sysctld. selinux announced late too and
    # was fixed in this same branch; sudoers is fine for the count that matters
    # here. Do NOT read sudoers as the model of "always announce first" - its
    # `announce` doc says the opposite for three of its five call sites, and says
    # why: L1/L2/L3 announce AFTER their comparison loop with the real accumulated
    # tally, because how much they compare is data-dependent and unknowable
    # upfront. An earlier version of this comment cited that doc for the reverse
    # claim.
    #
    # `ran_any` for the same reason as the sentinel guard: a run in which every
    # test was parked announces no count because no test body executed, and the
    # per-test table it DOES print is what the classification then uses.
    #
    # This carried a sentence reading "The BANNER stays mandatory for every run
    # regardless: it is what proves which corpus was read, and nothing else can
    # establish that." That was true when it was written and the carve-out
    # falsified it three lines below its own text: the banner guard now carries
    # the IDENTICAL `ran_any` conjunct (see it above), so an all-parked run is
    # classified with no banner at all and the asymmetry that sentence asserted
    # is gone. The correct scoped statement lives beside the guard it describes.
    #
    # What still holds, and is the reason rc 0 stays unreachable here: an
    # all-parked run cannot produce a green. `COMPARABLE >= 1` needs a row with
    # `R1 = ok` and `R3` in `{ok, FAILED}`, which forces a body to have executed
    # in both of those runs.
    if [ "${rc}" -eq 0 ] && [ "${ran_any}" -eq 1 ] && [ "${count_seen}" -eq 0 ]; then
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
    # The base never rendered a verdict for this test, so there is no baseline to
    # compare against.
    #
    # SPLIT ON R3, which the first version of this arm did not do: it excluded on
    # R1 alone and never read R3 at all. A test parked at the base that the branch
    # UN-parks and leaves red then printed `FAILED` in the R3HEAD column and `OK`
    # on the verdict line, from one run, at rc 0 while libtest exited 101. The repo
    # has exactly that history (`e2e_auditd_lint.rs` was `#[ignore]`d during Phase
    # 0 while its bodies were `todo!()` stubs).
    #
    # A row with no baseline that is RED at HEAD is ONLY_HEAD_FAILING's case
    # reached by a quieter route, and that gate's own ruling applies verbatim:
    # silence here would let `just test` be the only thing standing between it and
    # a merge. UNATTRIBUTABLE is genuinely different and stays rc 0 - there the
    # base DID render a verdict and it was already red.
    if [ "${R1[${name}]}" = "ignored" ]; then
        if [ "${R3[${name}]}" = "FAILED" ]; then
            ONLY_HEAD_FAILING+=("${name}")
        else
            BASE_IGNORED+=("${name}")
        fi
        continue
    fi
    # SILENCED: the base ran this test and HEAD skips it. A comparison row that
    # existed has been removed from the comparison, which is a loss of coverage
    # this driver is the last gate able to see - `cargo test` skips `#[ignore]` by
    # default, so `just test` and `just ci` are both blind to it.
    #
    # rc 1, deliberately, and symmetric with ONLY_HEAD_FAILING below: round 2 had
    # already ruled that a branch must not reach a green branch-differential while
    # a replay test it touched is not actually being checked. Silencing one is the
    # same outcome by a quieter route.
    #
    # This is NOT symmetric with a test the branch ADDS already parked, which is
    # rc 0 with its own label (ONLY_HEAD_PARKED below). Operator ruling, and the
    # reason is this repo's own convention: `boundary_substrate.rs` says
    # "`#[ignore]`d rather than deleted, per this repo's convention: removing the
    # `#[ignore]` is how the fix gets demonstrated", and #669/#677 are live
    # examples. Adding a parked pin for a known-open bug is normal practice here;
    # switching off a test that WAS running is a loss of coverage. There is no
    # override switch, deliberately.
    if [ "${R3[${name}]}" = "ignored" ]; then
        SILENCED+=("${name}")
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

# NOT declared here. `ONLY_HEAD_FAILING=()` used to sit on this line, and the
# classification loop above now appends to it - a reset here would have silently
# discarded exactly the rows that gate exists to fail. It lives in the
# pre-declaration block with its siblings.
for name in "${!R3[@]}"; do
    if [ -z "${R1[${name}]+set}" ]; then
        # Split three ways by verdict. A test the branch ADDED and left RED is not
        # a neutral "added by the branch" note: it has no base counterpart, so it
        # cannot be a REGRESSION by this driver's definition, but reporting it
        # under the same reassuring label as a passing addition is how a red new
        # test rode out at rc 0.
        #
        # A test the branch adds already PARKED gets its own label at rc 0. The
        # verdict column previously asserted the same thing about a test that ran
        # and one that did not. It is rc 0 rather than rc 1 by operator ruling:
        # adding a parked pin for a known-open bug is this repo's documented
        # convention (#669/#677), unlike silencing a test that WAS running.
        case "${R3[${name}]}" in
        FAILED) ONLY_HEAD_FAILING+=("${name}") ;;
        ignored) ONLY_HEAD_PARKED+=("${name}") ;;
        *) ONLY_HEAD+=("${name}") ;;
        esac
    fi
done

# Zero comparable rows has SEVERAL distinct causes and they point at different
# files, so they get different messages. Reporting one as the other sends the
# reader to the wrong place, which is most of the cost of a bad diagnostic.
#
# When this gate was written there were two causes. `SILENCED` and `BASE_IGNORED`
# were added later without revisiting it, and both landed in the final `die`: a
# branch that parked every replay row was told "no test name appears in BOTH the
# base and HEAD runs (0 base-only, 0 HEAD-only)", a sentence its own two counts
# refute, and was sent looking for a rename that never happened.
#
# SILENCED WINS OUTRIGHT. A run where every row was silenced is the strongest
# instance of the thing that gate exists to fail, not a diagnostic dead end, so it
# is reported as rc 1 below rather than dying rc 2 here.
#
# BOTH rc-1 buckets that skip COMPARABLE must stand this gate down, not just one.
# Round 4 added the SILENCED conjunct with the reasoning above and did not carry
# it to its sibling - while, in the same commit, WIDENING the population that
# reaches ONLY_HEAD_FAILING by adding the un-parked-and-red arm. The result was
# that a branch defect got reported as a tool error: rc 2 "these two builds cannot
# be compared", which sends the operator to change their base ref or fix their
# environment rather than to fix the red test, and the per-test table naming that
# test was never printed because every `die 2` here precedes the report block.
# All three round-5 reviewers found this independently.
if [ "${COMPARABLE}" -eq 0 ] &&
    [ "${#SILENCED[@]}" -eq 0 ] &&
    [ "${#ONLY_HEAD_FAILING[@]}" -eq 0 ]; then
    if [ "${#UNATTRIBUTABLE[@]}" -ne 0 ]; then
        die 2 "no row could be compared: ${#UNATTRIBUTABLE[@]} UNATTRIBUTABLE (the base was already red against its own corpus), ${#BASE_IGNORED[@]} #[ignore]d at the base, ${#ONLY_BASE[@]} base-only, ${#ONLY_HEAD[@]} HEAD-only, ${#ONLY_HEAD_PARKED[@]} HEAD-only and parked. Nothing was actually compared, so neither 'clean' nor 'regression' would be truthful"
    fi
    if [ "${#BASE_IGNORED[@]}" -ne 0 ]; then
        # NO CAUSE ATTRIBUTION HERE. An earlier version ended "that is a property
        # of <base>, not of this branch", which is false whenever the branch's own
        # rename or deletion is what emptied the comparable set: the base-only and
        # HEAD-only counts below can be non-zero, and had the branch not renamed
        # those rows they would have been comparable. It routed the operator to
        # change their base ref when the remedy was in their own diff, with no
        # table to contradict it (every `die 2` here precedes the report block).
        die 2 "no row could be compared: ${#BASE_IGNORED[@]} shared row(s) are #[ignore]d at the BASE so have no baseline verdict, alongside ${#ONLY_BASE[@]} base-only, ${#ONLY_HEAD[@]} HEAD-only and ${#ONLY_HEAD_PARKED[@]} HEAD-only-and-parked row(s). Check both the base ref and this branch's own renames before concluding which side is responsible"
    fi
    # Every bucket is named, so the reader is never handed a count that contradicts
    # the sentence around it.
    die 2 "no test name appears in BOTH the base and HEAD runs (${#ONLY_BASE[@]} base-only, ${#ONLY_HEAD[@]} HEAD-only, ${#ONLY_HEAD_PARKED[@]} HEAD-only and parked, ${#ONLY_HEAD_FAILING[@]} HEAD-only and failing); there is nothing to compare, so neither 'clean' nor 'regression' would be truthful"
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
# paths are interpolated rather than described, so the PATHS cannot drift again.
#
# `--force --force`, and both are load-bearing. This driver LOCKS its cache
# worktrees (see the lock call above), and git refuses to remove a locked
# worktree: "remove refuses to remove an unclean worktree unless --force is used.
# To remove a locked worktree, specify --force twice." The single-force form
# printed here previously failed with `fatal: cannot remove a locked working
# tree` - and because of the `&&`, the `rm -rf` of the target dir never ran
# either, so the reclaim line stranded the larger of the two directories. The
# paths were correct and the COMMAND was wrong, which the old comment's "they
# cannot drift again" did not cover.
#
# Roughly 180 MB total per lane per sha, most of it the target dir. Deliberately
# approximate: it tracks dependency growth and a precise pair of numbers here
# would rot without anything noticing.
printf '%s: base worktree %s (cached)\n' "${LABEL}" "${WT}"
printf '%s: reclaim with: git worktree remove --force --force %s && rm -rf %s\n\n' "${LABEL}" "${WT}" "${BASE_TARGET_DIR}"
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
for name in "${SILENCED[@]+"${SILENCED[@]}"}"; do row "${name}" "SILENCED at HEAD (#[ignore])"; done
for name in "${BASE_IGNORED[@]+"${BASE_IGNORED[@]}"}"; do row "${name}" "ignored at base (no baseline)"; done
for name in "${ONLY_BASE[@]+"${ONLY_BASE[@]}"}"; do row "${name}" "base-only (removed at HEAD)"; done
for name in "${ONLY_HEAD[@]+"${ONLY_HEAD[@]}"}"; do row "${name}" "HEAD-only (added by the branch)"; done
for name in "${ONLY_HEAD_PARKED[@]+"${ONLY_HEAD_PARKED[@]}"}"; do row "${name}" "HEAD-only and PARKED (#[ignore])"; done
for name in "${ONLY_HEAD_FAILING[@]+"${ONLY_HEAD_FAILING[@]}"}"; do row "${name}" "no baseline and FAILING"; done
printf '\n%d clean row(s) not listed. Scenario announcements: R1=%d R2=%d R3=%d.\n' \
    "${CLEAN}" "${SCEN[1]}" "${SCEN[2]}" "${SCEN[3]}"

# A test the branch added and left RED is a failure of the branch even though it
# has no base counterpart to regress against. Silence here would let `just test`
# be the only thing standing between it and a merge.
if [ "${#ONLY_HEAD_FAILING[@]}" -ne 0 ]; then
    # "no baseline verdict", NOT "exist only at HEAD". This bucket holds TWO
    # populations: rows the branch ADDED (absent at base) and rows the base had
    # PARKED that the branch un-parked and left red. The second kind is present at
    # the base - its R1base column literally reads `ignored` two lines above - so
    # "exists only at HEAD" sent the operator hunting a newly added test that is
    # not in the diff. Round 4 introduced that route and reused this sentence; two
    # reviewers found it, and the suite's own case had frozen the false wording.
    printf '%s: %d test(s) have no baseline verdict and are FAILING at HEAD (added, or #[ignore]d at base and un-parked): %s\n' \
        "${LABEL}" "${#ONLY_HEAD_FAILING[@]}" "${ONLY_HEAD_FAILING[*]}" >&2
    finish 1
fi

# The same ruling as ONLY_HEAD_FAILING, applied to the quieter route in. The base
# ran these tests and HEAD does not, so each one is a comparison row this branch
# removed from the comparison. `cargo test` skips `#[ignore]` by default, so no
# other gate in `just ci` sees the transition; reporting it as "removed at HEAD"
# at rc 0 (which is what the old `ignored) continue` produced) asserted a deletion
# that never happened and called the run clean.
if [ "${#SILENCED[@]}" -ne 0 ]; then
    printf '%s: %d test(s) ran at base %s and are #[ignore]d at HEAD: %s\n' \
        "${LABEL}" "${#SILENCED[@]}" "${BASE_SHA:0:12}" "${SILENCED[*]}" >&2
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
# lane whose helper announces once per test emits several. selinux announces once
# per test across three tests, so its sum is 3x the scenario count and would read
# as three times too many. No literal is quoted: #658's growth gate MANDATES that
# any branch touching that crate adds a scenario, so a number here rots on the
# next selinux branch by construction. The line above already
# calls these announcements; the two outputs used to contradict each other in one
# transcript, and the misleading one was what the rc contract pointed at.
printf '%s: OK (%d regressions, %d discriminated, %d scenario announcements in R3)\n' \
    "${LABEL}" 0 "${#DISCRIMINATED[@]}" "${SCEN[3]}"
finish 0
