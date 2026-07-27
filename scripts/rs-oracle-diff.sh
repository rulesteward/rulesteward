#!/usr/bin/env bash
#
# Shared driver for the session-9k-1 live differential recipes:
# `just diff-auditd`, `just diff-sysctld`, `just diff-sudoers`.
#
# Usage: bash scripts/rs-oracle-diff.sh <auditd|sysctld|sudoers>
#
# WHY ONE DRIVER RATHER THAN THREE RECIPES
#
# The exit-code mapping below is the only part of the harness whose failure mode
# is silent: every wrong branch reports "clean" rather than crashing. Written
# three times it would be wrong in three different ways, which is precisely how
# `just diff-fapolicyd` came to exit 0 with a skip message on every run for six
# weeks (#572). It is written once, here, and positive-controlled by
# scripts/rs-oracle-diff-test.sh against a stubbed cargo/docker/test-binary.
#
# THE EXIT-CODE MECHANISM (the load-bearing, non-obvious part)
#
# Measured: `cargo test --test no_such_target` exits 101, the SAME code as a
# failed assertion, and `cargo test ... -- --exact no_such_name` exits 0 having
# run zero tests. So classifying cargo's own exit code reports a broken build as
# oracle drift and reports a vacuous run as clean. Instead:
#
#   A1  `cargo test --no-run`. Every cargo-level error class (compile error,
#       missing target, lock drift) is consumed HERE, and any failure is rc 2 by
#       construction.
#   A2  the same command with --message-format=json, now warm, purely to learn
#       the built binary's path. No jq: the el8 oracle images do not have it and
#       neither does a minimal CI runner.
#   B1  execute that binary with the override UNSET. The committed corpus must be
#       green, or drift cannot be attributed to the fresh capture at all.
#   B2  execute the SAME binary with the override set to the fresh capture. Cargo
#       is out of the process tree, so 101 can now only mean libtest saw a
#       failing test.
#
# That is what makes the drift-vs-tool-error split structural rather than a
# guess. See CONTRIBUTING.md "Differential oracle contract".
#
# Exit codes (the dev-tooling contract, NOT the rulesteward binary's own):
#   0  verified clean; the success line carries a non-zero scenario count
#   1  drift: the product and the freshly captured oracle disagree
#   2  tool/environment error, including "the oracle was required but missing"
#   3  precondition unmet, a legitimate skip (no docker, images absent)

set -uo pipefail

usage() {
    cat >&2 <<'EOF'
usage: bash scripts/rs-oracle-diff.sh <lane>

  lane    auditd | sysctld | sudoers

Runs the lane's Tier-1 replay test twice: once against the committed corpus (to
establish a baseline) and once against a freshly captured one (the drift check).
EOF
}

LANE="${1-}"

# ---------------------------------------------------------------------------
# Frozen per-lane table.
#
# This table is Phase-0 shared surface. It is here, in one place, so that landing
# a lane does not require editing a file the other two lanes also touch: a lane
# owns its capture script and its corpus, and nothing else in this driver.
# ---------------------------------------------------------------------------
case "${LANE}" in
auditd)
    PKG="rulesteward-auditd"
    TEST_TARGET="auditd_corpus_oracle"
    CORPUS_VAR="RS_ORACLE_CORPUS_AUDITD"
    ORACLE_TOKEN="AUDITCTL"
    SENTINEL="RS-DIFF-AUDITD"
    CAPTURE="crates/rulesteward-auditd/tests/corpus/auditd-oracle/capture_auditd.sh"
    ;;
sysctld)
    PKG="rulesteward-sysctld"
    TEST_TARGET="sysctld_corpus_oracle"
    CORPUS_VAR="RS_ORACLE_CORPUS_SYSCTLD"
    ORACLE_TOKEN="SYSTEMD_SYSCTL"
    SENTINEL="RS-DIFF-SYSCTLD"
    CAPTURE="crates/rulesteward-sysctld/tests/corpus/sysctld-oracle/capture_sysctld.sh"
    ;;
sudoers)
    PKG="rulesteward-sudoers"
    TEST_TARGET="sudoers_corpus_oracle"
    CORPUS_VAR="RS_ORACLE_CORPUS_SUDOERS"
    ORACLE_TOKEN="VISUDO"
    SENTINEL="RS-DIFF-SUDOERS"
    CAPTURE="crates/rulesteward-sudoers/tests/corpus/sudoers-oracle/capture_sudoers.sh"
    ;;
"")
    echo "rs-oracle-diff: no lane given" >&2
    usage
    exit 2
    ;;
*)
    echo "rs-oracle-diff: unknown lane '${LANE}'" >&2
    usage
    exit 2
    ;;
esac

LABEL="diff-${LANE}"
IMAGES=(rs-oracle8 rs-oracle9 rs-oracle10)

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)" || exit 2
cd "${REPO_ROOT}" || exit 2

# Confirm we actually landed in the repo root before running anything relative to
# it. This is not paranoia: if `dirname` is unavailable the expansion above
# collapses to `cd "/.."`, which SUCCEEDS, and the driver would then resolve every
# relative path against `/`. Checking for a file we know is our sibling turns that
# into an immediate, legible failure.
if [ ! -f "scripts/rs-oracle-required.sh" ]; then
    echo "${LABEL}: resolved repo root '${REPO_ROOT}' does not contain scripts/rs-oracle-required.sh" >&2
    exit 2
fi

WORK="$(mktemp -d "${TMPDIR:-/tmp}/rs-oracle-${LANE}-XXXXXX")" || {
    echo "${LABEL}: could not create a working directory" >&2
    exit 2
}
FRESH="${WORK}/corpus"
LOG_BUILD="${WORK}/build.log"
LOG_JSON="${WORK}/build.json"
LOG_BASE="${WORK}/committed.log"
LOG_CAP="${WORK}/capture.log"
LOG_FRESH="${WORK}/fresh.log"

# Deliberately NOT an EXIT trap that always deletes: on drift (rc 1) or a tool
# error (rc 2) the captured corpus and the two run logs are the evidence, and
# discarding them would leave the operator with a verdict and nothing to inspect.
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

# A skip is only honest when nobody declared the oracle required. Where CI
# installs the oracle it sets RS_ORACLE_REQUIRED / RS_REQUIRE_<TOKEN>, and the
# very same missing-prerequisite condition must become a hard error there.
skip_or_fail() {
    if [ "${REQUIRED}" -eq 1 ]; then
        printf '%s: %s\n' "${LABEL}" "$*" >&2
        die 2 "the oracle is declared REQUIRED (RS_ORACLE_REQUIRED or RS_REQUIRE_${ORACLE_TOKEN}), so a missing prerequisite is an error, not a skip"
    fi
    printf '%s: SKIP - %s\n' "${LABEL}" "$*" >&2
    finish 3
}

# ---------------------------------------------------------------------------
# Is the oracle declared required? Fail-closed parsing lives in one place.
# ---------------------------------------------------------------------------
bash scripts/rs-oracle-required.sh "${ORACLE_TOKEN}"
req_rc=$?
case "${req_rc}" in
0) REQUIRED=1 ;;
1) REQUIRED=0 ;;
*)
    REQUIRED=1
    die 2 "scripts/rs-oracle-required.sh ${ORACLE_TOKEN} exited ${req_rc} (expected 0 or 1); refusing to guess whether the oracle is required"
    ;;
esac

# ---------------------------------------------------------------------------
# Repo-state preconditions. A missing committed capture script is a defect in the
# repository, never a reason to skip, so it is rc 2 even without docker present.
# ---------------------------------------------------------------------------
if [ ! -f "${CAPTURE}" ]; then
    die 2 "capture script ${CAPTURE} is missing; this lane's Tier-2 capture has not landed"
fi

# ---------------------------------------------------------------------------
# Environment preconditions. These are the only legitimate rc-3 conditions.
# ---------------------------------------------------------------------------
if ! command -v docker >/dev/null 2>&1; then
    skip_or_fail "docker is not on PATH; the live capture needs it"
fi
if ! docker image inspect "${IMAGES[@]}" >/dev/null 2>&1; then
    skip_or_fail "images ${IMAGES[*]} not found; build them with the loop in tools/oracle-images/README.md"
fi

# ---------------------------------------------------------------------------
# A1: consume every cargo-level error class here, so that later a 101 can only
# mean a failing assertion.
# ---------------------------------------------------------------------------
cargo test -p "${PKG}" --test "${TEST_TARGET}" --locked --no-run >"${LOG_BUILD}" 2>&1
build_rc=$?
if [ "${build_rc}" -ne 0 ]; then
    tail -30 "${LOG_BUILD}" >&2
    die 2 "cargo could not build ${PKG} --test ${TEST_TARGET} (exit ${build_rc}); this is a build error, not oracle drift"
fi

# ---------------------------------------------------------------------------
# A2: learn the built binary's path. Re-running --no-run is warm and cheap.
# ---------------------------------------------------------------------------
cargo test -p "${PKG}" --test "${TEST_TARGET}" --locked --no-run --message-format=json >"${LOG_JSON}" 2>/dev/null
json_rc=$?
if [ "${json_rc}" -ne 0 ]; then
    die 2 "cargo --message-format=json exited ${json_rc} on a build that had just succeeded"
fi

# `"executable":null` for non-test artifacts does not match the quoted form, so
# only real binaries survive. Build-script binaries are excluded by name. The
# count is then required to be EXACTLY one: picking the first of several would
# silently run whichever artifact cargo happened to emit first.
mapfile -t EXECUTABLES < <(
    grep -o '"executable":"[^"]*"' "${LOG_JSON}" |
        cut -d'"' -f4 |
        grep -v 'build-script' || true
)
if [ "${#EXECUTABLES[@]}" -ne 1 ]; then
    die 2 "expected exactly 1 test binary from cargo's JSON output, found ${#EXECUTABLES[@]}: ${EXECUTABLES[*]-none}"
fi
TEST_BIN="${EXECUTABLES[0]}"
if [ ! -x "${TEST_BIN}" ]; then
    die 2 "cargo reported test binary ${TEST_BIN}, which is not executable"
fi

# ---------------------------------------------------------------------------
# B1: baseline. If the committed corpus is already red, a red fresh run cannot be
# attributed to drift, so this is a tool error rather than a drift report.
# ---------------------------------------------------------------------------
env -u "${CORPUS_VAR}" "${TEST_BIN}" --nocapture >"${LOG_BASE}" 2>&1
base_rc=$?
if [ "${base_rc}" -ne 0 ]; then
    tail -30 "${LOG_BASE}" >&2
    die 2 "the COMMITTED corpus is not green (exit ${base_rc}); fix 'just test' before reading a drift result"
fi
if ! grep -qF "${SENTINEL}: mode=committed corpus=" "${LOG_BASE}"; then
    die 2 "the baseline run printed no '${SENTINEL}: mode=committed' banner; the test is not the one this recipe thinks it is"
fi

# ---------------------------------------------------------------------------
# Capture a fresh corpus from the live subsystem.
# ---------------------------------------------------------------------------
mkdir -p "${FRESH}" || die 2 "could not create ${FRESH}"
bash "${CAPTURE}" "${FRESH}" >"${LOG_CAP}" 2>&1
cap_rc=$?
case "${cap_rc}" in
0) ;;
3)
    tail -20 "${LOG_CAP}" >&2
    skip_or_fail "the capture script reported an unmet precondition (rc 3)"
    ;;
*)
    tail -30 "${LOG_CAP}" >&2
    die 2 "capture script ${CAPTURE} failed (exit ${cap_rc})"
    ;;
esac

# A capture that exits 0 having WRITTEN NOTHING is a tool error, not drift.
#
# Without this check the empty directory reaches B2, the replay test's own
# fail-closed parse rejects it, libtest exits 101, and the driver would report
# DRIFT: blaming the product for a capture that never ran. That is the wrong
# verdict, the wrong exit code, and it points the reader at the wrong file.
#
# Not hypothetical. A lane's capture script ran `cp` under `set -uo pipefail`
# with no `-e`, the copy failed with "Disk quota exceeded", and the script
# carried on and exited 0. `scripts/rs-capture-guard.sh` is the fix on the
# capture side; this is the driver refusing to interpret the result either way.
#
# Counted with bash globbing rather than `find` so the driver keeps working on a
# minimal PATH (and so its own test suite can stay hermetic). `dir/**` under
# globstar yields the directory itself plus every descendant, so the `-f` filter
# is what makes this "at least one REGULAR FILE, at any depth" rather than the
# weaker "the directory has an entry" - a tree of empty subdirectories is still
# an empty corpus.
shopt -s nullglob dotglob globstar
FRESH_FILES=()
for fresh_entry in "${FRESH}"/**; do
    [ -f "${fresh_entry}" ] && FRESH_FILES+=("${fresh_entry}")
done
shopt -u nullglob dotglob globstar
if [ "${#FRESH_FILES[@]}" -eq 0 ]; then
    tail -20 "${LOG_CAP}" >&2
    die 2 "the capture script exited 0 but wrote no files under ${FRESH}; an empty corpus is a capture failure, not oracle drift"
fi

# ---------------------------------------------------------------------------
# B2: the drift check itself.
# ---------------------------------------------------------------------------
env "${CORPUS_VAR}=${FRESH}" "${TEST_BIN}" --nocapture >"${LOG_FRESH}" 2>&1
fresh_rc=$?

# THE anti-vacuity guard, and it runs BEFORE any exit code is interpreted.
#
# If this recipe and the test disagree about the override variable's name, the
# "fresh" run reads the COMMITTED corpus, agrees with itself, and exits 0. That
# is a green run which compared nothing against nothing. Neither the count, nor
# the positive control, nor the exit code can detect it; only confirming that the
# test announced the exact path we handed it can.
if ! grep -qF "${SENTINEL}: mode=fresh corpus=${FRESH}" "${LOG_FRESH}"; then
    tail -30 "${LOG_FRESH}" >&2
    die 2 "the fresh run never announced '${SENTINEL}: mode=fresh corpus=${FRESH}'; it did not read the freshly captured corpus, so its exit code means nothing"
fi

# A two-sided positive control that comes back one-sided means the ORACLE is
# broken, not the product. That is rc 2, never 0 and never 1.
if grep -qF "${SENTINEL}: ORACLE-BROKEN" "${LOG_FRESH}"; then
    grep -F "${SENTINEL}: ORACLE-BROKEN" "${LOG_FRESH}" >&2
    die 2 "the corpus positive control failed: the oracle itself is broken, so neither 'clean' nor 'drift' would be a truthful verdict"
fi

# EVERY `scenarios=` announcement is checked, not just the last one, and the
# reported figure is their SUM.
#
# This was an order-dependent FAIL-OPEN. A test binary runs its cases on
# parallel libtest threads, so a suite with several announcing tests emits
# several `scenarios=` lines in a nondeterministic order (sudoers emits five,
# two of which are small fixed constants). `tail -1` therefore sampled a RANDOM
# one of N and applied the zero-check to that sample alone: a test that compared
# NOTHING would slip past whenever some sibling's line happened to land last.
# That is precisely the "nothing fired vs nothing ran" confusion this guard
# exists to prevent, reintroduced inside the guard itself. It also made the
# success line's count a coin flip - `OK (0 drift, 3 scenarios)` was reachable
# after 240 real comparisons, which is a false success line rather than a
# suppressed failure, but the rc convention requires that count to be honest
# evidence.
#
# Refusing on ANY zero announcement (not just a zero sum) is deliberate: one
# vacuous test among several live ones is exactly the case a sum would hide.
# Stripped with `${line##*=}` rather than sed: this driver runs in minimal
# environments (its own harness test deliberately supplies a PATH with no sed),
# so the extraction must stay inside shell builtins. `grep` is already a
# dependency above; nothing new may be added.
#
# The loop is fed by a heredoc, NOT a pipe: a `while read` on the right-hand
# side of a pipe runs in a subshell, so both accumulators would be discarded at
# `done` and the guard would silently see zero announcements.
count_lines="$(grep -F "${SENTINEL}: scenarios=" "${LOG_FRESH}")"
SCENARIOS=0
count_seen=0
while IFS= read -r count_line; do
    [ -n "${count_line}" ] || continue
    one="${count_line##*=}"
    case "${one}" in
    '' | *[!0-9]*)
        die 2 "unparseable scenario count '${one}' in a '${SENTINEL}: scenarios=' line"
        ;;
    esac
    if [ "${one}" -eq 0 ]; then
        die 2 "an announcement reported 0 scenarios; 'nothing fired' and 'nothing ran' are not the same verdict"
    fi
    SCENARIOS=$((SCENARIOS + one))
    count_seen=$((count_seen + 1))
done <<EOF
${count_lines}
EOF
if [ "${count_seen}" -eq 0 ]; then
    die 2 "the fresh run printed no '${SENTINEL}: scenarios=' line; the scenario count cannot be confirmed non-zero"
fi

case "${fresh_rc}" in
0)
    printf '%s: OK (0 drift, %s scenarios)\n' "${LABEL}" "${SCENARIOS}"
    finish 0
    ;;
101)
    tail -40 "${LOG_FRESH}" >&2
    printf '%s: DRIFT (%s scenarios compared); the product and the live oracle disagree\n' "${LABEL}" "${SCENARIOS}" >&2
    finish 1
    ;;
*)
    tail -40 "${LOG_FRESH}" >&2
    die 2 "the fresh run exited ${fresh_rc}, which is neither 0 (clean) nor 101 (a failing assertion); treating it as a tool error rather than guessing"
    ;;
esac
