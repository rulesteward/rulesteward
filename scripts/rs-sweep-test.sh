#!/usr/bin/env bash
#
# Positive-controlled test suite for scripts/rs-sweep.sh.
#
# The driver classifies every swept input into one of four buckets and then
# compares the divergence set against a committed frontier. EVERY wrong branch
# in it fails toward "clean": an oracle that never ran, a product whose files
# were never opened, a frontier that did not parse, and a genuinely clean sweep
# all produce the same shape of output. A green run of the real recipe therefore
# proves nothing about the driver - it exercises one path, the happy one.
#
# So the driver is run here against a stub docker and a stub product, once per
# interesting outcome, with no toolchain, no container and no network. The suite
# ends with a positive-control phase that seeds the single most dangerous bug
# back into a COPY of the driver and asserts a NAMED case catches it. Without
# that, this file could pass while testing nothing - which is the exact defect
# class the driver exists to prevent, reintroduced one level up.
#
# Usage: bash scripts/rs-sweep-test.sh
# Exit:  0 all cases pass, 1 a case failed, 2 the suite could not run.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)" || exit 2
DRIVER="${REPO_ROOT}/scripts/rs-sweep.sh"
REQUIRED_SH="${REPO_ROOT}/scripts/rs-oracle-required.sh"

for f in "${DRIVER}" "${REQUIRED_SH}"; do
    [ -f "${f}" ] || {
        echo "SUITE ERROR: ${f} not found" >&2
        exit 2
    }
done

SANDBOX_BASE="$(mktemp -d "${TMPDIR:-/tmp}/rs-sweep-test-XXXXXX")" || exit 2
trap 'rm -rf "${SANDBOX_BASE}"' EXIT

PASS=0
FAIL=0
FAILED_CASES=()
CONTROL_PHASE=0

# During a positive-control phase the cases are SUPPOSED not to meet their
# expectation - that is how the control proves the guard is load-bearing - so
# printing `FAIL` there announces SUCCESS using the word for failure (#641).
# `just instrument-test` asserts a suite exiting 0 prints no `FAIL` token, and
# an `EXPECTED-FAIL` spelling would still trip any log scrape keyed on it.
case_marker() {
    if [ "${CONTROL_PHASE}" -eq 1 ]; then printf 'CAUGHT'; else printf 'FAIL'; fi
}

# ---------------------------------------------------------------------------
# Sandbox: a fake repo root holding the driver under test, the real
# rs-oracle-required.sh (its fail-closed parsing is part of what is exercised),
# a stub PATH, and a stub product binary.
# ---------------------------------------------------------------------------
make_sandbox() {
    local driver_src="$1"
    local hide_docker="${2:-0}"
    local box
    box="$(mktemp -d "${SANDBOX_BASE}/box-XXXXXX")" || return 1

    mkdir -p "${box}/scripts" "${box}/bin" \
        "${box}/crates/rulesteward-sudoers/tests/corpus" || return 1
    cp "${driver_src}" "${box}/scripts/rs-sweep.sh" || return 1
    cp "${REQUIRED_SH}" "${box}/scripts/rs-oracle-required.sh" || return 1

    # Stub docker. `image inspect` gates the rc-3 precondition; `run` IS the
    # oracle, reading the manifest on stdin exactly as the real container does.
    #
    # The base verdict rule is "reject iff the line contains a backslash". That
    # is not arbitrary: it makes the ACCEPT canary (`alice h1 = ...`) rc 0 and
    # the REJECT canary (`alice\!h1 = ...`) rc 1 without special-casing either,
    # so a mode that breaks the canaries has to do so deliberately.
    cat >"${box}/bin/docker" <<'DOCKEOF'
#!/usr/bin/env bash
case "${1-}" in
image)
    [ "${STUB_IMAGE_OK:-1}" = "1" ] || exit 1
    exit 0
    ;;
run)
    mode="${STUB_ORACLE_MODE:-normal}"
    [ "${mode}" = "runfail" ] && exit 125
    lines=()
    while IFS= read -r line; do lines+=("${line}"); done
    n="${#lines[@]}"
    [ "${mode}" = "shortcount" ] && n=$((n - 1))
    i=0
    while [ "${i}" -lt "${n}" ]; do
        line="${lines[${i}]}"
        i=$((i + 1))
        case "${line}" in
        *\\*) rc=1 ;;
        *) rc=0 ;;
        esac
        case "${mode}" in
        nonvisudo) rc=127 ;;
        oneclass)
            # Every SWEPT input accepted; only the reject canary rejected. This
            # is the shape that a G7 counting the canaries would wave through.
            case "${line}" in
            'alice\!h1 = NOPASSWD: ALL') rc=1 ;;
            *) rc=0 ;;
            esac
            ;;
        badcanary)
            case "${line}" in
            'alice h1 = NOPASSWD: ALL') rc=1 ;;
            esac
            ;;
        esac
        printf 'V %s %s\n' "${i}" "${rc}"
    done
    exit 0
    ;;
*)
    exit 0
    ;;
esac
DOCKEOF
    chmod 0755 "${box}/bin/docker" || return 1
    [ "${hide_docker}" -eq 1 ] && rm -f "${box}/bin/docker"

    # Stub product. Mirrors the real CLI's JSON shape closely enough for the
    # driver's parser: six-space field indentation, `code` before `file`.
    #
    # Base rule is the MIRROR of the oracle's, so a clean sweep is genuinely
    # clean rather than accidentally so: a backslash line gets sudo-F01 (and
    # the oracle rejected it -> AGREE), everything else gets sudo-W01 (and the
    # oracle accepted it -> AGREE).
    cat >"${box}/bin/product" <<'PRODEOF'
#!/usr/bin/env bash
mode="${STUB_PRODUCT_MODE:-normal}"
[ "${mode}" = "toolfail" ] && exit 3
# Simulates a concurrent `cargo build` replacing the binary underneath a sweep
# that has already started. Appends ONCE (guarded by a marker) and only a
# comment, at EOF: bash slurps a script this small in a single read, so the
# running instance is unaffected while the file on disk changes.
if [ "${mode}" = "selfmutate" ] && [ ! -f "${0}.mutated" ]; then
    : >"${0}.mutated"
    printf '# rebuilt underneath the sweep\n' >>"${0}"
fi
target=""
for a in "$@"; do case "${a}" in -*) ;; sudoers | lint | json) ;; *) target="${a}" ;; esac; done
files=()
if [ -d "${target}" ]; then
    for f in "${target}"/*; do [ -f "${f}" ] && files+=("${f}"); done
else
    files+=("${target}")
fi
printf '{\n  "schemaVersion": 1,\n  "kind": "sudoers-lint",\n  "diagnostics": [\n'
first=1
emit() {
    [ "${first}" -eq 1 ] || printf '    },\n'
    first=0
    printf '    {\n      "severity": "%s",\n      "code": "%s",\n' "$2" "$1"
    printf '      "message": "stub",\n      "file": "%s",\n      "line": 1\n' "$3"
}
for f in "${files[@]}"; do
    base="${f##*/}"
    case "${mode}" in
    silent) continue ;;
    nocanary) case "${base}" in zzcanary*) continue ;; esac ;;
    esac
    content="$(cat "${f}")"
    code="sudo-W01"
    sev="Warning"
    case "${content}" in *\\*)
        code="sudo-F01"
        sev="Fatal"
        ;;
    esac
    # A single-file invocation is distinguishable from a batch one by the
    # target being a file. `batchdiff` makes the two disagree, which is the
    # only thing the driver's batch-vs-single cross-check can catch.
    if [ "${mode}" = "batchdiff" ] && [ ! -d "${target}" ] && [ "${base}" = "00000000" ]; then
        code="sudo-F01"
        sev="Fatal"
    fi
    if [ "${mode}" = "divergent" ] && [ "${base}" = "00000008" ]; then
        code="sudo-F01"
        sev="Fatal"
    fi
    emit "${code}" "${sev}" "${f}"
done
[ "${first}" -eq 1 ] || printf '    }\n'
printf '  ]\n}\n'
exit 1
PRODEOF
    chmod 0755 "${box}/bin/product" || return 1

    # A HERMETIC bin directory: the box's PATH is this and nothing else.
    #
    # Without it the `no-docker` cases are untestable, because prepending the
    # box to the inherited PATH leaves the machine's real docker perfectly
    # reachable - the case would then exercise a live docker against a stub
    # product and pass for a reason unrelated to what it claims to measure.
    #
    # It also pins the driver's dependency surface: if a future edit reaches for
    # a tool not in this list, the whole suite goes red rather than the driver
    # silently acquiring a dependency that a minimal CI container lacks.
    local tool src
    for tool in awk cat cksum comm cut dirname grep mkdir mktemp mv paste rm sort tail tr wc bash; do
        src="$(command -v "${tool}" 2>/dev/null)" || continue
        [ -n "${src}" ] && ln -sf "${src}" "${box}/bin/${tool}"
    done

    printf '%s\n' "${box}"
}

FRONTIER_REL="crates/rulesteward-sudoers/tests/corpus/sweep-frontier.txt"

# A syntactically valid, empty-divergence frontier. Most cases die long before
# the comparison, but the driver refuses to run at all without a frontier (by
# design), so every box needs one or those cases would return rc 2 for the wrong
# reason and the suite would pass while proving nothing.
seed_frontier() {
    local box="$1"
    cat >"${box}/${FRONTIER_REL}" <<'FEOF'
# test fixture
LANE sudoers
LENGTH 2
TOKENS 8
IMAGE rs-oracle9
TOTAL 64
COUNT AGREE 64
COUNT FALSE-FATAL 0
COUNT MISSED-GRANT 0
COUNT FAIL-OPEN 0
COUNT EQ-SPLIT 0
FEOF
}

# Runs the driver inside a box with the stub PATH and stub product. Echoes the
# exit code; the transcript lands in ${box}/out for the failure report.
run_driver() {
    local box="$1"
    shift
    mkdir -p "${box}/tmp"
    (
        cd "${box}" || exit 2
        PATH="${box}/bin" \
            RS_SWEEP_BIN="${box}/bin/product" \
            TMPDIR="${box}/tmp" \
            bash "${box}/scripts/rs-sweep.sh" "$@"
    ) >"${box}/out" 2>&1
    echo $?
}

check() {
    local name="$1" want="$2" got="$3" box="$4"
    if [ "${got}" = "${want}" ]; then
        PASS=$((PASS + 1))
        printf 'ok   %-32s rc=%s\n' "${name}" "${got}"
        return 0
    fi
    FAIL=$((FAIL + 1))
    FAILED_CASES+=("${name}")
    printf '%s %-32s want rc=%s got rc=%s\n' "$(case_marker)" "${name}" "${want}" "${got}"
    [ -f "${box}/out" ] && sed 's/^/       | /' "${box}/out" | tail -6
    return 1
}

# The default sweep parameters for every case: length 2 is 64 inputs, batch 32
# gives TWO batches so the per-batch canary logic is exercised rather than run
# once, and sample 8 gives eight batch-vs-single comparisons.
ARGS=(sudoers --length 2 --batch 32 --sample 8)

# ---------------------------------------------------------------------------
# The cases. Each returns the driver's rc under one seeded condition.
# ---------------------------------------------------------------------------
run_suite() {
    local driver_src="$1"
    local box rc

    # -- argument and repo-state handling -------------------------------------
    box="$(make_sandbox "${driver_src}")" || return 2
    seed_frontier "${box}"
    rc="$(run_driver "${box}" bogus-lane)"
    check "unknown-lane" 2 "${rc}" "${box}"

    rc="$(run_driver "${box}" sudoers --length notanumber)"
    check "non-numeric-length" 2 "${rc}" "${box}"

    rc="$(run_driver "${box}" sudoers --length 0)"
    check "zero-length" 2 "${rc}" "${box}"

    rc="$(run_driver "${box}" sudoers --bogus-flag)"
    check "unknown-option" 2 "${rc}" "${box}"

    box="$(make_sandbox "${driver_src}")" || return 2
    rc="$(run_driver "${box}" "${ARGS[@]}")"
    check "missing-frontier-is-rc2" 2 "${rc}" "${box}"

    # -- environment preconditions: the only legitimate rc 3 -------------------
    box="$(make_sandbox "${driver_src}" 1)" || return 2
    seed_frontier "${box}"
    rc="$(run_driver "${box}" "${ARGS[@]}")"
    check "no-docker-is-skip" 3 "${rc}" "${box}"

    box="$(make_sandbox "${driver_src}" 1)" || return 2
    seed_frontier "${box}"
    rc="$(RS_ORACLE_REQUIRED=1 run_driver "${box}" "${ARGS[@]}")"
    check "no-docker-when-required" 2 "${rc}" "${box}"

    box="$(make_sandbox "${driver_src}")" || return 2
    seed_frontier "${box}"
    rc="$(STUB_IMAGE_OK=0 run_driver "${box}" "${ARGS[@]}")"
    check "missing-image-is-skip" 3 "${rc}" "${box}"

    # -- oracle-side guards ---------------------------------------------------
    box="$(make_sandbox "${driver_src}")" || return 2
    seed_frontier "${box}"
    rc="$(STUB_ORACLE_MODE=runfail run_driver "${box}" "${ARGS[@]}")"
    check "oracle-container-failed" 2 "${rc}" "${box}"

    box="$(make_sandbox "${driver_src}")" || return 2
    seed_frontier "${box}"
    rc="$(STUB_ORACLE_MODE=nonvisudo run_driver "${box}" "${ARGS[@]}")"
    check "oracle-rc-not-visudo" 2 "${rc}" "${box}"

    box="$(make_sandbox "${driver_src}")" || return 2
    seed_frontier "${box}"
    rc="$(STUB_ORACLE_MODE=shortcount run_driver "${box}" "${ARGS[@]}")"
    check "oracle-partial-run" 2 "${rc}" "${box}"

    box="$(make_sandbox "${driver_src}")" || return 2
    seed_frontier "${box}"
    rc="$(STUB_ORACLE_MODE=badcanary run_driver "${box}" "${ARGS[@]}")"
    check "oracle-canary-flipped" 2 "${rc}" "${box}"

    # The oracle accepts every SWEPT input and rejects only the reject canary.
    # Three of the four buckets are then unreachable, so a clean frontier would
    # be a verdict about nothing. A guard that counted the canaries would see
    # one rc-1 line and wave this through.
    box="$(make_sandbox "${driver_src}")" || return 2
    seed_frontier "${box}"
    rc="$(STUB_ORACLE_MODE=oneclass run_driver "${box}" "${ARGS[@]}")"
    check "oracle-single-verdict-class" 2 "${rc}" "${box}"

    # -- product-side guards --------------------------------------------------
    box="$(make_sandbox "${driver_src}")" || return 2
    seed_frontier "${box}"
    rc="$(STUB_PRODUCT_MODE=toolfail run_driver "${box}" "${ARGS[@]}")"
    check "product-tool-failure" 2 "${rc}" "${box}"

    # A product that emits NOTHING is indistinguishable from a product that
    # found nothing. Every input would score MISSED-GRANT or AGREE depending
    # only on the oracle, and the sweep would report a confident frontier
    # having never opened a file.
    box="$(make_sandbox "${driver_src}")" || return 2
    seed_frontier "${box}"
    rc="$(STUB_PRODUCT_MODE=silent run_driver "${box}" "${ARGS[@]}")"
    check "product-emitted-nothing" 2 "${rc}" "${box}"

    box="$(make_sandbox "${driver_src}")" || return 2
    seed_frontier "${box}"
    rc="$(STUB_PRODUCT_MODE=nocanary run_driver "${box}" "${ARGS[@]}")"
    check "product-skipped-canaries" 2 "${rc}" "${box}"

    box="$(make_sandbox "${driver_src}")" || return 2
    seed_frontier "${box}"
    rc="$(STUB_PRODUCT_MODE=batchdiff run_driver "${box}" "${ARGS[@]}")"
    check "batch-and-single-disagree" 2 "${rc}" "${box}"

    # A concurrent `cargo build` replacing target/debug/rulesteward while the
    # sweep is running would have EARLY batches judged by one binary and LATE
    # batches by another, and the resulting frontier looks entirely ordinary.
    # Nothing else in the driver can notice it.
    box="$(make_sandbox "${driver_src}")" || return 2
    seed_frontier "${box}"
    rc="$(STUB_PRODUCT_MODE=selfmutate run_driver "${box}" "${ARGS[@]}")"
    check "product-binary-changed" 2 "${rc}" "${box}"

    # -- frontier handling ----------------------------------------------------
    box="$(make_sandbox "${driver_src}")" || return 2
    seed_frontier "${box}"
    rc="$(run_driver "${box}" sudoers --length 3 --batch 32 --sample 8)"
    check "frontier-parameter-mismatch" 2 "${rc}" "${box}"

    box="$(make_sandbox "${driver_src}")" || return 2
    seed_frontier "${box}"
    printf 'this file did not parse\n' >"${box}/${FRONTIER_REL}"
    rc="$(run_driver "${box}" "${ARGS[@]}")"
    check "frontier-did-not-parse" 2 "${rc}" "${box}"

    # -- the three verdicts ---------------------------------------------------
    box="$(make_sandbox "${driver_src}")" || return 2
    seed_frontier "${box}"
    rc="$(run_driver "${box}" "${ARGS[@]}" --update-frontier)"
    check "bootstrap-writes-frontier" 0 "${rc}" "${box}"
    rc="$(run_driver "${box}" "${ARGS[@]}")"
    check "clean-matches-frontier" 0 "${rc}" "${box}"

    # Same box, same frontier, one input now diverging.
    rc="$(STUB_PRODUCT_MODE=divergent run_driver "${box}" "${ARGS[@]}")"
    check "new-divergence-is-rc1" 1 "${rc}" "${box}"
    grep -q 'NEW divergence' "${box}/out" ||
        check "new-divergence-says-so" saw-it missing "${box}"

    # A frontier recorded WITH the divergence, then a product that agrees:
    # good news, and still rc 1, because the committed evidence is now stale.
    box="$(make_sandbox "${driver_src}")" || return 2
    seed_frontier "${box}"
    rc="$(STUB_PRODUCT_MODE=divergent run_driver "${box}" "${ARGS[@]}" --update-frontier)"
    check "bootstrap-with-divergence" 0 "${rc}" "${box}"
    rc="$(run_driver "${box}" "${ARGS[@]}")"
    check "closed-divergence-is-rc1" 1 "${rc}" "${box}"
    grep -q 'CLOSED divergence' "${box}/out" ||
        check "closed-divergence-says-so" saw-it missing "${box}"
}

# ---------------------------------------------------------------------------
# The suite proper.
# ---------------------------------------------------------------------------
printf 'rs-sweep-test: running against the real driver\n'
run_suite "${DRIVER}"
suite_rc=$?
[ "${suite_rc}" -eq 2 ] && {
    echo "SUITE ERROR: sandbox construction failed" >&2
    exit 2
}

# ---------------------------------------------------------------------------
# Positive controls.
#
# Each seeds ONE guard's bug back into a COPY of the driver and asserts that the
# case built for that guard STOPS returning the guard's exit code. If a case
# still reports the same rc against the sabotaged driver, then whatever that
# case was measuring, it was not the guard - and the suite would be green while
# the guard could be deleted.
#
# This is the reason the file exists. Every branch in the driver fails toward
# "clean", so a suite of green cases is exactly what a driver with no guards at
# all would also produce.
# ---------------------------------------------------------------------------
sabotage() {
    local out="$1" which="$2"
    python3 - "${DRIVER}" "${out}" "${which}" <<'PYEOF'
import sys
src, out, which = sys.argv[1], sys.argv[2], sys.argv[3]
s = open(src).read()
if which == "product-canary":
    a = '[ "${pa}" = "0,1" ] ||'
    b = '[ "${pf}" = "1" ] ||'
    assert a in s and b in s, "product-canary anchors moved"
    s = s.replace(a, '[ -n "${pa}${pf}x" ] ||').replace(b, '[ -n "x" ] ||')
elif which == "binary-pin":
    a = 'if [ "${BIN_SUM_END}" != "${BIN_SUM_START}" ]; then'
    assert a in s, "binary-pin anchor moved"
    s = s.replace(a, 'if [ "${BIN_SUM_END}" = "" ] && [ "${BIN_SUM_START}" = "impossible" ]; then')
elif which == "batch-single":
    a = '[ "${disagreed}" -eq 0 ] ||'
    assert a in s, "batch-single anchor moved"
    s = s.replace(a, '[ "${disagreed}" -ge 0 ] ||')
else:
    raise SystemExit("unknown sabotage " + which)
open(out, "w").write(s)
PYEOF
}

CONTROL_PHASE=1
control_fail=0

# Control 1: remove the per-batch product canary assertions. `product-emitted-
# nothing` must stop being rc 2.
SAB1="${SANDBOX_BASE}/driver-no-canary.sh"
if sabotage "${SAB1}" product-canary; then
    box="$(make_sandbox "${SAB1}")" || exit 2
    seed_frontier "${box}"
    rc="$(STUB_PRODUCT_MODE=silent run_driver "${box}" "${ARGS[@]}")"
    if [ "${rc}" = "2" ]; then
        printf 'CONTROL PROBLEM %-24s still rc=2 without the canary guard\n' "product-emitted-nothing"
        control_fail=1
    else
        printf 'ok   %-32s guard is load-bearing (sabotaged rc=%s)\n' "control:product-canary" "${rc}"
        PASS=$((PASS + 1))
    fi
else
    echo "SUITE ERROR: could not sabotage the driver (product-canary)" >&2
    exit 2
fi

# Control 2: neuter the batch-vs-single cross-check.
SAB2="${SANDBOX_BASE}/driver-no-xcheck.sh"
if sabotage "${SAB2}" batch-single; then
    box="$(make_sandbox "${SAB2}")" || exit 2
    seed_frontier "${box}"
    rc="$(STUB_PRODUCT_MODE=batchdiff run_driver "${box}" "${ARGS[@]}")"
    if [ "${rc}" = "2" ]; then
        printf 'CONTROL PROBLEM %-24s still rc=2 without the cross-check\n' "batch-and-single-disagree"
        control_fail=1
    else
        printf 'ok   %-32s guard is load-bearing (sabotaged rc=%s)\n' "control:batch-single" "${rc}"
        PASS=$((PASS + 1))
    fi
else
    echo "SUITE ERROR: could not sabotage the driver (batch-single)" >&2
    exit 2
fi
# Control 3: neuter the binary pin. `product-binary-changed` must stop being rc 2.
SAB3="${SANDBOX_BASE}/driver-no-binpin.sh"
if sabotage "${SAB3}" binary-pin; then
    box="$(make_sandbox "${SAB3}")" || exit 2
    seed_frontier "${box}"
    rc="$(STUB_PRODUCT_MODE=selfmutate run_driver "${box}" "${ARGS[@]}")"
    if [ "${rc}" = "2" ]; then
        printf 'CONTROL PROBLEM %-24s still rc=2 without the binary pin\n' "product-binary-changed"
        control_fail=1
    else
        printf 'ok   %-32s guard is load-bearing (sabotaged rc=%s)\n' "control:binary-pin" "${rc}"
        PASS=$((PASS + 1))
    fi
else
    echo "SUITE ERROR: could not sabotage the driver (binary-pin)" >&2
    exit 2
fi
CONTROL_PHASE=0

# ---------------------------------------------------------------------------
# Verdict. Deliberately avoids the token a green `just instrument-test` scrapes
# for (#641): a passing suite must not print the word for failure.
# ---------------------------------------------------------------------------
printf 'rs-sweep-test: %s ok, %s not-ok, %s control problem(s)\n' \
    "${PASS}" "${FAIL}" "${control_fail}"
if [ "${FAIL}" -ne 0 ]; then
    printf 'rs-sweep-test: cases not ok: %s\n' "${FAILED_CASES[*]}"
fi
[ "${FAIL}" -eq 0 ] && [ "${control_fail}" -eq 0 ]
