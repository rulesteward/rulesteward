#!/usr/bin/env bash
#
# `just sweep-sudoers`: an EXHAUSTIVE token sweep of a backend's boundary
# tokenizer against its real oracle, with a COMMITTED FRONTIER file.
#
# WHY THIS EXISTS (the structural point, not a nicety)
#
# The sudoers boundary lane ran five Adversarial Testing Loop rounds. Every one
# found a real defect and four of them found a REGRESSION introduced by the
# previous round's fix. Each round built its own exhaustive oracle differential -
# 55,986 inputs, then 19,607, then 18,420 - positive-controlled it, learned
# something, and then THREW IT AWAY. Round 3's sweep already contained round 4's
# regression inputs and scored them as acceptable loss.
#
# So the instrument is not new. What is new is that its output is COMMITTED, and
# that the next round starts from the previous round's evidence instead of
# rebuilding it. This is the same reasoning as `just diff-<lane>-branch` (#661):
# an adversary is re-rolled every round, so a DRY round measures that draw and
# not the code, and only an accumulating instrument can say otherwise.
#
# THE AXIS. Three differentials exist in this repo and they vary different things:
#
#   `just diff-<lane>`         holds the BINARY fixed, varies the CORPUS
#                              ("has the real subsystem drifted?")
#   `just diff-<lane>-branch`  holds the CORPUS fixed, varies the BINARY
#                              ("would this branch's corpus have caught this
#                               branch's bug?")
#   `just sweep-<lane>`        holds the ORACLE fixed, sweeps the INPUT SPACE
#                              ("what is the shape of the divergence set?")
#
# WHY A TOKEN ALPHABET AND NOT A CHARACTER ALPHABET
#
# The defect shape this lane keeps producing is `sigil blank principal blank
# principal` - the canonical live fail-open was `! alice h1 = NOPASSWD: ALL`.
# That CANNOT BE WRITTEN IN FOUR TOKENS, and every character-alphabet sweep this
# lane ran stopped at length 4 because length 5 over ~9 characters is 59,049
# inputs of mostly-uninteresting noise. Sweeping TOKENS makes length 5 mean five
# meaningful tokens, so the shape is reachable at 32,768 inputs.
#
# WHY FOUR BUCKETS AND WHY THEY ARE NEVER SUMMED
#
# `visudo` rc and our two signals (sudo-F01 "malformed", sudo-W01 "this grants
# passwordless ALL") are independent, and the cells have WILDLY different
# severity. A single verdict-agreement ratio is the instrument defect that let a
# whole round through: it let 434 newly-introduced low-severity rows and a live
# CRITICAL net out to "acceptable". The table:
#
#   visudo  F01  W01   bucket        meaning
#   ------  ---  ---   ------------  ---------------------------------------
#     0      0    1    AGREE         sudo loads it, we report the grant
#     0      1    *    FALSE-FATAL   sudo loads it, we cry malformed
#     0      0    0    MISSED-GRANT  sudo loads it and grants passwordless
#                                    root, and we say NOTHING. The worst cell.
#     1      1    *    AGREE         sudo rejects it, we cry malformed
#     1      0    1    FAIL-OPEN     sudo rejects it, we report a grant off a
#                                    file that will never load
#     1      0    0    AGREE         both decline
#
# MISSED-GRANT is split out from FALSE-FATAL deliberately. Both are "class A"
# (visudo rc 0) but one is a false alarm and the other is silence on a live
# NOPASSWD-root grant - #668's `_ => {}` arm, the reason this lane exists.
# Merging them makes the two counts move together and hides the severe one
# behind the noisy one.
#
# Exit codes (the dev-tooling contract, NOT the rulesteward binary's own):
#   0  the measured frontier MATCHES the committed one
#   1  the frontier MOVED: a NEW divergence, or a CLOSED one (distinct messages;
#      a closed one is still rc 1 because it means an issue was fixed and the
#      committed frontier is now stale evidence)
#   2  tool/environment error, including "this run measured nothing"
#   3  precondition unmet, a legitimate skip (no docker, images absent)
#
# Positive-controlled by scripts/rs-sweep-test.sh, which re-seeds this driver's
# guards into a copy of it and requires a NAMED case to catch each.

set -uo pipefail

usage() {
    cat >&2 <<'EOF'
usage: bash scripts/rs-sweep.sh <lane> [options]

  lane                 sudoers

  --length N           token-sequence length (default 5). The interesting
                       shape needs 5; 4 is a fast smoke of the harness.
  --image IMG          oracle image (default rs-oracle9, sudo 1.9.17p2)
  --batch N            files per product invocation (default 4096)
  --sample N           equivalence-pass sampling stride (default 512)
  --update-frontier    rewrite the committed frontier from this run.
                       Opt-in, per the project's read-only-by-default rule.

Holds the oracle fixed and sweeps the input space, classifying every input into
AGREE / FALSE-FATAL / MISSED-GRANT / FAIL-OPEN, then compares the divergence set
against the committed frontier.
EOF
}

LANE="${1-}"
[ "$#" -gt 0 ] && shift

LENGTH=5
IMAGE=rs-oracle9
BATCH=4096
SAMPLE=512
UPDATE=0

while [ "$#" -gt 0 ]; do
    case "$1" in
    --length)
        LENGTH="${2-}"
        shift 2 || true
        ;;
    --image)
        IMAGE="${2-}"
        shift 2 || true
        ;;
    --batch)
        BATCH="${2-}"
        shift 2 || true
        ;;
    --sample)
        SAMPLE="${2-}"
        shift 2 || true
        ;;
    --update-frontier)
        UPDATE=1
        shift
        ;;
    *)
        echo "rs-sweep: unknown option '$1'" >&2
        usage
        exit 2
        ;;
    esac
done

# ---------------------------------------------------------------------------
# Frozen per-lane table. One place, so a second lane does not edit the first's.
# ---------------------------------------------------------------------------
case "${LANE}" in
sudoers)
    PKG="rulesteward-cli"
    SUBCMD="sudoers"
    FRONTIER_REL="crates/rulesteward-sudoers/tests/corpus/sweep-frontier.txt"
    # The constant tail every generated LHS is pasted in front of. It is what
    # makes a bucket meaningful: every accepted input carries a REAL passwordless
    # ALL grant, so "we printed no sudo-W01" is unambiguously a miss.
    SUFFIX=" = NOPASSWD: ALL"
    FATAL_CODE="sudo-F01"
    GRANT_CODE="sudo-W01"
    ;;
"")
    echo "rs-sweep: no lane given" >&2
    usage
    exit 2
    ;;
*)
    echo "rs-sweep: unknown lane '${LANE}'" >&2
    usage
    exit 2
    ;;
esac

LABEL="sweep-${LANE}"

for numeric in "${LENGTH}" "${BATCH}" "${SAMPLE}"; do
    case "${numeric}" in
    '' | *[!0-9]*)
        echo "${LABEL}: --length/--batch/--sample take a non-negative integer, got '${numeric}'" >&2
        exit 2
        ;;
    esac
done
if [ "${LENGTH}" -lt 1 ] || [ "${BATCH}" -lt 1 ] || [ "${SAMPLE}" -lt 1 ]; then
    echo "${LABEL}: --length/--batch/--sample must all be >= 1" >&2
    exit 2
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)" || exit 2
cd "${REPO_ROOT}" || exit 2

# Confirm we landed in the repo root before resolving anything relative to it.
# If `dirname` were unavailable the expansion above collapses to `cd "/.."`,
# which SUCCEEDS, and every relative path below would resolve against `/`.
if [ ! -f "scripts/rs-oracle-required.sh" ]; then
    echo "${LABEL}: resolved repo root '${REPO_ROOT}' does not contain scripts/rs-oracle-required.sh" >&2
    exit 2
fi

FRONTIER="${REPO_ROOT}/${FRONTIER_REL}"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/rs-sweep-${LANE}-XXXXXX")" || {
    echo "${LABEL}: could not create a working directory" >&2
    exit 2
}

# Deliberately NOT an unconditional cleanup trap: on a moved frontier (rc 1) or a
# tool error (rc 2) the generated inputs and the per-input verdict table ARE the
# evidence, and a sweep that prints "3 new divergences" and then deletes the
# inputs that produced them is useless.
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

# A skip is only honest when nobody declared the oracle required.
skip_or_fail() {
    if [ "${REQUIRED}" -eq 1 ]; then
        printf '%s: %s\n' "${LABEL}" "$*" >&2
        die 2 "the oracle is declared REQUIRED (RS_ORACLE_REQUIRED or RS_REQUIRE_VISUDO), so a missing prerequisite is an error, not a skip"
    fi
    printf '%s: SKIP - %s\n' "${LABEL}" "$*" >&2
    finish 3
}

bash scripts/rs-oracle-required.sh VISUDO
req_rc=$?
case "${req_rc}" in
0) REQUIRED=1 ;;
1) REQUIRED=0 ;;
*)
    REQUIRED=1
    die 2 "scripts/rs-oracle-required.sh VISUDO exited ${req_rc} (expected 0 or 1); refusing to guess whether the oracle is required"
    ;;
esac

# A missing committed frontier is a defect in the REPOSITORY, never a reason to
# skip: the whole contract of this recipe is a comparison against it, and a run
# with nothing to compare against would otherwise report clean.
if [ ! -f "${FRONTIER}" ] && [ "${UPDATE}" -eq 0 ]; then
    die 2 "committed frontier ${FRONTIER_REL} is missing; re-create it with --update-frontier and commit it, do not let a sweep run with nothing to compare against"
fi

# ---------------------------------------------------------------------------
# Environment preconditions. These are the only legitimate rc-3 conditions.
# ---------------------------------------------------------------------------
if ! command -v docker >/dev/null 2>&1; then
    skip_or_fail "docker is not on PATH; the live oracle needs it"
fi
if ! docker image inspect "${IMAGE}" >/dev/null 2>&1; then
    skip_or_fail "image ${IMAGE} not found; build it per tools/oracle-images/README.md"
fi

# ---------------------------------------------------------------------------
# The product binary.
#
# Same two-step as scripts/rs-oracle-diff.sh: consume every cargo-level error
# class in the build, THEN learn the artifact path from a warm --message-format
# run. `cargo run` is not used because it would fold a compile error into the
# sweep's own exit code, and this driver must never report a build failure as a
# divergence.
#
# RS_SWEEP_BIN overrides both steps. That is the seam scripts/rs-sweep-test.sh
# uses to run the whole driver against a stub product with no toolchain at all.
# ---------------------------------------------------------------------------
LOG_BUILD="${WORK}/build.log"
LOG_JSON="${WORK}/build.json"

if [ -n "${RS_SWEEP_BIN-}" ]; then
    BIN="${RS_SWEEP_BIN}"
    [ -x "${BIN}" ] || die 2 "RS_SWEEP_BIN=${BIN} is not executable"
else
    cargo build -p "${PKG}" --locked >"${LOG_BUILD}" 2>&1
    build_rc=$?
    if [ "${build_rc}" -ne 0 ]; then
        tail -30 "${LOG_BUILD}" >&2
        die 2 "cargo could not build ${PKG} (exit ${build_rc}); this is a build error, not a divergence"
    fi
    cargo build -p "${PKG}" --locked --message-format=json >"${LOG_JSON}" 2>/dev/null
    json_rc=$?
    [ "${json_rc}" -eq 0 ] || die 2 "cargo --message-format=json exited ${json_rc} on a build that had just succeeded"

    # `"executable":null` for non-binary artifacts does not match the quoted
    # form, so only real binaries survive. Requiring EXACTLY one is what stops
    # the driver silently picking whichever artifact cargo emitted first.
    mapfile -t EXECUTABLES < <(
        grep -o '"executable":"[^"]*"' "${LOG_JSON}" |
            cut -d'"' -f4 |
            grep -v 'build-script' || true
    )
    if [ "${#EXECUTABLES[@]}" -ne 1 ]; then
        die 2 "expected exactly 1 binary from cargo's JSON output, found ${#EXECUTABLES[@]}: ${EXECUTABLES[*]-none}"
    fi
    BIN="${EXECUTABLES[0]}"
    [ -x "${BIN}" ] || die 2 "cargo reported binary ${BIN}, which is not executable"
fi

# Pin the product binary for the whole run.
#
# The driver resolves ${BIN} ONCE and then invokes it across minutes of batches.
# A concurrent `cargo build` - an operator running `just ci` in another terminal,
# or an editor's check-on-save - replaces that file underneath the sweep, so
# EARLY batches are judged by one binary and LATE batches by another. The
# resulting frontier looks entirely ordinary: no count is missing, no canary
# fires, and nothing else in this driver can see it.
#
# Read via stdin redirect so the digest is of the CONTENTS alone; `cksum FILE`
# would append the filename and make the two readings incomparable if ${BIN}
# were ever expressed differently. Required non-empty because a missing `cksum`
# would otherwise compare "" against "" and pass vacuously - the same
# nothing-ran-reads-as-clean shape this whole driver exists to refuse.
BIN_SUM_START="$(cksum <"${BIN}" 2>/dev/null)"
[ -n "${BIN_SUM_START}" ] ||
    die 2 "could not checksum the product binary ${BIN}; refusing to run a sweep whose binary cannot be pinned for its duration"

# ---------------------------------------------------------------------------
# The token alphabet.
#
# Held in ONE place, as parallel (token, hex) tables, because the frontier file
# records inputs in hex and a drift between the two tables would silently record
# the wrong input against a real divergence.
#
# The hex column is built by CONCATENATING per-token hex rather than by encoding
# the finished string, so no `ord()` is needed and the driver stays inside POSIX
# awk. It is exact for the same reason: the LHS is by construction a
# concatenation of these eight tokens and nothing else.
#
#   1 ax    a two-byte ordinary name (two bytes so a one-byte token cannot
#           accidentally look like a name)
#   2 !     the negation sigil
#   3 ,     the list separator
#   4 "     the quote
#   5 \     the escape
#   6 SP    a BLANK (sudo: [[:blank:]]; us: is_sudoers_blank)
#   7 VT    U+000B, a pure-ASCII byte that is whitespace to Rust's
#           char::is_whitespace but an ORDINARY WORD BYTE to sudo
#   8 NBSP  U+00A0, the same disagreement in a multi-byte encoding
#
# The equivalence variant swaps SP->TAB and VT->FF. Those pairs are
# class-identical on BOTH sides by inspection - which is a claim about the code,
# and this lane has been burned five times by exactly that kind of claim - so the
# second pass MEASURES the claim instead of assuming it. It is run over the
# divergences plus a sampled stride of the agreements, not the full cross
# product, which is why adding it costs seconds rather than tripling the run.
# ---------------------------------------------------------------------------
NTOKENS=8

# Deterministic odometer over NTOKENS^LENGTH. Least-significant digit first, so
# the enumeration order is stable across runs and the frontier diffs cleanly.
emit_digits() {
    awk -v len="${LENGTH}" -v nt="${NTOKENS}" 'BEGIN {
        total = 1
        for (i = 0; i < len; i++) total *= nt
        for (idx = 0; idx < total; idx++) {
            r = idx; s = ""
            for (p = 0; p < len; p++) { s = s (r % nt + 1); r = int(r / nt) }
            print s
        }
    }'
}

# digits -> (input files, oracle manifest, index table). One awk pass: 32,768
# shell iterations would spend all their time on subshell spawn, and this is the
# only part of the sweep that touches the filesystem per input.
materialize() {
    local digits="$1" variant="$2" indir="$3" manifest="$4" indexf="$5"
    awk -v INDIR="${indir}" -v MANIFEST="${manifest}" -v INDEXF="${indexf}" \
        -v BATCH="${BATCH}" -v SUFFIX="${SUFFIX}" -v VARIANT="${variant}" '
    BEGIN {
        T[1]="ax";  T[2]="!";  T[3]=",";  T[4]="\"";
        T[5]="\\";  T[6]=" ";  T[7]="\013"; T[8]="\302\240"
        H[1]="6178"; H[2]="21"; H[3]="2c"; H[4]="22"
        H[5]="5c";   H[6]="20"; H[7]="0b"; H[8]="c2a0"
        if (VARIANT == "equiv") {
            T[6]="\t";   H[6]="09"
            T[7]="\014"; H[7]="0c"
        }
    }
    {
        digits = $1
        s = ""; hx = ""
        n = length(digits)
        for (p = 1; p <= n; p++) {
            d = substr(digits, p, 1) + 0
            s = s T[d]; hx = hx H[d]
        }
        idx = NR - 1
        f = sprintf("%s/b%04d/%08d", INDIR, int(idx / BATCH), idx)
        printf("%s\n", s SUFFIX) > f
        close(f)
        printf("%s\n", s SUFFIX) > MANIFEST
        printf("%d\t%s\t%s\n", idx, digits, hx) > INDEXF
    }' "${digits}"
}

# The container-side oracle driver. Fixed and content-independent: it reads the
# manifest on stdin and prints one `V <lineno> <rc>` per input.
#
# One `visudo` process per input inside ONE container. Per-input `docker run`
# (what capture_sudoers.sh does, correctly, for 68 scenarios) would be ~2s of
# container startup times 32,768.
read -r -d '' ORACLE_SCRIPT <<'EOF'
i=0
while IFS= read -r line; do
    i=$((i + 1))
    printf '%s\n' "$line" | visudo -c -f - >/dev/null 2>&1
    printf 'V %s %s\n' "$i" "$?"
done
EOF

# Two canaries, appended to every manifest, whose verdicts are grounded in the
# committed corpus and were re-derived on rs-oracle9 for this driver:
#   accept  `alice h1 = NOPASSWD: ALL`    visudo rc 0
#   reject  `alice\!h1 = NOPASSWD: ALL`   visudo rc 1  (the escaped sigil is a
#                                         word byte, so the line has no host)
# They are the two-sided control: an image whose `visudo` is missing returns 127
# for every input, and a one-sided control cannot tell that from "everything was
# rejected".
CANARY_ACCEPT="alice h1 = NOPASSWD: ALL"
CANARY_REJECT="alice\\!h1 = NOPASSWD: ALL"

run_oracle() {
    local manifest="$1" out="$2"
    docker run --rm -i --network=none "${IMAGE}" bash -c "${ORACLE_SCRIPT}" \
        <"${manifest}" >"${out}" 2>"${out}.err"
    local rc=$?
    if [ "${rc}" -ne 0 ]; then
        tail -20 "${out}.err" >&2
        die 2 "the oracle container exited ${rc}; no verdict in this run can be trusted"
    fi
}

# JSON -> `idx F G`, one line per file that produced at least one diagnostic.
#
# A file with NO diagnostics never appears in the output at all, so absence
# means (0,0) - which for an accepted input is precisely the MISSED-GRANT cell.
# That is also exactly what an unread file looks like, which is why the canaries
# below are not optional decoration: they are the only thing separating "we were
# silent about this grant" from "the linter never opened the file".
#
# Anchored on the six-space field indentation rather than a bare substring, so a
# diagnostic MESSAGE that happened to contain the text `"file": "` could not be
# mistaken for the field. Within one diagnostic object `code` always precedes
# `file`, so the pairing is positional and needs no JSON parser.
parse_product() {
    local json="$1" fatal="$2" grant="$3"
    awk -v FATAL="${fatal}" -v GRANT="${grant}" '
    /^      "code": "/ {
        c = $0; sub(/^      "code": "/, "", c); sub(/".*$/, "", c); next
    }
    /^      "file": "/ {
        p = $0; sub(/^      "file": "/, "", p); sub(/".*$/, "", p)
        n = split(p, parts, "/"); base = parts[n]
        seen[base] = 1
        if (c == FATAL) F[base] = 1
        if (c == GRANT) G[base] = 1
        next
    }
    END {
        for (b in seen) printf "%s\t%d\t%d\n", b, F[b] + 0, G[b] + 0
    }' "${json}"
}

# ---------------------------------------------------------------------------
# One full pass: digits -> inputs -> (oracle verdict, product verdict) -> bucket
# per input. Used twice, once for the base alphabet and once for the
# equivalence variant, so the guards below cannot be true for one and skipped
# for the other.
#
# Sets PASS_BUCKETS (the `idx<TAB>bucket` table) and PASS_TOTAL.
# ---------------------------------------------------------------------------
sweep_pass() {
    local digits="$1" variant="$2" tag="$3"
    local dir="${WORK}/${tag}"
    local indir="${dir}/in" manifest="${dir}/manifest" indexf="${dir}/index"
    local oracle="${dir}/oracle" product="${dir}/product" buckets="${dir}/buckets"

    local total
    total="$(wc -l <"${digits}")" || die 2 "could not count ${digits}"
    total="${total// /}"
    [ "${total}" -gt 0 ] || die 2 "pass '${tag}' was handed an EMPTY digit set; a sweep of nothing must never report clean"

    mkdir -p "${indir}" || die 2 "could not create ${indir}"
    local nbatch b
    nbatch=$(((total + BATCH - 1) / BATCH))
    for ((b = 0; b < nbatch; b++)); do
        mkdir -p "$(printf '%s/b%04d' "${indir}" "${b}")" ||
            die 2 "could not create batch directory ${b} under ${indir}"
    done

    materialize "${digits}" "${variant}" "${indir}" "${manifest}" "${indexf}" ||
        die 2 "input materialization failed for pass '${tag}'"

    # G1 - the generator produced exactly what the odometer promised. A silent
    # short write here would shrink the swept space without shrinking any count
    # the operator reads.
    local wrote
    wrote="$(wc -l <"${manifest}")" || die 2 "could not count ${manifest}"
    wrote="${wrote// /}"
    [ "${wrote}" -eq "${total}" ] ||
        die 2 "pass '${tag}': generated ${wrote} inputs but the odometer enumerated ${total}"

    # The product canaries go in EVERY batch directory. Names sort after the
    # zero-padded indices and contain no `.`, so the drop-in eligibility rules
    # keep them.
    for ((b = 0; b < nbatch; b++)); do
        local bd
        bd="$(printf '%s/b%04d' "${indir}" "${b}")"
        printf '%s\n' "${CANARY_ACCEPT}" >"${bd}/zzcanary-accept" ||
            die 2 "could not write the accept canary into ${bd}"
        printf '%s\n' "${CANARY_REJECT}" >"${bd}/zzcanary-reject" ||
            die 2 "could not write the reject canary into ${bd}"
    done

    # The oracle canaries go at the END of the manifest, so the sweep's own
    # indices are untouched.
    printf '%s\n' "${CANARY_ACCEPT}" >>"${manifest}"
    printf '%s\n' "${CANARY_REJECT}" >>"${manifest}"

    run_oracle "${manifest}" "${oracle}"

    # G2 - one verdict per input, no more and no fewer. A `read` that stopped
    # early (a NUL byte, a truncated pipe) would otherwise leave later inputs
    # unclassified, and an unclassified accepted input scores as MISSED-GRANT.
    local ocount
    ocount="$(grep -c '^V ' "${oracle}")"
    [ "${ocount}" -eq $((total + 2)) ] ||
        die 2 "pass '${tag}': the oracle returned ${ocount} verdicts for $((total + 2)) inputs; a partial oracle run cannot be classified"

    # G3 - every verdict is a verdict. `visudo -c` exits 0 or 1; ANY other value
    # means it did not run (127) or did something else entirely, and every such
    # input would otherwise be scored as "sudo rejected it".
    local badrc
    badrc="$(awk '$1 == "V" && $3 != 0 && $3 != 1 { print; exit }' "${oracle}")"
    [ -z "${badrc}" ] ||
        die 2 "pass '${tag}': the oracle returned a non-visudo exit code (${badrc}); visudo -c exits 0 or 1, so this run measured something else"

    # G4 - the two-sided oracle control.
    local ca cr
    ca="$(awk -v n="$((total + 1))" '$1 == "V" && $2 == n { print $3 }' "${oracle}")"
    cr="$(awk -v n="$((total + 2))" '$1 == "V" && $2 == n { print $3 }' "${oracle}")"
    [ "${ca}" = "0" ] ||
        die 2 "pass '${tag}': the ACCEPT oracle canary returned rc '${ca}', expected 0; the oracle is broken, so neither agreement nor divergence would be a truthful verdict"
    [ "${cr}" = "1" ] ||
        die 2 "pass '${tag}': the REJECT oracle canary returned rc '${cr}', expected 1; the oracle is broken, so neither agreement nor divergence would be a truthful verdict"

    # ---------------------------------------------------------------------
    # Product side, one invocation per batch directory.
    # ---------------------------------------------------------------------
    : >"${product}"
    for ((b = 0; b < nbatch; b++)); do
        local bd json
        bd="$(printf '%s/b%04d' "${indir}" "${b}")"
        json="${dir}/out-b${b}.json"
        "${BIN}" "${SUBCMD}" lint --format json "${bd}" >"${json}" 2>"${json}.err"
        local prc=$?
        # 0 clean, 1 warnings, 2 errors, 5 unparseable-config: all ordinary
        # findings outcomes over a directory that by construction contains
        # malformed lines. 3 (tool failure) and anything else is not.
        case "${prc}" in
        0 | 1 | 2 | 5) ;;
        *)
            tail -20 "${json}.err" >&2
            die 2 "pass '${tag}': the product exited ${prc} on batch ${b}; that is a tool failure, not a findings outcome"
            ;;
        esac
        parse_product "${json}" "${FATAL_CODE}" "${GRANT_CODE}" >"${dir}/p-b${b}" ||
            die 2 "pass '${tag}': could not parse the product's JSON for batch ${b}"

        # G5 - the two-sided product control, per batch. This is what separates
        # "the linter was silent about this grant" from "the linter never opened
        # these files", which are the same observation in the JSON.
        local pa pf pg
        pa="$(awk -F'\t' '$1 == "zzcanary-accept" { print $2 "," $3 }' "${dir}/p-b${b}")"
        [ "${pa}" = "0,1" ] ||
            die 2 "pass '${tag}' batch ${b}: the accept canary scored '${pa}', expected '0,1' (no ${FATAL_CODE}, one ${GRANT_CODE}); this batch's silence proves nothing"
        pf="$(awk -F'\t' '$1 == "zzcanary-reject" { print $2 }' "${dir}/p-b${b}")"
        [ "${pf}" = "1" ] ||
            die 2 "pass '${tag}' batch ${b}: the reject canary did not produce ${FATAL_CODE}; this batch's silence proves nothing"

        grep -v '^zzcanary' "${dir}/p-b${b}" >>"${product}"
    done

    # G6 - batch mode and single-file mode must agree.
    #
    # Directory mode is a DIFFERENT code path from the one every corpus test and
    # every hand probe uses: it resolves one config across many drop-ins, and
    # sudo-W04 demonstrably moves between files under it. The claim that F01 and
    # W01 are per-line and therefore immune is a claim about the code, so it is
    # measured on a fixed stride rather than assumed.
    local i disagreed=0 checked=0
    for ((i = 0; i < total; i += SAMPLE)); do
        local sf sjson sb single batch
        sf="$(printf '%s/b%04d/%08d' "${indir}" "$((i / BATCH))" "${i}")"
        sjson="${dir}/single-${i}.json"
        "${BIN}" "${SUBCMD}" lint --format json "${sf}" >"${sjson}" 2>/dev/null
        sb="$(parse_product "${sjson}" "${FATAL_CODE}" "${GRANT_CODE}")"
        single="$(printf '%s\n' "${sb}" | awk -F'\t' -v n="$(printf '%08d' "${i}")" '$1 == n { print $2 "," $3 }')"
        [ -n "${single}" ] || single="0,0"
        batch="$(awk -F'\t' -v n="$(printf '%08d' "${i}")" '$1 == n { print $2 "," $3 }' "${product}")"
        [ -n "${batch}" ] || batch="0,0"
        checked=$((checked + 1))
        if [ "${single}" != "${batch}" ]; then
            echo "${LABEL}: index ${i} scores '${batch}' batched and '${single}' alone" >&2
            disagreed=$((disagreed + 1))
        fi
        rm -f "${sjson}"
    done
    [ "${checked}" -gt 0 ] ||
        die 2 "pass '${tag}': the batch-vs-single cross-check ran ZERO comparisons; it cannot certify the batch path"
    [ "${disagreed}" -eq 0 ] ||
        die 2 "pass '${tag}': ${disagreed} of ${checked} sampled inputs score differently batched than alone; the batch path is not measuring what the single-file path measures"

    # ---------------------------------------------------------------------
    # Classification. Every index must be covered; an uncovered index is a tool
    # error, never a bucket.
    # ---------------------------------------------------------------------
    awk -F'\t' -v total="${total}" -v OFS='\t' '
    FILENAME == ORACLE && $1 == "V" { orc[$2 - 1] = $3; next }
    FILENAME != ORACLE { F[$1 + 0] = $2; G[$1 + 0] = $3; next }
    END {
        for (i = 0; i < total; i++) {
            if (!(i in orc)) { printf("UNCOVERED %d\n", i) > "/dev/stderr"; bad++; continue }
            v = orc[i] + 0; f = F[i] + 0; g = G[i] + 0
            if (v == 0 && f == 1)             b = "FALSE-FATAL"
            else if (v == 0 && g == 1)        b = "AGREE"
            else if (v == 0)                  b = "MISSED-GRANT"
            else if (f == 1)                  b = "AGREE"
            else if (g == 1)                  b = "FAIL-OPEN"
            else                              b = "AGREE"
            print i, b
        }
        if (bad > 0) exit 3
    }' ORACLE="${oracle}" FS='[ \t]+' "${oracle}" FS='\t' "${product}" >"${buckets}"
    local crc=$?
    [ "${crc}" -eq 0 ] ||
        die 2 "pass '${tag}': classification left inputs uncovered (awk exit ${crc}); an unclassified accepted input would score as MISSED-GRANT"

    local bcount
    bcount="$(wc -l <"${buckets}")"
    bcount="${bcount// /}"
    [ "${bcount}" -eq "${total}" ] ||
        die 2 "pass '${tag}': classified ${bcount} of ${total} inputs"

    PASS_BUCKETS="${buckets}"
    PASS_INDEX="${indexf}"
    PASS_TOTAL="${total}"
}

# ---------------------------------------------------------------------------
# Pass 1: the base alphabet over the full cross product.
# ---------------------------------------------------------------------------
DIGITS="${WORK}/digits"
emit_digits >"${DIGITS}" || die 2 "the odometer failed"
EXPECTED=1
for ((i = 0; i < LENGTH; i++)); do EXPECTED=$((EXPECTED * NTOKENS)); done
gen="$(wc -l <"${DIGITS}")"
gen="${gen// /}"
[ "${gen}" -eq "${EXPECTED}" ] ||
    die 2 "the odometer enumerated ${gen} sequences, expected ${NTOKENS}^${LENGTH}=${EXPECTED}"

printf '%s: pass 1, %s inputs over %s tokens at length %s\n' "${LABEL}" "${EXPECTED}" "${NTOKENS}" "${LENGTH}" >&2
sweep_pass "${DIGITS}" base base
BASE_BUCKETS="${PASS_BUCKETS}"
BASE_INDEX="${PASS_INDEX}"

# G7 - the oracle must have produced BOTH verdicts across the swept space.
# An alphabet where visudo accepts everything (or rejects everything) makes
# three of the four buckets unreachable, and the sweep would report a clean
# frontier having been unable to observe a divergence at all.
# `$2 <= EXPECTED` excludes the two canaries. They are one accept and one
# reject BY CONSTRUCTION, so counting them guarantees both classes appear and
# turns this guard into a tautology: an oracle that accepted every swept input
# would still show one rc-1 line and pass.
oz="$(awk -v t="${EXPECTED}" '$1 == "V" && $2 <= t && $3 == 0' "${WORK}/base/oracle" | wc -l)"
oo="$(awk -v t="${EXPECTED}" '$1 == "V" && $2 <= t && $3 == 1' "${WORK}/base/oracle" | wc -l)"
oz="${oz// /}"
oo="${oo// /}"
if [ "${oz}" -eq 0 ] || [ "${oo}" -eq 0 ]; then
    die 2 "the oracle returned only one verdict class across the whole sweep (rc0=${oz}, rc1=${oo}); the alphabet is degenerate or the oracle is stuck"
fi

# ---------------------------------------------------------------------------
# Pass 2: the class-equivalence probe.
#
# Every divergence, plus a fixed stride of the agreements, re-run with SP->TAB
# and VT->FF. Those pairs are class-identical on both sides BY INSPECTION; this
# is the measurement that inspection is right. A disagreement is a per-byte
# recognizer split - the exact defect shape this lane has produced five times -
# and it is reported as its own kind rather than folded into a bucket count.
# ---------------------------------------------------------------------------
EQ_IDX="${WORK}/eq-idx"
awk -F'\t' -v s="${SAMPLE}" '$2 != "AGREE" || ($1 % s) == 0 { print $1 }' \
    "${BASE_BUCKETS}" >"${EQ_IDX}"
EQ_DIGITS="${WORK}/eq-digits"
awk -F'\t' 'NR == FNR { want[$1] = 1; next } ($1 in want) { print $2 }' \
    "${EQ_IDX}" "${BASE_INDEX}" >"${EQ_DIGITS}"
eqn="$(wc -l <"${EQ_DIGITS}")"
eqn="${eqn// /}"
[ "${eqn}" -gt 0 ] ||
    die 2 "the equivalence pass selected ZERO inputs; it cannot certify the SP/TAB and VT/FF classes"

printf '%s: pass 2, %s inputs with SP->TAB and VT->FF\n' "${LABEL}" "${eqn}" >&2
sweep_pass "${EQ_DIGITS}" equiv equiv
EQ_BUCKETS="${PASS_BUCKETS}"

# The binary that finished the sweep must be the binary that started it. Checked
# HERE, before any verdict is computed, so a swap can never reach the frontier.
BIN_SUM_END="$(cksum <"${BIN}" 2>/dev/null)"
if [ "${BIN_SUM_END}" != "${BIN_SUM_START}" ]; then
    die 2 "the product binary changed during the sweep (${BIN_SUM_START} -> ${BIN_SUM_END}); earlier and later batches were judged by DIFFERENT builds, so this run's frontier means nothing. Do not run a build concurrently with a sweep."
fi

# ---------------------------------------------------------------------------
# The measured frontier body: one sorted line per divergence, plus one per
# class-equivalence split. Inputs are recorded in HEX because they contain
# control bytes and NBSP, and because the frontier is a committed file that must
# stay pure ASCII.
# ---------------------------------------------------------------------------
MEASURED="${WORK}/measured-body"
{
    awk -F'\t' 'NR == FNR { b[$1] = $2; next }
        ($1 in b) && b[$1] != "AGREE" { printf "DIV\t%s\t%s\t%s\n", b[$1], $3, $2 }' \
        "${BASE_BUCKETS}" "${BASE_INDEX}"

    # The equivalence pass re-enumerates from 0, so its Nth row corresponds to
    # the Nth selected base index. Joined positionally, which is exact because
    # EQ_DIGITS was written in EQ_IDX order.
    paste "${EQ_IDX}" "${EQ_BUCKETS}" |
        awk -F'\t' 'NR == FNR { bb[$1] = $2; next }
            { base = bb[$1]; variant = $3
              if (base != variant) print $1 "\t" base "\t" variant }' \
            "${BASE_BUCKETS}" - |
        awk -F'\t' 'NR == FNR { h[$1] = $3; next }
            { printf "EQ\t%s>%s\t%s\t-\n", $2, $3, h[$1] }' "${BASE_INDEX}" -
} | LC_ALL=C sort >"${MEASURED}"

count_bucket() { awk -F'\t' -v b="$1" '$2 == b' "${BASE_BUCKETS}" | wc -l | tr -d ' '; }
N_AGREE="$(count_bucket AGREE)"
N_FALSE="$(count_bucket FALSE-FATAL)"
N_MISSED="$(count_bucket MISSED-GRANT)"
N_FAILOPEN="$(count_bucket FAIL-OPEN)"
N_EQSPLIT="$(grep -c '^EQ' "${MEASURED}")"

# The four counts must account for every input. A mismatch is an instrument
# defect - a bucket that fell out of the table - not a finding about the product.
sumcheck=$((N_AGREE + N_FALSE + N_MISSED + N_FAILOPEN))
[ "${sumcheck}" -eq "${EXPECTED}" ] ||
    die 2 "the four bucket counts total ${sumcheck} but ${EXPECTED} inputs were swept; a bucket is missing from the table"

# ---------------------------------------------------------------------------
# The committed frontier.
#
# Body lines are TAB-separated: kind, bucket, hex, digits, issue. The comparison
# is over the first FOUR fields; `issue` is human metadata carried across
# updates, so re-routing a known divergence to a different issue number does not
# read as a frontier move.
# ---------------------------------------------------------------------------
COMMITTED="${WORK}/committed-body"
if [ -f "${FRONTIER}" ]; then
    # Header agreement first. Comparing a length-4 run against a length-5
    # frontier would report the entire committed set as CLOSED - a spectacular
    # false "everything was fixed" - so the parameters are checked before the
    # sets are.
    fl="$(awk '$1 == "LENGTH" { print $2; exit }' "${FRONTIER}")"
    ft="$(awk '$1 == "TOKENS" { print $2; exit }' "${FRONTIER}")"
    if [ "${UPDATE}" -eq 0 ]; then
        [ "${fl}" = "${LENGTH}" ] ||
            die 2 "the committed frontier was measured at length '${fl}' and this run used '${LENGTH}'; these two sets are not comparable"
        [ "${ft}" = "${NTOKENS}" ] ||
            die 2 "the committed frontier was measured over '${ft}' tokens and this run used '${NTOKENS}'; these two sets are not comparable"
    fi
    awk -F'\t' '$1 == "DIV" || $1 == "EQ" { printf "%s\t%s\t%s\t%s\n", $1, $2, $3, $4 }' \
        "${FRONTIER}" | LC_ALL=C sort >"${COMMITTED}"
    # A frontier that exists but parses to nothing is a defect in the file, not
    # a product with no divergences: the two are indistinguishable downstream,
    # and the header above proves the file was at least the right shape.
    if [ ! -s "${COMMITTED}" ] && ! grep -q '^COUNT ' "${FRONTIER}"; then
        die 2 "the committed frontier ${FRONTIER_REL} has neither divergence lines nor COUNT lines; it did not parse, and an unparsed frontier must not read as an empty one"
    fi
else
    : >"${COMMITTED}"
fi

NEWDIV="${WORK}/new"
CLOSEDDIV="${WORK}/closed"
LC_ALL=C comm -23 "${MEASURED}" "${COMMITTED}" >"${NEWDIV}"
LC_ALL=C comm -13 "${MEASURED}" "${COMMITTED}" >"${CLOSEDDIV}"
n_new="$(wc -l <"${NEWDIV}")"
n_new="${n_new// /}"
n_closed="$(wc -l <"${CLOSEDDIV}")"
n_closed="${n_closed// /}"

render_rows() {
    # Renders hex back to a token-name spelling so a maintainer can read the
    # frontier without decoding it by hand.
    awk -F'\t' '{
        d = $4; names = ""
        if (d != "-") {
            split("ax|BANG|COMMA|DQUOTE|BSLASH|SP|VT|NBSP", NM, "|")
            for (p = 1; p <= length(d); p++) {
                names = names (p > 1 ? " " : "") NM[substr(d, p, 1) + 0]
            }
        } else { names = "(equivalence variant)" }
        printf "  %-4s %-22s %-18s %s\n", $1, $2, $3, names
    }' "$1"
}

# ---------------------------------------------------------------------------
# Report. The four counts are printed on four lines and never added together:
# a single agreement ratio is the instrument defect that let a live CRITICAL
# net out against 434 low-severity rows in an earlier round.
# ---------------------------------------------------------------------------
printf '%s: %s inputs swept at length %s over %s tokens (%s)\n' \
    "${LABEL}" "${EXPECTED}" "${LENGTH}" "${NTOKENS}" "${IMAGE}"
printf '  AGREE         %s\n' "${N_AGREE}"
printf '  FALSE-FATAL   %s   (visudo rc 0, we emit %s)\n' "${N_FALSE}" "${FATAL_CODE}"
printf '  MISSED-GRANT  %s   (visudo rc 0, we emit neither; a live grant we are silent about)\n' "${N_MISSED}"
printf '  FAIL-OPEN     %s   (visudo rc 1, we report a grant)\n' "${N_FAILOPEN}"
printf '  EQ-SPLIT      %s   (SP/TAB or VT/FF changed the verdict)\n' "${N_EQSPLIT}"

if [ "${UPDATE}" -eq 1 ]; then
    awk -F'\t' '$1 == "DIV" || $1 == "EQ"' "${FRONTIER}" 2>/dev/null >"${WORK}/old-issues" || : >"${WORK}/old-issues"
    {
        printf '# sudoers boundary-tokenizer sweep frontier.\n'
        printf '#\n'
        printf '# Written by `just sweep-%s-update`. This file is EVIDENCE, not\n' "${LANE}"
        printf '# configuration: it records the divergence set that was measured, so that the\n'
        printf '# next Adversarial Testing Loop round starts from the last one instead of\n'
        printf '# rebuilding it. `just sweep-%s` exits 1 when the measured set no longer\n' "${LANE}"
        printf '# matches, in EITHER direction - a new divergence and a closed one both mean\n'
        printf '# this file is now stale.\n'
        printf '#\n'
        printf '# Inputs are hex because they contain VT and NBSP and this file stays ASCII.\n'
        printf '# Every input is <LHS>%s, so an accepted one carries a REAL passwordless\n' "${SUFFIX}"
        printf '# grant and "we said nothing" is unambiguously a miss.\n'
        printf '#\n'
        printf '# The ISSUE column is metadata, not part of the comparison: re-routing a known\n'
        printf '# divergence to a different issue does not read as a frontier move. UNROUTED\n'
        printf '# means NOT YET TRIAGED. Attributing a row to an issue is a claim about WHY it\n'
        printf '# diverges, and a shape that merely resembles one is not evidence: issue #669\n'
        printf '# covers `x"ab"ALL`, a single space-separated word that sudo lexes as three\n'
        printf '# tokens, so counting words would mis-route it. Route a row when it has been\n'
        printf '# checked, and leave it UNROUTED when it has not.\n'
        printf '#\n'
        printf 'LANE %s\n' "${LANE}"
        printf 'LENGTH %s\n' "${LENGTH}"
        printf 'TOKENS %s\n' "${NTOKENS}"
        # The digit->token legend. Without it the DIGITS column is opaque
        # without reading this script, and the frontier has to be readable on
        # its own: it is the artifact a later round reasons from.
        printf 'ALPHABET 1=ax 2=! 3=, 4=dquote 5=backslash 6=SP 7=VT(0x0b) 8=NBSP(U+00A0)\n'
        printf 'ALPHABET-EQUIV pass 2 substitutes 6=TAB(0x09) 7=FF(0x0c) to test class-equivalence\n'
        printf 'IMAGE %s\n' "${IMAGE}"
        printf 'TOTAL %s\n' "${EXPECTED}"
        printf 'COUNT AGREE %s\n' "${N_AGREE}"
        printf 'COUNT FALSE-FATAL %s\n' "${N_FALSE}"
        printf 'COUNT MISSED-GRANT %s\n' "${N_MISSED}"
        printf 'COUNT FAIL-OPEN %s\n' "${N_FAILOPEN}"
        printf 'COUNT EQ-SPLIT %s\n' "${N_EQSPLIT}"
        # Preserve the issue column for rows already routed; UNROUTED otherwise.
        #
        # Keyed on FILENAME rather than the usual `NR == FNR`. That idiom is
        # WRONG here and silently discarded every row: when the previous
        # frontier holds no DIV lines - a bootstrap, or a run right after every
        # divergence closed - the first file is EMPTY, so awk reads no record
        # from it, FNR restarts at 1 on the second file, and `NR == FNR` is true
        # for the whole MEASURED set. Every row is then filed as an old issue
        # and nothing is printed. Measured 2026-08-20: 4,210 divergences in,
        # `frontier REWRITTEN (0 divergence rows)` out.
        awk -F'\t' -v OLD="${WORK}/old-issues" 'FILENAME == OLD { iss[$1 "\t" $2 "\t" $3 "\t" $4] = $5; next }
            { k = $1 "\t" $2 "\t" $3 "\t" $4
              printf "%s\t%s\n", k, (k in iss && iss[k] != "" ? iss[k] : "UNROUTED") }' \
            "${WORK}/old-issues" "${MEASURED}"
    } >"${FRONTIER}.new" || die 2 "could not write ${FRONTIER_REL}.new"

    # The write-back must carry EVERY measured row. This is the guard that the
    # NR==FNR defect above needed and did not have: the rewrite reported success
    # and a row count of zero, and a count of zero read exactly like a clean
    # sweep. A transform that dropped rows must never report a written frontier.
    wrote_rows="$(grep -cE '^(DIV|EQ)'"$(printf '\t')" "${FRONTIER}.new")"
    meas_rows="$(wc -l <"${MEASURED}")"
    if [ "${wrote_rows// /}" -ne "${meas_rows// /}" ]; then
        die 2 "the rewrite carried ${wrote_rows// /} rows for ${meas_rows// /} measured divergences; refusing to commit a frontier that lost evidence"
    fi
    mv "${FRONTIER}.new" "${FRONTIER}" || die 2 "could not replace ${FRONTIER_REL}"
    printf '%s: frontier REWRITTEN (%s divergence rows, %s equivalence rows)\n' \
        "${LABEL}" "$(grep -c '^DIV' "${FRONTIER}")" "$(grep -c '^EQ' "${FRONTIER}")"
    printf '%s: review the diff before committing. UNROUTED means NOT YET TRIAGED, not\n' "${LABEL}"
    printf '%s: unimportant; the ISSUE column is metadata and is preserved across updates.\n' "${LABEL}"
    finish 0
fi

if [ "${n_new}" -eq 0 ] && [ "${n_closed}" -eq 0 ]; then
    printf '%s: OK - the measured frontier matches %s (%s rows)\n' \
        "${LABEL}" "${FRONTIER_REL}" "$(wc -l <"${MEASURED}" | tr -d ' ')"
    finish 0
fi

if [ "${n_new}" -gt 0 ]; then
    printf '%s: %s NEW divergence(s) - inputs that diverge now and did not before:\n' "${LABEL}" "${n_new}" >&2
    render_rows "${NEWDIV}" >&2
fi
if [ "${n_closed}" -gt 0 ]; then
    printf '%s: %s CLOSED divergence(s) - the committed frontier lists these and they now AGREE.\n' "${LABEL}" "${n_closed}" >&2
    printf '%s: that is good news and still rc 1: an issue was fixed, so the committed evidence is stale.\n' "${LABEL}" >&2
    printf '%s: re-run with --update-frontier and commit the result.\n' "${LABEL}" >&2
    render_rows "${CLOSEDDIV}" >&2
fi
finish 1
