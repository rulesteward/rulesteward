#!/usr/bin/env bash
# capture_auditd.sh <outdir> - Lane A (auditd) Tier-2 live capture.
#
# Re-derives the per-line ACCEPT/REJECT verdict of every corpus scenario from a
# REAL `auditctl -R` and writes three flat TSVs (el8.tsv / el9.tsv / el10.tsv) into
# <outdir>. Invoked by scripts/rs-oracle-diff.sh (`just diff-auditd`); also safe to
# run by hand to regenerate the committed corpus under
# crates/rulesteward-auditd/tests/corpus/auditd-oracle/.
#
# Exit codes (CONTRIBUTING.md "Differential oracle contract", Tier-2 form):
#   0  captured cleanly
#   2  tool/environment error (docker present but something else failed, or the
#      safety canary fired - see below)
#   3  precondition unmet (no docker, or the rs-oracle images are not built) -
#      a legitimate skip, per scripts/rs-oracle-diff.sh's own docker/image checks.
#      This script re-checks independently so it stays correct when run by hand.
#
# SAFETY (tools/oracle-images/README.md "Lane A: audit netlink safety" - read
# that file before touching this invocation):
#
#   Audit netlink is NOT namespaced. A container that can actually reach it
#   mutates the HOST kernel's audit ruleset.
#
#   - NEVER --privileged, NEVER --network host, NEVER -v /:/host.
#   - The only permitted invocation is
#     `docker run --rm --network=none --cap-add=AUDIT_CONTROL rs-oracle<N>`.
#   - The `auditctl -s` canary runs FIRST, every container instantiation, before
#     any rule is tested in that same container. It is a status READ with zero
#     blast radius. If it SUCCEEDS (rc 0), netlink is live and the host is
#     reachable: this script ABORTS immediately (exit 2) rather than capture
#     anything. Only a FAILING canary permits testing a rule in that container.
#
# CLASSIFICATION (measured 2026-07-25, all three images; see the images README):
#   rc 4 (no capability)                    -> UNUSABLE, abort (should not occur;
#                                               we always pass --cap-add=AUDIT_CONTROL)
#   rc 0 (rule loaded)                      -> netlink reachable, ABORT (exit 2)
#   rc 1, stderr contains "Error sending add rule data request" -> ACCEPT
#     (the rule PARSED; the daemon-add was refused only by our sandboxed EPERM)
#   rc 1, otherwise (any other non-empty output, OR both streams empty)
#                                            -> REJECT (`-R` swallows many parse
#                                               diagnostics silently; see README)
#
# TOOLING CONSTRAINT: no jq, no python3, no find anywhere in this script (neither
# host- nor container-side) - plain bash + coreutils (grep/sed/cat/printf/base64/
# mktemp) only, so this runs on a minimal CI runner and inside the el8 image alike.

set -uo pipefail

OUTDIR="${1-}"
if [ -z "${OUTDIR}" ]; then
    echo "usage: capture_auditd.sh <outdir>" >&2
    exit 3
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)" || exit 2
EXISTING_CORPUS="${SCRIPT_DIR}/../auditd"

if ! command -v docker >/dev/null 2>&1; then
    echo "capture_auditd: docker is not on PATH" >&2
    exit 3
fi

IMAGES=(rs-oracle8 rs-oracle9 rs-oracle10)
if ! docker image inspect "${IMAGES[@]}" >/dev/null 2>&1; then
    echo "capture_auditd: images ${IMAGES[*]} not found; build them per tools/oracle-images/README.md" >&2
    exit 3
fi

mkdir -p "${OUTDIR}" || {
    echo "capture_auditd: could not create ${OUTDIR}" >&2
    exit 2
}

# ---------------------------------------------------------------------------
# Field escaping for the flat TSV (rule / evidence columns).
#
# A rule line may itself carry a literal TAB (the #584 tab-tokenization
# scenarios) or a literal 0x01 byte (the #489 embedded-key-separator scenario),
# either of which would corrupt `splitn(6, '\t')` column boundaries if written
# raw. `\` -> `\\` MUST run first, or the backslashes introduced by the other
# two substitutions would themselves be re-escaped.
# ---------------------------------------------------------------------------
esc_field() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//$'\t'/\\t}"
    s="${s//$'\x01'/\\x01}"
    printf '%s' "$s"
}

# Flatten stdout+stderr into one evidence string: tabs/newlines -> single
# space, collapse runs of spaces, trim. Mirrors
# tools/fapolicyd-probe-update's "flattened combined daemon stdout+stderr".
flatten_evidence() {
    local so="$1" se="$2"
    printf '%s %s' "$so" "$se" | tr '\t\n' '  ' | sed 's/  */ /g' | sed 's/^ *//;s/ *$//'
}

# ---------------------------------------------------------------------------
# One (image, id, class, rule) -> one TSV row, appended to $OUT (set by caller).
# Runs the canary + the rule in ONE container instantiation. Returns nonzero on
# any safety abort or unusable capture; the caller must treat that as fatal.
# ---------------------------------------------------------------------------
capture_one() {
    local image="$1" id="$2" class="$3" line="$4"
    local raw rc so se ev verdict

    raw=$(docker run --rm -i --network=none --cap-add=AUDIT_CONTROL "${image}" bash -c '
        set -u
        auditctl -s >/tmp/c.o 2>/tmp/c.e
        crc=$?
        if [ "$crc" -eq 0 ]; then
            echo "CANARY_LIVE_ABORT"
            exit 0
        fi
        f=$(mktemp)
        cat > "$f"
        auditctl -R "$f" 1>/tmp/o 2>/tmp/e
        rc=$?
        printf "RC=%s\n" "$rc"
        printf "OUT_B64=%s\n" "$(base64 -w0 /tmp/o)"
        printf "ERR_B64=%s\n" "$(base64 -w0 /tmp/e)"
        rm -f "$f" /tmp/o /tmp/e /tmp/c.o /tmp/c.e
    ' <<<"${line}")

    if printf '%s' "${raw}" | grep -q "CANARY_LIVE_ABORT"; then
        echo "capture_auditd: SAFETY ABORT - auditctl -s canary SUCCEEDED on ${image} (netlink is live, host reachable); refusing to capture ${id}" >&2
        return 2
    fi

    rc=$(printf '%s' "${raw}" | grep '^RC=' | cut -d= -f2)
    so=$(printf '%s' "${raw}" | grep '^OUT_B64=' | cut -d= -f2 | base64 -d 2>/dev/null)
    se=$(printf '%s' "${raw}" | grep '^ERR_B64=' | cut -d= -f2 | base64 -d 2>/dev/null)

    if [ -z "${rc}" ]; then
        echo "capture_auditd: no RC line from ${image} for ${id}; container output was: ${raw}" >&2
        return 2
    fi
    if [ "${rc}" -eq 0 ]; then
        echo "capture_auditd: SAFETY ABORT - rule '${id}' on ${image} LOADED (rc=0); netlink is reachable" >&2
        return 2
    fi
    if [ "${rc}" -eq 4 ]; then
        echo "capture_auditd: UNUSABLE - '${id}' on ${image} got rc=4 (auditctl never ran; capability missing?)" >&2
        return 2
    fi

    if printf '%s' "${se}" | grep -qF "Error sending add rule data request"; then
        verdict="accept"
    else
        verdict="reject"
    fi

    ev=$(flatten_evidence "${so}" "${se}")
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
        "${image}" "${id}" "${verdict}" "${class}" "$(esc_field "${line}")" "$(esc_field "${ev}")" >>"${OUT}"
}

# ---------------------------------------------------------------------------
# Scenario table: 33 existing corpus/auditd/* scenarios, re-grounded with a
# real per-line verdict (one representative line each: the first non-comment,
# non-blank line of that scenario's audit.rules - the SAME line a real
# augenrules-assembled file would present to auditctl first), plus the new
# tokenization / value-parsing grounding scenarios for #584/#601/#489/#491.
# ---------------------------------------------------------------------------
run_existing_scenarios() {
    local image="$1"
    local d id line
    for d in "${EXISTING_CORPUS}"/*/; do
        d="${d%/}"
        id="$(basename "${d}")"
        [ -f "${d}/audit.rules" ] || continue
        line="$(grep -vE '^[[:space:]]*(#|$)' "${d}/audit.rules" | head -1)"
        [ -n "${line}" ] || {
            echo "capture_auditd: ${id}/audit.rules has no rule line" >&2
            return 2
        }
        capture_one "${image}" "${id}" "existing" "${line}" || return $?
    done
}

run_new_scenarios() {
    local image="$1"
    local key256 key257
    key256="$(head -c 256 /dev/zero | tr '\0' 'k')"
    key257="$(head -c 257 /dev/zero | tr '\0' 'k')"

    capture_one "${image}" "iss584-quoted-path-space" "584" \
        '-w "/etc/my dir/file" -p wa -k q1' || return $?
    capture_one "${image}" "iss584-backslash-escaped-space" "584" \
        '-w /etc/my\ dir/file -p wa -k q2' || return $?
    capture_one "${image}" "iss584-embedded-tab-glues-flag" "584" \
        $'-w /etc/passwd\t-p wa -k q3' || return $?
    capture_one "${image}" "iss584-all-tabs-separators" "584" \
        $'-a\talways,exit\t-S\texecve\t-k\ttabsep' || return $?
    capture_one "${image}" "iss584-quoted-field-expr" "584" \
        "-a always,exit -F arch=b64 -S execve -F 'auid>=1000' -k q6" || return $?
    capture_one "${image}" "iss601-uppercase-perm-all" "601" \
        '-w /etc/passwd -p WA -k q4' || return $?
    capture_one "${image}" "iss601-uppercase-perm-mixed" "601" \
        '-w /etc/passwd -p Wa -k q5' || return $?
    capture_one "${image}" "iss489-multi-key" "489" \
        '-a always,exit -F arch=b64 -S execve -k key1 -k key2' || return $?
    capture_one "${image}" "iss489-key-at-cap-256" "489" \
        "-a always,exit -F arch=b64 -S execve -k ${key256}" || return $?
    capture_one "${image}" "iss489-key-over-cap-257" "489" \
        "-a always,exit -F arch=b64 -S execve -k ${key257}" || return $?
    capture_one "${image}" "iss489-embedded-0x01-in-key" "489" \
        $'-a always,exit -F arch=b64 -S execve -k key\x01withsep' || return $?
    capture_one "${image}" "iss491-neg-a0" "491" \
        '-a always,exit -F arch=b64 -S execve -F a0=-1' || return $?
    capture_one "${image}" "iss491-neg-a1" "491" \
        '-a always,exit -F arch=b64 -S execve -F a1=-1' || return $?
    capture_one "${image}" "iss491-neg-a2" "491" \
        '-a always,exit -F arch=b64 -S execve -F a2=-1' || return $?
    capture_one "${image}" "iss491-neg-a3" "491" \
        '-a always,exit -F arch=b64 -S execve -F a3=-1' || return $?
    capture_one "${image}" "iss491-neg-pers" "491" \
        '-a always,exit -F arch=b64 -S execve -F pers=-1' || return $?
    capture_one "${image}" "iss491-neg-devminor" "491" \
        '-a always,exit -F arch=b64 -S execve -F devminor=-1' || return $?
    capture_one "${image}" "control-accept" "control" \
        '-a always,exit -F arch=b64 -S execve -k exec_control' || return $?
    capture_one "${image}" "control-reject" "control" \
        '-a always,exit -F perm=zz -S execve' || return $?
}

# ---------------------------------------------------------------------------
# One image -> one el<N>.tsv, with a `#`-header naming the target and the
# LIVE audit-userspace version (the per-version positive control: if a
# base-image refresh ever collapses two of these to the same string, that is
# exactly what CONTRIBUTING.md's "known version divergence" control exists to
# catch).
# ---------------------------------------------------------------------------
capture_image() {
    local image="$1" elname="$2"
    OUT="${OUTDIR}/${elname}.tsv"
    : >"${OUT}"

    local audit_version
    audit_version="$(docker run --rm "${image}" rpm -q audit 2>/dev/null)"
    if [ -z "${audit_version}" ]; then
        echo "capture_auditd: could not read 'rpm -q audit' from ${image}" >&2
        return 2
    fi

    {
        echo "# rs-diff-auditd corpus"
        echo "# target=${elname} image=${image} audit_version=${audit_version} captured=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "# columns: target\tid\tverdict\tclass\trule\tevidence (splitn(6, '\\t'))"
        echo "# rule/evidence use '\\\\' -> '\', '\\t' -> TAB, '\\x01' -> 0x01 escaping (see capture_auditd.sh esc_field)."
    } >>"${OUT}"

    run_existing_scenarios "${image}" || return $?
    run_new_scenarios "${image}" || return $?
}

capture_image rs-oracle8 el8 || exit $?
capture_image rs-oracle9 el9 || exit $?
capture_image rs-oracle10 el10 || exit $?

echo "capture_auditd: wrote $(wc -l <"${OUTDIR}/el8.tsv") + $(wc -l <"${OUTDIR}/el9.tsv") + $(wc -l <"${OUTDIR}/el10.tsv") lines to ${OUTDIR}" >&2
exit 0
