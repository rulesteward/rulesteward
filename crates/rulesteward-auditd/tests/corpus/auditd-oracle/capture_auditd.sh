#!/usr/bin/env bash
# capture_auditd.sh <outdir> - Lane A (auditd) Tier-2 live capture.
#
# Re-derives the per-line RAW facts (rc, stdout, stderr) of every corpus
# scenario from a REAL `auditctl -R` and writes three flat TSVs (el8.tsv /
# el9.tsv / el10.tsv) into <outdir>. Invoked by scripts/rs-oracle-diff.sh
# (`just diff-auditd`); also safe to run by hand to regenerate the committed
# corpus under crates/rulesteward-auditd/tests/corpus/auditd-oracle/.
#
# Exit codes (CONTRIBUTING.md "Differential oracle contract", Tier-2 form):
#   0  captured cleanly
#   2  tool/environment error (docker present but something else failed, a
#      write failed, or the safety canary fired - see below)
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
#     `docker run --rm -i --network=none --cap-add=AUDIT_CONTROL rs-oracle<N>`.
#   - The `auditctl -s` canary runs FIRST, before EVERY rule line, inside the
#     SAME container instantiation (batched: one container per image, not one
#     per line - see "Batching" below). It is a status READ with zero blast
#     radius. If it SUCCEEDS (rc 0), netlink is live and the host is
#     reachable: this script ABORTS immediately (exit 2) rather than capture
#     anything further. Only a FAILING canary permits testing the next rule in
#     that container.
#
# RAW FACTS, NOT A VERDICT (session 9k-1 Lane A remediation)
#
# This script used to grep ONE string in the captured stderr and write a
# precomputed "accept"/"reject" verdict straight into the corpus. That string
# (`Error sending add rule data request`) only ever appears on the ADD-RULE
# path (`-w`/`-a`), so every control-only line (`-D`, `-b`, ...) was recorded
# as a parse REJECT - including `-D`, the first line of essentially every real
# `audit.rules` file. That bug is why this script no longer classifies
# anything: it writes the raw `(rc, stdout, stderr)` facts for each line,
# verbatim, and `rulesteward_auditd::oracle::classify_capture` (unit-tested,
# clippy'd, mutation-gated) turns those facts into a verdict. See
# `crates/rulesteward-auditd/src/oracle.rs` and
# `crates/rulesteward-auditd/tests/auditd_corpus_oracle.rs` for the
# classification truth table this corpus feeds.
#
# BATCHING
#
# One container instantiation PER IMAGE runs the canary and every scenario
# line in that image, rather than one `docker run` per line (which would mean
# one docker startup per corpus row - unaffordable once the corpus reaches
# ~70 scenario ids x 3 images). This is SAFER than the old one-container-per-
# line shape, not less safe: the canary still runs before every single line,
# just inside a longer-lived container instead of a fresh one each time.
#
# TOOLING CONSTRAINT: no jq, no python3, no find anywhere in this script (neither
# host- nor container-side) - plain bash + coreutils (base64/cat/printf/rm/mkdir)
# only, so this runs on a minimal CI runner and inside the el8 image alike.

set -uo pipefail

OUTDIR="${1-}"
if [ -z "${OUTDIR}" ]; then
    echo "usage: capture_auditd.sh <outdir>" >&2
    exit 3
fi

# LC_ALL=C before any directory glob (the existing-scenario enumeration below)
# so scenario ordering is not locale-dependent (CONTRIBUTING.md determinism
# note; session 9k-1 amendment).
export LC_ALL=C

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)" || exit 2
EXISTING_CORPUS="${SCRIPT_DIR}/../auditd"

REPO_ROOT="$(cd "${SCRIPT_DIR}" && git rev-parse --show-toplevel 2>/dev/null)"
if [ -z "${REPO_ROOT}" ]; then
    echo "capture_auditd: could not resolve the repo root via 'git rev-parse --show-toplevel' (not inside a git checkout?)" >&2
    exit 2
fi
# shellcheck source=/dev/null
. "${REPO_ROOT}/scripts/rs-capture-guard.sh"
rs_capture_guard_init "capture_auditd"

if ! command -v docker >/dev/null 2>&1; then
    echo "capture_auditd: docker is not on PATH" >&2
    exit 3
fi

IMAGES=(rs-oracle8 rs-oracle9 rs-oracle10)
if ! docker image inspect "${IMAGES[@]}" >/dev/null 2>&1; then
    echo "capture_auditd: images ${IMAGES[*]} not found; build them per tools/oracle-images/README.md" >&2
    exit 3
fi

rs_checked mkdir -p "${OUTDIR}"

# ---------------------------------------------------------------------------
# Container-side script, part 1: helpers + canary + the scenario-consuming
# loop, up to the point where the scenario data itself (a quoted here-doc, so
# NEITHER the host's nor the container's shell expands anything in it) is
# spliced in by capture_image(). Quoted delimiter ('RS_SCENARIOS_EOF') on both
# halves means this whole assembly is textual concatenation, not sourcing -
# every '$' below is executed by the CONTAINER's bash, never the host's.
# ---------------------------------------------------------------------------
read -r -d '' CONTAINER_SCRIPT_HEAD <<'HEAD_EOF'
set -u
export LC_ALL=C

# Byte-safe field escaper (session 9k-1 Lane A remediation): '\' -> '\\',
# TAB -> '\t', LF -> '\n', CR -> '\r', printable ASCII 0x21-0x7e and the plain
# 0x20 space pass through unescaped, everything else -> '\xHH'. A wholly empty
# field is encoded as the two-character sentinel '\0' (never a raw empty
# string, so no TSV column is ever silently absent). A leading or trailing
# space in the ENCODED result is re-escaped to '\x20' so no field starts or
# ends in whitespace (defeats a .editorconfig trim_trailing_whitespace pass
# silently corrupting a fixture).
esc_field() {
    local s="$1"
    if [ -z "$s" ]; then
        printf '\\0'
        return 0
    fi
    local out="" n=${#s} i c ord hex
    for ((i = 0; i < n; i++)); do
        c="${s:i:1}"
        case "$c" in
        $'\\') out+='\\' ;;
        $'\t') out+='\t' ;;
        $'\n') out+='\n' ;;
        $'\r') out+='\r' ;;
        *)
            ord=$(printf '%d' "'$c")
            if [ "$ord" -ge 33 ] && [ "$ord" -le 126 ]; then
                out+="$c"
            elif [ "$ord" -eq 32 ]; then
                out+=' '
            else
                hex=$(printf '%02x' "$ord")
                out+="\\x${hex}"
            fi
            ;;
        esac
    done
    if [ "${out:0:1}" = ' ' ]; then
        out="\\x20${out:1}"
    fi
    if [ "${#out}" -gt 0 ] && [ "${out: -1}" = ' ' ]; then
        out="${out:0:$((${#out} - 1))}\\x20"
    fi
    printf '%s' "$out"
}

# The auditctl -s canary: a status READ with zero blast radius. SUCCESS means
# netlink is live and the host ruleset is reachable - abort immediately rather
# than test anything (including the very first line). Run before EVERY line,
# not just once per container, per tools/oracle-images/README.md.
check_canary() {
    auditctl -s >/tmp/c.o 2>/tmp/c.e
    local crc=$?
    if [ "${crc}" -eq 0 ]; then
        echo "CANARY_LIVE_ABORT"
        exit 0
    fi
}

check_canary

RULEFILE=/tmp/rs-oracle-line.rules

while IFS=$'\t' read -r id class rule_b64; do
    [ -n "${id}" ] || continue
    check_canary
    rule="$(printf '%s' "${rule_b64}" | base64 -d)"
    printf '%s' "${rule}" >"${RULEFILE}"
    auditctl -R "${RULEFILE}" >/tmp/o 2>/tmp/e
    rc=$?
    so="$(cat /tmp/o)"
    se="$(cat /tmp/e)"
    rule_len=${#rule}
    out_len=${#so}
    err_len=${#se}
    printf 'ROW\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "${id}" "${class}" "${rc}" "${rule_len}" "${out_len}" "${err_len}" \
        "$(esc_field "${rule}")" "$(esc_field "${so}")" "$(esc_field "${se}")"
    rm -f /tmp/o /tmp/e /tmp/c.o /tmp/c.e
done <<'RS_SCENARIOS_EOF'
HEAD_EOF

read -r -d '' CONTAINER_SCRIPT_TAIL <<'TAIL_EOF'
RS_SCENARIOS_EOF
echo ALL_DONE
TAIL_EOF

# ---------------------------------------------------------------------------
# Scenario table (host side): id, class, rule -> appended as
# "id<TAB>class<TAB>base64(rule)" lines. Base64-encoding the rule is what lets
# a rule carry a literal TAB or 0x01 byte (the #584/#489 scenarios) through
# this transfer format without corrupting the id/class/rule split - id and
# class are always plain ASCII words WE choose, so they never need escaping.
# ---------------------------------------------------------------------------
SCENARIO_LINES=""

add_scenario() {
    local id="$1" class="$2" rule="$3"
    local b64
    b64="$(printf '%s' "${rule}" | base64 -w0)"
    SCENARIO_LINES+="${id}"$'\t'"${class}"$'\t'"${b64}"$'\n'
}

# 33 `existing`-class scenarios: one representative line per pre-existing
# tests/corpus/auditd/*/audit.rules scenario (the first non-comment,
# non-blank line - the same line a real augenrules-assembled file would
# present to auditctl first). rocky8-live-from-log-execve is excluded (ships
# no audit.rules, only a log sample).
add_existing_scenarios() {
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
        add_scenario "${id}" "existing" "${line}"
    done
}

# 19 pre-existing scenarios total (17 #584/#601/#489/#491 grounding scenarios
# INCLUDING the two positive controls, not 19 plus 2 more), carried over from
# the original capture (control-reject's RULE changed - see below).
add_584_601_489_491_scenarios() {
    local key256 key257
    key256="$(head -c 256 /dev/zero | tr '\0' 'k')"
    key257="$(head -c 257 /dev/zero | tr '\0' 'k')"

    add_scenario "iss584-quoted-path-space" "584" \
        '-w "/etc/my dir/file" -p wa -k q1'
    add_scenario "iss584-backslash-escaped-space" "584" \
        '-w /etc/my\ dir/file -p wa -k q2'
    add_scenario "iss584-embedded-tab-glues-flag" "584" \
        $'-w /etc/passwd\t-p wa -k q3'
    add_scenario "iss584-all-tabs-separators" "584" \
        $'-a\talways,exit\t-S\texecve\t-k\ttabsep'
    add_scenario "iss584-quoted-field-expr" "584" \
        "-a always,exit -F arch=b64 -S execve -F 'auid>=1000' -k q6"
    add_scenario "iss601-uppercase-perm-all" "601" \
        '-w /etc/passwd -p WA -k q4'
    add_scenario "iss601-uppercase-perm-mixed" "601" \
        '-w /etc/passwd -p Wa -k q5'
    add_scenario "iss489-multi-key" "489" \
        '-a always,exit -F arch=b64 -S execve -k key1 -k key2'
    add_scenario "iss489-key-at-cap-256" "489" \
        "-a always,exit -F arch=b64 -S execve -k ${key256}"
    add_scenario "iss489-key-over-cap-257" "489" \
        "-a always,exit -F arch=b64 -S execve -k ${key257}"
    add_scenario "iss489-embedded-0x01-in-key" "489" \
        $'-a always,exit -F arch=b64 -S execve -k key\x01withsep'
    add_scenario "iss491-neg-a0" "491" \
        '-a always,exit -F arch=b64 -S execve -F a0=-1'
    add_scenario "iss491-neg-a1" "491" \
        '-a always,exit -F arch=b64 -S execve -F a1=-1'
    add_scenario "iss491-neg-a2" "491" \
        '-a always,exit -F arch=b64 -S execve -F a2=-1'
    add_scenario "iss491-neg-a3" "491" \
        '-a always,exit -F arch=b64 -S execve -F a3=-1'
    add_scenario "iss491-neg-pers" "491" \
        '-a always,exit -F arch=b64 -S execve -F pers=-1'
    add_scenario "iss491-neg-devminor" "491" \
        '-a always,exit -F arch=b64 -S execve -F devminor=-1'
    add_scenario "control-accept" "control" \
        '-a always,exit -F arch=b64 -S execve -k exec_control'
    # CHANGED (session 9k-1 Lane A remediation): the old control-reject rule
    # was '-F perm=zz', which RuleSteward's own parser ALSO accepts (no
    # letter-set validation on -F perm= values) - a positive control must not
    # double as a product-divergence row, or a broken control and a real XFAIL
    # would be indistinguishable. '-F nosuchfield=1' is loud on the real
    # oracle ("-F unknown field: nosuchfield", tools/oracle-images/README.md)
    # AND rejected by RuleSteward's own field-name table (parse_audit_field
    # has no "nosuchfield" entry) - product and oracle AGREE on reject, so
    # this can never be an XFAIL.
    add_scenario "control-reject" "control" \
        '-a always,exit -F nosuchfield=1 -S execve'
}

# New grounding scenarios across three review rounds: 19 from the original
# remediation (fallback set - see PROVENANCE.md "Fallback scope" for why 19,
# not the nominal 42), 3 from the round-2 adversarial-review rework, and 2
# from the post-implementation (round-3) adversarial review - 24 total
# `add_scenario` calls in this function.
add_new_grounding_scenarios() {
    # Group 1: -p perm letters, including the invalid-letter reject that
    # closes #601's fail-open (an invalid letter, upper or lower, must be
    # rejected by BOTH sides - #601 was about VALID uppercase letters being
    # unexpectedly accepted by the real daemon, not about invalid ones).
    add_scenario "p-invalid-lower" "601" '-w /etc/passwd -p z -k pinvlow'
    add_scenario "p-invalid-upper" "601" '-w /etc/passwd -p Z -k pinvup'
    # -F perm= (field-based, not the -p watch flag above) with an invalid
    # letter: this is the row the OLD control-reject scenario used to carry
    # ('-F perm=zz'), which is why that rule had to move off the positive
    # control (a control must never double as a product-divergence row). Kept
    # here as its own grounding id: RuleSteward's parser stores any -F perm=
    # VALUE as an unvalidated string (no rwxa letter-set check), so it is
    # expected to ACCEPT where the real oracle REJECTS.
    add_scenario "f-perm-invalid-letter" "601" \
        '-a always,exit -F perm=zz -S execve -k fpermbad'

    # Group 2: unquoted comparison operators. Before this session the corpus
    # had ZERO unquoted non-'=' operators (every '>=' example was inside
    # quotes, which is issue #584's OWN territory, not the operator table's),
    # so an impl that rejected every operator except '=' would have passed
    # the whole suite undetected.
    add_scenario "op-ne" "op" '-a always,exit -F uid!=0 -S execve -k opne'
    add_scenario "op-lt" "op" '-a always,exit -F uid<1000 -S execve -k oplt'
    add_scenario "op-gt" "op" '-a always,exit -F uid>1000 -S execve -k opgt'
    add_scenario "op-le" "op" '-a always,exit -F uid<=1000 -S execve -k ople'
    add_scenario "op-ge" "op" '-a always,exit -F uid>=1000 -S execve -k opge'
    add_scenario "op-and" "op" '-a always,exit -F success&1 -S execve -k opand'
    add_scenario "op-andeq" "op" \
        '-a always,exit -F success&=1 -S execve -k opandeq'

    # Group 4: -k cap anti-monotone-length pair. The VALID line is padded with
    # extra (semantically inert) -F clauses so it is LONGER overall than the
    # INVALID line, which stays minimal - a naive "reject if the LINE is long"
    # rule would get this backwards. Exact byte lengths are measured (not
    # assumed) and recorded in PROVENANCE.md.
    local key_ok key_over
    key_ok="$(head -c 240 /dev/zero | tr '\0' 'k')"
    key_over="$(head -c 260 /dev/zero | tr '\0' 'k')"
    add_scenario "k-cap-valid-longer-line" "489" \
        "-a always,exit -F arch=b64 -S execve -F uid=0 -F gid=0 -F pid=1 -F ppid=1 -k ${key_ok}"
    add_scenario "k-cap-invalid-shorter-line" "489" \
        "-a always,exit -F arch=b64 -S execve -k ${key_over}"

    # Group 6: -D field-count edge cases, pinning #541 directly against the
    # real daemon. NOT loud, contrary to this lane's original plan (which
    # expected auditctl.c's `case 'D':` trailing-token check to print before
    # any netlink call, since it is an unconditional check with its own
    # audit_msg() call). Empirically all three are SILENT under `auditctl -R`
    # (measured this session on all three EL majors): `main()`'s `-R <file>`
    # dispatch (argc==3 && argv[1]=="-R") calls
    # `set_aumessage_mode(MSG_SYSLOG, DBG_NO)`, which redirects every
    # `audit_msg()`-routed diagnostic - INCLUDING case 'D's field-count
    # check - to syslog instead of stderr. Only diagnostics that bypass
    # `audit_msg()` entirely (`audit_number_to_errmsg`'s direct
    # `fprintf(stderr, ...)`, used by field/value validation such as
    # "-F unknown field") remain visible under `-R`. So these three rows join
    # the UNOBSERVABLE table alongside the bare -D/-b existing scenarios,
    # rather than confirming a loud pin - a real, if unplanned, finding. See
    # PROVENANCE.md "MSG_SYSLOG under -R".
    add_scenario "d-extra-silent" "541" '-D extra'
    add_scenario "d-k-only-silent" "541" '-D -k'
    add_scenario "d-k-extra-silent" "541" '-D -k mykey extra'

    # Named singles.
    add_scenario "f-unknown-field-unquoted" "fld" \
        '-a always,exit -F bogusfield=1 -S execve -k funknown'
    add_scenario "lead-A-prepend" "lead" \
        '-A always,exit -F arch=b64 -S execve -k aprepend'
    add_scenario "lead-garbage" "lead" 'garbage-not-a-flag'
    add_scenario "s-unknown-syscall" "syscall" \
        '-a always,exit -F arch=b64 -S totallynotasyscall -k sunknown'

    # --- Adversarial-review rework (round 2) additions ---

    # Closes a surviving mutation: parser.rs's parse_list_action tries BOTH
    # `list,action` and `action,list` orderings (auditctl(8) documents them as
    # commutative). Every other -a/-A row in this corpus is action-first
    # (always,exit / never,exit / always,exclude / always,task /
    # always,filesystem), so deleting the list-first try_list_action branch
    # left the corpus green. This row is list-first ("exit,always") and must
    # still ACCEPT on both sides.
    add_scenario "lead-list-first" "lead" \
        '-a exit,always -S execve -k listfirst'

    # Empirical confirmation of a second SILENT_SUCCESS_LEADING_FLAGS entry
    # beyond -D/-b (which the existing corpus already grounds via
    # rocky9-huge-ruleset/-stock-control/rocky10-rulesd-multifile and
    # rocky9-exclude-msgtype): -e follows the identical setopt() shape
    # (audit_set_enabled(fd, ...) on success, no audit_msg on failure).
    add_scenario "lead-e-enable" "lead" '-e 1'

    # Resolves the --reset-lost denylist question EMPIRICALLY rather than by
    # source argument alone (session 9k-1 round-2 adversarial review,
    # blocker 5): audit_reset_lost() in libaudit.c checks
    # audit_get_features() & AUDIT_FEATURE_BITMAP_LOST_RESET BEFORE any
    # netlink send, and returns -EAU_FIELDNOSUPPORT if that bit is unset -
    # which this sandbox's feature-bitmap load (itself gated on the same
    # blocked AUDIT_GET status call the -s canary exercises) always reports.
    # That error code prints via audit_number_to_errmsg (a direct
    # fprintf(stderr, ...), bypassing the MSG_SYSLOG mode -R sets), so this
    # is expected to be LOUD - the same SandboxLimited mechanism as
    # rocky9-filesystem-list's fstype finding, not the silent-success-path
    # ambiguity the other denylist entries share.
    add_scenario "reset-lost-probe" "541" '--reset-lost'

    # --- Adversarial-impl review (post-implementation, MISS 1) additions ---
    #
    # Grounds a product-too-STRICT divergence the impl-aware review found:
    # `-W`/`-d` (delete-form watch/syscall rules) reach the IDENTICAL
    # MSG_QUIET->send->MSG_STDERR sequence as `-w`/`-a` inside
    # handle_request()'s `else if (del != AUDIT_FILTER_UNSET)` branch
    # (auditctl.c ~line 1570), printing "Error sending delete rule data
    # request (%s)" on failure - the delete-side twin of
    # ADD_RULE_NETLINK_REFUSED. A refused delete-form line is therefore proof
    # it PARSED, exactly like the add probe. RuleSteward's parser (parser.rs
    # parse_line) has no "-W"/"-d" arm at all - both fall to
    # `other => Err("unknown flag")` - so product_verdict rejects while the
    # real oracle accepts.
    add_scenario "w-delete-watch" "584" '-W /etc/passwd -p wa -k x'
    add_scenario "d-delete-syscall" "584" '-d always,exit -S execve -k x'
}

build_scenario_table() {
    SCENARIO_LINES=""
    add_existing_scenarios || return $?
    add_584_601_489_491_scenarios
    add_new_grounding_scenarios
}

# ---------------------------------------------------------------------------
# One image -> one el<N>.tsv. Runs the ENTIRE scenario table inside ONE
# container instantiation (see "Batching" above), then post-processes the
# container's ROW lines into the 10-column corpus schema:
#   target  id  class  rc  rule_len  out_len  err_len  rule  stdout  stderr
# `target` is prepended here (the host knows the image tag; the container
# never needs to).
# ---------------------------------------------------------------------------
capture_image() {
    local image="$1" elname="$2"
    local out="${OUTDIR}/${elname}.tsv"
    rs_capture_context "${image}"

    local audit_version
    audit_version="$(docker run --rm --network=none "${image}" rpm -q audit 2>/dev/null)"
    if [ -z "${audit_version}" ]; then
        rs_capture_die "could not read 'rpm -q audit' from ${image}"
    fi

    local full_script="${CONTAINER_SCRIPT_HEAD}"$'\n'"${SCENARIO_LINES}${CONTAINER_SCRIPT_TAIL}"

    local raw
    raw="$(printf '%s' "${full_script}" | docker run --rm -i --network=none --cap-add=AUDIT_CONTROL "${image}" bash -s)"

    if printf '%s\n' "${raw}" | grep -qF "CANARY_LIVE_ABORT"; then
        rs_capture_die "SAFETY ABORT - auditctl -s canary SUCCEEDED on ${image} (netlink is live, host reachable); refusing to capture further"
    fi
    if ! printf '%s\n' "${raw}" | grep -qF "ALL_DONE"; then
        rs_capture_die "container run for ${image} did not reach ALL_DONE; output was: ${raw}"
    fi

    if ! : >"${out}"; then
        rs_capture_die "could not create ${out}"
    fi
    {
        echo "# rs-diff-auditd corpus"
        echo "# target=${elname} image=${image} audit_version=${audit_version}"
        echo "# captured=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "# columns: target id class rc rule_len out_len err_len rule stdout stderr (exact split('\\t'), 10 fields)"
        echo "# rule/stdout/stderr use '\\\\'->'\\', '\\t'->TAB, '\\n'->LF, '\\r'->CR, '\\xHH'->that byte, '\\0'->the empty string (see capture_auditd.sh esc_field)."
    } >>"${out}"

    local line rest id class rc rule_len out_len err_len rule so se
    local row_count=0
    while IFS= read -r line; do
        case "${line}" in
        ROW$'\t'*)
            rest="${line#ROW$'\t'}"
            IFS=$'\t' read -r id class rc rule_len out_len err_len rule so se <<<"${rest}"
            printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
                "${image}" "${id}" "${class}" "${rc}" "${rule_len}" "${out_len}" "${err_len}" \
                "${rule}" "${so}" "${se}" >>"${out}"
            row_count=$((row_count + 1))
            ;;
        esac
    done <<<"${raw}"

    if [ "${row_count}" -eq 0 ]; then
        rs_capture_die "0 ROW lines captured for ${image}; corpus would be empty"
    fi
    echo "capture_auditd: ${image} -> ${row_count} rows" >&2
    rs_capture_context
}

build_scenario_table || exit $?
capture_image rs-oracle8 el8
capture_image rs-oracle9 el9
capture_image rs-oracle10 el10

rs_capture_verify_output "${OUTDIR}" 3
exit 0
