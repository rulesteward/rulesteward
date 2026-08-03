#!/usr/bin/env bash
# Lane C (sudoers) live capture: re-derive the four visudo/cvtsudoers oracle
# results for every committed scenario's `input.sudoers`, against the three
# `rs-oracle{8,9,10}` images, and write one JSON document per (scenario,
# target) into the output directory. Session 9k-1 (#538).
#
# Usage: bash capture_sudoers.sh <output-dir>
#
# This is the Tier-2 half of the differential oracle contract (CONTRIBUTING.md
# "Differential oracle contract"): `scripts/rs-oracle-diff.sh sudoers` invokes
# this script to populate a FRESH corpus, then re-points the SAME Tier-1 test
# (`tests/sudoers_corpus_oracle.rs`) at it via `RS_ORACLE_CORPUS_SUDOERS`. This
# same script is also how the COMMITTED corpus below was produced in the first
# place - there is only ONE capture implementation, never a second hand-authored
# one.
#
# It CANNOT be pointed at its own directory, and this header used to say it
# could. With OUT == SELF_DIR the per-scenario `cp "$input" "$OUT/$scen/..."` is
# `cp X X`, which exits 1 ("are the same file"), so `rs_capture_die` turns the
# very first scenario into rc 2 and nothing is captured. Capture into a STAGING
# directory and copy the wanted files back:
#
#   bash capture_sudoers.sh /tmp/stage && diff -r . /tmp/stage
#
# Exit codes (the tools/*-update contract, NOT the rulesteward binary's own):
#   0  captured cleanly (every scenario x target combination captured)
#   2  tool/environment error (docker present but a run failed unexpectedly,
#      or a scenario's input.sudoers is missing/unreadable)
#   3  precondition unmet (docker missing, or an rs-oracle image missing) - a
#      legitimate skip; `scripts/rs-oracle-diff.sh` promotes this to rc 2 when
#      RS_ORACLE_REQUIRED / RS_REQUIRE_VISUDO says the oracle is required.
#
# Design notes:
# - No jq, no python3, no find: the el8 image has none of them (measured
#   2026-07-25 - even `which` is absent), and per scripts/rs-oracle-diff.sh's
#   own A2 comment, a minimal CI runner may lack jq too. Everything here,
#   inside the container AND on the host, is plain bash string handling; the
#   Tier-1 test (which links serde_json) is what actually PARSES the captured
#   JSON.
# - One `docker run --rm --network=none rs-oracle<N>` per (scenario, target):
#   the scenario's `input.sudoers` bytes go over stdin UNCHANGED (no shell
#   interpolation, so no escaping hazard), and NOTHING is written inside the
#   container - the container-side script reads stdin once into a shell
#   variable and replays it to each of the four oracle programs from memory.
#   `--network=none` costs nothing here (visudo/cvtsudoers need no network)
#   and keeps the invocation shape consistent with Lane A's stricter posture.
# - stdout and stderr are captured SEPARATELY per oracle call by running the
#   SAME deterministic command twice (once discarding stderr, once discarding
#   stdout) rather than via fd-juggling redirection tricks, which are fragile
#   to get right and hard to verify by inspection. The extra process per call
#   is cheap at this corpus's scale (45 scenarios x 3 targets x 4 programs).
#   All four calls for one (scenario, target) pair happen inside a SINGLE
#   `docker run`, delimited by plain-text markers the host parses back apart.
# - Every write (the output dir, each scenario dir, the copied input, each
#   per-target JSON document) goes through scripts/rs-capture-guard.sh
#   (`rs_checked` / `rs_checked_write`), which aborts the WHOLE capture with
#   rc 2 the instant one fails, rather than continuing past it and producing
#   a truncated corpus that still reports success (see that script's header
#   for the "Disk quota exceeded" incident this defends against). The script
#   ends with `rs_capture_verify_output` as an independent recount. A docker
#   invocation's own nonzero exit is NOT a write, and is deliberately left as
#   a soft per-(scenario,target) skip (tracked via `status`), same as before.

set -uo pipefail

OUT="${1:?usage: capture_sudoers.sh <output-dir>}"
SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)" || exit 2
REPO_ROOT="$(cd "${SELF_DIR}/../../../../.." && pwd)" || exit 2
# shellcheck disable=SC1091
. "${REPO_ROOT}/scripts/rs-capture-guard.sh"
rs_capture_guard_init "capture_sudoers"

declare -A IMAGE_FOR=([el8]=rs-oracle8 [el9]=rs-oracle9 [el10]=rs-oracle10)
TARGETS=(el8 el9 el10)
IMAGES=(rs-oracle8 rs-oracle9 rs-oracle10)

if ! command -v docker >/dev/null 2>&1; then
    echo "capture_sudoers: docker is not on PATH" >&2
    exit 3
fi
if ! docker image inspect "${IMAGES[@]}" >/dev/null 2>&1; then
    echo "capture_sudoers: one or more of ${IMAGES[*]} not found; build them per tools/oracle-images/README.md" >&2
    exit 3
fi

rs_checked mkdir -p "$OUT"

# The sudo rpm version is a per-TARGET constant (not per-scenario); read it once
# per target rather than once per (scenario, target) pair (90 redundant docker
# invocations otherwise, at this corpus's scale).
declare -A RPM_FOR
for target in "${TARGETS[@]}"; do
    image="${IMAGE_FOR[$target]}"
    rs_capture_context "rpm-version/$target"
    # Do NOT wrap this in rs_checked: the invocation lives inside a `$(...)`
    # command substitution, which runs in its OWN subshell - an `exit` there
    # would terminate only that subshell, not this script (see
    # rs-capture-guard.sh's own header on this exact hazard). Capture the
    # exit code directly and react at the TOP level instead.
    rpm_ver="$(docker run --rm --network=none "$image" rpm -q sudo 2>/dev/null)"
    rpm_rc=$?
    if [ "$rpm_rc" -ne 0 ]; then
        rs_capture_die "target '$target': rpm -q sudo exited $rpm_rc inside $image"
    fi
    if [ -z "$rpm_ver" ]; then
        rs_capture_die "target '$target': rpm -q sudo exited 0 but printed nothing"
    fi
    RPM_FOR[$target]="$rpm_ver"
done
rs_capture_context

# The fixed (content-independent) container-side driver. Reads stdin ONCE,
# then runs each of the four oracle programs against the SAME in-memory
# content, printing a delimited section per program: a header line naming the
# section and its exit code, the program's stdout, a marker, the program's
# stderr, and a footer line. Run twice per program (stdout-only, then
# stderr-only) since visudo/cvtsudoers are pure deterministic filters over
# their stdin - safe to re-run, and far more robust than fd-swap tricks.
read -r -d '' CONTAINER_SCRIPT <<'EOF'
c="$(cat)"
emit() {
    label="$1"; shift
    so="$(printf '%s' "$c" | "$@" 2>/dev/null)"
    rc=$?
    se="$(printf '%s' "$c" | "$@" 2>&1 1>/dev/null)"
    printf 'RS_SECTION %s rc=%s\n' "$label" "$rc"
    printf '%s\n' "$so"
    printf 'RS_STDERR_MARK\n'
    printf '%s\n' "$se"
    printf 'RS_SECTION_END %s\n' "$label"
}
emit VISUDO visudo -c -f -
emit VISUDO_STRICT visudo -c -s -f -
emit CVTSUDOERS cvtsudoers -f json
emit CVTSUDOERS_E cvtsudoers -f json -e
EOF

# JSON-escape a string for embedding inside a double-quoted JSON value.
# Order matters: backslash first, then the rest.
#
# The final `tr -d` pass strips any OTHER C0 control byte (0x00-0x1F minus the
# ones already turned into their two-character escapes above, which by this
# point are plain ASCII 'n'/'t' and no longer control bytes). This is not
# theoretical: `visudo`'s stderr, captured via an inner-shell `1>/dev/null`
# redirect inside the (non-tty, `docker run -i` without `-t`) container, was
# measured (2026-07-25) to occasionally emit a stray 0x05 byte immediately
# before its `^` error-pointer character - reproducible only through that
# exact redirection shape, not via a direct terminal run or a host-side
# redirect. Whatever produces it, a raw control byte inside a JSON string is
# invalid per the JSON spec regardless of its origin, so stripping the whole
# C0 range here is the correct fix independent of a full root-cause.
json_escape() {
    local s=$1
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    s=${s//$'\t'/\\t}
    s=${s//$'\r'/}
    s=${s//$'\n'/\\n}
    printf '%s' "$s" | LC_ALL=C tr -d '\000-\010\013\014\016-\037'
}

# Parse the delimited blob from CONTAINER_SCRIPT's stdout into four
# "rc\x1Fstdout\x1Fstderr" records, one per section, in a fixed order
# (VISUDO, VISUDO_STRICT, CVTSUDOERS, CVTSUDOERS_E). Sets four globals:
# SEC_VISUDO, SEC_VISUDO_STRICT, SEC_CVTSUDOERS, SEC_CVTSUDOERS_E.
parse_sections() {
    local blob=$1
    local label rc in_section in_stderr so se line
    in_section=""
    while IFS= read -r line; do
        case "$line" in
        "RS_SECTION "*)
            label="${line#RS_SECTION }"
            label="${label%% rc=*}"
            rc="${line##*rc=}"
            in_section="$label"
            in_stderr=0
            so=""
            se=""
            continue
            ;;
        "RS_STDERR_MARK")
            in_stderr=1
            continue
            ;;
        "RS_SECTION_END "*)
            # Trim the single trailing newline `emit` always appends after
            # each stream (from `printf '%s\n' "$so"` / "$se").
            so="${so%$'\n'}"
            se="${se%$'\n'}"
            printf -v "SEC_${in_section}" '%s\x1F%s\x1F%s' "$rc" "$so" "$se"
            in_section=""
            continue
            ;;
        esac
        if [ -n "$in_section" ]; then
            if [ "$in_stderr" -eq 0 ]; then
                so+="$line"$'\n'
            else
                se+="$line"$'\n'
            fi
        fi
    done <<<"$blob"
}

# Emit one `"key": {"rc": N, "stdout": "...", "stderr": "..."}` object from a
# parsed "rc\x1Fstdout\x1Fstderr" record.
render_field() {
    local key=$1 record=$2
    local rc so se
    # `read` (no -d) stops at the FIRST newline regardless of IFS, which would
    # silently truncate a multi-line stdout/stderr capture (cvtsudoers' JSON is
    # always multi-line) to its first line. `-d ''` makes newline an ordinary
    # IFS-split character instead of the record terminator, so the whole
    # (rc, stdout, stderr) record survives the split; the appended NUL gives
    # `read` a delimiter to find so it does not report a spurious failure at
    # EOF (harmless either way, but `|| true` keeps that from tripping `set -e`
    # semantics elsewhere).
    IFS=$'\x1f' read -r -d '' rc so se <<<"${record}"$'\0' || true
    printf '  "%s": {"rc": %s, "stdout": "%s", "stderr": "%s"}' \
        "$key" "$rc" "$(json_escape "$so")" "$(json_escape "$se")"
}

status=0
scenario_count=0
for scen_dir in "$SELF_DIR"/*/; do
    scen="$(basename "$scen_dir")"
    case "$scen" in
    _*) continue ;;
    esac
    input="$scen_dir/input.sudoers"
    if [ ! -f "$input" ]; then
        continue
    fi
    scenario_count=$((scenario_count + 1))
    rs_capture_context "$scen"
    rs_checked mkdir -p "$OUT/$scen"
    # The fresh corpus still needs the scenario's input alongside the oracle
    # results, since the Tier-1 test reads `input.sudoers` from the SAME
    # resolved corpus root regardless of committed/fresh mode.
    rs_checked cp "$input" "$OUT/$scen/input.sudoers"

    for target in "${TARGETS[@]}"; do
        image="${IMAGE_FOR[$target]}"
        rs_capture_context "$scen/$target"
        blob="$(docker run --rm -i --network=none "$image" bash -c "$CONTAINER_SCRIPT" <"$input" 2>/dev/null)"
        run_rc=$?
        if [ "$run_rc" -ne 0 ] || [ -z "$blob" ]; then
            echo "capture_sudoers: docker run for scenario '$scen' target '$target' failed (exit $run_rc)" >&2
            status=2
            continue
        fi
        parse_sections "$blob"
        if [ -z "${SEC_VISUDO-}" ] || [ -z "${SEC_VISUDO_STRICT-}" ] || [ -z "${SEC_CVTSUDOERS-}" ] || [ -z "${SEC_CVTSUDOERS_E-}" ]; then
            echo "capture_sudoers: scenario '$scen' target '$target': missing one or more sections in captured output" >&2
            status=2
            continue
        fi
        # `rs_checked_write` owns the redirect and checks the write
        # internally, but the WRITE side of a pipe still runs in its OWN
        # implicit subshell (bash puts every pipeline stage, including the
        # last, in a subshell unless `shopt -s lastpipe` is set with job
        # control on - neither is true in a plain script; empirically
        # confirmed: a bare `foo | fn_that_exits_2` leaves the ENCLOSING
        # script running). So an internal failure there would otherwise be
        # swallowed exactly like the original bug this guard exists to
        # catch. `set -o pipefail` (already on, top of file) is what makes
        # `$?` after the pipe reflect that failure; the explicit check below
        # is what actually stops the CAPTURE rather than silently
        # continuing past it.
        {
            printf '{\n'
            printf '  "target": "%s",\n' "$target"
            printf '  "sudo_rpm": "%s",\n' "$(json_escape "${RPM_FOR[$target]}")"
            render_field "visudo" "$SEC_VISUDO"
            printf ',\n'
            render_field "visudo_strict" "$SEC_VISUDO_STRICT"
            printf ',\n'
            render_field "cvtsudoers" "$SEC_CVTSUDOERS"
            printf ',\n'
            render_field "cvtsudoers_expanded" "$SEC_CVTSUDOERS_E"
            printf '\n}\n'
        } | rs_checked_write "$OUT/$scen/$target.json"
        write_rc=$?
        if [ "$write_rc" -ne 0 ]; then
            rs_capture_die "writing $OUT/$scen/$target.json exited $write_rc"
        fi
        unset SEC_VISUDO SEC_VISUDO_STRICT SEC_CVTSUDOERS SEC_CVTSUDOERS_E
    done
done

if [ "$scenario_count" -eq 0 ]; then
    echo "capture_sudoers: found zero scenario directories under $SELF_DIR" >&2
    exit 2
fi

# Independent recount (layer 2 of rs-capture-guard.sh): 1 input.sudoers plus
# one JSON document per target, per scenario. Catches a write that was never
# wrapped at all, regardless of what the code path above claims happened.
rs_capture_context
expected_files=$((scenario_count * (1 + ${#TARGETS[@]})))
rs_capture_verify_output "$OUT" "$expected_files"

# Gated on status, because an ungated success line is a suppression: the recount
# above counts files ON DISK and cannot tell this run's writes from a previous
# run's. Into a FRESH dir a failed scenario also skips its write, so the recount
# dies first and this line is unreachable - but into a REUSED dir already holding
# a complete corpus, a docker failure sets status=2 while the recount still
# passes, and the line printed "captured 45 scenarios" next to rc 2. That is the
# manual invocation this file's own header documents.
if [ "$status" -eq 0 ]; then
    echo "capture_sudoers: captured $scenario_count scenarios x ${#TARGETS[@]} targets into $OUT" >&2
else
    echo "capture_sudoers: FAILED (rc $status) after iterating $scenario_count scenario(s) into $OUT; any files present may be from an earlier run" >&2
fi
exit "$status"
