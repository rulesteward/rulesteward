#!/usr/bin/env bash
#
# Tier-2 live capture for the sysctld differential oracle (session 9k-1 Lane B).
#
# Invoked by scripts/rs-oracle-diff.sh as `bash <this> <output-dir>` (the frozen
# Phase-0 driver contract - see CONTRIBUTING.md "Differential oracle contract").
# For every scenario under this directory, materializes its tree.plan onto a
# throwaway rs-oracleN container's REAL root (systemd-sysctl has no --root: see
# CLAUDE.md "Measured sysctld oracle facts"), runs `--cat-config` and a
# `SYSTEMD_LOG_LEVEL=debug` apply, and writes the raw transcript plus a copy of
# the scenario's own tree.plan/content/scenario.meta into <output-dir>/<id>/, so
# the result is a complete, self-contained corpus the Tier-1 replay test can be
# repointed at via RS_ORACLE_CORPUS_SYSCTLD.
#
# Exit codes (CONTRIBUTING.md "Differential oracle contract"):
#   0  every scenario captured cleanly
#   2  tool/environment error (docker failure, a malformed scenario, an
#      unexpectedly-writable /proc/sys - see the canary below)
#   3  precondition unmet (no docker, images missing) - a legitimate skip
#
# TMPDIR: payload staging uses `mktemp -d "${TMPDIR:-/tmp}/..."`. On a dev
# sandbox where `/tmp` carries a per-user tmpfs quota (`mount | grep usrquota`;
# `quota -s` shows it), a near-exhausted quota makes `cp` fail PARTWAY with
# "Disk quota exceeded" while still exiting the surrounding script successfully
# - the captured content is then silently truncated/empty rather than the
# expected fixture text. If captures look empty or a scenario that should
# reject shows a clean accept, export TMPDIR to a path with real headroom (a
# repo-adjacent NFS mount, never `/mnt/...` from an executable per
# `just no-mnt-guard` - set it only in your shell, not in this script) before
# re-running. Same class of gotcha as the documented cargo-mutants scratch-disk
# issue; this script does not change its default so CI (which has no such
# quota) keeps the standard `/tmp` behavior.
#
# SAFETY (CLAUDE.md "Apply mode WRITES..."): apply mode really does attempt to
# write every resolved key to /proc/sys. This is only safe because Docker's
# default runtime bind-mounts /proc/sys read-only inside an unprivileged
# container (confirmed empirically 2026-07-25: `rc=1, Read-only file system`
# on all three rs-oracle images) - so a write attempt fails closed rather than
# mutating the host kernel. This script NEVER passes --privileged or
# --network=host (always --network=none, never a host mount), and the canary
# below POSITIVELY CONFIRMS /proc/sys is read-only before touching any real
# scenario; if the canary write unexpectedly SUCCEEDS, this script aborts
# rather than risk a live host mutation.
set -uo pipefail

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)" || exit 2

# Shared write-discipline helper (scripts/rs-capture-guard.sh): every write
# below goes through rs_checked / rs_checked_write, and the script ends with
# rs_capture_verify_output, so a failed write aborts the capture (rc 2)
# instead of silently producing a truncated corpus that still reports
# success - see that file's header for the "Disk quota exceeded" incident
# this guards against.
REPO_ROOT="$(cd "${SELF_DIR}/../../../../.." && pwd)" || exit 2
# shellcheck disable=SC1091
. "${REPO_ROOT}/scripts/rs-capture-guard.sh" || exit 2
rs_capture_guard_init "capture_sysctld"

OUT="${1-}"

if [ -z "${OUT}" ]; then
    echo "capture_sysctld: usage: bash capture_sysctld.sh <output-dir>" >&2
    exit 2
fi
rs_checked mkdir -p "${OUT}"

if ! command -v docker >/dev/null 2>&1; then
    echo "capture_sysctld: docker not on PATH" >&2
    exit 3
fi

MATERIALIZE="${SELF_DIR}/materialize.sh"
if [ ! -f "${MATERIALIZE}" ]; then
    echo "capture_sysctld: missing ${MATERIALIZE}" >&2
    exit 2
fi

declare -A CANARY_OK

# The read-only /proc/sys canary (see SAFETY above). Zero blast radius: it only
# READS the write's error, and the attempted write target
# (kernel.randomize_va_space) is not namespaced away from anything sensitive
# even in the failure path, because the write always fails under a correctly
# configured container runtime.
canary_check() {
    local image="$1"
    if [ -n "${CANARY_OK[${image}]-}" ]; then
        return 0
    fi
    if ! docker image inspect "${image}" >/dev/null 2>&1; then
        echo "capture_sysctld: image ${image} not found; build it per tools/oracle-images/README.md" >&2
        return 3
    fi
    local out
    out="$(docker run --rm --network=none "${image}" \
        sh -c 'echo 1 > /proc/sys/kernel/randomize_va_space; echo "RC=$?"' 2>&1)"
    if ! printf '%s\n' "${out}" | grep -qF 'Read-only file system'; then
        echo "capture_sysctld: SAFETY ABORT - /proc/sys did not refuse a write inside ${image}" >&2
        echo "capture_sysctld: canary output: ${out}" >&2
        echo "capture_sysctld: refusing to run any live capture (would risk mutating the host kernel)" >&2
        return 2
    fi
    CANARY_OK[${image}]=1
    return 0
}

# Read one `key: value` field from a scenario.meta file. Leading/trailing
# whitespace on the value is trimmed; a missing key yields an empty string.
# Deliberately hand-rolled (no serde/toml dependency): scenario.meta is a flat
# `key: value` line format by design, so a tiny grep+cut suffices and no new
# Cargo dependency is needed for either side of this differential (see
# PROVENANCE.md "Why no serde_json").
meta_field() {
    local file="$1" key="$2"
    grep -m1 "^${key}:" "${file}" 2>/dev/null | cut -d: -f2- | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'
}

# Read a scenario's vendored `---` inventory block from its tree.plan and
# reprint it field-normalized (TYPE\tRELPATH\tARG, always 3 tab-separated
# fields even if the source line omits a trailing tab on an empty ARG - a
# byte-for-byte comparison would otherwise trip on that harmless cosmetic
# variance, which `rulesteward_sysctld::oracle::parse_plan_line`'s splitn(3)
# never sees because it treats a missing third field as empty either way).
# Blank lines and `#`-comments are dropped, matching the Rust side's parser.
vendored_inventory_of() {
    local plan="$1"
    awk -F'\t' '
        BEGIN { in_inv = 0 }
        $0 == "---" { in_inv = 1; next }
        !in_inv { next }
        /^$/ { next }
        /^#/ { next }
        { printf "%s\t%s\t%s\n", $1, $2, $3 }
    ' "${plan}" | LC_ALL=C sort
}

# Read the `=== COMPUTED-INVENTORY ===` section out of a captured transcript
# (between that marker and the next `=== ` marker), same field-normalization
# as above, sorted the same way so the two sides compare byte-for-byte.
computed_inventory_of() {
    local transcript="$1"
    awk -F'\t' '
        /^=== COMPUTED-INVENTORY ===$/ { capture = 1; next }
        capture && /^=== / { capture = 0 }
        capture { printf "%s\t%s\t%s\n", $1, $2, $3 }
    ' "${transcript}" | LC_ALL=C sort
}

# The LIVE half of the materializer equivalence guard (Tier-1's Rust half is
# `rulesteward_sysctld::oracle::compute_inventory` vs the same vendored
# block - see materialize.sh's module doc). Compares what `materialize.sh
# --inventory` actually found on the rs-oracleN container's real filesystem
# against the scenario's own vendored expectation, so a BASH materializer bug
# - the class the Rust-only guard cannot see, since it never executes this
# file - fails the capture immediately instead of silently seeding a
# transcript built from the wrong tree.
check_computed_inventory() {
    local scen_dir="$1" out_file="$2"
    local vendored computed
    vendored="$(vendored_inventory_of "${scen_dir}/tree.plan")"
    computed="$(computed_inventory_of "${out_file}")"
    if [ -z "${computed}" ]; then
        echo "capture_sysctld: ${scen_dir}: no '=== COMPUTED-INVENTORY ===' section in the transcript - the bash materializer probe did not run or was not captured" >&2
        return 2
    fi
    if [ "${vendored}" != "${computed}" ]; then
        echo "capture_sysctld: ${scen_dir}: the LIVE bash materializer's inventory disagrees with tree.plan's vendored '---' block (a materialize.sh bug, or the vendored block itself is wrong):" >&2
        diff <(printf '%s\n' "${vendored}") <(printf '%s\n' "${computed}") >&2 || true
        return 2
    fi
    return 0
}

run_one_capture() {
    local image="$1" scen_dir="$2" out_file="$3"
    local cmd
    cmd='
(
set -u
rm -rf /etc/sysctl.d/* /run/sysctl.d/* /usr/local/lib/sysctl.d/* /usr/lib/sysctl.d/* /etc/sysctl.conf 2>/dev/null || true
# payload text executed by the container shell via sh -c, not a write this
# script performs on the host: rs_checked is not defined inside the
# container. capture-write-exempt: container-shell-payload
mkdir -p /etc/sysctl.d /run/sysctl.d /usr/local/lib/sysctl.d /usr/lib/sysctl.d
sh /rs-payload/materialize.sh /rs-payload/tree.plan /rs-payload/content ""
echo "=== COMPUTED-INVENTORY ==="
sh /rs-payload/materialize.sh --inventory ""
echo "=== CAT-CONFIG ==="
/usr/lib/systemd/systemd-sysctl --cat-config
echo "cat-config RC=$?"
echo "=== APPLY-DEBUG ==="
SYSTEMD_LOG_LEVEL=debug /usr/lib/systemd/systemd-sysctl
echo "apply RC=$?"
echo "=== VERSION ==="
/usr/lib/systemd/systemd-sysctl --version
) 2>&1
'
    # The whole payload script above runs inside ONE subshell whose stderr is
    # merged into its stdout AT THE SOURCE (the "2>&1" on the closing paren),
    # before it ever reaches docker's demuxing layer. This is load-bearing:
    # systemd-sysctl writes every line this differential asserts on (Parsing,
    # Setting, Overwriting, Skipping overridden file, and every parse/file
    # complaint) to STDERR, while every "=== ... ===" marker and "RC=" line
    # here is written by THIS shell to stdout. `docker start -a` attaches the
    # container's stdout and stderr as two independently-demuxed streams;
    # merging them with a host-side "2>&1" races their arrival order across
    # two kernel pipes and is NOT deterministic - measured directly: three
    # capture runs against unchanged images and unchanged product produced
    # 2/22, 0/22, and 1/22 scenarios with a stderr block landing on the wrong
    # side of a "=== " marker. A race-emptied APPLY-DEBUG section reads as
    # "key unset", which silently HIDES real drift for exactly the scenarios
    # whose correct verdict is "unset" (precedence-masked-key-drop,
    # degenerate-devnull-disable-idiom, slot-symlink-absent-divergence) - the
    # single most dangerous failure shape for a differential to have. Merging
    # inside the container makes it genuinely one stream, so the kernel
    # serializes every write() to that one fd in true program order; nothing
    # is left on the container's own stderr for `docker start -a`'s
    # "2>&1" below to race against.
    rs_capture_context "$(basename "${scen_dir}")@${image}"

    local payload
    payload="$(mktemp -d "${TMPDIR:-/tmp}/rs-sysctld-payload-XXXXXX")" || return 2
    rs_checked cp "${MATERIALIZE}" "${payload}/materialize.sh"
    rs_checked cp "${scen_dir}/tree.plan" "${payload}/tree.plan"
    if [ -d "${scen_dir}/content" ]; then
        rs_checked cp -r "${scen_dir}/content" "${payload}/content"
    else
        rs_checked mkdir -p "${payload}/content"
    fi

    local cid
    cid="$(docker create --network=none "${image}" sh -c "${cmd}")" || {
        rm -rf "${payload}"
        return 2
    }
    docker cp "${payload}" "${cid}:/rs-payload" >/dev/null || {
        docker rm -f "${cid}" >/dev/null 2>&1
        rm -rf "${payload}"
        return 2
    }
    docker start -a "${cid}" >"${out_file}" 2>&1
    local rc=$?
    docker rm -f "${cid}" >/dev/null 2>&1
    rm -rf "${payload}"
    if [ "${rc}" -ne 0 ]; then
        echo "capture_sysctld: docker start failed for ${scen_dir} on ${image} (rc=${rc})" >&2
        return 2
    fi
    if ! check_computed_inventory "${scen_dir}" "${out_file}"; then
        return 2
    fi
    return 0
}

captured=0
for scen_dir in "${SELF_DIR}"/*/; do
    scen_dir="${scen_dir%/}"
    name="$(basename "${scen_dir}")"
    rs_capture_context "${name}"
    [ -f "${scen_dir}/tree.plan" ] || continue
    [ -f "${scen_dir}/scenario.meta" ] || {
        echo "capture_sysctld: ${name}: missing scenario.meta" >&2
        exit 2
    }

    images_csv="$(meta_field "${scen_dir}/scenario.meta" images)"
    if [ -z "${images_csv}" ]; then
        echo "capture_sysctld: ${name}: scenario.meta has no 'images:' field" >&2
        exit 2
    fi

    IFS=',' read -r -a images <<<"${images_csv}"
    dest="${OUT}/${name}"
    rs_checked mkdir -p "${dest}"

    # When OUT is the committed corpus directory itself (populating it in
    # place, e.g. the one-time capture that seeds the committed transcripts),
    # scen_dir and dest are the SAME real path. Copying a directory onto
    # itself after an `rm -rf` would destroy the source before the copy runs,
    # so this step is skipped entirely in that case - there is nothing to
    # copy in, the scenario definition is already there.
    scen_real="$(cd "${scen_dir}" && pwd)"
    dest_real="$(cd "${dest}" && pwd)"
    if [ "${scen_real}" != "${dest_real}" ]; then
        rs_checked cp "${scen_dir}/tree.plan" "${dest}/tree.plan"
        rs_checked cp "${scen_dir}/scenario.meta" "${dest}/scenario.meta"
        if [ -d "${scen_dir}/content" ]; then
            rm -rf "${dest}/content"
            rs_checked cp -r "${scen_dir}/content" "${dest}/content"
        fi
    fi

    for image in "${images[@]}"; do
        image="$(echo "${image}" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
        [ -n "${image}" ] || continue

        canary_check "${image}"
        crc=$?
        if [ "${crc}" -ne 0 ]; then
            exit "${crc}"
        fi

        out_file="${dest}/oracle-${image}.txt"
        if ! run_one_capture "${image}" "${scen_dir}" "${out_file}"; then
            exit 2
        fi
        captured=$((captured + 1))
        echo "capture_sysctld: ${name} @ ${image} -> ${out_file}" >&2
    done
done

if [ "${captured}" -eq 0 ]; then
    echo "capture_sysctld: captured 0 scenario/image pairs; the corpus is empty or malformed" >&2
    exit 2
fi

# End-of-script layer (rs-capture-guard.sh): every captured scenario/image
# pair writes at least its own oracle-<image>.txt transcript, so ${captured}
# is a real, independently-computed lower bound on regular files under
# ${OUT} - this is NOT the same count re-derived a second way, it is what the
# loop above already tallied while capturing.
rs_capture_context
rs_capture_verify_output "${OUT}" "${captured}"

echo "capture_sysctld: OK (${captured} scenario/image captures)" >&2
exit 0
