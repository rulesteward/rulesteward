#!/usr/bin/env bash
# Shared write-discipline helper for the Tier-2 oracle capture scripts
# (session 9k-1). SOURCE this file; do not execute it.
#
#   . "${REPO_ROOT}/scripts/rs-capture-guard.sh"
#   rs_capture_guard_init "capture_sysctld"
#   ...
#   rs_checked cp "${scen_dir}/tree.plan" "${payload}/tree.plan"
#   ...
#   rs_capture_verify_output "${OUT}" "${expected}"
#
# WHY THIS EXISTS
#
# The capture scripts run `set -uo pipefail` WITHOUT `-e`, deliberately: they
# invoke commands whose nonzero exit is the observation itself (`auditctl`
# returning 1, a docker probe that must fail, `visudo -c` rejecting a document),
# and they read those codes with `cmd; rc=$?`, a construct `set -e` would abort
# before the assignment ever ran. Turning `-e` on wholesale would therefore
# break the measurement.
#
# The cost of that choice is that an ordinary failing write - a `cp` of a
# payload file into the container staging tree - does not stop the script. It
# continues, captures a transcript produced from an INCOMPLETE input tree, and
# exits 0. Lane B hit exactly this: `cp: Disk quota exceeded` while the run
# still reported success.
#
# So writes get an explicit wrapper instead of a global option. Two layers,
# because neither alone is sufficient:
#
#   1. `rs_checked` - per-call. Catches a failed write of an INPUT, where the
#      output file still gets produced and is merely wrong. An output count
#      cannot see that.
#   2. `rs_capture_verify_output` - end of script. Catches a write that was
#      never wrapped at all, including one added by a future edit, because it
#      counts what actually landed on disk rather than trusting the code path.
#
# `scripts/check-capture-writes.sh` is the third layer: a static gate that
# fails the build when a capture script performs a bare write outside
# `rs_checked`, so layer 1 stays structural rather than remembered.
#
# EXIT CODE
#
# Every failure here exits 2 - "tool/environment error" in the rc table in
# CONTRIBUTING.md "Differential oracle contract". A failed write is never rc 1
# (drift: the product and the oracle disagree) and never rc 3 (a legitimate
# skip). Reporting a broken capture as either of those is the exact confusion
# this contract exists to prevent.

# Label naming the sourcing script in every diagnostic. Set by
# `rs_capture_guard_init`; the fallback keeps a message readable if a caller
# forgets to initialise.
RS_CAPTURE_LABEL="${RS_CAPTURE_LABEL:-rs-capture-guard}"

# Optional breadcrumb (a scenario id, an image name) included in failures.
RS_CAPTURE_CONTEXT="${RS_CAPTURE_CONTEXT:-}"

# Name the sourcing script. Call once, near the top.
rs_capture_guard_init() {
    if [ "$#" -ne 1 ] || [ -z "$1" ]; then
        echo "rs-capture-guard: rs_capture_guard_init needs exactly one non-empty label" >&2
        exit 2
    fi
    RS_CAPTURE_LABEL="$1"
    RS_CAPTURE_CONTEXT=""
}

# Set (or with no argument, clear) the breadcrumb naming what is being captured
# right now. Failures inside a per-scenario loop are useless without it.
rs_capture_context() {
    RS_CAPTURE_CONTEXT="${1:-}"
}

# Print a diagnostic and exit 2.
rs_capture_die() {
    if [ -n "${RS_CAPTURE_CONTEXT}" ]; then
        echo "${RS_CAPTURE_LABEL}: [${RS_CAPTURE_CONTEXT}] $*" >&2
    else
        echo "${RS_CAPTURE_LABEL}: $*" >&2
    fi
    exit 2
}

# Run a command; abort the capture with rc 2 if it fails.
#
# Use for every write: `cp`, `mv`, `mkdir`, `install`, `tar -x`, a heredoc into
# a file. Do NOT use inside `$(...)` or a subshell - `exit` there terminates only
# the subshell, so the capture would carry on past a failure and the guard would
# be silently inert. Do NOT use for a command whose nonzero exit is the
# measurement; read that with `cmd; rc=$?` as before.
rs_checked() {
    if [ "$#" -eq 0 ]; then
        rs_capture_die "rs_checked called with no command"
    fi
    "$@"
    local rc=$?
    if [ "${rc}" -ne 0 ]; then
        rs_capture_die "command failed (rc ${rc}): $*"
    fi
}

# Write stdin to a file, aborting with rc 2 if the write fails.
#
# `rs_checked cat > f` cannot work: the redirection is applied by the shell to
# `rs_checked` itself, so a full disk fails the redirect before the wrapper has
# any say. This form owns the redirect and can therefore check it.
rs_checked_write() {
    if [ "$#" -ne 1 ] || [ -z "$1" ]; then
        rs_capture_die "rs_checked_write needs exactly one non-empty destination path"
    fi
    local dest="$1"
    if ! cat >"${dest}"; then
        rs_capture_die "could not write ${dest}"
    fi
    if [ ! -f "${dest}" ]; then
        rs_capture_die "wrote ${dest} but it does not exist afterwards"
    fi
}

# End-of-script assertion: the capture really produced output.
#
# `min_entries` is the number of regular files expected under `dir`, counted
# recursively. Pass the number the script itself computed while capturing, never
# a literal 0 and never the result of counting the same directory a second way -
# the point is to reconcile an INDEPENDENT expectation against what landed.
#
# This is the capture-side form of the rule in CONTRIBUTING.md, "Assert the
# count, do not merely print it": an instrument must prove it saw something,
# because "nothing fired" and "nothing ran" are otherwise identical downstream.
rs_capture_verify_output() {
    if [ "$#" -ne 2 ]; then
        rs_capture_die "rs_capture_verify_output needs <dir> <min_entries>"
    fi
    local dir="$1"
    local min="$2"

    case "${min}" in
    '' | *[!0-9]*)
        rs_capture_die "rs_capture_verify_output: min_entries '${min}' is not a non-negative integer"
        ;;
    esac
    if [ "${min}" -eq 0 ]; then
        rs_capture_die "rs_capture_verify_output: min_entries is 0; a capture that expects to write nothing has nothing to verify"
    fi
    if [ ! -d "${dir}" ]; then
        rs_capture_die "rs_capture_verify_output: ${dir} is not a directory"
    fi

    # Counted with bash globbing rather than `find` so the helper adds no PATH
    # dependency to a capture script that may run in a minimal container.
    local -a entries=()
    local e
    local saved_nullglob saved_dotglob saved_globstar
    saved_nullglob=$(shopt -p nullglob)
    saved_dotglob=$(shopt -p dotglob)
    saved_globstar=$(shopt -p globstar)
    shopt -s nullglob dotglob globstar
    for e in "${dir}"/**; do
        if [ -f "${e}" ]; then
            entries+=("${e}")
        fi
    done
    eval "${saved_nullglob}"
    eval "${saved_dotglob}"
    eval "${saved_globstar}"

    local got="${#entries[@]}"
    if [ "${got}" -lt "${min}" ]; then
        rs_capture_die "wrote ${got} file(s) under ${dir} but expected at least ${min}; the capture is short, so its corpus must not be trusted"
    fi
    echo "${RS_CAPTURE_LABEL}: verified ${got} file(s) under ${dir} (expected at least ${min})" >&2
}
