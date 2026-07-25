#!/usr/bin/env bash
# Gate: no repo-invoked command may reference a path outside the repo (#572).
#
# WHY
# The wave3 fapolicyd corpus lived at an absolute /mnt path and was destroyed in
# the 2026-07-13 NFS rebuild. `just diff-fapolicyd` then exited 0 with a skip
# message on every run: it reported success while checking nothing. The root
# cause is not "the NFS mount died", it is "a repo-invoked command depended on
# an input that could vanish". This gate makes that class impossible.
#
# WHAT COUNTS AS A VIOLATION
# A line containing the literal absolute-mount prefix, UNLESS the line is a
# comment (`#` or `//`, any indent) or carries the `mnt-path-exempt:` marker.
#
# The comment carve-out was MEASURED, not assumed. On the tree at 34d18ac there
# are 40 such references and exactly ONE is load-bearing (justfile:16, a
# `validate_sh :=` assignment the recipe actually reads). The rest are
# provenance citations in doc comments and PROVENANCE.md files recording where
# corpus data came from, plus genuine fixture paths inside simulate scenarios.
# A gate that flagged all 40 would need ~39 exemptions, and a gate that is 90%
# exemptions trains people to blanket-add them. Provenance is not the defect;
# an operative path is.
#
# Data files (*.md, *.json, *.rules, *.toml) are outside the scan set by
# construction, so PROVENANCE "NFS source:" lines need no exemption.
#
# ANTI-VACUITY
# A run that scanned ZERO eligible files is a TOOL ERROR, not a pass. The
# success line carries the file count so "scanned 214 files, all clean" is
# distinguishable from "scanned nothing" - the same reason the drift tools
# print `OK (0 drift, 3 controls)` rather than a bare `0 drift`.
#
# EXIT CODES
#   0 - clean; prints `OK (0 violations, N files scanned)` with N > 0
#   1 - at least one violation; names each file:line and the escape hatch
#   2 - tool error: a PATH argument that does not exist, or zero files scanned
#
# Usage: scripts/check-no-mnt-paths.sh [PATH...]
# Contract + test suite: scripts/check-no-mnt-paths-test.sh

set -uo pipefail

# The literal this gate forbids in executable position. The marker must sit on
# the SAME line as the match - the gate scans scripts/ too, so it flags itself
# otherwise (it did, on the first run).
readonly MNT_PREFIX='/mnt/'  # mnt-path-exempt: the gate's own pattern
readonly EXEMPT_MARKER='mnt-path-exempt:'

# collect_files DIR
# Emits the eligible files under DIR, one per line. Eligible = *.rs, *.sh,
# *.yml, *.yaml, or a file literally named `justfile`. Data files and corpus
# fixtures are deliberately excluded.
collect_files() {
    local dir="$1"
    find "${dir}" \
        \( -type d -name target -o -type d -name .git \) -prune -o \
        -type f \
        \( -name '*.rs' -o -name '*.sh' -o -name '*.yml' -o -name '*.yaml' \
           -o -name 'justfile' \) \
        -print 2>/dev/null
}

# default_scan_set
# The no-argument scan set, relative to the caller's CWD (the gate is always
# invoked from the repo root by `just` and by CI).
default_scan_set() {
    local d
    [[ -f justfile ]] && printf '%s\n' justfile
    for d in crates tools scripts .github/workflows; do
        [[ -d "${d}" ]] && collect_files "${d}"
    done
    return 0
}

# Build the file list from arguments, or the default set.
files=()
if [[ $# -eq 0 ]]; then
    while IFS= read -r f; do
        [[ -n "${f}" ]] && files+=("${f}")
    done < <(default_scan_set)
else
    for target in "$@"; do
        if [[ -f "${target}" ]]; then
            # An explicitly named file is scanned whatever its extension.
            files+=("${target}")
        elif [[ -d "${target}" ]]; then
            while IFS= read -r f; do
                [[ -n "${f}" ]] && files+=("${f}")
            done < <(collect_files "${target}")
        else
            echo "check-no-mnt-paths: ERROR - no such file or directory: ${target}" >&2
            exit 2
        fi
    done
fi

scanned=0
violations=0
report=""

for f in "${files[@]:-}"; do
    [[ -z "${f}" ]] && continue
    [[ -r "${f}" ]] || continue
    scanned=$((scanned + 1))
    while IFS= read -r hit; do
        [[ -z "${hit}" ]] && continue
        # `hit` is "LINENO:CONTENT" from grep -n.
        line_content="${hit#*:}"
        # Carve-out (a): the line is a comment.
        if [[ "${line_content}" =~ ^[[:space:]]*(#|//) ]]; then
            continue
        fi
        # Carve-out (b): the line carries the explicit exemption marker.
        if [[ "${line_content}" == *"${EXEMPT_MARKER}"* ]]; then
            continue
        fi
        violations=$((violations + 1))
        report+="  ${f}:${hit%%:*}: ${line_content}"$'\n'
    done < <(grep -nF -- "${MNT_PREFIX}" "${f}" 2>/dev/null || true)
done

# ANTI-VACUITY: scanning nothing must never read as clean.
if [[ "${scanned}" -eq 0 ]]; then
    echo "check-no-mnt-paths: ERROR - scanned 0 eligible files; refusing to report clean." >&2
    echo "  A run that measured nothing is not a pass. Check the scan target." >&2
    exit 2
fi

if [[ "${violations}" -gt 0 ]]; then
    echo "check-no-mnt-paths: ${violations} violation(s) in ${scanned} files scanned" >&2
    printf '%s' "${report}" >&2
    cat >&2 <<EOF

A repo-invoked command must not reference a path outside the repo. The wave3
fapolicyd corpus was lost exactly this way (#572): the path vanished and the
harness kept exiting 0.

Fix it by moving the input into the repo. If a reference is genuinely
historical provenance rather than a live dependency, either move it into a
comment or mark the line with '${EXEMPT_MARKER} <reason>'.
EOF
    exit 1
fi

echo "check-no-mnt-paths: OK (0 violations, ${scanned} files scanned)"
exit 0
