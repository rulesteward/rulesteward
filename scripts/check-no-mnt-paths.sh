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
# A line containing the literal absolute-mount prefix, UNLESS it is a comment IN
# THAT FILE'S LANGUAGE, or carries the `mnt-path-exempt:` marker.
#
# Comment syntax is language-specific, and getting that wrong leaked twice:
#   - Rust: ONLY `//`, `///`, `//!`. A leading `#` is an ATTRIBUTE, so
#     `#[path = "/mnt/..."]` (a compile-time file read) is a violation, as is
#     the inner `#![...]` form. `/* */` blocks are deliberately NOT recognised
#     - see the note at the check itself; recognising them correctly needs a
#     Rust lexer, and the attempt that did not have one silenced ~3400 live
#     lines. Block-comment provenance takes an `mnt-path-exempt:` marker.
#   - sh / yaml / justfile: `#`, EXCEPT a shebang. `#!/mnt/...` is the most
#     literal executable position there is.
#
# Precisely: the carve-out is "the line BEGINS with a comment marker", not "the
# line is a comment". So a TRAILING provenance comment on a code line -
# `let n = 1; // grounded in /mnt/x/notes.md` - is also flagged, in both
# languages. That is the second documented false positive alongside `/* */`, and
# it has the same cause: deciding whether the path sits before or after an
# inline marker needs the lexing that is deliberately not attempted here. Both
# fail loudly and take a one-line `mnt-path-exempt:` marker.
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
# A run that did not actually read what it claims to have read is a TOOL ERROR,
# not a pass. The success line carries the file count so "scanned 214 files, all
# clean" is distinguishable from "scanned nothing" - the same reason the drift
# tools print `OK (0 drift, 3 controls)` rather than a bare `0 drift`.
#
# The ways coverage can silently shrink, each closed here. (Stated as a list
# rather than a count: an earlier version of this comment led with a number that
# was already wrong by the next round.)
#   - zero eligible files matched -> rc 2;
#   - an enumerated file could not be opened -> rc 2;
#   - a directory could not be TRAVERSED, so its files were never enumerated at
#     all -> rc 2. The per-file readability probe structurally cannot see these,
#     which is why find's stderr is captured rather than discarded;
#   - grep declining to PRINT a match it found, which it does by default once it
#     sees a NUL byte or invalid encoding. Prevented outright by `-a` rather
#     than reported, since there is no reason to tolerate it.
#
# EXIT CODES
#   0 - clean; prints `OK (0 violations, N files scanned)` with N > 0
#   1 - at least one violation; names each file:line and the escape hatch
#   2 - tool error: a PATH argument that does not exist, zero files scanned, or
#       an incomplete scan (unreadable file, untraversable directory)
#
# Usage: scripts/check-no-mnt-paths.sh [PATH...]
# Contract + test suite: scripts/check-no-mnt-paths-test.sh

set -uo pipefail

# The literal this gate forbids in executable position. The marker must sit on
# the SAME line as the match - the gate scans scripts/ too, so it flags itself
# otherwise (it did, on the first run).
readonly MNT_PREFIX='/mnt/'  # mnt-path-exempt: the gate's own pattern
readonly EXEMPT_MARKER='mnt-path-exempt:'

# Anything `find` could not traverse lands here. A directory the walk cannot
# enter hides its contents from enumeration entirely, so the per-file `-r` probe
# can never see them: that check guards files we FOUND, and this guards files we
# could not find in the first place. Both halves are needed.
FIND_ERRORS="$(mktemp)"
trap 'rm -f "${FIND_ERRORS}"' EXIT

# collect_files DIR
# Emits the eligible files under DIR, one per line. Eligible = *.rs, *.sh,
# *.yml, *.yaml, or a file literally named `justfile`. Data files and corpus
# fixtures are deliberately excluded.
collect_files() {
    local dir="$1"
    # -L follows symlinks. Without it (find's -P default) `-type f` tests the
    # LINK rather than its target, while bash's `[[ -f ]]` in the explicit-path
    # branch follows - so the same file got opposite verdicts depending on
    # whether it was named directly or reached by walking.
    #
    # Under -L, `-type l` matches ONLY a link that could not be resolved, so
    # pruning it skips dangling symlinks without touching valid ones. (`-xtype l`
    # would be wrong here: under -L it matches EVERY symlink, which silently
    # excluded exactly the files this change exists to include. Verified both
    # ways against GNU findutils before choosing.)
    find -L "${dir}" \
        \( -type d -name target -o -type d -name .git -o -type l \) -prune -o \
        -type f \
        \( -name '*.rs' -o -name '*.sh' -o -name '*.yml' -o -name '*.yaml' \
           -o -name 'justfile' \) \
        -print 2>>"${FIND_ERRORS}"
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

# Comment syntax is LANGUAGE-SPECIFIC. Getting this wrong is how the first two
# cuts of this gate leaked: `#` was treated as a comment everywhere, but in Rust
# `#` starts an ATTRIBUTE. `#[path = "/mnt/..."]` makes rustc read that file at
# compile time, so it is a hard build dependency, not provenance.
comment_style_for() {
    case "$1" in
    *.rs) echo rust ;;
    *) echo hash ;;
    esac
}

scanned=0
violations=0
report=""
unreadable=()

for f in "${files[@]:-}"; do
    [[ -z "${f}" ]] && continue
    # An eligible file we cannot open is NOT a pass for that file. Record it;
    # a partial scan must not be reported as authoritative.
    if [[ ! -r "${f}" ]]; then
        unreadable+=("${f}")
        continue
    fi
    scanned=$((scanned + 1))
    style="$(comment_style_for "${f}")"
    while IFS= read -r hit; do
        [[ -z "${hit}" ]] && continue
        # `hit` is "LINENO:CONTENT" from grep -n.
        line_content="${hit#*:}"
        # Carve-out (a): the line is a comment IN THIS FILE'S LANGUAGE.
        if [[ "${style}" == rust ]]; then
            # Rust: ONLY `//` line comments (covers `//`, `///`, `//!`). A
            # leading `#` is an ATTRIBUTE, not a comment - both `#[...]` and
            # `#![...]`, since `#[path = "/mnt/..."]` is a compile-time read.
            #
            # `/* */` blocks are DELIBERATELY not recognised. A scanner for them
            # was written and then removed: without string-literal state, a `/*`
            # inside an ordinary string ("...rules.d/*.rules...", an idiom a
            # config linter uses constantly) opened a phantom block that
            # exempted every following line to EOF. That was live on nine
            # tracked files and silenced roughly 3400 lines while still printing
            # OK. Getting it right needs a Rust lexer, and the failure mode of
            # getting it wrong is SILENT.
            #
            # So this is a deliberate, documented false POSITIVE: provenance
            # inside a `/* */` block gets flagged and needs a one-line
            # `mnt-path-exempt:` marker. That direction fails loudly and is
            # fixed in seconds; the other direction hides violations. No such
            # block exists in the tree today.
            if [[ "${line_content}" =~ ^[[:space:]]*// ]]; then
                continue
            fi
        else
            # sh / yaml / justfile: `#` comments, EXCEPT a shebang. `#!` is the
            # most literal executable position there is - the kernel's
            # binfmt_script handler execs the named interpreter (execve(2)) - so
            # `#!/mnt/...` is a hard runtime dependency. It applies at any
            # indent, because `just` shebang recipes are indented, and they are
            # the majority form in this repo's justfile.
            if [[ "${line_content}" =~ ^[[:space:]]*# && ! "${line_content}" =~ ^[[:space:]]*#! ]]; then
                continue
            fi
        fi
        # Carve-out (b): the line carries the explicit exemption marker.
        if [[ "${line_content}" == *"${EXEMPT_MARKER}"* ]]; then
            continue
        fi
        violations=$((violations + 1))
        report+="  ${f}:${hit%%:*}: ${line_content}"$'\n'
        # -a (--binary-files=text) is load-bearing, not cosmetic. By default
        # grep SUPPRESSES matching lines once it sees a NUL byte or invalid
        # encoding, reporting only to stderr (and on some versions not even
        # that) while the file still counts toward `scanned`. That is a fourth
        # way coverage shrinks silently, alongside zero-files, unreadable file
        # and untraversable directory. A NUL byte in Rust source is legal and
        # compiles, so the input is not hypothetical.
    done < <(grep -a -nF -- "${MNT_PREFIX}" "${f}" 2>/dev/null || true)
done

# Scan-integrity checks. A run that could not read everything it was asked to
# read, or that read nothing at all, must never be reported as clean. Violations
# are reported first because they are the more actionable signal.
if [[ "${violations}" -eq 0 && -s "${FIND_ERRORS}" ]]; then
    echo "check-no-mnt-paths: ERROR - the directory walk could not traverse everything;" >&2
    echo "  files inside an unreadable directory are never enumerated, so a clean" >&2
    echo "  result here would not be authoritative:" >&2
    sed 's/^/    /' "${FIND_ERRORS}" >&2
    exit 2
fi

if [[ "${violations}" -eq 0 && "${#unreadable[@]}" -gt 0 ]]; then
    echo "check-no-mnt-paths: ERROR - ${#unreadable[@]} eligible file(s) could not be read;" >&2
    echo "  the scan is INCOMPLETE, so a clean result would not be authoritative:" >&2
    printf '    %s\n' "${unreadable[@]}" >&2
    exit 2
fi

# ANTI-VACUITY: scanning nothing must never read as clean.
if [[ "${violations}" -eq 0 && "${scanned}" -eq 0 ]]; then
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
