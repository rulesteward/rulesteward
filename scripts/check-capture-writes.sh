#!/usr/bin/env bash
# scripts/check-capture-writes.sh - layer 3 of the rs-capture-guard defense
# (session 9k-1): a static gate over the Tier-2 capture scripts themselves.
#
# WHY
# scripts/rs-capture-guard.sh gives every capture_*.sh two runtime layers:
# rs_checked wraps each write so a failed one aborts the capture (rc 2)
# instead of continuing past it, and rs_capture_verify_output counts what
# actually landed on disk at the end. Both are opt-in - a future edit can add
# a bare `cp`/`mkdir`/... outside the wrapper and neither layer notices,
# because layer 1 only checks the writes it was told about and layer 2 can
# still see a plausible-looking (if wrong) file count. This script is the
# structural backstop: it fails the build the moment a capture script writes
# without going through the wrapper, so layer 1 stays enforced rather than
# remembered. It is the shape of scripts/check-dac-guard.sh and
# scripts/check-no-mnt-paths.sh applied to this defect class - see
# rs-capture-guard.sh's own header for the "Disk quota exceeded" incident
# this whole three-layer design exists to prevent.
#
# WHAT COUNTS AS A VIOLATION
# In a discovered capture script, a line that invokes one of
#   cp mv install mkdir rmdir ln truncate tee dd
# as the command actually being run - i.e. it is the first word of a shell
# command segment, not an argument to something else - is a violation unless
# that segment's command word is itself `rs_checked` (a real invocation of
# one of these as a bare command starts the segment; `rs_checked cp ...`
# starts the segment with `rs_checked`, so the write command is never in
# command position at all and nothing needs to be special-cased for it).
# A `cat` segment that redirects into a file with a bare `>`/`>>` (rather
# than piping its output into `rs_checked_write`) is a violation of the same
# shape - `rs_checked_write` exists precisely because `rs_checked cat > f`
# cannot work (the shell binds the redirect to `rs_checked`, not to `cat`;
# see rs-capture-guard.sh's own comment on that function). fd-only redirects
# (`2>`, `>&`) and a discard to `/dev/null` are not writes this gate cares
# about and are not flagged.
#
# A shell command "segment" is whatever sits between the separators
# `&&`, `||`, `;`, `|`, `(` and the keywords `then`, `else`, `do`. Checking
# only the FIRST word of a segment is what makes a quoted diagnostic string
# ("could not cp the payload into place") safe by construction: the write
# command there is not the first word of any segment, it is an argument to
# whatever printed the message, so it can never match.
#
# NOT SCANNED, deliberately:
#   - a line that is a comment (starts, after optional leading whitespace,
#     with `#` and is not a shebang) - matches the sibling gates' convention:
#     ONLY a line beginning with the comment marker is recognised. A trailing
#     comment on a real code line is NOT specially stripped and can produce a
#     documented false positive, same as check-no-mnt-paths.sh's block-comment
#     and trailing-comment cases; the remedy is the same one-line escape hatch.
#   - a here-doc BODY: the payload text a capture script emits for the
#     container to execute is not shell code this script runs itself, so a
#     `cp`/`mkdir`/... inside it is not this gate's business. The here-doc
#     START line (which may itself perform a write, e.g. `cat <<'EOF' > f`)
#     is still scanned. A bare here-string (`<<<`) is not a here-doc and is
#     never treated as one - see the implementation note by the word `<<<`
#     below for why that distinction needs an explicit guard.
#
# ESCAPE HATCH
# A line carrying `capture-write-exempt: <reason>` - the marker followed by a
# NON-EMPTY reason, on that same line or the line immediately above it -
# exempts every write on that line. Mirrors check-dac-guard.sh's
# `dac-override-exempt:` hatch. Legitimate use: a write to a scratch path
# whose success is checked separately on the next line (so wrapping it in
# rs_checked would just duplicate that check), e.g.:
#
#   cp "${scratch_src}" "${scratch_dst}"  # capture-write-exempt: checked below
#   [ -f "${scratch_dst}" ] || rs_capture_die "scratch copy did not land"
#
# The marker WITHOUT a reason (just the bare token) does not exempt anything
# - a hatch with no stated reason is indistinguishable from someone pasting
#   the token to silence the gate, which is the failure mode the reason
#   requirement exists to catch.
#
# DISCOVERY
# Capture scripts are found by the fixed glob
#   ROOT/crates/*/tests/corpus/*/capture_*.sh
# ROOT defaults to "." (the gate is always invoked from the repo root by
# `just` and by CI). A ROOT that is not a directory is a tool error.
#
# THE COUNT FLOOR (CONTRIBUTING.md "Assert the count, do not merely print it")
# EXPECTED_CAPTURE_SCRIPTS below is the number of capture_*.sh files this
# branch is expected to carry. Scanning FEWER than that is a hard failure -
# a capture script vanishing (deleted, renamed, moved out of the glob shape)
# must not silently shrink what this gate checks. Scanning exactly zero
# when the constant is also zero is not a failure: today, on this branch,
# the auditd/sysctld/sudoers lanes that own capture_*.sh files have not
# merged yet, so a zero scan is this branch's honest state. That case still
# prints an explicit "nothing to check" line rather than an "OK, all clean"
# line, so the two can never be confused - the exact ambiguity that let
# `just diff-fapolicyd` report success while checking nothing (#572).
#
# EXIT CODES
#   0 - clean: either N>0 capture scripts scanned with 0 violations, or
#       EXPECTED_CAPTURE_SCRIPTS is 0 and 0 were found (the explicit
#       "nothing to check" case above).
#   1 - at least one bare-write violation found; message names every
#       file:line and the escape hatch.
#   2 - tool error: ROOT does not exist, fewer capture scripts were found
#       than EXPECTED_CAPTURE_SCRIPTS, or a discovered script could not be
#       read.
#
# Usage: scripts/check-capture-writes.sh [ROOT]
# Contract + test suite: scripts/check-capture-writes-test.sh

set -uo pipefail

ROOT="${1:-.}"
if [[ ! -d "${ROOT}" ]]; then
    echo "check-capture-writes: ERROR - no such directory: ${ROOT}" >&2
    exit 2
fi

# Number of Tier-2 capture scripts expected to exist. RAISE THIS TO 3 in the
# session 9k-1 integration-gate commit, once the auditd, sysctld and sudoers
# lanes have all merged and their capture_*.sh files are on this branch. Until
# then a zero scan is the honest state of the branch, not a passing gate.
readonly EXPECTED_CAPTURE_SCRIPTS=0

# Deliberately NOT overridable from the environment. An env var that can lower
# this constant is a switch that silently turns the gate's only anti-vacuity
# floor off, and it would be indistinguishable from a real pass in a CI log.
# This project has already shipped and caught one fail-OPEN env parse
# (`RS_REQUIRE_<ORACLE>` compared against the literal "1"), so a gate does not
# get a new environment bypass. The test suite exercises the unmet-floor path
# by `sed`ing this constant in a COPY of this script and running the copy -
# the same positive-control idiom scripts/rs-oracle-diff-test.sh uses.

readonly EXEMPT_MARKER='capture-write-exempt:'

shopt -s nullglob
files=("${ROOT}"/crates/*/tests/corpus/*/capture_*.sh)
shopt -u nullglob

scanned="${#files[@]}"

if [[ "${scanned}" -lt "${EXPECTED_CAPTURE_SCRIPTS}" ]]; then
    echo "check-capture-writes: ERROR - found ${scanned} capture script(s) under" >&2
    echo "  ${ROOT}/crates/*/tests/corpus/*/capture_*.sh but expected at least" >&2
    echo "  ${EXPECTED_CAPTURE_SCRIPTS}. Either a lane's capture_*.sh went missing," >&2
    echo "  or EXPECTED_CAPTURE_SCRIPTS needs raising or lowering DELIBERATELY -" >&2
    echo "  never silently, since that constant is the only thing standing between" >&2
    echo "  'checked nothing' and 'checked everything' for this gate." >&2
    exit 2
fi

if [[ "${scanned}" -eq 0 ]]; then
    echo "check-capture-writes: 0 capture scripts found under" >&2
    echo "  ${ROOT}/crates/*/tests/corpus/*/capture_*.sh. Nothing was scanned - and" >&2
    echo "  that is the honest state of this branch today (session 9k-1's lanes have" >&2
    echo "  not merged their capture_*.sh files yet), NOT the same thing as 'every" >&2
    echo "  capture script is clean'. Raise EXPECTED_CAPTURE_SCRIPTS once real" >&2
    echo "  capture scripts land, so a future accidental deletion fails loudly" >&2
    echo "  instead of quietly returning to this same message." >&2
    echo "check-capture-writes: nothing to check (0 capture scripts, 0 expected)"
    exit 0
fi

# AWK_PROG: per-file scanner. Single pass, one file at a time (state resets
# cleanly between files rather than needing an FNR==1 reset hack).
#
# State carried across lines:
#   in_heredoc / heredoc_delim / heredoc_dash - are we inside a here-doc BODY,
#     and if so, what terminates it ('<<-' strips leading tabs from the
#     terminator line; plain '<<' requires an exact match).
#   prev_had_marker - did the PREVIOUS physical line carry a
#     capture-write-exempt: marker with a non-empty reason? The escape hatch
#     is honoured on the violating line itself or the line immediately above.
AWK_PROG=$(cat <<'AWK_EOF'
BEGIN {
    in_heredoc = 0
    heredoc_delim = ""
    heredoc_dash = 0
    prev_had_marker = 0
}
{
    cur_line = $0
    lineno = FNR
    skip_scan = 0

    if (in_heredoc) {
        candidate = cur_line
        if (heredoc_dash) {
            sub(/^\t+/, "", candidate)
        }
        if (candidate == heredoc_delim) {
            in_heredoc = 0
        }
        skip_scan = 1
    } else if (cur_line ~ /^[[:space:]]*#/ && cur_line !~ /^[[:space:]]*#!/) {
        # A whole-line comment (leading '#', not a shebang). Only a LEADING
        # marker is recognised, matching check-no-mnt-paths.sh /
        # check-dac-guard.sh: a trailing comment on a real code line is not
        # specially stripped anywhere in this file.
        skip_scan = 1
    }

    if (!skip_scan) {
        # Here-doc start detection ('<<' or '<<-', never a here-string
        # '<<<'). A bare here-string given an unquoted bareword delimiter
        # (`<<<EOF`) would otherwise be misread as a here-doc-with-body
        # start, and every following line to EOF would be silently treated
        # as that "body" and never scanned again - the exact silent-suppression
        # failure this whole session exists to eliminate, so '<<<' is
        # neutralised before the here-doc regex ever sees it.
        check = cur_line
        gsub(/<<</, "@@@", check)
        delim = ""
        dash = 0
        if (match(check, /<<-?[[:space:]]*'[A-Za-z_][A-Za-z0-9_]*'/)) {
            seg = substr(check, RSTART, RLENGTH)
            dash = (seg ~ /^<<-/) ? 1 : 0
            delim = seg
            gsub(/^<<-?[[:space:]]*'/, "", delim)
            gsub(/'$/, "", delim)
        } else if (match(check, /<<-?[[:space:]]*"[A-Za-z_][A-Za-z0-9_]*"/)) {
            seg = substr(check, RSTART, RLENGTH)
            dash = (seg ~ /^<<-/) ? 1 : 0
            delim = seg
            gsub(/^<<-?[[:space:]]*"/, "", delim)
            gsub(/"$/, "", delim)
        } else if (match(check, /<<-?[[:space:]]*[A-Za-z_][A-Za-z0-9_]*/)) {
            seg = substr(check, RSTART, RLENGTH)
            dash = (seg ~ /^<<-/) ? 1 : 0
            delim = seg
            gsub(/^<<-?[[:space:]]*/, "", delim)
        }
        if (delim != "") {
            in_heredoc = 1
            heredoc_delim = delim
            heredoc_dash = dash
        }

        cur_has_reason = (cur_line ~ /capture-write-exempt:[[:space:]]*[^[:space:]]/)
        cur_has_bare_marker = (index(cur_line, "capture-write-exempt:") > 0)
        exempted = cur_has_reason || prev_had_marker

        # Split into command segments on the separators and keywords. Only
        # the FIRST word of a segment can be "the command actually invoked",
        # which is what makes both `rs_checked cp ...` (write command is an
        # ARGUMENT to rs_checked, never a segment-first-word) and a quoted
        # diagnostic string ("could not cp ...", also never a segment-first-
        # word) safe without any quote-aware parsing.
        segline = cur_line
        gsub(/(&&|\|\||;|\(|\|)/, "\n", segline)
        gsub(/[[:space:]](then|else|do)[[:space:]]/, "\n", segline)
        nseg = split(segline, segs, "\n")
        for (i = 1; i <= nseg; i++) {
            seg = segs[i]
            sub(/^[[:space:]]+/, "", seg)
            hit = ""
            if (seg ~ /^(cp|mv|install|mkdir|rmdir|ln|truncate|tee|dd)([[:space:]]|$)/) {
                hit = seg
            } else if (seg ~ /^cat([[:space:]]|$)/) {
                # A bare '>'/'>>' redirect out of `cat`, excluding fd-only
                # forms (`2>`, `>&`) and a discard to /dev/null - none of
                # those write bytes this gate needs verified.
                if (seg ~ />/ && seg !~ /[0-9]>/ && seg !~ />&/ && seg !~ />[[:space:]]*\/dev\/null/) {
                    hit = seg
                }
            }
            if (hit != "") {
                if (exempted) {
                    continue
                }
                violations++
                if (cur_has_bare_marker) {
                    printf "%s:%d: bare write (%s) has a capture-write-exempt: marker but NO stated reason - a hatch needs 'capture-write-exempt: <reason>', not just the bare token. Line: %s\n", FILENAME, lineno, hit, cur_line
                } else {
                    printf "%s:%d: bare write (%s) is not routed through rs_checked / rs_checked_write - wrap it, or add 'capture-write-exempt: <reason>' on this line or the line above. Line: %s\n", FILENAME, lineno, hit, cur_line
                }
            }
        }
    }

    prev_had_marker = (cur_line ~ /capture-write-exempt:[[:space:]]*[^[:space:]]/)
}
END {
    exit (violations > 0) ? 1 : 0
}
AWK_EOF
)

found_violation=0
report=""

for f in "${files[@]}"; do
    if [[ ! -r "${f}" ]]; then
        echo "check-capture-writes: ERROR - capture script found but not readable: ${f}" >&2
        exit 2
    fi
    file_out="$(awk "${AWK_PROG}" "${f}")" && file_rc=0 || file_rc=$?
    if [[ -n "${file_out}" ]]; then
        report+="${file_out}"$'\n'
    fi
    if [[ "${file_rc}" -gt 1 ]]; then
        echo "check-capture-writes: ERROR - awk failed scanning ${f} (rc ${file_rc})" >&2
        exit 2
    fi
    if [[ "${file_rc}" -eq 1 ]]; then
        found_violation=1
    fi
done

if [[ "${found_violation}" -eq 1 ]]; then
    printf '%s' "${report}" >&2
    cat >&2 <<EOF

A Tier-2 capture script must route every write through rs_checked /
rs_checked_write (scripts/rs-capture-guard.sh), so a failed write aborts the
capture instead of producing a truncated corpus that still reports success -
exactly what happened when a bare 'cp' hit "Disk quota exceeded" under
'set -uo pipefail' (no '-e') and the capture kept going and exited 0.

Fix it by wrapping the write, or if it is genuinely safe (e.g. a scratch
write whose success is checked on the next line), mark it with
'${EXEMPT_MARKER} <reason>' on that line or the line above.
EOF
    exit 1
fi

echo "check-capture-writes: OK (0 violations, ${scanned} capture script(s) scanned)"
exit 0
