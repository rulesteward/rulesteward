#!/usr/bin/env bash
# scripts/check-dac-guard.sh - CI gate (#467)
#
# INVOCATION CONTRACT (frozen by scripts/check-dac-guard-test.sh):
#
#   scripts/check-dac-guard.sh [DIR...]
#
#   - With no DIR arguments: scans "crates" relative to the caller's CWD
#     (the gate is always invoked from the repo root by `just` and CI, so
#     this resolves to the real crates/ tree in normal use).
#   - With one or more DIR arguments: scans each given DIR instead.
#   - Scan rule: recursively find every *.rs file that lives under a `src`
#     or `tests` path component somewhere below DIR. A crate-root build.rs
#     (outside src/ and tests/) is never scanned.
#   - For every scanned file, grep for the literal substrings
#     `from_mode(0o000` and `from_mode(0o555` (restrictive/deny chmod
#     modes). Other modes (0o644, 0o755, ...) are never matched.
#   - Each hit is a VIOLATION unless EITHER:
#       (a) a CAP_DAC_OVERRIDE marker (comment or string literal, exact
#           case-sensitive token) appears somewhere within the SAME
#           enclosing `fn ... { ... }` body as the from_mode(...) call -
#           per-function scoping, not a nearby-lines window; or
#       (b) a `dac-override-exempt: <reason>` line comment appears near
#           the from_mode(...) call.
#   - Exit 1 if any unguarded/unexempted violation is found (message
#     names the CAP_DAC_OVERRIDE convention). Exit 0 if the scanned tree
#     is clean, including the trivial case of zero from_mode(deny) calls.
#
# Guard convention reference: crates/rulesteward-sysctld/tests/system.rs
# (the `unreadable_search_directory_emits_a_file_level_f01` test) and the
# "DAC guard" section of CONTRIBUTING.md.
#
# Implementation note: function-scope detection is FN-HEADER-ANCHORED, not
# a brace/string/comment lexer. For every from_mode(deny) hit, the AWK
# scanner records every line in the file that matches a `fn` HEADER regex
# (line-start, optional whitespace, optional pub(...)/async/unsafe/extern
# "ABI" modifiers, then a bare `fn` keyword followed by whitespace - see
# FN_HEADER_RE below). The hit's enclosing region is
# [nearest preceding fn-header line, next following fn-header line - 1]
# (or EOF if there is no following fn-header line; or line 1 if the hit
# precedes every fn-header line in the file). A CAP_DAC_OVERRIDE marker or
# dac-override-exempt hatch is credited only if it falls inside that
# region. This never inspects string or comment contents to find the
# region boundaries, so it is immune by construction to raw string
# literals (r#"..."#), ordinary string literals, and char-literal braces
# desyncing detection - unlike a brace-counting scanner, which a raw
# string with an odd interior double-quote count can desync for the rest
# of the file (the bug this rewrite fixes; see #467 case8/case9 in
# scripts/check-dac-guard-test.sh).
#
# Documented blind spots (both rare in this repo's test code, and neither
# is a silent-fail-open risk the way the old brace desync was - a nested
# fn item narrows the guard-search region rather than widening it past a
# real violation):
#   - A `fn` item NESTED inside another fn's body counts as its own
#     region boundary, splitting the outer fn's body into two regions at
#     that point. A guard placed on the far side of a nested fn from its
#     from_mode(...) call would not be credited even though both are
#     lexically inside the same outer fn.
#   - A line that starts with (optional whitespace then) literal `fn `
#     text embedded inside a multi-line string literal is indistinguishable
#     from a real fn header and would false-anchor a region boundary.

set -uo pipefail

dirs=("$@")
if [[ "${#dirs[@]}" -eq 0 ]]; then
    dirs=("crates")
fi

# AWK_PROG: per-file scanner.
#
# Pass 1 (per input line, main rule): record the raw line text, note
# whether the line matches the fn-header regex (recording its line
# number in order), and note whether the line contains a from_mode(deny)
# hit (recording its line number).
#
# Pass 2 (END): for every from_mode(deny) hit line, walk the ordered
# fn-header line numbers to find the enclosing region - the nearest
# fn-header line at or before the hit, through the line before the next
# fn-header line after it (or EOF if none). Search that region's raw
# lines for a CAP_DAC_OVERRIDE marker or a dac-override-exempt: comment.
AWK_PROG=$(cat <<'AWK_EOF'
BEGIN {
    nhits = 0
    nfn = 0
}
{
    raw[NR] = $0
    if ($0 ~ /^[[:space:]]*(pub(\([^)]*\))?[[:space:]]+)?(async[[:space:]]+)?(unsafe[[:space:]]+)?(extern[[:space:]]+"[^"]*"[[:space:]]+)?fn[[:space:]]/) {
        nfn++
        fnline[nfn] = NR
    }
    if (index($0, "from_mode(0o000") > 0 || index($0, "from_mode(0o555") > 0) {
        nhits++
        hitline[nhits] = NR
    }
}
END {
    total = NR
    for (h = 1; h <= nhits; h++) {
        hl = hitline[h]
        wstart = 1
        wend = total
        for (f = 1; f <= nfn; f++) {
            if (fnline[f] <= hl) {
                wstart = fnline[f]
            } else {
                wend = fnline[f] - 1
                break
            }
        }
        guarded = 0
        for (ln = wstart; ln <= wend; ln++) {
            if (index(raw[ln], "CAP_DAC_OVERRIDE") > 0) {
                guarded = 1
                break
            }
            if (raw[ln] ~ /dac-override-exempt:/) {
                guarded = 1
                break
            }
        }
        if (!guarded) {
            printf "%s:%d: unguarded restrictive from_mode() chmod fixture - add a CAP_DAC_OVERRIDE marker in the same function, or a dac-override-exempt: <reason> comment.\n", FILENAME, hl
        }
    }
}
AWK_EOF
)

found_violation=0
report=""

while IFS= read -r -d '' file; do
    file_out="$(awk "${AWK_PROG}" "${file}")"
    if [[ -n "${file_out}" ]]; then
        report+="${file_out}"$'\n'
        found_violation=1
    fi
done < <(
    for d in "${dirs[@]}"; do
        find "${d}" -type f -name '*.rs' \( -path '*/src/*' -o -path '*/tests/*' \) -print0
    done
)

if [[ "${found_violation}" -eq 1 ]]; then
    printf '%s' "${report}"
    echo ""
    echo "Guard convention violated: every restrictive chmod fixture (from_mode(0o000)"
    echo "or from_mode(0o555)) needs a CAP_DAC_OVERRIDE marker (comment or string"
    echo "literal) within the SAME function, or a dac-override-exempt: <reason>"
    echo "comment nearby. See the guard idiom in"
    echo "crates/rulesteward-sysctld/tests/system.rs and the 'DAC guard' section of"
    echo "CONTRIBUTING.md."
    exit 1
fi

exit 0
