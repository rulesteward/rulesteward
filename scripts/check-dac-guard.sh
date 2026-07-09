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
# FN_HEADER_RE below). The hit's enclosing region starts at
# [nearest preceding fn-header line, next following fn-header line - 1]
# (or EOF if there is no following fn-header line; or line 1 if the hit
# precedes every fn-header line in the file) and is then TRIMMED from the
# tail: the region is walked backward from its end line while each line is
# blank, a line comment (// or ///), or an attribute (#[...] / #![...]),
# stopping at the first line that is none of those (typically the region's
# own closing brace). That trim removes the NEXT fn's lead-in (its doc
# comment / attributes / a freestanding comment above its own header) from
# the region, so a marker sitting only in that lead-in gap is not credited
# to this fn's hit (#467 case10 in scripts/check-dac-guard-test.sh) - the
# region is effectively [nearest preceding fn-header line, last real code
# line before the next fn's lead-in]. The region's end is then narrowed a
# second way: the scanner captures the anchoring fn-header line's own
# leading-whitespace indentation and scans FORWARD from that header for the
# first line consisting of exactly that indentation followed by a bare `}`
# (the fn's own closing brace, which standard Rust formatting places at the
# same indentation as its header) - the region end becomes the EARLIER of
# that brace line and the header/tail-trimmed end above (a MIN, never a
# widening). This closes a second fail-open gap the tail-trim alone cannot:
# a non-comment code line (const/use/static/mod/macro-invocation) sitting
# between a deny fn's closing brace and the next boundary stops the tail
# trim's backward walk before it reaches a CAP_DAC_OVERRIDE marker sitting
# ABOVE that code line, wrongly leaving the marker inside the region (#467
# case12 in scripts/check-dac-guard-test.sh) - the indentation-matched brace
# scan excludes that whole gap (code line and any marker above it) instead.
# A CAP_DAC_OVERRIDE marker or dac-override-exempt hatch is credited only if
# it falls inside that doubly-narrowed region. Neither narrowing step
# inspects string or comment contents to find the region boundaries, so both
# are immune by construction to raw string literals (r#"..."#), ordinary
# string literals, and char-literal braces desyncing detection - unlike a
# brace-counting scanner, which a raw string with an odd interior
# double-quote count can desync for the rest of the file (the bug this
# rewrite fixes; see #467 case8/case9 in scripts/check-dac-guard-test.sh).
#
# Documented blind spots (both rare in this repo's test code, and neither
# is a silent-fail-open risk the way the old brace desync was - a nested
# fn item narrows the guard-search region rather than widening it past a
# real violation):
#   - PINNED CONTRACT: a `fn` item NESTED inside another fn's body counts
#     as its own region boundary, splitting the outer fn's body into two
#     regions at that point. A guard placed on the far side of a nested fn
#     from its from_mode(...) call is deliberately NOT credited, even
#     though both are lexically inside the same outer fn (#467 case11).
#     This is intentionally over-strict rather than fixed to match: it can
#     force a spurious guard requirement but can never hide a real
#     violation, which is the opposite failure mode from the gap-marker
#     case the tail-trim above fixes. The remedy for a real guard in this
#     shape is to place the CAP_DAC_OVERRIDE marker before the nested item,
#     or to use the dac-override-exempt: hatch instead. The indentation-
#     matched brace-end narrowing is a MIN against this header-split
#     boundary, never a replacement for it, so it cannot loosen case11.
#   - A line that starts with (optional whitespace then) literal `fn `
#     text embedded inside a multi-line string literal is indistinguishable
#     from a real fn header and would false-anchor a region boundary. The
#     same is true, symmetrically, of a multi-line string or raw string
#     literal whose content happens to contain a line consisting solely of
#     the anchoring header's indentation followed by `}`: the indentation-
#     matched brace scan would false-anchor the region end there. Neither
#     case is known to occur in this repo's test code.

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
        # Trim the region tail: a region ending at (next fn header - 1)
        # includes that next fn's lead-in (its doc comment, attributes,
        # and/or a freestanding line comment, plus any blank separator
        # lines) - that lead-in belongs to the SIBLING fn, not to this
        # region, so a marker sitting there must not be credited to this
        # hit. Walk backward from wend while the line is blank, a line
        # comment (// or /// - both match the // prefix), or an attribute
        # (#[...] or #![...]); stop at the first line that is none of
        # those (typically the region's own closing brace). Bounded at
        # wstart so the fn header line itself is never trimmed away.
        while (wend > wstart && (raw[wend] ~ /^[[:space:]]*$/ || raw[wend] ~ /^[[:space:]]*\/\// || raw[wend] ~ /^[[:space:]]*#!?\[/)) {
            wend--
        }
        # Indentation-matched closing-brace end (#467 case12): the tail-trim
        # above only removes a CONTIGUOUS run of blank/comment/attribute
        # lines walking backward from the region's end, so a non-comment
        # code line sitting in the gap between this fn's own closing brace
        # and the next boundary (a sibling const/use/static/mod/macro-
        # invocation item) stops that walk before it reaches a marker
        # comment sitting ABOVE that code line, wrongly leaving the marker
        # inside the region. Close that gap directly: scan FORWARD from this
        # hit's anchoring fn-header line (wstart) for the first line whose
        # leading whitespace matches the header's OWN indentation followed
        # by a bare closing brace - the fn's own closing brace, which
        # standard Rust formatting places at the same indentation as its
        # header. Only lines up to the already header/tail-trimmed wend are
        # considered, so this can only NARROW the region, never widen it
        # past a real fn-header split (#467 case11 stays pinned: this is a
        # MIN with, not a replacement for, the header-split boundary). If no
        # such brace line exists in range, wend is left unchanged (the
        # existing header/tail-trimmed end is always a safe fallback).
        match(raw[wstart], /^[[:space:]]*/)
        hdr_indent = substr(raw[wstart], RSTART, RLENGTH)
        brace_re = "^" hdr_indent "}[[:space:]]*$"
        for (ln = wstart + 1; ln <= wend; ln++) {
            if (raw[ln] ~ brace_re) {
                wend = ln
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
