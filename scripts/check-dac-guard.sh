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
# Implementation note: function-scope detection is a lightweight character
# scanner (comment/string-aware brace counting keyed off the `fn` keyword),
# not a full Rust parser. It is exact for the guard idiom actually used in
# this repo (single-line `fn name(...) { ... }` signatures) and for the
# common case generally; pathological inputs (raw string literals, `fn`
# appearing inside an unrelated type annotation such as a bare function
# pointer type) are out of scope for a CI shell gate.

set -uo pipefail

dirs=("$@")
if [[ "${#dirs[@]}" -eq 0 ]]; then
    dirs=("crates")
fi

# AWK_PROG: per-file scanner.
#
# Pass 1 (per input line, main rule): a character-by-character scan that
# tracks block-comment / line-comment / string-literal state (so brace
# characters inside comments or strings are never counted) and maintains a
# brace-depth stack. Every time a `{` opens, the accumulated "code since the
# last brace event" buffer is checked for a whole-word `fn` token; the new
# stack frame is tagged is_fn accordingly. Every time a `}` closes, the
# frame is popped and recorded as a closed block [start_line, end_line,
# is_fn]. The buffer resets on every brace event, so a block's is_fn tag
# reflects only the signature immediately preceding its own opening brace.
# Raw (unmodified) line text is also stored, and every line is grep'd for
# the literal from_mode(0o000 / from_mode(0o555 substrings.
#
# Pass 2 (END): for every from_mode(deny) hit line, find the innermost
# is_fn block that contains it (max start_line among candidates spanning
# the hit line) and search that block's raw lines for CAP_DAC_OVERRIDE or
# a dac-override-exempt: comment. No enclosing fn is found only for
# pathological input; a small window around the hit line is used instead.
AWK_PROG=$(cat <<'AWK_EOF'
BEGIN {
    depth = 0
    cb = 0
    nhits = 0
    in_string = 0
    in_block_comment = 0
    escaped = 0
    buffer = ""
}
{
    raw[NR] = $0
    line = $0
    n = length(line)
    i = 1
    while (i <= n) {
        c = substr(line, i, 1)
        if (in_block_comment) {
            if (c == "*" && substr(line, i + 1, 1) == "/") {
                in_block_comment = 0
                i += 2
                continue
            }
            i++
            continue
        }
        if (in_string) {
            if (escaped) {
                escaped = 0
                i++
                continue
            }
            if (c == "\\") {
                escaped = 1
                i++
                continue
            }
            if (c == "\"") {
                in_string = 0
                i++
                continue
            }
            i++
            continue
        }
        if (c == "/" && substr(line, i + 1, 1) == "/") {
            break
        }
        if (c == "/" && substr(line, i + 1, 1) == "*") {
            in_block_comment = 1
            i += 2
            continue
        }
        if (c == "\"") {
            in_string = 1
            escaped = 0
            i++
            continue
        }
        if (c == "{") {
            newdepth = depth + 1
            stack_start[newdepth] = NR
            stack_isfn[newdepth] = (buffer ~ /(^|[^A-Za-z0-9_])fn([^A-Za-z0-9_]|$)/) ? 1 : 0
            depth = newdepth
            buffer = ""
            i++
            continue
        }
        if (c == "}") {
            if (depth > 0) {
                s = stack_start[depth]
                f = stack_isfn[depth]
                cb++
                cbstart[cb] = s
                cbend[cb] = NR
                cbisfn[cb] = f
                depth--
            }
            buffer = ""
            i++
            continue
        }
        buffer = buffer c
        i++
    }
    if (!in_block_comment && !in_string) {
        buffer = buffer " "
    }
    if (index(line, "from_mode(0o000") > 0 || index(line, "from_mode(0o555") > 0) {
        nhits++
        hitline[nhits] = NR
    }
}
END {
    for (h = 1; h <= nhits; h++) {
        hl = hitline[h]
        beststart = -1
        bestend = -1
        for (b = 1; b <= cb; b++) {
            if (cbisfn[b] && cbstart[b] <= hl && hl <= cbend[b]) {
                if (cbstart[b] > beststart) {
                    beststart = cbstart[b]
                    bestend = cbend[b]
                }
            }
        }
        if (beststart != -1) {
            wstart = beststart
            wend = bestend
        } else {
            wstart = (hl - 5 > 1) ? hl - 5 : 1
            wend = (hl + 2 <= NR) ? hl + 2 : NR
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
