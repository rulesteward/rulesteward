#!/usr/bin/env bash
# scripts/check-codes-count.sh - CI gate (#586)
#
# INVOCATION CONTRACT (frozen by scripts/check-codes-count-test.sh - read that
# file's header comment first for the full, authoritative specification;
# this header is a working summary, not a replacement for it):
#
#   scripts/check-codes-count.sh [REPO_ROOT]
#
#   - With no argument: REPO_ROOT defaults to the caller's CWD (the gate is
#     always invoked from the repo root by `just` and CI).
#   - With one argument: REPO_ROOT is that directory instead.
#
#   Scanned files (relative to REPO_ROOT), exactly two, IF PRESENT (a missing
#   scanned file contributes zero mentions and is not itself an error):
#     - README.md
#     - crates/rulesteward-cli/src/cli/mod.rs
#   Deliberately NOT scanned: CHANGELOG.md (point-in-time historical release
#   notes) and every other *.rs file (e.g. tests/cli_help.rs) - both verified
#   out of scope by two independent reviews.
#
#   Six backends, each with a code-prefix, a catalog file (relative to
#   REPO_ROOT), and a display name used by mention shape (c):
#     fapd-      crates/rulesteward-fapolicyd/src/lints/catalog.rs      fapolicyd
#     au-        crates/rulesteward-auditd/src/lints/catalog.rs         auditd
#     sshd-      crates/rulesteward-sshd/src/lints/catalog.rs           sshd_config
#     sudo-      crates/rulesteward-sudoers/src/lints/catalog.rs        sudoers
#     sysctld-   crates/rulesteward-sysctld/src/catalog.rs              sysctl.d
#     se-        crates/rulesteward-selinux/src/lints/catalog.rs        SELinux
#   KNOWN LIMITATION (flagged, not fixed here): this table is hardcoded, so a
#   7th backend added later is silently invisible to this gate until the
#   table is updated too.
#
#   A backend's CATALOG LENGTH is the count of OCCURRENCES (not lines) of the
#   literal substring `code: "<prefix>` in its catalog file: two entries
#   crammed onto one line count as 2, not 1. In practice this coincides with
#   a line count today (rustfmt's one-field-per-line style puts one entry per
#   line), but the occurrence count is the frozen, correct definition.
#
#   A "codes mention" is any of these three shapes, tied to one of the six
#   prefixes/display names (backtick-wrapping in shape (a) is optional, but
#   the open/close backticks are paired - both present or both absent):
#     (a) `<N> `<prefix>`? codes`  - "28 `fapd-` codes", "9 au- codes"
#     (b) `` `<prefix>`, <N> codes) `` - "### fapolicyd (`fapd-`, 28 codes)"
#     (c) `<N> <display-name> codes` - "28 fapolicyd codes"
#   Each mention's stated N must equal that backend's catalog length.
#
#   VIOLATION reporting: each unmatched mention is reported on one line as
#   exactly:
#       <file>:<line>: stated <N>, catalog length <M> for `<prefix>`
#
#   UNRECOGNIZED-MENTION rule (#586 round-4 hardening): partial coverage
#   erosion - a mention rewritten into prose that isn't one of the three
#   precise shapes above - used to go entirely unnoticed: `scanned` simply
#   drops and the gate exits 0. A line in a scanned file is now ALSO a
#   violation if it contains one of the six backends' PREFIX or DISPLAY NAME
#   (word-bounded: the character immediately before/after must not be a
#   letter, digit, or underscore - this is what stops "parse-error"'s
#   embedded "se-" from false-triggering `se-`), AND the word "codes"
#   (case-insensitive, so "Codes" counts), AND a digit, anywhere on that
#   line, but the line was NOT claimed by any of shapes (a)/(b)/(c) for that
#   backend. Reported as:
#       <file>:<line>: unrecognized "codes" mention for `<prefix>` (matches no known shape)
#   This does not change what counts toward the `scanned` summary line below
#   (that stays shape-based, unchanged) - it is an independent violation
#   source that also forces a non-zero exit.
#
#   PER-BACKEND MENTION COUNTS (#586 round-4 hardening): on every invocation,
#   stdout also includes, once per backend, a line of the exact literal form:
#       per-backend mentions: `<prefix>` = <N>
#   (N = the count of shape-based mentions, i.e. this backend's share of the
#   `scanned` total across both files) - lets tooling assert this figure
#   independently, without hardcoding the aggregate total, which drifts as
#   docs legitimately grow.
#
#   PER-BACKEND COVERAGE FLOOR (#586 round-5 hardening): the gate itself now
#   enforces N >= 1 for every one of the six backends, but ONLY when all six
#   catalog files listed in the table above exist under REPO_ROOT - i.e. only
#   against a full six-backend project tree, never against a narrow synthetic
#   fixture that deliberately stages a subset of catalogs to exercise one
#   specific shape/exclusion behavior (such a fixture asserts nothing about
#   backends it never staged a catalog for, so the floor does not apply to
#   it). This closes the gap the UNRECOGNIZED-MENTION rule above cannot: a
#   backend whose every mention is reworded into prose naming it by NEITHER
#   its prefix NOR its display name (e.g. "the sshd backend ships 13 lint
#   codes") carries no signal for that rule to catch either, and previously
#   drops to zero live mentions with no violation raised at all. A backend at
#   exactly 0 (when the floor applies) is reported as its own violation line,
#   syntactically distinct from a count mismatch or an unrecognized-mention
#   violation (neither of which carries a `<file>:<line>:` prefix):
#       per-backend coverage floor violated: `<prefix>` has 0 live "codes" mention(s) across README.md and crates/rulesteward-cli/src/cli/mod.rs (expected >= 1)
#
#   ANTI-VACUITY: a scan that finds ZERO "codes" mentions across both files
#   combined is ALSO a violation (exit non-zero). On every invocation, stdout
#   MUST include a summary line of the exact literal form:
#       scanned N "codes" mention(s)
#
#   EXIT CODE: 0 only when at least one mention was found AND every mention's
#   stated N equals its backend's catalog length AND no unrecognized-mention
#   violation was found AND (when all six catalogs are present) no backend's
#   live mention count is zero (the per-backend coverage floor). 1 otherwise.
#
# Implementation note: this is a fixed, small scan (2 files x 6 backends x 3
# shapes), so it is done directly in bash + grep (one `grep -nEo` call per
# shape per backend per file) rather than a single awk pass over arbitrarily
# many files (contrast scripts/check-dac-guard.sh, which recurses over an
# unbounded crates/ tree and so earns the single-awk-pass design). The six
# prefixes and display names are hardcoded literals controlled entirely by
# this script (not external input), so the one display name containing a
# regex metacharacter (`sysctl.d`'s `.`) is pre-escaped in the table below
# rather than run through a generic escaper.

set -uo pipefail

REPO_ROOT="${1:-$(pwd)}"

# Parallel arrays: index i describes one backend.
PREFIXES=(fapd- au- sshd- sudo- sysctld- se-)
CATALOG_FILES=(
    "crates/rulesteward-fapolicyd/src/lints/catalog.rs"
    "crates/rulesteward-auditd/src/lints/catalog.rs"
    "crates/rulesteward-sshd/src/lints/catalog.rs"
    "crates/rulesteward-sudoers/src/lints/catalog.rs"
    "crates/rulesteward-sysctld/src/catalog.rs"
    "crates/rulesteward-selinux/src/lints/catalog.rs"
)
# Display names as they appear in prose, already ERE-escaped where needed
# (only "sysctl.d" carries a regex metacharacter: the literal dot).
DISPLAY_NAMES_RE=(fapolicyd auditd sshd_config sudoers 'sysctl\.d' SELinux)

# The two scanned files, relative to REPO_ROOT.
SCAN_FILES=(
    "README.md"
    "crates/rulesteward-cli/src/cli/mod.rs"
)

# catalog_length PREFIX FILE
# Counts OCCURRENCES (not lines) of the literal substring `code: "<prefix>`
# in FILE - two entries crammed onto one line count as 2. A missing FILE
# yields 0, not an error.
catalog_length() {
    local prefix="$1" file="$2"
    local n=""
    n="$(grep -o "code: \"${prefix}" "${file}" 2>/dev/null | wc -l || true)"
    echo "${n:-0}"
}

CATALOG_LEN=()
for i in "${!PREFIXES[@]}"; do
    CATALOG_LEN[i]="$(catalog_length "${PREFIXES[i]}" "${REPO_ROOT}/${CATALOG_FILES[i]}")"
done

# ALL_CATALOGS_PRESENT gates the per-backend coverage floor below: it is only
# meaningful to require "every backend has >= 1 mention" when every backend's
# catalog file actually exists under REPO_ROOT (a full six-backend tree). A
# narrow synthetic fixture that stages only one or two catalogs to exercise a
# specific shape/exclusion behavior says nothing about the backends it never
# staged, so the floor must not apply to it.
ALL_CATALOGS_PRESENT=1
for i in "${!PREFIXES[@]}"; do
    [[ -f "${REPO_ROOT}/${CATALOG_FILES[i]}" ]] || ALL_CATALOGS_PRESENT=0
done

scanned=0
violations=""
violation_count=0

PREFIX_MENTION_COUNT=()
for i in "${!PREFIXES[@]}"; do
    PREFIX_MENTION_COUNT[i]=0
done

for scan_rel in "${SCAN_FILES[@]}"; do
    scan_abs="${REPO_ROOT}/${scan_rel}"
    [[ -f "${scan_abs}" ]] || continue

    for i in "${!PREFIXES[@]}"; do
        prefix="${PREFIXES[i]}"
        dispname_re="${DISPLAY_NAMES_RE[i]}"
        catlen="${CATALOG_LEN[i]}"

        # Shape (a): <N> (optionally, paired-backtick-wrapped) <prefix> codes
        shape_a="[0-9]+[[:space:]]+(\`${prefix}\`|${prefix})[[:space:]]+codes"
        # Shape (b): the README heading form - `<prefix>`, <N> codes)
        shape_b="\`${prefix}\`,[[:space:]]*[0-9]+[[:space:]]+codes\)"
        # Shape (c): <N> <display-name> codes
        shape_c="[0-9]+[[:space:]]+${dispname_re}[[:space:]]+codes"

        # Lines claimed by one of the three shapes above, for THIS backend on
        # THIS file - space-padded so membership can be tested as a fixed
        # substring (" ${lineno} ") without matching e.g. "1" inside "12".
        claimed_lines=" "

        for shape_re in "${shape_a}" "${shape_b}" "${shape_c}"; do
            while IFS=: read -r lineno match; do
                [[ -z "${lineno}" ]] && continue
                stated="$(printf '%s' "${match}" | grep -oE '[0-9]+' | head -1)"
                scanned=$((scanned + 1))
                PREFIX_MENTION_COUNT[i]=$((PREFIX_MENTION_COUNT[i] + 1))
                claimed_lines+="${lineno} "
                if [[ "${stated}" != "${catlen}" ]]; then
                    violations+="${scan_rel}:${lineno}: stated ${stated}, catalog length ${catlen} for \`${prefix}\`"$'\n'
                    violation_count=$((violation_count + 1))
                fi
            done < <(grep -nEo "${shape_re}" "${scan_abs}" 2>/dev/null || true)
        done

        # UNRECOGNIZED-MENTION rule: a line that references this backend (by
        # prefix or display name, word-bounded so "parse-error" cannot
        # false-trigger `se-`) AND says "codes" (case-insensitive) AND has a
        # digit, but was not claimed by any shape above, is itself a
        # violation - silent shape-erosion must not silently pass.
        signal_re="(^|[^A-Za-z0-9_])(${prefix}|${dispname_re})([^A-Za-z0-9_]|\$)"
        while IFS=: read -r lineno rest; do
            [[ -z "${lineno}" ]] && continue
            printf '%s' "${rest}" | grep -qiE 'codes' || continue
            printf '%s' "${rest}" | grep -qE '[0-9]' || continue
            [[ "${claimed_lines}" == *" ${lineno} "* ]] && continue
            violations+="${scan_rel}:${lineno}: unrecognized \"codes\" mention for \`${prefix}\` (matches no known shape)"$'\n'
            violation_count=$((violation_count + 1))
        done < <(grep -nE "${signal_re}" "${scan_abs}" 2>/dev/null || true)
    done
done

# PER-BACKEND COVERAGE FLOOR: only when every one of the six catalog files is
# present (see ALL_CATALOGS_PRESENT above), require every backend to have
# >= 1 live shape-based mention. This is what catches a backend whose every
# mention has been reworded into prose naming it by neither its prefix nor
# its display name - invisible to the UNRECOGNIZED-MENTION rule above too,
# since that rule also keys off the prefix/display-name signal.
if [[ "${ALL_CATALOGS_PRESENT}" -eq 1 ]]; then
    for i in "${!PREFIXES[@]}"; do
        if [[ "${PREFIX_MENTION_COUNT[i]}" -eq 0 ]]; then
            violations+="per-backend coverage floor violated: \`${PREFIXES[i]}\` has 0 live \"codes\" mention(s) across README.md and crates/rulesteward-cli/src/cli/mod.rs (expected >= 1)"$'\n'
            violation_count=$((violation_count + 1))
        fi
    done
fi

if [[ -n "${violations}" ]]; then
    printf '%s' "${violations}"
fi

echo "scanned ${scanned} \"codes\" mention(s)"
for i in "${!PREFIXES[@]}"; do
    echo "per-backend mentions: \`${PREFIXES[i]}\` = ${PREFIX_MENTION_COUNT[i]}"
done

if [[ "${violation_count}" -gt 0 || "${scanned}" -eq 0 ]]; then
    echo ""
    echo "Codes-count guard violated: every 'N codes' / 'N <backend> codes' prose"
    echo "mention in README.md or crates/rulesteward-cli/src/cli/mod.rs must equal"
    echo "its backend's catalog length (the count of code: \"<prefix> entries in"
    echo "that backend's catalog.rs). Zero mentions found is also a failure."
    exit 1
fi

exit 0
