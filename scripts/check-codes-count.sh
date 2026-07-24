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
#   A backend's CATALOG LENGTH is the count of lines matching the literal
#   substring `code: "<prefix>` in its catalog file.
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
#   ANTI-VACUITY: a scan that finds ZERO "codes" mentions across both files
#   combined is ALSO a violation (exit non-zero). On every invocation, stdout
#   MUST include a summary line of the exact literal form:
#       scanned N "codes" mention(s)
#
#   EXIT CODE: 0 only when at least one mention was found AND every mention's
#   stated N equals its backend's catalog length. 1 otherwise.
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
# Mirrors the frozen test's own helper: counts lines containing the literal
# substring `code: "<prefix>` in FILE. A missing FILE yields 0, not an error.
catalog_length() {
    local prefix="$1" file="$2"
    local n=""
    n="$(grep -c "code: \"${prefix}" "${file}" 2>/dev/null || true)"
    echo "${n:-0}"
}

CATALOG_LEN=()
for i in "${!PREFIXES[@]}"; do
    CATALOG_LEN[i]="$(catalog_length "${PREFIXES[i]}" "${REPO_ROOT}/${CATALOG_FILES[i]}")"
done

scanned=0
violations=""
violation_count=0

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

        for shape_re in "${shape_a}" "${shape_b}" "${shape_c}"; do
            while IFS=: read -r lineno match; do
                [[ -z "${lineno}" ]] && continue
                stated="$(printf '%s' "${match}" | grep -oE '[0-9]+' | head -1)"
                scanned=$((scanned + 1))
                if [[ "${stated}" != "${catlen}" ]]; then
                    violations+="${scan_rel}:${lineno}: stated ${stated}, catalog length ${catlen} for \`${prefix}\`"$'\n'
                    violation_count=$((violation_count + 1))
                fi
            done < <(grep -nEo "${shape_re}" "${scan_abs}" 2>/dev/null || true)
        done
    done
done

if [[ -n "${violations}" ]]; then
    printf '%s' "${violations}"
fi

echo "scanned ${scanned} \"codes\" mention(s)"

if [[ "${violation_count}" -gt 0 || "${scanned}" -eq 0 ]]; then
    echo ""
    echo "Codes-count guard violated: every 'N codes' / 'N <backend> codes' prose"
    echo "mention in README.md or crates/rulesteward-cli/src/cli/mod.rs must equal"
    echo "its backend's catalog length (the count of code: \"<prefix> entries in"
    echo "that backend's catalog.rs). Zero mentions found is also a failure."
    exit 1
fi

exit 0
