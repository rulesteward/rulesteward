#!/usr/bin/env bash
# scripts/rs-oracle-required.sh - the fail-closed "is this oracle required?"
# predicate shared by every `just diff-<lane>` recipe (session 9k-1).
#
# INVOCATION CONTRACT (frozen by scripts/rs-oracle-required-test.sh):
#
#   scripts/rs-oracle-required.sh <ORACLE>
#
#   Exit 0 - the oracle IS required (a recipe must promote its rc 3 to rc 2)
#   Exit 1 - the oracle is NOT required (a recipe may honestly skip with rc 3)
#   Exit 2 - usage error (missing, empty, extra, or malformed ORACLE argument)
#
#   0-means-required is deliberate: the caller asks "should I promote my skip?",
#   and `if bash scripts/rs-oracle-required.sh AUDITCTL; then exit 2; fi` reads
#   correctly under shell truthiness.
#
# WHY THIS IS A SHARED SCRIPT AND NOT THREE COPIES
# CONTRIBUTING.md's oracle contract gives rc 3 the meaning "precondition unmet,
# a legitimate skip". rc 3 is only safe because CI can promote it to a hard
# failure wherever the oracle really is installed, and that promotion is driven
# entirely by this parse. Parse it fail-OPEN and CI silently returns to
# skipping, which is the #572 failure the whole program exists to eliminate.
# The failure mode is SILENT, so triplicating the logic is how it recurs.
#
# FAIL-CLOSED, NOT FAIL-OPEN
# Any non-empty value that is not an explicit off-switch means REQUIRED.
# Comparing against the literal "1" is fail-OPEN and has already been written
# and caught once in this program: a later session writing `RS_REQUIRE_X: true`
# in YAML (unquoted, so it arrives as the string `true`) would silently get a
# fully green run in which nothing ran. Ambiguous means required.
#
# This mirrors `requirement_declared` in
# crates/rulesteward-selinux/tests/te_emit_checkmodule.rs, which is the shipped
# Rust half of the same predicate. Keep the two off-switch lists identical.

set -uo pipefail

readonly USAGE="usage: rs-oracle-required.sh <ORACLE>   (ORACLE matches ^[A-Z][A-Z0-9_]*$, e.g. AUDITCTL, VISUDO, SYSTEMD_SYSCTL)"

if [[ "$#" -ne 1 ]]; then
    echo "rs-oracle-required: expected exactly 1 argument, got $#" >&2
    echo "${USAGE}" >&2
    exit 2
fi

oracle="$1"

# A lowercase or hyphenated argument is a USAGE ERROR rather than being silently
# upcased or normalized. A typo that never matches any variable would otherwise
# read as "not required" forever, which is fail-open by another route: the
# recipe would skip cleanly in CI and nobody would ever see it.
if [[ ! "${oracle}" =~ ^[A-Z][A-Z0-9_]*$ ]]; then
    echo "rs-oracle-required: malformed ORACLE argument '${oracle}'" >&2
    echo "${USAGE}" >&2
    exit 2
fi

# Does this raw value declare the oracle required?
#
# Off-switches, case-insensitive after trimming surrounding whitespace:
#   unset, "", whitespace-only, "0", "false", "no", "off"
# Everything else non-empty is REQUIRED.
requirement_declared() {
    local raw="${1-}"
    # Trim leading and trailing whitespace. A value of "   " must read as unset,
    # not as the truthy string "   " - `VAR="$SOMETHING_UNSET "` is a realistic
    # way to produce it in a shell recipe.
    local value="${raw#"${raw%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"

    [[ -z "${value}" ]] && return 1

    local lowered="${value,,}"
    case "${lowered}" in
    0 | false | no | off) return 1 ;;
    *) return 0 ;;
    esac
}

# OR-combine the program-wide switch with the per-harness one. OR is the
# fail-closed reading and needs no precedence rule: to exempt one lane in a CI
# job, set only the per-lane variables in that job rather than the global one.
global_raw="${RS_ORACLE_REQUIRED-}"
per_lane_var="RS_REQUIRE_${oracle}"
per_lane_raw="${!per_lane_var-}"

if requirement_declared "${global_raw}"; then
    exit 0
fi

if requirement_declared "${per_lane_raw}"; then
    exit 0
fi

exit 1
