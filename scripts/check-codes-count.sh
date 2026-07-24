#!/usr/bin/env bash
# scripts/check-codes-count.sh - CI gate STUB (#586, RuleSteward session 9j lane 4)
#
# NOT YET IMPLEMENTED.
#
# This is a placeholder left by the 9j lane-4 TEST-AUTHOR so that
# scripts/check-codes-count-test.sh (the RED test suite that specifies this
# gate's frozen invocation contract - read the header comment there first)
# has a real, invocable script to exercise. The 9j lane-4 IMPLEMENTER
# replaces this file's body with the actual extraction/comparison logic
# described in that contract, and wires the `codes-guard` recipe into the
# justfile `ci:` dependency line in the SAME commit (the recipe itself was
# already declared in Phase 0; see the "(#586)" comment above it in
# justfile).
#
# Until replaced, this stub always fails loudly on stderr with a
# NOT IMPLEMENTED marker, so it can never be mistaken for a working gate
# that happens to report a clean tree - a silent/accidental "pass" here
# would be exactly the vacuous-pass failure mode this session guards
# against everywhere else.

set -euo pipefail

echo "check-codes-count.sh: NOT IMPLEMENTED - see the frozen contract in" \
    "scripts/check-codes-count-test.sh (#586)" >&2
exit 1
