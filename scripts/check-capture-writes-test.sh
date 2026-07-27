#!/usr/bin/env bash
# Test suite for scripts/check-capture-writes.sh (session 9k-1, layer 3 of the
# rs-capture-guard defense).
#
# FROZEN INVOCATION CONTRACT for the gate script (see check-capture-writes.sh's
# own header for the full contract; summarized here for this suite's cases):
#
#   scripts/check-capture-writes.sh [ROOT]
#
#   Discovery glob: ROOT/crates/*/tests/corpus/*/capture_*.sh
#   A write (cp/mv/install/mkdir/rmdir/ln/truncate/tee/dd as the first word of
#   a command segment, or a `cat` segment with a bare `>`/`>>` redirect) is a
#   violation unless the segment's command word is `rs_checked` /
#   `rs_checked_write`, the line is a whole-line comment, the write sits
#   inside a here-doc BODY, or the line (or the line immediately above) carries
#   'capture-write-exempt: <reason>' with a non-empty reason.
#
#   EXIT CODES
#     0 - clean (N>0 scripts, 0 violations; or 0 expected and 0 found, which
#         prints an explicit "nothing to check" line, never an "OK" line)
#     1 - at least one bare-write violation
#     2 - tool error: ROOT missing, fewer capture scripts found than
#         EXPECTED_CAPTURE_SCRIPTS, or an unreadable capture script
#
# THE POSITIVE CONTROL (the point of this whole suite)
# An instrument that parsed nothing must not report clean. The
# "*_caught" cases below are that control: each seeds exactly the shape of
# violation the gate exists to catch (a bare cp, a bare mkdir, an unwrapped
# `cat >` redirect, a reasonless hatch) into an otherwise-minimal capture
# script and asserts the gate rejects it. If any of those went green, the
# gate would be decorative and every "*_accepted" case below would be
# meaningless verification-by-absence-of-signal.
#
# Run with no arguments; safe to run locally or in CI.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
GATE="${REPO_ROOT}/scripts/check-capture-writes.sh"

# The gate binary each case runs. A case that needs the gate's own constants
# changed points this at a `sed`ed COPY instead, so the shipped script never
# grows an environment switch that could lower its floor in production. Same
# positive-control idiom as scripts/rs-oracle-diff-test.sh.
#
# Most cases below (1-11, 13, 14, 15) are testing violation-detection or
# root-handling behaviour that has nothing to do with EXPECTED_CAPTURE_SCRIPTS
# - their synthetic fixture trees carry 0-2 capture scripts, a count that has
# no reason to track whatever the shipped constant happens to be on this
# branch. They run against GATE_FLOOR0 (set up below, floor forced to 0) so
# they exercise the SAME violation-scanning code path regardless of how many
# real capture_*.sh files this branch has merged. Only case12 (floor-unmet)
# needs a DIFFERENT floor, and only case16 (the real tree) must run the
# actual shipped, unmodified gate - both override GATE_UNDER_TEST locally.
GATE_UNDER_TEST="${GATE}"

TMPROOT="$(mktemp -d)"
trap 'rm -rf "${TMPROOT}"' EXIT

pass=0
fail=0
failures=()

note_pass() {
    pass=$((pass + 1))
    echo "PASS: $1"
}

note_fail() {
    fail=$((fail + 1))
    failures+=("$1")
    echo "FAIL: $1"
}

# write_capture_script CASE FILENAME - writes stdin to
# TMPROOT/CASE/crates/fake/tests/corpus/scenario/FILENAME, the exact shape the
# gate's discovery glob requires.
write_capture_script() {
    local case="$1" filename="$2"
    local dir="${TMPROOT}/${case}/crates/fake/tests/corpus/scenario"
    mkdir -p "${dir}"
    cat >"${dir}/${filename}"
}

# run_case NAME CASEDIR EXPECT_RC [ENV_ASSIGN...]
# Invokes the gate against TMPROOT/CASEDIR (or an absolute CASEDIR, used for
# the real-tree and missing-root cases), with any ENV_ASSIGN VAR=VAL pairs
# applied via `env`. Captures combined stdout+stderr; records pass/fail.
run_case() {
    local name="$1" casedir="$2" expect="$3"
    shift 3
    local root
    if [[ "${casedir}" == /* ]]; then
        root="${casedir}"
    else
        root="${TMPROOT}/${casedir}"
    fi
    local out="${TMPROOT}/${name}.out"
    local rc=0
    env "$@" "${GATE_UNDER_TEST}" "${root}" >"${out}" 2>&1 || rc=$?
    if [[ "${rc}" -eq "${expect}" ]]; then
        note_pass "${name} (exit ${rc})"
    else
        note_fail "${name}: expected exit ${expect}, got ${rc}"
        sed 's/^/    | /' "${out}" || true
    fi
}

assert_output_contains() {
    local name="$1" needle="$2" desc="$3"
    local out="${TMPROOT}/${name}.out"
    if grep -qF "${needle}" "${out}" 2>/dev/null; then
        note_pass "${name}: ${desc}"
    else
        note_fail "${name}: ${desc} (got: $(cat "${out}" 2>/dev/null || echo '<no output>'))"
    fi
}

# ---------------------------------------------------------------------------
# Violation-detection gate copy: floor forced to 0.
#
# Cases 1-11, 13, 14 and 15 test whether a bare write is caught, what the
# message says, and how a missing-root or dirty-sibling tree is handled -
# none of that is about EXPECTED_CAPTURE_SCRIPTS. Their fixtures carry 0-2
# capture scripts, which is unrelated to (and must not be made to track)
# whatever the shipped gate's floor is on this branch. They run against a
# COPY of the gate with the floor forced to 0, so a fixture with 1 or 2
# scripts always clears the floor check and reaches the actual scan.
#
# Same `cmp -s` guard idiom as case12 below: if EXPECTED_CAPTURE_SCRIPTS is
# ever renamed or reformatted, the substitution silently edits nothing, and
# GATE_UNDER_TEST is deliberately left pointed at the real, unmodified
# ${GATE} in that event - so every case below fails LOUDLY (rc mismatches
# against the shipped floor) instead of quietly validating nothing.
# ---------------------------------------------------------------------------
GATE_FLOOR0="${TMPROOT}/check-capture-writes-floor0.sh"
sed -E 's/^readonly EXPECTED_CAPTURE_SCRIPTS=[0-9]+$/readonly EXPECTED_CAPTURE_SCRIPTS=0/' \
    "${GATE}" >"${GATE_FLOOR0}"
chmod +x "${GATE_FLOOR0}"
if cmp -s "${GATE}" "${GATE_FLOOR0}"; then
    note_fail "gate_floor0_setup: the floor substitution edited nothing; EXPECTED_CAPTURE_SCRIPTS was renamed or reformatted, so cases 1-11/13/14/15 will run against the unmodified (real-floor) gate and fail loudly on their own rc checks"
else
    GATE_UNDER_TEST="${GATE_FLOOR0}"
fi

# ---------------------------------------------------------------------------
# Case: a bare `cp` is caught.
# ---------------------------------------------------------------------------
write_capture_script case1 capture_thing.sh <<'EOF'
#!/usr/bin/env bash
set -uo pipefail
cp "$src" "$dst"
EOF
run_case "case1_bare_cp_caught" case1 1
assert_output_contains "case1_bare_cp_caught" "cp \"\$src\" \"\$dst\"" \
    "message quotes the violating command"
assert_output_contains "case1_bare_cp_caught" "capture_thing.sh:3:" \
    "message names the file and line"

# ---------------------------------------------------------------------------
# Case: a bare `mkdir` is caught.
# ---------------------------------------------------------------------------
write_capture_script case2 capture_thing.sh <<'EOF'
#!/usr/bin/env bash
mkdir -p "$dir"
EOF
run_case "case2_bare_mkdir_caught" case2 1
assert_output_contains "case2_bare_mkdir_caught" "mkdir -p \"\$dir\"" \
    "message quotes the violating command"

# ---------------------------------------------------------------------------
# Case: a bare `cat > file` redirect is caught (rs_checked cannot wrap this
# shape at all - the redirect binds to the shell, not to rs_checked - so the
# only correct fix is rs_checked_write; see rs-capture-guard.sh's own note).
# ---------------------------------------------------------------------------
write_capture_script case3 capture_thing.sh <<'EOF'
#!/usr/bin/env bash
cat <<'REMOTE' > "${payload}/run.sh"
echo hi
REMOTE
EOF
run_case "case3_bare_cat_redirect_caught" case3 1

# ---------------------------------------------------------------------------
# Case: `rs_checked cp ...` is accepted - the write command is an ARGUMENT to
# rs_checked, never the first word of its own command segment.
# ---------------------------------------------------------------------------
write_capture_script case4 capture_thing.sh <<'EOF'
#!/usr/bin/env bash
. "${REPO_ROOT}/scripts/rs-capture-guard.sh"
rs_capture_guard_init "capture_test"
rs_checked cp "$src" "$dst"
EOF
run_case "case4_rs_checked_cp_accepted" case4 0

# ---------------------------------------------------------------------------
# Case: piping into `rs_checked_write` is accepted - this is the ONLY correct
# way to check a `cat`-into-file write, since `rs_checked cat > f` cannot work.
# ---------------------------------------------------------------------------
write_capture_script case5 capture_thing.sh <<'EOF'
#!/usr/bin/env bash
. "${REPO_ROOT}/scripts/rs-capture-guard.sh"
rs_capture_guard_init "capture_test"
printf 'hello' | rs_checked_write "$dst"
EOF
run_case "case5_rs_checked_write_accepted" case5 0

# ---------------------------------------------------------------------------
# Case: a commented-out `cp` is accepted - a whole-line comment is never
# scanned, matching check-dac-guard.sh / check-no-mnt-paths.sh's convention.
# ---------------------------------------------------------------------------
write_capture_script case6 capture_thing.sh <<'EOF'
#!/usr/bin/env bash
# cp "$src" "$dst"   -- old approach, no longer used
echo ok
EOF
run_case "case6_commented_cp_accepted" case6 0

# ---------------------------------------------------------------------------
# Case: a `cp` (and a `mkdir`) inside a here-doc BODY are accepted - that text
# is payload for the CONTAINER to execute, not shell code this script runs
# itself. The here-doc START line legitimately pipes into rs_checked_write
# rather than using a bare `>` redirect, so it is clean too.
# ---------------------------------------------------------------------------
write_capture_script case7 capture_thing.sh <<'EOF'
#!/usr/bin/env bash
. "${REPO_ROOT}/scripts/rs-capture-guard.sh"
rs_capture_guard_init "capture_test"
cat <<'REMOTE' | rs_checked_write "${payload}/run.sh"
#!/bin/bash
cp /src /dst
mkdir -p /somewhere
REMOTE
EOF
run_case "case7_heredoc_body_accepted" case7 0

# ---------------------------------------------------------------------------
# Case: a `cp` mentioned inside a quoted diagnostic string is accepted - it is
# an ARGUMENT to rs_capture_die, never the first word of a command segment.
# No quote-parsing is needed for this: it falls out of only checking a
# segment's first word.
# ---------------------------------------------------------------------------
write_capture_script case8 capture_thing.sh <<'EOF'
#!/usr/bin/env bash
. "${REPO_ROOT}/scripts/rs-capture-guard.sh"
rs_capture_guard_init "capture_test"
rs_capture_die "could not cp the payload into place"
EOF
run_case "case8_quoted_diagnostic_accepted" case8 0

# ---------------------------------------------------------------------------
# Case: the capture-write-exempt: hatch on the SAME line is accepted.
# ---------------------------------------------------------------------------
write_capture_script case9 capture_thing.sh <<'EOF'
#!/usr/bin/env bash
cp "$scratch_src" "$scratch_dst"  # capture-write-exempt: scratch copy, checked by rc on the next line
[ -f "$scratch_dst" ] || exit 2
EOF
run_case "case9_exempt_same_line_accepted" case9 0

# ---------------------------------------------------------------------------
# Case: the capture-write-exempt: hatch on the line IMMEDIATELY ABOVE is also
# accepted, per the same-line-or-line-above contract.
# ---------------------------------------------------------------------------
write_capture_script case10 capture_thing.sh <<'EOF'
#!/usr/bin/env bash
# capture-write-exempt: scratch copy, checked by rc on the next line
cp "$scratch_src" "$scratch_dst"
EOF
run_case "case10_exempt_line_above_accepted" case10 0

# ---------------------------------------------------------------------------
# Case (THE HATCH-WITHOUT-A-REASON POSITIVE CONTROL): the bare
# 'capture-write-exempt:' token with no stated reason does NOT exempt
# anything. A hatch with no reason is indistinguishable from someone pasting
# the token just to silence the gate.
# ---------------------------------------------------------------------------
write_capture_script case11 capture_thing.sh <<'EOF'
#!/usr/bin/env bash
cp "$src" "$dst"  # capture-write-exempt:
EOF
run_case "case11_hatch_without_reason_rejected" case11 1
assert_output_contains "case11_hatch_without_reason_rejected" "NO stated reason" \
    "message explains the hatch needs a reason"

# ---------------------------------------------------------------------------
# Case (THE ANTI-VACUITY CASE): EXPECTED_CAPTURE_SCRIPTS unmet -> exit 2, not
# a pass.
#
# This fixture provides 0 capture scripts, so any floor forced strictly above
# 0 makes the floor unmet - the exact value (2) is arbitrary, chosen only to
# be visibly different from both 0 and the shipped constant. Exercised
# against a `sed`ed COPY of the gate rather than an environment override, so
# the shipped script carries no switch that could lower its floor outside
# this suite. The `cmp` check is what keeps this honest: if
# EXPECTED_CAPTURE_SCRIPTS is ever renamed or reformatted, the substitution
# silently edits nothing, and this case would then run the UNMODIFIED gate -
# whose real floor might still coincidentally exceed this fixture's 0
# scripts and report "unmet" for the wrong reason, masking the fact that the
# intended substitution never took effect. The `cmp -s` comparison, not this
# case's exit code, is what surfaces that.
# ---------------------------------------------------------------------------
mkdir -p "${TMPROOT}/case12/crates/fake/tests/corpus/scenario"
GATE_FLOOR2="${TMPROOT}/check-capture-writes-floor2.sh"
sed -E 's/^readonly EXPECTED_CAPTURE_SCRIPTS=[0-9]+$/readonly EXPECTED_CAPTURE_SCRIPTS=2/' \
    "${GATE}" >"${GATE_FLOOR2}"
chmod +x "${GATE_FLOOR2}"
if cmp -s "${GATE}" "${GATE_FLOOR2}"; then
    note_fail "case12_expected_floor_unmet: the floor substitution edited nothing; EXPECTED_CAPTURE_SCRIPTS was renamed or reformatted, so this case would test an unmodified gate"
else
    GATE_UNDER_TEST="${GATE_FLOOR2}"
    run_case "case12_expected_floor_unmet" case12 2
    assert_output_contains "case12_expected_floor_unmet" "expected at least" \
        "message states the unmet floor"
    GATE_UNDER_TEST="${GATE_FLOOR0}"
fi

# ---------------------------------------------------------------------------
# Case: zero capture scripts found, with the floor forced to 0 (GATE_FLOOR0,
# same copy cases 1-11 use), is clean but must say "nothing to check" - never
# an "OK, all clean" line that could be confused with a real, positive scan.
# This is no longer the SHIPPED floor (that floor is whatever
# EXPECTED_CAPTURE_SCRIPTS currently is on this branch - see case16 for the
# case that pins the shipped value against the real repo); this case is
# purely about the "0 expected, 0 found" message wording, which is exercised
# the same way regardless of what the shipped constant says.
# ---------------------------------------------------------------------------
mkdir -p "${TMPROOT}/case13/crates/fake/tests/corpus/scenario"
run_case "case13_zero_expected_zero_found" case13 0
assert_output_contains "case13_zero_expected_zero_found" "nothing to check" \
    "success line is explicit about having scanned nothing"

# ---------------------------------------------------------------------------
# Case: a ROOT that does not exist is a tool error, not a pass.
# ---------------------------------------------------------------------------
run_case "case14_missing_root" "${TMPROOT}/case14-does-not-exist" 2

# ---------------------------------------------------------------------------
# Case: a directory holding MULTIPLE capture scripts, one clean and one
# dirty, is flagged overall - a violation in one script must not be hidden by
# a clean sibling.
# ---------------------------------------------------------------------------
write_capture_script case15 capture_clean.sh <<'EOF'
#!/usr/bin/env bash
. "${REPO_ROOT}/scripts/rs-capture-guard.sh"
rs_checked cp "$a" "$b"
EOF
write_capture_script case15 capture_dirty.sh <<'EOF'
#!/usr/bin/env bash
mv "$a" "$b"
EOF
run_case "case15_one_dirty_sibling_fails_the_scan" case15 1
assert_output_contains "case15_one_dirty_sibling_fails_the_scan" "capture_dirty.sh" \
    "message names the specific dirty file"

# ---------------------------------------------------------------------------
# Case: THE REAL TREE, with no ROOT argument and the REAL, unmodified shipped
# gate (never GATE_UNDER_TEST), must be clean AND must report scanning
# exactly EXPECTED_CAPTURE_SCRIPTS scripts. This is the case whose absence
# let the floor raise from 0 to 3 go unnoticed by this suite until `just ci`
# actually ran the real gate against the real tree - every other case here
# runs against a synthetic fixture, so none of them would have caught a
# lane's capture_*.sh silently vanishing from the real repository. An
# rc-only check would not catch that either: if EXPECTED_CAPTURE_SCRIPTS were
# ever accidentally lowered while a script actually vanished, rc could still
# come back 0. So the expected count is read directly out of the constant
# (never hardcoded a second time here) and asserted against the message,
# meaning the two literally cannot drift apart from each other.
# ---------------------------------------------------------------------------
shipped_floor="$(grep -oE '^readonly EXPECTED_CAPTURE_SCRIPTS=[0-9]+' "${GATE}" | grep -oE '[0-9]+$')"
if [[ -z "${shipped_floor}" ]]; then
    note_fail "case16_real_tree: could not read EXPECTED_CAPTURE_SCRIPTS out of ${GATE} - the constant declaration was not found in the expected 'readonly EXPECTED_CAPTURE_SCRIPTS=<N>' shape"
else
    real_tree_out="${TMPROOT}/case16_real_tree.out"
    real_tree_rc=0
    (cd "${REPO_ROOT}" && bash "${GATE}") >"${real_tree_out}" 2>&1 || real_tree_rc=$?
    if [[ "${real_tree_rc}" -eq 0 ]]; then
        note_pass "case16_real_tree (exit 0)"
    else
        note_fail "case16_real_tree: expected exit 0, got ${real_tree_rc}"
        sed 's/^/    | /' "${real_tree_out}" || true
    fi
    if grep -qF "${shipped_floor} capture script(s) scanned" "${real_tree_out}" 2>/dev/null; then
        note_pass "case16_real_tree: message reports scanning exactly the shipped floor (${shipped_floor}) capture script(s)"
    else
        note_fail "case16_real_tree: message does not report scanning exactly ${shipped_floor} capture script(s) (got: $(cat "${real_tree_out}" 2>/dev/null || echo '<no output>'))"
    fi
fi

echo ""
echo "----------------------------------------"
total=$((pass + fail))
echo "${pass}/${total} passed"
if [[ "${fail}" -gt 0 ]]; then
    echo ""
    echo "Failures:"
    for f in "${failures[@]}"; do
        echo "  - ${f}"
    done
    exit 1
fi

exit 0
