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

# The gate binary each case runs. Normally the real one; a case that needs the
# gate's own constants changed points this at a `sed`ed COPY instead, so the
# shipped script never grows an environment switch that could lower its floor
# in production. Same positive-control idiom as scripts/rs-oracle-diff-test.sh.
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
# Exercised against a `sed`ed COPY of the gate rather than an environment
# override, so the shipped script carries no switch that could lower its floor
# outside this suite. The `cmp` check is what keeps this honest: if the
# constant is ever renamed or reformatted the substitution silently matches
# nothing, and this case would then be running an UNMODIFIED gate whose floor
# of 0 is trivially met - a green case testing the opposite of what it claims.
# ---------------------------------------------------------------------------
mkdir -p "${TMPROOT}/case12/crates/fake/tests/corpus/scenario"
GATE_FLOOR2="${TMPROOT}/check-capture-writes-floor2.sh"
sed 's/^readonly EXPECTED_CAPTURE_SCRIPTS=0$/readonly EXPECTED_CAPTURE_SCRIPTS=2/' \
    "${GATE}" >"${GATE_FLOOR2}"
chmod +x "${GATE_FLOOR2}"
if cmp -s "${GATE}" "${GATE_FLOOR2}"; then
    note_fail "case12_expected_floor_unmet: the floor substitution edited nothing; EXPECTED_CAPTURE_SCRIPTS was renamed or reformatted, so this case would test an unmodified gate"
else
    GATE_UNDER_TEST="${GATE_FLOOR2}"
    run_case "case12_expected_floor_unmet" case12 2
    assert_output_contains "case12_expected_floor_unmet" "expected at least" \
        "message states the unmet floor"
    GATE_UNDER_TEST="${GATE}"
fi

# ---------------------------------------------------------------------------
# Case: zero capture scripts found, with the SHIPPED (unoverridden) floor of
# 0, is clean but must say "nothing to check" - never an "OK, all clean" line
# that could be confused with a real, positive scan.
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
# Case: THE REAL TREE, with no ROOT argument, must be clean. On this branch
# today that means 0 capture scripts (the auditd/sysctld/sudoers lanes have
# not merged their capture_*.sh files yet), so this doubles as this suite's
# own dogfood confirmation that "0 expected, 0 found" is really what ships.
# ---------------------------------------------------------------------------
real_tree_out="${TMPROOT}/case16_real_tree.out"
real_tree_rc=0
(cd "${REPO_ROOT}" && bash "${GATE}") >"${real_tree_out}" 2>&1 || real_tree_rc=$?
if [[ "${real_tree_rc}" -eq 0 ]]; then
    note_pass "case16_real_tree (exit 0)"
else
    note_fail "case16_real_tree: expected exit 0, got ${real_tree_rc}"
    sed 's/^/    | /' "${real_tree_out}" || true
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
