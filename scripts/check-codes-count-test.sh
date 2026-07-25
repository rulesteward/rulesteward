#!/usr/bin/env bash
# RED test suite for scripts/check-codes-count.sh (#586).
#
# FROZEN INVOCATION CONTRACT for the gate script (the implementer inherits
# this; it is authored here, before the real implementation exists, in the
# same test-first spirit as scripts/check-dac-guard-test.sh for #467).
# Strengthened after adversarial-test review (9j lane 4, round 2): the
# review built four fake guards that each passed the original harness
# 10/10 while doing the wrong thing, and showed a CORRECT implementation
# would fail 4 of the original frozen assertions. Every "STRENGTHENED"
# marker below is a direct response to that review; nothing here weakens
# a prior assertion.
#
#   scripts/check-codes-count.sh [REPO_ROOT]
#
#   - With no argument: REPO_ROOT defaults to the caller's current working
#     directory (the gate is always invoked from the repo root, by `just`
#     and by CI, so this resolves to the real repo tree in normal use).
#   - With one argument: REPO_ROOT is that directory instead.
#
#   Scanned files (relative to REPO_ROOT), exactly two, IF PRESENT:
#     - README.md
#     - crates/rulesteward-cli/src/cli/mod.rs
#   A scanned file that does not exist under REPO_ROOT contributes zero
#   mentions and is NOT itself an error (keeps the contract testable
#   against minimal synthetic fixtures that only need a README.md).
#   STRENGTHENED: case_cli_mod_rs_scanned_independently below proves
#   cli/mod.rs is actually opened and checked on its own (a fixture with
#   ONLY a wrong mention in cli/mod.rs, no README.md at all, must still
#   fail) - the original harness never exercised this file at all, so a
#   `FILES=("README.md")` fake passed it 10/10.
#
#   OUT OF SCOPE (verified, deliberately NOT scanned), and NOW ENFORCED
#   BY A TEST (case_exclusions_are_honored), not just documented:
#     - CHANGELOG.md - release notes are point-in-time historical claims
#       ("sudoers shipped with 8 `sudo-` codes in 0.3.0"), correct for the
#       release they describe even after the catalog has since grown.
#       Scanning it would flag every past release note as a permanent,
#       unfixable violation.
#     - Any `.rs` file OTHER than crates/rulesteward-cli/src/cli/mod.rs
#       (e.g. crates/rulesteward-cli/tests/cli_help.rs's comment recalling
#       the #414 drift bug, "still claimed \"All 12 sshd- codes\"") - not
#       one of the two scanned files, so out of scope regardless of
#       comment style. That file's own live assertion
#       (`.stdout(predicate::str::contains("13 sshd-"))`) already checks
#       the current count independently of this gate.
#   Both exclusions were confirmed correct by two independent reviews (test
#   authoring + adversarial review), not assumed.
#
#   Six backends, each with a code-prefix, a catalog source file (relative
#   to REPO_ROOT), and a display name used by mention shape (c) below:
#
#     prefix     catalog file                                          display name
#     ------     ------------                                          ------------
#     fapd-      crates/rulesteward-fapolicyd/src/lints/catalog.rs      fapolicyd
#     au-        crates/rulesteward-auditd/src/lints/catalog.rs         auditd
#     sshd-      crates/rulesteward-sshd/src/lints/catalog.rs           sshd_config
#     sudo-      crates/rulesteward-sudoers/src/lints/catalog.rs        sudoers
#     sysctld-   crates/rulesteward-sysctld/src/catalog.rs              sysctl.d
#     se-        crates/rulesteward-selinux/src/lints/catalog.rs        SELinux
#
#   KNOWN LIMITATION (flagged, not fixed here): this table is hardcoded,
#   so a 7th backend added by a future wave would be silently invisible to
#   this gate unless the table (and the gate) are updated - the same
#   "prose rots and nothing notices" failure class #586 exists to close.
#   Deriving the backend set from a glob (crates/rulesteward-*/src/**/
#   catalog.rs) would close this permanently but is a bigger contract
#   change than this lane's scope; case_all_six_prefixes_all_three_shapes
#   below is the mechanical floor - it proves all SIX current catalogs are
#   actually read and compared (not just a hardcoded subset), which is the
#   strongest guarantee available without that redesign.
#
#   A backend's CATALOG LENGTH is the count of OCCURRENCES (not lines) of the
#   literal substring `code: "<prefix>` in its catalog file: two entries
#   crammed onto one line count as 2, not 1. In practice this coincides with
#   a line count today (rustfmt's one-field-per-line struct-literal style
#   puts one entry per line), but the occurrence count is the frozen, correct
#   definition - see case_catalog_length_counts_occurrences_not_lines below,
#   which seeds two entries on one line and requires catalog length 2.
#
#   A "codes mention" is any of these three shapes, found anywhere in the
#   scanned files, tied to one of the six prefixes/display names (real
#   examples from the current README.md / cli/mod.rs, quoted verbatim):
#     (a) `<N> `<prefix>`? codes` (backtick-wrapping optional; <prefix>
#         already includes its own trailing dash, e.g. "fapd-") -
#         "28 `fapd-` codes", "9 au- codes", "All 13 `sshd-` codes are active"
#     (b) `` `<prefix>`, <N> codes) `` - the README heading form -
#         "### fapolicyd (`fapd-`, 28 codes)"
#     (c) `<N> <display-name> codes` - "28 fapolicyd codes"
#   Each mention's stated N must equal that backend's catalog length.
#   STRENGTHENED: case_all_six_prefixes_all_three_shapes exercises all SIX
#   prefixes and all THREE shapes as seeded VIOLATIONS in one fixture - the
#   original harness only ever exercised shape (b) with `sysctld-`, so a
#   `PREFIXES=(au- sudo- sysctld-)` or "heading-shape-only" fake passed it
#   10/10.
#
#   VIOLATION reporting: each unmatched mention is reported on one line as
#   exactly:
#       <file>:<line>: stated <N>, catalog length <M> for `<prefix>`
#   (again, <prefix> already includes its own trailing dash, so this reads
#   e.g. "... for `fapd-`", never "`fapd--`")
#   so an operator can find and fix it, and so a test can assert BOTH
#   numbers were actually computed rather than a bare file:line with no
#   evidence the comparison happened.
#
#   ANTI-VACUITY: a scan that finds ZERO "codes" mentions across both
#   files combined is ALSO a violation (exit non-zero) - a rewritten doc
#   set that silently drops every prose mention must not silently satisfy
#   this gate ("nothing fired" == "nothing ran"). On every invocation
#   (clean or not), the script's stdout MUST include a summary line of
#   the exact literal form:
#       scanned N "codes" mention(s)
#   (N = decimal count, "(s)" is a literal non-inflected suffix so the
#   string is grep-able regardless of N) so tooling (and this test
#   harness) can assert N mechanically rather than trusting a bare exit
#   code. STRENGTHENED: every assertion against this line now checks an
#   EXACT N (case2 = exactly 1, case3 = exactly 0,
#   case_multi_mention_exact_count = exactly 4) - the original harness
#   only ever asserted N > 0, so a fake that printed a hardcoded
#   "scanned 14" (or any other positive number) whenever it detected the
#   real tree passed 10/10 without reading a single catalog file.
#
#   UNRECOGNIZED-MENTION rule (#586 round-4 hardening): a line in a scanned
#   file that references one of the six backends (by prefix or display name,
#   word-bounded so e.g. "parse-error" cannot false-trigger `se-`) AND
#   contains the word "codes" (case-insensitive) AND a digit, but was not
#   claimed by any of shapes (a)/(b)/(c) for that backend, is ITSELF a
#   violation - reported as:
#       <file>:<line>: unrecognized "codes" mention for `<prefix>` (matches no known shape)
#   This is what catches coverage silently eroding one mention at a time: a
#   mention reworded into unrecognized prose no longer just vanishes from
#   `scanned` unnoticed. See case_unrecognized_mention_* below.
#
#   PER-BACKEND MENTION COUNTS: on every invocation, stdout also includes,
#   once per backend, a line of the exact literal form:
#       per-backend mentions: `<prefix>` = <N>
#   (N = this backend's share of the shape-based `scanned` total across both
#   files).
#
#   PER-BACKEND COVERAGE FLOOR (#586 round-5 hardening): the gate itself
#   enforces N >= 1 for every backend, but ONLY when all six catalog files
#   are present under REPO_ROOT (a full six-backend tree; a narrow synthetic
#   fixture staging a subset of catalogs is not asserting anything about the
#   backends it never staged). This closes the gap the UNRECOGNIZED-MENTION
#   rule cannot: a backend whose every mention is reworded into prose naming
#   it by NEITHER its prefix NOR its display name carries no signal for that
#   rule either, and previously eroded to zero mentions with no violation at
#   all - see case_per_backend_floor_all_mentions_reworded_away below, which
#   reproduces exactly this against the real repo tree. Reported as:
#       per-backend coverage floor violated: `<prefix>` has 0 live "codes" mention(s) across README.md and crates/rulesteward-cli/src/cli/mod.rs (expected >= 1)
#   (no `<file>:<line>:` prefix - syntactically distinct from a count
#   mismatch or an unrecognized-mention violation, both of which carry one).
#
#   EXIT CODE: 0 only when at least one mention was found AND every
#   mention's stated N equals its backend's catalog length AND no
#   unrecognized-mention violation was found AND (when all six catalogs are
#   present) no backend's live mention count is zero. 1 otherwise.
#
# This test script is self-contained: it builds synthetic README.md (+
# synthetic catalog) fixtures in a mktemp dir per case, invokes the real gate
# (scripts/check-codes-count.sh) against them, and asserts the exit code
# and, where relevant, that the output names the right file:line, reports
# both numbers, reports an exact scanned-mentions count, or (for the
# exclusion case) does NOT name an out-of-scope file.
#
# STRENGTHENED (real-tree handling, replacing the original
# case4_real_tree_catches_known_live_bugs): the plan assigns README.md
# exclusively to this lane and wires `codes-guard` into `just ci` in the
# SAME commit the implementer adds the real script, so the implementer
# MUST also fix README.md's three then-live mismatches (at authoring time:
# README.md:127 "9 au- codes" vs actual 11, README.md:139 "8 sudo- codes" vs
# actual 9, README.md:286 "(`sysctld-`, 4 codes)" vs actual 5 - all three
# have since been fixed and now read 11/9/5 respectively) or `just ci` goes
# red. A frozen test that requires those exact lines to remain
# BROKEN would force the implementer to edit a frozen test the moment they
# do their job correctly - there is no repo state where both `just ci` and
# that old assertion are green. Two durable replacements, neither of which
# hardcodes a live line number, a live "wrong" value, or a live mention
# count (all computed at test-run time from whatever the tree currently
# contains, so they hold before AND after this lane's own fix commit):
#   - case_real_catalogs_seeded_drift: copies the REAL README.md and all
#     six REAL catalog files into a scratch dir, then APPENDS one new,
#     deliberately-wrong mention (real fapd- catalog length + 1000, so it
#     is wrong regardless of any future catalog growth) - proves the gate
#     works at real-repo scale without depending on the live tree's
#     current bug/fixed state.
#   - case_real_tree_pristine_eventually_clean: runs the gate against the
#     REAL repo tree, unmodified, with no arguments (mirrors
#     check-dac-guard-test.sh:513-527's case7_real_tree exactly) and
#     asserts exit 0. This WAS RED at authoring time (the three live
#     mismatches above existed then) and turned GREEN in the same commit
#     that implemented the gate and fixed README.md - that was the correct,
#     durable, TDD-red-then-green state for a lane whose own job included
#     the fix; the tree is clean now, so this case is a durable regression
#     guard, not a still-open TODO.
#
# Run with no arguments; safe to run locally or in CI.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
GATE="${REPO_ROOT}/scripts/check-codes-count.sh"

TMPROOT="$(mktemp -d)"
trap 'rm -rf "${TMPROOT}"' EXIT

pass=0
fail=0
failures=()

note_fail() {
    fail=$((fail + 1))
    failures+=("$1")
    echo "FAIL: $1"
}

note_pass() {
    pass=$((pass + 1))
    echo "PASS: $1"
}

# run_case NAME DIR EXPECT_RC
# Invokes the gate against DIR, captures combined stdout+stderr to
# TMPROOT/NAME.out, and asserts the exit code equals EXPECT_RC. Returns 0
# always (failures are recorded, not raised) so the harness can run every
# case even if earlier ones fail.
run_case() {
    local name="$1" dir="$2" expect_rc="$3"
    local out="${TMPROOT}/${name}.out"
    local rc=0
    "${GATE}" "${dir}" >"${out}" 2>&1 || rc=$?
    if [[ "${rc}" -eq "${expect_rc}" ]]; then
        note_pass "${name} (exit ${rc})"
    else
        note_fail "${name}: expected exit ${expect_rc}, got ${rc}"
        sed 's/^/    | /' "${out}" || true
    fi
}

# assert_output_contains NAME PATTERN DESC
# Requires TMPROOT/NAME.out (already captured by run_case, or by a manual
# case) to contain the literal fixed-string PATTERN.
assert_output_contains() {
    local name="$1" pattern="$2" desc="$3"
    local out="${TMPROOT}/${name}.out"
    if grep -qF -- "${pattern}" "${out}" 2>/dev/null; then
        note_pass "${name}: ${desc}"
    else
        note_fail "${name}: ${desc} (pattern '${pattern}' not found; got: $(cat "${out}" 2>/dev/null || echo '<no output>'))"
    fi
}

# assert_output_not_contains NAME PATTERN DESC
# STRENGTHENED (Blocker 5): the exclusion-enforcement counterpart to
# assert_output_contains - requires TMPROOT/NAME.out to NOT contain PATTERN.
assert_output_not_contains() {
    local name="$1" pattern="$2" desc="$3"
    local out="${TMPROOT}/${name}.out"
    if grep -qF -- "${pattern}" "${out}" 2>/dev/null; then
        note_fail "${name}: ${desc} (pattern '${pattern}' WAS found, but must not be; got: $(cat "${out}" 2>/dev/null || echo '<no output>'))"
    else
        note_pass "${name}: ${desc}"
    fi
}

# assert_scanned_count_exact NAME EXPECTED
# STRENGTHENED (Blocker 3): replaces the original assert_scanned_count_positive
# (which only checked N > 0, so a hardcoded "scanned 14" fake passed it).
# Requires the "scanned N \"codes\" mention(s)" summary line to report
# EXACTLY EXPECTED.
assert_scanned_count_exact() {
    local name="$1" expected="$2"
    local out="${TMPROOT}/${name}.out"
    local pattern="scanned ${expected} \"codes\" mention(s)"
    if grep -qF -- "${pattern}" "${out}" 2>/dev/null; then
        note_pass "${name}: anti-vacuity - scanned exactly ${expected} mention(s)"
    else
        local got=""
        got="$(grep -oE 'scanned [0-9]+ "codes" mention' "${out}" 2>/dev/null | grep -oE '[0-9]+' | head -1 || true)"
        note_fail "${name}: anti-vacuity - expected 'scanned ${expected} \"codes\" mention(s)', got scanned-count='${got:-<none>}' (full output: $(cat "${out}" 2>/dev/null || echo '<no output>'))"
    fi
}

write_fixture() {
    local rel="$1"
    local path="${TMPROOT}/${rel}"
    mkdir -p "$(dirname "${path}")"
    cat >"${path}"
}

# catalog_length PREFIX FILE
# Mirrors the gate's own counting rule (grep -c 'code: "<prefix>' FILE),
# used here to compute REAL catalog lengths at test-run time so seeded
# fixtures stay correct even if a catalog grows later.
catalog_length() {
    local prefix="$1" file="$2"
    local n=""
    n="$(grep -c "code: \"${prefix}" "${file}" 2>/dev/null || true)"
    echo "${n:-0}"
}

# stage_real_catalogs DESTDIR
# Copies all six REAL catalog files (verbatim, unmodified) into DESTDIR,
# preserving their real relative paths, so a scratch fixture can resolve
# every backend a copied real README.md might mention.
stage_real_catalogs() {
    local dest="$1"
    local rel
    for rel in \
        "crates/rulesteward-fapolicyd/src/lints/catalog.rs" \
        "crates/rulesteward-auditd/src/lints/catalog.rs" \
        "crates/rulesteward-sshd/src/lints/catalog.rs" \
        "crates/rulesteward-sudoers/src/lints/catalog.rs" \
        "crates/rulesteward-sysctld/src/catalog.rs" \
        "crates/rulesteward-selinux/src/lints/catalog.rs"; do
        mkdir -p "${dest}/$(dirname "${rel}")"
        cp "${REPO_ROOT}/${rel}" "${dest}/${rel}"
    done
}

# ---------------------------------------------------------------------------
# Shared synthetic catalog: a 3-entry sysctld- catalog, reused by several
# cases below. It deliberately uses different numbers than the real repo's
# SYSCTLD_CODES (which has 5) so a synthetic-case failure can never be
# confused with a real repo bug.
# ---------------------------------------------------------------------------
synthetic_sysctld_catalog() {
    cat <<'EOF'
pub const SYSCTLD_CODES: &[LintCode] = &[
    LintCode {
        code: "sysctld-F01",
        severity: Severity::Fatal,
        description: "fixture: parse failure",
    },
    LintCode {
        code: "sysctld-W01",
        severity: Severity::Warning,
        description: "fixture: last-wins conflict",
    },
    LintCode {
        code: "sysctld-W02",
        severity: Severity::Warning,
        description: "fixture: baseline gap",
    },
];
EOF
}

# A 2-entry synthetic se- catalog, used only by case_multi_mention_exact_count.
synthetic_se_catalog() {
    cat <<'EOF'
pub const SE_CODES: &[LintCode] = &[
    LintCode {
        code: "se-W01",
        severity: Severity::Warning,
        description: "fixture: boot config drift",
    },
    LintCode {
        code: "se-W02",
        severity: Severity::Warning,
        description: "fixture: enforce mode",
    },
];
EOF
}

# A 9-entry synthetic sudo- catalog and a 13-entry synthetic sshd- catalog,
# used only by case_exclusions_are_honored. STRENGTHENED (round-3 BLOCKER):
# without these, the exclusion fixture's out-of-scope CHANGELOG.md/cli_help.rs
# mentions (which reference sudo-/sshd-) have no catalog to be evaluated
# against at all, so NO implementation - correct or over-scanning - can
# tell them apart; the assertions were vacuous. These lengths deliberately
# DIFFER from the stated values in those two out-of-scope mentions (9 != 8,
# 13 != 12), so an over-scanner that reads them WOULD find and report a
# mismatch, making the not-contains assertions meaningful.
synthetic_sudo_catalog() {
    cat <<'EOF'
pub const SUDO_CODES: &[LintCode] = &[
    LintCode {
        code: "sudo-F01",
        severity: Severity::Fatal,
        description: "fixture: parse failure",
    },
    LintCode {
        code: "sudo-F02",
        severity: Severity::Fatal,
        description: "fixture: visudo-rejected token",
    },
    LintCode {
        code: "sudo-E01",
        severity: Severity::Error,
        description: "fixture: undefined alias",
    },
    LintCode {
        code: "sudo-W01",
        severity: Severity::Warning,
        description: "fixture: passwordless run-anything",
    },
    LintCode {
        code: "sudo-W02",
        severity: Severity::Warning,
        description: "fixture: passwordless run-anything variant",
    },
    LintCode {
        code: "sudo-W03",
        severity: Severity::Warning,
        description: "fixture: dead alias",
    },
    LintCode {
        code: "sudo-W04",
        severity: Severity::Warning,
        description: "fixture: weakened Defaults",
    },
    LintCode {
        code: "sudo-W05",
        severity: Severity::Warning,
        description: "fixture: missing use_pty",
    },
    LintCode {
        code: "sudo-W06",
        severity: Severity::Warning,
        description: "fixture: missing timestamp_timeout",
    },
];
EOF
}

synthetic_sshd_catalog() {
    cat <<'EOF'
pub const SSHD_CODES: &[LintCode] = &[
    LintCode {
        code: "sshd-F01",
        severity: Severity::Fatal,
        description: "fixture: parse failure",
    },
    LintCode {
        code: "sshd-F02",
        severity: Severity::Fatal,
        description: "fixture: drop-in override of required global",
    },
    LintCode {
        code: "sshd-E01",
        severity: Severity::Error,
        description: "fixture: unknown directive",
    },
    LintCode {
        code: "sshd-E02",
        severity: Severity::Error,
        description: "fixture: duplicate global",
    },
    LintCode {
        code: "sshd-E03",
        severity: Severity::Error,
        description: "fixture: unresolved Include",
    },
    LintCode {
        code: "sshd-E04",
        severity: Severity::Error,
        description: "fixture: Match-illegal directive",
    },
    LintCode {
        code: "sshd-W01",
        severity: Severity::Warning,
        description: "fixture: STIG-required missing",
    },
    LintCode {
        code: "sshd-W02",
        severity: Severity::Warning,
        description: "fixture: weaker than baseline",
    },
    LintCode {
        code: "sshd-W03",
        severity: Severity::Warning,
        description: "fixture: weak algorithm",
    },
    LintCode {
        code: "sshd-W04",
        severity: Severity::Warning,
        description: "fixture: deprecated directive",
    },
    LintCode {
        code: "sshd-W05",
        severity: Severity::Warning,
        description: "fixture: permissive Match override",
    },
    LintCode {
        code: "sshd-W06",
        severity: Severity::Warning,
        description: "fixture: algorithm-prefix reintroduction",
    },
    LintCode {
        code: "sshd-W07",
        severity: Severity::Warning,
        description: "fixture: cross-Match first-value-wins shadow",
    },
];
EOF
}

# ---------------------------------------------------------------------------
# Case 1: a seeded WRONG count (heading shape (b), stated 5, actual 3) ->
# exit 1, naming the fixture README's file:line (line 5). STRENGTHENED
# (CONCERN): also asserts the violation message reports BOTH the stated
# and the actual catalog-length numbers, not just a bare file:line.
# ---------------------------------------------------------------------------
c1="case1_seeded_wrong_count"
synthetic_sysctld_catalog | write_fixture "${c1}/crates/rulesteward-sysctld/src/catalog.rs"
write_fixture "${c1}/README.md" <<'EOF'
# Fixture repo for scripts/check-codes-count-test.sh

Unrelated prose line.

### sysctl.d (`sysctld-`, 5 codes)

More prose describing the sysctld backend.
EOF

run_case "${c1}" "${TMPROOT}/${c1}" 1
assert_output_contains "${c1}" "README.md:5" \
    "names the fixture README's file:line for the seeded mismatch"
assert_output_contains "${c1}" "stated 5, catalog length 3 for \`sysctld-\`" \
    "message reports both the stated (5) and actual (3) numbers"

# ---------------------------------------------------------------------------
# Case 2: the SAME fixture with the CORRECT count (stated 3, actual 3) ->
# exit 0. STRENGTHENED (Blocker 3): the scanned-mentions count must be
# EXACTLY 1 (this fixture has exactly one mention), not merely > 0.
# ---------------------------------------------------------------------------
c2="case2_correct_count"
synthetic_sysctld_catalog | write_fixture "${c2}/crates/rulesteward-sysctld/src/catalog.rs"
write_fixture "${c2}/README.md" <<'EOF'
# Fixture repo for scripts/check-codes-count-test.sh

Unrelated prose line.

### sysctl.d (`sysctld-`, 3 codes)

More prose describing the sysctld backend.
EOF

run_case "${c2}" "${TMPROOT}/${c2}" 0
assert_scanned_count_exact "${c2}" 1

# ---------------------------------------------------------------------------
# Case 3: ANTI-VACUITY. A fixture repo whose README.md contains ZERO "N
# codes" mentions (plain prose only, no catalog needed since nothing refers
# to one) -> exit 1, NOT 0. STRENGTHENED (Blocker 6): also asserts the
# summary line reports EXACTLY "scanned 0" - the original case only checked
# the exit code, which the always-fail stub (or any guard failing for an
# unrelated reason) satisfies vacuously.
# ---------------------------------------------------------------------------
c3="case3_zero_mentions_is_a_failure"
write_fixture "${c3}/README.md" <<'EOF'
# Fixture repo with no codes mentions at all

This README intentionally says nothing about lint code counts.
EOF

run_case "${c3}" "${TMPROOT}/${c3}" 1
assert_output_contains "${c3}" 'scanned 0 "codes" mention(s)' \
    "the summary line correctly reports zero mentions scanned (anti-vacuity)"

# ---------------------------------------------------------------------------
# Case: cli/mod.rs is scanned INDEPENDENTLY of README.md. STRENGTHENED
# (Blocker 2): the original harness never put a mention in cli/mod.rs at
# all, so a `FILES=("README.md")` fake (a real implementation with exactly
# one line wrong) passed it 10/10. This fixture has NO README.md at all -
# only a synthetic clap doc-comment file with a wrong mention - and must
# still be caught.
# ---------------------------------------------------------------------------
c_cli="case_cli_mod_rs_scanned_independently"
synthetic_sysctld_catalog | write_fixture "${c_cli}/crates/rulesteward-sysctld/src/catalog.rs"
write_fixture "${c_cli}/crates/rulesteward-cli/src/cli/mod.rs" <<'EOF'
// Fixture clap doc-comment file for scripts/check-codes-count-test.sh

/// All 5 sysctld- codes are active.
pub struct Fixture;
EOF

run_case "${c_cli}" "${TMPROOT}/${c_cli}" 1
assert_output_contains "${c_cli}" "crates/rulesteward-cli/src/cli/mod.rs:3" \
    "names the fixture cli/mod.rs file:line for the seeded mismatch (no README.md present at all)"
assert_output_contains "${c_cli}" "stated 5, catalog length 3 for \`sysctld-\`" \
    "message reports both numbers for the cli/mod.rs mention"

# ---------------------------------------------------------------------------
# Case: ALL SIX prefixes, ALL THREE mention shapes, each seeded WRONG.
# STRENGTHENED (Blocker 4): the original harness only ever exercised shape
# (b) with `sysctld-`, and case4 covered `au-`/`sudo-` only because those
# happened to be broken in the live tree right now. This fixture uses the
# REAL catalog files (so it also mechanically proves all six are actually
# read - the CONCERN 2 minimum bar) and computes each "wrong" value as
# (real length + 1), so it stays correct even if a catalog grows later.
# STRENGTHENED (round-3 CONCERN): the sysctld-/sshd- rows are swapped to
# shape (c)/(b) respectively (previously (b)/(c)) so shape (c) is exercised
# with `sysctl.d` - the ONE display name containing a regex metacharacter
# (the `.`). Unescaped, `sysctl.d` would also match `sysctlXd`; the live
# shape-(c) mention at README.md:352 is currently CORRECT, so the pristine
# real-tree case cannot detect that omission on its own - only a seeded
# fixture can.
#   fapd-     shape (a): "<N> `fapd-` codes"
#   au-       shape (b): "### auditd (`au-`, <N> codes)"
#   sshd-     shape (b): "### sshd_config (`sshd-`, <N> codes)"
#   sudo-     shape (a): "<N> sudo- codes"
#   sysctld-  shape (c): "<N> sysctl.d codes"
#   se-       shape (c): "<N> SELinux codes"
# Also STRENGTHENED (round-3 CONCERN): assertions now check the FULL
# canonical violation message (file:line + both numbers + prefix), not a
# bare file:line - an impl that names the right line for the WRONG prefix
# no longer passes.
# ---------------------------------------------------------------------------
c_matrix="case_all_six_prefixes_all_three_shapes"
matrix_dir="${TMPROOT}/${c_matrix}"
mkdir -p "${matrix_dir}"
stage_real_catalogs "${matrix_dir}"

m_real_fapd="$(catalog_length "fapd-" "${matrix_dir}/crates/rulesteward-fapolicyd/src/lints/catalog.rs")"
m_real_au="$(catalog_length "au-" "${matrix_dir}/crates/rulesteward-auditd/src/lints/catalog.rs")"
m_real_sshd="$(catalog_length "sshd-" "${matrix_dir}/crates/rulesteward-sshd/src/lints/catalog.rs")"
m_real_sudo="$(catalog_length "sudo-" "${matrix_dir}/crates/rulesteward-sudoers/src/lints/catalog.rs")"
m_real_sysctld="$(catalog_length "sysctld-" "${matrix_dir}/crates/rulesteward-sysctld/src/catalog.rs")"
m_real_se="$(catalog_length "se-" "${matrix_dir}/crates/rulesteward-selinux/src/lints/catalog.rs")"

m_wrong_fapd=$((m_real_fapd + 1))
m_wrong_au=$((m_real_au + 1))
m_wrong_sshd=$((m_real_sshd + 1))
m_wrong_sudo=$((m_real_sudo + 1))
m_wrong_sysctld=$((m_real_sysctld + 1))
m_wrong_se=$((m_real_se + 1))

write_fixture "${c_matrix}/README.md" <<EOF
# Fixture: full prefix x shape matrix

${m_wrong_fapd} \`fapd-\` codes

### auditd (\`au-\`, ${m_wrong_au} codes)

### sshd_config (\`sshd-\`, ${m_wrong_sshd} codes)

${m_wrong_sudo} sudo- codes

${m_wrong_sysctld} sysctl.d codes

${m_wrong_se} SELinux codes
EOF

run_case "${c_matrix}" "${matrix_dir}" 1
assert_output_contains "${c_matrix}" "README.md:3: stated ${m_wrong_fapd}, catalog length ${m_real_fapd} for \`fapd-\`" \
    "names the fapd- shape-(a) violation with both numbers (line 3)"
assert_output_contains "${c_matrix}" "README.md:5: stated ${m_wrong_au}, catalog length ${m_real_au} for \`au-\`" \
    "names the au- shape-(b) violation with both numbers (line 5)"
assert_output_contains "${c_matrix}" "README.md:7: stated ${m_wrong_sshd}, catalog length ${m_real_sshd} for \`sshd-\`" \
    "names the sshd- shape-(b) violation with both numbers (line 7)"
assert_output_contains "${c_matrix}" "README.md:9: stated ${m_wrong_sudo}, catalog length ${m_real_sudo} for \`sudo-\`" \
    "names the sudo- shape-(a) violation with both numbers (line 9)"
assert_output_contains "${c_matrix}" "README.md:11: stated ${m_wrong_sysctld}, catalog length ${m_real_sysctld} for \`sysctld-\`" \
    "names the sysctld- shape-(c) violation with both numbers (line 11, exercises the sysctl.d dot-metacharacter display name)"
assert_output_contains "${c_matrix}" "README.md:13: stated ${m_wrong_se}, catalog length ${m_real_se} for \`se-\`" \
    "names the se- shape-(c) violation with both numbers (line 13)"

# ---------------------------------------------------------------------------
# Case: exact scanned-mentions count on a MULTI-mention fixture (4 mentions,
# 2 backends, all correct). STRENGTHENED (Blocker 3, second requirement):
# case2 alone (1 mention) could not distinguish "always report 1" from
# "count correctly"; this fixture requires an exact count that is neither 0
# nor 1.
# ---------------------------------------------------------------------------
c_multi="case_multi_mention_exact_count"
synthetic_sysctld_catalog | write_fixture "${c_multi}/crates/rulesteward-sysctld/src/catalog.rs"
synthetic_se_catalog | write_fixture "${c_multi}/crates/rulesteward-selinux/src/lints/catalog.rs"
write_fixture "${c_multi}/README.md" <<'EOF'
# Fixture: multi-mention exact count

### sysctl.d (`sysctld-`, 3 codes)

3 sysctld- codes

### SELinux (`se-`, 2 codes)

2 se- codes
EOF

run_case "${c_multi}" "${TMPROOT}/${c_multi}" 0
assert_scanned_count_exact "${c_multi}" 4

# ---------------------------------------------------------------------------
# Case: documented exclusions are ENFORCED, not just documented.
# STRENGTHENED (Blocker 5): a CHANGELOG.md carrying a stale-but-historically
# -correct mention, and an out-of-scope .rs file (mirroring
# crates/rulesteward-cli/tests/cli_help.rs) carrying a `//` comment mention
# - both deliberately WRONG relative to what a naive broad scan would infer
# - must NOT be flagged, and the one real in-scope mention (correct) means
# the gate must exit 0.
#
# STRENGTHENED (round-3 BLOCKER): the fixture now ALSO ships a 9-entry
# synthetic sudo- catalog and a 13-entry synthetic sshd- catalog (the
# backends the two out-of-scope mentions reference), with lengths that
# DIFFER from those mentions' stated values (8 != 9, 12 != 13). Without
# these, an over-scanning implementation had nothing to compare the
# out-of-scope mentions against and could never flag them - the two
# assert_output_not_contains checks passed identically for a correct
# implementation AND an over-scanner, making them vacuous. Do NOT call
# stage_real_catalogs here: it would overwrite the synthetic 3-entry
# sysctld- catalog with the real 5-entry one and break the one in-scope
# mention's correctness.
# ---------------------------------------------------------------------------
c_excl="case_exclusions_are_honored"
synthetic_sysctld_catalog | write_fixture "${c_excl}/crates/rulesteward-sysctld/src/catalog.rs"
synthetic_sudo_catalog | write_fixture "${c_excl}/crates/rulesteward-sudoers/src/lints/catalog.rs"
synthetic_sshd_catalog | write_fixture "${c_excl}/crates/rulesteward-sshd/src/lints/catalog.rs"
write_fixture "${c_excl}/README.md" <<'EOF'
# Fixture repo proving exclusions are honored

### sysctl.d (`sysctld-`, 3 codes)

### sudoers (`sudo-`, 9 codes)

### sshd_config (`sshd-`, 13 codes)

All three in-scope mentions are correct. The `sudo-` and `sshd-` ones exist
only to satisfy the per-backend coverage floor: this fixture stages those two
catalogs as BAIT (so an over-scanner has something to compare the out-of-scope
CHANGELOG.md / cli_help.rs mentions against), and the floor applies to every
backend whose catalog is present. Their VALUES are what makes the bait work -
9 and 13 differ from the out-of-scope mentions' 8 and 12, so an over-scanner
still flags those and the two assertions below still discriminate.
EOF
write_fixture "${c_excl}/CHANGELOG.md" <<'EOF'
## [0.3.0]

- new sudoers backend (8 `sudo-` codes). Historical, correct for 0.3.0.
EOF
write_fixture "${c_excl}/crates/rulesteward-cli/tests/cli_help.rs" <<'EOF'
// #414: sshd-W07 was added after this help block was written, which still
// claimed "All 12 sshd- codes" and omitted W07 from the enumeration.
#[test]
fn sshd_lint_help_lists_all_codes_including_w07() {}
EOF

run_case "${c_excl}" "${TMPROOT}/${c_excl}" 0
assert_output_not_contains "${c_excl}" "CHANGELOG.md" \
    "does not flag the historical CHANGELOG.md mention (out of scope; its stated 8 differs from the fixture's 9-entry sudo- catalog, so an over-scanner WOULD flag it)"
assert_output_not_contains "${c_excl}" "cli_help.rs" \
    "does not flag the tests/cli_help.rs comment mention (out of scope, not one of the two scanned files; its stated 12 differs from the fixture's 13-entry sshd- catalog, so an over-scanner WOULD flag it)"

# ---------------------------------------------------------------------------
# Case: REAL catalogs (all six, copied verbatim) + the REAL README.md
# (copied verbatim) + one seeded, deliberately-wrong mention APPENDED to
# the copy. STRENGTHENED (Blocker 1, part A): proves the gate works at
# real-repo scale via a scratch COPY, without asserting anything about the
# live tree's current (soon to be fixed by this lane) bug state. The wrong
# value and the asserted line number are both computed at test-run time
# from whatever the real fapd- catalog/README currently contain, so this
# holds before and after this lane's own README.md fix commit.
# ---------------------------------------------------------------------------
c_seed="case_real_catalogs_seeded_drift"
seed_dir="${TMPROOT}/${c_seed}"
mkdir -p "${seed_dir}"
cp "${REPO_ROOT}/README.md" "${seed_dir}/README.md"
stage_real_catalogs "${seed_dir}"

seed_real_fapd="$(catalog_length "fapd-" "${seed_dir}/crates/rulesteward-fapolicyd/src/lints/catalog.rs")"
seed_wrong_fapd=$((seed_real_fapd + 1000))

{
    echo ""
    echo "### fapd-seeded-drift-probe (\`fapd-\`, ${seed_wrong_fapd} codes)"
} >>"${seed_dir}/README.md"

seed_line="$(grep -n 'fapd-seeded-drift-probe' "${seed_dir}/README.md" | head -1 | cut -d: -f1)"
# STRENGTHENED (round-3 CONCERN): guard against a latent self-satisfying
# path - if seed_line ever resolved empty (e.g. the `cp`/append above
# silently changed shape), an unguarded "README.md:${seed_line}" pattern
# would degrade to the substring "README.md:" and be satisfied by ANY
# violation line at all, not specifically the seeded one. Force a
# non-numeric sentinel (which can never appear in real gate output) so a
# resolution failure surfaces as an honest assertion failure instead.
if ! [[ "${seed_line}" =~ ^[0-9]+$ ]]; then
    note_fail "${c_seed}: could not resolve the seeded marker's line number in the copied README.md (got '${seed_line}')"
    seed_line="UNRESOLVED"
fi

run_case "${c_seed}" "${seed_dir}" 1
assert_output_contains "${c_seed}" "README.md:${seed_line}" \
    "names the seeded drift's file:line in a real-repo-scale copy"
assert_output_contains "${c_seed}" "stated ${seed_wrong_fapd}, catalog length ${seed_real_fapd} for \`fapd-\`" \
    "message reports both numbers for the seeded real-scale mismatch"

# ---------------------------------------------------------------------------
# ROUND-4 HARDENING (adversarial finding on #586): the anti-vacuity floor
# above is `scanned == 0`, so a mention rewritten into ANY phrasing outside
# the three precise shapes simply stops being scanned - `scanned` drops,
# `violation_count` stays 0, exit 0. Coverage erosion one mention at a time
# is silent. These cases freeze a new UNRECOGNIZED-MENTION rule: a line that
# references a known backend (by prefix or display name) and says "codes"
# (case-insensitive) and has a digit, but matches none of shapes (a)/(b)/(c),
# is ITSELF a violation.
#
# Each fixture below pairs the seeded bad line with one correct, in-scope
# sysctld- mention (the same synthetic 3-entry catalog used throughout this
# file) so exit 1 is unambiguously attributable to the seeded line, not to
# "no catalog to compare against" or an unrelated scanned-count mismatch.
# ---------------------------------------------------------------------------

# Case: `### auditd (au-, 99 codes)` - shape (b) hardcodes backticks around
# the prefix; shape (a) needs the number BEFORE the prefix. Neither matches
# this bare, reversed-relative-to-(a) heading, so a real 11-entry-vs-99 drift
# here would have been invisible before this rule.
c_unrec_au="case_unrecognized_mention_auditd_bare_prefix"
synthetic_sysctld_catalog | write_fixture "${c_unrec_au}/crates/rulesteward-sysctld/src/catalog.rs"
write_fixture "${c_unrec_au}/README.md" <<'EOF'
# Fixture: unrecognized-mention rule, bare-prefix heading (#586 round 4)

### auditd (au-, 99 codes)

### sysctl.d (`sysctld-`, 3 codes)
EOF

run_case "${c_unrec_au}" "${TMPROOT}/${c_unrec_au}" 1
assert_output_contains "${c_unrec_au}" "README.md:3: unrecognized \"codes\" mention for \`au-\`" \
    "flags the bare-prefix auditd heading as an unrecognized mention, naming its file:line and prefix"

# Case: `### sudoers (\`sudo-\` codes: 99)` - the REVERSED-ORDER variant: the
# number appears AFTER "codes" instead of before it, so none of shapes
# (a)/(b)/(c) (all of which require the number to precede "codes") match.
c_unrec_sudo="case_unrecognized_mention_sudoers_reversed_order"
synthetic_sysctld_catalog | write_fixture "${c_unrec_sudo}/crates/rulesteward-sysctld/src/catalog.rs"
write_fixture "${c_unrec_sudo}/README.md" <<'EOF'
# Fixture: unrecognized-mention rule, reversed-order heading (#586 round 4)

### sudoers (`sudo-` codes: 99)

### sysctl.d (`sysctld-`, 3 codes)
EOF

run_case "${c_unrec_sudo}" "${TMPROOT}/${c_unrec_sudo}" 1
assert_output_contains "${c_unrec_sudo}" "README.md:3: unrecognized \"codes\" mention for \`sudo-\`" \
    "flags the reversed-order sudoers heading as an unrecognized mention, naming its file:line and prefix"

# Case: `99 fapolicyd Codes today` - the CASE-VARIANT: shape (c)'s "codes" is
# a case-sensitive literal, so a capitalized "Codes" (a natural sentence-case
# rewrite) slips past it entirely today.
c_unrec_case="case_unrecognized_mention_fapolicyd_case_variant"
synthetic_sysctld_catalog | write_fixture "${c_unrec_case}/crates/rulesteward-sysctld/src/catalog.rs"
write_fixture "${c_unrec_case}/README.md" <<'EOF'
# Fixture: unrecognized-mention rule, case-variant "Codes" (#586 round 4)

99 fapolicyd Codes today

### sysctl.d (`sysctld-`, 3 codes)
EOF

run_case "${c_unrec_case}" "${TMPROOT}/${c_unrec_case}" 1
assert_output_contains "${c_unrec_case}" "README.md:3: unrecognized \"codes\" mention for \`fapd-\`" \
    "flags the case-variant ('Codes') fapolicyd mention as unrecognized, naming its file:line and prefix"

# ---------------------------------------------------------------------------
# ROUND-4 HARDENING, second finding: `catalog_length` must count OCCURRENCES
# of the literal substring `code: "<prefix>`, not LINES. A catalog with two
# entries crammed onto one line (needs `#[rustfmt::skip]` to survive
# `cargo fmt` in real code, hence synthetic-only here) must report catalog
# length 2, not 1. This fixture's README states "2 codes"; a line-counting
# implementation would compute catalog length 1 for this file (one matching
# LINE) and wrongly flag stated(2) != catlen(1) as a violation.
# ---------------------------------------------------------------------------
c_occ="case_catalog_length_counts_occurrences_not_lines"
write_fixture "${c_occ}/crates/rulesteward-sysctld/src/catalog.rs" <<'EOF'
pub const SYSCTLD_CODES: &[LintCode] = &[
    LintCode { code: "sysctld-F01", severity: Severity::Fatal, description: "a" }, LintCode { code: "sysctld-W01", severity: Severity::Warning, description: "b" },
];
EOF
write_fixture "${c_occ}/README.md" <<'EOF'
# Fixture: catalog_length counts occurrences, not lines (#586 round 4)

### sysctl.d (`sysctld-`, 2 codes)
EOF

run_case "${c_occ}" "${TMPROOT}/${c_occ}" 0
assert_scanned_count_exact "${c_occ}" 1

# ---------------------------------------------------------------------------
# Case: the REAL repo tree, invoked with NO arguments (default CWD), from
# the repo root, unmodified. STRENGTHENED (Blocker 1, part B; replaces the
# original case4's hardcoded-live-line assertions): mirrors
# check-dac-guard-test.sh's case7_real_tree exactly - durable, asserts only
# exit 0, no live content dependency. This WAS RED at authoring time
# (README.md:127/139/286 were still wrong) and turned GREEN in the same
# commit that implemented the gate and fixed README.md, per the plan; the
# tree is clean now, so this case is a durable regression guard against
# future drift, not a still-open TODO.
# ---------------------------------------------------------------------------
case_pristine_out="${TMPROOT}/case_real_tree_pristine.out"
case_pristine_rc=0
(cd "${REPO_ROOT}" && "${GATE}") >"${case_pristine_out}" 2>&1 || case_pristine_rc=$?
if [[ "${case_pristine_rc}" -eq 0 ]]; then
    note_pass "case_real_tree_pristine_eventually_clean (exit 0)"
else
    note_fail "case_real_tree_pristine_eventually_clean: expected exit 0 (README.md's drift was fixed in the same commit that implemented the gate), got ${case_pristine_rc}"
    sed 's/^/    | /' "${case_pristine_out}" || true
fi

# ---------------------------------------------------------------------------
# ROUND-4 HARDENING: a per-backend real-tree coverage floor. Reuses the
# output already captured above (the real tree, invoked with no arguments)
# rather than re-running the gate. For EACH of the six backends, the real
# tree must carry at least one live "codes" mention - this is the mechanical
# floor that kills every seeded row in the adversarial finding's table
# individually (each seeded scenario replaces ALL of one backend's mentions,
# dropping that backend's count to 0) WITHOUT hardcoding the current
# aggregate total (14) or any single backend's exact count, both of which
# drift as the docs legitimately grow.
#
# NOTE: this loop only asserts that the REAL tree, as it stands, already
# satisfies the floor - it does not prove the gate would REJECT a tree that
# didn't. That enforcement gap (found on NEEDS_REWORK review: the floor was
# printed but never asserted anywhere `just ci`/CI actually runs) is what
# round-5 below closes, inside the gate itself; see
# case_per_backend_floor_all_mentions_reworded_away.
# ---------------------------------------------------------------------------
for floor_prefix in fapd- au- sshd- sudo- sysctld- se-; do
    floor_n="$(grep -oE "per-backend mentions: \`${floor_prefix}\` = [0-9]+" "${case_pristine_out}" 2>/dev/null | grep -oE '[0-9]+$' | head -1 || true)"
    if [[ -n "${floor_n}" && "${floor_n}" -ge 1 ]]; then
        note_pass "real-tree per-backend floor: \`${floor_prefix}\` has ${floor_n} >= 1 live mention(s)"
    else
        note_fail "real-tree per-backend floor: \`${floor_prefix}\` has '${floor_n:-<none>}' live mention(s), expected >= 1"
    fi
done

# ---------------------------------------------------------------------------
# ROUND-5 HARDENING (adversarial finding on #586 NEEDS_REWORK review): the
# per-backend floor loop above only proves the REAL tree currently satisfies
# the floor - it never proves the GATE itself would reject a tree that
# didn't. The review demonstrated, live against this repo, that rewording
# all three real sshd- mentions into prose naming neither the `sshd-`
# prefix nor the `sshd_config` display name (invisible to the
# UNRECOGNIZED-MENTION rule too, since that rule keys off the same two
# signals) dropped `scanned` from 14 to 11, `per-backend mentions: `sshd-`
# = 0`, with exit STILL 0 - an entire backend's documentation silently
# erased behind a green gate. This case reproduces that exact scenario
# against a scratch copy of the real repo tree (all six real catalogs +
# real README.md + real cli/mod.rs) and requires the gate now exit 1,
# reporting the dedicated per-backend-floor message for `sshd-` - distinct
# from a count-mismatch or unrecognized-mention violation, so an operator
# can tell which failure class actually fired.
# ---------------------------------------------------------------------------
c_floor="case_per_backend_floor_all_mentions_reworded_away"
floor_dir="${TMPROOT}/${c_floor}"
mkdir -p "${floor_dir}/crates/rulesteward-cli/src/cli"
stage_real_catalogs "${floor_dir}"
cp "${REPO_ROOT}/README.md" "${floor_dir}/README.md"
cp "${REPO_ROOT}/crates/rulesteward-cli/src/cli/mod.rs" "${floor_dir}/crates/rulesteward-cli/src/cli/mod.rs"

floor_real_sshd="$(catalog_length "sshd-" "${floor_dir}/crates/rulesteward-sshd/src/lints/catalog.rs")"
floor_readme_pat1="All ${floor_real_sshd} \`sshd-\` codes"
floor_readme_pat2="### sshd_config (\`sshd-\`, ${floor_real_sshd} codes)"
floor_climod_pat="All ${floor_real_sshd} sshd- codes are active"

# Guard against a self-satisfying vacuous pass: confirm all three real live
# sshd- mentions are present, in the exact form this case rewords, BEFORE
# rewording - if the real README/cli-mod.rs wording ever drifts, this fails
# loudly instead of silently testing nothing.
if grep -qF "${floor_readme_pat1}" "${floor_dir}/README.md" \
    && grep -qF "${floor_readme_pat2}" "${floor_dir}/README.md" \
    && grep -qF "${floor_climod_pat}" "${floor_dir}/crates/rulesteward-cli/src/cli/mod.rs"; then
    note_pass "${c_floor}: all three real live sshd- mentions found in their expected form before rewording"
else
    note_fail "${c_floor}: expected sshd- mention text not found verbatim in the real tree (README.md/cli/mod.rs wording has drifted) - update this fixture's sed patterns"
fi

sed -i "s/${floor_readme_pat1}/the sshd backend ships ${floor_real_sshd} lint codes/" "${floor_dir}/README.md"
sed -i "s/${floor_readme_pat2}/### the sshd backend (${floor_real_sshd} lint codes total)/" "${floor_dir}/README.md"
sed -i "s/${floor_climod_pat}/All of the sshd backend lint codes (${floor_real_sshd}) are active/" "${floor_dir}/crates/rulesteward-cli/src/cli/mod.rs"

# Confirm the reword actually happened (no residual `sshd-`/`sshd_config`
# signal left on any of the three rewritten lines) before trusting the exit
# code below.
if grep -qF "${floor_readme_pat1}" "${floor_dir}/README.md" \
    || grep -qF "${floor_readme_pat2}" "${floor_dir}/README.md" \
    || grep -qF "${floor_climod_pat}" "${floor_dir}/crates/rulesteward-cli/src/cli/mod.rs"; then
    note_fail "${c_floor}: sed rewording of the sshd- mentions did not take effect"
else
    note_pass "${c_floor}: all three sshd- mentions successfully reworded to prose naming neither the prefix nor the display name"
fi

run_case "${c_floor}" "${floor_dir}" 1
assert_output_contains "${c_floor}" "per-backend coverage floor violated: \`sshd-\` has 0 live \"codes\" mention(s)" \
    "flags the per-backend floor violation once every sshd- mention is reworded away in both scanned files"
assert_output_contains "${c_floor}" "per-backend mentions: \`sshd-\` = 0" \
    "per-backend mentions line confirms sshd- dropped to exactly 0"
assert_output_not_contains "${c_floor}" "unrecognized \"codes\" mention for \`sshd-\`" \
    "the floor violation is NOT reported as an unrecognized-mention violation (the two failure classes stay distinguishable)"

# ---------------------------------------------------------------------------
# Case: the per-backend coverage floor STILL applies to the backends that ARE
# present when a DIFFERENT backend's catalog is absent. Regression pin for the
# session-9j senior integration review finding: an earlier revision gated the
# whole floor loop on a single repo-wide ALL_CATALOGS_PRESENT boolean, so ONE
# catalog going missing (a backend normalizing `src/lints/catalog.rs` to
# `src/catalog.rs` - the shape sysctld already uses - or simply being renamed)
# silently disarmed the floor for ALL SIX backends at once. A second backend's
# mentions could then be reworded away entirely with the gate still green.
#
# Fully synthetic on purpose: it asserts nothing about the real README's
# wording, so it cannot rot when that wording changes.
#
# Discriminating by construction - `sudo-`'s catalog is PRESENT with zero
# mentions (floor must fire) while `se-`'s catalog is ABSENT with zero
# mentions (floor must stay silent, since a missing catalog is deliberately
# not an error). The old global-flag implementation exits 0 here; the
# per-backend implementation exits 1 naming `sudo-` and only `sudo-`.
# ---------------------------------------------------------------------------
c_partial="case_per_backend_floor_survives_a_missing_sibling_catalog"
synthetic_sysctld_catalog | write_fixture "${c_partial}/crates/rulesteward-sysctld/src/catalog.rs"
synthetic_sudo_catalog | write_fixture "${c_partial}/crates/rulesteward-sudoers/src/lints/catalog.rs"
write_fixture "${c_partial}/README.md" <<'EOF'
# Fixture repo with one backend's catalog absent

### sysctl.d (`sysctld-`, 3 codes)

`sudo-`'s catalog is staged but has NO mention here - the floor must catch it.
`se-`'s catalog is not staged at all - the floor must stay silent about it.
EOF

run_case "${c_partial}" "${TMPROOT}/${c_partial}" 1
assert_output_contains "${c_partial}" "per-backend coverage floor violated: \`sudo-\` has 0 live \"codes\" mention(s)" \
    "the floor still fires for the PRESENT-catalog backend even though a sibling catalog is missing"
assert_output_not_contains "${c_partial}" "per-backend coverage floor violated: \`se-\`" \
    "the floor stays silent for the ABSENT-catalog backend (a missing catalog is not an error)"

echo ""
echo "----------------------------------------"
echo "${pass} passed, ${fail} failed"
if [[ "${fail}" -gt 0 ]]; then
    echo ""
    echo "Failures:"
    for f in "${failures[@]}"; do
        echo "  - ${f}"
    done
    exit 1
fi

exit 0
