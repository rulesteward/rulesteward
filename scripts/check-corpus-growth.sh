#!/usr/bin/env bash
# Gate: a branch that changes a crate's source must add evidence to THAT crate's
# committed corpus (#658, session-9o retrospective).
#
# WHY
# The Adversarial Testing Loop declares a round "dry" when a fresh adversary finds
# nothing and the mutation gate is clean. Both instruments are re-rolled every
# round: the adversary draws a NEW corpus each time, so "dry" measures the corpus
# that round happened to draw, not the code. On the branch that prompted this gate,
# five rounds and three confirmed fail-opens produced
# `git diff --name-only <fork-point>..HEAD -- 'crates/*/tests/corpus/'` = ZERO
# files, and one of those dry rounds certified a fail-open that was live in the
# tree. The evidence never accumulated, so nothing carried forward from round N to
# round N+1. This gate makes non-accumulation impossible to ship silently.
#
# WHAT COUNTS AS A VIOLATION
# For each IN-SCOPE crate X, the range touches `crates/X/src/**` but ADDS no file
# under `crates/X/tests/corpus/**`.
#
# The coupling is PER-CRATE, and that is the whole design. A global "did any
# corpus file get added" test is satisfied by an unrelated crate: a sudoers parser
# change paid for by a selinux corpus file. That version of this gate would report
# clean on exactly the change it exists to catch, which is why the self-test's
# `case3_cross_crate_corpus_add_does_not_pay_for_it` and the `per-crate-coupling`
# positive control both exist.
#
# Growth means an ADDED file, not a modified one. Editing an existing corpus entry
# is how a branch appears to add coverage while REPLACING it, which is precisely
# what a re-rolled adversarial corpus does.
#
# IN-SCOPE SET, DERIVED NOT HARDCODED
# A crate is in scope iff `crates/X/tests/corpus/` holds at least one tracked file
# AT THE BASE COMMIT. Deriving it means a crate that later grows a corpus is
# covered automatically, and a crate that has no corpus discipline yet is not
# blocked by a gate it cannot satisfy. A hardcoded list would rot exactly the way
# this repo's other measured-figure comments have (#642), and the rot would be
# silent because a dropped crate simply stops being checked.
#
# THE RANGE, AND WHY THIS GUARD IS THE ODD ONE OUT
# Every other guard in scripts/ walks a TREE. This one walks a COMMIT RANGE,
# because its escape hatch lives in a commit body - the only place a reviewer sees
# the excuse next to the change it excuses. That brings one failure mode the
# tree-walkers do not have: a base that resolves to the wrong commit yields an
# empty diff, and an empty diff has no violations. An unresolvable base is
# therefore rc 2 and never rc 0.
#
# ESCAPE HATCH: a COMMIT BODY line inside the range whose first non-whitespace is
# `# skip-corpus:`, followed by a real reason. It must OPEN its line, and the
# literal placeholder `<reason>` does not count - otherwise prose describing the
# hatch disables it, which is exactly what happened on the first real run.
#
# It suppresses the whole range, not one crate: a branch with a legitimate reason
# (a pure rename, a dependency bump that touches src, a revert) has that reason
# once, and per-crate markers would invite one per crate.
#
# The marker does NOT survive rebase or squash. That is a real limitation, not a
# footnote: a squash-merge that drops the body drops the exemption, and the gate
# will fail on the squashed commit if it is ever re-run against it. Put the reason
# in the PR description too.
#
# ANTI-VACUITY
# A run that examined nothing is a TOOL ERROR, not a pass. The success line
# carries the in-scope crate count, so "0 violations, 7 crates in scope" is
# distinguishable from "0 violations" printed by a gate that walked no crates at
# all. An EMPTY in-scope set is rc 2 for the same reason.
#
# An empty RANGE is different and is legitimately clean: a range that proposes no
# `crates/*/src/**` change has nothing to pay for. "Nothing was proposed" and
# "nothing could be computed" must not collapse into the same exit code.
#
# EXIT CODES
#   0 - clean; prints `OK (0 violations, N crates in scope, M changed)` with N > 0
#   1 - at least one in-scope crate changed src without adding corpus evidence
#   2 - tool error: not a git repo, base unresolvable, or an empty in-scope set
#
# Usage: scripts/check-corpus-growth.sh [BASE_SHA]
#        BASE_SHA defaults to `git merge-base origin/main HEAD`.
# Contract + test suite: scripts/check-corpus-growth-test.sh

set -uo pipefail

# Every rc-2 path except the in-scope vacuity guard goes through here, so that
# guard's own `exit 2` is the only literal one in the file.
#
# Hence the `exit 2` glued to the echo rather than put on its own line: the
# self-test's vacuity control rewrites `^    exit 2` by anchor, and a second line
# matching that anchor would make the control prove only that SOME rc-2 path
# exists rather than that the vacuity guard specifically is load-bearing.
die() {
    echo "check-corpus-growth: $*" >&2; exit 2
}

git rev-parse --git-dir >/dev/null 2>&1 || die "not a git repository: ${PWD}"

# --- Resolve the base -------------------------------------------------------
if [ "$#" -ge 1 ] && [ -n "${1:-}" ]; then
    base_desc="$1"
    base="$(git rev-parse --verify --quiet "${1}^{commit}")"
else
    base_desc="merge-base origin/main HEAD"
    base="$(git merge-base origin/main HEAD 2>/dev/null)"
fi

# An unfetched or missing origin/main lands here rather than producing an empty
# range. Reporting clean because the base could not be found is the one outcome
# this gate must never have.
[ -n "${base}" ] || die "cannot resolve base (${base_desc}); fetch origin or pass a base sha"

head_sha="$(git rev-parse --verify --quiet 'HEAD^{commit}')"
[ -n "${head_sha}" ] || die "cannot resolve HEAD"

# --- Build the in-scope set from the BASE commit ----------------------------
in_scope=""
in_scope_count=0
while IFS= read -r cdir; do
    [ -n "${cdir}" ] || continue
    corpus_at_base="$(git ls-tree -r --name-only "${base}" -- "${cdir}/tests/corpus/")"
    [ -n "${corpus_at_base}" ] || continue
    in_scope="${in_scope} ${cdir}"
    in_scope_count=$((in_scope_count + 1))
done < <(git ls-tree -d --name-only "${base}" crates/ 2>/dev/null)

if [ "${in_scope_count}" -eq 0 ]; then
    echo "check-corpus-growth: 0 crates in scope at ${base}; the gate examined nothing, which is a tool error and not a pass" >&2
    exit 2
fi

# --- The range --------------------------------------------------------------
changed_files="$(git diff --name-only "${base}" "${head_sha}")"
added_files="$(git diff --diff-filter=A --name-only "${base}" "${head_sha}")"
commit_bodies="$(git log --format=%B "${base}..${head_sha}" 2>/dev/null)"

# The exemption is checked before the walk but reported after it, so a run that
# skips still names how many crates it WOULD have checked. A skip that prints no
# denominator is indistinguishable from a skip that had nothing to skip.
skipped=""
skip_reason=""
while IFS= read -r bodyline; do
    # ANCHORED: the marker must OPEN its own line, after optional whitespace.
    #
    # An unanchored substring test is what shipped first, and it SKIPPED on this
    # gate's very first run against the real repo - because the commit body
    # introducing the gate describes the hatch inline as `# skip-corpus: <reason>`
    # and the test read that description as an invocation. The gate disabled
    # itself by being documented. check-no-mnt-paths.sh records the identical trap
    # ("it did, on the first run"): a gate whose marker can appear in prose ABOUT
    # the gate has to say WHERE the marker must sit, not merely that it occurs.
    #
    # Note the loop is fed by a here-doc, not a pipe. A pipe would put this in a
    # subshell and `skipped` would never escape it.
    [[ "${bodyline}" =~ ^[[:space:]]*#[[:space:]]*skip-corpus:[[:space:]]*(.+)$ ]] || continue
    reason="${BASH_REMATCH[1]}"
    # The literal placeholder out of the usage text is not a reason. Quoting the
    # documented form verbatim is not a decision about THIS branch.
    [ "${reason}" = "<reason>" ] && continue
    skipped=1
    skip_reason="${reason}"
    break
done <<EOF
${commit_bodies}
EOF

# src_changed CRATE - the range touches crates/CRATE/src/
src_changed() {
    case "
${changed_files}
" in
    *"
$1/src/"*) return 0 ;;
    esac
    return 1
}

# corpus_grew CRATE - the range ADDS a file under crates/CRATE/tests/corpus/
corpus_grew() {
    case "
${added_files}
" in
    *"
$1/tests/corpus/"*) return 0 ;;
    esac
    return 1
}

# Which crates DID grow, kept for the summary line so a violation report says what
# the branch actually paid for rather than only what it owes.
#
# Written with `&&` rather than an `if` block so that the violation loop below
# holds the file's ONLY `if corpus_grew "${crate}"; then` line. The per-crate
# coupling control rewrites that line by anchor, and rewriting this loop as well
# would make `growth_crates` self-referential and empty, which sabotages the gate
# in a different way than the one the control is supposed to be measuring.
growth_crates=""
for crate in ${in_scope}; do
    corpus_grew "${crate}" && growth_crates="${growth_crates} ${crate}"
done

changed_count=0
violations=0
report=""
for crate in ${in_scope}; do
    src_changed "${crate}" || continue
    changed_count=$((changed_count + 1))
    if corpus_grew "${crate}"; then
        continue
    fi
    report="${report}${crate}: src changed with no file ADDED under ${crate}/tests/corpus/
"
    violations=$((violations + 1))
done

if [ -n "${skipped}" ]; then
    printf 'check-corpus-growth: SKIPPED by `skip-corpus: %s` in a commit body (%d crates in scope, %d changed, %d would have been violations)\n' "${skip_reason}" \
        "${in_scope_count}" "${changed_count}" "${violations}" >&2
    echo "OK (0 violations, ${in_scope_count} crates in scope, ${changed_count} changed, skip-corpus honoured)"
    exit 0
fi

if [ "${violations}" -ne 0 ]; then
    printf '%s' "${report}" >&2
    cat >&2 <<EOF
check-corpus-growth: ${violations} violation(s), ${in_scope_count} crates in scope, ${changed_count} changed, base ${base}
A round whose corpus does not grow cannot tell you the code got safer, only that
this round's freshly drawn inputs missed. Add the input that FOUND the defect to
the committed corpus so the next round replays it.
Escape (whole range, and it does not survive rebase or squash):
  # skip-corpus: <reason>
in a commit body.
EOF
    exit 1
fi

echo "OK (0 violations, ${in_scope_count} crates in scope, ${changed_count} changed,${growth_crates:- none} grew)"
exit 0
