#!/usr/bin/env bash
# Per-lane mutation gate.
#
# rc IS the gate. cargo-mutants 27.x exits non-zero on a survivor or a timeout;
# --error-on-survival was removed. Everything below the cargo call is a
# VACUITY GUARD, not the pass condition: a run that mutated NOTHING reports the
# same "0 survivors" as a real pass, so we assert total_mutants > 0 and that the
# changed files actually appear in caught/missed before any green is trusted.
#
# usage: rs-mutation-gate.sh <worktree> <crate-name> <base-sha> <impl-sha>
set -u

WT="$1"; CRATE="$2"; BASE="$3"; IMPL="$4"
# Scratch honours TMPDIR. The per-UID /tmp tmpfs QUOTA (not the filesystem) is
# what fills on this machine, and `df` reports the filesystem, so it looks
# healthy while every shell dies; that exhaustion caused 80 of one session's
# 146 unique errors. Hardcoding /tmp here would put the gate's own scratch, and
# via the export below cargo-mutants' entire scratch tree, in the one place a
# fan-out is told not to use.
OUT="${TMPDIR:-/tmp}/mutgate-$CRATE"
rm -rf "$OUT"; mkdir -p "$OUT"

# Run from the WORKSPACE ROOT, not the crate dir. examine_globs in
# .cargo/mutants.toml is written workspace-root-relative
# ("crates/rulesteward-auditd/src/parser.rs"), so running from inside the crate
# with a --relative diff matches NOTHING and cargo-mutants reports "No mutants
# to filter" at rc=0 - a vacuous pass indistinguishable from a real one.
# Measured 2026-07-30.
cd "$WT" || { echo "GATE-ERROR: no worktree $WT"; exit 2; }

# rtk proxy: the compacting filter rewrites diffs and cargo-mutants then reports
# "Diff changes no Rust source files".
rtk proxy git diff "$BASE" "$IMPL" > "$OUT/impl.diff" 2>"$OUT/diff.err"

# Positive control on the diff itself, before it is trusted as scope.
hunks=$(grep -c '^diff --git' "$OUT/impl.diff")
rusth=$(grep -cE '^\+\+\+ b/.*\.rs$' "$OUT/impl.diff")
echo "DIFF: $hunks file-hunks, $rusth rust +++ lines"
if [ "$hunks" -eq 0 ] || [ "$rusth" -eq 0 ]; then
  echo "GATE-ERROR: diff carries no Rust hunks - scope would be vacuous"
  head -20 "$OUT/impl.diff"; exit 2
fi

export TMPDIR="$OUT/scratch"; mkdir -p "$TMPDIR"

cargo mutants --in-diff "$OUT/impl.diff" --test-package "$CRATE" -j4 > "$OUT/run.out" 2>&1
rc=$?
echo "CARGO-MUTANTS RC=$rc   (0=clean, non-zero=survivor or timeout)"

MO="$WT/mutants.out"
if [ ! -d "$MO" ]; then echo "GATE-ERROR: no mutants.out - nothing ran"; tail -30 "$OUT/run.out"; exit 2; fi

# Vacuity guard 1: something was actually mutated.
#
# `wc -l < f 2>/dev/null` does NOT suppress the error it looks like it does:
# redirections apply left to right, so the input redirection fails and prints
# before `2>/dev/null` is installed. Count the file by name instead.
countlines() { [ -f "$1" ] && wc -l <"$1" || echo 0; }
c=$(countlines "$MO/caught.txt")
m=$(countlines "$MO/missed.txt")
t=$(countlines "$MO/timeout.txt")
u=$(countlines "$MO/unviable.txt")
echo "MUTANTS: caught=$c missed=$m timeout=$t unviable=$u"
if [ "$((c + m + t))" -eq 0 ]; then
  echo "GATE-ERROR: VACUOUS - zero viable mutants tested. A green here means nothing."
  tail -30 "$OUT/run.out"; exit 2
fi

# Vacuity guard 2: the files we actually changed were among those mutated.
#
# This is the guard that READ as present and was not. The 9m original printed a
# per-file count and then exited with cargo's rc regardless, so a run that
# mutated a DIFFERENT file than the one the lane changed passed silently while
# printing "-> 0 mutants" on the way past. Guard 1 cannot see it: the
# denominator is non-zero, because some OTHER file was mutated.
#
# Only .rs files are checked. A diff may legitimately carry .md or .toml hunks
# and cargo-mutants will never mutate those; failing on them would make the
# gate unusable and would be the fastest route to someone deleting it.
#
# That reasoning stopped one step short, and the first review of this file
# caught it: `**/tests/**` is in .cargo/mutants.toml `exclude_globs`, so an
# integration-test file is a .rs file that cargo-mutants DELIBERATELY never
# mutates. Demanding coverage for it rc-2s on the shape every TDD lane
# produces (impl hunk + the frozen test file it makes green), with a message
# telling the operator to add the path to `examine_globs` - which cannot work,
# because exclude_globs wins. Fail-closed, but unusable, which is the same
# route to deletion by another name.
#
# So the partition is three-way, not two-way:
#   mutated          - the guard is satisfied for this file.
#   out of scope     - unmutated AND under a tests/ directory. Reported, not
#                      fatal; the coupling to exclude_globs is deliberate and
#                      is why `/tests/` is named here literally rather than a
#                      glob engine being reimplemented.
#   unexplained      - unmutated and NOT excluded by design. Still fatal: this
#                      is the mangled-diff and outside-examine_globs case.
# ...and if NOTHING changed was mutated, the run proved nothing even when every
# unmutated file was explainable, so that is fatal too.
#
# The loop reads from a process substitution rather than a pipe on purpose: a
# piped `while` runs in a subshell, so the accumulators would be discarded at
# `done` and this guard would silently become decorative a second time.
echo "--- changed files vs mutated files ---"
unmutated=""
outofscope=""
mutated_any=0
while read -r f; do
  [ -n "$f" ] || continue
  # Anchored at a path boundary and at the `:` cargo-mutants writes after the
  # file, so `a.rs` cannot be credited by a mutant in `xa.rs`. Left-anchored to
  # `^` OR `/` rather than `^` alone: whether the outcome files are repo- or
  # crate-relative depends on where the caller cd'd to, and a too-strict anchor
  # would turn that difference into a spurious GATE-ERROR.
  n=$(cat "$MO/caught.txt" "$MO/missed.txt" "$MO/timeout.txt" 2>/dev/null | grep -cE "(^|/)${f//./\\.}:")
  if [ "$n" -gt 0 ]; then
    echo "  $f -> $n mutants"
    mutated_any=1
  elif [ "$f" != "${f#tests/}" ] || [ "$f" != "${f/\/tests\//}" ]; then
    echo "  $f -> 0 mutants (SKIPPED: out of mutation scope, .cargo/mutants.toml exclude_globs '**/tests/**')"
    outofscope="$outofscope $f"
  else
    echo "  $f -> 0 mutants"
    unmutated="$unmutated $f"
  fi
done < <(grep -E '^\+\+\+ b/.*\.rs$' "$OUT/impl.diff" | sed 's|^+++ b/||')
if [ -n "$unmutated" ]; then
  echo "GATE-ERROR:$unmutated not among the mutated files - this lane's change was never tested."
  echo "  Usual causes: the file is outside .cargo/mutants.toml examine_globs, or"
  echo "  --in-diff was handed a rewritten diff (use 'rtk proxy git diff')."
  exit 2
fi
if [ "$mutated_any" -eq 0 ]; then
  echo "GATE-ERROR: no changed Rust file was mutated - every changed .rs file is"
  echo "  out of mutation scope ($outofscope), so this run proved nothing about the change."
  exit 2
fi

echo "--- survivors (missed) ---"
cat "$MO/missed.txt" 2>/dev/null || echo "(none)"
echo "--- timeouts ---"
cat "$MO/timeout.txt" 2>/dev/null || echo "(none)"
echo "GATE-RESULT: $CRATE rc=$rc"
exit $rc
