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
total=$(grep -c '"' "$MO/caught.txt" 2>/dev/null; true)
c=$(wc -l < "$MO/caught.txt" 2>/dev/null || echo 0)
m=$(wc -l < "$MO/missed.txt" 2>/dev/null || echo 0)
t=$(wc -l < "$MO/timeout.txt" 2>/dev/null || echo 0)
u=$(wc -l < "$MO/unviable.txt" 2>/dev/null || echo 0)
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
# The loop reads from a process substitution rather than a pipe on purpose: a
# piped `while` runs in a subshell, so `unmutated` would be discarded at `done`
# and this guard would silently become decorative a second time.
echo "--- changed files vs mutated files ---"
unmutated=""
while read -r f; do
  [ -n "$f" ] || continue
  n=$(cat "$MO/caught.txt" "$MO/missed.txt" "$MO/timeout.txt" 2>/dev/null | grep -cF "$f")
  echo "  $f -> $n mutants"
  [ "$n" -eq 0 ] && unmutated="$unmutated $f"
done < <(grep -E '^\+\+\+ b/.*\.rs$' "$OUT/impl.diff" | sed 's|^+++ b/||')
if [ -n "$unmutated" ]; then
  echo "GATE-ERROR:$unmutated not among the mutated files - this lane's change was never tested."
  echo "  Usual causes: the file is outside .cargo/mutants.toml examine_globs, or"
  echo "  --in-diff was handed a rewritten diff (use 'rtk proxy git diff')."
  exit 2
fi

echo "--- survivors (missed) ---"
cat "$MO/missed.txt" 2>/dev/null || echo "(none)"
echo "--- timeouts ---"
cat "$MO/timeout.txt" 2>/dev/null || echo "(none)"
echo "GATE-RESULT: $CRATE rc=$rc"
exit $rc
