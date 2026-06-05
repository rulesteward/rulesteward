# diff-line-churn-no-drift

- **class:** diff-drift
- **edge_case_axis:** diff-drift

## Intent

The snapshot and the current ruleset differ ONLY in line numbers: two
leading comments shift every rule down by two lines. The canonical
predicate keys are unchanged, so drift is empty. Proves the diff key is
predicate-based (f2 section 4.1: key = canonicalized predicate, NOT
file:line), not file:line based.

## Input

- `rules.d/A7-churn.rules`: two leading comment lines, then the two allow
  grants at lines 3 and 4.
- Flags: `--diff-against <snapshot.json>` (no `--against-trustdb`).

## Snapshot (diff_against)

A prior snapshot whose grants have the SAME predicates but were emitted
from a file with NO leading comments, so the rules sat at lines 1 and 2.
`source.line` differs between snapshot (1,2) and current (3,4), but the
canonical predicate key ignores line, so drift is empty (`drift: []`).

## golden-register.json

The §3.2 register for the current ruleset: two grants at lines 3 and 4
(`all : all` scope `all`; `all : trust=1` scope `trust`). Note that
`loadIndex` is the per-grant load-order counter (1, 2), independent of
`source.line` (3, 4): the comment shift moves the lines but not the grant
ordinal.

## Oracle / ground truth

Pure spec-derived mapping (f2 sections 3.2 / 4.1); no trust-DB digests
captured (against_trustdb is false).
