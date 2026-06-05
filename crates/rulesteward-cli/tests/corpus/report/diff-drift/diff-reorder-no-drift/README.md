# diff-reorder-no-drift

- **class:** diff-drift
- **edge_case_axis:** diff-drift

## Intent

The same grant set in a different file/load order. Diff is empty: the
drift comparison is set-equality on canonical keys (f2 section 4.1), so
ordering does not matter.

## Input

- `rules.d/A8-reorder.rules`: the two grants in the order
  (`execute / trust=1`, then `all : all`).
- Flags: `--diff-against <snapshot.json>` (no `--against-trustdb`).

## Snapshot (diff_against)

A prior snapshot with the SAME two grants in the OPPOSITE order
(`all : all` first, then `execute / trust=1`). Set-equality on the
canonical predicate keys yields `drift: []`.

## golden-register.json

The §3.2 register for the current ruleset, emitted in load order: grant 1
is `execute / trust=1` (scope `trust`, loadIndex 1), grant 2 is
`all : all` (scope `all`, loadIndex 2). The snapshot lists the same two
grants in the reverse order; the diff is order-independent, so it is empty.

## Oracle / ground truth

Pure spec-derived mapping (f2 sections 3.2 / 4.1); no trust-DB digests
captured (against_trustdb is false).
