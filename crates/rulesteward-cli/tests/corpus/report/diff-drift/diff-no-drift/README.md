# diff-no-drift

- **class:** diff-drift
- **edge_case_axis:** diff-drift

## Intent

The current ruleset is identical to the prior snapshot (same two grants,
same predicates). The diff is an empty array; with `--fail-on-drift`
absent, exit code is 0 (f2 section 5: drift is informational by default).

## Input

- `rules.d/A5-nodrift.rules`: two allow grants (all-all, then
  execute/trust=1).
- Flags: `--diff-against <snapshot.json>` (no `--against-trustdb`,
  no `--fail-on-drift`).

## Snapshot (diff_against)

A prior snapshot whose grant set is IDENTICAL: the same two grants with
the same canonical predicate keys. Diff yields `drift: []`; exit 0.

## golden-register.json

The §3.2 register for the current ruleset: two grants. Grant 1 is
`all : all` (scope `all`); grant 2 is `all : trust=1` (scope `trust`).
Without `--against-trustdb`, the `trust=1` grant is NOT enumerated, so
`hashOrigin` stays `none` and `hash`/`hashAlgorithm` are null. A snapshot
built from THIS register diffs to empty.

## Oracle / ground truth

Pure spec-derived mapping (f2 section 3.2); no trust-DB digests captured
(against_trustdb is false).
