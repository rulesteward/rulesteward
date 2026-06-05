# diff-removed-grant

## Intent

The current ruleset has one FEWER allow-grant than the `--diff-against`
snapshot. The grant present in the snapshot but gone now
(`allow perm=execute all : trust=1`) appears as a single `removed` drift row: a
revoked exception.

## edge_case_axis

diff-drift

## Mapping notes (f2 sections 3.2, 4.1, 4.2, 4.3)

- The snapshot (`snapshot.json`) holds two grants: `allow perm=open all : all`
  and `allow perm=execute all : trust=1`. The current ruleset
  (`A1-removed.rules`) holds only the first.
- Diff key = the canonical predicate tuple
  `(decision, perm, sorted(subject), sorted(object), set-expanded)` (f2 section
  4.1), reusing the grounded fapd-C02 AST-equality relation
  (`cross_file.rs:84-150`).
- The `all : all` grant's key matches both sides, so no drift. The
  `execute all : trust=1` grant's key is present in the snapshot and absent from
  the current set -> classified `removed` (f2 section 4.2). Removed rows carry
  the register row in `from`, `to: null` (f2 section 4.3).
- The removed grant's register row (source line, loadIndex) is taken from the
  SNAPSHOT, since it no longer exists in the current ruleset.

## Snapshot

`snapshot.json` is a valid §3.2 `exception-register` envelope with both grants.
`report --diff-against snapshot.json` over the current ruleset yields exactly
one `removed` row.
