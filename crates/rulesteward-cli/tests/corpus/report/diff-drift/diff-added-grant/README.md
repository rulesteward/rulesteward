# diff-added-grant

## Intent

The current ruleset has one MORE allow-grant than the `--diff-against` snapshot.
The added grant (`allow perm=execute all : trust=1`) appears as a single `added`
drift row. This is the highest-signal drift for an auditor: a new exception
appeared.

## edge_case_axis

diff-drift

## Mapping notes (f2 sections 3.2, 4.1, 4.2, 4.3)

- Current ruleset (`A0-added.rules`) holds two grants:
  `allow perm=open all : all` (line 1) and `allow perm=execute all : trust=1`
  (line 2). The snapshot (`snapshot.json`) holds only the first.
- The diff key is the canonical predicate tuple
  `(decision, perm, sorted(subject), sorted(object), set-expanded)` (f2 section
  4.1), which reuses the grounded fapd-C02 AST-equality relation
  (`cross_file.rs:84-150`).
- The `all : all` grant's canonical key matches between snapshot and current, so
  it is NOT a drift row. The `execute all : trust=1` grant's key is present in
  the current set and absent from the snapshot -> classified `added` (f2 section
  4.2). Added rows carry the register row in `to`, `from: null` (f2 section 4.3).
- The drift envelope is `{schemaVersion:1, kind:"exception-register-drift",
  drift:[...]}` (f2 section 4.3).

## Snapshot

`snapshot.json` is a valid §3.2 `exception-register` envelope containing only the
`all : all` grant. `report --diff-against snapshot.json` over the current
ruleset yields exactly one `added` row.
