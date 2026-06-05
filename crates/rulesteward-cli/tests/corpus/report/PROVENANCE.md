# Vendored fapolicyd report corpus - wave-1 consolidated

Vendored at 2026-06-04T for barrier test authoring (issue #81/#82/#83/#84).
Source: /mnt/side-projects/fapolicyd-report-corpus/20260603T034301Z-wave1-consolidated (NFS)
Oracle method: f2 section 3.2 spec-derived golden registers + real trustdb digests.
Timestamp: 20260603T034301Z

Total scenarios vendored: 72 (see source INDEX.md for full table)
Classes: cardinality(5), decision(5), perm(4), scope(14), hash-origin-alg(8),
         set-expansion(5), path-extraction(6), against-trustdb(8), diff-drift(9),
         load-order(4), noise-filter(4)

NOTE: The source INDEX.md and issue #84 cite "63 scenarios" but the corpus
actually contains 72 leaf scenarios (the 9-scenario report-wave1-patch phase was
added after the issue was filed). All 72 are vendored here.

## trustJoin shape inconsistency (known, surfaced for user confirmation)

Two different trustJoin shapes appear in the corpus goldens:

Shape A (against-trustdb category, 6 of 8 scenarios):
  "trustJoin": [{ "grantIndex": 0, "rows": [{path, source, size, digest}] }]

Shape B (diff-drift/diff-changed-trustdb-digest, against-trustdb/trustdb-source-unknown):
  "trustJoin": [{ "path": "...", "source": "...", "size": N, "digest": "..." }]

The test oracle asserts Shape A (grantIndex + rows) as authoritative.
See report_oracle.rs for the [QUESTION FOR USER] on this point.
