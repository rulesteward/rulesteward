# diff-multi-drift

- **class:** diff-drift
- **edge_case_axis:** diff-drift

## Intent

A single diff that produces all three drift kinds at once: one `added`,
one `removed`, and one `changed` row (f2 section 4.2). Exercises the
union-of-keys + classify algorithm end to end.

## Input

- `rules.d/A6-multi.rules`: two current grants:
  1. `allow perm=open all : all` (scope `all`)
  2. `allow perm=open all : filehash=0123...cdef` (scope `hash`,
     SHA256 re-pin of an object whose snapshot digest was `ffff...ffff`)
- Flags: `--diff-against <snapshot.json>` (no `--against-trustdb`).

## Snapshot (diff_against)

The prior snapshot is constructed so the union of keys yields one of each
drift kind:

- `allow perm=open all : filehash=ffff...ffff` (same canonical predicate
  key as current grant 2, but a DIFFERENT digest) -> **changed**
  (from `ffff...ffff`, to `0123...cdef`).
- `allow perm=execute all : trust=1` (present in snapshot, ABSENT now)
  -> **removed**.
- The current `allow perm=open all : all` grant is ABSENT from the
  snapshot -> **added**.

Net drift: 1 added (`all : all`), 1 removed (`execute / trust=1`),
1 changed (the filehash re-pin). Three rows total.

## golden-register.json

The §3.2 register for the CURRENT ruleset only: two grants (the all-all
grant and the SHA256 filehash-pinned grant). The snapshot and the
resulting 3-row drift are described above; the golden register is the
emit-side artifact the diff consumes.

## Oracle / ground truth

Pure spec-derived mapping (f2 section 3.2). The `0123...cdef` digest is a
synthetic 64-hex (SHA256 by length); no trust-DB digests captured
(against_trustdb is false).
