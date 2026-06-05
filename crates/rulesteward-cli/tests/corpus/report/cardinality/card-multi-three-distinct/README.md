# card-multi-three-distinct

## Intent

Three allow grants with distinct predicates in one file; `loadIndex` increments
and each row is distinct. Exercises multi-row enumeration, per-row scope
classification, and path extraction across three different scopes (trust, path,
dir).

## edge_case_axis

cardinality

## Input

`rules.d/20-three.rules`:

```
allow perm=execute all : trust=1
allow perm=open exe=/usr/bin/rpm : all
allow perm=any uid=0 : dir=/var/tmp/
```

## Golden output reasoning (f2 section 3.2 mapping)

Row 1 (line 1, loadIndex 1): `allow perm=execute all : trust=1`
- subject `all`, object `trust=1`, scope `trust` (object-side `trust=1`).
- No path, no hash.

Row 2 (line 2, loadIndex 2): `allow perm=open exe=/usr/bin/rpm : all`
- subject `exe=/usr/bin/rpm`, object `all`, scope `path` (subject `exe=`).
- subjectPaths `["/usr/bin/rpm"]` (extracted from `exe=`).

Row 3 (line 3, loadIndex 3): `allow perm=any uid=0 : dir=/var/tmp/`
- subject `uid=0`, object `dir=/var/tmp/`, scope `dir` (object `dir=`).
- objectPaths `["/var/tmp/"]` (a `dir=` value is extracted as a path).
- `uid=` is a subject narrowing attr but is NOT a path, so subjectPaths `[]`.

All three rows: `hash` null, `hashOrigin` none, `hashAlgorithm` null,
`setExpansions` `{}`. Each `source.file` is `20-three.rules`; lines 1/2/3.
