# scope-pattern-subject

## Intent

A subject `pattern=` (subject-only attr) yields `scope:"pattern"`.

## edge_case_axis

`scope`

## Input

One file `56-pattern.rules`:

```
allow perm=any pattern=ld_so : all
```

## Why the golden output is correct (f2 sections 2.2 / 3.2)

- Single allow-family grant -> one register row, `loadIndex:1`, `source.line:1`.
- `perm=any` renders `perm:"any"`.
- `pattern=` is a subject-only loader-pattern attribute (corpus README: `pattern`
  is subject). Subject side renders `pattern=ld_so`; object side is `all`.
- A pattern predicate matches by loader pattern, not a path or hash:
  `scope:"pattern"`. A pattern value is not a filesystem path, so both
  `subjectPaths` and `objectPaths` are `[]` (f2 section 2.2 extracts only
  `exe=`/`path=`/`dir=` values).
- Pattern-scoped grant has no inline hash and no `--against-trustdb`:
  `hash:null`, `hashOrigin:"none"`, `hashAlgorithm:null`.
- No SetRef used: `setExpansions:{}`.
