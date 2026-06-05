# scope-all

## Intent

`all : all` yields `scope:"all"` (no narrowing predicate).

## edge_case_axis

`scope`

## Input

One file `58-allscope.rules`:

```
allow perm=open all : all
```

## Why the golden output is correct (f2 sections 2.2 / 3.2)

- Single allow-family grant -> one register row, `loadIndex:1`, `source.line:1`.
- `perm=open` renders `perm:"open"`.
- Both sides are the `all` wildcard: subject `all`, object `all`.
- No narrowing predicate (no trust/path/dir/ftype/pattern/hash, no uid/gid):
  `scope:"all"` (corpus README closed-enum definition).
- No path attr present, so `subjectPaths` and `objectPaths` are `[]`.
- No inline hash, no `--against-trustdb`: `hash:null`, `hashOrigin:"none"`,
  `hashAlgorithm:null`.
- No SetRef used: `setExpansions:{}`.
