# perm-any

## Intent

perm=any renders perm:"any".

## edge_case_axis

`perm`

## Input

One file `43-any.rules`:

```
allow perm=any uid=0 : dir=/var/tmp/
```

## Why the golden output is correct (f2 sections 2.2 / 3.2)

- Single allow-family grant -> one register row, `loadIndex:1`, `source.line:1`.
- `perm=any` renders `perm:"any"` (Display for Perm, `format.rs:26-35`).
- Subject side is `uid=0`; object side is `dir=/var/tmp/` (Display-rendered
  sides, `format.rs:56-74`).
- `dir=` is a path-prefix predicate: `scope:"dir"`. Per f2 section 2.2 the `dir=`
  value is extracted as a path, so `objectPaths:["/var/tmp/"]`. `uid=0` is not a
  path, so `subjectPaths:[]`.
- No inline `filehash=`/`sha256hash=`, no `--against-trustdb`: `hash:null`,
  `hashOrigin:"none"`, `hashAlgorithm:null` (honest none, dir-scoped grant).
- No SetRef used: `setExpansions:{}`.
