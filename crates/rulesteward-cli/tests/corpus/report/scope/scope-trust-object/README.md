# scope-trust-object

## Intent

trust=1 on the object side yields scope:"trust".

## edge_case_axis

`scope`

## Input

One file `50-trust-obj.rules`:

```
allow perm=execute all : trust=1
```

## Why the golden output is correct (f2 sections 2.2 / 3.2)

- Single allow-family grant -> one register row, `loadIndex:1`, `source.line:1`.
- `perm=execute` renders `perm:"execute"`.
- Subject side is `all`; object side is `trust=1` (Display-rendered sides,
  `format.rs:56-74`).
- `trust=1` is a trust predicate (`trust` is either-side, `attrs.rs:57`); on the
  object side it yields `scope:"trust"`. `trust` is not an `exe=`/`path=`/`dir=`
  value, so `subjectPaths:[]` and `objectPaths:[]`.
- No inline `filehash=`/`sha256hash=`, no `--against-trustdb`: `hash:null`,
  `hashOrigin:"none"`, `hashAlgorithm:null`.
- No SetRef used: `setExpansions:{}`.
