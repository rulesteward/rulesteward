# perm-execute

## Intent

perm=execute renders perm:"execute".

## edge_case_axis

`perm`

## Input

One file `42-execute.rules`:

```
allow perm=execute all : trust=1
```

## Why the golden output is correct (f2 sections 2.2 / 3.2)

- Single allow-family grant -> one register row, `loadIndex:1`, `source.line:1`.
- `perm=execute` renders `perm:"execute"` (Display for Perm, `format.rs:26-35`).
- Subject side is `all`; object side is `trust=1` (Display-rendered sides,
  `format.rs:56-74`).
- `trust=1` on the object side is a trust predicate: `scope:"trust"`. `trust` is
  neither an `exe=`/`path=`/`dir=` value, so nothing is extracted:
  `subjectPaths:[]`, `objectPaths:[]`.
- No inline `filehash=`/`sha256hash=`, no `--against-trustdb`: `hash:null`,
  `hashOrigin:"none"`, `hashAlgorithm:null`.
- No SetRef used: `setExpansions:{}`.
