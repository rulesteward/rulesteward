# scope-path-object

## Intent

An object path= yields scope:"path" and objectPaths extraction.

## edge_case_axis

`scope`

## Input

One file `53-path-obj.rules`:

```
allow perm=open uid=0 : path=/etc/hosts
```

## Why the golden output is correct (f2 sections 2.2 / 3.2)

- Single allow-family grant -> one register row, `loadIndex:1`, `source.line:1`.
- `perm=open` renders `perm:"open"`.
- Subject side is `uid=0`; object side is `path=/etc/hosts` (Display-rendered
  sides, `format.rs:56-74`). `path` is object-only (`attrs.rs:55`).
- `path=` is a concrete path predicate: `scope:"path"`. Per f2 section 2.2 the
  `path=` value is extracted as a path on the object side, so
  `objectPaths:["/etc/hosts"]`. `uid=0` is not a path, so `subjectPaths:[]`.
- No inline `filehash=`/`sha256hash=`, no `--against-trustdb`: `hash:null`,
  `hashOrigin:"none"`, `hashAlgorithm:null`.
- No SetRef used: `setExpansions:{}`.
