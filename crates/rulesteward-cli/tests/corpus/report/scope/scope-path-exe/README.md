# scope-path-exe

## Intent

A subject exe= path yields scope:"path" and subjectPaths extraction.

## edge_case_axis

`scope`

## Input

One file `52-path-exe.rules`:

```
allow perm=open exe=/usr/bin/rpm : all
```

## Why the golden output is correct (f2 sections 2.2 / 3.2)

- Single allow-family grant -> one register row, `loadIndex:1`, `source.line:1`.
- `perm=open` renders `perm:"open"`.
- Subject side is `exe=/usr/bin/rpm`; object side is `all` (Display-rendered
  sides, `format.rs:56-74`). `exe` is subject-only (`attrs.rs:48`).
- `exe=` is a concrete path predicate: `scope:"path"`. Per f2 section 2.2 the
  `exe=` value is extracted as a path on the subject side, so
  `subjectPaths:["/usr/bin/rpm"]`. The object side is `all` (not a path), so
  `objectPaths:[]`.
- No inline `filehash=`/`sha256hash=`, no `--against-trustdb`: `hash:null`,
  `hashOrigin:"none"`, `hashAlgorithm:null`.
- No SetRef used: `setExpansions:{}`.
