# scope-trust-subject

## Intent

trust=1 on the subject side still yields scope:"trust" (trust is either-side).

## edge_case_axis

`scope`

## Input

One file `51-trust-subj.rules`:

```
allow perm=any uid=0 trust=1 : all
```

## Why the golden output is correct (f2 sections 2.2 / 3.2)

- Single allow-family grant -> one register row, `loadIndex:1`, `source.line:1`.
- `perm=any` renders `perm:"any"`.
- Subject side carries two attrs and renders `uid=0 trust=1` (space-separated
  subject Attrs, Display for Rule `format.rs:62-64`); object side is `all`.
- `trust` is either-side (`attrs.rs:57`); here it sits on the SUBJECT side and
  still yields `scope:"trust"` (the README scope axis: `trust` matches object OR
  subject). Neither `uid=` nor `trust=` is an `exe=`/`path=`/`dir=` value, so
  `subjectPaths:[]` and `objectPaths:[]`.
- No inline `filehash=`/`sha256hash=`, no `--against-trustdb`: `hash:null`,
  `hashOrigin:"none"`, `hashAlgorithm:null`.
- No SetRef used: `setExpansions:{}`.
