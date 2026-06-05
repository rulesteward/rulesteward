# scope-ftype-object

## Intent

An object `ftype=` MIME type yields `scope:"ftype"`, no path, hash none.

## edge_case_axis

`scope`

## Input

One file `55-ftype.rules`:

```
allow perm=open all : ftype=application/x-sharedlib
```

## Why the golden output is correct (f2 sections 2.2 / 3.2)

- Single allow-family grant -> one register row, `loadIndex:1`, `source.line:1`.
- `perm=open` renders `perm:"open"`.
- Subject side is `all`; object side is `ftype=application/x-sharedlib`.
- `ftype=` is a MIME-type predicate, not a path or hash: `scope:"ftype"`. Per f2
  section 2.2 there is no path to extract from an ftype value, so both
  `subjectPaths` and `objectPaths` are `[]`.
- An ftype-scoped grant matches by MIME type, not by hash (f2 section 2.4): the
  hash column is honestly `none`. `hash:null`, `hashOrigin:"none"`,
  `hashAlgorithm:null`.
- No SetRef used: `setExpansions:{}`.
