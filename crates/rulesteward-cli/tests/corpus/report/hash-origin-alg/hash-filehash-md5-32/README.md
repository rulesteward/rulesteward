# hash-filehash-md5-32

## Intent

A 32-hex inline `filehash` yields `hashOrigin:"rule-filehash"`,
`hashAlgorithm:"MD5"` (length 32).

## edge_case_axis

`hash-origin-alg`

## Input

One file `60-md5.rules`:

```
allow perm=open all : filehash=0123456789abcdef0123456789abcdef
```

## Why the golden output is correct (f2 sections 2.2 / 2.3 / 3.2)

- Single allow-family grant -> one register row, `loadIndex:1`, `source.line:1`.
- `perm=open` renders `perm:"open"`.
- Subject side is `all`; object side renders `filehash=<32 hex>`.
- `filehash=` is an inline object-side hash pin (f2 section 2.3 case 1):
  `hashOrigin:"rule-filehash"`, `scope:"hash"`.
- The `hash` field carries the literal 32-hex value. Algorithm BY HEX LENGTH
  (f2 section 2.3 / `trustdb.rs:107-108`): 32 hex -> `MD5`.
- A filehash value is not a path: `subjectPaths` and `objectPaths` are `[]`.
- No SetRef used: `setExpansions:{}`.
- The 32-hex value is a deterministic placeholder (static inline pin,
  `against_trustdb:false`, no trust-DB capture).
