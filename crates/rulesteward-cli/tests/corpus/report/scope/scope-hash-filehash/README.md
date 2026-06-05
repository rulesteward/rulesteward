# scope-hash-filehash

## Intent

An inline `filehash=` object attr yields `scope:"hash"`.

## edge_case_axis

`scope`

## Input

One file `57-hashscope.rules`:

```
allow perm=open all : filehash=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

## Why the golden output is correct (f2 sections 2.2 / 2.3 / 3.2)

- Single allow-family grant -> one register row, `loadIndex:1`, `source.line:1`.
- `perm=open` renders `perm:"open"`.
- Subject side is `all`; object side renders `filehash=<64 hex>`.
- `filehash=` is an inline object-side hash pin (f2 section 2.3 case 1), so
  `scope:"hash"` and `hashOrigin:"rule-filehash"`.
- The `hash` field carries the literal hex value. Algorithm is inferred BY HEX
  LENGTH (f2 section 2.3 / corpus README): 64 hex -> `SHA256`.
- A filehash value is not a filesystem path, so `subjectPaths` and `objectPaths`
  are both `[]`.
- No SetRef used: `setExpansions:{}`.
- The 64-hex value `0123...cdef` is a deterministic placeholder digest (no
  trust-DB capture needed; this is a static inline pin, `against_trustdb:false`).
