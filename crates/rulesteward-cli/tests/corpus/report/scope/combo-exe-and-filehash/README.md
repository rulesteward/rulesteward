# combo-exe-and-filehash

- **class:** scope
- **edge_case_axis:** scope

## Intent

A grant with a SUBJECT `exe=` (a concrete executable path) AND an OBJECT
`filehash=` (an inline integrity pin). The register extracts the executable into
`subjectPaths`, records the inline hash with `hashOrigin:"rule-filehash"`, and
resolves `scope:"hash"` - the strongest static pin wins over the path predicate.

## Input

One file `C5-exehash.rules`:

```
allow perm=execute exe=/usr/bin/python3 : filehash=0123456789abcdef...0123456789abcdef
```

(`filehash=` is a 64-hex value.) No `--against-trustdb`, no `--diff-against`.

## Why the golden output is correct (f2 sections 2.2 / 2.3 / 3.2)

- One allow-family grant -> one register row, `loadIndex:1`, `source.line:1`.
- `perm=execute` renders `perm:"execute"`. Subject renders
  `exe=/usr/bin/python3`; object renders `filehash=<64 hex>`.
- `exe=` is a concrete subject path: `subjectPaths:["/usr/bin/python3"]`
  (f2 section 2.2 path extraction over `exe=`/`path=`/`dir=` values). The
  `filehash=` value is NOT a path, so `objectPaths:[]`.
- The object carries an inline `filehash=` pin, so `hash` = the literal hex,
  `hashOrigin:"rule-filehash"`, `hashAlgorithm:"SHA256"` (64 hex -> SHA256 by the
  length convention, `trustdb.rs:107-108`).
- `scope:"hash"`: when both a path predicate (`exe=`) and an inline hash pin
  (`filehash=`) are present, the inline hash is "the STRONGEST static pin"
  (f2 section 2.3, line 100), so it determines the scope. This is the same
  specificity precedence applied in `combo-trust-and-ftype` (hash > path > ftype >
  trust > all), and it is the answer the task specifies for this scenario
  ("hashOrigin rule-filehash, scope hash").
- No SetRef: `setExpansions:{}`.
- The 64-hex value is a deterministic placeholder (static inline pin,
  `against_trustdb:false`, no trust-DB capture).
