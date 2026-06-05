# combo-multi-everything

- **class:** scope
- **edge_case_axis:** scope

## Intent

A single RICH grant that exercises every per-row register field at once:
a narrowed SUBJECT (`exe=`), a multi-attribute OBJECT (`ftype=%set` + `filehash=`),
an explicit PERM, an inline HASH, a SET EXPANSION, and SOURCE provenance - all in
one register row. The "everything together" smoke fixture for the section-3.2
mapping.

## Input

One file `C7-multi.rules`:

```
%mimes=application/x-executable,application/x-sharedlib
allow perm=execute exe=/usr/sbin/foo : ftype=%mimes filehash=89abcdef...01234567
```

(`filehash=` is a 64-hex value.) The set `%mimes` is defined on line 1; the single
grant on line 2 references it via `ftype=%mimes` and also pins an inline
`filehash=`. No `--against-trustdb`, no `--diff-against`.

## Why the golden output is correct (f2 sections 2.2 / 2.3 / 3.2)

- The single allow-family grant on line 2 -> one register row, `loadIndex:1`,
  `source.line:2` (the set-definition line is not a grant and is not load-indexed).
- PERM: `perm=execute` renders `perm:"execute"`.
- SUBJECT: `exe=/usr/sbin/foo` renders on the subject side; the concrete path is
  extracted into `subjectPaths:["/usr/sbin/foo"]` (f2 section 2.2).
- OBJECT: renders both attrs in source order, `ftype=%mimes filehash=<64 hex>`
  (lossless `Display for Rule`, with the SetRef rendered verbatim as `%mimes`).
  Neither `ftype=` nor `filehash=` is a path, so `objectPaths:[]`.
- HASH: the inline `filehash=` is the strongest static pin (f2 section 2.3,
  line 100), so `hash` = the literal 64-hex value, `hashOrigin:"rule-filehash"`,
  `hashAlgorithm:"SHA256"` (64 hex -> SHA256). It also determines `scope:"hash"`
  (hash wins over the `exe=` path and the `ftype=` type, same specificity
  precedence as `combo-exe-and-filehash` and `combo-trust-and-ftype`).
- SET EXPANSION: the grant references `%mimes`, so `setExpansions` carries
  `"%mimes" -> ["application/x-executable", "application/x-sharedlib"]` (sorted;
  f2 section 2.2). The `filehash=` pin and the `%mimes` SetRef coexist on the
  object side without interfering.
- SOURCE: `source:{file:"C7-multi.rules", line:2}`.
- The 64-hex value is a deterministic placeholder (static inline pin,
  `against_trustdb:false`, no trust-DB capture).
