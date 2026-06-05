# card-multi-many-mixed

## Intent

Eight allow grants spanning several scopes in one file; stress row ordering and
heterogeneity. Covers trust, path (exe + path), dir, ftype, pattern, an inline
SHA256 filehash, and the broad `all : all` scope in a single register, with
`loadIndex` incrementing 1..8.

## edge_case_axis

cardinality

## Input

`rules.d/25-many.rules`:

```
allow perm=execute all : trust=1
allow perm=open exe=/usr/bin/rpm : all
allow perm=any uid=0 : dir=/var/tmp/
allow perm=open all : ftype=application/x-sharedlib
allow perm=any pattern=ld_so : all
allow perm=open uid=0 : path=/etc/hosts
allow perm=open all : filehash=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
allow perm=open all : all
```

## Golden output reasoning (f2 section 3.2 mapping)

| line | predicate | scope | paths | hash |
|---|---|---|---|---|
| 1 | `all : trust=1` | trust | - | none |
| 2 | `exe=/usr/bin/rpm : all` | path | subjectPaths `/usr/bin/rpm` | none |
| 3 | `uid=0 : dir=/var/tmp/` | dir | objectPaths `/var/tmp/` | none |
| 4 | `all : ftype=application/x-sharedlib` | ftype | - | none |
| 5 | `pattern=ld_so : all` | pattern | - | none |
| 6 | `uid=0 : path=/etc/hosts` | path | objectPaths `/etc/hosts` | none |
| 7 | `all : filehash=<64hex>` | hash | - | rule-filehash / SHA256 |
| 8 | `all : all` | all | - | none |

- Row 7 carries the inline 64-hex `filehash=` value: `hash` = the hex string,
  `hashOrigin` `rule-filehash`, `hashAlgorithm` `SHA256` (64 hex chars -> SHA256
  by the length convention). `scope` `hash` (hash-pinned). The hash hex appears
  both in the rendered `object` string and in the `hash` field.
- `pattern=` (row 5) is a subject-only attr and is NOT a path; subjectPaths `[]`.
- `uid=` (rows 3, 6) narrows the subject but extracts no path.
- All rows: `setExpansions` `{}` (no `SetRef`). `source.file` `25-many.rules`,
  lines 1..8; `loadIndex` 1..8 in file load order.
