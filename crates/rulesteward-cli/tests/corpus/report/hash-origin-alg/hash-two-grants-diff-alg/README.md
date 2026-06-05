# hash-two-grants-diff-alg

## Intent

Two allow-grants in one file, each pinned by an inline `filehash=` of a different
hex length, so `hashAlgorithm` varies row to row within a single register:

- Grant 1 (line 1): `filehash=<32 hex>` -> `hashAlgorithm: MD5`.
- Grant 2 (line 2): `filehash=<128 hex>` -> `hashAlgorithm: SHA512`.

Both rows are `hashOrigin: rule-filehash`, `scope: hash`. The hash value in each
row is the literal hex from the rule (no disk, no trust DB; 100% static per f2
section 2.3 item 1). Algorithm is inferred purely by hex length using the
project length convention 32=MD5, 40=SHA1, 64=SHA256, 128=SHA512
(`trustdb.rs:107-108,185-191`).

`subjectPaths` / `objectPaths` are empty (no `exe=`/`path=`/`dir=` value present;
`all` is not a path). `setExpansions` is `{}` (no SetRef in either rule).
`loadIndex` increments 1,2 in single-file load order; `source.line` tracks each
rule's line.

## edge_case_axis

`hash-origin-alg` - exercises the hashOrigin x hashAlgorithm axis, specifically
that the algorithm column is computed per-row by hex length and can differ
between two grants in the same file.
