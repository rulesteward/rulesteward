# set-expansion-single-member

## Intent

A single-member set expansion, to confirm the `members` array shape when a set
has exactly one element.

`%one=text/x-shellscript` is defined on line 1; the grant on line 2
(`allow perm=open all : ftype=%one`) references it via `ftype=%one`. The register
row therefore carries `setExpansions: {"%one": ["text/x-shellscript"]}` (one
member, sorted trivially). The `object` predicate renders the SetRef verbatim as
`ftype=%one` (lossless `Display for AttrValue` -> `%name`), while the resolved
members live only in `setExpansions`.

Scope is `ftype` (the only keying predicate). `hashOrigin: none`, `hash: null`,
`hashAlgorithm: null` (type-scoped grant, no inline hash, honest none per f2
section 2.4). `subjectPaths` / `objectPaths` empty (no path-valued attr).
`source.line` is 2 (the grant line, NOT the setdef line); `loadIndex` is 1 (the
set definition is not a grant and is not load-indexed).

## edge_case_axis

`set-expansion` - exercises the SetRef-resolution axis with a single-member set,
confirming the members array is a one-element list, not a bare string.
