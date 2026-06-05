# set-expansion-two-refs-one-rule

## Intent

One rule referencing TWO different `%macro` sets - one on the subject side
(`exe=%tools`) and one on the object side (`ftype=%mimes`). BOTH SetRefs appear
as keys in the single grant's `setExpansions`.

## edge_case_axis

`set-expansion` - exercises multi-SetRef resolution within ONE grant, proving
`setExpansions` is keyed by SetRef name and can carry more than one entry for a
single register row (one per distinct `%set` referenced, on either side).

## Input

One file `75-tworefs.rules`:

```
%tools=/usr/bin/zip,/usr/bin/tar
%mimes=text/x-python,application/x-executable
allow perm=execute exe=%tools : ftype=%mimes
```

`%tools` (line 1) and `%mimes` (line 2) are both defined; the single grant
(line 3) references `%tools` in its subject `exe=` and `%mimes` in its object
`ftype=`. No `--against-trustdb`, no `--diff-against`.

## Why the golden output is correct (f2 sections 2.2 / 3.2)

- One allow-family grant -> one register row, `loadIndex:1`, `source.line:3`
  (the two set-definition lines are not grants and are not load-indexed).
- `perm=execute` renders `perm:"execute"`.
- Subject renders `exe=%tools`, object renders `ftype=%mimes` (each SetRef
  renders verbatim as `%name` via `Display for AttrValue`, `format.rs:42`; the
  concrete members live only in `setExpansions`).
- `subjectPaths:[]` / `objectPaths:[]`: `exe=%tools` is a SetRef, NOT a concrete
  path string, so no path is extracted into `subjectPaths` (path extraction is
  over literal `exe=`/`path=`/`dir=` VALUES, f2 section 2.2; a `%set` reference
  is not a literal path). `ftype=` carries no path either.
- `setExpansions` carries BOTH SetRefs the grant references, each mapped to its
  concrete members in SORTED order (f2 section 2.2 `set_expansion`):
  - `"%mimes"` -> `["application/x-executable", "text/x-python"]` (definition
    order was `text/x-python,application/x-executable`; the register sorts).
  - `"%tools"` -> `["/usr/bin/tar", "/usr/bin/zip"]` (definition order was
    `/usr/bin/zip,/usr/bin/tar`; the register sorts).
- Scope keys on the object predicate kind: `ftype` (the object's keying attr is
  `ftype=`; the subject's `exe=%tools` narrows the subject but the register's
  `scope` reflects the object predicate, consistent with `scope-ftype-object`).
  `hash:null`, `hashOrigin:"none"`, `hashAlgorithm:null` (no inline hash).
