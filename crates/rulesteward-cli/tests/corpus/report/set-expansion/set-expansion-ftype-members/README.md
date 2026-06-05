# set-expansion-ftype-members

## Intent

A `%macro` set used in an `ftype=` object predicate; the register row's
`setExpansions` shows the concrete, SORTED members of the set.

## edge_case_axis

`set-expansion` - exercises multi-member SetRef resolution in an object `ftype=`
predicate and confirms the members array is emitted in sorted order, independent
of the definition-line order.

## Input

One file `74-editors.rules`:

```
%editors=text/x-shellscript,text/x-python,text/x-perl
allow perm=open all : ftype=%editors
```

The set `%editors` is defined on line 1 in NON-sorted order
(`text/x-shellscript, text/x-python, text/x-perl`); the grant on line 2 references
it via `ftype=%editors`.

No `--against-trustdb`, no `--diff-against`.

## Why the golden output is correct (f2 sections 2.2 / 3.2)

- The single allow-family grant on line 2 yields one register row,
  `loadIndex:1`, `source.line:2` (the set-definition line is not a grant and is
  not load-indexed; mirrors `set-defined-but-unused` and `set-no-expansion`).
- `perm=open` renders `perm:"open"`.
- Subject side is `all`; object side is `ftype=%editors` (the SetRef renders
  verbatim as `%editors` via `Display for AttrValue`, `format.rs:42`).
- `ftype=` is a MIME-type predicate, not a path or hash: `scope:"ftype"`,
  `subjectPaths:[]`, `objectPaths:[]` (an ftype value carries no path, f2
  section 2.4).
- No inline `filehash=`/`sha256hash=`, no `--against-trustdb`: `hash:null`,
  `hashOrigin:"none"`, `hashAlgorithm:null` (type-scoped, honest none).
- The grant references `%editors`, so `setExpansions` carries one key,
  `"%editors"`, mapping to the concrete members. Per f2 section 2.2
  (`set_expansion` = the `Entry::SetDefinition` values for the SetRef), the
  members are emitted SORTED: `["text/x-perl", "text/x-python",
  "text/x-shellscript"]` (note the definition-line order was reversed; the
  register sorts, so the array does not echo the source order).
