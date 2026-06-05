# card-single-allow-all

## Intent

The simplest possible single grant: `allow perm=open all : all`. One register
row, the broadest possible scope (`all : all`), no narrowing predicate, no path,
no hash.

## edge_case_axis

cardinality

## Input

`rules.d/10-single.rules`:

```
allow perm=open all : all
```

## Golden output reasoning (f2 section 3.2 mapping)

- `decision`: `allow` (the allow-family base decision).
- `perm`: `open` (explicit `perm=open`).
- `subject`: `all` (Display-rendered subject side, a single `Attr::All`).
- `object`: `all` (Display-rendered object side, a single `Attr::All`).
- `subjectPaths` / `objectPaths`: both `[]` (no `exe=`/`path=`/`dir=` value).
- `hash`: `null`, `hashOrigin`: `none`, `hashAlgorithm`: `null` (no inline hash,
  no `--against-trustdb`).
- `scope`: `all` (`all : all`, no narrowing predicate beyond uid/gid).
- `setExpansions`: `{}` (no `SetRef` used).
- `source`: `{ "file": "10-single.rules", "line": 1 }` (1-based line).
- `loadIndex`: `1` (first and only enumerated grant).
