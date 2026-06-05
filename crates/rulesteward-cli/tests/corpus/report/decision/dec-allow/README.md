# dec-allow

## Intent

The `allow` decision keyword renders `decision: "allow"`. Baseline of the
decision axis: the plain allow-family base decision produces the string `allow`
in the register row.

## edge_case_axis

decision

## Input

`rules.d/30-allow.rules`:

```
allow perm=execute all : trust=1
```

## Golden output reasoning (f2 section 3.2 mapping)

- `decision`: `allow` (the `Decision::Allow` variant, Display string `allow` per
  `format.rs`).
- `perm`: `execute`.
- `subject`: `all`, `object`: `trust=1`.
- `scope`: `trust` (object-side `trust=1`).
- `subjectPaths` / `objectPaths`: `[]` (no `exe=`/`path=`/`dir=`).
- `hash` null, `hashOrigin` none, `hashAlgorithm` null (no inline hash, no
  `--against-trustdb`).
- `setExpansions` `{}`.
- `source`: `{ "file": "30-allow.rules", "line": 1 }`; `loadIndex` `1`.
