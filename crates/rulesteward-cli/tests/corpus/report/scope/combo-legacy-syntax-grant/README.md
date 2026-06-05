# combo-legacy-syntax-grant

- **class:** scope
- **edge_case_axis:** scope

## Intent

A grant written in the LEGACY (non-colon) fapolicyd syntax
(`decision [perm=X] subj... obj...`, no `:` separator) that still maps to the SAME
section-3.2 register envelope a modern rule would. The syntax flavor affects the
lossless round-trip rendering of the WHOLE line, NOT the per-side register fields,
so the register row is flavor-agnostic.

## Input

One file `C6-legacy.rules`:

```
allow uid=0 path=/usr/bin/sh
```

This is a legacy-flavor rule: no colon, and `perm=` is omitted. It is the exact
grounded form the parser's `legacy_simple_subject_object_split` test parses
(`parser/grammar.rs`): subject `uid=0`, object `path=/usr/bin/sh`,
`SyntaxFlavor::Legacy`. The positional split anchors on the first object-only
attribute (`path`, object-only in the legacy dialect, `grammar.rs:234-273`).

No `--against-trustdb`, no `--diff-against`.

## Why the golden output is correct (f2 sections 2.2 / 2.3 / 3.2)

- One allow-family `Entry::Rule` -> one register row, `loadIndex:1`,
  `source.line:1`. The legacy flavor produces the same `Entry::Rule` shape as
  modern (`ast.rs:3-6` - both flavors produce a unified `Rule`), so the register
  walker treats it identically.
- `perm=` is omitted, so `Rule::perm` is `None`, which DEFAULTS to `open`
  (f2 section 2.2: "perm: Rule::perm (default open)"; same as the
  `perm-default-open` scenario). Hence `perm:"open"`.
- The register's `subject` / `object` fields render `Rule::subject` and
  `Rule::object` SEPARATELY (each side rendered via `Display`), so they are
  `"uid=0"` and `"path=/usr/bin/sh"` respectively - the legacy no-colon rendering
  only matters for whole-line round-trip, not for the per-side register strings.
- `path=` is a concrete object path: `scope:"path"`,
  `objectPaths:["/usr/bin/sh"]` (f2 section 2.2 path extraction). `uid=` narrows
  the subject but is not a path: `subjectPaths:[]`.
- No inline `filehash=`/`sha256hash=`, no `--against-trustdb`: `hash:null`,
  `hashOrigin:"none"`, `hashAlgorithm:null`.
- No SetRef: `setExpansions:{}`.
