# card-empty-only-setdef

## Intent

A file containing only a set definition and a comment, no rules at all; golden
`grants` is empty. This proves that an `Entry::SetDefinition` (a `%name=...`
line) is NOT mistaken for a grant and that a file with zero allow-family rules
emits `grants: []`.

## edge_case_axis

cardinality

## Input

`rules.d/01-setonly.rules`:

```
# just a set, no rules
%langs=text/x-perl,text/x-python
```

## Golden output reasoning (f2 section 3.2 mapping)

- The comment line is an `Entry::Comment`, not a rule.
- `%langs=text/x-perl,text/x-python` parses to an `Entry::SetDefinition`, not an
  `Entry::Rule`; it defines a macro but no rule references it, so it does not
  appear anywhere in the register (set expansions only attach to a grant that
  uses a `SetRef`).
- No allow-family `Rule` exists, so `grants` is `[]`.
- No `--against-trustdb` and no `--diff-against`: no `trustJoin`, no drift.
