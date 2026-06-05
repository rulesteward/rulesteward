# card-empty-no-grants

## Intent

A file with only comments, blanks, and a deny rule yields zero allow-grants;
golden `grants` is an empty array. This exercises the noise-filter path: the
register enumerates ONLY allow-family decisions (`allow`, `allow_audit`,
`allow_syslog`, `allow_log` per f2 section 2.1), so a lone `deny_audit` rule
produces no register row. Comments and blank lines are also non-grant entries.

## edge_case_axis

cardinality

## Input

`rules.d/00-empty.rules`:

```
# no allow grants here

deny_audit perm=any all : all
```

## Golden output reasoning (f2 section 3.2 mapping)

- The comment (`Entry::Comment`) and blank line (`Entry::Blank`) are not rules.
- `deny_audit` is a deny-family decision, NOT in the allow family enumerated by
  the register, so it is excluded.
- No allow-family `Rule` remains, so `grants` is `[]`.
- No `--against-trustdb` and no `--diff-against`: no `trustJoin`, no drift.
