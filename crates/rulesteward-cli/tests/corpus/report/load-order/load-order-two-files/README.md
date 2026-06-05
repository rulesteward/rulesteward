# load-order-two-files

- **class:** load-order
- **edge_case_axis:** load-order

## Intent

Two rule files with distinct numeric prefixes. The per-grant `loadIndex`
reflects `fagenrules_cmp` load order across files, and each row's
`source.file` correctly names the file the grant came from (f2 sections
2.4 / 3.2).

## Input

- `rules.d/10-a.rules`: `allow perm=open all : all`.
- `rules.d/90-z.rules`: `allow perm=execute all : trust=1`.
- Flags: none (no `--against-trustdb`, no `--diff-against`).

## Load order (fagenrules_cmp)

`fagenrules_cmp` natural-sorts on file name (`load_order.rs`): the digit
run `10` < `90`, so `10-a.rules` loads before `90-z.rules`. Thus:

- loadIndex 1 -> the `all : all` grant, `source.file = "10-a.rules"`.
- loadIndex 2 -> the `execute / trust=1` grant,
  `source.file = "90-z.rules"`.

## golden-register.json

The §3.2 register: two grants in load order. Grant 1 is scope `all` from
`10-a.rules:1`; grant 2 is scope `trust` from `90-z.rules:1`. Without
`--against-trustdb` the `trust=1` grant is not enumerated, so its
`hashOrigin` is `none`.

## Oracle / ground truth

Load order is computed via `fagenrules_cmp` (`load_order.rs`: GNU
`ls -v`-style natural sort, digit run `10` < `90`). Mapping is otherwise
pure spec-derived (f2 section 3.2); no trust-DB digests captured.
