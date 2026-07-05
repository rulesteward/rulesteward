# Mutation baseline - `rulesteward-sudoers`

## Baseline (post-#433 refactor)

| Metric | Value |
|---|---|
| Tool | `cargo-mutants` 27.0.0 |
| Command | `cargo mutants -p rulesteward-sudoers --no-shuffle --re 'tokens\|lints/mod.rs\|lints/f01.rs' --test-workspace false` (config: `.cargo/mutants.toml`) |
| Mutants tested | 59 |
| **Caught (killed by tests)** | **56** |
| **Missed (survived - the regression-bait number)** | **0** |
| Unviable (mutation produced uncompilable code) | 3 |
| Timeouts | 0 |
| **CI gate** | non-zero exit on any survivor (cargo-mutants 27 default) |

A CI build that surfaces even one new survivor fails the mutants workflow
(nightly cron + `run-mutants` PR label). This table is scoped to the files the
#433 split touched (`lints/tokens/**`, `lints/f01.rs`, and the `lint` dispatcher
in `lints/mod.rs`); the whole-crate gate is the nightly `mutants.yml` run over
the full `examine_globs` scope.

## Scope

Per `.cargo/mutants.toml`, the sudoers crate is examined via:

```
examine_globs = [
    "crates/rulesteward-sudoers/src/parser.rs",
    "crates/rulesteward-sudoers/src/resolve.rs",
    "crates/rulesteward-sudoers/src/lints/**/*.rs",
]
```

The recursive `lints/**/*.rs` glob automatically covers the new `lints/tokens/`
subdirectory and `lints/f01.rs` created by the #433 split - no glob widening was
needed (a file outside `examine_globs` mutates zero times and silently
false-passes; staying under `lints/` avoids that vacuity trap). There is no
sudoers-specific `exclude_re` entry.

## Refactor identity (#433 - behavior-preserving split)

#433 split the 801-line `lints/tokens.rs` into per-subject submodules
(`tokens/{mod,shared,command_specs,group_subject,runas,defaults}.rs`), flattened
`check_defaults` by extracting a `check_defaults_scope` helper, and moved `f01`
into `lints/f01.rs`. It is strictly behavior-preserving: the 125-test inline
module is byte-identical (empty diff), all 378 sudoers unit tests pass unchanged,
and the emitted diagnostics are byte-identical.

Mutation before/after (same scoped command, run on the pre-split and post-split
trees):

| | Mutants | Caught | Missed | Unviable |
|---|---|---|---|---|
| Before (pre-split main `c72a7de`) | 57 | 54 | 0 | 3 |
| After (post-split) | 59 | 56 | 0 | 3 |

The `+2` mutants are the new `check_defaults_scope` helper (`-> bool with true`,
`-> bool with false`, and body variants); all are CAUGHT by the existing tests -
they are equivalents of the pre-split `if diags.len() > before { return }`
mutants (`> -> >=` = always-return, `> -> <` = never-return), which the
before-baseline already killed. `missed = 0` on both sides is the proof no
behavior or test-coverage gap was introduced by the split.
