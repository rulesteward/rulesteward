# Mutation baseline - `rulesteward-sshd`

## Baseline (post-#432 refactor)

| Metric | Value |
|---|---|
| Tool | `cargo-mutants` 27.0.0 |
| Command | `cargo mutants -p rulesteward-sshd --no-shuffle --re 'structural' --test-workspace false` (config: `.cargo/mutants.toml`) |
| Mutants tested | 162 |
| **Caught (killed by tests)** | **144** |
| **Missed (survived - the regression-bait number)** | **0** |
| Unviable (mutation produced uncompilable code) | 18 |
| Timeouts | 0 |
| **CI gate** | non-zero exit on any survivor (cargo-mutants 27 default) |

A CI build that surfaces even one new survivor fails the mutants workflow
(nightly cron + `run-mutants` PR label). This table is scoped to the files the
#432 split touched (the `lints/structural/**` tree); the whole-crate gate is the
nightly `mutants.yml` run over the full `examine_globs` scope.

## Scope

Per `.cargo/mutants.toml`, the sshd crate is examined via:

```
examine_globs = [
    "crates/rulesteward-sshd/src/parser.rs",
    "crates/rulesteward-sshd/src/lints/**/*.rs",
]
```

The recursive `lints/**/*.rs` glob automatically covers the new
`lints/structural/` subdirectory created by the #432 split - no glob widening was
needed (a file outside `examine_globs` mutates zero times and silently
false-passes; staying under `lints/` avoids that vacuity trap).

### `glob_match` timeout exclusions (function-anchored)

`glob_match`'s cursor advances include three NON-TERMINATING advances (mutating
`+=` to `*=` hangs the loop rather than producing a wrong answer, so they hit the
per-mutant timeout floor and cannot be killed by an assertion). #432 extracted
these three into a dedicated `glob_advance` helper so the exclusion is
FUNCTION-anchored (`matching\.rs:.*in glob_advance`) instead of line-anchored -
retiring the anchor-drift failure class that reddened the nightly (hotfix #431).
The `exclude_re` entries are:

```
'w07\.rs:.*replace && with || in name_instances_have_common_witness'
'matching\.rs:.*replace + with * in glob_match'
'matching\.rs:.*replace + with * in glob_advance'
'matching\.rs:.*replace glob_advance -> usize with 0'
'matching\.rs:.*replace glob_advance -> usize with 1'
'matching\.rs:.*replace parse_negated_port_list -> Vec<u32> with'
```

The two TERMINATING char-match advances (`p += 1; v += 1;` in `glob_match`) and
the killable `glob_advance` `+ -> -` (usize underflow) are deliberately LEFT
in-gate; only the genuinely non-terminating mutants are excluded.

## Refactor identity (#432 - behavior-preserving split)

#432 split the 4132-line `lints/structural.rs` into a `structural/` directory
module (`mod.rs`, `matching.rs`, and one submodule per pass e01/e02/e03/e04/w05/
w07), and extracted `glob_advance`. It is strictly behavior-preserving: the 137
inline tests and their 245 assertion lines are byte-identical (empty diff), all
sshd tests pass unchanged, and the emitted diagnostics are byte-identical.

Mutation before/after (same scoped command, run on the pre-split and post-split
trees):

| | Mutants | Caught | Missed | Unviable | Timeout |
|---|---|---|---|---|---|
| Before (pre-split main `c72a7de`) | 164 | 146 | 0 | 18 | 0 |
| After (post-split) | 162 | 144 | 0 | 18 | 0 |

The `-2` mutants are the intended `glob_advance` extraction: the three old
`x += 1` advance sites lose their `+= -> -=` in-gate mutants (`-3`) and
`glob_advance` adds back exactly one killable `+ -> -` (`+1`) = net `-2`.
`missed = 0` AND `timeout = 0` on both sides is the proof: no new survivor, and
the three non-terminating mutants stay correctly excluded (a timeout of 0 is only
possible if the function-anchored exclusions bind - an escaped mutant would hang
180s and register as a timeout).
