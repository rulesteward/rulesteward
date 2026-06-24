# Mutation baseline - `rulesteward-fapolicyd` + `rulesteward-core`

## Baseline

| Metric | Value |
|---|---|
| Tool | `cargo-mutants` 27.0.0 |
| Command | `cargo mutants --no-shuffle` (config: `.cargo/mutants.toml`) |
| Mutants generated | 205 |
| **Caught (killed by tests)** | **167** |
| **Missed (survived - the regression-bait number)** | **0** |
| Unviable (mutation produced uncompilable code) | 38 |
| Timeouts | 0 |
| **CI gate** | non-zero exit on any survivor (cargo-mutants 27 default) |

A CI build that surfaces even one new survivor will fail the mutants
workflow (nightly cron + `run-mutants` PR label).

## Scope

Per `.cargo/mutants.toml`:

```
examine_globs = [
    "crates/rulesteward-core/src/diagnostic.rs",
    "crates/rulesteward-fapolicyd/src/parser/**/*.rs",
    "crates/rulesteward-fapolicyd/src/lints/**/*.rs",
    "crates/rulesteward-fapolicyd/src/attrs.rs",
    "crates/rulesteward-fapolicyd/src/trustdb.rs",
    "crates/rulesteward-sink/src/**/*.rs",
    "crates/rulesteward-cli/src/commands/trustdb_compute.rs",
]
exclude_globs = [
    "**/tests/**",
    "**/format.rs",
    "**/ast.rs",
]
```

`trustdb.rs` is in scope (it is the only `unsafe` code in the project - the
`heed`/LMDB mmap boundary - so it warrants the strongest gate) along with the
`rulesteward-sink` crate (the `Event` stable wire schema). `format.rs` (Display
impls) is excluded because mutation-noise is heavy there - most mutations on a
Display impl are textual nudges that the round-trip property already catches
semantically. `ast.rs` is excluded because it's plain type definitions with no
behaviour to mutate. The `rulesteward-cli` crate is mostly outside the net
(mechanical glue covered by e2e tests), with ONE exception:
`commands/trustdb_compute.rs` holds the pure trust-DB diff/stale algorithms
(path-grouping, value-multiset comparison, stale filtering), extracted out of the
I/O orchestration precisely so they can be exact-unit-tested and mutation-gated.
The orchestration (`commands/fapolicyd.rs`) and the Display-style renderers
(`output/trustdb.rs`) stay excluded.

## How the baseline reached zero

The first run produced 4 survivors:

| File | Line | Mutation | Killed by |
|---|---|---|---|
| `parser/mod.rs` | 69 | `b == b' ' \|\| b == b'\t'` → `&&` | `whitespace_only_line_is_blank_entry` (new) |
| `lints/layout.rs` | 42 | `is_file() && extension == "rules"` → `\|\|` | superseded -- see note below |
| `lints/source_scan.rs` | 27 | `idx == last_idx && raw_line.is_empty()` → `\|\|` | `w03_continues_scanning_past_leading_blank_lines` (new) |
| `lints/source_scan.rs` | 27 | `idx == last_idx && raw_line.is_empty()` → `idx != last_idx ...` | `w03_continues_scanning_past_leading_blank_lines` (new) |

Three targeted unit tests were added; second run came back at 0 survivors.

> **`lints/layout.rs:42` row superseded (issue #274, fapd-F02 widen).** The
> original survivor was killed by `check_layout_silent_when_rules_d_only_holds_subdirectory`.
> The fapd-F02 widen to full `fagenrules` `ls | wc -w` parity removes the
> `&& extension == "rules"` clause entirely (a non-dotfile entry of ANY extension,
> file OR subdirectory, now counts), so that exact mutant no longer exists in the
> code. The test was inverted/renamed to
> `check_layout_fires_when_rules_d_has_only_subdir_named_dot_rules` (a `nested.rules/`
> subdir now FIRES). The widened `directory_has_rules_files` predicate is covered by
> the fresh widen tests in `lints/layout.rs` and re-baselined by the next mutation run.

Session 3c-B added `lints/reachability.rs` (fapd-W01 rule shadowing); its
mutants are all caught (three `subsumes_value` survivors were killed with
targeted unit tests during initial development), so the baseline stays at 0
missed.

Session 3c-B also added fapd-S02 (`lints/macros.rs::s02`, macro definition
not at file top). Its mutants - `replace s02 with vec![]`, `delete match arm
Entry::Rule(_)`, and both `seen_rule` guard flips - are all caught by the
inline `s02_*` unit tests, so the baseline stays at 0 missed.

## Re-running locally

```bash
cargo install cargo-mutants --locked      # one-time, ~5 min
cargo mutants --no-shuffle                # ~3 min on this codebase
```

The config at `.cargo/mutants.toml` is auto-loaded.

## Re-running in CI

The `.github/workflows/mutants.yml` workflow runs on three triggers:

1. **Nightly cron** - `0 4 * * *` (04:00 UTC).
2. **PR label** - add the `run-mutants` label to any open PR.
3. **Manual** - `workflow_dispatch`.

It uses `taiki-e/install-action@v2` to install `cargo-mutants` from a
prebuilt binary (seconds, not minutes), then runs the same command above;
cargo-mutants 27 exits non-zero by default on a genuine survivor, failing
the workflow.

## When the baseline should change

Bump the baseline number (and update `mutants.yml`) only after a
deliberate review of the new survivor. Acceptable reasons:

- The mutated line is in defensive error-handling that can't be reached
  in practice (rare - add a `#[allow(...)]` or refactor to remove the
  unreachable branch first).
- The mutation produces semantically-identical behaviour (the function
  is symmetric in the mutated direction).

Unacceptable reason: "we couldn't easily kill it." Add the test.
