# Mutation baseline - `rulesteward-fapolicyd` + `rulesteward-core`

## Baseline

| Metric | Value |
|---|---|
| Tool | `cargo-mutants` 27.0.0 |
| Command | `cargo mutants --no-shuffle` (config: `.cargo/mutants.toml`) |
| Mutants generated | 93 |
| **Caught (killed by tests)** | **71** |
| **Missed (survived - the regression-bait number)** | **0** |
| Unviable (mutation produced uncompilable code) | 22 |
| Timeouts | 0 |
| **CI gate** | `--error-on-survival 0` |

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
]
exclude_globs = [
    "**/tests/**",
    "**/format.rs",
    "**/ast.rs",
]
```

`format.rs` (Display impls) is excluded because mutation-noise is heavy
there - most mutations on a Display impl are textual nudges that the
round-trip property already catches semantically. `ast.rs` is excluded
because it's plain type definitions with no behaviour to mutate.

## How the baseline reached zero

The first run produced 4 survivors:

| File | Line | Mutation | Killed by |
|---|---|---|---|
| `parser/mod.rs` | 69 | `b == b' ' \|\| b == b'\t'` → `&&` | `whitespace_only_line_is_blank_entry` (new) |
| `lints/layout.rs` | 42 | `is_file() && extension == "rules"` → `\|\|` | `check_layout_silent_when_rules_d_only_holds_subdirectory` (new) |
| `lints/source_scan.rs` | 27 | `idx == last_idx && raw_line.is_empty()` → `\|\|` | `w03_continues_scanning_past_leading_blank_lines` (new) |
| `lints/source_scan.rs` | 27 | `idx == last_idx && raw_line.is_empty()` → `idx != last_idx ...` | `w03_continues_scanning_past_leading_blank_lines` (new) |

Three targeted unit tests were added; second run came back at 0 survivors.

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
prebuilt binary (seconds, not minutes), then runs the same command above
with `--error-on-survival 0` so a regression fails the workflow.

## When the baseline should change

Bump the baseline number (and update `mutants.yml`) only after a
deliberate review of the new survivor. Acceptable reasons:

- The mutated line is in defensive error-handling that can't be reached
  in practice (rare - add a `#[allow(...)]` or refactor to remove the
  unreachable branch first).
- The mutation produces semantically-identical behaviour (the function
  is symmetric in the mutated direction).

Unacceptable reason: "we couldn't easily kill it." Add the test.
