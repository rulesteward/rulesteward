# Mutation baseline - `rulesteward-sink`

## Baseline

| Metric | Value |
|---|---|
| Tool | `cargo-mutants` 27.0.0 |
| Command | `cargo mutants -p rulesteward-sink` (config: `.cargo/mutants.toml`) |
| Mutants tested | 5 |
| **Caught (killed by tests)** | **4** |
| **Missed (survived - the regression-bait number)** | **0** |
| Unviable (mutation produced uncompilable code) | 1 |
| Timeouts | 0 |
| **CI gate** | non-zero exit on any survivor (cargo-mutants 27 default) |

A CI build that surfaces even one new survivor will fail the mutants
workflow (nightly cron + `run-mutants` PR label).

## Scope

Per `.cargo/mutants.toml`, the sink crate is examined whole:

```
examine_globs = [ ..., "crates/rulesteward-sink/src/**/*.rs" ]
exclude_globs = [ "**/tests/**", "**/format.rs", "**/ast.rs" ]
exclude_re    = [ "NdjsonStdoutSink>::(emit|flush)" ]
```

The real serialization logic lives in the generic `NdjsonSink<W>` core, which
is mutation-tested over an in-memory `Vec<u8>` writer (the unit tests assert the
exact emitted bytes, so emit/flush mutations are killed).

## The two excluded stdout delegations

`NdjsonStdoutSink::emit` and `NdjsonStdoutSink::flush` are one-line forwards to
the generic core wrapping `std::io::Stdout`. Replacing either body with `Ok(())`
is an **equivalent mutant**: an in-process test cannot capture the real stdout
byte stream, so the mutation is unobservable. The identical write/flush logic is
already killed via the generic `NdjsonSink<Vec<u8>>` path; only the thin
real-stdout forwarding survives. These two mutants are excluded by name in
`exclude_re` (not via `#[mutants::skip]`) so the rationale stays in reviewable
config rather than scattered as source attributes.

## Re-run

```
cargo mutants -p rulesteward-sink
```

Expect `0 missed`. Any survivor is a real coverage gap (or a new equivalent
mutant that must be justified in `exclude_re` with a comment, like the two
above).
