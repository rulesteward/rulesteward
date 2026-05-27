# Contributing to RuleSteward

Thanks for your interest. This document covers the local-dev workflow, the
shape of a useful first contribution, and the conventions PRs are expected
to follow.

## Local dev

The CI gates are reproducible locally. The full re-run is:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo llvm-cov --workspace --locked --fail-under-lines 80
```

A `justfile` at the repo root wraps the above as `just ci`. The
`rust-toolchain.toml` pins the channel so a fresh clone bootstraps the
right toolchain on first `cargo` invocation; no `rustup install` step
needed.

## How to add a new lint code

The fapolicyd module is the worked example. Each lint code (E02, E03, E04,
E05, W07) lives as its own file under
`crates/rulesteward-fapolicyd/src/lints/` with the diagnostic builder, the
test fixtures, and the `#[cfg(test)]` module side by side. Copy the shape
of an existing code, register the new code in `lints/mod.rs`, and add
fixture-driven tests; the CI gate enforces 80% line coverage.

## Good first issue

Issues labeled `good-first-issue` are a curated entry point. Comment on
the issue to claim it before opening a PR, so the maintainer can flag any
in-flight work that would conflict.

## PR review

Issues and PRs are reviewed on a solo-dev best-effort basis. Filing a PR
with a clear summary, a passing CI run, and a checked-off PR template
checklist is the fastest path to review.

## Commit authorship

All commits are user-authored. Do not add `Co-Authored-By: Claude` or
any other AI-attribution trailer to a commit message. This applies even
if the commit was drafted with AI assistance.

## License

By contributing, you agree that your contributions are licensed under the
project's Apache-2.0 license (engine) or BSD-3-Clause (rule templates),
matching the existing license boundary.
