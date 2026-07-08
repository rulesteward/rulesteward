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

The fapolicyd module is the worked example. Each lint code (fapd-E02,
fapd-E03, fapd-E04, fapd-E05, fapd-W07) lives as its own file under
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

## DAC guard: root-safe chmod deny-mode fixtures

Some tests exercise a permission-denied code path by chmod'ing a file or
directory to a restrictive mode (`from_mode(0o000)` for read-deny,
`from_mode(0o555)` for write-deny) and checking the resulting error. RHEL-
family distro CI runs the suite as root, and root bypasses Linux DAC
(discretionary access control) via `CAP_DAC_OVERRIDE` - the chmod still
"succeeds" on disk, but the denial never actually blocks the process, so
the assertion would silently pass for the wrong reason (or, before #464/#465,
outright fail under root). Every such test must probe the real precondition
and skip cleanly instead of assuming the deny lands:

```rust
if std::fs::File::open(&f).is_ok() {
    let _ = std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o644));
    eprintln!(
        "SKIP <test_name>: 0o000 is readable here (running as root / \
         CAP_DAC_OVERRIDE); cannot exercise the deny arm"
    );
    return;
}
```

See `crates/rulesteward-sysctld/tests/system.rs`
(`unreadable_search_directory_emits_a_file_level_f01`) for the canonical
worked example, and the 7 guards added across `crates/rulesteward-cli` in
#465 for more instances.

`scripts/check-dac-guard.sh` (wired into CI as `just dac-guard`, #467) is a
static gate that enforces this: every `from_mode(0o000)` or `from_mode(0o555)`
call under `crates/**/{src,tests}/**/*.rs` must have a `CAP_DAC_OVERRIDE`
marker (a comment or string literal containing that exact token) somewhere
in the *same function* as the call. If a fixture genuinely does not need the
guard (for example, an illustrative chmod whose assertions do not depend on
the denial actually being enforced), add an explicit escape hatch instead of
a `CAP_DAC_OVERRIDE` marker:

```rust
// dac-override-exempt: illustrative chmod only, no assertion in this
// fixture depends on the denial actually being enforced.
```

Run `just dac-guard` locally to check before pushing; the same command runs
in the PR-CI lint tier.

## Commit authorship

All commits are user-authored. Do not add `Co-Authored-By: Claude` or
any other AI-attribution trailer to a commit message. This applies even
if the commit was drafted with AI assistance.

## License

By contributing, you agree that your contributions are licensed under the
project's Apache-2.0 license (engine) or BSD-3-Clause (rule templates),
matching the existing license boundary.
