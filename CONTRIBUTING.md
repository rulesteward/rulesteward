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

`scripts/check-dac-guard.sh` (#467) is a static gate that enforces this;
CI's lint job runs it directly as `bash scripts/check-dac-guard.sh`, and
`just ci` (via the `dac-guard` recipe) runs the same script locally. Every
`from_mode(0o000)` or `from_mode(0o555)`
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

Run `just dac-guard` locally to check before pushing (the local equivalent
of the `bash scripts/check-dac-guard.sh` step CI's lint job runs).

The gate's per-function scoping is deliberately fail-closed around nested
`fn` items: a `fn` declared inside another fn's body splits the outer fn
into two search regions at that point, so a `CAP_DAC_OVERRIDE` marker
placed after a nested `fn` is not credited to a `from_mode(...)` call
before it even though both are lexically inside the same outer fn - place
the marker before the nested item (or use the `dac-override-exempt:`
hatch) if you hit this shape.

## Differential oracle contract

A "differential" here means checking RuleSteward's answer against the real
subsystem's answer (the fapolicyd daemon, `checkmodule`, `auditctl`,
`systemd-sysctl`, `visudo`) rather than against a hand-authored expectation.
Hand-authored expectations have repeatedly frozen the wrong answer; a daemon
cannot.

Every differential is built in **two tiers, and only the live tier may skip**:

- **Tier 1, the replay test** (`crates/<crate>/tests/<x>_oracle.rs`). Pure Rust.
  Reads a committed corpus of `(input, recorded-oracle-verdict)` pairs and
  asserts the product agrees. No docker, no root, no network, no tool on PATH,
  **so there is no skip path at all.** Runs in `just test` / `just ci` and in
  every CI container. Model: `crates/rulesteward-selinux/tests/selinux_corpus_oracle.rs`.
- **Tier 2, the capture/drift tool.** Re-derives the oracle from the live
  subsystem and fails on drift. The only part allowed to skip. Model:
  `tools/sshd-probe-update` + `just diff-sshd`.

This split is why a missing docker daemon degrades the guarantee from "nothing
was checked" to "the oracle was not re-derived."

### Exit codes

| rc | meaning |
|---|---|
| 0 | verified clean. The success line MUST carry a non-zero count, e.g. `OK (0 drift, 214 scenarios)` |
| 1 | drift: the product and the oracle disagree |
| 2 | tool/environment error: unparseable transcript, zero data rows, or the oracle was required but missing |
| 3 | precondition unmet, a legitimate skip (no docker, image absent) |

`3` exists so a developer without docker gets an honest skip while CI, which
sets `RS_ORACLE_REQUIRED=1`, turns the same condition into a hard failure.
Collapsing it into `0` is exactly the bug that made `just diff-fapolicyd` report
success for six weeks while checking nothing (#572).

### Three rules every harness must satisfy

1. **Assert the count, do not merely print it.** `assert!(scenarios.len() >= FLOOR)`
   before reporting success. The older `tools/*-update` print
   `OK (0 drift, {N} controls)` but never assert `N > 0`; new harnesses must.
   `OK (0 drift, 0 scenarios)` has to be unreachable by construction.
2. **Carry a positive control.** Every corpus holds at least one input the
   oracle must REJECT and one it must ACCEPT. If both come back with the same
   verdict, the *oracle* is broken: exit 2, never 0 and never 1. Where an oracle
   is captured per-version, add a control pinning a known version divergence -
   it is the only thing that detects "all three transcripts are secretly the
   same file".
3. **Parse fail-closed.** Empty body, header-only input, or zero data rows must
   return an error, never `Ok(vec![])`. See
   `tools/fapolicyd-probe-update/src/transcript.rs`.

The through-line: **an instrument must prove it saw something.** "Nothing fired"
and "nothing ran" produce identical output otherwise, and every one of this
project's silent-gate failures has been that confusion. The mechanical guard for
the narrower case of out-of-repo inputs is `just no-mnt-guard`.

## Commit authorship

All commits are user-authored. Do not add `Co-Authored-By: Claude` or
any other AI-attribution trailer to a commit message. This applies even
if the commit was drafted with AI assistance.

## License

By contributing, you agree that your contributions are licensed under the
project's Apache-2.0 license (engine) or BSD-3-Clause (rule templates),
matching the existing license boundary.
