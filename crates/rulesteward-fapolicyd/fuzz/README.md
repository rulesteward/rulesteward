# rulesteward-fapolicyd fuzz harness

Fuzz targets for the `rulesteward-fapolicyd` crate, exercising the public
parser and the trust-DB value parser against arbitrary byte inputs.

**Nightly required.** `cargo-fuzz` relies on `libfuzzer` instrumentation that
is only available on nightly. All commands below use `cargo +nightly fuzz`.

## Targets

| Target | Function under test | Invariant |
|---|---|---|
| `parse_rules` | `parse_rules_file(&str, &Path)` | Never panics; always returns `Ok` or `Err(Vec<Diagnostic>)` |
| `parse_trust_value` | `trustdb::parse_trust_value(&[u8])` | Never panics; always returns `Ok` or `Err(MalformedValue)` |

## Prerequisites

```bash
# Install cargo-fuzz (already installed in this repo's dev environment)
cargo install cargo-fuzz

# Ensure nightly is installed
rustup toolchain install nightly
```

## Running a target

```bash
# From the crate root (crates/rulesteward-fapolicyd/)
cd crates/rulesteward-fapolicyd

# Run indefinitely (Ctrl-C to stop)
cargo +nightly fuzz run parse_rules
cargo +nightly fuzz run parse_trust_value

# Bounded run: stop after 1 000 000 executions or 5 minutes
cargo +nightly fuzz run parse_rules -- -runs=1000000 -max_total_time=300
cargo +nightly fuzz run parse_trust_value -- -runs=1000000 -max_total_time=300

# Smoke check (50 000 runs, as used in CI)
cargo +nightly fuzz run parse_rules -- -runs=50000 -max_total_time=90
cargo +nightly fuzz run parse_trust_value -- -runs=50000 -max_total_time=90
```

## Re-seeding / extending the corpus

Seed files live under `fuzz/corpus/<target>/`. The fuzzer discovers
interesting new inputs automatically during a run and saves them to the
corpus directory. You can add hand-crafted seeds at any time:

```bash
# Add a seed for parse_rules (any valid or invalid .rules content)
echo 'allow perm=open uid=0 : all' > fuzz/corpus/parse_rules/my-seed.rules

# Add a seed for parse_trust_value (on-disk trust-DB value format)
# Format: "<src_int> <size_bytes> <lowercase_hex_digest>"
printf '1 1234567 a3f5b7c9d1e2f4a6b8c0d2e4f6a8b0c2d4e6f8a0b2c4d6e8f0a2b4c6d8e0f2a4' \
  > fuzz/corpus/parse_trust_value/my-sha256.bin
```

## Handling a found crash

If the fuzzer discovers a panic or abort, it writes the crashing input to
`fuzz/artifacts/<target>/crash-<sha1>`. Do NOT commit these artifact files.

To reproduce and inspect a crash:

```bash
cargo +nightly fuzz run parse_rules fuzz/artifacts/parse_rules/crash-<sha1>
```

A crash in either target is a real bug. Stop, record the artifact path and
the panic message, and open an issue before attempting any fix.

## Workspace isolation

This crate is excluded from the stable workspace via the `exclude` key in
the root `Cargo.toml`. The stable `cargo build --workspace` command will
not attempt to compile this crate. The fuzz crate carries its own
`[workspace]` (implicit via `cargo-fuzz` conventions) and uses the
`fuzz-targets` Cargo feature of `rulesteward-fapolicyd` to access the
internal `parse_trust_value` function through a `#[doc(hidden)]` shim.
