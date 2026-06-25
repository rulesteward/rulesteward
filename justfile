# RuleSteward developer task runner.
#
# Each recipe mirrors a CI gate verbatim so `just ci` reproduces the
# blocking gate locally. Run `just --list` to see all recipes.
#
# This file lives alongside .github/workflows/ci.yml; when you change
# a CI invocation, update the corresponding recipe here.

# Default: print recipes when `just` is invoked with no args.
_default:
    @just --list

# Check formatting (cargo fmt --all --check).
fmt:
    cargo fmt --all --check

# Apply formatting in-place (cargo fmt --all).
fmt-fix:
    cargo fmt --all

# Run clippy with --deny warnings.
clippy:
    cargo clippy --workspace --all-targets --locked -- -D warnings

# Run the workspace test suite.
test:
    cargo test --workspace --locked

# Run llvm-cov with the 80% floor.
cov:
    cargo llvm-cov --workspace --locked --fail-under-lines 80

# Build the static musl binary (requires musl-gcc + the rustup target).
musl:
    CC_x86_64_unknown_linux_musl=musl-gcc \
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=musl-gcc \
    cargo build --release --target x86_64-unknown-linux-musl --bin rulesteward --locked

# Run the full local CI gate in CI order (fmt + clippy + test + cov).
ci: fmt clippy test cov

# (#287) Cross-version fapolicyd differential harness wrapper (opt-in, dev-only;
# NOT part of `just ci`). Requires docker + the prebuilt fapolicyd{8,9,10}
# images; skips gracefully when they are absent. Lane C fills this in.
diff-fapolicyd:
    @echo "diff-fapolicyd: stub (pending #287 implementation)"

# (#291) Isolated trustdb NO_LOCK RW-contention harness (opt-in; NOT part of
# `just ci`). A dedicated CI job runs only this recipe. Lane B fills this in.
trustdb-contention:
    @echo "trustdb-contention: stub (pending #291 implementation)"
