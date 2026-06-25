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

# Path to the cross-version differential harness script (#287, dev-only).
# Override syntax (variable must precede the recipe name):
#   just validate_sh=/other/validate.sh diff-fapolicyd /corpus 'glob/*'
validate_sh := "/mnt/side-projects/fapolicyd-corpus/20260601T013116Z-wave3-combined/tools/validate.sh"

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

# (#287) Cross-version fapolicyd differential harness (opt-in, dev-only; NOT part of
# `just ci`). Requires docker + the prebuilt fapolicyd{8,9,10} images and validate.sh.
# Skips gracefully when any prerequisite is absent (exits 0 with a clear message).
# Usage: just diff-fapolicyd <corpus_abs_dir> '<glob>'
# Example: just diff-fapolicyd /mnt/.../wave3-combined 'adversarial/*'
diff-fapolicyd corpus glob:
    #!/usr/bin/env bash
    set -uo pipefail
    VALIDATE_SH="{{validate_sh}}"
    CORPUS="{{corpus}}"
    GLOB="{{glob}}"
    # --- prerequisite checks (graceful skip) ---
    if ! command -v docker >/dev/null 2>&1; then
        echo "diff-fapolicyd: prerequisites missing - need docker + the prebuilt fapolicyd{8,9,10} images and validate.sh; build/pull them first (see CLAUDE.md 'Differential verification')" >&2
        exit 0
    fi
    if [ ! -f "$VALIDATE_SH" ]; then
        echo "diff-fapolicyd: prerequisites missing - validate.sh not found at $VALIDATE_SH (override with validate_sh=... or see CLAUDE.md 'Differential verification')" >&2
        exit 0
    fi
    if ! docker image inspect fapolicyd8 fapolicyd9 fapolicyd10 >/dev/null 2>&1; then
        echo "diff-fapolicyd: prerequisites missing - fapolicyd8/9/10 docker images not found; pull or build them first (see CLAUDE.md 'Differential verification')" >&2
        exit 0
    fi
    # --- run the harness ---
    bash "$VALIDATE_SH" start
    bash "$VALIDATE_SH" run "$CORPUS" "$GLOB"; rc=$?
    bash "$VALIDATE_SH" stop
    exit $rc

# (#291) Isolated trustdb NO_LOCK RW-contention harness (opt-in; NOT part of
# `just ci`). A dedicated CI job runs only this recipe. Lane B fills this in.
trustdb-contention:
    @echo "trustdb-contention: stub (pending #291 implementation)"
