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

# Run llvm-cov: 80% workspace floor + >=90% parser/lint floor (mirrors ci.yml). (#395)
cov:
    cargo llvm-cov --no-report --workspace --locked
    cargo llvm-cov report --fail-under-lines 80
    cargo llvm-cov report --package rulesteward-core --package rulesteward-fapolicyd --package rulesteward-selinux --package rulesteward-auditd --package rulesteward-sshd --package rulesteward-sudoers --package rulesteward-sysctld --package rulesteward-cli --fail-under-lines 90

# (#467) Guard against unguarded chmod deny-mode fixtures (from_mode(0o000) /
# from_mode(0o555)) under crates/**/{src,tests} that lack a CAP_DAC_OVERRIDE
# marker (or a dac-override-exempt: escape hatch) in the same function - see
# the "DAC guard" section of CONTRIBUTING.md.
dac-guard:
    bash scripts/check-dac-guard.sh

# Build the static musl binary (requires musl-gcc + the rustup target).
musl:
    CC_x86_64_unknown_linux_musl=musl-gcc \
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=musl-gcc \
    cargo build --release --target x86_64-unknown-linux-musl --bin rulesteward --locked

# Run the full local CI gate in CI order (fmt + clippy + dac-guard + test + cov).
ci: fmt clippy dac-guard test cov

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
# `just ci`). Runs ONLY the #[ignore]d `trustdb_contention` integration test:
# a NO_LOCK reader (open_trustdb_readonly + iter_entries/get_entry) hammered
# against a separate live writer PROCESS that churns the same DB. Gated by both
# `#[ignore]` and `required-features = ["test-fixtures"]` so the default
# `just test` / coverage run never executes it. A dedicated CI job runs only
# this recipe, isolated from the main test matrix.
trustdb-contention:
    cargo test -p rulesteward-fapolicyd --features test-fixtures \
        --test trustdb_contention --locked -- --ignored --test-threads=1

# (#335 follow-up) Drift-check / refresh the sysctld STIG baselines against
# ComplianceAsCode/content. The tool lives in its OWN workspace (tools/stig-update),
# OUT of `just ci`. All three recipes skip gracefully (exit 0) when curl is absent.
#
# stig-check         : derive at the PINNED refs (stig-refs.toml); exit 1 on any drift
#                      vs the shipped baseline.rs tables (the CI drift gate uses this).
# stig-check-latest  : derive at the LATEST CaC release; report pending upstream changes.
# stig-derive <p>    : print the derived table + diff + paste-ready k(...) lines for
#                      review (p = rhel8|rhel9|rhel10, or `all`). Usage: just stig-derive rhel9
stig-check:
    #!/usr/bin/env bash
    set -uo pipefail
    if ! command -v curl >/dev/null 2>&1; then
        echo "stig-check: prerequisites missing - need curl + network access to ComplianceAsCode" >&2
        exit 0
    fi
    cargo run --quiet --manifest-path tools/stig-update/Cargo.toml -- check

stig-check-latest:
    #!/usr/bin/env bash
    set -uo pipefail
    if ! command -v curl >/dev/null 2>&1; then
        echo "stig-check-latest: prerequisites missing - need curl + network access" >&2
        exit 0
    fi
    cargo run --quiet --manifest-path tools/stig-update/Cargo.toml -- check --latest

stig-derive product="all":
    #!/usr/bin/env bash
    set -uo pipefail
    if ! command -v curl >/dev/null 2>&1; then
        echo "stig-derive: prerequisites missing - need curl + network access" >&2
        exit 0
    fi
    if [ "{{product}}" = "all" ]; then
        cargo run --quiet --manifest-path tools/stig-update/Cargo.toml -- derive
    else
        cargo run --quiet --manifest-path tools/stig-update/Cargo.toml -- derive --product "{{product}}"
    fi

# (#444) Drift-check / refresh the sshd W01/W02 STIG baselines against the OFFICIAL
# DISA XCCDF. Same nested-tool pattern (tools/sshd-stig-update, OUT of `just ci`).
# DISA versions each RHEL STIG by FILENAME (no releases API), so there is NO
# `--latest` mode; `check` derives at the pinned zips in the tool's stig-refs.toml.
# The LIVE recipes skip gracefully (exit 0) when curl/unzip are absent.
#
# sshd-stig-check         : LIVE - fetch the pinned DISA zips; exit 1 on any drift vs
#                           stig.rs (the weekly sshd-stig-drift workflow uses this).
# sshd-stig-check-offline : OFFLINE - drift-check stig.rs against the committed real
#                           DISA fixtures; no network (the PR-gate uses this).
# sshd-stig-derive <p>    : print the derived table + diff + paste-ready lines for
#                           review (p = rhel8|rhel9|rhel10, or `all`).
sshd-stig-check:
    #!/usr/bin/env bash
    set -uo pipefail
    if ! command -v curl >/dev/null 2>&1 || ! command -v unzip >/dev/null 2>&1; then
        echo "sshd-stig-check: prerequisites missing - need curl + unzip + network to dl.dod.cyber.mil" >&2
        exit 0
    fi
    cargo run --quiet --manifest-path tools/sshd-stig-update/Cargo.toml -- check

sshd-stig-check-offline:
    #!/usr/bin/env bash
    set -euo pipefail
    # Offline drift gate: derive from the committed real-DISA fixtures and confirm
    # stig.rs still matches. No network. Any product's drift (exit 1) or error (2)
    # fails the recipe.
    for p in rhel8 rhel9 rhel10; do
        cargo run --quiet --manifest-path tools/sshd-stig-update/Cargo.toml -- \
            check --product "$p" --file "tools/sshd-stig-update/tests/fixtures/${p}_sshd_controls.xml"
    done

sshd-stig-derive product="all":
    #!/usr/bin/env bash
    set -uo pipefail
    if ! command -v curl >/dev/null 2>&1 || ! command -v unzip >/dev/null 2>&1; then
        echo "sshd-stig-derive: prerequisites missing - need curl + unzip + network access" >&2
        exit 0
    fi
    if [ "{{product}}" = "all" ]; then
        cargo run --quiet --manifest-path tools/sshd-stig-update/Cargo.toml -- derive
    else
        cargo run --quiet --manifest-path tools/sshd-stig-update/Cargo.toml -- derive --product "{{product}}"
    fi

# (#372) Drift-check the sshd E01/E04/W04 lint tables against a LIVE sshd daemon by
# probing the Rocky 8/9/10 + openssh-server images. Same nested-tool pattern
# (tools/sshd-probe-update, OUT of `just ci`). The LIVE recipes skip gracefully (exit 0)
# when docker or the images are absent; the weekly sshd-probe-drift workflow builds the
# images and runs the live check in CI.
#
# diff-sshd             : LIVE - probe the sshd-probe{8,9,10} images; exit 1 on drift.
# diff-sshd-offline     : OFFLINE - drift-check against the committed daemon fixtures
#                         (the PR-gate uses this); no docker.
# sshd-probe-derive <p> : print the derived sets + diff + paste-ready lines (p =
#                         rhel8|rhel9|rhel10, or `all`).

# LIVE: probe the sshd-probe{8,9,10} images and drift-check; exit 1 on drift.
diff-sshd:
    #!/usr/bin/env bash
    set -uo pipefail
    if ! command -v docker >/dev/null 2>&1; then
        echo "diff-sshd: prerequisites missing - need docker + the sshd-probe{8,9,10} images (build from tools/sshd-probe-update/dockerfiles/<n>/)" >&2
        exit 0
    fi
    if ! docker image inspect sshd-probe8 sshd-probe9 sshd-probe10 >/dev/null 2>&1; then
        echo "diff-sshd: prerequisites missing - sshd-probe8/9/10 images not found; build each from tools/sshd-probe-update/dockerfiles/<n>/Dockerfile (docker build -t sshd-probe<n> ...)" >&2
        exit 0
    fi
    cargo run --quiet --manifest-path tools/sshd-probe-update/Cargo.toml -- check

diff-sshd-offline:
    #!/usr/bin/env bash
    set -euo pipefail
    # Offline drift gate: replay the committed daemon-probe fixtures and confirm the
    # shipped E01/E04/W04 tables still match. No docker. Any product's drift (exit 1)
    # or error (2) fails the recipe.
    for p in rhel8 rhel9 rhel10; do
        cargo run --quiet --manifest-path tools/sshd-probe-update/Cargo.toml -- \
            check --product "$p" --transcript "tools/sshd-probe-update/tests/fixtures/${p}_probe.jsonl"
    done

sshd-probe-derive product="all":
    #!/usr/bin/env bash
    set -uo pipefail
    if ! command -v docker >/dev/null 2>&1; then
        echo "sshd-probe-derive: prerequisites missing - need docker + the sshd-probe{8,9,10} images" >&2
        exit 0
    fi
    if [ "{{product}}" = "all" ]; then
        cargo run --quiet --manifest-path tools/sshd-probe-update/Cargo.toml -- derive
    else
        cargo run --quiet --manifest-path tools/sshd-probe-update/Cargo.toml -- derive --product "{{product}}"
    fi
