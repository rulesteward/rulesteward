# rulesteward -- the command menu.
#
# CI calls these recipes and the one bootstrap script and nothing else, so
# .github/ holds no logic of its own and could be deleted at a platform migration
# without losing a mechanism. xtask/lint.sh asserts that rather than trusting it.
#
# Recipes stay one line on purpose. Anything with real logic -- a trap, a temp
# directory, a digest check -- lives in xtask/*.sh beside sync-fixtures.sh, where
# shellcheck reads it.

# The pinned cargo-deny, cargo-mutants and typos live in .tools/bin, which no
# recipe would otherwise see: just does not source xtask/lib.sh.
export PATH := justfile_directory() + "/.tools/bin:" + env("PATH")

# List the recipes.
default:
    @just --list --unsorted

# Every static gate, in one pass, all verdicts reported.
lint:
    ./xtask/lint.sh

# The suite.
test:
    cargo test --locked

# The middle of three tiers. The Stop hook runs `just lint` once per agent turn,
# `just check` adds the suite and is what a developer runs by hand before
# pushing, and mutation testing runs only in CI -- so a local green is not a CI
# green and must not be read as one.
check: lint test

# The full 121-log corpus, through the gitignored `research` symlink. Panics
# naming the symlink when it is absent, which is the point: a sweep that quietly
# passes because it did not run is worse than no sweep.
corpus:
    cargo test --locked --features full-corpus

# The musl release build, plus the assertion that the binary is static.
musl:
    ./xtask/musl.sh

# Mutation testing. Unsharded and judged against docs/mutation-baseline.json;
# MUTANTS_SHARD=k/8 runs one shard and judges nothing, which is what CI does.
mutants *ARGS:
    ./xtask/mutants.sh {{ARGS}}

# The absolute gate on changed code. Its own recipe because the workflow gate
# fullmatches `just <recipe>` and will not take an argument.
mutants-diff:
    ./xtask/mutants.sh --in-diff

# Sums the eight shards' job outputs and applies the ratchet.
mutants-verdict:
    ./xtask/mutants.sh --verdict
