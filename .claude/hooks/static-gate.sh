#!/usr/bin/env bash
# The static gate, run once per turn when Claude has changed a file a gate reads.
#
# **Stop, not PostToolUse.** A PostToolUse hook on Edit|Write misses a file
# rewritten by `sed -i`, a heredoc or a `python3 - <<PY` block, which then reaches
# no gate until someone runs `just check`. `Stop` fires once per turn however the
# edit was made, so the hole closes by construction rather than by guessing which
# Bash commands write files. `Stop` is also the only one of the two that can
# block: exit 2 keeps the turn open and puts stderr in front of the model, so the
# break is fixed in the same turn instead of being reported after it.
#
# **The signature is content, not `git status`.** `git status --porcelain` prints
# ` M path` for a modified file before and after a second edit, and a second edit
# is the common case inside a turn. This hashes the contents of the files the
# gates read instead.
#
# **A given tree state blocks at most once.** Exit 2 continues the turn, which
# produces another Stop, so an unconditional block would wedge the session. The
# state file records the verdict beside the signature: a signature already
# recorded as `block` reports nothing and exits 0. Blocking again requires the
# model to have actually changed something.
#
# Measured on this box (16 cores): `just lint` warm 2.1-2.8 s, cold (after
# `cargo clean`) 11.6-12.3 s, this signature 0.023-0.027 s. The settings.json
# timeout of 60 s is several times the cold run. `just test` stays out: that is
# `just check`, the tier a developer runs by hand.

set -euo pipefail
IFS=$'\n\t'

# $CLAUDE_PROJECT_DIR is set by the harness. The fallback keeps the script
# runnable by hand.
REPO="${CLAUDE_PROJECT_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
cd "$REPO"

# The worktree's own pinned tools, the same prepend the justfile does. A worktree
# built by worktree-create.sh has `just` here and nowhere else.
PATH="$REPO/.tools/bin:$PATH"
export PATH

# .cache/ is gitignored and does not exist on a fresh clone.
STATE="$REPO/.cache/static-gate.state"

# What the pattern reaches: clippy and fmt over *.rs and the [lints] tables in
# Cargo.toml, cargo-deny over Cargo.lock and deny.toml, typos over its
# _typos.toml, workflows-carry-no-logic over .github/workflows/*.yml, shellcheck
# over xtask/*.sh and .claude/hooks/*.sh, plus the justfile that runs all of it.
# Enumerated through git so target/, .tools/ and .cache/ fall out of scope via
# .gitignore rather than via a second list that would drift from it.
signature() {
    { git ls-files -z; git ls-files -o --exclude-standard -z; } \
        | grep -zE '\.(rs|toml|yml|sh)$|(^|/)(Cargo\.lock|justfile)$' \
        | sort -z \
        | xargs -0 -r sha256sum \
        | sha256sum \
        | cut -d' ' -f1
}

# Failing open means running the gate, never skipping it: if git is unavailable
# or a file vanishes mid-hash, `cur` is empty and every branch below falls
# through to running lint.
cur="$(signature)" || cur=""

if [ -n "$cur" ] && [ -f "$STATE" ]; then
    verdict=""
    sig=""
    IFS=' ' read -r verdict sig < "$STATE" || true
    if [ "$sig" = "$cur" ]; then
        case "$verdict" in
            pass|block) exit 0 ;;
        esac
    fi
fi

record() {
    [ -n "$cur" ] || return 0
    mkdir -p "$(dirname "$STATE")"
    printf '%s %s\n' "$1" "$cur" > "$STATE" || true
}

if ! output="$(just lint 2>&1)"; then
    record block
    printf 'just lint failed:\n' >&2
    printf '%s\n' "$output" >&2
    exit 2
fi

record pass
exit 0
