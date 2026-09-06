#!/usr/bin/env bash
# Creates the worktree Claude Code asked for, and builds its `.tools/bin` and
# `research` symlink before the tree is handed to anything.
#
# **This hook creates the worktree rather than reacting to one.** Claude Code
# runs its own `git worktree add` only when a `WorktreeCreate` hook prints
# nothing, so a hook that merely wanted to install tools would fire before the
# directory it needed to install into existed. Printing the path on stdout is how
# this says the creation is already done, and the branch name below
# (`worktree-<name>`) is the one the harness uses itself.
#
# **Why it exists at all**, against the survey's rejection of the event:
# install-tools.sh puts the pinned `typos` and `cargo-deny` in the worktree's own
# .tools/bin, and the Stop hook runs `just lint`, which needs both. Without this
# a fresh worktree's first turn would block on "command not found" every time.
#
# **A non-zero exit aborts the creation**, and the worktree and branch this
# script made are removed first, so a retry starts from nothing rather than from
# half a tree.
#
# `set -e` is deliberately absent: every step's failure is caught and reported
# with the step's name, and an unnoticed early exit would leave the worktree
# behind.

set -uo pipefail
IFS=$'\n\t'

# The first stderr line has to be this script's message, so a missing jq is
# reported here rather than as bash's own "command not found" ahead of it.
if ! command -v jq >/dev/null 2>&1; then
    printf 'rulesteward: worktree setup failed at jq\n' >&2
    printf 'jq is not on PATH\n' >&2
    exit 1
fi

# The harness sends `name` and `cwd` and nothing else. Everything else is derived
# from `cwd`, which is the checkout the session was in when it asked: the repo
# root through git's common dir, so a request made from inside a linked worktree
# still lands beside it rather than under it, and the source branch from that
# checkout's HEAD, so a worktree cut while on a feature branch starts from the
# feature branch and not from master.
input="$(cat)"
name="$(jq -r '.name // empty' <<<"$input" 2>/dev/null)"
cwd="$(jq -r '.cwd // empty' <<<"$input" 2>/dev/null)"
cwd="${cwd:-$PWD}"

if [ -z "$name" ]; then
    printf 'rulesteward: worktree setup failed at input\n' >&2
    printf 'expected name in the hook JSON, got:\n' >&2
    printf '%s\n' "$input" >&2
    exit 1
fi

# Absolute, because `--git-common-dir` is otherwise relative to `cwd` and this
# script's own working directory is not promised to be `cwd`.
common="$(git -C "$cwd" rev-parse --path-format=absolute --git-common-dir 2>/dev/null)" || common=""
if [ -z "$common" ]; then
    printf 'rulesteward: worktree setup failed at input\n' >&2
    printf 'cwd is not inside a git repository: %s\n' "$cwd" >&2
    exit 1
fi
REPO="$(dirname "$common")"
# A branch name when on one, the commit when detached: `worktree add` accepts
# either as the start point.
source_branch="$(git -C "$cwd" symbolic-ref -q --short HEAD 2>/dev/null || git -C "$cwd" rev-parse HEAD)"
# The directory the harness itself uses, so `EnterWorktree` with `path` and the
# exit-time cleanup both recognise the tree.
path="$REPO/.claude/worktrees/$name"
branch="worktree-$name"

# Removing the worktree *and* the branch: `worktree add -b` refuses a branch that
# already exists, so leaving the branch behind would make every retry fail on the
# first step for a reason unrelated to the one being retried.
#
# Only once this script created them. `worktree add` itself fails when the branch
# already exists, and deleting that branch would destroy someone's work in the
# name of tidying up after a creation that never happened.
created=0
fail() {
    printf 'rulesteward: worktree setup failed at %s\n' "$1" >&2
    printf '%s\n' "$2" >&2
    if [ "$created" = 1 ]; then
        git -C "$REPO" worktree remove --force "$path" >/dev/null 2>&1
        git -C "$REPO" branch -D "$branch" >/dev/null 2>&1
    fi
    exit 1
}

out="$(git -C "$REPO" worktree add "$path" -b "$branch" "$source_branch" 2>&1)" \
    || fail "git worktree add" "$out"
created=1

# Output captured per step so a failure reports what the step said and a success
# says nothing at all -- stdout belongs to the path.
out="$(cd "$path" && ./xtask/install-tools.sh 2>&1)" \
    || fail "xtask/install-tools.sh" "$out"

# The corpus symlink, resolved through the main checkout's own. Skipped silently
# when that checkout has none: the SessionStart probe is what reports it, and a
# worktree is not the place to guess where the private repo lives.
research="$(readlink -f "$REPO/research" 2>/dev/null)" || research=""
if [ -n "$research" ] && [ -d "$research" ]; then
    out="$(ln -s "$research" "$path/research" 2>&1)" || fail "ln -s research" "$out"
fi

printf '%s\n' "$path"
exit 0
