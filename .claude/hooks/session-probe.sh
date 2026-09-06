#!/usr/bin/env bash
# Check the one state that is cheap to detect and expensive to misdiagnose.
#
# The `research` symlink points at the private rulesteward-research checkout and
# is gitignored, so it exists on no fresh clone and in no worktree the harness
# made by itself. Without it `just corpus` panics inside
# `every_capture_is_either_acted_on_or_explained` (tests/corpus.rs), which reads
# like a bug in the sweep rather than a missing link.
#
# SessionStart stdout is injected into context, so **silence is the healthy
# path**: a probe that prints on every start is a per-session token tax. It also
# always exits 0. SessionStart cannot block, and a probe that could fail is a way
# to disrupt every session in the project.
#
# Deliberately one check. This is not a second copy of CLAUDE.md.

set -uo pipefail
IFS=$'\n\t'

REPO="${CLAUDE_PROJECT_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"

# -e follows the link, so a dangling symlink is as false as a missing one.
if [ ! -e "$REPO/research" ]; then
    printf '%s\n' "rulesteward: the 'research' symlink is missing or dangling, so 'just corpus' will panic. In the main checkout: ln -s ../rulesteward-research research. In a worktree, .claude/hooks/worktree-create.sh makes it from whatever the main checkout's resolves to."
fi

exit 0
