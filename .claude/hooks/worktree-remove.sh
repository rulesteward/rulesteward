#!/usr/bin/env bash
# Removes a worktree Claude Code is done with, but only when nothing in it would
# be lost.
#
# **This hook decides, not Claude Code.** Once worktree-create.sh has made a
# tree, Claude Code removes it only through this hook: exit 0 means the tree is
# gone, and a non-zero exit with the directory still present keeps it and sends
# stderr to the debug log. So every refusal below exits 1 and says why.
#
# **Removed only when clean and pushed.** The tree has no modified or untracked
# file, no ignored file outside the disposable build output listed at the check,
# no edit hidden from `git status`, no git repository nested inside it, no
# per-worktree ref, and no rebase, merge, bisect, cherry-pick or revert in
# progress. HEAD is on a branch, its reflog names no commit that would be
# orphaned, and every commit on HEAD is on some remote-tracking branch, so a
# tree cut from a pushed feature branch qualifies. Nothing is fetched first,
# and the branch itself is never deleted, so a commit the check misjudges still
# lives on the branch after the tree is gone. Any check that fails keeps the
# tree.
#
# **Claude Code's own lock is lifted first.** It locks the trees it hands out
# with the reason `claude agent <name> (pid ...)`, and `git worktree remove`
# refuses a locked tree. A lock with any other reason is left alone, so git
# refuses and the tree is kept.
#
# `set -e` is deliberately absent, as in worktree-create.sh: every failure is
# caught and reported, because an unnoticed early exit would read as a removal
# that silently did not happen.

set -uo pipefail
IFS=$'\n\t'

if ! command -v jq >/dev/null 2>&1; then
    printf 'rulesteward: kept the worktree: jq is not on PATH\n' >&2
    exit 1
fi

input="$(cat)"
path="$(jq -r '.worktree_path // empty' <<<"$input" 2>/dev/null)"
if [ -z "$path" ]; then
    printf 'rulesteward: kept the worktree: expected worktree_path in the hook JSON, got:\n' >&2
    printf '%s\n' "$input" >&2
    exit 1
fi

# Already gone counts as removed.
[ -e "$path" ] || exit 0

# The first stderr line is the reason, because that is the line agent view
# quotes when it reports a refused delete. So git's own stderr (errors, and
# hints such as the sparse-index one) is collected and printed after it.
err="$(mktemp)" || { printf 'rulesteward: kept %s: mktemp failed\n' "$path" >&2; exit 1; }
trap 'rm -f "$err"' EXIT
exec 3>&2 2>"$err"
say() {
    printf 'rulesteward: %s\n' "$1" >&3
    [ $# -lt 2 ] || printf '%s\n' "$2" >&3
    cat "$err" >&3
    exit 1
}
keep() { say "kept $path: $1" "${@:2}"; }

# Every check reads the real tree: find does not descend a symlinked path, and
# git resolves it and deletes what it points at.
real="$(realpath -e -- "$path")" || keep "cannot resolve the path"
path="$real"

gitdir="$(git -C "$path" rev-parse --path-format=absolute --git-dir)" \
    || keep "not a git worktree"

# One listing for both rules. --untracked-files=all lists every file, also inside
# an ignored directory, so the allowlist below matches by prefix; it also
# overrides a user's status.showUntrackedFiles=no, which would hide an untracked
# file that the removal would then delete.
status="$(git -C "$path" status --porcelain --ignored --untracked-files=all --ignore-submodules=none)" \
    || keep "git status failed"
dirty="$(grep -v '^!! ' <<<"$status")"
[ -z "$dirty" ] || keep "it has uncommitted or untracked changes" "$(head -n 10 <<<"$dirty")"

# Ignored files go with the tree, so only what the repo's own tooling writes and
# rebuilds may: target/ (cargo, plus xtask/live.sh and release.sh under it),
# .tools/ (xtask/install-tools.sh), .cache/ and mutants.out*/ (xtask/mutants.sh
# and cargo-mutants), dist/ (xtask/release.sh), *.snap.new (insta, from
# `cargo test`) and .venv/ (a Python tool environment). research is allowed only
# as the symlink worktree-create.sh makes. Anything else, such as notes under
# .claude/ or a real research/ directory, keeps the tree.
precious="$(grep '^!! ' <<<"$status" \
    | grep -vE '^!! ((target|\.tools|\.cache|mutants\.out[^/]*|dist|\.venv)/|.*\.snap\.new$)')"
[ ! -L "$path/research" ] || precious="$(grep -vx '!! research' <<<"$precious")"
[ -z "$precious" ] || keep "it has ignored files that are not build output" "$(head -n 10 <<<"$precious")"

# `git status` and `git worktree remove` both skip a tracked file flagged
# assume-unchanged (a lowercase tag here) or skip-worktree (`S`), so an edit to
# one would be deleted unseen. A sparse checkout is kept for the same reason.
files="$(git -C "$path" ls-files -v)" || keep "git ls-files failed"
hidden="$(grep -m 5 '^[a-zS] ' <<<"$files")"
[ -z "$hidden" ] || keep "it has tracked files that git status does not check" "$hidden"

# A repository inside the allowed directories would go with them. It is found
# by a .git entry (a clone, a linked worktree, a submodule) or by its layout
# (a bare repo or a --separate-git-dir store: objects/ beside HEAD and refs/).
# find does not follow symlinks, so the research symlink is not a hit.
nested="$(find "$path" -mindepth 2 \( -name .git -o \( -type d -name objects \
    -exec test -f '{}/../HEAD' -a -d '{}/../refs' \; \) \) -print -quit)" \
    || keep "cannot search the tree for nested repositories"
[ -z "$nested" ] || keep "it holds another git repository or worktree" "$nested"

for op in rebase-merge rebase-apply MERGE_HEAD BISECT_LOG CHERRY_PICK_HEAD REVERT_HEAD sequencer; do
    [ ! -e "$gitdir/$op" ] || keep "a rebase, merge, bisect, cherry-pick or revert is in progress ($op)"
done

wtrefs="$(git -C "$path" for-each-ref --format='%(refname)' refs/worktree/)" \
    || keep "git for-each-ref failed"
[ -z "$wtrefs" ] || keep "it has per-worktree refs, which go with it" "$wtrefs"

branch="$(git -C "$path" symbolic-ref -q --short HEAD)" \
    || keep "HEAD is detached, so its commits are on no branch the check can read"

# A commit made on a detached HEAD and left behind by switching back is named
# only by this tree's HEAD reflog, which the removal deletes. The steps of a
# rebase that finished onto a branch are skipped: a fixup's intermediate pick is
# in that reflog alone too, and its content is in the result. The reflog runs
# newest first, so a `(finish): returning to refs/heads/` entry opens the skip
# and the run's `(start)` closes it. An aborted, quit or detached rebase writes
# no such finish, so a conflict resolved in it is still checked. Branch reflogs
# live in the common dir and survive.
headlog="$(git -C "$path" log -g --format='%H %gs' HEAD)" || keep "cannot read the HEAD reflog"
branchlog="$(git -C "$path" log -g --format=%H --branches)" || keep "cannot read the branch reflogs"
picked="$(awk '
    skip && /^[0-9a-f]+ rebase( -i)? \(start\)/ { skip = 0; next }
    /^[0-9a-f]+ rebase( -i)? \(finish\): returning to refs\/heads\// { skip = 1; next }
    !skip { print $1 }' <<<"$headlog")"
# Unquoted on purpose: one commit per line, and IFS splits on newlines.
# shellcheck disable=SC2086
orphan="$(git -C "$path" rev-list -n 1 $picked --not --branches --remotes --tags $branchlog)" \
    || keep "cannot check the HEAD reflog for orphaned commits"
[ -z "$orphan" ] || keep "commit $orphan is named only by this tree's HEAD reflog"

# Pushed means on some remote-tracking branch, whatever the upstream is: a tree
# cut from a pushed feature branch has nothing of its own, and a local upstream
# or a local branch named like a remote one does not count.
ahead="$(git -C "$path" rev-list --count HEAD --not --remotes)" \
    || keep "cannot compare HEAD with the remote-tracking branches"
[ "$ahead" = 0 ] || keep "$branch has $ahead commit(s) that are on no remote-tracking branch"

if grep -qs '^claude agent ' "$gitdir/locked"; then
    git -C "$path" worktree unlock "$path" >&2 || keep "git worktree unlock failed"
fi

# Run from the common dir, not from inside the tree being deleted. A failure
# here may come after git deleted part of the tree, so it is not called a keep.
common="$(git -C "$path" rev-parse --path-format=absolute --git-common-dir)" \
    || keep "cannot find the common git dir"
git -C "$common" worktree remove "$path" >&2 || say "removal of $path failed"
exit 0
