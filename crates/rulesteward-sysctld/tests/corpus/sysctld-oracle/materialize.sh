#!/bin/sh
# Shared tree.plan materializer (session 9k-1 Lane B, sysctld).
#
# Realizes a scenario's tree.plan onto a root prefix. Used by BOTH sides of the
# differential: the bash capture (this file, run inside the rs-oracleN
# container, ROOT="" so paths land at the container's real "/") and the Rust
# Tier-1 replay test (which ports this exact algorithm to build the same tree
# under a tempdir(), ROOT=<tempdir>). Keeping ONE algorithm description (this
# file's comments) is what the "materializer equivalence guard" in
# sysctld_corpus_oracle.rs checks against: both materializers recompute a
# filesystem inventory afterward and compare it to a vendored expectation, so a
# divergence between this shell version and the Rust port is a hard, readable
# Tier-1 failure - no docker required to see it.
#
# Usage: materialize.sh <plan-file> <content-dir> <root-prefix>
#
# <plan-file> is tab-separated `TYPE\tRELPATH\tARG` lines, one entry per line,
# terminated by a line containing exactly `---` (everything after that marker
# is the VENDORED INVENTORY block, not a materialization instruction - this
# script stops reading at the marker and never interprets inventory lines).
#
# TYPE is one of:
#   d   create a directory at RELPATH (ARG ignored)
#   f   copy a regular file from <content-dir>/RELPATH to RELPATH (ARG ignored)
#   l   create a symlink at RELPATH whose target is ARG verbatim (relative
#       target unless ARG is exactly `/dev/null`, the one permitted absolute
#       target - see the corpus PROVENANCE.md "symlink target" schema rule)
#   p   create a FIFO at RELPATH via mkfifo(1) (ARG ignored). NOT used live in
#       this corpus (a `.conf` FIFO hangs systemd-sysctl indefinitely - see
#       PROVENANCE.md finding (b)); kept for a future bounded-timeout scenario.
#
# Lines that are blank or start with `#` are ignored (comments), matching the
# tree.plan header convention. Parent directories are created implicitly
# (mkdir -p) before every entry, so a scenario need not declare a `d` line for
# every ancestor - only for a directory that is itself the point of the
# scenario (e.g. the degenerate `.conf`-named-directory case) or that would
# otherwise stay empty.
#
# After every entry is materialized, the merged-usr alias `<root>/lib ->
# usr/lib` is (re)created UNCONDITIONALLY (man sysctl.d(5) treats
# /usr/lib/sysctl.d and /lib/sysctl.d as the SAME directory on a real host).
# A tree.plan declaring a path starting `lib/` is a corpus authoring error -
# see the Rust side's assertion.
set -e

PLAN="$1"
CONTENT="$2"
ROOT="$3"

# Always ensure the four standard search directories exist, even if the
# scenario's plan never references one of them. This keeps the post-hoc
# inventory identical in shape across every scenario (four `d` entries always
# present), which is what lets the equivalence guard use one fixed expected
# skeleton rather than a per-scenario conditional.
for d in etc/sysctl.d run/sysctl.d usr/local/lib/sysctl.d usr/lib/sysctl.d; do
  mkdir -p "$ROOT/$d"
done

in_inventory=0
while IFS="$(printf '\t')" read -r type relpath arg || [ -n "$type" ]; do
  if [ "$in_inventory" -eq 1 ]; then
    continue
  fi
  case "$type" in
    '' | '#'*) continue ;;
    ---) in_inventory=1; continue ;;
  esac
  dest="$ROOT/$relpath"
  parent=$(dirname "$dest")
  mkdir -p "$parent"
  case "$type" in
    d) mkdir -p "$dest" ;;
    f) cp "$CONTENT/$relpath" "$dest" ;;
    l) ln -s "$arg" "$dest" ;;
    p) mkfifo "$dest" ;;
    *)
      echo "materialize.sh: unknown tree.plan type '$type' for $relpath" >&2
      exit 2
      ;;
  esac
done <"$PLAN"

mkdir -p "$ROOT/usr/lib"
rm -f "$ROOT/lib"
ln -s usr/lib "$ROOT/lib"
