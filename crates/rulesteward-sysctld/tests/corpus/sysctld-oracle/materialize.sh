#!/bin/sh
# Shared tree.plan materializer (session 9k-1 Lane B, sysctld).
#
# Realizes a scenario's tree.plan onto a root prefix. Used by BOTH sides of the
# differential: the bash capture (this file, run inside the rs-oracleN
# container, ROOT="" so paths land at the container's real "/") and the Rust
# Tier-1 replay test (which ports this exact algorithm to build the same tree
# under a tempdir(), ROOT=<tempdir>). Keeping ONE algorithm description (this
# file's comments) is what the materializer equivalence guard checks against -
# and each side has its OWN comparison, run at a different point:
#
#   - Tier-1 (Rust, docker-free): `rulesteward_sysctld::oracle::compute_inventory`
#     globs the tempdir() tree this file's Rust port built and compares it to
#     the scenario's vendored `---` block. Catches a RUST materializer bug.
#   - Tier-2 (this file's `--inventory` mode, LIVE only): `capture_sysctld.sh`
#     invokes `sh materialize.sh --inventory <root>` right after materializing
#     inside the rs-oracleN container, and compares ITS output to the SAME
#     vendored block on the host before accepting the capture. Catches a BASH
#     materializer bug - the class the Rust-only guard cannot see, because it
#     never executes this file.
#
# A divergence on either side is a hard, readable failure naming which
# materializer disagreed with the vendored expectation - see
# `capture_sysctld.sh`'s `check_computed_inventory` for the live-side half.
#
# Usage:
#   materialize.sh <plan-file> <content-dir> <root-prefix>   (materialize)
#   materialize.sh --inventory <root-prefix>                 (recompute only)
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

# --inventory mode: recompute the canonical tree inventory by GLOBBING an
# already-materialized root - never by replaying a plan - matching
# `rulesteward_sysctld::oracle::compute_inventory` field-for-field (TSV
# `TYPE\tRELPATH\tARG`, `l` carries the raw unresolved symlink target, `d`/`f`
# carry an empty ARG). Scope: the four standard search directories (as a `d`
# entry plus their non-recursive contents), the `lib -> usr/lib` alias, and
# `etc/sysctl.conf` if present - the same scope the Rust side documents in its
# module doc "Scope of the equivalence guard". Prints unsorted; the caller
# sorts both sides identically before comparing.
if [ "${1:-}" = "--inventory" ]; then
  ROOT="${2:-}"
  for d in etc/sysctl.d run/sysctl.d usr/local/lib/sysctl.d usr/lib/sysctl.d; do
    printf 'd\t%s\t\n' "$d"
    for f in "$ROOT/$d"/*; do
      [ -e "$f" ] || [ -L "$f" ] || continue
      name=$(basename "$f")
      relpath="$d/$name"
      if [ -L "$f" ]; then
        printf 'l\t%s\t%s\n' "$relpath" "$(readlink "$f")"
      elif [ -d "$f" ]; then
        printf 'd\t%s\t\n' "$relpath"
      else
        printf 'f\t%s\t\n' "$relpath"
      fi
    done
  done
  lib="$ROOT/lib"
  if [ -L "$lib" ]; then
    printf 'l\tlib\t%s\n' "$(readlink "$lib")"
  elif [ -d "$lib" ]; then
    printf 'd\tlib\t\n'
  elif [ -e "$lib" ]; then
    printf 'f\tlib\t\n'
  fi
  econf="$ROOT/etc/sysctl.conf"
  if [ -L "$econf" ]; then
    printf 'l\tetc/sysctl.conf\t%s\n' "$(readlink "$econf")"
  elif [ -d "$econf" ]; then
    printf 'd\tetc/sysctl.conf\t\n'
  elif [ -e "$econf" ]; then
    printf 'f\tetc/sysctl.conf\t\n'
  fi
  exit 0
fi

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
    l)
      # The only permitted absolute symlink target is /dev/null (the man
      # sysctl.d(5) disable idiom) - mirrors the Rust side's assertion in
      # rulesteward_sysctld::oracle::materialize exactly, so this rule is
      # genuinely enforced on BOTH sides rather than documented on one.
      case "$arg" in
        /*)
          if [ "$arg" != "/dev/null" ]; then
            echo "materialize.sh: the only permitted absolute symlink target is /dev/null, got '$arg' for $relpath" >&2
            exit 2
          fi
          ;;
      esac
      ln -s "$arg" "$dest"
      ;;
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
