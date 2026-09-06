#!/usr/bin/env bash
# Sourced by every script in xtask/. Holds no commands of its own beyond the
# shell settings, so sourcing it never acts.
# shellcheck disable=SC2034  # REPO and TOOLS_BIN are read by the callers.
set -euo pipefail
# A `die` inside `$(helper)` has to stop the caller; command substitutions do not
# inherit errexit on their own.
shopt -s inherit_errexit
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOLS_BIN="$REPO/.tools/bin"
PATH="$TOOLS_BIN:$PATH"
export PATH
log()  { printf '%s\n' "$*" >&2; }
die()  { printf 'error: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "$1 is not installed"; }
