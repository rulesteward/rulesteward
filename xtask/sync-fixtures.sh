#!/usr/bin/env bash
# Vendor the golden-test fixtures out of the private rulesteward-research repo.
#
# Why vendor at all: this repo is public and rulesteward-research is private, so
# public CI cannot see the corpus. One fixture per parser hazard lands here; the
# full 121-log corpus stays there and is swept locally with --features full-corpus.
#
# Nothing sensitive is being published. A sweep of all 121 logs found no IPs, no
# home paths and no usernames; identity is numeric only (auid=1000, uid=998). The
# `# kernel=` and `# nevra=` headers are kept verbatim on purpose: the Rocky 8 log
# records the host kernel because the guest ran nested, which is itself a finding.
#
#   ./xtask/sync-fixtures.sh          re-copy
#   ./xtask/sync-fixtures.sh --check  exit 1 if a vendored fixture has drifted
set -euo pipefail

cd "$(dirname "$0")/.."
SRC="${RESEARCH:-research}/docs/fixtures/raw"
DST="tests/fixtures"

[ -d "$SRC" ] || { echo "no $SRC; is the research symlink present?" >&2; exit 1; }

# file:mode   all | head:N | tail:N, counting records and never the '#' header.
#
# Which END gets kept is not cosmetic. The reload probe's corrupted records are the
# LAST 416 in the file — the corruption starts after the failed reload — so a head:
# cap on it silently vendors only the clean records and the fixture tests nothing.
#
# rocky9-base-conf-validate.log is deliberately absent (D14). Its 21-field no-colon
# duplicate-key records exist in that capture only inside `# record:` annotations,
# and a `#` line is a comment to the tool, so vendoring the file would test nothing.
# That one record is copied out by hand as tests/fixtures/handwritten-21-fields.log.
FIXTURES=(
  "rocky8-base-edge-paths.log:all"                             # escaping, path=??, 511 cap
  "rocky8-base-gaps.log:all"                                   # Rocky 8: no prefix at all
  "rocky9-base-gaps.log:all"                                   # Rocky 9 framing, same shape as 10
  "rocky9-journal-live-vm-short.log:all"                       # journalctl -o short: double prefix
  "rocky10-base-gaps.log:all"                                  # ANSI prefix, spaces in paths
  "rocky10-base-syslog-format.log:all"                         # subject trust=1, object trust=0
  "rocky10-base-syslog-framing-syslog-raw.log:head:200"        # syslog framing, daemon PID
  "rocky8-base-reload-probe-empty-ruleset-daemon.log:tail:250" # corrupted field names
)

check=0
[ "${1:-}" = "--check" ] && check=1
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
status=0

for entry in "${FIXTURES[@]}"; do
  name="${entry%%:*}"; mode="${entry#*:}"
  [ -f "$SRC/$name" ] || { echo "missing upstream: $SRC/$name" >&2; exit 1; }

  if [ "$mode" = "all" ]; then
    cp "$SRC/$name" "$tmp/$name"
  else
    end="${mode%%:*}"; cap="${mode##*:}"
    # -a everywhere: the reload probe's field names are raw bytes out of freed
    # memory, so these files are not text and grep would otherwise go quiet.
    grep -a '^#' "$SRC/$name" > "$tmp/$name" || true
    printf '# TRUNCATED by xtask/sync-fixtures.sh to the %s %s records.\n' "$end" "$cap" \
      >> "$tmp/$name"
    # tail reads its whole input, so no SIGPIPE against pipefail.
    grep -av '^#' "$SRC/$name" | "$end" -n "$cap" >> "$tmp/$name"
  fi

  if [ "$check" = 1 ]; then
    if ! cmp -s "$tmp/$name" "$DST/$name"; then
      echo "drifted: $DST/$name" >&2
      status=1
    fi
  else
    cp "$tmp/$name" "$DST/$name"
    printf '%8s  %s\n' "$(du -h "$DST/$name" | cut -f1)" "$name"
  fi
done

[ "$check" = 1 ] && [ "$status" = 0 ] && echo "fixtures match upstream"
exit "$status"
