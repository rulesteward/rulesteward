#!/usr/bin/env bash
# The live acceptance run: the musl binary against a real fapolicyd, on a rootful
# Rocky container or on a Rocky VM over ssh.
#
#   xtask/live.sh <8|9|10> [base|denyall]                container
#   xtask/live.sh <8|9|10> vm [base|denyall|journal]     VM, host `rockyN` from ~/.ssh/config
#
# `journal` runs the daemon under systemd with a --debug-deny drop-in and
# captures every journalctl output mode; it needs systemd, so it is VM-only.
#
# Local-only, like `just corpus`: it needs rootful podman (fanotify needs
# CAP_SYS_ADMIN in the initial user namespace, so rootless cannot work) or a
# private VM, and the daemon helpers from the research harness through the
# `research` symlink. Reports land in target/live/. The case itself is
# xtask/live-case.sh.
#
# The VM path snapshots the whole /etc/fapolicyd tree and asserts the restore,
# copied from research/docs/harvest/vm-harvest.sh rather than sourced: that
# script resolves its case from its own tree, and it is finished work that this
# repo should not edit to suit itself.

# shellcheck source=xtask/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

VER="${1:?usage: live.sh <8|9|10> [vm] [base|denyall|journal]}"
shift
MODE=container
[ "${1:-}" = "vm" ] && { MODE=vm; shift; }
VARIANT="${1:-base}"
case "$VARIANT" in base|denyall|journal) ;; *) die "variant is base, denyall or journal, not $VARIANT" ;; esac
[ "$VARIANT" = journal ] && [ "$MODE" = container ] && die "journal needs systemd: use  live.sh $VER vm journal"

LIB="$REPO/research/docs/harvest/lib.sh"
[ -f "$LIB" ] || die "research/docs/harvest/lib.sh is missing: make the symlink with  ln -s ../rulesteward-research research"
CASE="$REPO/xtask/live-case.sh"
BIN="$REPO/target/x86_64-unknown-linux-musl/release/rulesteward"
OUT="$REPO/target/live"
NAME="rocky${VER}-${VARIANT}-live"
[ "$MODE" = vm ] && NAME="$NAME-vm"
mkdir -p "$OUT"
[ -f "$OUT/$NAME.log" ] && mv -f "$OUT/$NAME.log" "$OUT/$NAME.log.stale"

"$REPO/xtask/musl.sh"

if [ "$MODE" = container ]; then
    need podman
    log "== rocky$VER container: $VARIANT =="
    sudo podman run --rm --privileged \
        -v "$LIB:/harvest/lib.sh:ro,Z" \
        -v "$CASE:/harvest/case.sh:ro,Z" \
        -v "$BIN:/harvest/rulesteward:ro,Z" \
        -v "$OUT:/out:Z" \
        -e "FIXTURE_NAME=$NAME" -e "HARVEST_VARIANT=$VARIANT" -e "HARVEST_ARG=" \
        "docker.io/rockylinux/rockylinux:${VER}" bash /harvest/case.sh || true
    log "== $NAME: $(tail -1 "$OUT/$NAME.log")"
    exit 0
fi

HOST="${VM_HOST:-rocky$VER}"
ORIG=/var/tmp/rulesteward-etc-fapolicyd.orig
LOCK=/var/lock/rulesteward-harvest.lock
ssh_() { ssh -o BatchMode=yes "$HOST" "$@"; }
rules_consistent() { ssh_ 'sudo fagenrules --check 2>&1' | grep -q 'No change'; }

ssh_ "sudo flock -n $LOCK true" || die "a run already holds $LOCK on $HOST"
ssh_ 'pgrep -x fapolicyd >/dev/null' && die "fapolicyd is already running on $HOST"
ssh_ "sudo test -d $ORIG" && die "stale snapshot $ORIG on $HOST: a previous run died before restoring; inspect it before anything else"
rules_consistent || die "compiled.rules does not match rules.d on $HOST; run  ssh $HOST 'sudo fagenrules'"

log "== $HOST: staging =="
ssh_ 'sudo rm -rf /harvest /out && sudo mkdir -p /harvest /out'
tar -C "$(dirname "$LIB")" -cf - lib.sh | ssh_ 'sudo tar -C /harvest -xf -'
tar -C "$(dirname "$CASE")" -cf - live-case.sh | ssh_ 'sudo tar -C /harvest -xf - && sudo mv /harvest/live-case.sh /harvest/case.sh'
tar -C "$(dirname "$BIN")" -cf - rulesteward | ssh_ 'sudo tar -C /harvest -xf -'

log "== $HOST: running $VARIANT =="
set +e
ssh_ "
  sudo cp -a /etc/fapolicyd $ORIG
  sudo flock -n $LOCK env FIXTURE_NAME='$NAME' HARVEST_VARIANT='$VARIANT' HARVEST_ARG='' \
       VM_RUN=1 timeout 1800 bash /harvest/case.sh
  rc=\$?
  # The journal variant's systemd drop-in, removed whether or not the case got
  # that far: stop first, so the unit systemd stops is the one it started.
  sudo systemctl stop fapolicyd 2>/dev/null
  sudo rm -f /etc/systemd/system/fapolicyd.service.d/rulesteward.conf
  sudo rmdir /etc/systemd/system/fapolicyd.service.d 2>/dev/null
  sudo systemctl daemon-reload
  sudo pkill -9 -x fapolicyd 2>/dev/null
  # Copy THEN swap: a restore that rm -rf's first and fails on the copy leaves
  # the host with no /etc/fapolicyd at all.
  sudo sh -c 'rm -rf /etc/fapolicyd.restoring &&
              cp -a $ORIG /etc/fapolicyd.restoring &&
              rm -rf /etc/fapolicyd &&
              mv /etc/fapolicyd.restoring /etc/fapolicyd'
  sudo fapolicyd-cli --delete-db >/dev/null 2>&1
  sudo systemctl disable fapolicyd >/dev/null 2>&1
  sudo rm -rf /tmp/live /tmp/deny.log /tmp/rs.out /tmp/rs.err /tmp/denials*.txt /tmp/suggested-paths.txt /run/fapolicyd/fapolicyd.fifo
  exit \$rc
"
RC=$?
set -e
ssh_ 'sudo cat /out/*.log' > "$OUT/$NAME.log" || true
# Everything else the case wrote -- the journal variant's captures -- pulled the
# same way staging pushed, before the /out cleanup below.
rm -rf "${OUT:?}/$NAME" && mkdir -p "$OUT/$NAME"
ssh_ 'sudo tar -C /out -cf - .' | tar -C "$OUT/$NAME" -xf - || true

# Assert the restore, do not assume it.
if ssh_ 'sudo test -d /etc/fapolicyd/rules.d && ! sudo test -d /etc/fapolicyd/rules.d.off &&
         ! sudo test -f /etc/fapolicyd/rules.d/00-rulesteward.rules &&
         ! sudo test -f /etc/fapolicyd/rules.d/50-rulesteward.rules &&
         ! sudo test -f /etc/fapolicyd/rules.d/99-deny-everything.rules &&
         ! sudo test -e /etc/systemd/system/fapolicyd.service.d/rulesteward.conf' \
   && rules_consistent && ! ssh_ 'pgrep -x fapolicyd >/dev/null' \
   && ! ssh_ 'systemctl is-active -q fapolicyd'; then
    ssh_ "sudo rm -rf $ORIG /harvest /out"
    log "   restore asserted on $HOST"
else
    log "   RESTORE NOT VERIFIED on $HOST: snapshot kept at $ORIG"
fi
log "== $NAME (case rc=$RC): $(tail -1 "$OUT/$NAME.log")"
