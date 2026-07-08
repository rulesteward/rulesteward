#!/bin/sh
# Probe a real sshd binary for the sshd-probe-update drift tool (#372).
# Runs INSIDE a Rocky+openssh container. Arg 1 = a file with one candidate
# keyword per line. Emits TSV to stdout, EXACTLY two physical lines per keyword:
#   <kw>\topt\t<rc>\t<stderr, flattened to one line>     (Loop B)
#   <kw>\tmatch\t<rc>\t<stderr, flattened to one line>   (Loop C)
# Some keywords produce MULTI-LINE stderr (invalid value, missing host key), so
# each record's stderr is captured to a file and flattened (tabs+newlines ->
# single spaces, trimmed) before the single record-terminating newline is added.
# Loop B (`sshd -t -o KW=yes`) feeds E01 (known iff not "Bad configuration
# option") + W04 (deprecated iff "Deprecated option"). Loop C (a non-activating
# `Match User nomatch_zz_user` file + `sshd -t -f`) feeds E04 (global-only iff
# "not allowed within a Match block"; test unknown FIRST).
set -u
ssh-keygen -A >/dev/null 2>&1 || true
SSHD=/usr/sbin/sshd
CFG=/tmp/rs_probe_match.conf
ERR=/tmp/rs_probe_err
CANDS="$1"

emit() {
  # $1=kw $2=opt|match $3=rc ; stderr is in $ERR. Flatten to one trimmed line.
  printf '%s\t%s\t%s\t' "$1" "$2" "$3"
  sed 's/\t/ /g' "$ERR" | tr '\r\n' '  ' | sed -e 's/  */ /g' -e 's/^ *//' -e 's/ *$//'
  printf '\n'
}

while IFS= read -r kw; do
  [ -z "$kw" ] && continue
  "$SSHD" -t -o "$kw=yes" >"$ERR" 2>&1
  emit "$kw" opt "$?"
  printf 'Match User nomatch_zz_user\n%s yes\n' "$kw" > "$CFG"
  "$SSHD" -t -f "$CFG" >"$ERR" 2>&1
  emit "$kw" match "$?"
done < "$CANDS"
