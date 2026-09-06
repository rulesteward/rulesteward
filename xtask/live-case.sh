#!/bin/bash
# The live acceptance case. Runs as root inside a rootful --privileged container
# or on a VM under VM_RUN=1, driven by xtask/live.sh. It mirrors real use: a
# running permissive daemon, denials captured, the tool run ON THIS HOST with
# --conf, its stdout applied exactly as printed with the daemon live, then the
# identical triggers again. PASS means no suggested path was denied a second
# time; every FAIL names the path, and a second placement pass separates a wrong
# rule from a wrongly placed one.
#
# Daemon helpers come from the research harness (fp_setup, fp_start, as_tester,
# fp_manifest), which is why the file lives at /harvest/lib.sh here. Never
# fp_setup_stig: on Rocky 8 the SSG remediation removes a systemd mask and
# starts an ENFORCING daemon. The `denyall` variant is the STIG's whole
# observable effect, written by hand.
set -u
# shellcheck source=/dev/null
source /harvest/lib.sh
RS=/harvest/rulesteward
OUT="/out/${FIXTURE_NAME:-live}.log"
exec >"$OUT" 2>&1

fail() { echo "FAIL: $*"; exit 1; }

fp_setup || fail fp_setup
if [ "${HARVEST_VARIANT:-base}" = "denyall" ]; then
    echo 'deny_audit perm=any all : all' > /etc/fapolicyd/rules.d/99-deny-everything.rules
    fagenrules || fail fagenrules
fi
fp_manifest | sed 's/^/# /'
echo "# case=live variant=${HARVEST_VARIANT:-base} rulesteward=$($RS --version)"
echo "# --- compiled rules before ---"
grep -vE '^\s*(#|$)' /etc/fapolicyd/compiled.rules | nl -b a | sed 's/^/# /'

# Not coreutils: on Rocky those are shims to /usr/bin/coreutils and the event
# would report that path. grep is a real ELF and ignores argv[0].
mkdir -p /tmp/live && chmod 755 /tmp/live
cp /usr/bin/grep /tmp/live/probe-grep && chmod 755 /tmp/live/probe-grep
printf '#!/bin/bash\necho hi\n' > /tmp/live/probe.sh && chmod 755 /tmp/live/probe.sh
cp /usr/lib64/libz.so.1 /tmp/live/probe-lib.so && chmod 755 /tmp/live/probe-lib.so
echo "plain data" > /tmp/live/data.txt && chmod 644 /tmp/live/data.txt

trigger() {
    as_tester /tmp/live/probe-grep -c x /etc/hostname   # untrusted execute
    as_tester /tmp/live/probe.sh                         # untrusted script (allowed)
    as_tester cat /tmp/live/probe-lib.so                 # untrusted sharedlib open
    as_tester cat /tmp/live/data.txt                     # plain data open (allowed)
    as_tester /usr/bin/grep -c x /etc/hostname           # trusted control (allowed)
    # A trusted binary through the loader: the shipped ld_so pattern rule denies
    # it with the OBJECT trusted, the only trust=1 denial a default install has.
    as_tester /lib64/ld-linux-x86-64.so.2 /usr/bin/grep -c x /etc/hostname
    command sleep 4
}

PID=$(fp_start /tmp/deny.log) || fail fp_start
# fp_start stops waiting after 120 s but still returns the pid. A VM start
# rebuilds the trust db from a real rpmdb and can take longer than that.
for _ in $(seq 1 300); do
    grep -q "Starting to listen" /tmp/deny.log && break
    kill -0 "$PID" 2>/dev/null || fail "daemon died before listening"
    command sleep 2
done
grep -q "Starting to listen" /tmp/deny.log || fail "daemon never listened"

MARK=$(wc -l < /tmp/deny.log)
trigger
echo "== pass 1 denials =="
tail -n +$((MARK+1)) /tmp/deny.log | grep 'dec=deny' | tee /tmp/denials1.txt
echo "count=$(wc -l < /tmp/denials1.txt)"

echo "== rulesteward fapolicyd analyze --conf /etc/fapolicyd/fapolicyd.conf =="
tail -n +$((MARK+1)) /tmp/deny.log \
    | $RS fapolicyd analyze --conf /etc/fapolicyd/fapolicyd.conf >/tmp/rs.out 2>/tmp/rs.err
RC=$?
echo "exit=$RC"
echo "-- stdout --"; cat /tmp/rs.out
echo "-- stderr --"; cat /tmp/rs.err
[ "$RC" -eq 0 ] || fail "analyze exited $RC"
[ -s /tmp/rs.out ] || fail "analyze emitted nothing for $(wc -l < /tmp/denials1.txt) denials"

echo "== applying stdout verbatim (daemon live, as a user would) =="
# The eval below is the test, not an oversight: a user pastes these lines into a
# root shell, so the case does the same, and a quoting defect in shell_quote
# shows up here as a failed or wrong command rather than being masked by an
# argv call. The input is the tool's own stdout over filenames this case
# created, on a --rm container or a VM whose /etc/fapolicyd is restored after.
RULES=/etc/fapolicyd/rules.d/50-rulesteward.rules
: > /tmp/suggested-paths.txt
while IFS= read -r line; do
    case "$line" in
        "fapolicyd-cli --file add "*)
            eval "$line" || echo "  (--file add exited $?)"
            eval "printf '%s\n' ${line#fapolicyd-cli --file add }" >> /tmp/suggested-paths.txt ;;
        "fapolicyd-cli --update")
            timeout 120 fapolicyd-cli --update || echo "  (--update exited $?)" ;;
        allow*)
            echo "$line" >> "$RULES"
            printf '%s\n' "${line##* : path=}" >> /tmp/suggested-paths.txt ;;
        *) echo "UNEXPECTED LINE: $line" ;;
    esac
done < /tmp/rs.out
if [ -f "$RULES" ]; then
    fagenrules; echo "fagenrules exit=$?"
    timeout 60 fapolicyd-cli --reload-rules; echo "--reload-rules exit=$?"
fi
command sleep 5
echo "-- suggested paths --"; cat /tmp/suggested-paths.txt

still_denied() {  # still_denied <denials-file>: prints each suggested path found, returns 1 if any
    local hit=0 p
    while IFS= read -r p; do
        grep -F -q -- "path=$p" "$1" && { echo "STILL DENIED: $p"; hit=1; }
    done < /tmp/suggested-paths.txt
    return $hit
}

echo "== pass 2: identical triggers =="
MARK=$(wc -l < /tmp/deny.log)
trigger
tail -n +$((MARK+1)) /tmp/deny.log | grep 'dec=deny' | tee /tmp/denials2.txt
echo "count=$(wc -l < /tmp/denials2.txt)"
echo "== verdict =="
STILL=0
still_denied /tmp/denials2.txt || STILL=1

if [ "$STILL" -eq 1 ] && [ -f "$RULES" ]; then
    # First match wins and rules.d merges in name order, so 50- sits after the
    # shipped 30-patterns deny. The same rule, placed first.
    echo "== pass 3: same rules moved to 00-rulesteward.rules =="
    mv "$RULES" /etc/fapolicyd/rules.d/00-rulesteward.rules
    fagenrules; echo "fagenrules exit=$?"
    timeout 60 fapolicyd-cli --reload-rules; echo "--reload-rules exit=$?"
    command sleep 5
    MARK=$(wc -l < /tmp/deny.log)
    trigger
    tail -n +$((MARK+1)) /tmp/deny.log | grep 'dec=deny' | tee /tmp/denials3.txt
    echo "count=$(wc -l < /tmp/denials3.txt)"
    STILL=0
    still_denied /tmp/denials3.txt || STILL=1
    [ "$STILL" -eq 0 ] && echo "PLACEMENT: 50- failed, 00- passed"
fi
fp_stop "$PID"
echo "-- daemon tail --"; tail -5 /tmp/deny.log | grep -v 'dec='
[ "$STILL" -eq 0 ] && echo "PASS" || echo "FAIL: suggested paths still denied"
