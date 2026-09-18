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
# observable effect, written by hand. The `placement` variant denies a trusted
# binary by an object-side rule, the one denial shape a path rule resolves, so
# the run reaches the placement note that no default install produces.
#
# The `journal` variant is VM-only and replaces fp_start and both apply passes:
# it runs the daemon under systemd with a --debug-deny drop-in and captures the
# same denials through every journalctl output mode, to settle how the tool
# reads a journal capture rather than a redirected stderr log.
#
# The `audit` variant is VM-only too, and starts the shipped unit with NO
# drop-in: the route under test is the ordinary non-debug daemon, which logs
# deny_audit nowhere but auditd. It captures every ausearch mode in two passes,
# before and after loading the two STIG syscall rules, to measure what auditd
# carries for a denial. There is no apply pass.
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
elif [ "${HARVEST_VARIANT:-base}" = "placement" ]; then
    # 41- sorts between 41-shared-obj and 42-trusted-elf, whose
    # `allow perm=execute all : trust=1` would shadow any deny placed after it.
    echo 'deny_audit perm=execute all : path=/usr/bin/sed' > /etc/fapolicyd/rules.d/41-live-placement.rules
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
    as_tester /usr/bin/sed -n 1p /etc/hostname           # trusted control; placement denies it by object
    # A trusted binary through the loader: the shipped ld_so pattern rule denies
    # it with the OBJECT trusted, the only trust=1 denial a default install has.
    as_tester /lib64/ld-linux-x86-64.so.2 /usr/bin/grep -c x /etc/hostname
    command sleep 4
}

if [ "${HARVEST_VARIANT:-base}" = "journal" ]; then
    [ "${VM_RUN:-}" = 1 ] || fail "journal variant needs systemd: VM only"
    # An enforcing daemon started through systemd locks the host, and unlike
    # fp_start there is no --permissive on the command line to fall back on.
    grep -qE '^permissive\s*=\s*1' /etc/fapolicyd/fapolicyd.conf ||
        fail "permissive is not 1; refusing systemctl start"

    mkdir -p /etc/systemd/system/fapolicyd.service.d
    # --debug-deny skips become_daemon() (fapolicyd.c guards it with
    # `if (!debug_mode)`), so the shipped Type=forking unit would wait for a
    # parent that never exits and kill the daemon on timeout. Type=simple, no
    # PIDFile, and ExecStart cleared before it is reset -- only Type=oneshot
    # accepts more than one ExecStart, so appending a second one would fail.
    printf '[Service]\nType=simple\nPIDFile=\nExecStart=\nExecStart=/usr/sbin/fapolicyd --debug-deny\n' \
        > /etc/systemd/system/fapolicyd.service.d/rulesteward.conf
    systemctl daemon-reload

    # `@<seconds>` is systemd's epoch timestamp form (systemd.time(7)); it
    # bounds every journalctl read below to this run.
    SINCE=@$(date +%s)
    systemctl start fapolicyd || fail "systemctl start"
    for _ in $(seq 1 300); do
        journalctl -u fapolicyd --since="$SINCE" -o cat | grep -q "Starting to listen" && break
        systemctl is-active -q fapolicyd || fail "daemon died before listening"
        command sleep 2
    done
    journalctl -u fapolicyd --since="$SINCE" -o cat | grep -q "Starting to listen" ||
        fail "daemon never listened"

    echo "== unit =="
    systemctl show fapolicyd -p Type -p MainPID -p StandardOutput -p StandardError -p SyslogLevelPrefix

    trigger
    command sleep 4

    J="/out/${FIXTURE_NAME:-live}.journal"
    journalctl -u fapolicyd --since="$SINCE" -o short    > "$J.short"
    journalctl -u fapolicyd --since="$SINCE" -o short -a > "$J.short-a"
    journalctl -u fapolicyd --since="$SINCE" -o cat      > "$J.cat"
    journalctl -u fapolicyd --since="$SINCE" -o cat -a   > "$J.cat-a"
    journalctl -u fapolicyd --since="$SINCE" -o json     > "$J.json"
    # rsyslog is installed on all three VMs, so the same records land here too.
    [ -f /var/log/messages ] && cp /var/log/messages "/out/${FIXTURE_NAME:-live}.messages"

    # Q5: does the tool read a journal capture the way it reads the stderr log?
    for m in cat cat-a; do
        for action in rules trust; do
            echo "== rulesteward fapolicyd $action --conf /etc/fapolicyd/fapolicyd.conf < journal.$m =="
            $RS fapolicyd "$action" --conf /etc/fapolicyd/fapolicyd.conf \
                < "$J.$m" > /tmp/rs.out 2> /tmp/rs.err
            echo "exit=$?"
            echo "-- stdout --"; cat /tmp/rs.out
            echo "-- stderr --"; cat /tmp/rs.err
        done
    done
    echo "== denials in journal.cat-a =="; grep -c 'dec=deny' "$J.cat-a"

    systemctl stop fapolicyd
    for f in "$J.short" "$J.short-a" "$J.cat" "$J.cat-a" "$J.json"; do
        [ -s "$f" ] || fail "empty capture $f"
    done
    echo "PASS"; exit 0
fi

if [ "${HARVEST_VARIANT:-base}" = "audit" ]; then
    [ "${VM_RUN:-}" = 1 ] || fail "audit variant needs systemd and auditd: VM only"
    # Same reason as the journal block: an enforcing daemon started through
    # systemd locks the host and there is no --permissive to fall back on.
    grep -qE '^permissive\s*=\s*1' /etc/fapolicyd/fapolicyd.conf ||
        fail "permissive is not 1; refusing systemctl start"
    # `enabled 2` is the immutable state: auditctl -a and -d both fail and only a
    # reboot clears it, so the two passes would collapse into one.
    auditctl -s | grep -qE '^enabled 1$' ||
        fail "auditctl -s is not 'enabled 1': 2 is immutable and needs a reboot, refusing"
    systemctl is-active -q auditd || fail "auditd is not running"
    # That drop-in would put --debug-deny back on the command line and the route
    # under test would be stderr again, not auditd.
    [ -e /etc/systemd/system/fapolicyd.service.d/rulesteward.conf ] &&
        fail "stale journal drop-in present: the audit route is the shipped unit"
    command -v ausearch >/dev/null || fail "ausearch is missing: install audit"

    echo "== audit rules as found =="
    auditctl -l
    echo "== auditctl -s =="
    auditctl -s

    SINCE=@$(date +%s)
    systemctl start fapolicyd || fail "systemctl start"
    # No --debug-deny here, so the daemon forks and talks through syslog; the
    # line still reaches the journal, just not on the unit's own stderr.
    for _ in $(seq 1 300); do
        journalctl -u fapolicyd --since="$SINCE" | grep -q "Starting to listen" && break
        systemctl is-active -q fapolicyd || fail "daemon died before listening"
        command sleep 2
    done
    # Not a failure: whether the shipped unit logs that line at all is one of the
    # things this variant is here to measure.
    journalctl -u fapolicyd --since="$SINCE" | grep -q "Starting to listen" ||
        echo "no 'Starting to listen' line in the journal after 600 s; unit active, proceeding"

    echo "== unit =="
    systemctl show fapolicyd -p Type -p MainPID -p ExecStart

    audit_pass() {  # audit_pass <tag>: trigger, then capture every ausearch mode
        local A="/out/${FIXTURE_NAME:-live}.audit.$1"
        local d t e f m action el
        # ausearch parses -ts with strptime %x and date's %x uses the same
        # locale, so the two agree whatever LANG happens to be over ssh.
        d=$(date +%x); t=$(date +%T); e=$(date +%s)
        command sleep 1
        trigger
        command sleep 3   # auditd batches; give it time to flush to disk

        # -m FANOTIFY selects whole events that contain a FANOTIFY record;
        # all.raw is the unfiltered slice, for the case where the record rides
        # inside a SYSCALL event or is not written at all. stderr is appended,
        # never dropped: a "<no matches>" message must not become a failure.
        # --input-logs because ausearch reads STDIN whenever stdin is not a
        # tty, and under ssh or cron it is not: the first run of this variant
        # searched an empty pipe on all three releases and captured nothing.
        {
            ausearch --input-logs -m FANOTIFY -ts "$d" "$t" --raw > "$A.fanotify.raw"
            ausearch --input-logs -m FANOTIFY -ts "$d" "$t"       > "$A.fanotify.default"
            ausearch --input-logs -m FANOTIFY -ts "$d" "$t" -i    > "$A.fanotify.i"
            ausearch --input-logs -ts "$d" "$t" --raw             > "$A.all.raw"
            # The file underneath ausearch, sliced on the epoch in
            # msg=audit(...), so a record ausearch declines to report is
            # still visible.
            awk -v e="$e" '{ i = index($0, "msg=audit("); if (i) { split(substr($0, i + 10), a, "."); if (a[1] + 0 >= e) print } }' \
                /var/log/audit/audit.log > "$A.audit.log"
        } 2>>"$A.err"

        echo "== $1: records =="
        for f in "$A.fanotify.raw" "$A.fanotify.default" "$A.fanotify.i" "$A.all.raw" "$A.audit.log"; do
            printf '%s %s\n' "$(wc -l < "$f")" "$(basename "$f")"
        done
        echo "== $1: FANOTIFY record types =="
        grep -o '^type=[A-Z_]*' "$A.fanotify.raw" | sort | uniq -c
        echo "== $1: first FANOTIFY event, raw =="
        head -8 "$A.fanotify.raw"

        # Every mode against every action, reported: -i is not supported input and
        # what it produces is worth seeing rather than asserting.
        for m in fanotify.raw fanotify.default fanotify.i; do
            for action in rules trust why; do
                echo "== $1: rulesteward fapolicyd $action --conf /etc/fapolicyd/fapolicyd.conf < audit.$1.$m =="
                $RS fapolicyd "$action" --conf /etc/fapolicyd/fapolicyd.conf \
                    < "$A.$m" > /tmp/rs.out 2> /tmp/rs.err
                echo "exit=$?"
                echo "-- stdout --"; cat /tmp/rs.out
                echo "-- stderr --"; cat /tmp/rs.err
            done
        done

        # Q6 has an answer now: the reader landed (#88), so the syscall pass is
        # asserted and not just reported. The expectation inverts by release --
        # 9 and 10 carry the rule number in fan_info (`D` is rule 13, the shipped
        # `deny_audit perm=execute all : all`), and Rocky 8's kernel 4.18 writes
        # fan_info=0, where the diagnostic saying so is the whole result. The
        # asfound pass stays unasserted beyond the exit code: on 8 its capture is
        # empty, which is itself a measured finding.
        if [ "$1" = syscall ]; then
            $RS fapolicyd why --conf /etc/fapolicyd/fapolicyd.conf \
                < "$A.fanotify.raw" > /tmp/rs.why || fail "why exit $? on audit.$1.fanotify.raw"
            el=$(. /etc/os-release; echo "${VERSION_ID%%.*}")
            if [ "$el" = 8 ]; then
                grep -q 'carry no rule number' /tmp/rs.why ||
                    fail "el8: why says nothing about fan_info=0"
            else
                grep -q '^rule=13 ' /tmp/rs.why || fail "el$el: why names no rule=13"
            fi
            echo "== $1: why asserted on el$el =="
        fi
    }

    audit_pass asfound

    echo "== loading the two STIG syscall rules =="
    # key= is what makes the auditctl -d below and the restore assertion in
    # live.sh exact rather than a guess at which rules were already there. Under
    # a permissive daemon nothing returns EPERM, so the second rule is expected
    # not to fire; that gets recorded, not worked around.
    auditctl -a always,exit -F arch=b64 -S execve -F key=rulesteward-live ||
        fail "auditctl -a execve"
    auditctl -a always,exit -F arch=b64 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EPERM -F key=rulesteward-live ||
        fail "auditctl -a open"
    auditctl -l

    audit_pass syscall

    auditctl -d always,exit -F arch=b64 -S execve -F key=rulesteward-live
    auditctl -d always,exit -F arch=b64 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EPERM -F key=rulesteward-live
    auditctl -l | grep -q rulesteward-live && fail "audit rules not removed"
    systemctl stop fapolicyd
    # Empty is a legitimate result here, so it is reported and not asserted.
    for f in "/out/${FIXTURE_NAME:-live}.audit.asfound.fanotify.raw" \
             "/out/${FIXTURE_NAME:-live}.audit.syscall.fanotify.raw"; do
        if [ -s "$f" ]; then
            echo "$(wc -l < "$f") lines $(basename "$f")"
        else
            echo "empty $(basename "$f")"
        fi
    done
    echo "PASS"; exit 0
fi

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
if [ "${HARVEST_VARIANT:-base}" = placement ]; then
    # The daemon numbers rules without the %languages set line, so the number is
    # one less than `nl` above shows and differs from the issue's count; take it
    # from the record and hold the placement note to the same number.
    PLACED=$(grep -oE 'rule=[0-9]+ dec=deny_audit perm=execute .* path=/usr/bin/sed .*trust=1' /tmp/denials1.txt | grep -om1 'rule=[0-9]*')
    [ -n "$PLACED" ] || fail "placement: expected a trust=1 execute denial of /usr/bin/sed"
    echo "placement: denied by $PLACED"
fi

# Three runs of the same pass over the same input: the rules.d fragment and the
# trust commands go to different places and are applied differently below; the
# why report is asserted on and never applied.
for action in rules trust why; do
    echo "== rulesteward fapolicyd $action --conf /etc/fapolicyd/fapolicyd.conf =="
    tail -n +$((MARK+1)) /tmp/deny.log \
        | $RS fapolicyd "$action" --conf /etc/fapolicyd/fapolicyd.conf \
            >"/tmp/rs.$action" 2>/tmp/rs.err
    RC=$?
    echo "exit=$RC"
    echo "-- stdout --"; cat "/tmp/rs.$action"
    echo "-- stderr --"; cat /tmp/rs.err
    [ "$RC" -eq 0 ] || fail "$action exited $RC"
    # stderr carries errors only, so anything on it here is a failure of the run.
    [ -s /tmp/rs.err ] && fail "$action wrote to stderr"
done
grep -qE '^(allow|fapolicyd-cli) ' /tmp/rs.rules /tmp/rs.trust ||
    fail "nothing emitted for $(wc -l < /tmp/denials1.txt) denials"
# The ld_so trigger fires in every variant and 30-patterns sorts before both
# 41-live-placement and 99-deny-everything, so rule 5 is its denier everywhere.
grep -qE '^rule=[0-9]+ +30-patterns\.rules +[0-9]+ denials +subject-side, nothing to emit +deny_audit perm=any pattern=ld_so : all$' /tmp/rs.why ||
    fail "why: no subject-side line for the ld_so pattern rule"
if [ "${HARVEST_VARIANT:-base}" = placement ]; then
    grep -qF ' : path=/usr/bin/sed' /tmp/rs.rules || fail "placement: no path rule for /usr/bin/sed"
    grep -qE "^$PLACED +41-live-placement\.rules " /tmp/rs.why ||
        fail "why: no line for $PLACED in 41-live-placement.rules"
    grep -qF "# rulesteward: new file: rules.d/40-rulesteward.rules (sorts before 41-live-placement.rules, $PLACED)" /tmp/rs.rules ||
        fail "placement: note is not the expected 40-rulesteward.rules line"
fi

echo "== applying both artifacts verbatim (daemon live, as a user would) =="
# The eval below is the test, not an oversight: a user pastes these lines into a
# root shell, so the case does the same, and a quoting defect in shell_quote
# shows up here as a failed or wrong command rather than being masked by an
# argv call. The input is the tool's own stdout over filenames this case
# created, on a --rm container or a VM whose /etc/fapolicyd is restored after.
# The fragment goes where the tool's own placement note says it should; 50- is
# the fallback for "none recommended".
RULES=$(grep -om1 'rules.d/[0-9]*-rulesteward.rules' /tmp/rs.rules)
if [ -n "$RULES" ]; then
    WHENCE="from the placement note"
else
    RULES=rules.d/50-rulesteward.rules
    WHENCE="the fallback, no file recommended"
fi
RULES=/etc/fapolicyd/$RULES
echo "== rules file: $RULES ($WHENCE) =="
: > /tmp/suggested-paths.txt
while IFS= read -r line; do
    case "$line" in
        # Diagnostics ride on stdout as comments now. A user keeps them as the
        # fragment's header; this case only applies the lines that do something.
        "#"*) ;;
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
done < <(cat /tmp/rs.rules /tmp/rs.trust)
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
# The placement variant exists to prove the note lands the rule where it works,
# so a rule that needs pass 3 is the failure, not a second chance.
if [ "$STILL" -eq 1 ] && [ "${HARVEST_VARIANT:-base}" = placement ]; then
    fail "placement: rule written to $RULES and /usr/bin/sed still denied; pass 3 not run"
fi

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
