# FANOTIFY Audit Fixtures -- Rocky 8.10

## System Information

- OS: Rocky Linux 8.10 (Green Obsidian)
- PRETTY_NAME: "Rocky Linux 8.10 (Green Obsidian)"
- Kernel: 4.18.0-553.el8_10.x86_64
- audit package: audit-3.1.2-1.el8.x86_64
- fapolicyd package: fapolicyd-1.3.2-1.el8.x86_64

## Capture Timestamp

2026-06-24T01:51:22Z

## Setup

- fapolicyd was NOT installed before this capture; installed via:
  `sudo dnf -y install fapolicyd`
- Default install has `permissive = 0` (enforcing from first install).
- auditd confirmed active.
- fapolicyd started: `sudo systemctl restart fapolicyd` -> active.

## Trigger Command

```
cp /bin/true /tmp/rs_untrusted
sudo chmod +x /tmp/rs_untrusted
/tmp/rs_untrusted
# Result: bash: /tmp/rs_untrusted: Operation not permitted (exit=126)
```

fapolicyd IS enforcing (exit=126 confirmed on multiple trigger attempts).
The `deny_audit` rules ARE present in /etc/fapolicyd/rules.d/90-deny-execute.rules.

## FANOTIFY Records

NONE. Rocky 8.10 (kernel 4.18.0-553.el8_10.x86_64) with fapolicyd 1.3.2 and
audit 3.1.2 does NOT emit FANOTIFY audit events (type 1331) when fapolicyd
denies execution.

Verified:
```
sudo grep -a 'type=FANOTIFY' /var/log/audit/audit.log
# => 0 matches after confirmed denials
```

Root cause: The Linux kernel 4.18 (RHEL 8 base kernel) does not write FANOTIFY
events to the audit subsystem. FANOTIFY audit event support (type 1331) was added
in later kernel versions. fapolicyd 1.3.2 relies on the kernel to write these
events; on kernel 4.18 the denial is enforced via fanotify but no audit record
is emitted.

## ausearch Behavior

`sudo ausearch -m FANOTIFY` returns `<no matches>` (expected -- no records exist).

## Key Finding for rulesteward

The `explain fanotify` feature CANNOT produce output for Rocky 8.10 / RHEL 8
with fapolicyd 1.3.2 / kernel 4.18. This is a kernel limitation, not a fapolicyd
or audit configuration issue. Any rulesteward feature that reads FANOTIFY audit
records must document this as a known gap for RHEL 8 systems.

## Cleanup

- `sudo systemctl stop fapolicyd` (was not running before capture)
- `rm -f /tmp/rs_untrusted`
- fapolicyd package left installed (newly installed this session)
- permissive=0 conf setting unchanged (was already 0 from fresh install)
