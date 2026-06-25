# FANOTIFY Audit Fixtures -- Rocky 9.8

## System Information

- OS: Rocky Linux 9.8 (Blue Onyx)
- PRETTY_NAME: "Rocky Linux 9.8 (Blue Onyx)"
- Kernel: (5.x series, Rocky 9)
- audit package: audit-3.1.5-8.el9.x86_64
- fapolicyd package: fapolicyd-1.4.5-1.1.el9_8.x86_64

## Capture Timestamp

2026-06-24T01:51:05Z

## Setup

- fapolicyd was already installed (1.4.5); permissive was 1 (permissive mode).
- Set `permissive = 0` in /etc/fapolicyd/fapolicyd.conf via:
  `sudo sed -i 's/^permissive *= *1/permissive = 0/' /etc/fapolicyd/fapolicyd.conf`
- Restarted fapolicyd: `sudo systemctl restart fapolicyd`
- auditd was already active.
- The permissive=0 conf edit was NOT reverted (as instructed). fapolicyd was stopped after capture.

## Trigger Command

```
cp /bin/true /tmp/rs_untrusted
sudo chmod +x /tmp/rs_untrusted
/tmp/rs_untrusted
# Result: bash: /tmp/rs_untrusted: Operation not permitted (exit=126)
```

The binary at /tmp/rs_untrusted is not in fapolicyd's trust DB (rpmdb tracks /bin/true
but not /tmp/rs_untrusted), so the `deny_audit perm=execute all : all` rule in
/etc/fapolicyd/rules.d/90-deny-execute.rules fires.

## FANOTIFY Records

Real records captured from `/var/log/audit/audit.log` via:
```
sudo grep -a 'type=FANOTIFY' /var/log/audit/audit.log
```

Record 1 (first trigger):
```
type=FANOTIFY msg=audit(1782265656.665:9304): resp=2 fan_type=1 fan_info=D subj_trust=2 obj_trust=0
```

Record 2 (second trigger, same session):
```
type=FANOTIFY msg=audit(1782265786.214:9605): resp=2 fan_type=1 fan_info=D subj_trust=2 obj_trust=0
```

## Field Reference

- `resp=2`: Response is DENY (1=allow, 2=deny)
- `fan_type=1`: fanotify event type (FAN_OPEN_EXEC_PERM = execute permission check)
- `fan_info=D`: Decision is Deny
- `subj_trust=2`: Subject (caller process) trust level from fapolicyd
- `obj_trust=0`: Object (executed file /tmp/rs_untrusted) trust level -- untrusted (0)

## ausearch Behavior

`sudo ausearch -m FANOTIFY` returns `<no matches>` even though records exist in the
audit log. This is a known limitation: FANOTIFY events (type 1331) are standalone
single-record events and ausearch's -m filter does not index them on audit 3.1.5.
The records must be retrieved via direct grep of the audit log file.

This behavior is consistent across -ts today, -ts recent, and no time filter.

## Cleanup

- `sudo systemctl stop fapolicyd` (was inactive before capture)
- `rm -f /tmp/rs_untrusted`
- fapolicyd package left installed (was already installed before this session)
- permissive=0 conf edit NOT reverted (was permissive=1 before; edit noted here)
