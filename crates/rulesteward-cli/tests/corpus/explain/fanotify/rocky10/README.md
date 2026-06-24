# FANOTIFY Audit Fixtures -- Rocky 10.2

## System Information

- OS: Rocky Linux 10.2 (Red Quartz)
- PRETTY_NAME: "Rocky Linux 10.2 (Red Quartz)"
- Kernel: (6.x series, Rocky 10)
- audit package: audit-4.0.3-5.el10.x86_64
- fapolicyd package: fapolicyd-1.4.5-1.2.el10_2.x86_64

## Capture Timestamp

2026-06-24T01:51:10Z

## Setup

- fapolicyd was NOT installed before this capture; installed via:
  `sudo dnf -y install fapolicyd`
- Default install has `permissive = 0` (enforcing from first install).
- auditd confirmed active.
- fapolicyd.conf permissive=0 confirmed before starting.

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
type=FANOTIFY msg=audit(1782265665.529:5369): resp=2 fan_type=1 fan_info=D subj_trust=2 obj_trust=0
```

Record 2 (second trigger, same session):
```
type=FANOTIFY msg=audit(1782265794.546:5517): resp=2 fan_type=1 fan_info=D subj_trust=2 obj_trust=0
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
single-record events and ausearch's -m filter does not index them on audit 4.0.3.
The records must be retrieved via direct grep of the audit log file.

This behavior is consistent across -ts today, -ts recent, and no time filter.

## Cleanup

- `sudo systemctl stop fapolicyd` (was not running before capture)
- `rm -f /tmp/rs_untrusted`
- fapolicyd package left installed (newly installed this session)
- permissive=0 conf setting unchanged (was already 0 from fresh install)
