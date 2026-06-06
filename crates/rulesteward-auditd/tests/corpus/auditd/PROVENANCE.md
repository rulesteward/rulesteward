## Auditd Corpus Provenance

NFS source: `/mnt/side-projects/auditd-corpus/20260603T004238Z/`
RS commit: d5999cc (HEAD at test-author time, branch 139-lane-a-auditd-corpus)

### Scenarios vendored

33 grammar scenarios (Category 1-3 from corpus INDEX.md):

- rocky8-cis-file-watches
- rocky8-pci-dss
- rocky9-arch-paired
- rocky9-deep-many-watches
- rocky9-exclude-msgtype
- rocky9-exclude-overlap
- rocky9-execve-auid
- rocky9-execve-unrestricted
- rocky9-field-compare
- rocky9-filesystem-list
- rocky9-huge-ruleset
- rocky9-identity-watches
- rocky9-key-collision
- rocky9-login-watches
- rocky9-mac-policy
- rocky9-multi-S-or
- rocky9-never-below-always
- rocky9-never-suppress
- rocky9-no-key-rules
- rocky9-perm-watch-expansion
- rocky9-prepend-vs-append
- rocky9-priv-commands
- rocky9-rare-syscall
- rocky9-stig-finalize
- rocky9-stig-hardened
- rocky9-stock-control
- rocky9-task-list
- rocky9-time-change
- rocky9-whitespace-torture
- rocky10-cis-benchmark
- rocky10-module-ops
- rocky10-rulesd-multifile
- rocky10-watch-vs-syscall-equiv

1 vm-live scenario (small log slice only, for from-log path exercise):

- rocky8-live-from-log-execve

### Files per grammar scenario

Per grammar scenario: `manifest.json`, `audit.rules`, `oracle/tiers.json`, `oracle/cost-band.json`.

### Files per from-log scenario

Per from-log scenario: `manifest.json`, `audit-sample.log`, `oracle/from-log-counts.json`, `rules.d/30-execve.rules`.

### Intentional exclusions

Raw vm-live `.log` files for the 13 other vm-live scenarios (Categories 4-6) are NOT vendored.
Their `audit-sample.log` files range from 100KB to several MB and are not needed for the
library-level cost-model tests. The single `rocky8-live-from-log-execve/audit-sample.log`
(136KB, 645 lines) is vendored to exercise the `count_events_by_key` code path.
