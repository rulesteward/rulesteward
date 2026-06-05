# report golden-register scenario: trustdb-no-flag-trust1

**class:** against-trustdb  
**edge_case_axis:** against-trustdb

## Intent

trust=1 grant WITHOUT the flag; golden notes the grant expands to N entries and advises --against-trustdb; no trustJoin block emitted.

## Input rule file(s)

- `93-noflag.rules`:
  ```
allow perm=execute all : trust=1
  ```

## Oracle

Golden envelope computed by the f2 section 3.2 mapping (spec-derived). Trust-DB digests are REAL values captured from a live `fapolicyd9` (`fapolicyd-1.4.5-1.1.el9_8`) container: real system binaries (`/usr/bin/ls`, `/usr/bin/cat`, `/usr/bin/rpm`) keep their on-disk size+SHA256; fixture paths (`/opt/local/tool`, `/usr/local/bin/mytool`) are deterministic files created in the container and hashed there. `against_trustdb=false`, `diff_against=false`.
No `trustJoin` block is emitted (no `--against-trustdb`). The `trust=1` grant is reported trust-scoped; enumeration is deferred to the flag.

## Notes

Without --against-trustdb the envelope has NO trustJoin key; the trust=1 grant is reported as trust-scoped, enumeration deferred to the flag (f2 section 2.4). Same grant row as scenario 1, minus the join.
