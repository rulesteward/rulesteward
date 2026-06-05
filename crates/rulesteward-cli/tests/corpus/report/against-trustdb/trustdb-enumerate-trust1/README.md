# report golden-register scenario: trustdb-enumerate-trust1

**class:** against-trustdb  
**edge_case_axis:** against-trustdb

## Intent

trust=1 grant WITH --against-trustdb; trustJoin enumerates trust-DB rows (path/size/digest SHA256/source). Requires a fixture trust DB.

## Input rule file(s)

- `90-trustenum.rules`:
  ```
allow perm=execute all : trust=1
  ```

## Oracle

Golden envelope computed by the f2 section 3.2 mapping (spec-derived). Trust-DB digests are REAL values captured from a live `fapolicyd9` (`fapolicyd-1.4.5-1.1.el9_8`) container: real system binaries (`/usr/bin/ls`, `/usr/bin/cat`, `/usr/bin/rpm`) keep their on-disk size+SHA256; fixture paths (`/opt/local/tool`, `/usr/local/bin/mytool`) are deterministic files created in the container and hashed there. `against_trustdb=true`, `diff_against=false`.
A top-level `trustJoin` block attaches the resolved trust-DB rows (path/size/digest/source) for each enumerable grant.

## Notes

trust=1 enumerates all 3 fixture rows; grant row stays hashOrigin=none (trust-scoped, not a single concrete file); rows live in trustJoin.
