# report golden-register scenario: trustdb-path-join-miss

**class:** against-trustdb  
**edge_case_axis:** against-trustdb

## Intent

A path grant whose path is NOT in the trust DB WITH --against-trustdb; the join finds no match, hashOrigin stays none, trustJoin row empty for that grant. Honest miss.

## Input rule file(s)

- `92-pathmiss.rules`:
  ```
allow perm=open exe=/usr/local/bin/notindb : all
  ```

## Oracle

Golden envelope computed by the f2 section 3.2 mapping (spec-derived). Trust-DB digests are REAL values captured from a live `fapolicyd9` (`fapolicyd-1.4.5-1.1.el9_8`) container: real system binaries (`/usr/bin/ls`, `/usr/bin/cat`, `/usr/bin/rpm`) keep their on-disk size+SHA256; fixture paths (`/opt/local/tool`, `/usr/local/bin/mytool`) are deterministic files created in the container and hashed there. `against_trustdb=true`, `diff_against=false`.
A top-level `trustJoin` block attaches the resolved trust-DB rows (path/size/digest/source) for each enumerable grant.

## Notes

Fixture DB contains only /usr/bin/ls; the grant's path is absent -> empty trustJoin rows, hashOrigin stays none. Honest miss, not a gap.
