# report golden-register scenario: trustdb-source-filedb

**class:** against-trustdb  
**edge_case_axis:** against-trustdb

## Intent

A trust row with source int 2 maps to TrustSource FileDb.

## Input rule file(s)

- `95-srcfile.rules`:
  ```
allow perm=open exe=/usr/local/bin/mytool : all
  ```

## Oracle

Golden envelope computed by the f2 section 3.2 mapping (spec-derived). Trust-DB digests are REAL values captured from a live `fapolicyd9` (`fapolicyd-1.4.5-1.1.el9_8`) container: real system binaries (`/usr/bin/ls`, `/usr/bin/cat`, `/usr/bin/rpm`) keep their on-disk size+SHA256; fixture paths (`/opt/local/tool`, `/usr/local/bin/mytool`) are deterministic files created in the container and hashed there. `against_trustdb=true`, `diff_against=false`.
A top-level `trustJoin` block attaches the resolved trust-DB rows (path/size/digest/source) for each enumerable grant.

## Notes

source int 2 (SRC_FILE_DB) -> TrustSource::FileDb (trustdb.rs:45); the trustJoin row's source field is the string "FileDb".
