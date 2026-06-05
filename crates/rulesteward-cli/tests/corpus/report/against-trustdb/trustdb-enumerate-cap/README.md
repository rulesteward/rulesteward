# trustdb-enumerate-cap

## Intent

A single `allow perm=execute all : trust=1` grant, evaluated under
`--against-trustdb` against a trust DB carrying 25 rows. The golden asserts a
non-trivial `count` (25) so the Q4 cap behavior is exercised. In JSON the
register emits `count` plus the enumerated entries (f2 Q4: "in JSON emit a
count + the entries"); in human output the full listing is opt-in via
`--enumerate-trust`, but the JSON golden always carries the entries.

## edge_case_axis

against-trustdb

## Mapping notes (f2 sections 2.4, 3.2, Q4)

- `allow perm=execute all : trust=1` is a `trust`-scoped grant (object is
  `trust=1`). The grant row itself pins no single hash, so `hash: null`,
  `hashOrigin: "none"`, `hashAlgorithm: null`. `subjectPaths`/`objectPaths`
  are empty (no `exe=`/`path=`/`dir=` literal).
- A `trust=1` grant covers EVERY trusted file (f2 section 2.4). Statically
  uncountable; WITH `--against-trustdb` the register iterates the trust DB
  (`iter_entries`) and enumerates each covered file as an exception. The
  `trustJoin` block carries `count` (25) and, per Q4's JSON behavior, the 25
  resolved `(path, size, digest, source)` rows.
- Every trust-DB digest is SHA256 (64-hex) per the on-disk
  `path size sha256hex` format (f2 section 2.3).

## Real-digest provenance (not synthetic)

All 25 `trustJoin` rows are REAL, captured from the pinned `fapolicyd9` image
(`fapolicyd-1.4.5-1.1.el9_8`). 25 real regular files under `/usr/bin` were
added to the file trust DB and read back from `/etc/fapolicyd/fapolicyd.trust`
(3-field `path size sha256hex` lines), then sorted+deduped and the first 25
kept:

```
# in container, abbreviated:
for p in <25 real /usr/bin files>; do fapolicyd-cli --file add "$p"; done
grep -v '^#' /etc/fapolicyd/fapolicyd.trust | awk 'NF==3' | sort -u | head -25
# e.g. /usr/bin/bash 1389024 ec6d007d48ef11bc47ad3f372b4b20ff2f0d4e63867e7e4cc0f1b17b19fa88b2
```

`source: "FileDb"` reflects how the rows were created (`--file add` ->
SRC_FILE_DB = 2 -> `TrustSource::FileDb`, verified `trustdb.rs:42-50`). The
`(size, digest)` are the real file content for each path. The count of 25 is
the fixture size that makes the cap axis non-trivial.
