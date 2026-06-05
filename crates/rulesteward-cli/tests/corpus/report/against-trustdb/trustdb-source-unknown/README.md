# trustdb-source-unknown

## Intent

A trust row whose `source` integer is 0 maps to `TrustSource::Unknown`. Under
`--against-trustdb`, the path grant `allow perm=open exe=/opt/vendor/bin/agent : all`
joins to the trust DB row for `/opt/vendor/bin/agent`; the resolved `trustJoin`
entry carries `source: "Unknown"`, and the grant's `hashOrigin` becomes `trustdb`
with the SHA256 digest.

## edge_case_axis

against-trustdb

## Mapping notes (f2 sections 2.2, 2.3, 3.2)

- The grant has `exe=/opt/vendor/bin/agent` on the subject side, so
  `subjectPaths` extracts `/opt/vendor/bin/agent` and `scope` is `path`
  (f2 README scope axis: keyed on `exe=`).
- Without `--against-trustdb` the grant would be `hashOrigin: none`. WITH the
  flag, the concrete subject path joins `TrustDb::get_entry`; the resolved
  `(size, digest, source)` triple is attached. `hashOrigin` flips to `trustdb`
  and the digest length 64 -> `SHA256` (the trust-DB digest is always SHA256 per
  the on-disk `path size sha256hex` format, f2 section 2.3).
- `TrustSource::from_int(0) == Unknown` is the verified mapping in
  `trustdb.rs:42-50` (0 = SRC_UNKNOWN). `TrustSource` serializes via
  `#[derive(Serialize)]` to the bare variant name, so `source` is the JSON
  string `"Unknown"`.

## Real-digest provenance (not synthetic)

The `(size, digest)` pair in `trustJoin` is REAL, captured from the pinned
`fapolicyd9` image (`fapolicyd-1.4.5-1.1.el9_8`):

```
# in container:
cp /usr/bin/true /opt/vendor/bin/agent
fapolicyd-cli --file add /opt/vendor/bin/agent
grep '^/opt/vendor/bin/agent ' /etc/fapolicyd/fapolicyd.trust
# -> /opt/vendor/bin/agent 51 c73afb60197c9c64805d2b4ab95efdee8646f8248ff800de2575a11eed8f9f08
# corroborated independently:
stat -c %s /opt/vendor/bin/agent   # 51
sha256sum /opt/vendor/bin/agent    # c73afb60...f9f08
```

The `path size sha256hex` trust-file format and the digest both match f2
section 2.3's `[CONTAINER]` claim. The `source: "Unknown"` value is a
DELIBERATE SYNTHETIC FIXTURE override: the on-disk `fapolicyd.trust` text file
has NO source field (source is assigned at LMDB-compile time, and a
`--file add` row compiles to `FileDb`=2). This scenario's whole axis is the
`source` int -> variant mapping, so the fixture pins the source int to 0 to
exercise the `Unknown` branch. The mapping (0 -> Unknown) is itself verified in
`trustdb.rs:42-50`; only the assignment of source=0 to THIS row is synthetic.
The `digest`/`size` are real for the real file content.
