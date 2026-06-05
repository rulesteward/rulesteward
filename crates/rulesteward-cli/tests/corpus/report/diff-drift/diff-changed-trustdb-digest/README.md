# diff-changed-trustdb-digest

- **class:** diff-drift
- **edge_case_axis:** diff-drift

## Intent

Under `--against-trustdb`, the resolved trust-DB digest for an enumerable
grant differs from the digest baked into a prior snapshot. The current
ruleset and the snapshot share the same canonical grant key
(`allow open exe=/usr/bin/rpm : all`), but the resolved trust digest for
`/usr/bin/rpm` differs, so the diff yields exactly one `changed`
(integrity-drift) row. This is the "the allowed binary's hash changed"
case (f2 section 4.2 `changed`).

## Input

- `rules.d/A4-trustdigest.rules`: a single path-scoped allow grant for
  `/usr/bin/rpm`.
- Flags: `--against-trustdb <fixture>` AND
  `--diff-against <snapshot.json>`.

## Snapshot (diff_against)

A prior register snapshot where the trustJoin digest for `/usr/bin/rpm`
was an OLD 64-hex value (NOT `4153ba40...`). The current fixture trust DB
records the NEW digest `4153ba40ce4cbbe142248737a1438016d504ec50d00a186d9a0958e482de0826`
for the same path. Same canonical grant key, differing resolved trust
digest, so the drift output carries one `changed` row whose `from.hash`
is the OLD snapshot digest and `to.hash` is the NEW digest above.

## golden-register.json

The §3.2 register for the CURRENT ruleset under `--against-trustdb`:
one path-scoped grant whose `hashOrigin` is `trustdb` and whose resolved
`hash` is the REAL on-disk SHA256 of `/usr/bin/rpm` in `fapolicyd9`
(`fapolicyd-1.4.5-1.1.el9_8`), plus a top-level `trustJoin` row with the
real `(path,size,digest,source)`. The drift envelope itself is described
above; the golden register is the emit-side artifact the diff consumes.

## Oracle / ground truth

- Real values captured from container `fapd-rep-cdtd2` (`fapolicyd9`):
  `/usr/bin/rpm` size `24200`, sha256
  `4153ba40ce4cbbe142248737a1438016d504ec50d00a186d9a0958e482de0826`.
  `rpm -qf /usr/bin/rpm` = `rpm-4.16.1.3-40.el9.x86_64`, so the trust
  source is `RpmDb` (int 1) per `TrustSource::from_int` (`trustdb.rs:42-50`).
- Note: `fapolicyd9` ships `/etc/fapolicyd/fapolicyd.trust` with only
  commented example lines and an empty `trust.d/`; `--dump-db` produced no
  live entry (the minimal container has no compiled `data.mdb`, matching
  f2 section 8). The captured `(size,sha256)` come from the real on-disk
  binary, which is exactly the bytes fapolicyd would hash, and the source
  is RpmDb because rpm owns the file. These are REAL ground-truth values,
  not the commented example digest.
