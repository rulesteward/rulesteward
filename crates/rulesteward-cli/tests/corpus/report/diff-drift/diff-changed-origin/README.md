# diff-changed-origin

- **class:** diff-drift
- **edge_case_axis:** diff-drift

## Intent

Drift where a grant's `hashOrigin` changed. The snapshot was emitted WITHOUT
`--against-trustdb` (so the concrete-path grant had `hashOrigin:"none"`,
`hash:null`); the current run is WITH `--against-trustdb`, so the same grant joins
to the trust DB and resolves a digest (`hashOrigin:"trustdb"`, a real SHA256).
Same canonical grant key, differing attached `hash` + `hashOrigin`, so the diff
yields exactly one `changed` row (f2 section 4.2 - the `hashOrigin` change is an
explicitly listed `changed` trigger).

## Input

- `rules.d/A8-origin.rules`: `allow perm=open exe=/usr/bin/rpm : all`
  (a single path-scoped allow grant for `/usr/bin/rpm`).
- Flags: `--against-trustdb <fixture>` AND `--diff-against <snapshot.json>`.

## Snapshot (diff_against)

`snapshot.json` is a valid section-3.2 `exception-register` envelope holding the
SAME grant as it appeared in a PRIOR run that was NOT given `--against-trustdb`:
`hash:null`, `hashOrigin:"none"`, `hashAlgorithm:null`. The current run, given
`--against-trustdb`, resolves the trust-DB digest for `/usr/bin/rpm`, so the
current register row carries `hashOrigin:"trustdb"` and the resolved SHA256.

## Why one `changed` row (f2 sections 4.1 / 4.2 / 4.3)

- The canonical key `(decision, perm, sorted(subject), sorted(object),
  set-expanded)` (f2 section 4.1) is identical between snapshot and current:
  `(allow, open, [exe=/usr/bin/rpm], [all], no set)`. Only the attached
  `hash`/`hashOrigin` differ (the join resolution), which f2 section 4.2 lists as
  a `changed` trigger ("the `hashOrigin`, or (under `--against-trustdb`) the
  resolved trust-DB digest").
- Same key, differing attached origin/hash, so the row classifies `changed`.
  A `changed` row carries BOTH `from` (snapshot row, `hashOrigin:"none"`) and `to`
  (current row, `hashOrigin:"trustdb"`), per f2 section 4.3. `grant` mirrors the
  current (`to`) row.
- Both register rows are section-3.2 rows for a concrete-path grant:
  `scope:"path"`, `subjectPaths:["/usr/bin/rpm"]`, `objectPaths:[]`,
  `setExpansions:{}`, `source.line:1`, `loadIndex:1`. The `from` row's hash trio
  is null/none/null; the `to` row's is the resolved SHA256 / `trustdb` / `SHA256`.
- The drift envelope is `{schemaVersion:1, kind:"exception-register-drift",
  drift:[...]}` (f2 section 4.3). The drift envelope itself carries no top-level
  `trustJoin` block (that block belongs to the emit-side `exception-register`
  envelope, f2 section 3.2); the resolved digest lives inside the `to` row's
  `hash` field.

## Oracle / ground truth

- Real values captured from container `fapd-rep-cdtd2` (`fapolicyd9`,
  `fapolicyd-1.4.5-1.1.el9_8`): `/usr/bin/rpm` size `24200`, sha256
  `4153ba40ce4cbbe142248737a1438016d504ec50d00a186d9a0958e482de0826`.
  `rpm -qf /usr/bin/rpm` = `rpm-4.16.1.3-40.el9.x86_64`, so the trust source is
  `RpmDb` (int 1) per `TrustSource::from_int` (`trustdb.rs:42-50`). These are the
  same real ground-truth values used by `diff-changed-trustdb-digest`.
