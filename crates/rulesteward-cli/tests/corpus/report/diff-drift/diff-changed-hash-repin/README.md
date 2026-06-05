# diff-changed-hash-repin

- **class:** diff-drift
- **edge_case_axis:** diff-drift

## Intent

Drift where a grant's RULE-EMBEDDED `filehash=` value changed (a re-pin). The
current ruleset and the `--diff-against` snapshot share the same canonical grant
key, but the attached integrity hash differs, so the diff yields exactly one
`changed` (integrity-drift) row. This is the "the allowed binary was re-pinned to
a new digest" case (f2 section 4.2 `changed`).

## Input

- `rules.d/A7-repin.rules`:
  `allow perm=open all : filehash=fedcba98...6543210` (the NEW 64-hex pin).
- Flags: `--diff-against <snapshot.json>` (no `--against-trustdb`).

## Snapshot (diff_against)

`snapshot.json` is a valid section-3.2 `exception-register` envelope holding the
SAME grant with the OLD 64-hex filehash
`0123456789abcdef...0123456789abcdef`. `report --diff-against snapshot.json`
over the current ruleset yields exactly one `changed` row.

## Why one `changed` row (f2 sections 4.1 / 4.2 / 4.3)

- The diff key is the canonical predicate tuple
  `(decision, perm, sorted(subject), sorted(object), set-expanded)` (f2 section
  4.1). f2 section 4.2 lists "the `hash` (a grant re-pinned to a new digest)" as
  an explicit `changed` case, so the HASH VALUE is treated as an attached
  attribute that can differ WITHOUT changing the canonical key (otherwise a
  re-pin would surface as an `added` + a `removed`, which f2 section 4.2
  explicitly does not want). The canonical key here is therefore
  `(allow, open, [all], filehash-pinned object, no set)` and is identical
  between snapshot and current; only the attached `hash` differs.
- Same key, differing attached `hash`, so the row classifies `changed`
  (f2 section 4.2). A `changed` row carries BOTH `from` (the snapshot register
  row, OLD hash) and `to` (the current register row, NEW hash), per f2 section
  4.3 ("CHANGED rows carry both from and to register rows"). `grant` mirrors the
  current (`to`) row, matching the `added`/`removed` precedent where `grant` is
  the present-state row.
- Both register rows are section-3.2 rows: `scope:"hash"`,
  `hashOrigin:"rule-filehash"`, `hashAlgorithm:"SHA256"` (64 hex -> SHA256 by the
  length convention), `subjectPaths`/`objectPaths` empty (a filehash value is not
  a path), `setExpansions:{}`, `source.line:1`, `loadIndex:1`.
- The drift envelope is `{schemaVersion:1, kind:"exception-register-drift",
  drift:[...]}` (f2 section 4.3).

## Oracle / ground truth

The two 64-hex values are deterministic placeholder digests (static inline pins,
`against_trustdb:false`, no trust-DB capture). The drift is purely a property of
the two ruleset/snapshot texts, computed by the f2 section 4 diff over the
section-3.2 register rows.
