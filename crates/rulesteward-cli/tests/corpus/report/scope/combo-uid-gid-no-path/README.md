# combo-uid-gid-no-path

- **class:** scope
- **edge_case_axis:** scope

## Intent

`uid=` and `gid=` narrow the subject but extract NO path; the object is `all`, so
the grant's scope is `all` and `subjectPaths` is empty. Confirms that subject
attributes which are not paths (uid/gid) do not leak into `subjectPaths`, mirroring
the materialized `perm-any` fixture where `uid=0` produces no subject path.

## Input

- `rules.d/C3-uidgid.rules`: `allow perm=any uid=0 gid=0 : all`
- No `--against-trustdb`, no `--diff-against`.

## Expected golden (golden-register.json)

A single allow-grant row:
- `decision: allow`, `perm: any`
- `subject: "uid=0 gid=0"` (both attrs render on the subject side; confirmed against
  the real chumsky parser via `parse_rules_file`)
- `object: "all"`
- `subjectPaths: []`, `objectPaths: []` (uid/gid are not path-bearing attributes)
- `hash: null`, `hashOrigin: "none"`, `hashAlgorithm: null`
- `scope: "all"` (no narrowing predicate beyond uid/gid; object is `all`)
- `setExpansions: {}`
- `source: { file: "C3-uidgid.rules", line: 1 }`, `loadIndex: 1`

## Oracle

f2 section 3.2 mapping (spec-derived). subject/object rendering and the empty
subjectPaths were confirmed empirically against `rulesteward-fapolicyd::parse_rules_file`
(the rule parses as a Modern-flavor rule, subject = [uid=0, gid=0], object = [all]).
No em-dashes in any file (hyphens / colons only).
