# paths-subject-exe

**Class:** path-extraction
**Edge-case axis:** path-extraction

## Intent

Subject `exe=` extracted to `subjectPaths`, `objectPaths` empty.

A single allow-grant whose subject pins a concrete executable
(`exe=/usr/bin/python3`) and whose object is `all`. The register must
extract the `exe=` value into `subjectPaths` (subject side) and leave
`objectPaths` empty, since the object carries no `exe=`/`path=`/`dir=`
value. Scope is `path` (the grant is keyed on a concrete path).

## Input

- `rules.d/80-subjexe.rules`: `allow perm=execute exe=/usr/bin/python3 : all`

No `--against-trustdb`, no `--diff-against`.

## Oracle

Golden envelope computed by the f2 section 3.2 mapping (spec-derived):
render subject/object predicates via `Display for Rule`, extract
`exe=`/`path=`/`dir=` values into `subjectPaths`/`objectPaths` by side,
no inline `filehash=`/`sha256hash=` so hash is null / hashOrigin `none`
/ hashAlgorithm null, scope `path`, single grant so `loadIndex` 1,
`source.line` 1.

Primary source: `/home/runner/rulesteward-docs/f2-report-emitter-grounding.md`
sections 2.2 and 3.2.
