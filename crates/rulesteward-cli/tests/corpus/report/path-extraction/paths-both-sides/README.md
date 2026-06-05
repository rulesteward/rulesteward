# paths-both-sides

**Class:** path-extraction
**Edge-case axis:** path-extraction

## Intent

`exe=` on subject AND `path=` on object; both `subjectPaths` and
`objectPaths` populated.

A single allow-grant that pins a concrete executable on the subject
(`exe=/usr/bin/rpm`) and a concrete object path
(`path=/var/lib/rpm/Packages`). The register extracts the subject `exe=`
into `subjectPaths` and the object `path=` into `objectPaths`, proving
both-side extraction in one row. Scope is `path`.

## Input

- `rules.d/83-bothpaths.rules`: `allow perm=execute exe=/usr/bin/rpm : path=/var/lib/rpm/Packages`

No `--against-trustdb`, no `--diff-against`.

## Oracle

Golden envelope computed by the f2 section 3.2 mapping (spec-derived):
subject `exe=` (subject-only attr) -> `subjectPaths`; object `path=`
(object-only attr) -> `objectPaths`; no inline hash so hash null /
hashOrigin `none` / hashAlgorithm null; scope `path`; single grant
`loadIndex` 1, `source.line` 1.

Primary source: `/home/runner/rulesteward-docs/f2-report-emitter-grounding.md`
sections 2.2 and 3.2.
