# paths-object-path

**Class:** path-extraction
**Edge-case axis:** path-extraction

## Intent

Object `path=` extracted to `objectPaths`, `subjectPaths` empty.

A single allow-grant whose subject narrows by `uid=0` (no path attr) and
whose object pins a concrete `path=/usr/bin/ls`. The register extracts
the object `path=` value into `objectPaths` and leaves `subjectPaths`
empty (`uid=` is not a path attr). Scope is `path`.

## Input

- `rules.d/81-objpath.rules`: `allow perm=open uid=0 : path=/usr/bin/ls`

No `--against-trustdb`, no `--diff-against`.

## Oracle

Golden envelope computed by the f2 section 3.2 mapping (spec-derived):
`path=` is an object-only attr (`attrs.rs` OBJECT_ONLY), extracted to
`objectPaths`; `uid=` extracts no path so `subjectPaths` is empty; no
inline hash so hash null / hashOrigin `none` / hashAlgorithm null; scope
`path`; single grant `loadIndex` 1, `source.line` 1.

Primary source: `/home/runner/rulesteward-docs/f2-report-emitter-grounding.md`
sections 2.2 and 3.2.
