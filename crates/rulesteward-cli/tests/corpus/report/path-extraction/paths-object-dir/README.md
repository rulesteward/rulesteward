# paths-object-dir

**Class:** path-extraction
**Edge-case axis:** path-extraction

## Intent

Object `dir=` extracted to `objectPaths` as a path prefix.

A single allow-grant whose object is keyed on a directory prefix
(`dir=/opt/app/`). The `dir=` value is path-bearing, so it is extracted
into `objectPaths` (trailing slash preserved verbatim). `subjectPaths`
is empty (`uid=` is not a path). Scope is `dir` (the grant is keyed on a
path prefix, distinct from a concrete `path=`).

## Input

- `rules.d/82-objdir.rules`: `allow perm=any uid=0 : dir=/opt/app/`

No `--against-trustdb`, no `--diff-against`.

## Oracle

Golden envelope computed by the f2 section 3.2 mapping (spec-derived):
`dir=` is path-bearing and both-sides (`attrs.rs` BOTH_SIDES), here on
the object side, extracted to `objectPaths`; the value `/opt/app/` is
preserved exactly including the trailing slash; no inline hash so hash
null / hashOrigin `none` / hashAlgorithm null; scope `dir`; single grant
`loadIndex` 1, `source.line` 1.

Primary source: `/home/runner/rulesteward-docs/f2-report-emitter-grounding.md`
sections 2.2 and 3.2.
