# paths-none

**Class:** path-extraction
**Edge-case axis:** path-extraction

## Intent

A grant with no path-bearing attr; both `subjectPaths` and `objectPaths`
empty.

A single allow-grant whose subject is `all` and whose object is keyed on
a MIME type (`ftype=text/x-shellscript`). Neither side carries an
`exe=`/`path=`/`dir=` value, so both `subjectPaths` and `objectPaths`
are empty. This is the honest "type-scoped, no path" case. Scope is
`ftype`.

## Input

- `rules.d/84-nopaths.rules`: `allow perm=open all : ftype=text/x-shellscript`

No `--against-trustdb`, no `--diff-against`.

## Oracle

Golden envelope computed by the f2 section 3.2 mapping (spec-derived):
`ftype=` is not a path-bearing attr, so no extraction on either side;
both path arrays empty; no inline hash so hash null / hashOrigin `none`
/ hashAlgorithm null; scope `ftype`; single grant `loadIndex` 1,
`source.line` 1.

Primary source: `/home/runner/rulesteward-docs/f2-report-emitter-grounding.md`
sections 2.2 and 3.2.
