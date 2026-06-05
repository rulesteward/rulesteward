# paths-multi-same-side

**Class:** path-extraction
**Edge-case axis:** path-extraction

## Intent

A subject with `exe=` AND `comm=` (comm is not a path): only `exe`
extracted to `subjectPaths`, `comm` ignored for path extraction.

A single allow-grant whose subject carries two attrs, `exe=` (a concrete
path) and `comm=` (a process command name, NOT a path). The register
renders the full subject predicate (`exe=/usr/bin/python3.14 comm=dnf`)
but extracts ONLY the `exe=` value into `subjectPaths`; `comm=` is not a
path-bearing attr and is excluded from extraction. `objectPaths` is
empty (object is `all`). Scope is `path`.

## Input

- `rules.d/85-execomm.rules`: `allow perm=open exe=/usr/bin/python3.14 comm=dnf : all`

No `--against-trustdb`, no `--diff-against`.

## Oracle

Golden envelope computed by the f2 section 3.2 mapping (spec-derived):
both `exe=` and `comm=` are subject-only attrs (`attrs.rs` SUBJECT_ONLY)
and render into the `subject` string space-separated in source order via
`Display for Rule`; path extraction is limited to `exe=`/`path=`/`dir=`,
so only `/usr/bin/python3.14` lands in `subjectPaths` and `comm=dnf` is
ignored; no inline hash so hash null / hashOrigin `none` / hashAlgorithm
null; scope `path`; single grant `loadIndex` 1, `source.line` 1.

Primary source: `/home/runner/rulesteward-docs/f2-report-emitter-grounding.md`
sections 2.2 and 3.2.
