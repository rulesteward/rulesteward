# perm-default-open

- **class:** perm
- **edge_case_axis:** perm

## Intent

A grant with no perm= defaults to open; golden perm:"open".

## Notes

A grant with no perm= clause defaults to open (spec 2.3; perm_clause().or_not() in grammar.rs makes perm Option<Perm> = None, mapped to "open" by the register). subject and object are both `all` so scope=all.

## Oracle

golden-register.json is the CORRECT canonical JSON envelope computed by the f2 section 3.2 mapping (spec-derived), applied to the rules.d/ input. No --against-trustdb and no --diff-against for this scenario, so there is no trustJoin block and the envelope is the plain exception-register shape. Primary source: f2-report-emitter-grounding.md sections 2.2 and 3.2.
