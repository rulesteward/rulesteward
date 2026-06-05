# dec-all-four-one-file

- **class:** decision
- **edge_case_axis:** decision

## Intent

One file with all four allow-family decisions plus a deny; register enumerates exactly the four allows, deny excluded.

## Notes

One file holds one of each allow-family decision (lines 1-4) plus a deny_audit (line 5). The register enumerates EXACTLY the four allow-family rules; the deny is excluded (allow-only, f2 Q2). loadIndex mirrors fapolicyd --list numbering over ALL compiled rules in load order: the four allows are 1,2,3,4; the deny occupies slot 5 in load order but is not emitted as a grant. Each row's scope matches its predicate kind (all, path, ftype, dir).

## Oracle

golden-register.json is the CORRECT canonical JSON envelope computed by the f2 section 3.2 mapping (spec-derived), applied to the rules.d/ input. No --against-trustdb and no --diff-against for this scenario, so there is no trustJoin block and the envelope is the plain exception-register shape. Primary source: f2-report-emitter-grounding.md sections 2.2 and 3.2.
