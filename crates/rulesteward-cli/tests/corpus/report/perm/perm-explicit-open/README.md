# perm-explicit-open

- **class:** perm
- **edge_case_axis:** perm

## Intent

Explicit perm=open renders perm:"open", indistinguishable in output from the default.

## Notes

Explicit perm=open renders perm:"open". The golden output is byte-identical to perm-default-open's grant row except for the source file/line: the register cannot distinguish a defaulted-open from an explicit-open perm, which is the point of this paired scenario.

## Oracle

golden-register.json is the CORRECT canonical JSON envelope computed by the f2 section 3.2 mapping (spec-derived), applied to the rules.d/ input. No --against-trustdb and no --diff-against for this scenario, so there is no trustJoin block and the envelope is the plain exception-register shape. Primary source: f2-report-emitter-grounding.md sections 2.2 and 3.2.
