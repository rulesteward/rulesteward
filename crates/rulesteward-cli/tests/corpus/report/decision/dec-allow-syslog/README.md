# dec-allow-syslog

- **class:** decision
- **edge_case_axis:** decision

## Intent

decision keyword allow_syslog renders decision:"allow_syslog".

## Notes

The allow_syslog decision keyword renders decision:"allow_syslog". perm=any renders perm:"any". The object ftype=text/x-shellscript is a MIME-type predicate so scope=ftype, no path extraction, hash none (type-scoped, honest).

## Oracle

golden-register.json is the CORRECT canonical JSON envelope computed by the f2 section 3.2 mapping (spec-derived), applied to the rules.d/ input. No --against-trustdb and no --diff-against for this scenario, so there is no trustJoin block and the envelope is the plain exception-register shape. Primary source: f2-report-emitter-grounding.md sections 2.2 and 3.2.
