# dec-allow-log

- **class:** decision
- **edge_case_axis:** decision

## Intent

decision keyword allow_log renders decision:"allow_log".

## Notes

The allow_log decision keyword renders decision:"allow_log". The object dir=/var/tmp/ is a path-prefix so scope=dir and objectPaths=["/var/tmp/"] (dir is extracted as a path per f2 section 2.2).

## Oracle

golden-register.json is the CORRECT canonical JSON envelope computed by the f2 section 3.2 mapping (spec-derived), applied to the rules.d/ input. No --against-trustdb and no --diff-against for this scenario, so there is no trustJoin block and the envelope is the plain exception-register shape. Primary source: f2-report-emitter-grounding.md sections 2.2 and 3.2.
