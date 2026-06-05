# dec-allow-audit

- **class:** decision
- **edge_case_axis:** decision

## Intent

decision keyword allow_audit renders decision:"allow_audit".

## Notes

The allow_audit decision keyword is one of the four allow-family decisions the register enumerates (allow | allow_audit | allow_syslog | allow_log, ast.rs:11-20). The subject exe=/usr/bin/rpm is a concrete path so scope=path and subjectPaths=["/usr/bin/rpm"]; the object side is `all`.

## Oracle

golden-register.json is the CORRECT canonical JSON envelope computed by the f2 section 3.2 mapping (spec-derived), applied to the rules.d/ input. No --against-trustdb and no --diff-against for this scenario, so there is no trustJoin block and the envelope is the plain exception-register shape. Primary source: f2-report-emitter-grounding.md sections 2.2 and 3.2.
