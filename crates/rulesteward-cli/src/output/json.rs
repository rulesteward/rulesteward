//! JSON output: a versioned envelope object
//! `{ "schemaVersion": N, "diagnostics": [ ... ] }`.

use rulesteward_core::Diagnostic;
use serde::Serialize;

/// Current JSON output schema version. Per spec section 11 the JSON schema is
/// versioned; this bumps only on a backwards-incompatible (semver-major) change
/// to the envelope shape below. v0.1.0 freezes it at 1.
const SCHEMA_VERSION: u32 = 1;

#[derive(Serialize)]
struct JsonReport<'a> {
    #[serde(rename = "schemaVersion")]
    schema_version: u32,
    diagnostics: &'a [Diagnostic],
}

#[must_use]
pub fn render(diags: &[Diagnostic]) -> String {
    let report = JsonReport {
        schema_version: SCHEMA_VERSION,
        diagnostics: diags,
    };
    let mut s =
        serde_json::to_string_pretty(&report).expect("Diagnostic serialization cannot fail");
    s.push('\n');
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use rulesteward_core::Severity;

    #[test]
    fn json_is_versioned_envelope_with_diagnostics_array() {
        // v0.1.0 freezes the JSON contract as a VERSIONED ENVELOPE object
        // `{ "schemaVersion": 1, "diagnostics": [...] }` (spec section 11 promises a
        // versioned schema). RED before the envelope lands (output is a bare array).
        let d = Diagnostic::new(
            Severity::Error,
            "fapd-E01",
            5..10,
            "unknown attribute",
            "/tmp/x.rules",
            3,
            12,
        );
        let out = render(std::slice::from_ref(&d));
        let v: serde_json::Value = serde_json::from_str(&out).expect("re-parse json output");
        assert_eq!(
            v["schemaVersion"],
            serde_json::json!(1),
            "JSON output must carry schemaVersion=1: {out}"
        );
        let arr = v["diagnostics"]
            .as_array()
            .expect("`diagnostics` must be an array");
        assert_eq!(arr.len(), 1);
        let parsed: Diagnostic =
            serde_json::from_value(arr[0].clone()).expect("diagnostic round-trips in envelope");
        assert_eq!(parsed, d);
    }

    #[test]
    fn json_empty_diags_is_envelope_with_empty_array_not_bare_array() {
        let out = render(&[]);
        let v: serde_json::Value = serde_json::from_str(&out).expect("re-parse");
        assert_eq!(v["schemaVersion"], serde_json::json!(1));
        assert!(
            v["diagnostics"]
                .as_array()
                .expect("`diagnostics` array")
                .is_empty()
        );
        assert!(
            v.is_object(),
            "v0.1.0 JSON is a versioned envelope object, not the old bare array"
        );
    }

    #[test]
    fn json_output_ends_with_newline() {
        // Machine-readable output ends with a trailing newline (shell-pipeline safety).
        assert!(render(&[]).ends_with('\n'));
    }
}
