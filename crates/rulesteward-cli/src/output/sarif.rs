//! SARIF 2.1.0 diagnostic rendering (Feature 3e).
//!
//! Builds a [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
//! log from a slice of [`Diagnostic`] using the `serde-sarif` 0.8 type-safe
//! builders, then serializes it to pretty JSON. The output validates against
//! the official OASIS SARIF 2.1.0 JSON schema.
//!
//! Mapping (one SARIF `result` per `Diagnostic`, preserving input order):
//!   * `code`     -> `result.ruleId`
//!   * `severity` -> `result.level` (Fatal/Error -> "error";
//!     Warning -> "warning"; Style/Convention/Extra -> "note")
//!   * `message`  -> `result.message.text`
//!   * `file`     -> `physicalLocation.artifactLocation.uri`
//!   * `line`     -> `region.startLine`
//!   * `column`   -> `region.startColumn`

use rulesteward_core::{Diagnostic, Severity};
use serde_sarif::sarif::{
    ArtifactLocation, Location, Message, PhysicalLocation, Region, Result as SarifResult,
    ResultLevel, Run, Sarif, Tool, ToolComponent,
};

use super::RenderError;

/// The driver name recorded in `tool.driver.name`.
const DRIVER_NAME: &str = "rulesteward";

/// The project home page, recorded in `tool.driver.informationUri`.
const INFORMATION_URI: &str = "https://github.com/ErstBlack/rulesteward";

/// Map a [`Severity`] to its SARIF [`ResultLevel`].
///
/// Fatal/Error escalate to `error`; Warning is `warning`; the advisory tiers
/// (Style/Convention/Extra) all collapse to `note`.
const fn severity_to_level(severity: Severity) -> ResultLevel {
    match severity {
        Severity::Fatal | Severity::Error => ResultLevel::Error,
        Severity::Warning => ResultLevel::Warning,
        Severity::Style | Severity::Convention | Severity::Extra => ResultLevel::Note,
    }
}

/// Build the single SARIF `result` for one diagnostic.
fn diagnostic_to_result(diag: &Diagnostic) -> SarifResult {
    // `Region` line/column are i64 in the SARIF schema; the Diagnostic stores
    // them as usize (1-based). The cast is lossless for any real source file.
    let region = Region::builder()
        .start_line(i64::try_from(diag.line).unwrap_or(i64::MAX))
        .start_column(i64::try_from(diag.column).unwrap_or(i64::MAX))
        .build();

    let artifact_location = ArtifactLocation::builder()
        .uri(diag.file.display().to_string())
        .build();

    let physical_location = PhysicalLocation::builder()
        .artifact_location(artifact_location)
        .region(region)
        .build();

    let location = Location::builder()
        .physical_location(physical_location)
        .build();

    SarifResult::builder()
        .rule_id(diag.code.to_string())
        .level(severity_to_level(diag.severity))
        .message(Message::builder().text(diag.message.clone()).build())
        .locations(vec![location])
        .build()
}

/// Render diagnostics as a SARIF 2.1.0 log serialized to pretty JSON.
///
/// Diagnostic order is preserved in `runs[0].results[]`. The returned string
/// has no trailing newline added beyond what `serde_json` produces (pretty
/// JSON already ends without one); the dispatcher / CLI print it verbatim.
///
/// # Errors
/// Returns [`RenderError::Serialization`] if `serde_json` fails to serialize
/// the SARIF log. In practice this cannot happen for the value built here
/// (every field is a plain JSON-representable type), but the SARIF log is
/// serialized via the fallible `serde_json::to_string_pretty`, so the error
/// path is surfaced rather than silently `expect`-ed.
pub fn render(diags: &[Diagnostic]) -> Result<String, RenderError> {
    let results: Vec<SarifResult> = diags.iter().map(diagnostic_to_result).collect();

    let driver = ToolComponent::builder()
        .name(DRIVER_NAME)
        .version(env!("CARGO_PKG_VERSION").to_string())
        .information_uri(INFORMATION_URI)
        .build();

    let run = Run::builder()
        .tool(Tool::builder().driver(driver).build())
        .results(results)
        .build();

    let log = Sarif::builder()
        .schema(serde_sarif::sarif::SCHEMA_URL.to_string())
        .version(serde_json::Value::String(
            serde_sarif::sarif::Version::V2_1_0.to_string(),
        ))
        .runs(vec![run])
        .build();

    serde_json::to_string_pretty(&log).map_err(|e| RenderError::Serialization(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn severity_levels_map_to_sarif_levels() {
        assert_eq!(severity_to_level(Severity::Fatal), ResultLevel::Error);
        assert_eq!(severity_to_level(Severity::Error), ResultLevel::Error);
        assert_eq!(severity_to_level(Severity::Warning), ResultLevel::Warning);
        assert_eq!(severity_to_level(Severity::Style), ResultLevel::Note);
        assert_eq!(severity_to_level(Severity::Convention), ResultLevel::Note);
        assert_eq!(severity_to_level(Severity::Extra), ResultLevel::Note);
    }

    #[test]
    fn empty_diags_render_valid_sarif_with_empty_results() {
        let out = render(&[]).expect("render empty");
        let v: Value = serde_json::from_str(&out).expect("parse JSON");
        assert_eq!(v.get("version").and_then(Value::as_str), Some("2.1.0"));
        let results = v
            .pointer("/runs/0/results")
            .and_then(Value::as_array)
            .expect("results array");
        assert!(results.is_empty(), "no diagnostics -> empty results");
    }

    #[test]
    fn render_preserves_diagnostic_order_and_fields() {
        let diags = vec![
            Diagnostic::new(Severity::Error, "fapd-E01", 0..1, "first", "/a.rules", 3, 7),
            Diagnostic::new(
                Severity::Warning,
                "fapd-W01",
                0..1,
                "second",
                "/b.rules",
                9,
                2,
            ),
        ];
        let out = render(&diags).expect("render");
        let v: Value = serde_json::from_str(&out).expect("parse");
        let results = v
            .pointer("/runs/0/results")
            .and_then(Value::as_array)
            .expect("results");
        assert_eq!(results.len(), 2);
        assert_eq!(
            results[0].get("ruleId").and_then(Value::as_str),
            Some("fapd-E01")
        );
        assert_eq!(
            results[0].get("level").and_then(Value::as_str),
            Some("error")
        );
        assert_eq!(
            results[0]
                .pointer("/locations/0/physicalLocation/region/startColumn")
                .and_then(Value::as_u64),
            Some(7)
        );
        assert_eq!(
            results[1].get("ruleId").and_then(Value::as_str),
            Some("fapd-W01")
        );
    }
}
