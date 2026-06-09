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
use rulesteward_fapolicyd::catalog::LintCode;
use serde_sarif::sarif::{
    ArtifactLocation, Location, Message, MultiformatMessageString, PhysicalLocation, Region,
    ReportingConfiguration, ReportingDescriptor, Result as SarifResult, ResultKind, ResultLevel,
    Run, Sarif, Tool, ToolComponent,
};

use super::RenderError;

/// Per-check coverage attestation payload for `--sarif-include-pass` (#137).
///
/// `rules` are every `fapd-` check that EVALUATED for this run (used to
/// populate `tool.driver.rules[]`); `passes` are the subset that evaluated AND
/// produced no finding (emitted as `kind:"pass"` results). Both are catalog
/// entries so the renderer has each code's id, severity, and description.
/// Constructed by the lint command from
/// [`rulesteward_fapolicyd::catalog::evaluated`] minus the codes that fired.
///
/// When `--sarif-include-pass` is off the renderer is given `None`, producing
/// byte-identical output to the pre-#137 form (no `rules[]`, no pass results).
#[derive(Debug)]
pub struct PassInfo {
    /// Every evaluated check (populates `tool.driver.rules[]`).
    pub rules: Vec<&'static LintCode>,
    /// Evaluated-and-clean checks (emitted as `kind:"pass"` results).
    pub passes: Vec<&'static LintCode>,
}

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

/// Build a `tool.driver.rules[]` entry (`ReportingDescriptor`) for a catalog
/// code: its id, a `shortDescription`, and the severity-mapped default level.
fn rule_descriptor(c: &LintCode) -> ReportingDescriptor {
    ReportingDescriptor::builder()
        .id(c.code.to_string())
        .short_description(
            MultiformatMessageString::builder()
                .text(c.description.to_string())
                .build(),
        )
        .default_configuration(
            ReportingConfiguration::builder()
                // `ReportingConfiguration.level` is `Option<serde_json::Value>`;
                // a `ResultLevel` serializes to its camelCase string
                // ("error"/"warning"/"note"). Serializing a fieldless enum
                // cannot fail, so the `unwrap_or_default` is unreachable defense.
                .level(serde_json::to_value(severity_to_level(c.severity)).unwrap_or_default())
                .build(),
        )
        .build()
}

/// Build a `kind:"pass"` coverage result for a clean evaluated check.
///
/// No `locations` is set: per-check coverage attestation ("this check ran over
/// the rule set and was clean") is analysis-wide, not anchored to a single
/// source line. `level` is `none`, the SARIF convention for a pass.
fn pass_result(c: &LintCode) -> SarifResult {
    SarifResult::builder()
        .rule_id(c.code.to_string())
        .kind(ResultKind::Pass)
        .level(ResultLevel::None)
        .message(
            Message::builder()
                .text(format!("{} evaluated; no findings", c.code))
                .build(),
        )
        .build()
}

/// Render diagnostics as a SARIF 2.1.0 log serialized to pretty JSON.
///
/// Diagnostic order is preserved in `runs[0].results[]`. The returned string
/// has no trailing newline added beyond what `serde_json` produces (pretty
/// JSON already ends without one); the dispatcher / CLI print it verbatim.
///
/// `pass` carries the per-check coverage attestation for `--sarif-include-pass`
/// (#137): `Some(..)` appends a `tool.driver.rules[]` catalog and one
/// `kind:"pass"` result per evaluated-and-clean check; `None` is byte-identical
/// to the pre-#137 output (no `rules[]`, findings only).
///
/// # Errors
/// Returns [`RenderError::Serialization`] if `serde_json` fails to serialize
/// the SARIF log. In practice this cannot happen for the value built here
/// (every field is a plain JSON-representable type), but the SARIF log is
/// serialized via the fallible `serde_json::to_string_pretty`, so the error
/// path is surfaced rather than silently `expect`-ed.
pub fn render(diags: &[Diagnostic], pass: Option<&PassInfo>) -> Result<String, RenderError> {
    let mut results: Vec<SarifResult> = diags.iter().map(diagnostic_to_result).collect();
    if let Some(pass) = pass {
        results.extend(pass.passes.iter().map(|c| pass_result(c)));
    }

    // Only attach `tool.driver.rules[]` when pass coverage is requested, so the
    // flag-off output stays byte-identical to the pre-#137 form. (TypedBuilder
    // setters change the builder type, hence two distinct build chains rather
    // than a conditional `.rules(..)` on one builder.)
    let driver = match pass {
        None => ToolComponent::builder()
            .name(DRIVER_NAME)
            .version(env!("CARGO_PKG_VERSION").to_string())
            .information_uri(INFORMATION_URI)
            .build(),
        Some(pass) => ToolComponent::builder()
            .name(DRIVER_NAME)
            .version(env!("CARGO_PKG_VERSION").to_string())
            .information_uri(INFORMATION_URI)
            .rules(
                pass.rules
                    .iter()
                    .map(|c| rule_descriptor(c))
                    .collect::<Vec<_>>(),
            )
            .build(),
    };

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

    // Append a trailing newline so machine-readable SARIF is shell-pipeline-safe
    // and consistent with the JSON renderer (output/json.rs).
    serde_json::to_string_pretty(&log)
        .map(|mut s| {
            s.push('\n');
            s
        })
        .map_err(|e| RenderError::Serialization(e.to_string()))
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
    fn render_output_ends_with_trailing_newline() {
        // Machine-readable output must end with a newline for shell-pipeline
        // safety, matching the JSON renderer (output/json.rs).
        let out = render(&[], None).expect("render empty");
        assert!(out.ends_with('\n'), "SARIF output must end with a newline");
    }

    #[test]
    fn empty_diags_render_valid_sarif_with_empty_results() {
        let out = render(&[], None).expect("render empty");
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
        let out = render(&diags, None).expect("render");
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
