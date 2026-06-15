//! SARIF 2.1.0 renderer round-trip + schema-validation tests (Feature 3e).
//!
//! These tests assert the structure a CORRECT `output::render(Sarif, ..)`
//! implementation must produce: a SARIF 2.1.0 log that validates against the
//! OFFICIAL OASIS schema and carries the per-diagnostic ruleId / level /
//! message / location fields.
//!
//! RED state (test-author phase): `output/sarif.rs::render` is still the stub
//! returning `Err(RenderError::SarifNotImplemented)`, so `output::render`
//! returns `Err` and the very first `.expect(..)` below fails. The implementer
//! replaces the stub with a real serde-sarif serializer to turn these GREEN.
//!
//! SARIF 2.1.0 schema source (bundled as a test fixture, committed alongside):
//!   <https://json.schemastore.org/sarif-2.1.0.json>
//! whose `$id` is the canonical OASIS schema
//!   <https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json>
//! (JSON Schema draft-07). Retrieved 2026-05-30.

use std::collections::BTreeMap;

use boon::{Compiler, Schemas};
use rulesteward_cli::cli::OutputFormat;
use rulesteward_cli::output::render;
use rulesteward_core::{Diagnostic, Severity};
use serde_json::Value;

/// A known set of diagnostics covering ALL SIX severity tiers so the
/// level-mapping assertions below are non-vacuous and every arm of the
/// severity -> SARIF-level map is independently pinned:
///   Fatal      -> SARIF level "error"
///   Error      -> SARIF level "error"
///   Warning    -> SARIF level "warning"
///   Style      -> SARIF level "note"
///   Convention -> SARIF level "note"
///   Extra      -> SARIF level "note"
///
/// Distinct expected levels per arm let a wrong mapping fail: e.g. a
/// `Fatal -> "note"`, `Convention -> "warning"`, or `Extra -> "warning"`
/// regression is caught by the per-result `level` assertions below.
fn sample_diags() -> Vec<Diagnostic> {
    vec![
        Diagnostic::new(
            Severity::Fatal,
            "fapd-F01",
            0..1,
            "rules file does not parse",
            "/etc/fapolicyd/rules.d/10-fatal.rules",
            1,
            1,
        ),
        Diagnostic::new(
            Severity::Error,
            "fapd-E02",
            5..8,
            "filehash is not a 64-char hex digest",
            "/etc/fapolicyd/rules.d/30-bad.rules",
            3,
            12,
        ),
        Diagnostic::new(
            Severity::Warning,
            "fapd-W03",
            0..4,
            "inline trailing comment is ignored by fapolicyd",
            "/etc/fapolicyd/rules.d/40-warn.rules",
            7,
            1,
        ),
        Diagnostic::new(
            Severity::Style,
            "fapd-S02",
            0..0,
            "macro defined after first rule",
            "/etc/fapolicyd/rules.d/50-style.rules",
            2,
            1,
        ),
        Diagnostic::new(
            Severity::Convention,
            "fapd-C01",
            0..0,
            "rule ordering does not follow recommended convention",
            "/etc/fapolicyd/rules.d/60-conv.rules",
            4,
            1,
        ),
        Diagnostic::new(
            Severity::Extra,
            "fapd-X01",
            0..0,
            "extra informational note",
            "/etc/fapolicyd/rules.d/70-extra.rules",
            5,
            1,
        ),
    ]
}

/// The expected `(ruleId, level, uri, startLine)` row for each `sample_diags()`
/// entry, in order. Pins all six severity -> SARIF-level arms:
///   Fatal/Error -> "error"; Warning -> "warning";
///   Style/Convention/Extra -> "note".
/// A wrong mapping (e.g. `Fatal -> "note"`, `Convention -> "warning"`,
/// `Extra -> "warning"`) fails the per-result `level` assertion that consumes
/// this table.
fn expected_results() -> [(&'static str, &'static str, &'static str, u64); 6] {
    [
        (
            "fapd-F01",
            "error",
            "/etc/fapolicyd/rules.d/10-fatal.rules",
            1,
        ),
        (
            "fapd-E02",
            "error",
            "/etc/fapolicyd/rules.d/30-bad.rules",
            3,
        ),
        (
            "fapd-W03",
            "warning",
            "/etc/fapolicyd/rules.d/40-warn.rules",
            7,
        ),
        (
            "fapd-S02",
            "note",
            "/etc/fapolicyd/rules.d/50-style.rules",
            2,
        ),
        (
            "fapd-C01",
            "note",
            "/etc/fapolicyd/rules.d/60-conv.rules",
            4,
        ),
        (
            "fapd-X01",
            "note",
            "/etc/fapolicyd/rules.d/70-extra.rules",
            5,
        ),
    ]
}

/// The SARIF renderer ignores the `sources` map (only the human renderer uses
/// it), but `render` requires one.
fn empty_sources() -> BTreeMap<String, String> {
    BTreeMap::new()
}

/// Load the bundled official SARIF 2.1.0 schema as a `serde_json::Value`.
fn load_sarif_schema() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/sarif-2.1.0.schema.json"
    );
    let bytes = std::fs::read(path).expect("read bundled SARIF 2.1.0 schema fixture");
    serde_json::from_slice(&bytes).expect("bundled SARIF schema parses as JSON")
}

/// The rendered SARIF must (a) be `Ok`, (b) parse as JSON, and (c) validate
/// against the official SARIF 2.1.0 JSON schema using `boon`. A stub returning
/// `Err`, or a wrong serializer producing malformed SARIF, fails here.
#[test]
fn sarif_render_validates_against_official_schema() {
    let diags = sample_diags();
    let rendered = render(OutputFormat::Sarif, &diags, &empty_sources(), None)
        .expect("SARIF render must return Ok(String) for a real implementation");

    let instance: Value =
        serde_json::from_str(&rendered).expect("rendered SARIF must parse as JSON");

    let schema = load_sarif_schema();

    // boon 0.6.1: add the schema document under its own `$id`, compile by that
    // same loc, then validate the rendered instance against the compiled index.
    let schema_id = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json";
    let mut compiler = Compiler::new();
    compiler
        .add_resource(schema_id, schema)
        .expect("add SARIF schema resource");
    let mut schemas = Schemas::new();
    let sch_index = compiler
        .compile(schema_id, &mut schemas)
        .expect("compile SARIF 2.1.0 schema");

    if let Err(e) = schemas.validate(&instance, sch_index) {
        panic!(
            "rendered SARIF failed official-schema validation:\n{e}\n--- instance ---\n{rendered}"
        );
    }
}

/// The rendered SARIF must carry the exact top-level + per-result structure a
/// correct implementation produces. This is the discriminating assertion set:
/// a wrong impl that emits valid-but-empty SARIF, or omits ruleId/level/uri,
/// fails here even if it passed the schema gate.
#[test]
fn sarif_render_has_expected_structure() {
    let diags = sample_diags();
    let rendered = render(OutputFormat::Sarif, &diags, &empty_sources(), None)
        .expect("SARIF render must return Ok(String) for a real implementation");
    let v: Value = serde_json::from_str(&rendered).expect("rendered SARIF must parse as JSON");

    // Top-level SARIF identity.
    assert_eq!(
        v.get("version").and_then(Value::as_str),
        Some("2.1.0"),
        "top-level version must be \"2.1.0\""
    );
    assert!(
        v.get("$schema").and_then(Value::as_str).is_some(),
        "a top-level $schema URI must be present"
    );

    // Exactly one run, with the rulesteward driver.
    let runs = v
        .get("runs")
        .and_then(Value::as_array)
        .expect("runs[] array present");
    assert_eq!(runs.len(), 1, "exactly one run expected");
    assert_eq!(
        runs[0].pointer("/tool/driver/name").and_then(Value::as_str),
        Some("rulesteward"),
        "runs[0].tool.driver.name must be \"rulesteward\""
    );

    // One result per diagnostic, in order, with the discriminating fields.
    let results = runs[0]
        .get("results")
        .and_then(Value::as_array)
        .expect("runs[0].results[] array present");
    assert!(!results.is_empty(), "results[] must be non-empty");
    assert_eq!(
        results.len(),
        diags.len(),
        "one SARIF result per input diagnostic"
    );

    // Expected per-result (ruleId, level, uri, startLine), one row per
    // `sample_diags()` entry, pinning all six severity -> level arms.
    let expected = expected_results();

    for (i, (code, level, uri, start_line)) in expected.iter().enumerate() {
        let r = &results[i];
        assert_eq!(
            r.get("ruleId").and_then(Value::as_str),
            Some(*code),
            "result[{i}].ruleId must equal the diagnostic code"
        );
        assert_eq!(
            r.get("level").and_then(Value::as_str),
            Some(*level),
            "result[{i}].level must be the severity-mapped SARIF level"
        );
        assert!(
            r.pointer("/message/text")
                .and_then(Value::as_str)
                .is_some_and(|t| !t.is_empty()),
            "result[{i}].message.text must be a non-empty string"
        );
        assert_eq!(
            r.pointer("/locations/0/physicalLocation/artifactLocation/uri")
                .and_then(Value::as_str),
            Some(*uri),
            "result[{i}] artifactLocation.uri must equal the diagnostic file path"
        );
        assert_eq!(
            r.pointer("/locations/0/physicalLocation/region/startLine")
                .and_then(Value::as_u64),
            Some(*start_line),
            "result[{i}] region.startLine must equal the diagnostic line"
        );
    }
}

/// Regression: the SARIF driver `informationUri` must point at the canonical
/// project repository (`github.com/rulesteward/rulesteward`), not the historical
/// `ErstBlack/rulesteward`. SARIF consumers surface this as the tool's home
/// page, so a stale URL sends users to the wrong repo.
#[test]
fn sarif_render_information_uri_is_canonical_repo() {
    let diags = sample_diags();
    let rendered = render(OutputFormat::Sarif, &diags, &empty_sources(), None)
        .expect("SARIF render must return Ok(String)");
    let v: Value = serde_json::from_str(&rendered).expect("rendered SARIF must parse as JSON");
    let uri = v
        .pointer("/runs/0/tool/driver/informationUri")
        .and_then(Value::as_str)
        .expect("tool.driver.informationUri must be present");
    assert_eq!(
        uri, "https://github.com/rulesteward/rulesteward",
        "informationUri must be the canonical repo URL, not a stale fork"
    );
}
