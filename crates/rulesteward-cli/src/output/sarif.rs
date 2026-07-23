//! SARIF 2.1.0 diagnostic rendering (Feature 3e).
//!
//! Builds a [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
//! log from a slice of [`Diagnostic`] using the `serde-sarif` 0.8 type-safe
//! builders, then serializes it to pretty JSON. The output validates against
//! the official OASIS SARIF 2.1.0 JSON schema.
//!
//! Dependency note (#194): `serde-sarif` is the de-facto standard SARIF crate but
//! is in low-maintenance mode. The decision is ACCEPT-with-a-watch -- our usage is
//! a narrow, schema-validated subset (this file only), so if an advisory or yank
//! ever lands on it the fallback is a ~200-LOC write-once vendor-light of just the
//! types we emit (the OASIS-schema test is the safety net). See issue #194.
//!
//! Mapping (one SARIF `result` per `Diagnostic`, preserving input order):
//!   * `code`     -> `result.ruleId`
//!   * `severity` -> `result.level` (Fatal/Error -> "error";
//!     Warning -> "warning"; Style/Convention/Extra -> "note")
//!   * `message`  -> `result.message.text`
//!   * `file`     -> `physicalLocation.artifactLocation.uri`
//!   * `line`     -> `region.startLine`
//!   * `column`   -> `region.startColumn`
//!
//! Control provenance (v0.7 L4, issue #505): `diag.controls` is read
//! generically for every diagnostic (no backend special-casing) and rendered
//! as SARIF taxonomies -- `runs[0].taxonomies[]` gets one `ToolComponent` per
//! distinct [`rulesteward_core::Framework`] present across the input, and each
//! control-bearing result's `taxa[]` references the matching taxon by id and
//! index. A diagnostic with no controls renders byte-identically to the
//! pre-L4 form: no `taxonomies` key, no `taxa` key on its result.

use std::collections::BTreeMap;

use rulesteward_core::{ControlRef, Diagnostic, Framework, Severity};
use rulesteward_fapolicyd::catalog::LintCode;
use serde_sarif::sarif::{
    ArtifactLocation, Location, Message, MultiformatMessageString, PhysicalLocation, PropertyBag,
    Region, ReportingConfiguration, ReportingDescriptor, ReportingDescriptorReference,
    Result as SarifResult, ResultKind, ResultLevel, Run, Sarif, Tool, ToolComponent,
    ToolComponentReference,
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
const INFORMATION_URI: &str = "https://github.com/rulesteward/rulesteward";

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

/// Distinct controls for one [`Framework`], in first-seen order across the
/// input diagnostics. One of these becomes one `runs[0].taxonomies[]`
/// [`ToolComponent`]; each entry becomes one taxon in its `taxa[]`.
type TaxonomyGroup = (Framework, Vec<ControlRef>);

/// Group every diagnostic's controls by framework, deduplicated by `id`,
/// preserving first-seen order for both the framework list and each
/// framework's control list.
///
/// This is the generic, backend-agnostic read of `diag.controls`: it makes no
/// assumption about which lint code or backend produced the finding, so a
/// later backend that starts tagging controls picks up taxonomy output
/// automatically. Returns an empty `Vec` when no diagnostic carries any
/// control, which is what lets [`render`] skip `taxonomies` entirely for the
/// byte-identical no-controls case.
fn collect_taxonomy_groups(diags: &[Diagnostic]) -> Vec<TaxonomyGroup> {
    let mut groups: Vec<TaxonomyGroup> = Vec::new();
    for diag in diags {
        for control in &diag.controls {
            let idx = groups
                .iter()
                .position(|(fw, _)| *fw == control.framework)
                .unwrap_or_else(|| {
                    groups.push((control.framework, Vec::new()));
                    groups.len() - 1
                });
            let group = &mut groups[idx];
            if !group.1.iter().any(|c| c.id == control.id) {
                group.1.push(control.clone());
            }
        }
    }
    groups
}

/// Find `control`'s position within its framework's group in `groups`.
///
/// Every control attached to a diagnostic is guaranteed to appear in the
/// group [`collect_taxonomy_groups`] built from the SAME diagnostic slice, so
/// this only returns `None` if called with a mismatched `groups` argument; the
/// `unwrap_or(0)` fallback at call sites is unreachable defense, matching the
/// project's other `unwrap_or` casts (e.g. `severity_to_level`'s callers).
fn control_taxon_index(groups: &[TaxonomyGroup], control: &ControlRef) -> Option<i64> {
    groups
        .iter()
        .find(|(fw, _)| *fw == control.framework)
        .and_then(|(_, controls)| controls.iter().position(|c| c.id == control.id))
        .and_then(|i| i64::try_from(i).ok())
}

/// Build one taxonomy `taxa[]` entry (a [`ReportingDescriptor`]) for a
/// control: its canonical `id`, plus `name` when the control carries a human
/// title, plus a `properties.aliases` bag carrying the control's `alias` (the
/// DISA V-number) when present.
///
/// `name` and `properties` are both `Option` fields on the `TypedBuilder`
/// (`strip_option`), so conditionally setting them on a single builder chain
/// would need a 4-way type-state branch. Instead the base descriptor (with the
/// required `id`) is built once, then the two optionals are assigned directly
/// to the public fields -- `None` leaves the field unset, so a no-name /
/// no-alias control emits neither key (`skip_serializing_if = Option::is_none`).
fn control_reporting_descriptor(control: &ControlRef) -> ReportingDescriptor {
    let mut descriptor = ReportingDescriptor::builder()
        .id(control.id.clone())
        .build();
    descriptor.name.clone_from(&control.name);
    if let Some(alias) = &control.alias {
        let mut properties = BTreeMap::new();
        // `additional_properties` is `#[serde(flatten)]`, so this key lands
        // directly inside the taxon's `properties` object:
        //   "properties": { "aliases": ["<V-number>"] }
        properties.insert(
            "aliases".to_string(),
            serde_json::Value::Array(vec![serde_json::Value::String(alias.clone())]),
        );
        descriptor.properties = Some(
            PropertyBag::builder()
                .additional_properties(properties)
                .build(),
        );
    }
    descriptor
}

/// Build one `runs[0].taxonomies[]` entry: a [`ToolComponent`] named after the
/// framework's uppercase label, whose `taxa[]` is one [`ReportingDescriptor`]
/// per distinct control in that framework.
fn taxonomy_component(framework: Framework, controls: &[ControlRef]) -> ToolComponent {
    ToolComponent::builder()
        .name(framework.name())
        .taxa(
            controls
                .iter()
                .map(control_reporting_descriptor)
                .collect::<Vec<_>>(),
        )
        .build()
}

/// Build one result `taxa[]` reference for a control: its own `id`, the
/// `index` into its framework's taxonomy `taxa[]` (so the reference resolves
/// precisely), and a [`ToolComponentReference`] naming the taxonomy component.
fn control_taxa_reference(
    control: &ControlRef,
    groups: &[TaxonomyGroup],
) -> ReportingDescriptorReference {
    ReportingDescriptorReference::builder()
        .id(control.id.clone())
        .index(control_taxon_index(groups, control).unwrap_or(0))
        .tool_component(
            ToolComponentReference::builder()
                .name(control.framework.name())
                .build(),
        )
        .build()
}

/// Build the single SARIF `result` for one diagnostic.
///
/// Reads `diag.controls` generically (no backend special-casing): when
/// non-empty, the result's `taxa[]` gets one [`ReportingDescriptorReference`]
/// per control, each resolvable against `taxonomy_groups` (built by
/// [`collect_taxonomy_groups`] over the SAME diagnostic slice passed to
/// [`render`]). When `diag.controls` is empty, `taxa` is left unset (`None`),
/// so a control-free diagnostic renders byte-identically to the pre-L4 form
/// (pinned by `sarif_no_controls_omits_taxonomy_keys`).
fn diagnostic_to_result(diag: &Diagnostic, taxonomy_groups: &[TaxonomyGroup]) -> SarifResult {
    let artifact_location = ArtifactLocation::builder()
        .uri(diag.file.display().to_string())
        .build();

    // The SARIF 2.1.0 schema requires `region.startLine`/`startColumn` >= 1
    // when `region` is present. An UNANCHORED diagnostic has no real source
    // byte range to report: `line == 0` is the codebase-wide convention for
    // this (see `rulesteward_core::diagnostic::anchored_at`'s doc, and e.g.
    // `sysctld`'s `w02_baseline` MISSING-key arm / fapolicyd's `file_level`
    // helper, both of which construct `Diagnostic::new(.., 0, 0)` with no
    // `source_id`). Emitting `region: {startLine: 0, ...}` for these would be
    // schema-invalid, so `region` is omitted entirely rather than lying about
    // a line that does not exist; `physicalLocation.artifactLocation.uri` (the
    // real file/dir the finding is about) is still emitted, matching the
    // human renderer's own "unanchored -> no snippet, but still named" shape.
    let physical_location = if diag.line == 0 {
        PhysicalLocation::builder()
            .artifact_location(artifact_location)
            .build()
    } else {
        // `Region` line/column are i64 in the SARIF schema; the Diagnostic
        // stores them as usize (1-based). The cast is lossless for any real
        // source file.
        let region = Region::builder()
            .start_line(i64::try_from(diag.line).unwrap_or(i64::MAX))
            .start_column(i64::try_from(diag.column).unwrap_or(i64::MAX))
            .build();
        PhysicalLocation::builder()
            .artifact_location(artifact_location)
            .region(region)
            .build()
    };

    let location = Location::builder()
        .physical_location(physical_location)
        .build();

    // TypedBuilder setters change the builder's type-state, so a conditional
    // `.taxa(..)` on one shared builder does not type-check; two full build
    // chains (as `render`'s `driver` construction already does for `rules[]`)
    // is the idiom.
    if diag.controls.is_empty() {
        SarifResult::builder()
            .rule_id(diag.code.to_string())
            .level(severity_to_level(diag.severity))
            .message(Message::builder().text(diag.message.clone()).build())
            .locations(vec![location])
            .build()
    } else {
        let taxa = diag
            .controls
            .iter()
            .map(|c| control_taxa_reference(c, taxonomy_groups))
            .collect::<Vec<_>>();
        SarifResult::builder()
            .rule_id(diag.code.to_string())
            .level(severity_to_level(diag.severity))
            .message(Message::builder().text(diag.message.clone()).build())
            .locations(vec![location])
            .taxa(taxa)
            .build()
    }
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
/// Control provenance (v0.7 L4): `diag.controls` is read generically for every
/// diagnostic and rendered as SARIF taxonomies -- `runs[0].taxonomies[]` gets
/// one [`ToolComponent`] per distinct [`Framework`] present, and each
/// control-bearing result gets a matching `taxa[]`. When no diagnostic carries
/// any control, `taxonomies` is omitted and no result gets a `taxa` key, so
/// output stays byte-identical to the pre-L4 form (e.g. fapolicyd, which never
/// tags controls).
///
/// # Errors
/// Returns [`RenderError::Serialization`] if `serde_json` fails to serialize
/// the SARIF log. In practice this cannot happen for the value built here
/// (every field is a plain JSON-representable type), but the SARIF log is
/// serialized via the fallible `serde_json::to_string_pretty`, so the error
/// path is surfaced rather than silently `expect`-ed.
pub fn render(diags: &[Diagnostic], pass: Option<&PassInfo>) -> Result<String, RenderError> {
    let taxonomy_groups = collect_taxonomy_groups(diags);
    let mut results: Vec<SarifResult> = diags
        .iter()
        .map(|d| diagnostic_to_result(d, &taxonomy_groups))
        .collect();
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

    // Only attach `runs[0].taxonomies` when at least one diagnostic carries a
    // control, so the no-controls output stays byte-identical to the pre-L4
    // form (same two-full-branch reasoning as the `driver` construction above).
    let run = if taxonomy_groups.is_empty() {
        Run::builder()
            .tool(Tool::builder().driver(driver).build())
            .results(results)
            .build()
    } else {
        let taxonomies = taxonomy_groups
            .iter()
            .map(|(framework, controls)| taxonomy_component(*framework, controls))
            .collect::<Vec<_>>();
        Run::builder()
            .tool(Tool::builder().driver(driver).build())
            .results(results)
            .taxonomies(taxonomies)
            .build()
    };

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
    fn sarif_emits_control_taxonomies() {
        // Inverts the v0.7 Phase-0 lock (formerly
        // `sarif_is_control_agnostic_in_v0_7_phase0`): L4 wires SARIF's
        // purpose-built compliance slot (`taxonomies` + per-result `taxa`), so
        // a control-bearing finding now DIFFERS from a control-free one, and
        // the taxonomy component / taxon / result reference are all mutually
        // resolvable (by id and by toolComponent.name + index).
        let d = Diagnostic::new(Severity::Warning, "sysctld-W02", 0..0, "x", "/e.conf", 1, 1)
            .with_controls(vec![
                ControlRef::new(Framework::Stig, "RHEL-08-040110").with_alias("V-230552"),
            ]);
        let out = render(&[d], None).expect("render");
        let v: Value = serde_json::from_str(&out).expect("parse");

        let taxonomies = v
            .pointer("/runs/0/taxonomies")
            .and_then(Value::as_array)
            .expect("runs[0].taxonomies present when a diagnostic carries controls");
        assert_eq!(taxonomies.len(), 1, "exactly one taxonomy component (STIG)");
        assert_eq!(
            taxonomies[0].get("name").and_then(Value::as_str),
            Some("STIG"),
            "taxonomy component name is the framework's uppercase label"
        );
        let taxa = taxonomies[0]
            .pointer("/taxa")
            .and_then(Value::as_array)
            .expect("taxonomy component has a taxa[] array");
        assert_eq!(taxa.len(), 1);
        assert_eq!(
            taxa[0].get("id").and_then(Value::as_str),
            Some("RHEL-08-040110"),
            "the taxon's id is the control's canonical id"
        );

        let result_taxa = v
            .pointer("/runs/0/results/0/taxa")
            .and_then(Value::as_array)
            .expect("result.taxa present when the diagnostic carries controls");
        assert_eq!(result_taxa.len(), 1);
        assert_eq!(
            result_taxa[0].get("id").and_then(Value::as_str),
            Some("RHEL-08-040110"),
            "result.taxa[0].id references the same control id"
        );
        assert_eq!(
            result_taxa[0]
                .pointer("/toolComponent/name")
                .and_then(Value::as_str),
            Some("STIG"),
            "result.taxa[0].toolComponent.name resolves to the STIG taxonomy component"
        );
        assert_eq!(
            result_taxa[0].get("index").and_then(Value::as_i64),
            Some(0),
            "result.taxa[0].index points at the taxon's position in the taxonomy's taxa[]"
        );
    }

    #[test]
    fn sarif_taxon_carries_alias_in_properties() {
        // A control's `alias` (the DISA V-number) is carried on the TAXON (the
        // canonical metadata home), inside a SARIF properties bag under an
        // `aliases` array -- NOT on the per-result taxa reference. This is the
        // machine-readable analogue of the human renderer's ` (STIG id/V-num)`
        // suffix.
        let d = Diagnostic::new(Severity::Warning, "sysctld-W02", 0..0, "x", "/e.conf", 1, 1)
            .with_controls(vec![
                ControlRef::new(Framework::Stig, "RHEL-08-040110").with_alias("V-230552"),
            ]);
        let out = render(&[d], None).expect("render");
        let v: Value = serde_json::from_str(&out).expect("parse");

        assert_eq!(
            v.pointer("/runs/0/taxonomies/0/taxa/0/properties/aliases/0")
                .and_then(Value::as_str),
            Some("V-230552"),
            "the taxon carries the DISA V-number under properties.aliases[0]"
        );
        // The alias lives on the taxon, not on the per-result reference.
        assert!(
            v.pointer("/runs/0/results/0/taxa/0/properties").is_none(),
            "the per-result taxa reference must NOT carry the alias properties"
        );
    }

    #[test]
    fn sarif_taxon_without_alias_omits_properties() {
        // A control with no alias emits NO properties key on its taxon, keeping
        // the no-alias sub-case minimal (additive-only: properties appears only
        // when there is an alias to carry).
        let d = Diagnostic::new(Severity::Warning, "sysctld-W02", 0..0, "x", "/e.conf", 1, 1)
            .with_controls(vec![ControlRef::new(Framework::Stig, "RHEL-08-040110")]);
        let out = render(&[d], None).expect("render");
        let v: Value = serde_json::from_str(&out).expect("parse");

        assert!(
            v.pointer("/runs/0/taxonomies/0/taxa/0").is_some(),
            "the taxon itself is present"
        );
        assert!(
            v.pointer("/runs/0/taxonomies/0/taxa/0/properties")
                .is_none(),
            "a control with no alias must emit no properties key on its taxon"
        );
    }

    #[test]
    fn sarif_dedups_the_same_control_across_diagnostics() {
        // Two diagnostics both citing the same STIG control id must share ONE
        // taxon (not two), and both results' taxa references must resolve to
        // that same index. Exercises the "generic across all diagnostics, not
        // per-diagnostic" grouping in `collect_taxonomy_groups`.
        let d1 = Diagnostic::new(Severity::Warning, "sysctld-W02", 0..0, "a", "/a.conf", 1, 1)
            .with_controls(vec![ControlRef::new(Framework::Stig, "RHEL-08-040110")]);
        let d2 = Diagnostic::new(Severity::Warning, "sysctld-W02", 0..0, "b", "/b.conf", 2, 1)
            .with_controls(vec![ControlRef::new(Framework::Stig, "RHEL-08-040110")]);
        let out = render(&[d1, d2], None).expect("render");
        let v: Value = serde_json::from_str(&out).expect("parse");

        let taxa = v
            .pointer("/runs/0/taxonomies/0/taxa")
            .and_then(Value::as_array)
            .expect("taxonomy taxa present");
        assert_eq!(taxa.len(), 1, "the shared control id dedups to one taxon");

        for i in 0..2 {
            let idx = v
                .pointer(&format!("/runs/0/results/{i}/taxa/0/index"))
                .and_then(Value::as_i64)
                .expect("result taxa index present");
            assert_eq!(idx, 0, "both results reference the same (only) taxon");
        }
    }

    #[test]
    fn sarif_no_controls_omits_taxonomy_keys() {
        // Additive-only contract: a diagnostic with EMPTY controls must render
        // byte-identically to the pre-L4 shape -- no `taxonomies` key on the
        // run, no `taxa` key on the result. This is what lets fapolicyd (which
        // never carries controls) stay byte-for-byte unchanged.
        let d = Diagnostic::new(Severity::Warning, "fapd-W01", 0..0, "x", "/e.rules", 1, 1);
        let out = render(&[d], None).expect("render");
        let v: Value = serde_json::from_str(&out).expect("parse");

        assert!(
            v.pointer("/runs/0/taxonomies").is_none(),
            "no controls anywhere -> no taxonomies key at all"
        );
        assert!(
            v.pointer("/runs/0/results/0/taxa").is_none(),
            "a control-free result must have no taxa key"
        );
    }

    #[test]
    fn sarif_two_frameworks_each_get_taxonomy_and_referenced_taxa() {
        // A finding carrying controls from TWO distinct frameworks gets two
        // taxonomy components, and the result's taxa references both.
        let d = Diagnostic::new(Severity::Warning, "sysctld-W02", 0..0, "x", "/e.conf", 1, 1)
            .with_controls(vec![
                ControlRef::new(Framework::Stig, "RHEL-08-040110"),
                ControlRef::new(Framework::Cis, "1.5.3"),
            ]);
        let out = render(&[d], None).expect("render");
        let v: Value = serde_json::from_str(&out).expect("parse");

        let taxonomies = v
            .pointer("/runs/0/taxonomies")
            .and_then(Value::as_array)
            .expect("taxonomies present");
        assert_eq!(
            taxonomies.len(),
            2,
            "one taxonomy component per distinct framework"
        );
        let names: Vec<&str> = taxonomies
            .iter()
            .filter_map(|t| t.get("name").and_then(Value::as_str))
            .collect();
        assert!(names.contains(&"STIG"), "STIG taxonomy component present");
        assert!(names.contains(&"CIS"), "CIS taxonomy component present");

        let result_taxa = v
            .pointer("/runs/0/results/0/taxa")
            .and_then(Value::as_array)
            .expect("result.taxa present");
        assert_eq!(result_taxa.len(), 2, "one taxa reference per control");
        let ref_components: Vec<&str> = result_taxa
            .iter()
            .filter_map(|t| t.pointer("/toolComponent/name").and_then(Value::as_str))
            .collect();
        assert!(ref_components.contains(&"STIG"));
        assert!(ref_components.contains(&"CIS"));
        let ref_ids: Vec<&str> = result_taxa
            .iter()
            .filter_map(|t| t.get("id").and_then(Value::as_str))
            .collect();
        assert!(ref_ids.contains(&"RHEL-08-040110"));
        assert!(ref_ids.contains(&"1.5.3"));
    }

    #[test]
    fn startcolumn_omitted_when_line_positive_column_zero() {
        // Defensive-hardening pin (#581): `line == 0` already omits `region`
        // entirely (see `region_is_omitted_for_unanchored_diagnostics...`
        // above), but a diagnostic with `line > 0` and `column == 0` is a
        // DIFFERENT case -- `region` IS built (because `diag.line != 0`), and
        // today `start_column` is set unconditionally from `diag.column`,
        // which would emit `"startColumn": 0`. That is schema-invalid: SARIF
        // 2.1.0 requires `region.startColumn` >= 1 when present. No shipping
        // backend constructs `line > 0, column == 0` today (every backend
        // maintains line>0 => column>=1), so this is unreachable via any real
        // lint path -- but the renderer must not lie about an invalid column
        // if a future backend ever does. `startLine` must still be present
        // (line>0 is a real, valid line).
        let d = Diagnostic::new(
            Severity::Warning,
            "fapd-W03",
            0..0,
            "defensive: unreachable via any backend today",
            "/etc/fapolicyd/rules.d/10-x.rules",
            7,
            0,
        );
        let out = render(&[d], None).expect("render");
        let v: Value = serde_json::from_str(&out).expect("parse");

        let region = v
            .pointer("/runs/0/results/0/locations/0/physicalLocation/region")
            .expect("line>0 must still produce a region");
        assert_eq!(
            region.get("startLine").and_then(Value::as_i64),
            Some(7),
            "startLine must still be present and correct for line>0"
        );
        assert!(
            region.get("startColumn").is_none(),
            "column==0 must omit the startColumn key entirely, not emit \
             startColumn: 0 (schema-invalid): {region}"
        );
    }

    #[test]
    fn startcolumn_present_when_line_and_column_positive() {
        // Companion green pin: guards against over-guarding -- a normal
        // anchored diagnostic (line>=1, column>=1) must still carry BOTH
        // startLine and startColumn.
        let d = Diagnostic::new(
            Severity::Warning,
            "fapd-W03",
            0..0,
            "normal anchored diagnostic",
            "/etc/fapolicyd/rules.d/10-x.rules",
            7,
            3,
        );
        let out = render(&[d], None).expect("render");
        let v: Value = serde_json::from_str(&out).expect("parse");

        let region = v
            .pointer("/runs/0/results/0/locations/0/physicalLocation/region")
            .expect("line>0 must produce a region");
        assert_eq!(region.get("startLine").and_then(Value::as_i64), Some(7));
        assert_eq!(
            region.get("startColumn").and_then(Value::as_i64),
            Some(3),
            "column>=1 must still emit startColumn"
        );
    }

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

    #[test]
    fn region_is_omitted_for_unanchored_diagnostics_but_kept_for_anchored_ones() {
        // Pin for the unanchored-SARIF-region fix (#511): `line == 0` is the
        // codebase-wide UNANCHORED convention (mirrors
        // `rulesteward_fapolicyd::lints::file_level`'s exact construction: a
        // 0..0 span with line=0/column=0, used by fapd-C01/F02/X01). The SARIF
        // 2.1.0 schema requires `region.startLine`/`startColumn` >= 1 when
        // `region` is present, so an unanchored diagnostic must omit `region`
        // entirely rather than emit `startLine: 0` (schema-invalid). A second,
        // anchored (line >= 1) diagnostic in the same render call must still
        // carry a `region` with both fields >= 1, so this test also guards
        // against an overcorrection that drops `region` unconditionally.
        let unanchored = Diagnostic::new(
            Severity::Convention,
            "fapd-C01",
            0..0,
            "rules.d filename does not follow the NN- numeric-prefix convention",
            "/etc/fapolicyd/rules.d/badname.rules",
            0,
            0,
        );
        let anchored = Diagnostic::new(
            Severity::Warning,
            "fapd-W03",
            0..4,
            "inline trailing comment is ignored by fapolicyd",
            "/etc/fapolicyd/rules.d/10-x.rules",
            7,
            1,
        );
        let out = render(&[unanchored, anchored], None).expect("render");
        let v: Value = serde_json::from_str(&out).expect("parse");

        let unanchored_loc = v
            .pointer("/runs/0/results/0/locations/0/physicalLocation")
            .expect("unanchored result has a physicalLocation");
        assert!(
            unanchored_loc.get("region").is_none(),
            "an unanchored diagnostic (line=0) must omit the region key entirely, \
             not emit startLine: 0 (schema-invalid): {unanchored_loc}"
        );
        assert_eq!(
            unanchored_loc
                .pointer("/artifactLocation/uri")
                .and_then(Value::as_str),
            Some("/etc/fapolicyd/rules.d/badname.rules"),
            "artifactLocation.uri must still be present for an unanchored finding"
        );

        let anchored_region = v
            .pointer("/runs/0/results/1/locations/0/physicalLocation/region")
            .expect("an anchored diagnostic (line>=1) must still carry a region");
        let start_line = anchored_region
            .get("startLine")
            .and_then(Value::as_i64)
            .expect("startLine present on an anchored region");
        let start_column = anchored_region
            .get("startColumn")
            .and_then(Value::as_i64)
            .expect("startColumn present on an anchored region");
        assert!(
            start_line >= 1,
            "anchored region startLine must be >= 1, got {start_line}"
        );
        assert!(
            start_column >= 1,
            "anchored region startColumn must be >= 1, got {start_column}"
        );
    }
}
