//! Output-format dispatch. Each format module owns a
//! `render` function for its specific output type.
//!
//! The `human` renderer takes an additional `sources` map so it can produce
//! ariadne snippets when source text is available. The `json` and `sarif`
//! renderers do not need source text.

pub mod csv;
pub mod human;
pub mod json;
pub mod register;
pub mod sarif;
pub mod trustdb;

use std::collections::BTreeMap;

use rulesteward_core::Diagnostic;

use crate::cli::OutputFormat;

/// Errors a renderer can return. The human and JSON renderers are infallible;
/// only the SARIF renderer can fail, and only at the final `serde_json`
/// serialization step (which in practice cannot fail for the value built, but
/// the API is fallible so the error is surfaced rather than `expect`-ed).
#[derive(Debug, thiserror::Error)]
pub enum RenderError {
    /// Serializing the rendered output to a string failed.
    #[error("serializing output: {0}")]
    Serialization(String),
}

/// Render diagnostics in the requested format.
///
/// `sources` maps `source_id` values to raw source-file content. Only the
/// human renderer uses this; json and sarif renderers ignore it.
///
/// `pass` carries the SARIF per-check coverage attestation for
/// `--sarif-include-pass` (#137). It is only meaningful for `OutputFormat::Sarif`;
/// the human and json renderers ignore it. Pass `None` for every non-SARIF call
/// and for SARIF runs without the flag (byte-identical to the pre-#137 output).
pub fn render(
    format: OutputFormat,
    diags: &[Diagnostic],
    sources: &BTreeMap<String, String>,
    pass: Option<&sarif::PassInfo>,
) -> Result<String, RenderError> {
    match format {
        OutputFormat::Human => Ok(human::render(diags, sources)),
        OutputFormat::Json => Ok(json::render(diags)),
        OutputFormat::Sarif => sarif::render(diags, pass),
    }
}

/// Render `diags` in the operator-selected Human/Json/Sarif format and print
/// the non-empty result to stdout.
///
/// The shared lint-shell emitter for the five `OutputFormat` lint verbs
/// (sshd / sysctl / sudoers / auditd / selinux): each supplies its own
/// envelope `kind` string and `schema_version` constant (CC-1) and stages
/// `sources` for the ariadne human path. The JSON arm always renders the
/// versioned lint envelope (`json::render_lint_envelope`), never the plain
/// `json::render` fapolicyd uses, so the envelope stays byte-identical to
/// before SARIF was added (#511). The SARIF arm always passes `pass: None`:
/// `--sarif-include-pass` per-check coverage attestation stays fapolicyd-only
/// (CC-4); these five verbs are findings-only. fapolicyd is NOT a caller: it
/// uses the three-variant [`render`] directly (with the real
/// `--sarif-include-pass` attestation). Exit-code mapping stays in the caller
/// (`exit_code::compute`); a rendering failure here is reported to the caller
/// so it can override that mapping to a tool failure (mirrors the
/// `output::render` error-handling convention in `commands::fapolicyd::lint`).
pub fn emit_lint(
    format: OutputFormat,
    kind: &str,
    schema_version: u32,
    diags: &[Diagnostic],
    sources: &BTreeMap<String, String>,
) -> Result<(), RenderError> {
    let output = match format {
        OutputFormat::Human => human::render(diags, sources),
        OutputFormat::Json => json::render_lint_envelope(kind, schema_version, diags),
        OutputFormat::Sarif => sarif::render(diags, None)?,
    };
    if !output.is_empty() {
        print!("{output}");
    }
    Ok(())
}
