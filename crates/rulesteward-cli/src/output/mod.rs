//! Output-format dispatch. Each format module owns a
//! `render` function for its specific output type.
//!
//! The `human` renderer takes an additional `sources` map so it can produce
//! ariadne snippets when source text is available. The `json` and `sarif`
//! renderers do not need source text.

pub mod human;
pub mod json;
pub mod sarif;

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
pub fn render(
    format: OutputFormat,
    diags: &[Diagnostic],
    sources: &BTreeMap<String, String>,
) -> Result<String, RenderError> {
    match format {
        OutputFormat::Human => Ok(human::render(diags, sources)),
        OutputFormat::Json => Ok(json::render(diags)),
        OutputFormat::Sarif => sarif::render(diags),
    }
}
