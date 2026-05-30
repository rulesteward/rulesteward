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

/// Errors a renderer can return. Currently only used by the SARIF stub;
/// human and JSON renderers cannot fail.
#[derive(Debug, thiserror::Error)]
pub enum RenderError {
    /// SARIF rendering is stubbed in v0.1.0-dev - caller must map to exit 3.
    #[error("sarif format not yet implemented in v0.1.0-dev")]
    SarifNotImplemented,
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
