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

#[cfg(test)]
mod tests {
    use super::*;
    use rulesteward_core::Severity;

    fn fake_diag() -> Diagnostic {
        Diagnostic::new(
            Severity::Warning,
            "fapd-W02",
            0..0,
            "broad allow",
            "/tmp/x.rules",
            1,
            1,
        )
    }

    fn empty_sources() -> BTreeMap<String, String> {
        BTreeMap::new()
    }

    #[test]
    fn sarif_dispatch_returns_err_not_implemented() {
        match render(OutputFormat::Sarif, &[fake_diag()], &empty_sources()) {
            Err(RenderError::SarifNotImplemented) => {}
            other => panic!("expected SarifNotImplemented, got {other:?}"),
        }
    }

    #[test]
    fn render_error_implements_std_error_trait() {
        fn assert_error<E: std::error::Error>() {}
        assert_error::<RenderError>();
    }

    #[test]
    fn render_error_display_matches_sarif_caller_message() {
        let e = RenderError::SarifNotImplemented;
        assert_eq!(
            e.to_string(),
            "sarif format not yet implemented in v0.1.0-dev",
        );
    }
}
