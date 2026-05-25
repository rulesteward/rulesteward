//! Output-format dispatch. Each format module owns a
//! `render(&[Diagnostic]) -> Result<String, RenderError>`.

pub mod human;
pub mod json;
pub mod sarif;

use rulesteward_core::Diagnostic;

use crate::cli::OutputFormat;

#[derive(Debug)]
pub enum RenderError {
    /// SARIF rendering is stubbed in v0.1.0-dev — caller must map to exit 3.
    SarifNotImplemented,
}

pub fn render(format: OutputFormat, diags: &[Diagnostic]) -> Result<String, RenderError> {
    match format {
        OutputFormat::Human => Ok(human::render(diags)),
        OutputFormat::Json => Ok(json::render(diags)),
        OutputFormat::Sarif => sarif::render(diags),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rulesteward_core::Severity;

    fn fake_diag() -> Diagnostic {
        Diagnostic::new(Severity::Warning, "W02", 0..0, "broad allow", "/tmp/x.rules", 1, 1)
    }

    #[test]
    fn sarif_dispatch_returns_err_not_implemented() {
        match render(OutputFormat::Sarif, &[fake_diag()]) {
            Err(RenderError::SarifNotImplemented) => {}
            other => panic!("expected SarifNotImplemented, got {other:?}"),
        }
    }
}
