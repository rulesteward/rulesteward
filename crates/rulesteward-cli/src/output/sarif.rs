//! SARIF-format diagnostic rendering. Stubbed in v0.1.0-dev - real
//! implementation lands in Session 3+. The stub always returns
//! `Err(SarifNotImplemented)`, which the CLI maps to exit code 3
//! (tool failure) per spec §9.4.

use rulesteward_core::Diagnostic;

use super::RenderError;

pub fn render(_diags: &[Diagnostic]) -> Result<String, RenderError> {
    Err(RenderError::SarifNotImplemented)
}
