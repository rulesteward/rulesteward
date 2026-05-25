//! JSON output: a top-level array of `Diagnostic` objects.

use rulesteward_core::Diagnostic;

#[must_use]
pub fn render(diags: &[Diagnostic]) -> String {
    serde_json::to_string_pretty(diags).expect("Diagnostic serialization cannot fail")
}

#[cfg(test)]
mod tests {
    use super::*;
    use rulesteward_core::Severity;

    #[test]
    fn json_renders_as_array_of_diagnostic_objects() {
        let d = Diagnostic::new(Severity::Error, "E01", 5..10, "unknown attribute", "/tmp/x.rules", 3, 12);
        let out = render(std::slice::from_ref(&d));
        let parsed: Vec<Diagnostic> = serde_json::from_str(&out).expect("re-parse json output");
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0], d);
    }

    #[test]
    fn json_empty_diags_is_empty_array() {
        let out = render(&[]);
        let parsed: Vec<Diagnostic> = serde_json::from_str(&out).expect("re-parse");
        assert!(parsed.is_empty());
    }
}
