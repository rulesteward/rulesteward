//! Human-readable diagnostic rendering. Uses a plain `file:line:col [CODE]
//! severity: message` line per diagnostic for v0.1.0-dev; the richer
//! `ariadne::Report` source-span output lands once AST byte spans are
//! threaded through in Session 3.

use core::fmt::Write as _;

use rulesteward_core::{Diagnostic, Severity};

#[must_use]
pub fn render(diags: &[Diagnostic]) -> String {
    if diags.is_empty() {
        return String::new();
    }
    let mut out = String::new();
    for d in diags {
        // `fmt::Write` on a `String` is infallible — the `Result` is always `Ok`.
        let _ = writeln!(
            out,
            "{file}:{line}:{col} [{code}] {sev}: {msg}",
            file = d.file.display(),
            line = d.line,
            col = d.column,
            code = d.code,
            sev = severity_word(d.severity),
            msg = d.message,
        );
    }
    out
}

fn severity_word(s: Severity) -> &'static str {
    match s {
        Severity::Fatal => "fatal",
        Severity::Error => "error",
        Severity::Warning => "warning",
        Severity::Style => "style",
        Severity::Convention => "convention",
        Severity::Extra => "extra",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rulesteward_core::Severity;

    #[test]
    fn human_renders_severity_letter_code_and_message() {
        let d = Diagnostic::new(
            Severity::Warning,
            "W02",
            0..0,
            "broad allow on execute (subject=all, object=all)",
            "/tmp/sample.rules",
            5,
            1,
        );
        let out = render(&[d]);
        assert!(out.contains("[W02]"), "expected `[W02]` in {out}");
        assert!(
            out.contains("broad allow on execute"),
            "expected message in {out}"
        );
        assert!(
            out.contains("/tmp/sample.rules"),
            "expected file path in {out}"
        );
        assert!(out.contains(":5:"), "expected line number `:5:` in {out}");
    }

    #[test]
    fn human_renders_zero_diagnostics_as_empty() {
        let out = render(&[]);
        assert!(
            out.is_empty(),
            "expected empty output for empty diags, got {out:?}"
        );
    }
}
