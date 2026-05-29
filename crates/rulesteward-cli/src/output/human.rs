//! Human-readable diagnostic rendering.
//!
//! When a diagnostic has `source_id.is_some()` and the source text is
//! available in `sources`, renders a rich `ariadne::Report` snippet with the
//! source line and a caret underline.
//!
//! When `source_id` is absent (e.g. fapd-F02 layout fatals, fapd-F01 parse errors), the
//! renderer falls back to a plain `file:line:col [CODE] severity: message`
//! line - the same format used before Session 3a.
//!
//! The CODE / file / line / col header appears in BOTH rendering paths so
//! operators can grep the output uniformly regardless of whether a snippet is
//! present.

use std::collections::BTreeMap;
use std::io::IsTerminal as _;

use core::fmt::Write as _;

use ariadne::{Config, Label, Report, ReportKind, Source};
use rulesteward_core::{Diagnostic, Severity, span::Span};

/// Map our `Severity` to an `ariadne::ReportKind`.
fn report_kind(severity: Severity) -> ReportKind<'static> {
    match severity {
        Severity::Fatal | Severity::Error => ReportKind::Error,
        Severity::Warning => ReportKind::Warning,
        Severity::Style | Severity::Convention | Severity::Extra => ReportKind::Advice,
    }
}

/// Convert a byte-offset span into a char-offset span using `source`.
///
/// ariadne 0.6 indexes its `Source` by CHARACTER offset, but our `Span` is a
/// BYTE range into the source. Convert byte offsets to char offsets so the
/// caret lands correctly (and renders at all) when the source contains
/// multibyte UTF-8 before the span. Falls back to the raw byte value if an
/// offset is not a char boundary (should not happen for parser-produced spans).
fn byte_span_to_char_span(span: &Span, source: &str) -> Span {
    let to_char = |b: usize| source.get(..b).map_or(b, |s| s.chars().count());
    to_char(span.start)..to_char(span.end)
}

/// Build the `ariadne::Label` for a diagnostic with a known
/// `source_id`. Takes a pre-computed char-offset span so ariadne locates
/// the source position correctly even when the source contains multibyte
/// UTF-8 before the span.
fn label_for<'a>(id: &'a str, span: Span, msg: &'a str) -> Label<(&'a str, Span)> {
    Label::new((id, span)).with_message(msg)
}

/// Determine whether ANSI color output is appropriate.
///
/// Colors are enabled only when stdout is a TTY AND the `NO_COLOR`
/// environment variable is absent. This follows the `NO_COLOR.org` convention
/// and prevents escape codes from appearing in piped or redirected output.
fn color_enabled() -> bool {
    std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none()
}

/// Render a single diagnostic as an ariadne snippet into `out`.
///
/// Returns `false` when the source text is not available and the caller
/// should fall back to plain rendering.
///
/// The `Report::with_message` title intentionally omits `file:line:col` -
/// ariadne's own bracket header (`[ <source_id>:<line>:<col> ]`) already
/// shows that. Including both produced visible duplication in the rendered
/// output. Plain mode (the fallback branch in `render`) still emits the full
/// `file:line:col [CODE] sev: msg` for grep parity.
fn render_ariadne(d: &Diagnostic, source_id: &str, source_text: &str, out: &mut Vec<u8>) -> bool {
    let config = Config::default().with_color(color_enabled());
    // Convert byte offsets to char offsets: ariadne 0.6 indexes its `Source`
    // by character position. For ASCII-only sources byte offset == char offset,
    // so existing tests are unaffected. For multibyte UTF-8, the byte offset
    // may exceed the char-length and ariadne silently omits the snippet.
    let cspan = byte_span_to_char_span(&d.span, source_text);
    let mut report_buf: Vec<u8> = Vec::new();
    let result = Report::build(report_kind(d.severity), (source_id, cspan.clone()))
        .with_config(config)
        .with_message(format!(
            "[{code}] {sev}: {msg}",
            code = d.code,
            sev = severity_word(d.severity),
            msg = d.message,
        ))
        .with_label(label_for(source_id, cspan.clone(), d.message.as_str()))
        .finish()
        .write((source_id, Source::from(source_text)), &mut report_buf);
    match result {
        Ok(()) => {
            out.extend_from_slice(&report_buf);
            true
        }
        Err(_) => false,
    }
}

/// Render diagnostics to a human-readable string.
///
/// `sources` maps `source_id` values (as set via
/// `Diagnostic::with_source_id`) to the file's raw text content.
/// Diagnostics with a matching entry get a rich ariadne snippet; all others
/// fall back to the plain `file:line:col [CODE] severity: message` format.
#[must_use]
pub fn render(diags: &[Diagnostic], sources: &BTreeMap<String, String>) -> String {
    if diags.is_empty() {
        return String::new();
    }
    let mut out_bytes: Vec<u8> = Vec::new();
    let mut out_plain = String::new();

    for d in diags {
        let used_ariadne = if let Some(ref id) = d.source_id {
            if let Some(text) = sources.get(id) {
                render_ariadne(d, id.as_str(), text, &mut out_bytes)
            } else {
                false
            }
        } else {
            false
        };

        if !used_ariadne {
            // Plain fallback: write to the plain string buffer, then append
            // to out_bytes as UTF-8 at the end.
            let _ = writeln!(
                out_plain,
                "{file}:{line}:{col} [{code}] {sev}: {msg}",
                file = d.file.display(),
                line = d.line,
                col = d.column,
                code = d.code,
                sev = severity_word(d.severity),
                msg = d.message,
            );
        }
    }

    // Merge: ariadne output is in out_bytes (ANSI-colored bytes); plain is in
    // out_plain. Combine as UTF-8. Ariadne output may contain ANSI escapes
    // but is valid UTF-8.
    let ariadne_str = String::from_utf8_lossy(&out_bytes).into_owned();
    if ariadne_str.is_empty() {
        out_plain
    } else if out_plain.is_empty() {
        ariadne_str
    } else {
        // Mix: plain diagnostics first, then ariadne snippets. Each group
        // already ends with a newline.
        format!("{out_plain}{ariadne_str}")
    }
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

    fn empty_sources() -> BTreeMap<String, String> {
        BTreeMap::new()
    }

    #[test]
    fn human_renders_severity_letter_code_and_message_plain() {
        let d = Diagnostic::new(
            Severity::Warning,
            "fapd-W02",
            0..0,
            "broad allow on execute (subject=all, object=all)",
            "/tmp/sample.rules",
            5,
            1,
        );
        let out = render(&[d], &empty_sources());
        assert!(out.contains("[fapd-W02]"), "expected `[fapd-W02]` in {out}");
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
        let out = render(&[], &empty_sources());
        assert!(
            out.is_empty(),
            "expected empty output for empty diags, got {out:?}"
        );
    }

    #[test]
    fn human_uses_ariadne_snippet_when_source_id_and_text_present() {
        let source = "allow xyz=0 : all\n";
        let mut sources = BTreeMap::new();
        sources.insert("/tmp/test.rules".to_string(), source.to_string());
        let d = Diagnostic::new(
            Severity::Error,
            "fapd-E01",
            6..9, // "xyz" within "allow xyz=0 : all"
            "unknown attribute `xyz`",
            "/tmp/test.rules",
            1,
            7,
        )
        .with_source_id("/tmp/test.rules");
        let out = render(&[d], &sources);
        // ariadne 0.6 uses box-drawing underlines (─, U+2500) rather than ASCII ^.
        assert!(
            out.contains('\u{2500}'),
            "ariadne box-drawing underline must appear in {out:?}"
        );
        assert!(out.contains("xyz"), "source text must appear in {out:?}");
    }

    #[test]
    fn human_falls_back_to_plain_when_source_id_absent() {
        let source = "allow xyz=0 : all\n";
        let mut sources = BTreeMap::new();
        sources.insert("/tmp/test.rules".to_string(), source.to_string());
        // No .with_source_id() call - source_id stays None.
        let d = Diagnostic::new(
            Severity::Fatal,
            "fapd-F02",
            0..0,
            "both fapolicyd.rules and rules.d/ present",
            "/tmp/test.rules",
            0,
            0,
        );
        let out = render(&[d], &sources);
        assert!(
            out.contains("[fapd-F02]"),
            "plain [fapd-F02] must appear in {out:?}"
        );
        assert!(!out.contains('^'), "no caret for fallback plain in {out:?}");
    }

    #[test]
    fn report_kind_maps_fatal_and_error_to_report_error() {
        assert!(
            matches!(report_kind(Severity::Fatal), ReportKind::Error),
            "Fatal must map to ReportKind::Error"
        );
        assert!(
            matches!(report_kind(Severity::Error), ReportKind::Error),
            "Error must map to ReportKind::Error"
        );
    }

    #[test]
    fn report_kind_maps_warning() {
        assert!(
            matches!(report_kind(Severity::Warning), ReportKind::Warning),
            "Warning must map to ReportKind::Warning"
        );
    }

    #[test]
    fn report_kind_maps_style_convention_extra_to_advice() {
        for sev in [Severity::Style, Severity::Convention, Severity::Extra] {
            assert!(
                matches!(report_kind(sev), ReportKind::Advice),
                "{sev:?} must map to ReportKind::Advice"
            );
        }
    }

    #[test]
    fn human_ariadne_snippet_renders_with_multibyte_source() {
        // multibyte column-0 comment (3 CJK chars = 9 bytes), then a rule with
        // an unknown attribute on line 2. The byte offset of "xyz" is 9+1+1 =
        // beyond the char-length of line 1 alone, which exposed the bug where
        // ariadne silently dropped the caret snippet.
        let source = "# \u{65e5}\u{672c}\u{8a9e} comment\nallow xyz=0 : all\n";
        let byte_start = source.find("xyz").expect("xyz present");
        let mut sources = BTreeMap::new();
        sources.insert("/t.rules".to_string(), source.to_string());
        let d = Diagnostic::new(
            Severity::Error,
            "fapd-E01",
            byte_start..byte_start + 3,
            "unknown attribute `xyz`",
            "/t.rules",
            2,
            7,
        )
        .with_source_id("/t.rules");
        let out = render(&[d], &sources);
        // ariadne 0.6 uses box-drawing chars (U+2500 and family) in its caret
        // box. If ariadne cannot locate the span (byte > char bound) it silently
        // omits the entire snippet - the presence of U+2500 proves the snippet
        // rendered correctly.
        assert!(
            out.contains('\u{2500}'),
            "ariadne caret box-drawing must render even with multibyte source, got: {out:?}"
        );
        assert!(out.contains("xyz"), "source text must appear: {out:?}");
    }

    #[test]
    fn byte_span_to_char_span_ascii_is_identity() {
        // For ASCII-only source, byte offset == char offset.
        let source = "allow xyz=0 : all\n";
        let span = 6..9usize;
        assert_eq!(byte_span_to_char_span(&span, source), 6..9);
    }

    #[test]
    fn byte_span_to_char_span_multibyte_shifts_correctly() {
        // "# \u{65e5}\u{672c}\u{8a9e} comment\n" is 3 CJK chars (3 bytes each)
        // plus "# " (2) and " comment\n" (9) = 2 + 9 + 9 = 20 bytes, 14 chars.
        // "allow " follows at byte 20, char 14.
        let source = "# \u{65e5}\u{672c}\u{8a9e} comment\nallow xyz=0 : all\n";
        let byte_start = source.find("xyz").expect("xyz present");
        let char_start = source[..byte_start].chars().count();
        let char_end = char_start + 3; // "xyz" is 3 chars (ASCII)
        let cspan = byte_span_to_char_span(&(byte_start..byte_start + 3), source);
        assert_eq!(cspan.start, char_start, "char start must match");
        assert_eq!(cspan.end, char_end, "char end must match");
    }
}
