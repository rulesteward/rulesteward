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

use std::collections::{BTreeMap, HashMap};
use std::io::IsTerminal as _;

use core::fmt::Write as _;

use ariadne::{Config, Label, Report, ReportKind, Source};
use rulesteward_core::{ControlRef, Diagnostic, Severity, span::Span};

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
/// multibyte UTF-8 before the span.
///
/// `to_char` is TOTAL (defined for every `usize`, including a mid-character
/// offset or an offset past `source.len()`) and MONOTONE NON-DECREASING in
/// its argument. It counts char-START indices strictly below `b`, which means
/// a mid-character offset rounds UP to the index of the character it falls
/// inside of, and any offset past `source.len()` saturates at
/// `source.chars().count()` rather than passing through unchanged. Because
/// both endpoints of the span go through this same total, monotone function,
/// `span.start <= span.end` implies the converted span is also ordered - that
/// is a theorem, not a clamp applied after the fact.
///
/// This matters because converting each endpoint independently via
/// `source.get(..b)`, falling back to the raw BYTE value whenever an endpoint
/// is not a char boundary (issue #595), INVERTS spans: a span whose `start` is
/// mid-character and whose `end` is boundary-aligned keeps a large byte value
/// on one side and shrinks to a small char count on the other.
/// `ariadne::Label::new` asserts `span.start() <= span.end()` and aborts the
/// process when that happens, so the operator sees a hard panic instead of a
/// diagnostic.
///
/// `to_char(b)`, for `b` at or past `source.len()`, is `source.chars().count()`
/// by definition (saturation) - `b.min(source.len())` folds that case into the
/// same walk rather than branching on it: `is_char_boundary(source.len())` is
/// always `true`, so the clamp alone makes the saturating arm total. For `b`
/// strictly inside the source, `to_char(b)` equals `source[..q].chars().count()`
/// where `q` is the smallest char boundary `>= b`, found by advancing `q` one
/// byte at a time until `source.is_char_boundary(q)` holds (at most 3 steps
/// past a mid-character `b`, since a UTF-8 scalar is at most 4 bytes): `q` is
/// `b` itself when `b` is already a boundary, or the start of the NEXT scalar
/// when `b` lands mid-character. This is the same total, monotone, round-up
/// mapping a per-char walk computes one char at a time - see
/// `mid_character_offset_rounds_up_to_the_next_char_boundary` below for the
/// byte-by-byte derivation of WHY a boundary-scan-then-prefix-count agrees
/// with "count char starts strictly below `b`" at every offset, including
/// mid-character ones.
///
/// This avoids `source.char_indices().take_while(|(i, _)| *i < b).count()`
/// (#595 perf follow-up), which fully DECODES every scalar below `b` - each
/// step assembling a `char`'s scalar value from 1-4 bytes - to answer a
/// question that only needs to know where chars START, not what they decode
/// to. `str::chars().count()` has a dedicated fast path in the standard
/// library that counts non-continuation bytes directly without assembling
/// scalar values. `Chars` being a concrete (non-generic) type does NOT by
/// itself keep that fast path out of this crate's own codegen: `Chars::count`
/// and the `count::count_chars` it forwards to are both `#[inline]`, and an
/// `#[inline]` function's MIR is exported cross-crate and instantiated into
/// the CALLING crate's CGU at the CALLER's opt-level regardless of whether
/// the function is generic (verified against `core::str::iter`/`count` at
/// `$(rustc --print sysroot)/lib/rustlib/src/rust/library/core/src/str/` on
/// 1.97.0). What actually stays a call into the pre-optimized prebuilt
/// `libcore` is one level further down: `do_count_chars` (the SWAR chunked
/// variant used for longer inputs) and `char_count_general_case` (the
/// short-input / head-tail fallback) are NEITHER of them `#[inline]`, so
/// those two are what is not re-monomorphised into this crate at ITS OWN
/// opt-level. That distinction is what actually matters at `opt-level = 0`
/// (this crate's dev/test profile): a hand-written byte-counting loop written
/// IN this crate is still compiled unoptimized and was measured, isolated
/// from `render()`'s own overhead, at a materially smaller but still real
/// speedup over the decode loop it replaced - real, but not enough headroom
/// to clear this file's tail/head ratio gate with margin. Routing the actual
/// counting through `str::chars().count()` was measured (in the same
/// isolated harness) to close that remaining gap, cutting the decode loop's
/// ~12.8x (release) / ~1000x (dev) per-byte cost down to roughly 1.0x-1.6x.
fn byte_span_to_char_span(span: &Span, source: &str) -> Span {
    let to_char = |b: usize| {
        let mut q = b.min(source.len());
        while !source.is_char_boundary(q) {
            q += 1;
        }
        source[..q].chars().count()
    };
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
/// `source_cache` holds one lazily-built `ariadne::Source` per `source_id`,
/// populated on first use via the `HashMap` entry API (#559). Building a
/// `Source` line-indexes the whole source text, so an uncached implementation
/// (one calling `Source::from(source_text)` inside this function, once per
/// diagnostic) costs O(diagnostics x `source_length`) when many diagnostics
/// anchor to one large file. `render` (below) owns `source_cache` for the
/// lifetime of one call and passes it in by mutable reference, so it is
/// shared across every diagnostic in that call but never persists beyond
/// it, and it is populated only for `source_id`s a diagnostic actually
/// references, never eagerly for the whole `sources` map.
///
/// ariadne implements `Cache<Id>` for `(Id, &Source<I>)` as well as for
/// `(Id, Source<I>)`, so passing a reference to the cached `Source` here
/// costs nothing beyond the initial cache miss.
///
/// The `Report::with_message` title intentionally omits `file:line:col` -
/// ariadne's own bracket header (`[ <source_id>:<line>:<col> ]`) already
/// shows that. Including both produced visible duplication in the rendered
/// output. Plain mode (the fallback branch in `render`) still emits the full
/// `file:line:col [CODE] sev: msg` for grep parity.
fn render_ariadne<'src>(
    d: &Diagnostic,
    source_id: &'src str,
    source_text: &'src str,
    source_cache: &mut HashMap<&'src str, Source<&'src str>>,
    out: &mut Vec<u8>,
) -> bool {
    let config = Config::default().with_color(color_enabled());
    // Convert byte offsets to char offsets: ariadne 0.6 indexes its `Source`
    // by character position. For ASCII-only sources byte offset == char offset,
    // so existing tests are unaffected. For multibyte UTF-8, the byte offset
    // may exceed the char-length and ariadne silently omits the snippet.
    let cspan = byte_span_to_char_span(&d.span, source_text);
    let mut report_buf: Vec<u8> = Vec::new();
    let source = source_cache
        .entry(source_id)
        .or_insert_with(|| Source::from(source_text));
    let result = Report::build(report_kind(d.severity), (source_id, cspan.clone()))
        .with_config(config)
        .with_message(format!(
            "[{code}] {sev}: {msg}{controls}",
            code = d.code,
            sev = severity_word(d.severity),
            msg = d.message,
            controls = format_controls(&d.controls),
        ))
        .with_label(label_for(source_id, cspan.clone(), d.message.as_str()))
        .finish()
        .write((source_id, &*source), &mut report_buf);
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
    // One `ariadne::Source` per unique `source_id`, built lazily on first
    // use and reused for every later diagnostic against that same id in
    // this call (#559). Scoped to this single `render()` call, not hoisted
    // any wider - see `render_ariadne`'s doc comment.
    let mut source_cache: HashMap<&str, Source<&str>> = HashMap::new();

    for d in diags {
        let used_ariadne = if let Some(ref id) = d.source_id {
            if let Some(text) = sources.get(id) {
                render_ariadne(d, id.as_str(), text, &mut source_cache, &mut out_bytes)
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
                "{file}:{line}:{col} [{code}] {sev}: {msg}{controls}",
                file = d.file.display(),
                line = d.line,
                col = d.column,
                code = d.code,
                sev = severity_word(d.severity),
                msg = d.message,
                controls = format_controls(&d.controls),
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

/// Format the compliance-control suffix appended after a diagnostic's message.
///
/// Returns `""` for a finding with no controls, so the rendered line is
/// byte-identical to the pre-v0.7 output. Otherwise returns ` (<FW> <id>)` (or
/// ` (<FW> <id>/<alias>)` when a secondary id is present), joining multiple
/// controls with `, `. The LEADING space is what makes the empty case add
/// nothing to the line.
pub(crate) fn format_controls(controls: &[ControlRef]) -> String {
    if controls.is_empty() {
        return String::new();
    }
    let joined = controls
        .iter()
        .map(|c| {
            let framework = c.framework.name();
            match &c.alias {
                Some(alias) => format!("{framework} {}/{alias}", c.id),
                None => format!("{framework} {}", c.id),
            }
        })
        .collect::<Vec<_>>()
        .join(", ");
    format!(" ({joined})")
}

#[cfg(test)]
mod tests {
    use super::*;
    use rulesteward_core::{ControlRef, Framework, Severity};
    use std::time::{Duration, Instant};

    fn empty_sources() -> BTreeMap<String, String> {
        BTreeMap::new()
    }

    /// Strip ANSI CSI escape sequences (`ESC '[' ... final-byte`, the
    /// general form covering ariadne's SGR color codes) from `s`.
    ///
    /// `render()`'s ariadne path colors its output whenever `color_enabled()`
    /// is true, which happens whenever the CALLING PROCESS's
    /// own stdout is a real terminal - including `cargo test` run
    /// interactively (not piped/CI-captured). An exact-byte `assert_eq!`
    /// pin taken against raw `render()` output is therefore fragile: it
    /// passes in CI (stdout piped -> colors off) but fails under a real
    /// pty for reasons that have nothing to do with correctness. Stripping
    /// ANSI before comparing makes the pin identical either way (a no-op
    /// when colors are already off).
    fn strip_ansi(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        let mut chars = s.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '\u{1b}' && chars.peek() == Some(&'[') {
                chars.next(); // consume '['
                // Parameter bytes 0x30-0x3F, then intermediate bytes 0x20-0x2F.
                while let Some(&next) = chars.peek() {
                    if ('0'..='?').contains(&next) || (' '..='/').contains(&next) {
                        chars.next();
                    } else {
                        break;
                    }
                }
                // Final byte 0x40-0x7E, if present.
                if let Some(&next) = chars.peek()
                    && ('@'..='~').contains(&next)
                {
                    chars.next();
                }
            } else {
                out.push(c);
            }
        }
        out
    }

    #[test]
    fn strip_ansi_is_identity_when_no_escape_present() {
        let plain = "no escapes here: [1] just brackets\n";
        assert_eq!(strip_ansi(plain), plain);
    }

    #[test]
    fn strip_ansi_removes_sgr_color_codes() {
        let colored = "\u{1b}[1;31merror\u{1b}[0m: plain text \u{1b}[32mok\u{1b}[0m";
        assert_eq!(strip_ansi(colored), "error: plain text ok");
    }

    /// Build a synthetic fapolicyd-shaped source of at least `min_bytes`
    /// bytes, returning the text plus a byte span (into a distinct token)
    /// for each of at least `min_spans` lines - so scaling tests can anchor
    /// many independent, valid diagnostics without a fragile hand-computed
    /// offset table.
    fn synthetic_source_with_spans(
        min_bytes: usize,
        min_spans: usize,
    ) -> (String, Vec<std::ops::Range<usize>>) {
        let mut text = String::new();
        let mut spans = Vec::new();
        let mut i = 0usize;
        while text.len() < min_bytes || spans.len() < min_spans {
            let prefix = "allow exe=/usr/bin/prog";
            let token = format!("{i:06}");
            let start = text.len() + prefix.len();
            text.push_str(prefix);
            text.push_str(&token);
            text.push_str(" trust=1\n");
            spans.push(start..start + token.len());
            i += 1;
        }
        (text, spans)
    }

    /// Run `f` `reps` times (plus one untimed warm-up) and return the
    /// MINIMUM elapsed duration observed. Minimum-of-N is the standard
    /// micro-benchmark technique for filtering out scheduler / GC / page-
    /// fault noise: real cost never makes a run FASTER than its true floor,
    /// so the minimum is the least-noisy honest estimate.
    fn min_duration_over<F: FnMut()>(mut f: F, reps: usize) -> Duration {
        f(); // untimed warm-up
        let mut best: Option<Duration> = None;
        for _ in 0..reps {
            let start = Instant::now();
            f();
            let elapsed = start.elapsed();
            best = Some(match best {
                Some(b) if b <= elapsed => b,
                _ => elapsed,
            });
        }
        best.expect("reps must be > 0")
    }

    // -----------------------------------------------------------------
    // Regression harness for the per-`source_id` `ariadne::Source` cache
    // (#559). Every other `render(...)` test in this file passes
    // exactly ONE diagnostic, so none of them exercise a cache at all - a
    // cache keyed wrongly (or not keyed by `source_id` at all, e.g. a
    // naive "hoist `Source::from` out of the loop entirely" refactor that
    // builds a single `Source` once and reuses it for every diagnostic
    // regardless of which `source_id` it belongs to) would sail through
    // every existing test untouched. These two tests exist to close that
    // gap: they pin the exact rendered bytes for (a) multiple diagnostics
    // sharing one `source_id`, and (b) multiple diagnostics against
    // DIFFERENT `source_id`s in the same `render()` call, interleaved so
    // that input order also has to be preserved. Both PASS against any
    // correct implementation, cached or not (an uncached one is correct,
    // just O(n * len) slow) - they are a regression harness, EXCEPT that
    // (b) is precisely the case a naive whole-call hoist would break.
    // -----------------------------------------------------------------

    #[test]
    fn human_render_multiple_diagnostics_same_source_id_exact_pin() {
        // Two diagnostics anchored to the SAME source_id, at two different
        // lines/spans. Guards against the classic caching bug where a
        // cached `Source` is mutated or advanced by its first use (e.g. an
        // internal cursor) so the SECOND diagnostic against the same
        // source renders against stale state.
        let source = "allow exe=/usr/bin/foo trust=1\nallow exe=/usr/bin/bar trust=0\n";
        let mut sources = BTreeMap::new();
        sources.insert("same.rules".to_string(), source.to_string());

        let byte_1 = source.find("foo").expect("foo present");
        let d1 = Diagnostic::new(
            Severity::Error,
            "fapd-E02",
            byte_1..byte_1 + 3,
            "first same-source finding",
            "same.rules",
            1,
            byte_1 + 1,
        )
        .with_source_id("same.rules");

        let byte_2 = source.find("bar").expect("bar present");
        let d2 = Diagnostic::new(
            Severity::Warning,
            "fapd-W02",
            byte_2..byte_2 + 3,
            "second same-source finding",
            "same.rules",
            2,
            byte_2 + 1,
        )
        .with_source_id("same.rules");

        // Strip ANSI before comparing: `color_enabled()` is
        // true whenever THIS test process's own stdout is a real terminal
        // (e.g. `cargo test` run interactively), which would otherwise
        // inject SGR color codes and break an exact-byte pin for reasons
        // unrelated to correctness. Stripping is a no-op when colors are
        // already off (CI, piped stdout), so the pin stays exact everywhere.
        let out = strip_ansi(&render(&[d1, d2], &sources));

        let expected = "Error: [fapd-E02] error: first same-source finding\n   \u{256d}\u{2500}[ same.rules:1:20 ]\n   \u{2502}\n 1 \u{2502} allow exe=/usr/bin/foo trust=1\n   \u{2502}                    \u{2500}\u{252c}\u{2500}  \n   \u{2502}                     \u{2570}\u{2500}\u{2500}\u{2500} first same-source finding\n\u{2500}\u{2500}\u{2500}\u{256f}\nWarning: [fapd-W02] warning: second same-source finding\n   \u{256d}\u{2500}[ same.rules:2:20 ]\n   \u{2502}\n 2 \u{2502} allow exe=/usr/bin/bar trust=0\n   \u{2502}                    \u{2500}\u{252c}\u{2500}  \n   \u{2502}                     \u{2570}\u{2500}\u{2500}\u{2500} second same-source finding\n\u{2500}\u{2500}\u{2500}\u{256f}\n";
        assert_eq!(
            out, expected,
            "exact-byte pin for two diagnostics sharing one source_id; any \
             behavior change (including a caching regression) must be a \
             deliberate, reviewed change to this expected string"
        );

        // Belt-and-suspenders content-isolation check, independent of the
        // exact-pin above: the first diagnostic's snippet must anchor on
        // line 1 ("foo") and not leak line 2's text, and vice versa.
        let split_at = out.find("Warning:").expect("second report present");
        let (first_report, second_report) = out.split_at(split_at);
        assert!(
            first_report.contains("foo") && !first_report.contains("bar"),
            "first report must show its own line only, got {first_report:?}"
        );
        assert!(
            second_report.contains("bar") && !second_report.contains("foo"),
            "second report must show its own line only, got {second_report:?}"
        );
    }

    #[test]
    // Test helpers use byte_a1/byte_b1, d_a1/d_b1, idx_a1/idx_b1 (source-A
    // vs source-B pairs, first/second finding) in the same scope; clippy
    // false-positives on that pairing (same allow used in
    // rulesteward-fapolicyd's explain_logic.rs / explain_fanotify_parse.rs
    // for the analogous rule1/rule2 pattern).
    #[allow(clippy::similar_names)]
    fn human_render_multiple_distinct_source_ids_exact_pin_and_order() {
        // THE key deliverable for #559: three diagnostics against TWO
        // distinct source_ids, in input order A, B, A. A naive "hoist
        // `Source::from` out of the loop" cache (one `Source` built once,
        // reused for every diagnostic regardless of `source_id`) fails
        // this test two ways: (1) the `b.rules` diagnostic would render
        // against `a.rules`'s text - EITHER wrong content (if the byte
        // offsets happen to stay in-bounds against the wrong source), OR a
        // HEADER-ONLY report with no caret snippet (ariadne 0.6's
        // `write()` treats both an id-mismatched `Cache::fetch` and an
        // out-of-range span by skipping just that label/note and still
        // returning `Ok(())` - see source.rs's `Cache for (Id, Source)`
        // and write.rs's span-bounds checks - it does NOT fall back to
        // this crate's plain `file:line:col` format, which only ever comes
        // from the separate `!used_ariadne` branch in `render()`);
        // and (2) a cache implementation that groups-by-source-id instead
        // of preserving input order would emit A, A, B instead of A, B, A.
        let source_a = "allow exe=/usr/bin/alpha trust=1\ndeny_audit perm=any : all\n";
        let source_b = "deny_audit perm=open : all\nallow exe=/usr/bin/beta trust=0\n";
        let mut sources = BTreeMap::new();
        sources.insert("a.rules".to_string(), source_a.to_string());
        sources.insert("b.rules".to_string(), source_b.to_string());

        let byte_a1 = source_a.find("alpha").expect("alpha present");
        let d_a1 = Diagnostic::new(
            Severity::Error,
            "fapd-E01",
            byte_a1..byte_a1 + 5,
            "first A finding",
            "a.rules",
            1,
            byte_a1 + 1,
        )
        .with_source_id("a.rules");

        let byte_b1 = source_b.find("open").expect("open present");
        let d_b1 = Diagnostic::new(
            Severity::Warning,
            "fapd-W01",
            byte_b1..byte_b1 + 4,
            "first B finding",
            "b.rules",
            1,
            byte_b1 + 1,
        )
        .with_source_id("b.rules");

        let byte_a2 = source_a.find("any").expect("any present");
        let d_a2 = Diagnostic::new(
            Severity::Style,
            "fapd-S01",
            byte_a2..byte_a2 + 3,
            "second A finding",
            "a.rules",
            2,
            byte_a2 + 1,
        )
        .with_source_id("a.rules");

        // Input order: A, B, A. Neither source is fully processed before
        // the other starts.
        //
        // Strip ANSI before comparing (see the sibling same-source-id test
        // for why): this test process's own stdout may be a real terminal,
        // and an unstripped pin would fail under a pty for reasons
        // unrelated to #559.
        let out = strip_ansi(&render(&[d_a1, d_b1, d_a2], &sources));

        let expected = "Error: [fapd-E01] error: first A finding\n   \u{256d}\u{2500}[ a.rules:1:20 ]\n   \u{2502}\n 1 \u{2502} allow exe=/usr/bin/alpha trust=1\n   \u{2502}                    \u{2500}\u{2500}\u{252c}\u{2500}\u{2500}  \n   \u{2502}                      \u{2570}\u{2500}\u{2500}\u{2500}\u{2500} first A finding\n\u{2500}\u{2500}\u{2500}\u{256f}\nWarning: [fapd-W01] warning: first B finding\n   \u{256d}\u{2500}[ b.rules:1:17 ]\n   \u{2502}\n 1 \u{2502} deny_audit perm=open : all\n   \u{2502}                 \u{2500}\u{2500}\u{252c}\u{2500}  \n   \u{2502}                   \u{2570}\u{2500}\u{2500}\u{2500} first B finding\n\u{2500}\u{2500}\u{2500}\u{256f}\nAdvice: [fapd-S01] style: second A finding\n   \u{256d}\u{2500}[ a.rules:2:17 ]\n   \u{2502}\n 2 \u{2502} deny_audit perm=any : all\n   \u{2502}                 \u{2500}\u{252c}\u{2500}  \n   \u{2502}                  \u{2570}\u{2500}\u{2500}\u{2500} second A finding\n\u{2500}\u{2500}\u{2500}\u{256f}\n";
        assert_eq!(
            out, expected,
            "exact-byte pin for three diagnostics across two source_ids in \
             A, B, A order; a naive whole-call `Source` hoist or a \
             source-grouping cache must fail this assertion"
        );

        // Ordering, checked independently of the exact-pin above: each
        // diagnostic's code must appear strictly before the next one's, in
        // INPUT order (A, B, A), not grouped by source_id (which would
        // produce A, A, B).
        let idx_a1 = out.find("fapd-E01").expect("fapd-E01 present");
        let idx_b1 = out.find("fapd-W01").expect("fapd-W01 present");
        let idx_a2 = out.find("fapd-S01").expect("fapd-S01 present");
        assert!(
            idx_a1 < idx_b1 && idx_b1 < idx_a2,
            "diagnostics must render in INPUT order (A, B, A): \
             got offsets a1={idx_a1} b1={idx_b1} a2={idx_a2} in {out:?}"
        );

        // Content isolation, checked independently of the exact-pin above:
        // each report must render against ITS OWN source text, never the
        // other source's. This is the assertion a naive single-Source
        // hoist breaks even if it somehow avoided the exact-pin diff (for
        // example, by getting lucky with byte offsets that stay in bounds
        // in the wrong source).
        let (a1_segment, rest) = out.split_at(idx_b1);
        let idx_a2_in_rest = rest.find("fapd-S01").expect("fapd-S01 present");
        let (b1_segment, a2_segment) = rest.split_at(idx_a2_in_rest);
        assert!(
            a1_segment.contains("alpha") && !a1_segment.contains("open"),
            "first A report must show a.rules text, not b.rules, got {a1_segment:?}"
        );
        assert!(
            b1_segment.contains("open") && !b1_segment.contains("alpha"),
            "B report must show b.rules text, not a.rules, got {b1_segment:?}"
        );
        assert!(
            a2_segment.contains("any") && !a2_segment.contains("open"),
            "second A report must show a.rules text, not b.rules, got {a2_segment:?}"
        );
    }

    #[test]
    fn human_render_source_id_present_but_missing_from_sources_falls_back_to_plain() {
        // The THIRD `render()` path, untested until now: `source_id` is
        // `Some(..)` but ABSENT from `sources` (the `else { false }` arm
        // feeding `used_ariadne`). A cache using e.g.
        // `.cloned().unwrap_or_default()` on a missing key would silently
        // render a header-only ariadne report against an EMPTY source
        // instead of falling back to the plain `file:line:col` line.
        let sources: BTreeMap<String, String> = BTreeMap::new(); // "missing.rules" absent
        let d = Diagnostic::new(
            Severity::Error,
            "fapd-E03",
            0..0,
            "orphaned source_id",
            "missing.rules",
            4,
            1,
        )
        .with_source_id("missing.rules");

        let out = strip_ansi(&render(&[d], &sources));
        let expected = "missing.rules:4:1 [fapd-E03] error: orphaned source_id\n";
        assert_eq!(
            out, expected,
            "a source_id absent from `sources` must fall back to the exact plain line"
        );
        assert!(
            !out.contains('\u{2500}'),
            "no ariadne box-drawing underline must appear for the missing-source \
             fallback, got {out:?}"
        );
    }

    #[test]
    fn human_render_mixed_plain_and_ariadne_groups_plain_first_regardless_of_input_order() {
        // `render()` collects ALL plain lines into one buffer and ALL
        // ariadne snippets into a separate buffer, then always emits
        // plain-buffer-then-ariadne-buffer (human.rs ~142-154) - REGARDLESS
        // of each diagnostic's position in the input slice. A refactor that
        // instead collects everything into ONE buffer in strict input
        // order would silently change these exact bytes while passing
        // every single-kind test in this file. This test also doubles as
        // the missing-source_id-in-a-mixed-batch case (the same shape the
        // sibling single-diagnostic test above covers alone).
        //
        // Input order here is ariadne-diagnostic FIRST, plain-diagnostic
        // SECOND - the opposite of the expected OUTPUT order below.
        let source = "allow exe=/usr/bin/present trust=1\n";
        let mut sources = BTreeMap::new();
        sources.insert("present.rules".to_string(), source.to_string());

        let byte_p = source.find("present").expect("present token present");
        let d_ariadne = Diagnostic::new(
            Severity::Error,
            "fapd-E04",
            byte_p..byte_p + 7,
            "present-source finding",
            "present.rules",
            1,
            byte_p + 1,
        )
        .with_source_id("present.rules");

        let d_plain = Diagnostic::new(
            Severity::Warning,
            "fapd-W05",
            0..0,
            "missing text",
            "orphan.rules",
            9,
            1,
        )
        .with_source_id("orphan.rules"); // absent from `sources`

        let out = strip_ansi(&render(&[d_ariadne, d_plain], &sources));

        let expected = "orphan.rules:9:1 [fapd-W05] warning: missing text\nError: [fapd-E04] error: present-source finding\n   \u{256d}\u{2500}[ present.rules:1:20 ]\n   \u{2502}\n 1 \u{2502} allow exe=/usr/bin/present trust=1\n   \u{2502}                    \u{2500}\u{2500}\u{2500}\u{252c}\u{2500}\u{2500}\u{2500}  \n   \u{2502}                       \u{2570}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500} present-source finding\n\u{2500}\u{2500}\u{2500}\u{256f}\n";
        assert_eq!(
            out, expected,
            "the plain line must appear BEFORE the ariadne snippet even though the \
             ariadne diagnostic came FIRST in the input slice"
        );
    }

    #[test]
    fn human_render_distinct_source_ids_with_identical_text_render_independently() {
        // A cache keyed by SOURCE TEXT rather than `source_id`
        // (e.g. a `HashMap<String, (Id, Source)>` deduplicating by
        // content) is byte-correct only when ids never collide.
        // `ariadne::Cache for (Id, Source)` errors on an id mismatch
        // (`fetch` returns `Err` unless the requested id equals the
        // cache's stored id), so a text-keyed cache would silently drop
        // the SECOND id's snippet down to a header-only report (no caret
        // box) even though the underlying bytes are identical to the
        // first.
        let source = "allow exe=/usr/bin/twin trust=1\n";
        let mut sources = BTreeMap::new();
        sources.insert("a.rules".to_string(), source.to_string());
        sources.insert("c.rules".to_string(), source.to_string()); // byte-identical to a.rules

        let byte_twin = source.find("twin").expect("twin present");
        let d_a = Diagnostic::new(
            Severity::Error,
            "fapd-E05",
            byte_twin..byte_twin + 4,
            "first twin finding",
            "a.rules",
            1,
            byte_twin + 1,
        )
        .with_source_id("a.rules");
        let d_c = Diagnostic::new(
            Severity::Warning,
            "fapd-W06",
            byte_twin..byte_twin + 4,
            "second twin finding",
            "c.rules",
            1,
            byte_twin + 1,
        )
        .with_source_id("c.rules");

        let out = strip_ansi(&render(&[d_a, d_c], &sources));

        assert!(
            out.contains("a.rules:1"),
            "first report header must reference a.rules, got {out:?}"
        );
        assert!(
            out.contains("c.rules:1"),
            "second report header must reference c.rules, got {out:?}"
        );

        let split_at = out.find("fapd-W06").expect("fapd-W06 present");
        let (a_segment, c_segment) = out.split_at(split_at);
        assert!(
            a_segment.contains('\u{2500}'),
            "a.rules report must render its full box-drawing snippet, got {a_segment:?}"
        );
        assert!(
            c_segment.contains('\u{2500}'),
            "c.rules report must ALSO render its full box-drawing snippet, not a \
             header-only report from an id-mismatched cache lookup, got {c_segment:?}"
        );
    }

    #[test]
    fn human_render_diagnostic_count_on_one_source_scales_sublinearly() {
        // #559 perf regression harness. An implementation that rebuilds
        // `ariadne::Source` PER DIAGNOSTIC makes N diagnostics against the
        // SAME source_id cost roughly N x the per-`Source::from` build
        // time; the per-source_id cache costs close to 1x regardless of N.
        // Measured in the debug profile (what `cargo test` runs):
        // `Source::from` ~21.5ms @ 50KB. This is a RATIO check - never an
        // absolute wall-clock threshold - specifically so it cannot flake
        // on a loaded CI box: uncached the ratio is ~24x, cached ~1-2x.
        // The 6x cutoff leaves generous margin above the cached case while
        // still well below the uncached one.
        let (source, spans) = synthetic_source_with_spans(50_000, 24);
        let mut sources = BTreeMap::new();
        sources.insert("scaling.rules".to_string(), source);

        let one_diag = vec![
            Diagnostic::new(
                Severity::Warning,
                "fapd-W03",
                spans[0].clone(),
                "scaling probe",
                "scaling.rules",
                1,
                1,
            )
            .with_source_id("scaling.rules"),
        ];
        let many_diags: Vec<Diagnostic> = spans[..24]
            .iter()
            .enumerate()
            .map(|(i, span)| {
                Diagnostic::new(
                    Severity::Warning,
                    "fapd-W03",
                    span.clone(),
                    "scaling probe",
                    "scaling.rules",
                    i + 1,
                    1,
                )
                .with_source_id("scaling.rules")
            })
            .collect();

        let t_one = min_duration_over(|| drop(render(&one_diag, &sources)), 3);
        let t_many = min_duration_over(|| drop(render(&many_diags, &sources)), 3);

        assert!(
            t_many < t_one * 6,
            "24 diagnostics on ONE source_id took {t_many:?}, vs {t_one:?} for 1 \
             diagnostic (ratio {:.1}x) - expected < 6x if the Source is cached per \
             source_id rather than rebuilt per diagnostic (#559)",
            t_many.as_secs_f64() / t_one.as_secs_f64()
        );
    }

    #[test]
    fn human_render_cost_scales_with_used_sources_not_map_size() {
        // #559 perf regression harness targeting a DIFFERENT wrong "fix"
        // than the sibling scaling test above: an EAGER whole-map cache
        // (e.g. `ariadne::sources()`, which iterates and builds a `Source`
        // for EVERY map entry up front - ariadne-0.6.0 src/source.rs
        // ~398-410) would pass the single-source-id scaling test above
        // (only one source_id is used there) yet still be a real
        // regression on a directory-mode lint run, where `sources` holds
        // one entry PER SCANNED FILE regardless of how many carry
        // findings (commands/fapolicyd/lint.rs:138 inserts every staged
        // file). The right invariant: render() cost should track how many
        // DISTINCT source_ids actually have a diagnostic pointed at them,
        // not how many entries `sources` holds. The current code passes
        // this (it never looks at unused map entries), so this is a
        // GREEN-BY-DESIGN regression guard - its job is to fail a
        // plausible wrong "fix", not the current code.
        let (used_source, spans) = synthetic_source_with_spans(50_000, 1);

        let mut small_map = BTreeMap::new();
        small_map.insert("used.rules".to_string(), used_source.clone());

        let mut large_map = BTreeMap::new();
        large_map.insert("used.rules".to_string(), used_source);
        for i in 0..39 {
            let (unused_source, _) = synthetic_source_with_spans(50_000, 1);
            large_map.insert(format!("unused-{i:02}.rules"), unused_source);
        }

        let diags = vec![
            Diagnostic::new(
                Severity::Warning,
                "fapd-W03",
                spans[0].clone(),
                "scaling probe",
                "used.rules",
                1,
                1,
            )
            .with_source_id("used.rules"),
        ];

        let t_small = min_duration_over(|| drop(render(&diags, &small_map)), 3);
        let t_large = min_duration_over(|| drop(render(&diags, &large_map)), 3);

        assert!(
            t_large < t_small * 6,
            "one diagnostic against a 40-entry sources map took {t_large:?}, vs \
             {t_small:?} for the SAME diagnostic against a 1-entry map (ratio {:.1}x) - \
             expected < 6x; an eager whole-map cache fails this even though its output \
             is byte-identical to today's (#559)",
            t_large.as_secs_f64() / t_small.as_secs_f64()
        );
    }

    #[test]
    fn human_render_cost_independent_of_span_position_within_source() {
        // #595 perf regression harness for `byte_span_to_char_span`'s
        // CONSTANT factor, distinct from the two scaling harnesses above
        // (which pin diagnostic COUNT and sources-map SIZE). Same source,
        // same finding COUNT (24), same total source size (~50,008 bytes,
        // `synthetic_source_with_spans(50_000, 24)` above) - the ONLY thing
        // that differs between the two measured groups is WHERE in the
        // source the spans sit: the FIRST 24 of the ~1316 generated spans
        // (byte offsets 23..903, the first ~1.8% of the file - see
        // `synthetic_source_with_spans`'s doc comment above for the
        // per-line layout) vs the LAST 24 (byte offsets ~49096..49999, the
        // tail of the file).
        //
        // `byte_span_to_char_span`'s current body (see its doc comment
        // above) walks forward from the offset to the next char boundary,
        // then calls `source[..q].chars().count()` on the resulting
        // boundary-aligned prefix - so its cost is still O(endpoint
        // offset): converting a tail-anchored span still counts roughly
        // 50x more of the source than converting a head-anchored one.
        // `render()`'s other per-diagnostic work (the per-source_id
        // `Source` cache lookup, `Label`/`Report` construction, writing
        // the snippet) does not depend on WHERE in the file the span
        // sits, so this harness isolates the conversion's own
        // offset-dependent cost from render()'s constant overhead.
        //
        // The shape this harness guards against is a decode-heavy body:
        // `source.char_indices().take_while(|(i, _)| *i < b).count()`, a
        // per-char scalar decode loop with no vectorized fast path, which
        // fully re-assembles every UTF-8 scalar below the offset. It is
        // semantically identical to the boundary-scan-plus-`chars().count()`
        // body described above (both are total, monotone mappings that agree
        // on every char boundary, and every offset in this ASCII source IS a
        // char boundary) and only decode-cost worse. See
        // `byte_span_to_char_span`'s outer doc comment for why
        // `chars().count()` is cheaper: it forwards to a chunked,
        // non-continuation-byte count already compiled into a pre-optimized
        // std, unlike a hand-written loop written IN this crate, which stays
        // unoptimized at this crate's own opt-level.
        //
        // Measured on the development host in the debug profile (what
        // `just test` and CI run): the decode-heavy body runs 7.70x-26.34x
        // tail/head over 30 iterations - a clean FAIL of the 4x gate below.
        // The current body runs 0.62x-1.95x over 75 iterations across three
        // load regimes: idle (max 1.89x), 48-way CPU oversubscription (max
        // 1.95x), and pinned to 2 CPUs against 8 competing spinners (max
        // 1.44x).
        //
        // This is a wall-clock ratio, not a deterministic pin, so its
        // trustworthiness comes from two-sided discrimination, not from
        // the absolute numbers: roughly 2x of margin separates the 4x
        // gate from both the fast case's observed ceiling and the slow
        // case's observed floor, and `min_duration_over(_, 3)` keeps
        // each measured rep in the 25-80ms range - large enough that
        // scheduler/GC/page-fault noise does not dominate it.
        //
        // The 4x gate is intentionally STRICTER than the two sibling
        // scaling tests above, which both use 6x (see
        // `human_render_diagnostic_count_on_one_source_scales_sublinearly`'s
        // RATIO-check rationale): the 4x gate sits with wide margin on both
        // sides of the measured fast/slow ranges above.
        let (source, spans) = synthetic_source_with_spans(50_000, 24);
        let mut sources = BTreeMap::new();
        sources.insert("scaling.rules".to_string(), source);

        let head_diags: Vec<Diagnostic> = spans[..24]
            .iter()
            .enumerate()
            .map(|(i, span)| {
                Diagnostic::new(
                    Severity::Warning,
                    "fapd-W03",
                    span.clone(),
                    "scaling probe",
                    "scaling.rules",
                    i + 1,
                    1,
                )
                .with_source_id("scaling.rules")
            })
            .collect();
        let tail_diags: Vec<Diagnostic> = spans[spans.len() - 24..]
            .iter()
            .enumerate()
            .map(|(i, span)| {
                Diagnostic::new(
                    Severity::Warning,
                    "fapd-W03",
                    span.clone(),
                    "scaling probe",
                    "scaling.rules",
                    i + 1,
                    1,
                )
                .with_source_id("scaling.rules")
            })
            .collect();

        let t_head = min_duration_over(|| drop(render(&head_diags, &sources)), 3);
        let t_tail = min_duration_over(|| drop(render(&tail_diags, &sources)), 3);

        assert!(
            t_tail < t_head * 4,
            "24 diagnostics anchored at the TAIL of the source took {t_tail:?}, vs \
             {t_head:?} for 24 diagnostics of the SAME count anchored at the HEAD of \
             the SAME source (ratio {:.1}x) - expected < 4x; byte_span_to_char_span's \
             conversion cost should not depend on how far into the source a span sits \
             (#595 perf regression: see byte_span_to_char_span's doc comment \
             and the comment above)",
            t_tail.as_secs_f64() / t_head.as_secs_f64()
        );
    }

    #[test]
    fn format_controls_maps_every_framework_and_joins_multiple() {
        // Direct pin on format_controls: empty -> "" (byte-identical), each
        // framework's label, the alias arm, and the ", " join for multiple
        // controls. human.rs is NOT in the mutation-gate examine_globs, so these
        // direct assertions are the only net on the framework-label match arms
        // (a mutant swapping "CIS" for "STIG" survives every render()-level test).
        assert_eq!(format_controls(&[]), "");
        assert_eq!(
            format_controls(&[ControlRef::new(Framework::Stig, "RHEL-08-040110")]),
            " (STIG RHEL-08-040110)"
        );
        assert_eq!(
            format_controls(&[ControlRef::new(Framework::Cis, "1.1.1")]),
            " (CIS 1.1.1)"
        );
        assert_eq!(
            format_controls(&[ControlRef::new(Framework::Pci, "2.2.2")]),
            " (PCI 2.2.2)"
        );
        assert_eq!(
            format_controls(&[ControlRef::new(Framework::Nist, "AC-3")]),
            " (NIST AC-3)"
        );
        assert_eq!(
            format_controls(&[
                ControlRef::new(Framework::Stig, "RHEL-08-030130").with_alias("V-230404"),
                ControlRef::new(Framework::Cis, "5.2.1"),
            ]),
            " (STIG RHEL-08-030130/V-230404, CIS 5.2.1)",
            "multiple controls join with ', ' and the alias renders as id/alias"
        );
    }

    #[test]
    fn human_appends_control_suffix_on_plain_line() {
        // A finding carrying a STIG control renders ` (STIG <id>)` after the
        // message on the plain fallback line, so an operator reading text output
        // sees the control mapping, not just the free-text message.
        let d = Diagnostic::new(
            Severity::Warning,
            "sysctld-W02",
            0..0,
            "kernel param weak",
            "/etc/sysctl.conf",
            5,
            1,
        )
        .with_controls(vec![ControlRef::new(Framework::Stig, "RHEL-08-040110")]);
        let out = render(&[d], &empty_sources());
        assert!(
            out.contains("(STIG RHEL-08-040110)"),
            "control suffix must appear in {out:?}"
        );
    }

    #[test]
    fn human_omits_control_suffix_when_no_controls() {
        // No controls -> no suffix, so the plain line stays byte-identical to the
        // pre-v0.7 format. Guards the empty-is-unchanged invariant.
        let d = Diagnostic::new(
            Severity::Error,
            "fapd-E01",
            5..10,
            "unknown attribute",
            "/tmp/x.rules",
            3,
            12,
        );
        let out = render(&[d], &empty_sources());
        assert!(
            !out.contains("(STIG"),
            "a finding with no controls must have no suffix, got {out:?}"
        );
    }

    #[test]
    fn human_control_suffix_includes_alias_when_present() {
        // When a control carries a secondary id (the DISA Group/Vuln number), the
        // suffix shows `<id>/<alias>`. Pins the alias arm of format_controls.
        let d = Diagnostic::new(
            Severity::Warning,
            "au-W06",
            0..0,
            "missing rule",
            "/etc/audit/rules.d/x.rules",
            2,
            1,
        )
        .with_controls(vec![
            ControlRef::new(Framework::Stig, "RHEL-08-030130").with_alias("V-230404"),
        ]);
        let out = render(&[d], &empty_sources());
        assert!(
            out.contains("(STIG RHEL-08-030130/V-230404)"),
            "alias must render after the id in {out:?}"
        );
    }

    #[test]
    fn human_ariadne_title_carries_control_id() {
        // The ariadne snippet path (source present) also carries the control in
        // its report title, so the mapping is visible in both render paths.
        let source = "kernel.kptr_restrict = 0\n";
        let mut sources = BTreeMap::new();
        sources.insert("/etc/sysctl.conf".to_string(), source.to_string());
        let d = Diagnostic::new(
            Severity::Warning,
            "sysctld-W02",
            0..20,
            "insecure value",
            "/etc/sysctl.conf",
            1,
            1,
        )
        .with_source_id("/etc/sysctl.conf")
        .with_controls(vec![ControlRef::new(Framework::Stig, "RHEL-08-040110")]);
        let out = render(&[d], &sources);
        assert!(
            out.contains("RHEL-08-040110"),
            "ariadne title must carry the control id in {out:?}"
        );
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

    /// The caret-column pin (issue #595): assert the RENDERED column against a
    /// value derived BY HAND from the source layout.
    ///
    /// Be precise about what this test does and does not discriminate. The
    /// obvious overstatement - "this is what a monotone-but-wrong replacement
    /// fails" - is mechanically FALSE here. This test's span is `44..49` and
    /// BOTH endpoints are char boundaries, so every candidate mapping agrees:
    ///
    /// ```text
    /// byte span:           44..49
    /// ceil walk (the fix): 35..40      old byte-fallback: 35..40
    /// floor walk:          35..40      clamp on the old:  35..40
    /// ```
    ///
    /// A clamp is a NO-OP on a span that is already ordered and boundary
    /// aligned, and floor and ceil agree on every boundary offset, so all four
    /// render the identical header `t.rules:2:22`. The pins that actually
    /// separate the mapping families are the offset tables in
    /// `mid_character_offset_rounds_up_to_the_next_char_boundary`, which probe
    /// MID-character offsets; this test cannot do that job and does not claim to.
    ///
    /// What it genuinely catches, and what no property in this file catches:
    ///
    /// - **byte-vs-char confusion.** A mapping that handed ariadne the raw byte
    ///   offset would pass 44 for a source of only 43 characters. Be exact about
    ///   how that surfaces HERE: ariadne resolves nothing and renders `?:?`, so
    ///   the test fails on the third bullet below rather than on a caret that
    ///   moved. (The sibling e2e in `tests/e2e_sysctl_lint.rs` is where the same
    ///   confusion does move a visible column, to `:2:10`.)
    /// - **a boundary-offset off-by-one.** Any variant that shifts every
    ///   boundary offset up by one - widening a `take_while` predicate to
    ///   `*i <= b` admits one, and the current boundary walk would admit one
    ///   by counting the prefix past `q` rather than up to it - renders
    ///   column 23 instead of 22. Such a variant stays
    ///   total and monotone, so it is invisible to every ordering, totality and
    ///   saturation property. This is the one that needs the exact column.
    /// - **a snippet that silently fails to render at all.**
    ///
    /// The observable is ariadne's own bracket header,
    /// `[ <source_id>:<line>:<col> ]` (`ariadne-0.6.0/src/write.rs:280`), whose
    /// `col` is counted in CHARACTERS (`write.rs:262-269`). The multi-source
    /// cache pin earlier in this file asserts the same header shape
    /// (`\u{256d}\u{2500}[ a.rules:1:20 ]`), so the format is already pinned
    /// twice over.
    ///
    /// Layout, derived by hand:
    ///
    /// ```text
    /// line 1: "# \u{1F600} \u{65E5}\u{672C}\u{8A9E} notes"
    /// line 2: "allow exe=/usr/bin/x trust=1"
    /// ```
    ///
    /// Line 1 carries a 4-byte emoji plus three 3-byte CJK scalars: 13 bytes of
    /// multibyte for 4 characters. That gap is the point - any byte-vs-char
    /// confusion in `byte_span_to_char_span` moves the column asserted below.
    ///
    /// Line 2 is pure ASCII, so its 1-based CHARACTER columns are:
    ///
    /// ```text
    /// a1 l2 l3 o4 w5 _6 e7 x8 e9 =10 /11 u12 s13 r14 /15 b16 i17 n18 /19 x20 _21 t22
    /// ```
    ///
    /// so `trust` begins at character column 22 of line 2, and the header must
    /// read `t.rules:2:22`. The value is derived from the layout, NOT copied
    /// from a test run: copying observed output converts the assertion into a
    /// snapshot of whatever the code does, bug included.
    #[test]
    fn human_ariadne_header_column_is_char_counted_with_multibyte_before_the_line() {
        let source = "# \u{1f600} \u{65e5}\u{672c}\u{8a9e} notes\nallow exe=/usr/bin/x trust=1\n";
        let byte_start = source.find("trust").expect("trust present");
        let mut sources = BTreeMap::new();
        sources.insert("t.rules".to_string(), source.to_string());
        let d = Diagnostic::new(
            Severity::Error,
            "fapd-E01",
            byte_start..byte_start + "trust".len(),
            "trust attribute is not permitted here",
            "t.rules",
            2,
            22,
        )
        .with_source_id("t.rules");

        // Strip ANSI first: `color_enabled()` is true whenever this test
        // process's own stdout is a real terminal, so an unstripped pin passes
        // in CI and fails under a pty for reasons unrelated to #595.
        let out = strip_ansi(&render(&[d], &sources));

        assert!(
            out.contains("\u{256d}\u{2500}[ t.rules:2:22 ]"),
            "ariadne's header must place the caret at character column 22 of \
             line 2 despite 13 bytes of multibyte on line 1; got: {out:?}"
        );
        assert!(
            out.contains('\u{2500}'),
            "the caret box must render at all (ariadne silently omits the whole \
             snippet when it cannot locate the span); got: {out:?}"
        );
        assert!(
            out.contains("allow exe=/usr/bin/x trust=1"),
            "the underlined source line must appear verbatim; got: {out:?}"
        );
    }

    // -----------------------------------------------------------------
    // Layer-2 property tests for `byte_span_to_char_span`.
    //
    // Properties 1-3 are ASCII-only by construction; properties 4-6 (#595)
    // are the multibyte ones that pin the defect. Do not narrow 4-6 to
    // boundary-aligned or in-bounds offsets: that restriction IS the bug.
    //
    // Properties:
    // 1. For ASCII-only source, the char span equals the byte span (identity).
    // 2. For any source and char-boundary byte offsets, the char offset is
    //    <= the byte offset (multibyte chars compress the char index).
    // 3. For any source and char-boundary byte offset b, char offset ==
    //    source[..b].chars().count().
    // 4. (#595) For ANY source, multibyte included, and ANY ORDERED byte span -
    //    boundary-aligned or not, in bounds or not - the converted char span is
    //    still ORDERED. This is the direct pin on the panic: `ariadne::Label::new`
    //    asserts `start <= end` (ariadne-0.6.0/src/lib.rs:145) and aborts the
    //    process in the DEFAULT renderer when it does not hold.
    // 5. (#595) Totality: a DEGENERATE byte span `b..b` converts to a degenerate
    //    char span, for every `b` including mid-character and past-the-end.
    // 6. (#595) Saturation: every offset past `source.len()` maps to
    //    `source.chars().count()`, not to itself.
    // -----------------------------------------------------------------

    mod proptest_byte_to_char {
        use super::super::byte_span_to_char_span;
        use proptest::prelude::*;

        /// How far past `source.len()` the generated offsets reach.
        ///
        /// 5 clears the widest UTF-8 scalar (4 bytes) plus one, so an
        /// out-of-bounds offset is always genuinely out of bounds rather than
        /// merely inside the final character.
        const OOB_SLACK: usize = 5;

        /// One piece of generated source text, one arm per UTF-8 length class
        /// the renderer has to survive. Contains no `\n`: the source builder
        /// below owns line structure.
        ///
        /// | class          | scalar(s)                      | UTF-8 bytes |
        /// |----------------|--------------------------------|-------------|
        /// | CJK            | U+65E5, U+672C, U+8A9E         | 3           |
        /// | combining mark | `e` + U+0301 (COMBINING ACUTE) | 1 + 2       |
        /// | 4-byte emoji   | U+1F600                        | 4           |
        /// | ASCII filler   | `[a-z0-9 =:.]`                 | 1           |
        ///
        /// Each class earns its place. CJK is the class issue #595 reproduces
        /// with. The combining mark is one grapheme cluster spanning two
        /// scalars, so it fails any "count graphemes" mistake. The 4-byte emoji
        /// is the ONLY class with three distinct interior byte offsets, so an
        /// off-by-one that first appears at interior offset +3 is invisible to a
        /// 3-byte-only alphabet. ASCII filler keeps ordinary runs in the mix so
        /// the properties are not exclusively about exotic input.
        fn multibyte_piece() -> impl Strategy<Value = String> {
            prop_oneof![
                Just("\u{65e5}".to_string()),
                Just("\u{672c}".to_string()),
                Just("\u{8a9e}".to_string()),
                Just("e\u{301}".to_string()),
                Just("\u{1f600}".to_string()),
                "[a-z0-9 =:.]{1,4}",
            ]
        }

        /// A multi-line source built from [`multibyte_piece`], optionally
        /// opening with a UTF-8 BOM and optionally CLOSING with a trailing
        /// `\n` after its last line.
        ///
        /// U+FEFF (3 bytes) is generated ONLY at offset 0, the one position it
        /// is meaningful and the one position the fapolicyd parser treats
        /// specially when computing `body_start_in_file`
        /// (`rulesteward-fapolicyd/src/parser/mod.rs:73-79`).
        ///
        /// `trailing_newline` (issue #595): a generator that ended every
        /// source in `\n` unconditionally would let `byte_span_to_char_span`'s
        /// boundary scan always find a non-continuation byte (the newline)
        /// before reaching `source.len()`, so no case here would drive that
        /// scan all the way to the end of the source. `trailing_newline`
        /// closes that gap: when false and the last line's own last scalar
        /// is multibyte, the source's final byte is itself a continuation
        /// byte, so the scan must reach `source.len()` before finding a
        /// boundary - the same end-of-source case the hand-written
        /// `mid_character_offset_rounds_up_to_the_next_char_boundary` unit
        /// test's final-scalar block pins exactly.
        fn multibyte_source() -> impl Strategy<Value = String> {
            let line =
                prop::collection::vec(multibyte_piece(), 1..4).prop_map(|pieces| pieces.concat());
            (
                any::<bool>(),
                prop::collection::vec(line, 1..6),
                any::<bool>(),
            )
                .prop_map(|(leading_bom, lines, trailing_newline)| {
                    let mut src = String::new();
                    if leading_bom {
                        src.push('\u{feff}');
                    }
                    let last = lines.len() - 1;
                    for (i, line) in lines.into_iter().enumerate() {
                        src.push_str(&line);
                        if i != last || trailing_newline {
                            src.push('\n');
                        }
                    }
                    src
                })
        }

        proptest! {
            // `failure_persistence: None`: a failing property here would
            // otherwise write `crates/rulesteward-cli/proptest-regressions/`,
            // a path that is not gitignored, so it could be neither
            // committed nor ignored cleanly. Nothing
            // is lost - the shrunk input is in the panic message, and the
            // interesting offsets are pinned explicitly by the unit test below
            // rather than left to a saved seed.
            #![proptest_config(ProptestConfig {
                cases: 512,
                failure_persistence: None,
                ..ProptestConfig::default()
            })]

            // Property 1: ASCII-only source: byte span == char span.
            // For any ASCII string and two in-bounds offsets, the conversion
            // is identity. Kills mutations that apply char-index logic to ASCII.
            #[test]
            fn ascii_source_char_span_equals_byte_span(
                src in "[a-zA-Z0-9 !:=]{1,40}",
                start_idx in 0usize..40,
                end_delta in 0usize..5,
            ) {
                let start = start_idx.min(src.len());
                let end = (start + end_delta).min(src.len());
                let span = start..end;
                let cspan = byte_span_to_char_span(&span, &src);
                prop_assert_eq!(cspan.start, start,
                    "ASCII source: char start {} must equal byte start {}", cspan.start, start);
                prop_assert_eq!(cspan.end, end,
                    "ASCII source: char end {} must equal byte end {}", cspan.end, end);
            }

            // Property 2: char offset <= byte offset for any char-boundary
            // offset in any source. In ASCII (1 byte/char) they are equal.
            #[test]
            fn char_offset_le_byte_offset(src in "[a-zA-Z0-9 \n]{1,60}") {
                // For ASCII-only sources every offset is both a char and byte boundary.
                for b in 0..=src.len() {
                    let cspan = byte_span_to_char_span(&(b..b), &src);
                    prop_assert!(
                        cspan.start <= b,
                        "char offset {} must be <= byte offset {} in {:?}",
                        cspan.start, b, src
                    );
                }
            }

            // Property 3: char offset == source[..b].chars().count() for any
            // char-boundary byte offset. Verifies that the conversion counts
            // chars correctly, not just divides bytes.
            #[test]
            fn char_offset_equals_chars_count(
                src in "[a-zA-Z0-9 ]{1,50}",
                offset_idx in 0usize..51,
            ) {
                let b = offset_idx.min(src.len());
                let expected_chars = src[..b].chars().count();
                let cspan = byte_span_to_char_span(&(b..b), &src);
                prop_assert_eq!(cspan.start, expected_chars,
                    "char offset for byte {} must be {} in {:?}",
                    b, expected_chars, src);
            }

            // Property 4 (T1a, issue #595): ORDERING is preserved.
            //
            // The property whose absence let #595 through. Properties 1-3 are
            // all ASCII-only, and none of them relates `to_char(start)` to
            // `to_char(end)` for `start != end` - two independent gaps, and a
            // multibyte generator alone would not have closed the second.
            //
            // The generator deliberately draws offsets that are NOT char
            // boundaries and offsets past the end of the source. Restricting
            // either one is exactly the assumption the defect lives in: a
            // non-boundary `start` takes the `map_or` fallback and keeps its
            // raw BYTE value while a boundary `end` converts to a (smaller)
            // CHAR count, and the resulting span is inverted.
            #[test]
            fn multibyte_ordered_byte_span_stays_ordered(
                src in multibyte_source(),
                p in 0usize..4096,
                q in 0usize..4096,
            ) {
                let hi = src.len() + OOB_SLACK;
                let a = p % (hi + 1);
                let b = q % (hi + 1);
                let (start, end) = if a <= b { (a, b) } else { (b, a) };
                let cspan = byte_span_to_char_span(&(start..end), &src);
                prop_assert!(
                    cspan.start <= cspan.end,
                    "ordered byte span {}..{} over {:?} converted to the INVERTED \
                     char span {}..{}; ariadne::Label::new asserts start <= end \
                     and aborts the process when it does not hold",
                    start, end, src, cspan.start, cspan.end
                );
            }

            // Property 5 (T1b, issue #595): TOTALITY.
            //
            // GREEN before AND after the fix - it describes behavior the old
            // function already had, and exists so a later rewrite that reaches
            // for slicing (`&source[..b]`, which PANICS on a non-boundary
            // offset) cannot land quietly. A degenerate input span must stay
            // degenerate, which is strictly stronger than "does not panic".
            #[test]
            fn degenerate_byte_span_stays_degenerate(
                src in multibyte_source(),
                p in 0usize..4096,
            ) {
                let hi = src.len() + OOB_SLACK;
                let b = p % (hi + 1);
                let cspan = byte_span_to_char_span(&(b..b), &src);
                prop_assert_eq!(
                    cspan.start, cspan.end,
                    "degenerate byte span {}..{} over {:?} must stay degenerate, got {}..{}",
                    b, b, src, cspan.start, cspan.end
                );
            }

            // Property 6 (T1d, issue #595): SATURATION past the end.
            //
            // An out-of-bounds byte offset maps to the source's total char
            // count, not to itself. The old function returned the raw byte
            // value here (`source.get(..b)` is `None` past the end), which is
            // both larger than any real char offset and, paired with an
            // in-bounds `end`, one of the two ways to invert the span.
            #[test]
            fn out_of_bounds_offset_saturates_at_char_count(
                src in multibyte_source(),
                over in 1usize..=OOB_SLACK,
            ) {
                let b = src.len() + over;
                let expected = src.chars().count();
                let cspan = byte_span_to_char_span(&(b..b), &src);
                prop_assert_eq!(
                    cspan.start, expected,
                    "byte offset {} is past the end of {:?} ({} bytes) and must \
                     saturate at its {} chars, got {}",
                    b, src, src.len(), expected, cspan.start
                );
            }
        }

        /// T1c (issue #595): the EXACT mapping at a mid-character offset.
        ///
        /// A unit test, not a property: the ordering properties above pin that
        /// the mapping is monotone, and this pins WHICH monotone mapping it is.
        /// Both are needed - a monotone-but-wrong mapping satisfies every
        /// ordering assertion and still moves the caret.
        ///
        /// Byte layout of `"\u{65e5}\u{672c}\u{8a9e}\n"`, derived by hand (three
        /// CJK scalars at 3 bytes each, then a 1-byte newline):
        ///
        /// ```text
        /// byte:   0  1  2 | 3  4  5 | 6  7  8 | 9
        /// scalar: U+65E5    U+672C    U+8A9E    U+000A
        /// char:   0         1         2         3
        /// ```
        ///
        /// Char START indices are therefore {0, 3, 6, 9}, and `to_char(b)`
        /// counts the char starts STRICTLY BELOW `b`:
        ///
        /// ```text
        /// to_char(0)  = |{}|           = 0
        /// to_char(3)  = |{0}|          = 1
        /// to_char(4)  = |{0, 3}|       = 2   <- byte 4 is mid-character
        /// to_char(5)  = |{0, 3}|       = 2   <- byte 5 is mid-character
        /// to_char(6)  = |{0, 3}|       = 2
        /// to_char(9)  = |{0, 3, 6}|    = 3
        /// to_char(10) = |{0, 3, 6, 9}| = 4   <- == src.chars().count()
        /// ```
        ///
        /// So the span `4..6` - issue #595's own reproduction, which the old
        /// function mapped to the inverted `4..2` - maps to `2..2`.
        ///
        /// Byte 4 lies INSIDE the scalar starting at byte 3 (char index 1) and
        /// maps to 2, the index of the FOLLOWING character. That is ROUND-UP,
        /// not floor. Round-down would be equally total and equally monotone;
        /// this test records round-up as a DECISION rather than leaving it an
        /// accident a later cleanup can silently flip. What is NOT arbitrary,
        /// and is the whole point, is that both endpoints go through the SAME
        /// total monotone function and so can never take different branches.
        ///
        /// Every expected value above is derived from the byte layout, not read
        /// off a test run: copying observed output would pin whatever the code
        /// does, including whatever it does wrong.
        ///
        /// # The offset TABLES are load-bearing; the headline assertion is not
        ///
        /// Do not trim the tables below as redundant with the `4..6 -> 2..2`
        /// assertion. They are what kills the CLAMP family, and the headline
        /// assertion on its own does not.
        ///
        /// A clamp such as `let s = old(start); let e = old(end); s.min(e)..e`
        /// is exactly the repair issue #595's own "suggested fix direction"
        /// proposes. On the reproduction span it computes `old(4) = 4`,
        /// `old(6) = 2`, `min(4, 2) = 2`, and returns `2..2` - it PASSES the
        /// headline assertion. What catches it is the table rows at bytes 4 and
        /// 5, which probe the DEGENERATE span `b..b`: clamping an endpoint
        /// against an identical endpoint is a no-op, so the raw byte value 4
        /// shows through where 2 is required.
        ///
        /// Precisely: the tables are the ONLY thing that catches the SATURATING
        /// variant (the one that also maps past-the-end offsets to the char
        /// count). The literal sketch above, which leaves out-of-bounds offsets
        /// passing through as raw bytes, is additionally killed by property 6.
        /// So "only the tables" is true of the harder variant and not of the
        /// weaker one - which is precisely why the tables cannot be trimmed.
        ///
        /// That is also why a clamp is the wrong shape in the first place. It
        /// relocates the caret to a position no evidence supports and leaves the
        /// reader unable to tell "the span was fine" from "the span was garbage
        /// and I hid it". A total, monotone mapping needs no clamp: the ordering
        /// is a theorem, not a repair.
        #[test]
        fn mid_character_offset_rounds_up_to_the_next_char_boundary() {
            let src = "\u{65e5}\u{672c}\u{8a9e}\n";
            assert_eq!(
                src.len(),
                10,
                "three 3-byte CJK scalars plus a 1-byte newline"
            );
            assert_eq!(src.chars().count(), 4, "four scalars");
            assert!(!src.is_char_boundary(4), "byte 4 must be mid-character");
            assert!(!src.is_char_boundary(5), "byte 5 must be mid-character");

            assert_eq!(
                byte_span_to_char_span(&(4..6), src),
                2..2,
                "issue #595's reproduction span 4..6 must map to the ORDERED 2..2, \
                 not the inverted 4..2 the byte-fallback produced"
            );

            // The full mapping, not just the reproduction's two endpoints. This
            // is what separates the intended round-up walk from any other
            // monotone mapping; it is what kills the clamp family (see the doc
            // comment); and it is what makes a `<` -> `<=` off-by-one in the
            // walk's predicate observable (that mutation moves to_char(3) from
            // 1 to 2).
            for (b, expected) in [
                (0usize, 0usize),
                (3, 1),
                (4, 2),
                (5, 2),
                (6, 2),
                (9, 3),
                (10, 4),
            ] {
                let cspan = byte_span_to_char_span(&(b..b), src);
                assert_eq!(
                    cspan.start, expected,
                    "to_char({b}) must be {expected} (char starts are 0, 3, 6, 9)"
                );
            }

            // The 4-byte class, pinned exactly rather than merely generated.
            //
            // The multibyte alphabet includes U+1F600 specifically because it is
            // the only class with THREE distinct interior byte offsets, so an
            // off-by-one that first appears at interior offset +3 is invisible
            // to a 3-byte-only alphabet. Properties 4/5/6 do generate it, but
            // they assert ordering, degeneracy and saturation - none of which is
            // sensitive to WHICH monotone mapping was chosen. Without the rows
            // below, that stated rationale would be undischarged: the emoji
            // would be generated and its exact mapping never checked.
            //
            // Byte layout of "\u{1F600}\u{65E5}\n", derived by hand:
            //
            //   byte:   0  1  2  3 | 4  5  6 | 7
            //   scalar: U+1F600      U+65E5    U+000A
            //   char:   0            1         2
            //
            // Char START indices are {0, 4, 7}, so counting the starts strictly
            // below b gives 1 for every one of the emoji's interior offsets
            // (1, 2, 3) AND for byte 4 - the emoji rounds up to the index of the
            // following character, exactly as the 3-byte case does at +1/+2.
            let emoji_src = "\u{1f600}\u{65e5}\n";
            assert_eq!(
                emoji_src.len(),
                8,
                "a 4-byte emoji, a 3-byte CJK, a newline"
            );
            assert_eq!(emoji_src.chars().count(), 3, "three scalars");
            for b in [1usize, 2, 3] {
                assert!(
                    !emoji_src.is_char_boundary(b),
                    "byte {b} must be interior to the 4-byte scalar"
                );
            }
            for (b, expected) in [
                (0usize, 0usize),
                (1, 1),
                (2, 1),
                (3, 1),
                (4, 1),
                (5, 2),
                (7, 2),
                (8, 3),
            ] {
                let cspan = byte_span_to_char_span(&(b..b), emoji_src);
                assert_eq!(
                    cspan.start, expected,
                    "to_char({b}) over a 4-byte scalar must be {expected} \
                     (char starts are 0, 4, 7)"
                );
            }

            // The FINAL-SCALAR case (issue #595): a source that does
            // NOT end in `\n` and whose LAST scalar is multibyte.
            //
            // Every table above ends its source with a 1-byte `\n`, which is
            // itself a char boundary, so `byte_span_to_char_span`'s boundary
            // scan always finds one before reaching `source.len()`. None of
            // those tables ever drives the scan all the way to the very end
            // of the source - the one place a scan starting past every char
            // boundary must still terminate correctly. This case closes that
            // gap: the source's very last byte is itself a continuation
            // byte, so converting an offset inside the final scalar forces
            // the scan to walk to `source.len()` before it finds a boundary.
            //
            // The scan uses `source.is_char_boundary(q)` (#595), which is
            // total for every `q` up to and including `source.len()`, so an
            // index-out-of-bounds at the end of the source cannot occur by
            // construction. This table's job is coverage of the
            // end-of-source arm.
            //
            // Byte layout of `"ab\u{1F600}"`, derived by hand: two 1-byte
            // ASCII chars, then a 4-byte emoji, with NOTHING after it.
            //
            //   byte:   0  1 | 2  3  4  5
            //   scalar: a  b   U+1F600
            //   char:   0  1   2
            //
            // Char START indices are {0, 1, 2}. Bytes 3, 4 and 5 are INTERIOR
            // continuation bytes of the final (and only) multibyte scalar -
            // the source's very last byte (index 5) is itself a continuation
            // byte, so walking from any of 3/4/5 drives `q` up to `len` (6)
            // without ever meeting a non-continuation byte to stop on first.
            let final_scalar_src = "ab\u{1f600}";
            assert_eq!(
                final_scalar_src.len(),
                6,
                "two ASCII bytes plus a 4-byte emoji, no trailing newline"
            );
            assert_eq!(final_scalar_src.chars().count(), 3, "three scalars");
            for b in [3usize, 4, 5] {
                assert!(
                    !final_scalar_src.is_char_boundary(b),
                    "byte {b} must be interior to the final emoji scalar"
                );
            }
            for (b, expected) in [(2usize, 2usize), (3, 3), (4, 3), (5, 3), (6, 3)] {
                let cspan = byte_span_to_char_span(&(b..b), final_scalar_src);
                assert_eq!(
                    cspan.start, expected,
                    "to_char({b}) over a final multibyte scalar with no trailing \
                     newline must be {expected} (char starts are 0, 1, 2); bytes \
                     3-5 drive the scan all the way to len (6) with no boundary \
                     found before that point - the end-of-source case none of \
                     the tables above ever exercise"
                );
            }
        }
    }
}
