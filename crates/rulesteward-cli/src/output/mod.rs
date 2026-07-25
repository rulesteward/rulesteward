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
/// (CC-4); these five verbs are findings-only. fapolicyd is not a caller for
/// its NORMAL render path (it uses the three-variant [`render`] directly,
/// with the real `--sarif-include-pass` attestation) -- but it does reach
/// this function through [`emit_path_error_envelope`] for the empty
/// path-error envelope (#561/#583), since an empty diagnostics set with
/// `pass: None` renders byte-identical either way. Exit-code mapping stays
/// in the caller (`exit_code::compute`); a rendering failure here is
/// reported to the caller so it can override that mapping to a tool failure
/// (mirrors the `output::render` error-handling convention in
/// `commands::fapolicyd::lint`).
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

/// Shared path-error envelope emitter (#561/#583).
///
/// When a lint verb's target path cannot be read at all (missing, wrong
/// type, permission denied) it must still emit a valid (empty) envelope on
/// stdout under `--format json`/`--format sarif` -- not silently drop to zero
/// bytes just because no file was ever staged for the normal render. Called
/// ALONGSIDE (not instead of) the caller's own `eprintln!` diagnostic; under
/// Human format this renders an empty diagnostics list, which is `""`, so
/// nothing new prints to stdout there. Render failures are deliberately
/// swallowed: the caller already returns `EXIT_TOOL_FAILURE` for the original
/// path error regardless of whether this succeeds.
///
/// One shared helper replaces what used to be four identical private copies
/// (`sshd`/`sysctl`/`sudoers`/`auditd`, each closing over its own `kind` +
/// `schema_version` constant): `selinux lint`'s path-error arm calls it too
/// (kind `"selinux-lint"`), as does `fapolicyd lint`'s positional
/// directory-scan-mode early return (kind `"lint"`, `schema_version`
/// [`json::LINT_SCHEMA_VERSION`]). fapolicyd is not an [`emit_lint`] caller
/// for its normal render path (it calls the three-variant [`render`]
/// directly, for the real `--sarif-include-pass` attestation) -- but for an
/// EMPTY diagnostics set with `pass: None`, `emit_lint`'s output is
/// byte-identical to `render`'s (both dispatch to the same per-format
/// renderers with the same inputs), so this ONE helper covers it too instead
/// of a sixth private copy.
pub fn emit_path_error_envelope(format: OutputFormat, kind: &str, schema_version: u32) {
    let _ = emit_lint(format, kind, schema_version, &[], &BTreeMap::new());
}
