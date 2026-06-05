//! Exception-register output renderers (human | json | csv).
//!
//! Mirrors `output::trustdb` flat-row style. The JSON renderer delegates to
//! `output::json::render_envelope`; the CSV renderer reuses
//! `output::csv::to_csv`; the human renderer produces aligned columns with a
//! trailing summary line.

use rulesteward_fapolicyd::register::{
    EXCEPTION_REGISTER_DRIFT_KIND, EXCEPTION_REGISTER_KIND, REGISTER_SCHEMA_VERSION,
};
use rulesteward_fapolicyd::{DriftRow, HashOrigin, RegisterRow, Scope, TrustEntry, TrustSource};
use serde::Serialize;

use crate::output::csv::to_csv;
use crate::output::json::render_envelope;

// ---------------------------------------------------------------------------
// trustJoin row shape (Shape A - per-grant path join)
// ---------------------------------------------------------------------------

/// One row inside a `trustJoin[N].rows` array (Shape A): a trust-DB record
/// that matched a grant's subject/object path.
#[derive(Serialize)]
pub struct TrustJoinRow {
    pub path: String,
    pub source: String,
    pub size: u64,
    pub digest: String,
}

impl TrustJoinRow {
    #[must_use]
    pub fn from_entry(e: &TrustEntry) -> Self {
        Self {
            path: e.path.clone(),
            source: source_label(e.source).to_owned(),
            size: e.size,
            digest: e.digest.clone(),
        }
    }
}

fn source_label(s: TrustSource) -> &'static str {
    match s {
        TrustSource::RpmDb => "RpmDb",
        TrustSource::FileDb => "FileDb",
        TrustSource::Deb => "Deb",
        TrustSource::Unknown => "Unknown",
    }
}

/// One element of the `trustJoin` array (Shape A): per-grant join result.
#[derive(Serialize)]
pub struct TrustJoinEntry {
    #[serde(rename = "grantIndex")]
    pub grant_index: usize,
    pub rows: Vec<TrustJoinRow>,
}

// ---------------------------------------------------------------------------
// enumerate-cap shape (trust=1 grant, supressed or full enumeration)
// ---------------------------------------------------------------------------

/// The `grantSource` location for an enumerate-cap `trustJoin` block.
#[derive(Serialize)]
pub struct TrustJoinCapSource {
    pub file: String,
    pub line: usize,
}

/// The cap-form `trustJoin` object (for a `trust=1` grant).
///
/// Without `--enumerate-trust`: `enumerated: false`, no `entries`.
/// With `--enumerate-trust`: `enumerated: true`, `entries` present.
#[derive(Serialize)]
pub struct TrustJoinCap {
    #[serde(rename = "grantSource")]
    pub grant_source: TrustJoinCapSource,
    pub count: usize,
    pub enumerated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entries: Option<Vec<TrustJoinRow>>,
}

// ---------------------------------------------------------------------------
// JSON envelope payloads
// ---------------------------------------------------------------------------

/// Payload for the `exception-register` JSON envelope (plain register, no trustJoin).
#[derive(Serialize)]
struct RegisterPayload<'a> {
    grants: &'a [RegisterRow],
}

/// Payload for the `exception-register` JSON envelope with Shape A trustJoin.
#[derive(Serialize)]
struct RegisterWithJoinPayload<'a> {
    grants: &'a [RegisterRow],
    #[serde(rename = "trustJoin")]
    trust_join: Vec<TrustJoinEntry>,
}

/// Payload for the `exception-register` JSON envelope with cap-form trustJoin.
#[derive(Serialize)]
struct RegisterWithCapPayload<'a> {
    grants: &'a [RegisterRow],
    #[serde(rename = "trustJoin")]
    trust_join: TrustJoinCap,
}

/// Payload for the `exception-register-drift` JSON envelope.
#[derive(Serialize)]
struct DriftPayload<'a> {
    drift: &'a [DriftRow],
}

// ---------------------------------------------------------------------------
// Public rendering entry points
// ---------------------------------------------------------------------------

/// Render the exception register as a JSON envelope string.
///
/// When `trust_join` is `Some`, embeds the per-grant join entries (Shape A) or
/// the cap object.
#[must_use]
pub fn render_json_register(grants: &[RegisterRow]) -> String {
    render_envelope(
        EXCEPTION_REGISTER_KIND,
        REGISTER_SCHEMA_VERSION,
        &RegisterPayload { grants },
    )
}

/// Render the register with a Shape A (per-grant array) `trustJoin`.
#[must_use]
pub fn render_json_register_with_join(grants: &[RegisterRow], join: Vec<TrustJoinEntry>) -> String {
    render_envelope(
        EXCEPTION_REGISTER_KIND,
        REGISTER_SCHEMA_VERSION,
        &RegisterWithJoinPayload {
            grants,
            trust_join: join,
        },
    )
}

/// Render the register with a cap-form `trustJoin` object (trust=1 grant).
#[must_use]
pub fn render_json_register_with_cap(grants: &[RegisterRow], cap: TrustJoinCap) -> String {
    render_envelope(
        EXCEPTION_REGISTER_KIND,
        REGISTER_SCHEMA_VERSION,
        &RegisterWithCapPayload {
            grants,
            trust_join: cap,
        },
    )
}

/// Render a drift report as a JSON envelope string.
#[must_use]
pub fn render_json_drift(drift: &[DriftRow]) -> String {
    render_envelope(
        EXCEPTION_REGISTER_DRIFT_KIND,
        REGISTER_SCHEMA_VERSION,
        &DriftPayload { drift },
    )
}

/// Render the exception register in CSV format.
///
/// Columns: decision, perm, subject, object, hash, hashOrigin, scope,
/// sourcefile, sourceline, loadIndex.
#[must_use]
pub fn render_csv_register(grants: &[RegisterRow]) -> String {
    let headers = &[
        "decision",
        "perm",
        "subject",
        "object",
        "hash",
        "hashOrigin",
        "scope",
        "sourceFile",
        "sourceLine",
        "loadIndex",
    ];
    let rows: Vec<Vec<String>> = grants
        .iter()
        .map(|r| {
            vec![
                r.decision.clone(),
                r.perm.clone(),
                r.subject.clone(),
                r.object.clone(),
                r.hash.clone().unwrap_or_default(),
                hash_origin_str(r.hash_origin).to_owned(),
                scope_str(r.scope).to_owned(),
                r.source.file.clone(),
                r.source.line.to_string(),
                r.load_index.to_string(),
            ]
        })
        .collect();
    to_csv(headers, &rows)
}

/// Render the exception register in human-readable format.
///
/// Produces aligned columns followed by a trailing summary line.
#[must_use]
pub fn render_human_register(grants: &[RegisterRow]) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    for r in grants {
        let hash_display = r.hash.as_deref().unwrap_or("-");
        let _ = writeln!(
            out,
            "{:<14} {:<8} {:<40} {:<40} {:<10} {}:{}",
            r.decision,
            r.perm,
            truncate(&r.subject, 38),
            truncate(&r.object, 38),
            hash_origin_str(r.hash_origin),
            r.source.file,
            r.source.line,
        );
        // Print hash on next line if present (it's 64+ chars)
        if r.hash.is_some() {
            let _ = writeln!(out, "  hash={hash_display}");
        }
    }
    // Summary line
    let total = grants.len();
    let hash_pinned = grants
        .iter()
        .filter(|r| r.hash_origin == HashOrigin::RuleFilehash)
        .count();
    let trust_scoped = grants
        .iter()
        .filter(|r| matches!(r.scope, rulesteward_fapolicyd::Scope::Trust))
        .count();
    let _ = writeln!(
        out,
        "{total} allow-grants ({hash_pinned} hash-pinned, {trust_scoped} trust-scoped)"
    );
    out
}

fn truncate(s: &str, max_len: usize) -> String {
    // Use char-aware truncation to avoid panicking on multibyte UTF-8 sequences
    // (fapolicyd paths can contain non-ASCII characters).
    if s.chars().count() <= max_len {
        s.to_owned()
    } else {
        s.chars().take(max_len).collect()
    }
}

fn scope_str(s: Scope) -> &'static str {
    match s {
        Scope::All => "all",
        Scope::Path => "path",
        Scope::Dir => "dir",
        Scope::Ftype => "ftype",
        Scope::Pattern => "pattern",
        Scope::Hash => "hash",
        Scope::Trust => "trust",
    }
}

fn hash_origin_str(o: HashOrigin) -> &'static str {
    match o {
        HashOrigin::None => "none",
        HashOrigin::RuleFilehash => "rule-filehash",
        HashOrigin::Trustdb => "trustdb",
    }
}
