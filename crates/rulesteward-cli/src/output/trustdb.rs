//! Trust-DB report rendering (Human + Json).
//!
//! The trust-DB verbs (`list` / `check` / `diff` / `stale`) produce flat row
//! reports, not source-anchored diagnostics, so they do NOT go through the
//! ariadne `human` renderer. Each verb builds a small serde report type here
//! and renders it as either a pretty JSON array (machine-readable, trailing
//! newline) or aligned human columns.

use rulesteward_fapolicyd::{DiskVerdict, TrustEntry, TrustSource};
use serde::Serialize;

/// One row of `trustdb list` output: the recorded trust-DB entry verbatim.
#[derive(Debug, Serialize)]
pub struct ListRow {
    pub path: String,
    pub source: TrustSource,
    pub size: u64,
    pub sha256: String,
}

impl From<&TrustEntry> for ListRow {
    fn from(e: &TrustEntry) -> Self {
        Self {
            path: e.path.clone(),
            source: e.source,
            size: e.size,
            sha256: e.sha256.clone(),
        }
    }
}

/// The verdict for one path in a `check` / `diff` (vs-disk) / `stale` report.
///
/// `Absent` means the queried path is not recorded in the trust DB at all
/// (distinct from `Missing`, where it IS recorded but the file is gone on disk).
#[derive(Debug, Serialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum CheckVerdict {
    Match,
    Missing,
    SizeMismatch { recorded: u64, actual: u64 },
    HashMismatch { recorded: String, actual: String },
    ReadError { message: String },
    NotInDb,
}

impl From<&DiskVerdict> for CheckVerdict {
    fn from(v: &DiskVerdict) -> Self {
        match v {
            DiskVerdict::Match => Self::Match,
            DiskVerdict::Missing => Self::Missing,
            DiskVerdict::SizeMismatch { recorded, actual } => Self::SizeMismatch {
                recorded: *recorded,
                actual: *actual,
            },
            DiskVerdict::HashMismatch { recorded, actual } => Self::HashMismatch {
                recorded: recorded.clone(),
                actual: actual.clone(),
            },
            DiskVerdict::ReadError(m) => Self::ReadError { message: m.clone() },
        }
    }
}

impl CheckVerdict {
    /// True iff this verdict counts as a divergence (non-clean) for exit-code
    /// purposes. `Match` is clean; everything else (missing/mismatch/read
    /// error/not-in-DB) is a divergence.
    #[must_use]
    pub fn is_divergence(&self) -> bool {
        !matches!(self, Self::Match)
    }
}

/// One row of a `check` / `diff` (vs-disk) / `stale` report.
#[derive(Debug, Serialize)]
pub struct CheckRow {
    pub path: String,
    #[serde(flatten)]
    pub verdict: CheckVerdict,
}

/// Which side of a DB-vs-DB diff a row appears on.
#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DbDiffKind {
    /// Present only in the primary (`--db`) database.
    OnlyInDb,
    /// Present only in the `--against` database.
    OnlyInAgainst,
    /// Present in both under the same key but with a differing value.
    ValueDiffers,
}

/// One row of a DB-vs-DB `diff` report.
#[derive(Debug, Serialize)]
pub struct DbDiffRow {
    pub path: String,
    #[serde(flatten)]
    pub kind: DbDiffKind,
}

// ---- Renderers --------------------------------------------------------------

/// Render a `list` report.
#[must_use]
pub fn render_list(rows: &[ListRow], json: bool) -> String {
    if json {
        to_json(rows)
    } else {
        use std::fmt::Write as _;
        let mut out = String::new();
        for r in rows {
            // Writing to a String is infallible.
            let _ = writeln!(
                out,
                "{:<8} {:>12} {} {}",
                source_label(r.source),
                r.size,
                r.sha256,
                r.path
            );
        }
        out
    }
}

/// Render a `check` / `diff` (vs-disk) / `stale` report.
#[must_use]
pub fn render_checks(rows: &[CheckRow], json: bool) -> String {
    if json {
        to_json(rows)
    } else {
        use std::fmt::Write as _;
        let mut out = String::new();
        for r in rows {
            // Writing to a String is infallible.
            let _ = writeln!(out, "{:<14} {}", verdict_label(&r.verdict), r.path);
        }
        out
    }
}

/// Render a DB-vs-DB `diff` report.
#[must_use]
pub fn render_db_diff(rows: &[DbDiffRow], json: bool) -> String {
    if json {
        to_json(rows)
    } else {
        use std::fmt::Write as _;
        let mut out = String::new();
        for r in rows {
            // Writing to a String is infallible.
            let _ = writeln!(out, "{:<16} {}", db_diff_label(&r.kind), r.path);
        }
        out
    }
}

/// Serialize a report to pretty JSON with a trailing newline.
///
/// Mirrors `output/json.rs` exactly: the report types here are plain structs of
/// owned `String`/`u64`/`enum` fields with no map keys that can fail to
/// serialize, so `serde_json::to_string_pretty` is infallible for them and the
/// `.expect(...)` cannot fire.
fn to_json<T: Serialize + ?Sized>(report: &T) -> String {
    let mut s =
        serde_json::to_string_pretty(report).expect("trust-DB report serialization cannot fail");
    s.push('\n');
    s
}

fn source_label(source: TrustSource) -> &'static str {
    match source {
        TrustSource::RpmDb => "rpm",
        TrustSource::FileDb => "file",
        TrustSource::Deb => "deb",
        TrustSource::Unknown => "unknown",
    }
}

fn verdict_label(v: &CheckVerdict) -> &'static str {
    match v {
        CheckVerdict::Match => "match",
        CheckVerdict::Missing => "missing",
        CheckVerdict::SizeMismatch { .. } => "size-mismatch",
        CheckVerdict::HashMismatch { .. } => "hash-mismatch",
        CheckVerdict::ReadError { .. } => "read-error",
        CheckVerdict::NotInDb => "not-in-db",
    }
}

fn db_diff_label(k: &DbDiffKind) -> &'static str {
    match k {
        DbDiffKind::OnlyInDb => "only-in-db",
        DbDiffKind::OnlyInAgainst => "only-in-against",
        DbDiffKind::ValueDiffers => "value-differs",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_json_is_array_with_trailing_newline() {
        let rows = vec![ListRow {
            path: "/usr/bin/ls".to_owned(),
            source: TrustSource::RpmDb,
            size: 111,
            sha256: "a".repeat(64),
        }];
        let out = render_list(&rows, true);
        assert!(out.ends_with('\n'), "json output must end with newline");
        let v: serde_json::Value = serde_json::from_str(&out).expect("valid json");
        let arr = v.as_array().expect("top-level array");
        assert_eq!(arr.len(), 1);
        let obj = arr[0].as_object().expect("object");
        for key in ["path", "source", "size", "sha256"] {
            assert!(obj.contains_key(key), "missing key {key}");
        }
    }

    #[test]
    fn check_verdict_match_is_not_divergence_others_are() {
        assert!(!CheckVerdict::Match.is_divergence());
        assert!(CheckVerdict::Missing.is_divergence());
        assert!(CheckVerdict::NotInDb.is_divergence());
        assert!(
            CheckVerdict::SizeMismatch {
                recorded: 1,
                actual: 2
            }
            .is_divergence()
        );
    }
}
