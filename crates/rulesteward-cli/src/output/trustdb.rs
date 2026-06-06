//! Trust-DB report rendering (Human + Json).
//!
//! The trust-DB verbs (`list` / `check` / `diff` / `stale`) produce flat row
//! reports, not source-anchored diagnostics, so they do NOT go through the
//! ariadne `human` renderer. Each verb builds a small serde report type here
//! and renders it as either a pretty JSON array (machine-readable, trailing
//! newline) or aligned human columns.

use rulesteward_fapolicyd::{DiskVerdict, TrustEntry, TrustSource};
use serde::Serialize;

use crate::output::csv::to_csv;
use crate::output::json::render_envelope;

/// Schema version for the `trust-entries` JSON kind (CC-2 / #63). Bumps only on a
/// breaking change to the trust-DB row payload (field removal, rename, retype).
pub const TRUST_ENTRIES_SCHEMA_VERSION: u32 = 1;

/// `kind` discriminator for the unified trust-DB JSON envelope.
const TRUST_ENTRIES_KIND: &str = "trust-entries";

/// Envelope payload for the trust-DB verbs: the rows live under a `data` key so
/// the wire shape is `{ schemaVersion, kind: "trust-entries", data: [...] }`.
#[derive(Serialize)]
struct TrustEntriesPayload<'a, T: Serialize> {
    data: &'a [T],
}

/// Wrap a row slice in the unified `trust-entries` envelope (CC-2 / #63).
///
/// Replaces the pre-v0.2 bare top-level JSON array. Same trailing-newline
/// convention as the bare array it supersedes (via `render_envelope`).
fn to_envelope<T: Serialize>(rows: &[T]) -> String {
    render_envelope(
        TRUST_ENTRIES_KIND,
        TRUST_ENTRIES_SCHEMA_VERSION,
        &TrustEntriesPayload { data: rows },
    )
}

/// One row of `trustdb list` output: the recorded trust-DB entry verbatim.
///
/// The `digest` field holds whatever hash algorithm fapolicyd recorded for this
/// entry (MD5/SHA1/SHA256/SHA512, depending on the fapolicyd version and DB
/// generation). The JSON key is `"digest"` - a previous version used `"sha256"`
/// which was misleading for non-SHA256 trust DBs.
#[derive(Debug, Serialize)]
pub struct ListRow {
    pub path: String,
    pub source: TrustSource,
    pub size: u64,
    pub digest: String,
    /// Weak hash algorithm implied by the digest length (MD5/SHA1), if any.
    /// `None` for strong SHA256/SHA512 digests; omitted from JSON when `None`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub weak: Option<&'static str>,
}

impl From<&TrustEntry> for ListRow {
    fn from(e: &TrustEntry) -> Self {
        Self {
            path: e.path.clone(),
            source: e.source,
            size: e.size,
            digest: e.digest.clone(),
            weak: rulesteward_fapolicyd::weak_digest_algorithm(&e.digest),
        }
    }
}

/// The verdict for one path in a `check` / `diff` (vs-disk) / `stale` report.
///
/// `Absent` means the queried path is not recorded in the trust DB at all
/// (distinct from `Missing`, where it IS recorded but the file is gone on disk).
#[derive(Debug, Serialize, PartialEq, Eq)]
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
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct CheckRow {
    pub path: String,
    #[serde(flatten)]
    pub verdict: CheckVerdict,
}

/// Which side of a DB-vs-DB diff a row appears on.
#[derive(Debug, Serialize, PartialEq, Eq)]
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
#[derive(Debug, Serialize, PartialEq, Eq)]
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
        to_envelope(rows)
    } else {
        use std::fmt::Write as _;
        let mut out = String::new();
        for r in rows {
            // Writing to a String is infallible.
            let _ = write!(
                out,
                "{:<8} {:>12} {} {}",
                source_label(r.source),
                r.size,
                r.digest,
                r.path
            );
            if let Some(alg) = r.weak {
                let _ = write!(out, " (weak: {alg})");
            }
            let _ = writeln!(out);
        }
        out
    }
}

/// Render a `list` report as RFC-4180 CSV (#64 / CC-3).
///
/// Columns (stable order): `source,size,digest,path,weak`. The `weak` column
/// holds the weak-hash algorithm name (e.g. `MD5`) implied by the digest length,
/// or is empty for strong (SHA256/SHA512) digests. One row per trust entry; no
/// aggregate/summary rows (a single rectangular table, per the locked CSV policy).
#[must_use]
pub fn render_csv_list(rows: &[ListRow]) -> String {
    let headers = &["source", "size", "digest", "path", "weak"];
    let body: Vec<Vec<String>> = rows
        .iter()
        .map(|r| {
            vec![
                source_label(r.source).to_owned(),
                r.size.to_string(),
                r.digest.clone(),
                r.path.clone(),
                r.weak.unwrap_or("").to_owned(),
            ]
        })
        .collect();
    to_csv(headers, &body)
}

/// Render a `check` / `diff` (vs-disk) / `stale` report.
#[must_use]
pub fn render_checks(rows: &[CheckRow], json: bool) -> String {
    if json {
        to_envelope(rows)
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
        to_envelope(rows)
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
    fn list_json_is_trust_entries_envelope_with_trailing_newline() {
        let rows = vec![ListRow {
            path: "/usr/bin/ls".to_owned(),
            source: TrustSource::RpmDb,
            size: 111,
            digest: "a".repeat(64),
            weak: None,
        }];
        let out = render_list(&rows, true);
        assert!(out.ends_with('\n'), "json output must end with newline");
        let v: serde_json::Value = serde_json::from_str(&out).expect("valid json");
        // CC-2 / #63: the unified envelope, not a bare array.
        assert!(
            v.is_object(),
            "must be the envelope object, not a bare array"
        );
        assert_eq!(v["schemaVersion"], serde_json::json!(1));
        assert_eq!(v["kind"], serde_json::json!("trust-entries"));
        let arr = v["data"].as_array().expect("`data` array");
        assert_eq!(arr.len(), 1);
        let obj = arr[0].as_object().expect("object");
        for key in ["path", "source", "size", "digest"] {
            assert!(obj.contains_key(key), "missing key {key}");
        }
    }

    /// A row built from a weak (MD5 32-hex) trust entry must carry the weak algo,
    /// surfaced in both human and JSON output; a strong (SHA256) row carries none.
    /// RED: the stub `From` sets `weak: None` and `render_list` does not annotate.
    #[test]
    fn list_annotates_weak_md5_entry_human_and_json() {
        use rulesteward_fapolicyd::{TrustEntry, TrustSource};
        let weak_entry = TrustEntry {
            path: "/usr/bin/weak".to_owned(),
            source: TrustSource::FileDb,
            size: 10,
            digest: "a".repeat(32), // MD5 length
        };
        let strong_entry = TrustEntry {
            path: "/usr/bin/strong".to_owned(),
            source: TrustSource::FileDb,
            size: 20,
            digest: "b".repeat(64), // SHA256 length
        };
        let rows: Vec<ListRow> = [&weak_entry, &strong_entry]
            .iter()
            .map(|e| ListRow::from(*e))
            .collect();

        // Human output marks the weak row, leaves the strong row unmarked.
        let human = render_list(&rows, false);
        assert!(
            human.contains("weak: MD5"),
            "human list must annotate the MD5 entry with 'weak: MD5'; got:\n{human}",
        );
        let weak_line = human
            .lines()
            .find(|l| l.contains("/usr/bin/weak"))
            .expect("weak line present");
        let strong_line = human
            .lines()
            .find(|l| l.contains("/usr/bin/strong"))
            .expect("strong line present");
        assert!(
            weak_line.contains("weak:"),
            "the MD5 line must be annotated; got: {weak_line}",
        );
        assert!(
            !strong_line.contains("weak:"),
            "the SHA256 line must NOT be annotated; got: {strong_line}",
        );

        // JSON: weak row has "weak":"MD5"; strong row omits the key.
        let json = render_list(&rows, true);
        let v: serde_json::Value = serde_json::from_str(&json).expect("valid json");
        assert_eq!(v["kind"], serde_json::json!("trust-entries"));
        let arr = v["data"].as_array().expect("`data` array");
        let weak_obj = arr
            .iter()
            .find(|o| o["path"] == "/usr/bin/weak")
            .expect("weak obj");
        assert_eq!(
            weak_obj["weak"], "MD5",
            "weak row must serialize \"weak\":\"MD5\""
        );
        let strong_obj = arr
            .iter()
            .find(|o| o["path"] == "/usr/bin/strong")
            .expect("strong obj");
        assert!(
            strong_obj.as_object().expect("obj").get("weak").is_none(),
            "strong row must omit the \"weak\" key; got: {strong_obj}",
        );
    }

    /// The JSON key for the hash field must be `"digest"` (not `"sha256"`).
    /// The field holds any hash algorithm fapolicyd may record (MD5/SHA1/SHA256/SHA512).
    #[test]
    fn list_json_key_is_digest_not_sha256() {
        let rows = vec![ListRow {
            path: "/usr/bin/ls".to_owned(),
            source: TrustSource::RpmDb,
            size: 111,
            digest: "a".repeat(64),
            weak: None,
        }];
        let out = render_list(&rows, true);
        let v: serde_json::Value = serde_json::from_str(&out).expect("valid json");
        assert_eq!(v["kind"], serde_json::json!("trust-entries"));
        let obj = v["data"].as_array().expect("`data` array")[0]
            .as_object()
            .expect("object");
        assert!(
            obj.contains_key("digest"),
            "JSON key must be 'digest' (not 'sha256'); got keys: {:?}",
            obj.keys().collect::<Vec<_>>()
        );
        assert!(
            !obj.contains_key("sha256"),
            "JSON must NOT contain the old 'sha256' key; got keys: {:?}",
            obj.keys().collect::<Vec<_>>()
        );
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

    // -- #64: `trustdb list --format csv` renderer ----------------------------

    /// CSV list output has a stable header, one row per entry, the weak-hash
    /// algorithm in its own column (empty for strong digests), and a trailing
    /// newline. Columns are aggregate-free (one row per trust entry).
    #[test]
    fn list_csv_header_rows_and_weak_column() {
        let rows = vec![
            ListRow {
                path: "/usr/bin/ls".to_owned(),
                source: TrustSource::RpmDb,
                size: 111,
                digest: "a".repeat(64),
                weak: None,
            },
            ListRow {
                path: "/usr/bin/weak".to_owned(),
                source: TrustSource::FileDb,
                size: 10,
                digest: "b".repeat(32),
                weak: Some("MD5"),
            },
        ];
        let csv = render_csv_list(&rows);
        let strong_row = format!("rpm,111,{},/usr/bin/ls,", "a".repeat(64));
        let weak_row = format!("file,10,{},/usr/bin/weak,MD5", "b".repeat(32));
        let mut lines = csv.lines();
        assert_eq!(
            lines.next(),
            Some("source,size,digest,path,weak"),
            "stable header row"
        );
        assert_eq!(
            lines.next(),
            Some(strong_row.as_str()),
            "strong row: empty weak column"
        );
        assert_eq!(
            lines.next(),
            Some(weak_row.as_str()),
            "weak row: MD5 in the weak column"
        );
        assert_eq!(lines.next(), None, "exactly two data rows, no extras");
        assert!(csv.ends_with('\n'), "csv must end with a trailing newline");
    }

    /// A path containing a comma is RFC-4180 quoted (delegated to `to_csv`).
    #[test]
    fn list_csv_quotes_path_with_comma() {
        let rows = vec![ListRow {
            path: "/usr/bin/a,b".to_owned(),
            source: TrustSource::RpmDb,
            size: 1,
            digest: "c".repeat(64),
            weak: None,
        }];
        let csv = render_csv_list(&rows);
        assert!(
            csv.contains("\"/usr/bin/a,b\""),
            "a path with a comma must be quoted; got:\n{csv}"
        );
    }

    /// Empty input yields a header-only CSV with a trailing newline (no data rows).
    #[test]
    fn list_csv_empty_is_header_only() {
        assert_eq!(render_csv_list(&[]), "source,size,digest,path,weak\n");
    }
}
