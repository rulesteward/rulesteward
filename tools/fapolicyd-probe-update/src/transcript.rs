//! The offline probe-transcript model and its TSV parser.
//!
//! A [`Transcript`] is the flattened record of one probe run for ONE (target,
//! dataset) pair - e.g. `tests/fixtures/fapolicyd8-pattern.tsv` holds the `pattern`
//! dataset probed against the rhel8 image. Each data row is
//! `dataset\tid\tverdict\tloaded_n\tevidence` (5 tab-separated fields; see the
//! `#`-commented documentation header committed at the top of every fixture file,
//! e.g. `tests/fixtures/fapolicyd8-pattern.tsv` lines 1-22). Lines that are blank, or
//! whose first non-whitespace character is `#`, are documentation comments, not data.

use std::path::Path;

/// One row's verdict.
///
/// `Ok` is the informational `version` dataset's only verdict (not accept/reject -
/// see `tests/fixtures/fapolicyd8-version.tsv` lines 1-10); `Accept`/`Reject` are the
/// daemon-load parse-gate outcomes for the `pattern` and `e07` datasets (ACCEPT iff a
/// `Loaded N rules` line appears with no preceding `ERROR` line; REJECT otherwise -
/// `tests/fixtures/fapolicyd8-pattern.tsv` lines 11-14).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Ok,
    Accept,
    Reject,
}

/// One flattened probe row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeRow {
    /// The dataset this row belongs to: `"version"` | `"pattern"` | `"e07"`.
    pub dataset: String,
    /// The probed id: `"rpm_q"` (version), a candidate `pattern=` value (pattern), or
    /// an `<attr>_<shape>` id, e.g. `"pid_signed_negfirst"` (e07).
    pub id: String,
    pub verdict: Verdict,
    /// The `Loaded N rules` count, or `None` for the informational `version` row
    /// (whose `loaded_n` column is the empty string in every fixture).
    pub loaded_n: Option<u32>,
    /// The flattened (tab/newline -> single-space) combined daemon stdout+stderr, or
    /// (for `version`) the raw `rpm -q fapolicyd` output.
    pub evidence: String,
}

/// A full probe transcript: every row from one (target, dataset) fixture file.
pub type Transcript = Vec<ProbeRow>;

/// Read a fapolicyd probe TSV transcript from `path`.
///
/// # Errors
/// Returns a readable error, naming `path`, if the file cannot be read or
/// [`parse_tsv`] rejects its contents.
pub fn read_transcript(path: &Path) -> Result<Transcript, String> {
    let body =
        std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    parse_tsv(&body).map_err(|e| format!("{}: {e}", path.display()))
}

/// Parse the fapolicyd probe TSV format from an in-memory string (the testable core
/// of [`read_transcript`]). See the module doc for the row shape.
///
/// # Frozen contract (see `tests` below for the pinning cases)
/// - A line is a comment iff, after trimming leading whitespace, its first character
///   is `#`. A blank (whitespace-only) line is skipped without being treated as data.
/// - Every remaining line is a data row: exactly 5 tab-separated fields
///   (`dataset`, `id`, `verdict`, `loaded_n`, `evidence`), split with `splitn(5, '\t')`
///   so a defensively-tab-containing `evidence` field never gets truncated.
/// - `dataset` must be one of `"version"` | `"pattern"` | `"e07"`.
/// - `id` must be non-empty.
/// - `verdict` must be one of `"ok"` | `"accept"` | `"reject"` (parsed into
///   [`Verdict`]).
/// - `loaded_n`: the empty string parses to `None`; any other value must parse as a
///   `u32` or the row is rejected.
/// - `evidence` may be empty.
/// - A malformed row's error names the offending 1-based line number.
///
/// # Fails CLOSED (never returns an empty `Ok` for a broken input)
/// - An empty or whitespace-only body is an error.
/// - A body with no `#`-prefixed line anywhere (no documentation header - a
///   plausible symptom of a fixture truncated from the top) is an error.
/// - A body with a header but zero data rows (truncated from the bottom, or a
///   comments-only file) is an error.
///
/// # Errors
/// See "Frozen contract" and "Fails CLOSED" above.
pub fn parse_tsv(body: &str) -> Result<Transcript, String> {
    if body.trim().is_empty() {
        return Err("empty probe transcript body".to_string());
    }

    let mut rows = Vec::new();
    let mut saw_header = false;

    for (idx, line) in body.lines().enumerate() {
        let line_no = idx + 1;
        let trimmed = line.trim_start();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with('#') {
            saw_header = true;
            continue;
        }

        let fields: Vec<&str> = line.splitn(5, '\t').collect();
        let [dataset, id, verdict_str, loaded_n_str, evidence] = fields.as_slice() else {
            return Err(format!(
                "line {line_no}: expected 5 tab-separated fields (dataset, id, verdict, \
                 loaded_n, evidence), got {}",
                fields.len()
            ));
        };

        if !matches!(*dataset, "version" | "pattern" | "e07") {
            return Err(format!(
                "line {line_no}: unknown dataset {dataset:?} (expected version|pattern|e07)"
            ));
        }
        if id.is_empty() {
            return Err(format!("line {line_no}: id must not be empty"));
        }
        let verdict = match *verdict_str {
            "ok" => Verdict::Ok,
            "accept" => Verdict::Accept,
            "reject" => Verdict::Reject,
            other => {
                return Err(format!(
                    "line {line_no}: unknown verdict {other:?} (expected ok|accept|reject)"
                ));
            }
        };
        let loaded_n = if loaded_n_str.is_empty() {
            None
        } else {
            Some(loaded_n_str.parse::<u32>().map_err(|e| {
                format!("line {line_no}: loaded_n {loaded_n_str:?} is not a valid u32: {e}")
            })?)
        };

        rows.push(ProbeRow {
            dataset: (*dataset).to_string(),
            id: (*id).to_string(),
            verdict,
            loaded_n,
            evidence: (*evidence).to_string(),
        });
    }

    if !saw_header {
        return Err(
            "missing documentation header (no '#'-prefixed line found; the fixture may be \
             truncated from the top)"
                .to_string(),
        );
    }
    if rows.is_empty() {
        return Err(
            "no data rows found (the fixture may be truncated from the bottom, or is \
             comments-only)"
                .to_string(),
        );
    }

    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    const RHEL8_VERSION: &str = include_str!("../tests/fixtures/fapolicyd8-version.tsv");
    const RHEL9_VERSION: &str = include_str!("../tests/fixtures/fapolicyd9-version.tsv");
    const RHEL10_VERSION: &str = include_str!("../tests/fixtures/fapolicyd10-version.tsv");
    const RHEL8_PATTERN: &str = include_str!("../tests/fixtures/fapolicyd8-pattern.tsv");
    const RHEL9_PATTERN: &str = include_str!("../tests/fixtures/fapolicyd9-pattern.tsv");
    const RHEL10_PATTERN: &str = include_str!("../tests/fixtures/fapolicyd10-pattern.tsv");
    const RHEL8_E07: &str = include_str!("../tests/fixtures/fapolicyd8-e07.tsv");
    const RHEL9_E07: &str = include_str!("../tests/fixtures/fapolicyd9-e07.tsv");
    const RHEL10_E07: &str = include_str!("../tests/fixtures/fapolicyd10-e07.tsv");

    // -----------------------------------------------------------------------
    // TSV parser known-answer: every committed fixture, structural shape.
    // A wrong impl that (e.g.) drops the last row, mis-splits on the first tab
    // instead of using splitn(5, ..), or fails to skip the `#` header is caught by
    // asserting the EXACT row count and spot-checking first/last rows per file.
    // -----------------------------------------------------------------------

    /// Source: `tests/fixtures/fapolicyd8-version.tsv` line 11, itself sourced from
    /// `rpm -q fapolicyd` inside the `fapolicyd8` container (drift-findings.md
    /// dataset (a) table: fapolicyd8 -> `fapolicyd-1.3.2-1.el8.x86_64`).
    #[test]
    fn parse_rhel8_version_fixture_yields_one_row() {
        let t = parse_tsv(RHEL8_VERSION).expect("parse");
        assert_eq!(t.len(), 1, "the version dataset carries exactly one row");
        assert_eq!(t[0].dataset, "version");
        assert_eq!(t[0].id, "rpm_q");
        assert_eq!(t[0].verdict, Verdict::Ok);
        assert_eq!(
            t[0].loaded_n, None,
            "the version row's loaded_n column is empty"
        );
        assert_eq!(t[0].evidence, "fapolicyd-1.3.2-1.el8.x86_64");
    }

    /// Source: `tests/fixtures/fapolicyd9-version.tsv` line 11
    /// (`fapolicyd-1.4.5-1.1.el9_8.x86_64`).
    #[test]
    fn parse_rhel9_version_fixture_yields_one_row() {
        let t = parse_tsv(RHEL9_VERSION).expect("parse");
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].evidence, "fapolicyd-1.4.5-1.1.el9_8.x86_64");
    }

    /// Source: `tests/fixtures/fapolicyd10-version.tsv` line 11
    /// (`fapolicyd-1.4.5-1.2.el10_2.x86_64`).
    #[test]
    fn parse_rhel10_version_fixture_yields_one_row() {
        let t = parse_tsv(RHEL10_VERSION).expect("parse");
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].evidence, "fapolicyd-1.4.5-1.2.el10_2.x86_64");
    }

    /// Source: `tests/fixtures/fapolicyd8-pattern.tsv` lines 23-27 (5 candidates:
    /// normal, ld_so, ld_preload, static, the bogus sentinel).
    #[test]
    fn parse_rhel8_pattern_fixture_yields_five_rows_with_rhel8_verdicts() {
        let t = parse_tsv(RHEL8_PATTERN).expect("parse");
        assert_eq!(t.len(), 5);
        let by_id = |id: &str| t.iter().find(|r| r.id == id).unwrap();
        // rhel8 (1.3.2): `normal` REJECTED (introduced only in 1.4.x).
        assert_eq!(by_id("normal").verdict, Verdict::Reject);
        assert_eq!(by_id("normal").loaded_n, Some(0));
        assert_eq!(by_id("ld_so").verdict, Verdict::Accept);
        assert_eq!(by_id("ld_so").loaded_n, Some(1));
        assert_eq!(by_id("ld_preload").verdict, Verdict::Accept);
        assert_eq!(by_id("static").verdict, Verdict::Accept);
        assert_eq!(
            by_id("zzzz_rulesteward_probe_bogus").verdict,
            Verdict::Reject
        );
        assert!(t.iter().all(|r| r.dataset == "pattern"));
    }

    /// Source: `tests/fixtures/fapolicyd9-pattern.tsv` lines 23-27. rhel9 (1.4.5)
    /// accepts `normal` too (the 1.4.x-added value), unlike rhel8.
    #[test]
    fn parse_rhel9_pattern_fixture_accepts_normal_unlike_rhel8() {
        let t = parse_tsv(RHEL9_PATTERN).expect("parse");
        assert_eq!(t.len(), 5);
        let by_id = |id: &str| t.iter().find(|r| r.id == id).unwrap();
        assert_eq!(
            by_id("normal").verdict,
            Verdict::Accept,
            "normal is accepted on 1.4.x, unlike rhel8's 1.3.2"
        );
        assert_eq!(by_id("ld_so").verdict, Verdict::Accept);
        assert_eq!(by_id("ld_preload").verdict, Verdict::Accept);
        assert_eq!(by_id("static").verdict, Verdict::Accept);
        assert_eq!(
            by_id("zzzz_rulesteward_probe_bogus").verdict,
            Verdict::Reject
        );
    }

    /// Source: `tests/fixtures/fapolicyd10-pattern.tsv` lines 23-27. rhel10 shares
    /// 1.4.5 with rhel9 (RHEL 9.8 rebased 1.4.3 -> 1.4.5), so the same 4 values
    /// accept.
    #[test]
    fn parse_rhel10_pattern_fixture_matches_rhel9_shape() {
        let t = parse_tsv(RHEL10_PATTERN).expect("parse");
        assert_eq!(t.len(), 5);
        let by_id = |id: &str| t.iter().find(|r| r.id == id).unwrap();
        assert_eq!(by_id("normal").verdict, Verdict::Accept);
        assert_eq!(
            by_id("zzzz_rulesteward_probe_bogus").verdict,
            Verdict::Reject
        );
    }

    /// Source: `tests/fixtures/fapolicyd8-e07.tsv` lines 30-52 (23 probes across 11
    /// attributes). rhel8: pid/ppid type UNSIGNED (accept plain int, reject
    /// negative-first and string sets); gid types PERMISSIVE (accepts str/int/mixed).
    #[test]
    fn parse_rhel8_e07_fixture_yields_23_rows_with_rhel8_divergence() {
        let t = parse_tsv(RHEL8_E07).expect("parse");
        assert_eq!(t.len(), 23, "11 attrs x their tested shapes = 23 rows");
        assert!(t.iter().all(|r| r.dataset == "e07"));
        let by_id = |id: &str| t.iter().find(|r| r.id == id).unwrap();
        // Unsigned invariant (uid/auid/sessionid): int accepts, str rejects.
        for attr in ["uid", "auid", "sessionid"] {
            assert_eq!(by_id(&format!("{attr}_int")).verdict, Verdict::Accept);
            assert_eq!(by_id(&format!("{attr}_str")).verdict, Verdict::Reject);
        }
        // pid/ppid on rhel8 (1.3.2): Unsigned, NOT Signed.
        for attr in ["pid", "ppid"] {
            assert_eq!(
                by_id(&format!("{attr}_int")).verdict,
                Verdict::Accept,
                "{attr}_int must ACCEPT on rhel8 (Unsigned)"
            );
            assert_eq!(
                by_id(&format!("{attr}_signed_negfirst")).verdict,
                Verdict::Reject,
                "{attr}_signed_negfirst must REJECT on rhel8 (not yet Signed)"
            );
            assert_eq!(by_id(&format!("{attr}_str")).verdict, Verdict::Reject);
        }
        // gid on rhel8 (1.3.2): Permissive - str/int/mixed all accept.
        assert_eq!(by_id("gid_str").verdict, Verdict::Accept);
        assert_eq!(by_id("gid_int").verdict, Verdict::Accept);
        assert_eq!(by_id("gid_mixed").verdict, Verdict::Accept);
        // Str invariant (exe subject; path/mode object): str accepts, int rejects.
        for attr in ["exe", "path", "mode"] {
            assert_eq!(by_id(&format!("{attr}_str")).verdict, Verdict::Accept);
            assert_eq!(by_id(&format!("{attr}_int")).verdict, Verdict::Reject);
        }
        // NoSet invariant: pattern/trust always reject a %set.
        assert_eq!(by_id("pattern_set").verdict, Verdict::Reject);
        assert_eq!(by_id("trust_set").verdict, Verdict::Reject);
    }

    /// Source: `tests/fixtures/fapolicyd9-e07.tsv` lines 30-52. rhel9 (1.4.5): pid/
    /// ppid flip to SIGNED (reject plain int, accept negative-first); gid flips to
    /// UNSIGNED (reject str/mixed, still accept int) - the two version-divergent
    /// categories documented in `crates/rulesteward-fapolicyd/src/attrs.rs`.
    #[test]
    fn parse_rhel9_e07_fixture_flips_pid_ppid_and_gid_categories() {
        let t = parse_tsv(RHEL9_E07).expect("parse");
        assert_eq!(t.len(), 23);
        let by_id = |id: &str| t.iter().find(|r| r.id == id).unwrap();
        for attr in ["pid", "ppid"] {
            assert_eq!(
                by_id(&format!("{attr}_int")).verdict,
                Verdict::Reject,
                "{attr}_int must REJECT on rhel9 (a plain positive-int set types \
                 UNSIGNED, not SIGNED)"
            );
            assert_eq!(
                by_id(&format!("{attr}_signed_negfirst")).verdict,
                Verdict::Accept,
                "{attr}_signed_negfirst must ACCEPT on rhel9 (Signed)"
            );
            assert_eq!(by_id(&format!("{attr}_str")).verdict, Verdict::Reject);
        }
        assert_eq!(
            by_id("gid_str").verdict,
            Verdict::Reject,
            "gid_str must REJECT on rhel9 (Unsigned, not Permissive)"
        );
        assert_eq!(by_id("gid_int").verdict, Verdict::Accept);
        assert_eq!(by_id("gid_mixed").verdict, Verdict::Reject);
    }

    /// Source: `tests/fixtures/fapolicyd10-e07.tsv` lines 30-52. rhel10 shares
    /// 1.4.5 with rhel9 - same divergent shape as the rhel9 fixture (only the
    /// `Cannot change to uid NNN` teardown-line UID differs, which is not asserted).
    #[test]
    fn parse_rhel10_e07_fixture_matches_rhel9_shape() {
        let t = parse_tsv(RHEL10_E07).expect("parse");
        assert_eq!(t.len(), 23);
        let by_id = |id: &str| t.iter().find(|r| r.id == id).unwrap();
        assert_eq!(by_id("pid_int").verdict, Verdict::Reject);
        assert_eq!(by_id("pid_signed_negfirst").verdict, Verdict::Accept);
        assert_eq!(by_id("gid_str").verdict, Verdict::Reject);
        assert_eq!(by_id("gid_int").verdict, Verdict::Accept);
    }

    // -----------------------------------------------------------------------
    // Comment / blank-line skipping.
    // -----------------------------------------------------------------------

    #[test]
    fn parse_skips_hash_comment_and_blank_lines() {
        let body = "# a doc header line\n\n  \nversion\trpm_q\tok\t\tfapolicyd-9.9.9\n";
        let t = parse_tsv(body).expect("parse");
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].evidence, "fapolicyd-9.9.9");
    }

    #[test]
    fn parse_treats_indented_hash_as_a_comment_too() {
        // A `#` after leading whitespace must still count as a comment line, not a
        // malformed data row.
        let body = "  # indented comment\nversion\trpm_q\tok\t\tfapolicyd-9.9.9\n";
        let t = parse_tsv(body).expect("parse");
        assert_eq!(t.len(), 1);
    }

    // -----------------------------------------------------------------------
    // Fail CLOSED: empty / missing-header / no-data-rows / malformed rows.
    // -----------------------------------------------------------------------

    #[test]
    fn parse_empty_body_is_an_error() {
        let e = parse_tsv("").unwrap_err();
        assert!(e.contains("empty"), "err={e}");
    }

    #[test]
    fn parse_whitespace_only_body_is_an_error() {
        let e = parse_tsv("   \n\n\t\n  ").unwrap_err();
        assert!(e.contains("empty"), "err={e}");
    }

    /// A body with data rows but NO `#`-prefixed documentation header line at all -
    /// a plausible symptom of a fixture truncated from the top (the header block
    /// stripped, only the data surviving). Must fail closed, not silently accept.
    #[test]
    fn parse_body_with_no_header_comment_is_an_error() {
        let body = "version\trpm_q\tok\t\tfapolicyd-9.9.9\n";
        let e = parse_tsv(body).unwrap_err();
        assert!(e.contains("header"), "err={e}");
    }

    /// A body with ONLY the documentation header and zero data rows - a plausible
    /// symptom of a fixture truncated from the bottom. Must fail closed (never
    /// silently succeed with an empty `Transcript`).
    #[test]
    fn parse_header_only_body_with_zero_data_rows_is_an_error() {
        let body = "# fapolicyd probe transcript - dataset: version\n# more header\n";
        let e = parse_tsv(body).unwrap_err();
        assert!(
            e.contains("no data") || e.contains("truncated") || e.contains("empty"),
            "err={e}"
        );
    }

    #[test]
    fn parse_row_with_too_few_fields_is_an_error_naming_the_line() {
        let body = "# header\nversion\trpm_q\tok\n";
        let e = parse_tsv(body).unwrap_err();
        assert!(e.contains("line 2"), "err={e}");
    }

    #[test]
    fn parse_row_with_unknown_verdict_is_an_error_naming_the_line() {
        let body = "# header\npattern\tld_so\tmaybe\t1\tsome evidence\n";
        let e = parse_tsv(body).unwrap_err();
        assert!(e.contains("line 2"), "err={e}");
        assert!(e.contains("verdict"), "err={e}");
    }

    #[test]
    fn parse_row_with_non_numeric_loaded_n_is_an_error_naming_the_line() {
        let body = "# header\npattern\tld_so\taccept\tNOTANUM\tsome evidence\n";
        let e = parse_tsv(body).unwrap_err();
        assert!(e.contains("line 2"), "err={e}");
    }

    #[test]
    fn parse_row_with_unknown_dataset_is_an_error() {
        let body = "# header\nbogus_dataset\tid1\tok\t\tsome evidence\n";
        let e = parse_tsv(body).unwrap_err();
        assert!(e.contains("dataset"), "err={e}");
    }

    /// A parse error must report the correct 1-BASED line number counting from the
    /// start of the file (comment lines included in the count, since that is what a
    /// human editor's line numbering shows). Line 1 is a comment, line 2 is a good
    /// data row, line 3 is malformed - the error must say "line 3", not "line 2"
    /// (which would indicate an off-by-one against the comment line, e.g. counting
    /// only data rows) and not "line 1".
    #[test]
    fn parse_error_line_number_counts_from_file_start_including_comments() {
        let body = "# header\nversion\trpm_q\tok\t\tfapolicyd-9.9.9\npattern\tld_so\n";
        let e = parse_tsv(body).unwrap_err();
        assert!(e.contains("line 3"), "expected line 3 in: {e}");
    }
}
