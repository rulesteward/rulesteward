//! Lane A (auditd) differential-oracle replay test (session 9k-1, #584/#601/#489/#491).
//!
//! Tier 1 of the two-tier contract in `CONTRIBUTING.md` "Differential oracle
//! contract": pure Rust, reads a COMMITTED corpus of
//! `(rule-line, recorded-`auditctl -R`-verdict)` pairs and asserts
//! [`rulesteward_auditd::oracle::classify_rule_line`] agrees with the real
//! daemon's answer. No docker, no root, no network, no tool on PATH - so there
//! is no skip path at all. `just diff-auditd` (Tier 2, `scripts/rs-oracle-diff.sh`
//! -> `tests/corpus/auditd-oracle/capture_auditd.sh`) re-points this SAME binary
//! at a freshly captured corpus via `RS_ORACLE_CORPUS_AUDITD` to check for drift.
//!
//! # Required product API (frozen by THIS test; built by a later implementer)
//!
//! ```ignore
//! #[derive(Debug, Clone, Copy, PartialEq, Eq)]
//! pub enum Verdict { Accept, Reject }
//! pub fn classify_rule_line(line: &str) -> Verdict
//! ```
//!
//! The derives are load-bearing: this test compares, debug-prints, and clones
//! `Verdict` values (see [`Row`] and the mismatch-panic message below).
//!
//! `line` is one already comment-stripped, trimmed, single physical line from an
//! audit.rules file - exactly what a real `augenrules`-assembled
//! `/etc/audit/audit.rules` hands to `auditctl -R` for that line (comment-
//! stripping is `augenrules`'s job, not `auditctl -R`'s - see
//! `tools/oracle-images/README.md`). `classify_rule_line` must decide ACCEPT vs
//! REJECT the way the REAL `auditctl -R` parse gate does: tokenize by splitting
//! ONLY on the literal space byte (never tab; quotes and backslashes are literal
//! characters, NOT stripped - `audit_strsplit` semantics, per the images
//! README). This is deliberately NOT the same tokenizer as
//! [`rulesteward_auditd::parser`], which intentionally strips a token's
//! balanced leading+trailing single quote for admin-UX reasons (see
//! `parser.rs`'s `quote_strip_balanced_is_stripped` test) - that leniency is
//! exactly what makes several `existing`-class corpus rows in this file REJECT
//! for real `auditctl` while `rulesteward_auditd::parser` calls them syntactically
//! fine. `oracle::classify_rule_line` must NOT delegate to the lenient parser for
//! those rows; it needs its own literal-space, literal-quote tokenizer plus
//! enough value-level validation (permission letters, `-F` field names/operators,
//! numeric parsing per field, the 256-byte `-k` cap) to match real `auditctl`.
//!
//! # Corpus format
//!
//! Flat TSV, one file per target (`el8.tsv` / `el9.tsv` / `el10.tsv`) under the
//! resolved corpus root. Each data row is
//! `target\tid\tverdict\tclass\trule\tevidence`, split with `splitn(6, '\t')` so
//! `evidence` (last) never gets truncated by a stray tab. `rule` and `evidence`
//! use a 3-form backslash escape (`\\` -> `\`, `\t` -> TAB, `\x01` -> the 0x01
//! byte) because two corpus rows carry a literal TAB and one a literal 0x01 byte
//! in their rule text (see [`unescape_field`]); a raw tab there would otherwise
//! corrupt the column split. A `#`-prefixed header (4 lines) precedes the data
//! rows in every file, matching `tools/fapolicyd-probe-update`'s convention.
//! The second header line carries `audit_version=<rpm -q audit output>`, read
//! by [`assert_version_divergence_control`] below.
//!
//! # Provenance
//!
//! See `tests/corpus/auditd-oracle/PROVENANCE.md` for image versions, capture
//! date, the safety invariant, and the honest #530/#531 exclusion.

use std::path::{Path, PathBuf};

use rulesteward_auditd::oracle::{Verdict, classify_rule_line};
use rulesteward_core::oracle_corpus::{resolve_corpus_root, sentinel_banner, sentinel_count};

/// Named floor, derived from the corpus actually captured 2026-07-25 (33
/// `existing`-class scenarios re-grounded from `tests/corpus/auditd/*/audit.rules`
/// + 17 new `#584`/`#601`/`#489`/`#491` grounding scenarios + 2 positive-control
/// scenarios = 52 scenario ids, each captured against el8/el9/el10 = 156 rows).
/// Raise this deliberately, in the same commit, when the corpus grows.
const FLOOR_ROWS: usize = 156;

/// Floor on the number of DISTINCT scenario ids (one per corpus target file).
const FLOOR_SCENARIO_IDS: usize = 52;

/// The three target files every capture (committed or fresh) must produce.
const EXPECTED_TARGETS: &[&str] = &["el8", "el9", "el10"];

/// The two-sided positive control ids (CONTRIBUTING.md rule 2): a rule the real
/// oracle must ACCEPT and one it must REJECT, each with non-silent evidence, so
/// a broken harness that silently returns "reject" for everything (or "accept"
/// for everything) is caught as an ORACLE fault, not misread as product drift.
const CONTROL_ACCEPT_ID: &str = "control-accept";
const CONTROL_REJECT_ID: &str = "control-reject";

/// Product/oracle divergences, named with their issue number. EMPTY: every
/// scenario in this corpus is expected to be resolvable by a `classify_rule_line`
/// that faithfully reimplements `audit_strsplit` tokenization plus the field/
/// value validation this corpus grounds. (The genuinely kernel-only #530/#531
/// cases are EXCLUDED from the corpus entirely - see PROVENANCE.md - rather than
/// xfailed here, because the safe offline oracle can never reach them at all.)
/// Kept as a named, asserted-empty const so a real future finding has a place to
/// land without silently becoming a flaky test.
const XFAIL: &[(&str, &str)] = &[];

// ---------------------------------------------------------------------------
// Corpus model
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct Row {
    target: String,
    id: String,
    verdict: Verdict,
    class: String,
    rule: String,
    evidence: String,
}

/// Reverse [`capture_auditd.sh`'s] `esc_field`: `\\` -> `\`, `\t` -> TAB,
/// `\x01` -> the 0x01 byte. Order matters on the encode side (backslash first);
/// on decode we scan left-to-right and consume exactly one escape at a time, so
/// order is naturally handled. Panics on an unrecognized escape (fail-closed: a
/// corpus row we cannot faithfully decode must not be silently misread).
fn unescape_field(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            match bytes.get(i + 1) {
                Some(b'\\') => {
                    out.push('\\');
                    i += 2;
                }
                Some(b't') => {
                    out.push('\t');
                    i += 2;
                }
                Some(b'x')
                    if bytes.get(i + 2) == Some(&b'0') && bytes.get(i + 3) == Some(&b'1') =>
                {
                    out.push('\u{0001}');
                    i += 4;
                }
                other => panic!(
                    "unescape_field: unrecognized escape after backslash at byte {i} \
                     (next={other:?}) in {s:?}"
                ),
            }
        } else {
            // Safe: we only special-case the ASCII backslash byte above, so
            // stepping one byte at a time never splits a multi-byte UTF-8
            // sequence (none of our fields carry non-ASCII content).
            out.push(char::from(bytes[i]));
            i += 1;
        }
    }
    out
}

fn corpus_root() -> PathBuf {
    let default = PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/corpus/auditd-oracle"
    ));
    let (root, mode) = resolve_corpus_root("RS_ORACLE_CORPUS_AUDITD", &default);
    eprintln!("{}", sentinel_banner("RS-DIFF-AUDITD", mode, &root));
    root
}

/// Discover target files: every `*.tsv` in the corpus root whose name does not
/// start with `_`, sorted for determinism. Enumeration is filesystem-driven (not
/// a hardcoded scenario count) even though the SET of expected target names
/// ([`EXPECTED_TARGETS`]) is asserted below.
fn target_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let entries = std::fs::read_dir(root)
        .unwrap_or_else(|e| panic!("read corpus dir {}: {e}", root.display()));
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        if name.starts_with('_') || !name.ends_with(".tsv") {
            continue;
        }
        out.push(path);
    }
    out.sort();
    out
}

/// Parse one target TSV. Fails closed exactly like
/// `tools/fapolicyd-probe-update/src/transcript.rs`: empty/whitespace-only body,
/// no `#`-header anywhere, or a header with zero data rows are all errors, never
/// a silently empty `Vec`.
fn parse_target_tsv(path: &Path) -> (String, Vec<Row>) {
    let body =
        std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    if body.trim().is_empty() {
        panic!("{}: empty corpus file", path.display());
    }

    let mut audit_version: Option<String> = None;
    let mut saw_header = false;
    let mut rows = Vec::new();

    for (idx, line) in body.lines().enumerate() {
        let lineno = idx + 1;
        let trimmed = line.trim_start();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with('#') {
            saw_header = true;
            if let Some(pos) = trimmed.find("audit_version=") {
                let rest = &trimmed[pos + "audit_version=".len()..];
                let version = rest.split_whitespace().next().unwrap_or("");
                audit_version = Some(version.to_string());
            }
            continue;
        }

        let fields: Vec<&str> = line.splitn(6, '\t').collect();
        let [target, id, verdict_str, class, rule_raw, evidence_raw] = fields.as_slice() else {
            panic!(
                "{}:{lineno}: expected 6 tab-separated fields (target, id, verdict, class, \
                 rule, evidence), got {}",
                path.display(),
                fields.len()
            );
        };
        let verdict = match *verdict_str {
            "accept" => Verdict::Accept,
            "reject" => Verdict::Reject,
            other => panic!(
                "{}:{lineno}: unknown corpus verdict {other:?} (expected accept|reject)",
                path.display()
            ),
        };
        rows.push(Row {
            target: (*target).to_string(),
            id: (*id).to_string(),
            verdict,
            class: (*class).to_string(),
            rule: unescape_field(rule_raw),
            evidence: unescape_field(evidence_raw),
        });
    }

    if !saw_header {
        panic!(
            "{}: missing documentation header (no '#'-prefixed line; file may be truncated \
             from the top)",
            path.display()
        );
    }
    if rows.is_empty() {
        panic!(
            "{}: no data rows found (file may be truncated from the bottom, or is \
             comments-only)",
            path.display()
        );
    }

    let version = audit_version.unwrap_or_else(|| {
        panic!(
            "{}: header carries no 'audit_version=' token; the per-version positive control \
             cannot be evaluated",
            path.display()
        )
    });
    (version, rows)
}

// ---------------------------------------------------------------------------
// The oracle test
// ---------------------------------------------------------------------------

#[test]
fn auditd_oracle_corpus_matches_real_auditctl() {
    let root = corpus_root();

    let files = target_files(&root);
    let file_names: Vec<String> = files
        .iter()
        .map(|p| p.file_stem().unwrap().to_string_lossy().to_string())
        .collect();
    let mut sorted_names = file_names.clone();
    sorted_names.sort_unstable();
    let mut expected_sorted = EXPECTED_TARGETS.to_vec();
    expected_sorted.sort_unstable();
    assert_eq!(
        sorted_names,
        expected_sorted,
        "expected exactly the target files {EXPECTED_TARGETS:?} under {}, found {file_names:?}",
        root.display()
    );

    let mut all_rows: Vec<Row> = Vec::new();
    let mut versions: Vec<(String, String)> = Vec::new(); // (target-file-stem, audit_version)
    for path in &files {
        let stem = path.file_stem().unwrap().to_string_lossy().to_string();
        let (version, rows) = parse_target_tsv(path);
        versions.push((stem, version));
        all_rows.extend(rows);
    }

    // Rule 1 (CONTRIBUTING "Assert the count, do not merely print it"): print
    // BEFORE asserting, but the assertion is what carries the guarantee.
    eprintln!("{}", sentinel_count("RS-DIFF-AUDITD", all_rows.len()));
    assert!(
        all_rows.len() >= FLOOR_ROWS,
        "expected >= {FLOOR_ROWS} corpus rows across {EXPECTED_TARGETS:?}, got {}",
        all_rows.len()
    );

    let mut unique_ids: Vec<&str> = all_rows.iter().map(|r| r.id.as_str()).collect();
    unique_ids.sort_unstable();
    unique_ids.dedup();
    assert!(
        unique_ids.len() >= FLOOR_SCENARIO_IDS,
        "expected >= {FLOOR_SCENARIO_IDS} distinct scenario ids, got {}",
        unique_ids.len()
    );

    // ------------------------------------------------------------------
    // Version-divergence positive control (CONTRIBUTING: "Where an oracle is
    // captured per-version, add a control pinning a known version divergence:
    // it is the only thing that detects 'all three transcripts are secretly
    // the same file'"). Measured 2026-07-25 (tools/oracle-images/README.md):
    // no corpus scenario's ACCEPT/REJECT verdict differs across el8/el9/el10
    // audit-userspace 3.1.2/3.1.5/4.0.3, so the divergence this control pins is
    // the audit-userspace VERSION STRING itself, captured live at capture time
    // (not hardcoded from the README), rather than a rule-level behavior split.
    // ------------------------------------------------------------------
    assert_version_divergence_control(&versions);

    // ------------------------------------------------------------------
    // Two-sided positive control (CONTRIBUTING rule 2). Checked against the
    // CORPUS's own recorded verdict, independent of the product: if the
    // capture harness were broken (e.g. misclassifying every rule as the same
    // verdict), the oracle is broken, not the product, and the run must fail
    // rather than report clean or drift.
    // ------------------------------------------------------------------
    for (stem, _version) in &versions {
        let accept_row = all_rows
            .iter()
            .find(|r| r.target_file_stem_matches(stem) && r.id == CONTROL_ACCEPT_ID);
        let reject_row = all_rows
            .iter()
            .find(|r| r.target_file_stem_matches(stem) && r.id == CONTROL_REJECT_ID);
        let (Some(accept_row), Some(reject_row)) = (accept_row, reject_row) else {
            eprintln!(
                "RS-DIFF-AUDITD: ORACLE-BROKEN missing positive-control row(s) for target \
                 file '{stem}': accept={:?} reject={:?}",
                accept_row.map(|r| &r.id),
                reject_row.map(|r| &r.id)
            );
            panic!("positive control rows missing for target file '{stem}'");
        };
        if accept_row.verdict == reject_row.verdict {
            eprintln!(
                "RS-DIFF-AUDITD: ORACLE-BROKEN target='{stem}' control-accept and control-reject \
                 both recorded verdict={:?}; the capture harness cannot distinguish accept from \
                 reject, so neither a clean nor a drift verdict would be truthful",
                accept_row.verdict
            );
            panic!("two-sided positive control collapsed for target file '{stem}'");
        }
        assert_eq!(
            accept_row.verdict,
            Verdict::Accept,
            "control-accept row for '{stem}' must be recorded as accept in the corpus itself"
        );
        assert_eq!(
            reject_row.verdict,
            Verdict::Reject,
            "control-reject row for '{stem}' must be recorded as reject in the corpus itself"
        );
        assert!(
            !reject_row.evidence.is_empty(),
            "control-reject row for '{stem}' must carry NON-SILENT evidence (this is the \
             control that proves the harness truly parsed and rejected, not just went silent); \
             rule={:?}",
            reject_row.rule
        );
    }

    // ------------------------------------------------------------------
    // Product vs oracle: the actual comparison this whole file exists for.
    // ------------------------------------------------------------------
    let mut xfail_hit: Vec<(String, String)> = Vec::new();
    let mut compared = 0usize;
    for row in &all_rows {
        let got = classify_rule_line(&row.rule);
        if got == row.verdict {
            compared += 1;
            continue;
        }
        if XFAIL.iter().any(|(t, i)| *t == row.target && *i == row.id) {
            xfail_hit.push((row.target.clone(), row.id.clone()));
            compared += 1;
            continue;
        }
        panic!(
            "auditd oracle divergence: target={} id={} class={} rule={:?} corpus_verdict={:?} \
             classify_rule_line={:?} evidence={:?}",
            row.target, row.id, row.class, row.rule, row.verdict, got, row.evidence
        );
    }
    assert_eq!(
        compared,
        all_rows.len(),
        "every corpus row must be either matched or xfailed"
    );
    assert_eq!(
        xfail_hit.len(),
        XFAIL.len(),
        "every XFAIL entry must have been enumerated and actually hit; hit={xfail_hit:?} \
         declared={XFAIL:?} (an xfail that stops reproducing must fail the suite)"
    );
}

impl Row {
    /// `true` if this row's `target` column (the docker image tag, e.g.
    /// `rs-oracle8`) corresponds to the target FILE stem (`el8`) it was read
    /// from. Encoded as a small match rather than a shared table because the
    /// mapping is frozen (exactly 3 pairs) and a wrong pairing here would be
    /// silently self-consistent (never observed) rather than caught.
    fn target_file_stem_matches(&self, stem: &str) -> bool {
        matches!(
            (stem, self.target.as_str()),
            ("el8", "rs-oracle8") | ("el9", "rs-oracle9") | ("el10", "rs-oracle10")
        )
    }
}

/// Assert the 3 captured `audit_version=` strings are pairwise distinct. If a
/// base-image refresh ever collapses two of them, THIS is what detects "all
/// three transcripts are secretly the same file" per CONTRIBUTING.md.
fn assert_version_divergence_control(versions: &[(String, String)]) {
    assert_eq!(
        versions.len(),
        3,
        "expected exactly 3 (target, audit_version) pairs, got {versions:?}"
    );
    for i in 0..versions.len() {
        for j in (i + 1)..versions.len() {
            let (ti, vi) = &versions[i];
            let (tj, vj) = &versions[j];
            if vi == vj {
                eprintln!(
                    "RS-DIFF-AUDITD: ORACLE-BROKEN target='{ti}' and target='{tj}' both report \
                     audit_version={vi:?}; the per-version divergence control cannot confirm \
                     these are genuinely distinct captures"
                );
                panic!("version-divergence control collapsed between '{ti}' and '{tj}'");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Unit tests for this file's own escaping logic (test infrastructure, not the
// product under test - but a bug here would silently corrupt every comparison
// above, so it gets its own adversarial coverage).
// ---------------------------------------------------------------------------
#[cfg(test)]
mod unescape_tests {
    use super::unescape_field;

    #[test]
    fn plain_text_round_trips_unchanged() {
        assert_eq!(
            unescape_field("-w /etc/passwd -p wa -k q1"),
            "-w /etc/passwd -p wa -k q1"
        );
    }

    #[test]
    fn escaped_tab_becomes_a_real_tab() {
        assert_eq!(
            unescape_field(r"-w /etc/passwd\t-p wa -k q3"),
            "-w /etc/passwd\t-p wa -k q3"
        );
    }

    #[test]
    fn escaped_backslash_becomes_one_literal_backslash() {
        // Encoded form (as capture_auditd.sh's esc_field would write it) for the
        // real rule `-w /etc/my\ dir/file -p wa -k q2` (one literal backslash
        // before the space).
        assert_eq!(
            unescape_field(r"-w /etc/my\\ dir/file -p wa -k q2"),
            "-w /etc/my\\ dir/file -p wa -k q2"
        );
    }

    #[test]
    fn escaped_x01_becomes_the_soh_byte() {
        assert_eq!(
            unescape_field(r"-a always,exit -F arch=b64 -S execve -k key\x01withsep"),
            "-a always,exit -F arch=b64 -S execve -k key\u{0001}withsep"
        );
    }

    #[test]
    #[should_panic(expected = "unrecognized escape")]
    fn an_unknown_escape_is_rejected_fail_closed() {
        unescape_field(r"-w /etc/passwd\z-p wa");
    }
}
