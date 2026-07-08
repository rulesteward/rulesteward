//! The offline probe-transcript model and its two parsers.
//!
//! A [`Transcript`] is the flattened record of a probe run: two [`ProbeReply`]s
//! per candidate keyword (one [`ProbeKind::Opt`], one [`ProbeKind::Match`]). This
//! module is the `Command`-free offline core - it holds the JSONL reader used by
//! the offline `check --transcript` path and the TSV parser that
//! [`crate::probe`] feeds the raw docker stdout through. Keeping both parsers here
//! (rather than one in the docker seam) keeps the pure parsing logic testable.

use std::path::Path;

/// Which of the two per-keyword probes a reply came from.
///
/// `Opt` is `sshd -t -o KW=yes` (feeds E01 known + W04 deprecated); `Match` is a
/// non-activating `Match` block + `sshd -t -f` (feeds E04 Match-permitted).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeKind {
    /// `sshd -t -o KW=yes` - the option-validation probe.
    Opt,
    /// non-activating `Match` block + `sshd -t -f` - the Match-permitted probe.
    Match,
}

/// One flattened probe reply: the keyword, which probe produced it, the `sshd -t`
/// exit code, and the (one-line-flattened) stderr the daemon emitted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeReply {
    /// The probed `sshd_config` keyword, lowercase.
    pub kw: String,
    /// Which probe (`opt` / `match`) this reply is for.
    pub probe: ProbeKind,
    /// The `sshd -t` exit code.
    pub rc: i32,
    /// The daemon's stderr, flattened to a single line.
    pub stderr: String,
}

/// A full probe transcript: every reply from a single product's probe run.
pub type Transcript = Vec<ProbeReply>;

/// Parse `probe` string field into a [`ProbeKind`].
fn probe_kind(s: &str) -> Result<ProbeKind, String> {
    match s {
        "opt" => Ok(ProbeKind::Opt),
        "match" => Ok(ProbeKind::Match),
        other => Err(format!(
            "unknown probe kind {other:?} (expected \"opt\" or \"match\")"
        )),
    }
}

/// Read a JSONL probe transcript from `path`. Each non-blank line is one JSON
/// object `{"kw":..,"probe":"opt"|"match","rc":<int>,"stderr":..}`. Parsed with
/// `serde_json::Value` (no derive) so JSON escapes in `stderr` are handled
/// correctly. The 1-based line number is reported on any malformed line.
pub fn read_transcript(path: &Path) -> Result<Transcript, String> {
    let body =
        std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    parse_jsonl(&body).map_err(|e| format!("{}: {e}", path.display()))
}

/// Parse a JSONL probe transcript from an in-memory string (the testable core of
/// [`read_transcript`]).
pub fn parse_jsonl(body: &str) -> Result<Transcript, String> {
    let mut out = Transcript::new();
    for (i, line) in body.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let lineno = i + 1;
        let v: serde_json::Value = serde_json::from_str(line)
            .map_err(|e| format!("line {lineno}: not valid JSON: {e}"))?;
        let kw = v
            .get("kw")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| format!("line {lineno}: missing string field \"kw\""))?;
        let probe = v
            .get("probe")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| format!("line {lineno}: missing string field \"probe\""))?;
        let rc = v
            .get("rc")
            .and_then(serde_json::Value::as_i64)
            .ok_or_else(|| format!("line {lineno}: missing integer field \"rc\""))?;
        let stderr = v
            .get("stderr")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| format!("line {lineno}: missing string field \"stderr\""))?;
        out.push(ProbeReply {
            kw: kw.to_string(),
            probe: probe_kind(probe).map_err(|e| format!("line {lineno}: {e}"))?,
            rc: i32::try_from(rc)
                .map_err(|_| format!("line {lineno}: rc {rc} out of i32 range"))?,
            stderr: stderr.to_string(),
        });
    }
    Ok(out)
}

/// Parse the tab-separated stdout of the in-container probe script (see
/// `remote_probe.sh`) into a [`Transcript`]. Each line is exactly
/// `kw\tprobe\trc\tstderr` (stderr already flattened to one line, so it never
/// contains a tab or newline). Used only by [`crate::probe`] on live docker
/// output; kept here so the pure parse stays unit-testable.
pub fn parse_tsv(stdout: &str) -> Result<Transcript, String> {
    let mut out = Transcript::new();
    for (i, line) in stdout.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let lineno = i + 1;
        // splitn(4) so a stderr that (defensively) still holds a tab stays intact.
        let mut fields = line.splitn(4, '\t');
        let kw = fields
            .next()
            .ok_or_else(|| format!("line {lineno}: empty TSV record"))?;
        let probe = fields
            .next()
            .ok_or_else(|| format!("line {lineno}: missing probe-kind field"))?;
        let rc = fields
            .next()
            .ok_or_else(|| format!("line {lineno}: missing rc field"))?;
        // stderr may be absent (empty) -> default to "".
        let stderr = fields.next().unwrap_or("");
        out.push(ProbeReply {
            kw: kw.to_string(),
            probe: probe_kind(probe).map_err(|e| format!("line {lineno}: {e}"))?,
            rc: rc
                .parse::<i32>()
                .map_err(|_| format!("line {lineno}: bad rc {rc:?}"))?,
            stderr: stderr.to_string(),
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_jsonl_reads_both_kinds() {
        let body = "\
{\"kw\": \"acceptenv\", \"probe\": \"opt\", \"rc\": 0, \"stderr\": \"\"}
{\"kw\": \"acceptenv\", \"probe\": \"match\", \"rc\": 0, \"stderr\": \"\"}
";
        let t = parse_jsonl(body).expect("parse");
        assert_eq!(t.len(), 2);
        assert_eq!(t[0].kw, "acceptenv");
        assert_eq!(t[0].probe, ProbeKind::Opt);
        assert_eq!(t[1].probe, ProbeKind::Match);
    }

    /// stderr with a JSON-escaped double-quote must decode to a literal `"` - a
    /// naive split-on-quote parser would corrupt this. Grounded in the real
    /// fixtures (e.g. `unsupported option \"yes\"`).
    #[test]
    fn parse_jsonl_decodes_escaped_quotes() {
        let body = "{\"kw\": \"addressfamily\", \"probe\": \"opt\", \"rc\": 255, \"stderr\": \"command-line line 0: unsupported option \\\"yes\\\".\"}";
        let t = parse_jsonl(body).expect("parse");
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].rc, 255);
        assert_eq!(
            t[0].stderr,
            "command-line line 0: unsupported option \"yes\"."
        );
    }

    #[test]
    fn parse_jsonl_skips_blank_lines() {
        let body = "\n{\"kw\":\"x\",\"probe\":\"opt\",\"rc\":0,\"stderr\":\"\"}\n\n";
        assert_eq!(parse_jsonl(body).unwrap().len(), 1);
    }

    #[test]
    fn parse_jsonl_rejects_unknown_probe_kind() {
        let body = "{\"kw\":\"x\",\"probe\":\"weird\",\"rc\":0,\"stderr\":\"\"}";
        let e = parse_jsonl(body).unwrap_err();
        assert!(e.contains("line 1"), "err={e}");
        assert!(e.contains("unknown probe kind"), "err={e}");
    }

    #[test]
    fn parse_jsonl_reports_missing_field_with_lineno() {
        let body = "{\"kw\":\"a\",\"probe\":\"opt\",\"rc\":0,\"stderr\":\"\"}\n{\"kw\":\"b\",\"probe\":\"opt\",\"stderr\":\"\"}";
        let e = parse_jsonl(body).unwrap_err();
        assert!(e.contains("line 2"), "err={e}");
        assert!(e.contains("rc"), "err={e}");
    }

    #[test]
    fn parse_jsonl_rejects_non_json() {
        assert!(parse_jsonl("not json at all").is_err());
    }

    #[test]
    fn parse_tsv_reads_records() {
        let stdout = "acceptenv\topt\t0\t\nacceptenv\tmatch\t0\t\nx\topt\t255\tBad configuration option: x\n";
        let t = parse_tsv(stdout).expect("parse");
        assert_eq!(t.len(), 3);
        assert_eq!(t[2].kw, "x");
        assert_eq!(t[2].probe, ProbeKind::Opt);
        assert_eq!(t[2].rc, 255);
        assert_eq!(t[2].stderr, "Bad configuration option: x");
    }

    #[test]
    fn parse_tsv_rejects_bad_rc() {
        assert!(parse_tsv("x\topt\tNOTANUM\t").is_err());
    }

    /// A parse error must name the correct 1-based line number. Line 1 is valid
    /// and line 2 is malformed (a single token, no tabs -> missing probe field),
    /// so the error must say `line 2` - this pins `lineno = i + 1` (a `i * 1`
    /// mutation would misreport `line 1`).
    #[test]
    fn parse_tsv_error_reports_1_based_line_number() {
        let stdout = "kw\topt\t0\t\nmalformed_second_line_no_tabs";
        let e = parse_tsv(stdout).unwrap_err();
        assert!(e.contains("line 2"), "expected 1-based line 2 in: {e}");
    }
}
