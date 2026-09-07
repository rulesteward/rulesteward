//! The pipeline. Pure: bytes in, bytes and diagnostics out.

use super::emit;
use super::model::{self, Diagnostic, Record, Suggestion};
use super::parse::{self, MAX_PAYLOAD};
use super::policy::{self, Decision};

/// `parse_syslog_format` stops after 21 names and still returns success, so names past
/// the cap are never compared against anything (DESIGN.md §4).
const MAX_SYSLOG_FIELDS: usize = 21;

#[derive(Debug, Default)]
pub struct Outcome {
    pub stdout: Vec<u8>,
    pub diagnostics: Vec<Diagnostic>,
    /// §9's exit 2: we read the input but could not make sense of any of it.
    pub consumed_but_unparseable: bool,
}

/// One pass over the input, one record per line.
///
/// The order of the per-line steps is part of the contract. Each step earns its place:
///
/// 1. `#` and empty are tested on the RAW line, BEFORE the framing prefix is stripped.
///    A commented-out example carries a `]: ` of its own, so stripping first turns a
///    comment into live input — which is how a trust entry once came out of a
///    `# record: ...` line in the research capture.
/// 2. strip the framing prefix, because the 511-byte cap applies to the payload.
/// 3. drop the once-per-daemon-start deprecation notice.
/// 4. parse.
/// 5. no fields at all is prose, not a record: it counts as content but not as parsed,
///    which is exactly what §9's exit 2 is measuring.
/// 6. corruption BEFORE the denial filter. A corrupted record's names are freed memory
///    but its values survive, so it reads as `dec=no-opinion` and the filter would drop
///    it — reporting silence from a daemon that is allowing everything.
/// 7. the denial filter, from the parsed subject side.
/// 8. truncation, which decides whether the record may be acted on at all.
/// 9. the policy decision, then emission and deduplication.
pub fn analyze(input: &[u8], syslog_format: Option<&[String]>) -> Outcome {
    let mut out = Outcome::default();

    if let Some(fields) = syslog_format {
        // `format_value`'s uid/gid branch dereferences `subj` with no NULL check on
        // Rocky 9/10, which is a SIGSEGV; on Rocky 8 an empty gid set leaves the buffer
        // unterminated, so the field carries heap bytes that can include a space and
        // break field splitting. Either way the host is misconfigured and we say so.
        for f in fields
            .iter()
            .filter(|f| matches!(f.as_str(), "uid" | "gid"))
        {
            out.diagnostics.push(Diagnostic {
                line: None,
                msg: format!(
                    "syslog_format names {f}=; the daemon's uid/gid formatter can segfault \
                     on Rocky 9/10 and emits unterminated heap bytes on Rocky 8 (research \
                     syslog-format.md:66-96); remove it from the host config"
                ),
            });
        }
    }

    let mut content = 0usize;
    let mut parsed = 0usize;
    let mut corrupt = 0usize;
    // Deduplication is on the whole suggestion (D12). `TrustFile` equality is path
    // equality, because one user action emits both a perm=execute and a perm=open
    // record and one trust entry covers both perms. `Rule` equality is
    // `(perm, exe, path)`, because those same two records need two rules: they can
    // match different rules and the emitted rule depends on the perm.
    let mut seen: Vec<Suggestion> = Vec::new();
    let mut rules_emitted = false;

    for (i, raw) in input.split(|&b| b == b'\n').enumerate() {
        let line = Some(i + 1);
        // Leading whitespace and all: the research captures indent their commented-out
        // example records, and an indented comment is still a comment.
        let trimmed = raw.trim_ascii_start();
        if trimmed.is_empty() || trimmed.starts_with(b"#") {
            continue;
        }

        let payload = parse::strip_prefix(raw);
        if parse::is_noise(payload) {
            continue;
        }
        content += 1;

        let record = parse::parse(payload);
        let names: Vec<&[u8]> = record
            .subject
            .iter()
            .chain(record.object.iter().flatten())
            .map(|(k, _)| k.as_slice())
            .collect();
        if names.is_empty() {
            continue;
        }
        parsed += 1;

        if names.iter().any(|n| parse::is_corrupt_field_name(n)) {
            corrupt += 1;
            continue;
        }

        if !parse::is_denial(&record) {
            continue;
        }

        if let Some(msg) = truncated(&record, syslog_format, payload.len()) {
            out.diagnostics.push(Diagnostic { line, msg });
            continue;
        }

        match policy::decide(&record) {
            Decision::Emit { suggestion, note } => {
                if let Some(msg) = note {
                    out.diagnostics.push(Diagnostic { line, msg });
                }
                if seen.contains(&suggestion) {
                    continue;
                }
                rules_emitted |= matches!(suggestion, Suggestion::Rule { .. });
                out.stdout.extend_from_slice(&emit::render(&suggestion));
                seen.push(suggestion);
            }
            Decision::Explain(msg) => out.diagnostics.push(Diagnostic { line, msg }),
        }
    }

    if corrupt > 0 {
        out.diagnostics.push(Diagnostic {
            line: None,
            msg: format!(
                "{corrupt} records have unreadable field names: the daemon failed a rules \
                 reload and is now running with NO rules, allowing everything. Restart it. \
                 Nothing below can be trusted as a denial record"
            ),
        });
    }

    // D12: these warnings belong to the run, not to a line, and each describes a way a
    // rule silently does nothing on a real host.
    if rules_emitted {
        out.diagnostics.push(Diagnostic {
            line: None,
            msg: "a rule placed in /etc/fapolicyd/rules.d/ has no effect on a host that \
                  still has a legacy /etc/fapolicyd/fapolicyd.rules, and the daemon logs \
                  nothing about it; check which file the daemon loads before adding the \
                  rule"
                .into(),
        });
        out.diagnostics.push(Diagnostic {
            line: None,
            msg: "validate the rules file before reloading and check the daemon \
                  afterwards: fapolicyd-cli --reload-rules exits 0 even when the reload \
                  crashed the daemon or left it allowing everything"
                .into(),
        });
        out.diagnostics.push(Diagnostic {
            line: None,
            msg: "the file must sort before the file holding the rule that denied: rules.d/ \
                  is merged in filename order and the first match wins, so a rule at 50- \
                  never reaches a denial from 30-patterns.rules; rule=N in the record is \
                  that rule's position in compiled.rules with %set lines dropped, and \
                  fagenrules --check shows the merged order"
                .into(),
        });
    }

    out.diagnostics = collapse(out.diagnostics);

    // §9's exit 2 is "input consumed but unparseable" — not "no denials found". A log
    // full of allow records is a successful run with nothing to suggest.
    out.consumed_but_unparseable = content > 0 && parsed == 0;
    out
}

/// Steps 3 and 4 of DESIGN.md §6's ladder. `Some(reason)` means do not emit.
///
/// Step 3, with a format in hand: a name in `syslog_format` that the record does not
/// carry means the daemon ran out of buffer partway through. Only the first 21 names
/// are compared, because `parse_syslog_format` silently stops there. Splitting that
/// slice on `:` is what keeps the sides apart; if the `:` fell past the cap the record
/// is subject-side only by construction, so the object side is not examined at all.
/// Duplicate names are a presence test either way, so they need no special handling.
///
/// Step 4, the 511-byte cap, runs ONLY without a format. It has the false negative
/// §2 describes — a record that happens to end short of the cap looks whole — so it is
/// the fallback, never a cross-check on step 3.
fn truncated(
    record: &Record,
    syslog_format: Option<&[String]>,
    payload_len: usize,
) -> Option<String> {
    let missing = |field: &str| {
        format!(
            "record truncated: syslog_format names {field}= but the record lacks it; \
             emitting nothing, because path= may be a prefix of the real path"
        )
    };

    let Some(names) = syslog_format else {
        return (payload_len >= MAX_PAYLOAD).then(|| {
            format!(
                "record truncated at the {MAX_PAYLOAD}-byte cap; emitting nothing, \
                 because path= is a prefix of the real path"
            )
        });
    };

    let names = &names[..names.len().min(MAX_SYSLOG_FIELDS)];
    let (subject, object) = match names.iter().position(|n| n == ":") {
        Some(i) => (&names[..i], &names[i + 1..]),
        None => (names, &names[names.len()..]),
    };

    if let Some(f) = subject
        .iter()
        .find(|f| model::get(&record.subject, f.as_bytes()).is_none())
    {
        return Some(missing(f));
    }

    let first_object = object.first()?;
    let Some(side) = record.object.as_ref() else {
        return Some(missing(first_object));
    };
    object
        .iter()
        .find(|f| model::get(side, f.as_bytes()).is_none())
        .map(|f| missing(f))
}

/// D11. A real log repeats the same sentence thousands of times; one line with a count
/// says the same thing. The first line number wins, because that is the one worth
/// opening the log at.
fn collapse(diagnostics: Vec<Diagnostic>) -> Vec<Diagnostic> {
    let mut out: Vec<(Diagnostic, usize)> = Vec::new();
    for d in diagnostics {
        match out.iter_mut().find(|(kept, _)| kept.msg == d.msg) {
            Some((_, n)) => *n += 1,
            None => out.push((d, 1)),
        }
    }
    out.into_iter()
        .map(|(mut d, n)| {
            if n > 1 {
                d.msg = format!("{} (x{n})", d.msg);
            }
            d
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEFAULT_FORMAT: &str = "rule,dec,perm,auid,pid,exe,:,path,ftype,trust";

    fn format(spec: &str) -> Vec<String> {
        spec.split(',').map(str::to_string).collect()
    }

    fn stderr(o: &Outcome) -> String {
        o.diagnostics
            .iter()
            .map(|d| match d.line {
                Some(n) => format!("line {n}: {}\n", d.msg),
                None => format!("{}\n", d.msg),
            })
            .collect()
    }

    /// The shipped format names `trust`; this record stops at `ftype`.
    const SHORT: &[u8] =
        b"rule=1 dec=deny_audit perm=open auid=1000 pid=1 exe=/usr/bin/bash : path=/tmp/x ftype=text/plain\n";

    #[test]
    fn a_format_naming_uid_or_gid_is_reported_as_a_host_hazard() {
        let o = analyze(b"", Some(&format("rule,uid,gid,:,path")));
        assert_eq!(o.diagnostics.len(), 2, "{}", stderr(&o));
        assert!(
            o.diagnostics.iter().all(|d| d.line.is_none()),
            "{}",
            stderr(&o)
        );
        assert!(o.diagnostics[0].msg.contains("uid="), "{}", stderr(&o));
        assert!(o.diagnostics[1].msg.contains("gid="), "{}", stderr(&o));
    }

    #[test]
    fn a_field_the_format_names_and_the_record_lacks_is_truncation() {
        let f = format(DEFAULT_FORMAT);
        let o = analyze(SHORT, Some(&f));
        assert!(o.stdout.is_empty(), "must emit nothing when truncated");
        assert_eq!(o.diagnostics.len(), 1, "{}", stderr(&o));
        assert_eq!(o.diagnostics[0].line, Some(1));
        assert!(
            o.diagnostics[0].msg.contains("names trust="),
            "{}",
            stderr(&o)
        );
    }

    #[test]
    fn the_same_record_with_no_format_is_short_enough_not_to_be_truncated() {
        // Step 4 is the fallback, not a cross-check: this record is nowhere near the
        // cap, so the field the format wanted is not reported missing.
        assert!(SHORT.len() < MAX_PAYLOAD);
        let o = analyze(SHORT, None);
        assert!(!stderr(&o).contains("truncated"), "{}", stderr(&o));

        // With the field present it emits, which is what "not truncated" has to mean.
        let whole = [&SHORT[..SHORT.len() - 1], b" trust=0\n"].concat();
        let o = analyze(&whole, None);
        assert!(o.diagnostics.is_empty(), "{}", stderr(&o));
        assert!(o.stdout.starts_with(b"fapolicyd-cli --file add "));
    }

    #[test]
    fn twenty_one_names_with_no_colon_compare_the_subject_side_only() {
        // MAX_SYSLOG_FIELDS truncates the format before the `:` is reached, so the
        // daemon emits a subject-only record and there is no object side to check.
        let ten = "rule,dec,perm,auid,sessionid,pid,ppid,trust,comm,exe";
        let f = format(&format!("{ten},{ten},rule,:,path,ftype"));
        assert!(f.len() > MAX_SYSLOG_FIELDS);
        let record = b"rule=1 dec=deny_audit perm=open auid=1000 sessionid=1 pid=1 ppid=1 \
                       trust=1 comm=bash exe=/usr/bin/bash\n";
        let o = analyze(record, Some(&f));
        assert!(
            !stderr(&o).contains("truncated"),
            "not truncated: {}",
            stderr(&o)
        );
    }

    #[test]
    fn a_record_at_the_byte_cap_with_no_format_is_truncated() {
        let head = b"rule=1 dec=deny_audit perm=open exe=/usr/bin/bash : path=/tmp/";
        let mut record = head.to_vec();
        record.resize(MAX_PAYLOAD, b'x');
        record.push(b'\n');
        let o = analyze(&record, None);
        assert!(o.stdout.is_empty());
        assert_eq!(o.diagnostics.len(), 1, "{}", stderr(&o));
        assert!(
            o.diagnostics[0].msg.contains("511-byte cap"),
            "{}",
            stderr(&o)
        );
    }

    #[test]
    fn identical_diagnostics_collapse_to_one_line_with_a_count() {
        let mut input = SHORT.to_vec();
        input.extend_from_slice(SHORT);
        let f = format(DEFAULT_FORMAT);
        let o = analyze(&input, Some(&f));
        assert_eq!(o.diagnostics.len(), 1, "{}", stderr(&o));
        assert_eq!(o.diagnostics[0].line, Some(1), "the FIRST line is kept");
        assert!(o.diagnostics[0].msg.ends_with("(x2)"), "{}", stderr(&o));
    }

    #[test]
    fn a_commented_out_record_is_not_input() {
        // The comment carries a `]: ` of its own. Stripping the prefix first would
        // make this line indistinguishable from a live denial.
        let input = b"# record: 09/06/26 00:00:00 [ DEBUG ]: rule=2 dec=deny_audit perm=open \
                      exe=/usr/bin/bash : path=/etc/login.defs trust=0\n";
        let o = analyze(input, None);
        assert!(
            o.stdout.is_empty(),
            "{}",
            String::from_utf8_lossy(&o.stdout)
        );
        assert!(o.diagnostics.is_empty(), "{}", stderr(&o));
        assert!(!o.consumed_but_unparseable, "a comment is not content");
    }

    /// A `trust=1` denial, short enough that step 4 never fires.
    const TRUSTED: &[u8] =
        b"dec=deny_audit perm=execute exe=/usr/bin/bash : path=/tmp/gaps/trusted-ls trust=1\n";

    #[test]
    fn a_trusted_denial_emits_a_rule_and_the_host_notices() {
        let o = analyze(TRUSTED, None);
        assert_eq!(
            String::from_utf8(o.stdout.clone()).unwrap(),
            "allow perm=execute exe=/usr/bin/bash : path=/tmp/gaps/trusted-ls\n"
        );
        let text = stderr(&o);
        assert!(text.contains("rules.d/ has no effect"), "{text}");
        assert!(text.contains("--reload-rules exits 0"), "{text}");
        assert!(text.contains("sort before"), "{text}");
        assert!(
            o.diagnostics.iter().all(|d| d.line.is_none()),
            "the notices belong to the run, not to a line: {text}"
        );
    }

    #[test]
    fn the_same_rule_twice_is_emitted_once() {
        let input = [TRUSTED, TRUSTED].concat();
        let o = analyze(&input, None);
        assert_eq!(o.stdout.iter().filter(|b| **b == b'\n').count(), 1);
    }

    #[test]
    fn one_path_under_two_perms_needs_two_rules() {
        // Executing a file emits both a perm=execute and a perm=open record, and the
        // emitted rule depends on the perm — so this is two rules, not one (D12).
        let open = String::from_utf8(TRUSTED.to_vec())
            .unwrap()
            .replace("perm=execute", "perm=open");
        let input = [TRUSTED, open.as_bytes()].concat();
        let o = analyze(&input, None);
        assert_eq!(
            String::from_utf8(o.stdout).unwrap(),
            "allow perm=execute exe=/usr/bin/bash : path=/tmp/gaps/trusted-ls\n\
             allow perm=open exe=/usr/bin/bash : path=/tmp/gaps/trusted-ls\n"
        );
    }

    #[test]
    fn a_denial_with_no_trust_field_emits_a_rule_and_says_why() {
        let input = b"dec=deny_audit perm=open exe=/usr/bin/bash : path=/tmp/x\n";
        let o = analyze(input, None);
        assert_eq!(
            String::from_utf8(o.stdout.clone()).unwrap(),
            "allow perm=open exe=/usr/bin/bash : path=/tmp/x\n"
        );
        let text = stderr(&o);
        assert!(text.contains("line 1: no trust= in this record"), "{text}");
    }
}
