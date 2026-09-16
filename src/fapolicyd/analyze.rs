//! The pipeline. Pure: bytes in, bytes and diagnostics out.

use super::emit;
use super::model::{self, Artifact, Diagnostic, Record, Suggestion};
use super::parse::{self, MAX_PAYLOAD};
use super::policy::{self, Decision};
use super::rules;
use super::rules_d;
use std::collections::{BTreeSet, HashMap};

/// `parse_syslog_format` stops after 21 names and still returns success, so names past
/// the cap are never compared against anything (DESIGN.md §4).
const MAX_SYSLOG_FIELDS: usize = 21;

/// Two artifacts, never one stream. `rules` is a rules.d fragment and `trust` is a list
/// of `fapolicyd-cli` commands; they go to different places and one run of the pass
/// produces both, so the caller writes whichever one its action names.
#[derive(Debug, Default)]
pub struct Outcome {
    pub rules: Vec<u8>,
    pub trust: Vec<u8>,
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
/// 9. the `rule=` lookup, which can refuse the record outright (§7).
/// 10. the policy decision, then emission and deduplication.
///
/// `rules` is `None` when there is no rules file — no `--conf`, or the read failed —
/// which is v1's behaviour exactly. `rules_d` is empty for the same reasons and also
/// whenever the legacy `fapolicyd.rules` won the read, because then the merge order in
/// `rules.d/` is not the order that produced the record's `rule=`.
pub fn analyze(
    input: &[u8],
    syslog_format: Option<&[String]>,
    rules: Option<&[rules::Rule]>,
    rules_d: &[rules_d::File],
) -> Outcome {
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
                // A misconfigured host makes every record suspect, whichever artifact
                // the user asked for.
                artifact: Artifact::Both,
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
    // Counted and not flagged: each artifact's output names how many suggestions the
    // other one holds, so a user who ran one action learns the other half exists.
    let mut rules_emitted = 0usize;
    let mut trust_emitted = 0usize;
    // The `rule=` of every record that produced a rule, deduplicated: the placement
    // note has to name the file those rules have to be merged ahead of.
    let mut denied: BTreeSet<usize> = BTreeSet::new();
    // Records naming a rule the file does not have, or one that is an allow: either
    // says the rules file is not this log's, and both are reported once for the run.
    let mut unmatched = 0usize;
    // §6's stale `exe=`, keyed by the pid bytes as logged. One run is one capture, so
    // it is never reset, and it dies with the loop.
    let mut execs: HashMap<Vec<u8>, (Vec<u8>, Vec<u8>)> = HashMap::new();

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
            // Nothing was emitted, so neither artifact can be read as complete.
            out.diagnostics.push(Diagnostic {
                line,
                msg,
                artifact: Artifact::Both,
            });
            continue;
        }

        // Unconditionally and first, so the pid map is maintained even for records the
        // rule lookup below goes on to refuse.
        let stale = stale_exe(&mut execs, &record);

        // rule=0 is "no rule matched" and is never an index (§5). Parsed here rather
        // than inside the lookup below because the placement note needs the number
        // whether or not there is a rules file to resolve it against.
        let n = record
            .subject_get(b"rule")
            .and_then(|v| std::str::from_utf8(&v).ok()?.parse::<usize>().ok())
            .filter(|n| *n != 0);

        if let Some(rules) = rules {
            match n.map(|n| (n, rules::find(rules, n))) {
                Some((n, Some(r))) if r.refuses() => {
                    out.diagnostics.push(Diagnostic {
                        line,
                        // The refusal names both answers as impossible, so it belongs
                        // in whichever one the user is holding.
                        artifact: Artifact::Both,
                        msg: format!(
                            "rule={n} is subject-side ({}): it constrains the process, not the \
                             file, so no path rule and no trust entry can resolve this denial; \
                             emitting nothing",
                            r.text
                        ),
                    });
                    continue;
                }
                Some((_, Some(r))) if !r.decision.starts_with("deny") => unmatched += 1,
                Some((_, None)) => unmatched += 1,
                // A deny rule that does not refuse, or a record with no `rule=` field at
                // all. The second is not a mismatch: the compiled default syslog_format
                // does name `rule`, but a host conf that drops it would otherwise make
                // every record a mismatch.
                _ => {}
            }
        }

        match policy::decide(&record, stale.as_deref()) {
            Decision::Emit { suggestion, note } => {
                // The note explains the suggestion, so it follows it into that
                // artifact and nowhere else.
                let artifact = match suggestion {
                    Suggestion::Rule { .. } => Artifact::Rules,
                    Suggestion::TrustFile { .. } => Artifact::Trust,
                };
                if let Some(msg) = note {
                    out.diagnostics.push(Diagnostic {
                        line,
                        msg,
                        artifact,
                    });
                }
                // A `TrustFile` carries no exe, so the note would be noise there.
                if let (Some(execed), Suggestion::Rule { .. }) = (&stale, &suggestion) {
                    out.diagnostics.push(Diagnostic {
                        line,
                        // It describes how the rule was scoped; a trust entry has no exe.
                        artifact: Artifact::Rules,
                        msg: format!(
                            "exe= is stale: pid {pid} was denied perm=execute of {execed}, and \
                             the daemon keeps the pre-exec image until that exec is permitted; \
                             the emitted rule is scoped to exe={execed} and not to the logged \
                             exe={logged}",
                            pid = String::from_utf8_lossy(
                                &record.subject_get(b"pid").unwrap_or_default()
                            ),
                            execed = String::from_utf8_lossy(execed),
                            logged = String::from_utf8_lossy(
                                &record.subject_get(b"exe").unwrap_or_default()
                            ),
                        ),
                    });
                }
                if seen.contains(&suggestion) {
                    continue;
                }
                if matches!(suggestion, Suggestion::Rule { .. }) {
                    rules_emitted += 1;
                    if let Some(n) = n {
                        denied.insert(n);
                    }
                } else {
                    trust_emitted += 1;
                }
                let rendered = emit::render(&suggestion);
                match artifact {
                    Artifact::Rules => out.rules.extend_from_slice(&rendered),
                    _ => out.trust.extend_from_slice(&rendered),
                }
                seen.push(suggestion);
            }
            // Nothing was emitted into either artifact, so both have to say why.
            Decision::Explain(msg) => out.diagnostics.push(Diagnostic {
                line,
                msg,
                artifact: Artifact::Both,
            }),
        }
    }

    if corrupt > 0 {
        out.diagnostics.push(Diagnostic {
            line: None,
            artifact: Artifact::Both,
            msg: format!(
                "{corrupt} records have unreadable field names: the daemon failed a rules \
                 reload and is now running with NO rules, allowing everything. Restart it. \
                 Nothing below can be trusted as a denial record"
            ),
        });
    }

    if unmatched > 0 {
        out.diagnostics.push(Diagnostic {
            line: None,
            artifact: Artifact::Both,
            msg: format!(
                "the rules file does not match this log: {unmatched} record(s) name a rule= the \
                 file does not contain, or one that is an allow rule; those records were \
                 analysed without it"
            ),
        });
    }

    // D12: this note belongs to the run, not to a line. The two standing advisories
    // that used to sit beside it are input-independent and live in `rules --help`.
    if rules_emitted > 0 {
        out.diagnostics.push(Diagnostic {
            line: None,
            artifact: Artifact::Rules,
            msg: placement_note(rules_d, rules, &denied),
        });
    }

    // Each artifact names the other one's contents, because a user who ran one action
    // has no other way to learn that the input also needed the other.
    if trust_emitted > 0 {
        out.diagnostics.push(Diagnostic {
            line: None,
            artifact: Artifact::Rules,
            msg: format!(
                "{trust_emitted} untrusted path(s) need a trust entry, not a rule: run \
                 rulesteward fapolicyd trust on the same input"
            ),
        });
    }
    if rules_emitted > 0 {
        out.diagnostics.push(Diagnostic {
            line: None,
            artifact: Artifact::Trust,
            msg: format!(
                "{rules_emitted} denial(s) need a rule, not a trust entry: run \
                 rulesteward fapolicyd rules on the same input"
            ),
        });
    }

    out.diagnostics = collapse(out.diagnostics);

    // §9's exit 2 is "input consumed but unparseable" — not "no denials found". A log
    // full of allow records is a successful run with nothing to suggest.
    out.consumed_but_unparseable = content > 0 && parsed == 0;
    out
}

/// D12's third note: where the emitted rule has to be placed for it to be reached.
///
/// With `rules.d/` in hand and a `rule=` to look up, the note leads with the filename to
/// create and names the file it has to sort before. An unprefixed file sorts last, so
/// the recommendation there is one past the last numbered prefix rather than nothing.
/// The remaining cases lead with "none recommended" and name the constraint: a `0-`
/// prefix, `rules.d/` disagreeing with `compiled.rules`, or no `rules.d/` read at all --
/// `--no-conf`, a legacy `fapolicyd.rules`, or records that carry no `rule=`. How
/// `rules.d/` merges is the same on every run and lives in `rules --help` instead.
///
/// The earliest file wins: a name that sorts before it sorts before all of them.
fn placement_note(
    rules_d: &[rules_d::File],
    compiled: Option<&[rules::Rule]>,
    denied: &BTreeSet<usize>,
) -> String {
    let Some(compiled) = compiled.filter(|_| !rules_d.is_empty() && !denied.is_empty()) else {
        return "new file: none recommended (rules.d/ not read: --no-conf, legacy \
                fapolicyd.rules, or unreadable)"
            .into();
    };

    let located: Vec<(usize, Option<usize>)> = denied
        .iter()
        .map(|&n| (n, rules_d::locate(rules_d, compiled, n)))
        .collect();
    if located.iter().any(|(_, at)| at.is_none()) {
        return "new file: none recommended (rules.d/ changed since fagenrules ran; run \
                fagenrules, recapture, rerun)"
            .into();
    }

    let earliest = located.iter().filter_map(|&(_, at)| at).min().unwrap_or(0);
    let name = &rules_d[earliest].name;
    let numbers: Vec<String> = located
        .iter()
        .filter(|&&(_, at)| at == Some(earliest))
        .map(|(n, _)| n.to_string())
        .collect();
    let subject = match numbers.as_slice() {
        [one] => format!("rule={one}"),
        many => format!("rules {}", many.join(", ")),
    };
    match rules_d::recommend(rules_d, earliest) {
        Some(before) => {
            format!("new file: rules.d/{before} (sorts before {name}, {subject})")
        }
        None => format!("new file: none recommended (nothing sorts before {name}, {subject})"),
    }
}

/// DESIGN.md §6's stale `exe=`: the image a later record's rule must be scoped to, or
/// `None`.
///
/// Substitute when the record has the same `pid` and the same `exe` as a preceding
/// denied `perm=execute` of P, and is neither that exec record nor an access to P
/// itself. Last exec denial per pid wins.
fn stale_exe(execs: &mut HashMap<Vec<u8>, (Vec<u8>, Vec<u8>)>, record: &Record) -> Option<Vec<u8>> {
    // Rocky 9/10 render an unavailable pid as `0`, ambiguous with a real zero, and
    // Rocky 8 as `-2`. An unavailable pid is not a process identity and may not key a
    // substitution across two unrelated processes.
    let pid = record
        .subject_get(b"pid")
        .filter(|p| !matches!(p.as_slice(), b"0" | b"-2" | b"?"))?;
    let exe = record.subject_get(b"exe")?;
    let path = record.object_get(b"path");

    if record.subject_get(b"perm").as_deref() == Some(b"execute") {
        if let Some(p) = path {
            execs.insert(pid, (exe, p));
        }
        // The exec record itself keeps the exe it was logged with: once the exec is
        // permitted it is not logged at all, so there is nothing to rewrite it to.
        return None;
    }
    let (pre_exec, execed) = execs.get(&pid)?;
    // So does the companion open of the exec'd path, for the same reason.
    (exe == *pre_exec && path.as_deref() != Some(execed.as_slice())).then(|| execed.clone())
    // ponytail: pids are matched as logged, so a pid reused after the denied exec
    // inside one capture inherits the substitution. The same-exe test is the guard —
    // the reusing process has to be running the same image for it to fire. Key on
    // (pid, ppid, auid) or add a record-count window only if a capture ever shows it.
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
///
/// The artifact is part of the key: the same sentence written into two different files
/// is two lines, each counting only what its own reader will see.
fn collapse(diagnostics: Vec<Diagnostic>) -> Vec<Diagnostic> {
    let mut out: Vec<(Diagnostic, usize)> = Vec::new();
    for d in diagnostics {
        match out
            .iter_mut()
            .find(|(kept, _)| kept.msg == d.msg && kept.artifact == d.artifact)
        {
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

    fn notes(o: &Outcome) -> String {
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
        let o = analyze(b"", Some(&format("rule,uid,gid,:,path")), None, &[]);
        assert_eq!(o.diagnostics.len(), 2, "{}", notes(&o));
        assert!(
            o.diagnostics.iter().all(|d| d.line.is_none()),
            "{}",
            notes(&o)
        );
        assert!(o.diagnostics[0].msg.contains("uid="), "{}", notes(&o));
        assert!(o.diagnostics[1].msg.contains("gid="), "{}", notes(&o));
    }

    #[test]
    fn a_field_the_format_names_and_the_record_lacks_is_truncation() {
        let f = format(DEFAULT_FORMAT);
        let o = analyze(SHORT, Some(&f), None, &[]);
        assert!(
            o.rules.is_empty() && o.trust.is_empty(),
            "must emit nothing when truncated"
        );
        assert_eq!(o.diagnostics.len(), 1, "{}", notes(&o));
        assert_eq!(o.diagnostics[0].line, Some(1));
        assert!(
            o.diagnostics[0].msg.contains("names trust="),
            "{}",
            notes(&o)
        );
    }

    #[test]
    fn the_same_record_with_no_format_is_short_enough_not_to_be_truncated() {
        // Step 4 is the fallback, not a cross-check: this record is nowhere near the
        // cap, so the field the format wanted is not reported missing.
        assert!(SHORT.len() < MAX_PAYLOAD);
        let o = analyze(SHORT, None, None, &[]);
        assert!(!notes(&o).contains("truncated"), "{}", notes(&o));

        // With the field present it emits, which is what "not truncated" has to mean.
        let whole = [&SHORT[..SHORT.len() - 1], b" trust=0\n"].concat();
        let o = analyze(&whole, None, None, &[]);
        assert!(o.trust.starts_with(b"fapolicyd-cli --file add "));
        // The only thing left to say is that the other action holds this suggestion.
        assert_eq!(o.diagnostics.len(), 1, "{}", notes(&o));
        assert!(
            o.diagnostics[0].msg.contains("need a trust entry"),
            "{}",
            notes(&o)
        );
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
        let o = analyze(record, Some(&f), None, &[]);
        assert!(
            !notes(&o).contains("truncated"),
            "not truncated: {}",
            notes(&o)
        );
    }

    #[test]
    fn a_record_at_the_byte_cap_with_no_format_is_truncated() {
        let head = b"rule=1 dec=deny_audit perm=open exe=/usr/bin/bash : path=/tmp/";
        let mut record = head.to_vec();
        record.resize(MAX_PAYLOAD, b'x');
        record.push(b'\n');
        let o = analyze(&record, None, None, &[]);
        assert!(o.rules.is_empty() && o.trust.is_empty());
        assert_eq!(o.diagnostics.len(), 1, "{}", notes(&o));
        assert!(
            o.diagnostics[0].msg.contains("511-byte cap"),
            "{}",
            notes(&o)
        );
    }

    #[test]
    fn identical_diagnostics_collapse_to_one_line_with_a_count() {
        let mut input = SHORT.to_vec();
        input.extend_from_slice(SHORT);
        let f = format(DEFAULT_FORMAT);
        let o = analyze(&input, Some(&f), None, &[]);
        assert_eq!(o.diagnostics.len(), 1, "{}", notes(&o));
        assert_eq!(o.diagnostics[0].line, Some(1), "the FIRST line is kept");
        assert!(o.diagnostics[0].msg.ends_with("(x2)"), "{}", notes(&o));
    }

    #[test]
    fn a_commented_out_record_is_not_input() {
        // The comment carries a `]: ` of its own. Stripping the prefix first would
        // make this line indistinguishable from a live denial.
        let input = b"# record: 09/06/26 00:00:00 [ DEBUG ]: rule=2 dec=deny_audit perm=open \
                      exe=/usr/bin/bash : path=/etc/login.defs trust=0\n";
        let o = analyze(input, None, None, &[]);
        assert!(
            o.rules.is_empty() && o.trust.is_empty(),
            "{}{}",
            String::from_utf8_lossy(&o.rules),
            String::from_utf8_lossy(&o.trust)
        );
        assert!(o.diagnostics.is_empty(), "{}", notes(&o));
        assert!(!o.consumed_but_unparseable, "a comment is not content");
    }

    /// A `trust=1` denial, short enough that step 4 never fires.
    const TRUSTED: &[u8] =
        b"dec=deny_audit perm=execute exe=/usr/bin/bash : path=/tmp/gaps/trusted-ls trust=1\n";

    #[test]
    fn a_trusted_denial_emits_a_rule_and_the_host_notices() {
        let o = analyze(TRUSTED, None, None, &[]);
        assert_eq!(
            String::from_utf8(o.rules.clone()).unwrap(),
            "allow perm=execute exe=/usr/bin/bash : path=/tmp/gaps/trusted-ls\n"
        );
        let text = notes(&o);
        assert!(text.contains("new file:"), "{text}");
        assert!(
            o.diagnostics.iter().all(|d| d.line.is_none()),
            "the note belongs to the run, not to a line: {text}"
        );
    }

    #[test]
    fn the_same_rule_twice_is_emitted_once() {
        let input = [TRUSTED, TRUSTED].concat();
        let o = analyze(&input, None, None, &[]);
        assert_eq!(o.rules.iter().filter(|b| **b == b'\n').count(), 1);
    }

    #[test]
    fn one_path_under_two_perms_needs_two_rules() {
        // Executing a file emits both a perm=execute and a perm=open record, and the
        // emitted rule depends on the perm — so this is two rules, not one (D12).
        let open = String::from_utf8(TRUSTED.to_vec())
            .unwrap()
            .replace("perm=execute", "perm=open");
        let input = [TRUSTED, open.as_bytes()].concat();
        let o = analyze(&input, None, None, &[]);
        assert_eq!(
            String::from_utf8(o.rules).unwrap(),
            "allow perm=execute exe=/usr/bin/bash : path=/tmp/gaps/trusted-ls\n\
             allow perm=open exe=/usr/bin/bash : path=/tmp/gaps/trusted-ls\n"
        );
    }

    #[test]
    fn a_denial_with_no_trust_field_emits_a_rule_and_says_why() {
        let input = b"dec=deny_audit perm=open exe=/usr/bin/bash : path=/tmp/x\n";
        let o = analyze(input, None, None, &[]);
        assert_eq!(
            String::from_utf8(o.rules.clone()).unwrap(),
            "allow perm=open exe=/usr/bin/bash : path=/tmp/x\n"
        );
        let text = notes(&o);
        assert!(text.contains("line 1: no trust= in this record"), "{text}");
    }

    /// The shipped `pattern=ld_so` deny, alone, at its real number.
    fn ld_so() -> Vec<rules::Rule> {
        vec![rules::Rule::new(
            5,
            "deny_audit perm=any pattern=ld_so : all",
        )]
    }

    #[test]
    fn a_subject_side_rule_refuses_in_every_trust_arm() {
        // The refusal sits BEFORE the decision table, so no arm of it runs — including
        // `trust=0`, which is the /etc/hostname trust add issue #10 is about.
        for tail in ["trust=0", "trust=1", ""] {
            let input = format!(
                "rule=5 dec=deny_audit perm=open pid=1 exe=/usr/sbin/runuser : \
                 path=/etc/hostname {tail}\n"
            );
            let o = analyze(input.as_bytes(), None, Some(&ld_so()), &[]);
            assert!(
                o.rules.is_empty() && o.trust.is_empty(),
                "{tail}: {}{}",
                String::from_utf8_lossy(&o.rules),
                String::from_utf8_lossy(&o.trust)
            );
            let text = notes(&o);
            assert!(text.contains("pattern=ld_so"), "{tail}: {text}");
            assert!(text.contains("rule=5 is subject-side"), "{tail}: {text}");
        }
    }

    #[test]
    fn a_resolved_rule_with_no_rules_d_keeps_the_generic_placement_note() {
        // A legacy host, or an unreadable rules.d/: compiled.rules resolved rule=1, but
        // no merge order was read, so the note may name neither a file nor a drift.
        let rules = vec![rules::Rule::new(1, "deny_audit perm=execute all : all")];
        let input = b"rule=1 dec=deny_audit perm=execute pid=1 exe=/usr/bin/bash : \
                      path=/tmp/gaps/trusted-ls trust=1\n";
        let o = analyze(input, None, Some(&rules), &[]);
        let text = notes(&o);
        assert!(o.rules.starts_with(b"allow perm=execute"), "{text}");
        assert!(text.contains("not read"), "generic note: {text}");
        assert!(!text.contains("does not match"), "{text}");
    }

    #[test]
    fn an_unprefixed_file_is_named_a_filename_not_declined() {
        // `local.rules` sorts last of all, so any numbered name sorts before it.
        let rule = rules::Rule::new(1, "deny_audit perm=execute all : all");
        let rules_d = vec![rules_d::File {
            name: "local.rules".into(),
            rules: vec![rule.clone()],
        }];
        let input = b"rule=1 dec=deny_audit perm=execute pid=1 exe=/usr/bin/bash : \
                      path=/tmp/gaps/trusted-ls trust=1\n";
        let o = analyze(input, None, Some(&[rule]), &rules_d);
        let text = notes(&o);
        assert!(
            text.contains(
                "new file: rules.d/1-rulesteward.rules (sorts before local.rules, rule=1)"
            ),
            "{text}"
        );
    }

    #[test]
    fn a_rule_number_the_file_does_not_have_is_one_note_and_v1_behaviour() {
        let input = b"rule=99 dec=deny_audit perm=open pid=1 exe=/usr/bin/bash : \
                      path=/tmp/x trust=0\n";
        let o = analyze(input, None, Some(&ld_so()), &[]);
        assert_eq!(
            String::from_utf8(o.trust.clone()).unwrap(),
            "fapolicyd-cli --file add '/tmp/x'\nfapolicyd-cli --update\n"
        );
        // The mismatch note, plus the cross-reference into the `rules` output.
        assert_eq!(o.diagnostics.len(), 2, "{}", notes(&o));
        assert_eq!(o.diagnostics[0].line, None);
        assert!(
            o.diagnostics[0].msg.contains("does not match this log"),
            "{}",
            notes(&o)
        );
    }

    #[test]
    fn an_allow_rule_for_a_denial_record_counts_as_a_mismatch() {
        // A denial record's rule= is a deny rule by construction, so landing on an
        // allow is the same evidence as landing on nothing.
        let rules = vec![rules::Rule::new(
            3,
            "allow perm=open exe=/usr/bin/rpm : all",
        )];
        let input = b"rule=3 dec=deny_audit perm=open pid=1 exe=/usr/bin/bash : \
                      path=/tmp/x trust=0\n";
        let o = analyze(input, None, Some(&rules), &[]);
        assert!(o.trust.starts_with(b"fapolicyd-cli --file add "));
        assert_eq!(o.diagnostics.len(), 2, "{}", notes(&o));
        assert!(
            o.diagnostics[0].msg.contains("does not match this log"),
            "{}",
            notes(&o)
        );
    }

    #[test]
    fn a_record_with_no_rule_field_is_not_a_mismatch() {
        // A host conf whose syslog_format drops `rule` would otherwise report every
        // record as a mismatch.
        let input = b"dec=deny_audit perm=open pid=1 exe=/usr/bin/bash : path=/tmp/x trust=0\n";
        let o = analyze(input, None, Some(&ld_so()), &[]);
        assert!(o.trust.starts_with(b"fapolicyd-cli --file add "));
        assert!(!notes(&o).contains("does not match"), "{}", notes(&o));
    }

    const LOADER: &str = "/usr/lib64/ld-linux-x86-64.so.2";

    #[test]
    fn records_after_a_denied_exec_are_scoped_to_the_exec_d_path() {
        // The fixture's shape: the loader's execute denial, the companion open of the
        // loader, a further open under the same pid and exe, and an unrelated pid.
        let input = format!(
            "dec=deny_audit perm=execute pid=75414 exe=/usr/sbin/runuser : path={LOADER} trust=1\n\
             dec=deny_audit perm=open pid=75414 exe=/usr/sbin/runuser : path={LOADER} trust=1\n\
             dec=deny_audit perm=open pid=75414 exe=/usr/sbin/runuser : path=/usr/bin/grep trust=1\n\
             dec=deny_audit perm=open pid=999 exe=/usr/sbin/runuser : path=/usr/bin/sed trust=1\n"
        );
        let o = analyze(input.as_bytes(), None, None, &[]);
        assert_eq!(
            String::from_utf8(o.rules.clone()).unwrap(),
            format!(
                "allow perm=execute exe=/usr/sbin/runuser : path={LOADER}\n\
                 allow perm=open exe=/usr/sbin/runuser : path={LOADER}\n\
                 allow perm=open exe={LOADER} : path=/usr/bin/grep\n\
                 allow perm=open exe=/usr/sbin/runuser : path=/usr/bin/sed\n"
            )
        );
        let text = notes(&o);
        assert_eq!(
            text.matches("exe= is stale").count(),
            1,
            "one substituted line, one note: {text}"
        );
        assert!(text.contains("line 3: exe= is stale"), "{text}");
    }

    #[test]
    fn an_unavailable_pid_never_matches() {
        // Rocky 9/10 log an unavailable pid as `0`, which is not a process identity.
        let input = format!(
            "dec=deny_audit perm=execute pid=0 exe=/usr/sbin/runuser : path={LOADER} trust=1\n\
             dec=deny_audit perm=open pid=0 exe=/usr/sbin/runuser : path=/usr/bin/grep trust=1\n"
        );
        let o = analyze(input.as_bytes(), None, None, &[]);
        assert!(
            String::from_utf8(o.rules.clone())
                .unwrap()
                .contains("allow perm=open exe=/usr/sbin/runuser : path=/usr/bin/grep"),
            "{}",
            String::from_utf8_lossy(&o.rules)
        );
        assert!(!notes(&o).contains("exe= is stale"), "{}", notes(&o));
    }

    #[test]
    fn a_substituted_exe_that_cannot_be_written_becomes_all() {
        // The override goes THROUGH the exe filter, so an unwritable one is `all` and
        // never the stale logged value, which is known wrong.
        let input = b"dec=deny_audit perm=execute pid=42 exe=/usr/sbin/runuser :                       path=/tmp/spaced\\ bash trust=1\n                      dec=deny_audit perm=open pid=42 exe=/usr/sbin/runuser :                       path=/usr/bin/grep trust=1\n";
        let o = analyze(input, None, None, &[]);
        let text = String::from_utf8(o.rules.clone()).unwrap();
        assert!(
            text.contains("allow perm=open all : path=/usr/bin/grep"),
            "{text}"
        );
        assert!(
            !text.contains("/usr/sbin/runuser : path=/usr/bin/grep"),
            "{text}"
        );
    }
}
