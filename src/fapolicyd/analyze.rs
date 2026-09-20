//! The pipeline. Pure: bytes in, bytes and diagnostics out.

use super::audit;
use super::check;
use super::emit;
use super::model::{self, Artifact, Diagnostic, Record, Source, Suggestion};
use super::parse::{self, MAX_PAYLOAD};
use super::policy::{self, Decision};
use super::rules;
use super::rules_d;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::Write;

/// `parse_syslog_format` stops after 21 names and still returns success, so names past
/// the cap are never compared against anything (DESIGN.md §4).
const MAX_SYSLOG_FIELDS: usize = 21;

/// Three results, never one stream. `rules` is a rules.d fragment, `trust` is a list of
/// `fapolicyd-cli` commands and `why` is the per-rule report; they go to different
/// places and one run of the pass produces all three, so the caller writes whichever
/// one its action names.
#[derive(Debug, Default)]
pub struct Outcome {
    pub rules: Vec<u8>,
    pub trust: Vec<u8>,
    /// The audit2why half: one line per denying rule, ascending by number. Rendered
    /// here and not in `emit.rs`, because these lines are a report and not
    /// `Suggestion`s — there is no target file for them to be written into.
    pub why: Vec<u8>,
    /// The `check` report: one line per distinct denial, in first-seen order, saying what
    /// the proposed rules.d/ would do with it. Empty unless a candidate path was given.
    pub check: Vec<u8>,
    pub diagnostics: Vec<Diagnostic>,
    /// §9's exit 2: we read the input but could not make sense of any of it.
    pub consumed_but_unparseable: bool,
}

/// What one rule number accounts for: how many records it denied, and how many
/// distinct suggestions of each kind those records produced. `denials` is counted at
/// the `rule=` lookup and the other two beside `rules_emitted`/`trust_emitted`, so they
/// count suggestions after deduplication while `denials` counts records.
#[derive(Default)]
struct Tally {
    denials: usize,
    rules: usize,
    trust: usize,
}

/// One pass over the input, over the records of whichever source wrote it.
///
/// Two sources reach the same pipeline: `daemon_records` below, one record per line,
/// and `audit::records`, which assembles one per FANOTIFY record out of an `ausearch`
/// event. Steps 1 to 5 are what "this line is a record" means and belong to the source;
/// everything from step 6 down is the pass and runs over both, once.
///
/// The order of the steps is part of the contract. Each step earns its place:
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
///
/// `proposal` is what `check` is checking (#158), and `None` for every action but
/// `check`: the pass is one pass, so the check runs inside the same loop rather than over
/// a second reading of the same records.
pub fn analyze(
    input: &[u8],
    syslog_format: Option<&[String]>,
    rules: Option<&[rules::Rule]>,
    rules_d: &[rules_d::File],
    proposal: Option<check::Proposal<'_>>,
) -> Outcome {
    let mut out = Outcome::default();

    // The arms differ only in what rule N is placed against: candidates against the
    // `rules.d/` fagenrules generated `compiled.rules` from, the directory itself against
    // `compiled.rules`, because an in-place edit is exactly the two disagreeing. Only the
    // second is gated on its `%set` definitions still being the loaded ones -- a candidate
    // given by `PATH` that redefines a set is the same hazard and is #139's.
    let proposed = proposal.map(|p| match p {
        check::Proposal::Merged(files) => (Some(rules_d), true, files),
        check::Proposal::OnDisk { sets_agree } => (None, sets_agree, rules_d),
    });

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

    // The audit route is decided on the input's first real line and changes two things
    // only: where the records come from, and that no truncation test applies to them.
    let audit = audit::is_audit(input);
    let source = if audit {
        audit::records(input, rules)
    } else {
        daemon_records(input)
    };
    out.diagnostics.extend(source.diagnostics);
    // `syslog_format` describes the daemon's own line. An audit record was assembled
    // from whole audit fields, so neither §6 test has anything to measure on it.
    let syslog_format = if audit { None } else { syslog_format };
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
    // `why`'s whole input, ascending by rule number because a BTreeMap iterates in key
    // order and the report is one line per denying rule in that order.
    let mut tally: BTreeMap<usize, Tally> = BTreeMap::new();
    // Records naming a rule the file does not have, or one that is an allow: either
    // says the rules file is not this log's, and both are reported once for the run.
    let mut unmatched = 0usize;
    // §6's stale `exe=`, keyed by the pid bytes as logged. One run is one capture, so
    // it is never reset, and it dies with the loop.
    let mut execs: HashMap<Vec<u8>, (Vec<u8>, Vec<u8>)> = HashMap::new();
    // `check`'s rows, in first-seen order, which is the order the report is written in.
    let mut checked: Vec<(check::Key, usize, check::Verdict)> = Vec::new();

    for (line, record, payload_len) in source.records {
        if names(&record)
            .iter()
            .any(|n| parse::is_corrupt_field_name(n))
        {
            corrupt += 1;
            continue;
        }

        if !parse::is_denial(&record) {
            continue;
        }

        if let Some(msg) = truncated(&record, syslog_format, payload_len) {
            // Nothing was emitted, so neither artifact can be read as complete.
            out.diagnostics.push(Diagnostic {
                line: Some(line),
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

        // D4: tallied here, after the truncation refusal and before the refusal below,
        // so a truncated record counts nowhere and a subject-side rule's count equals
        // the number of refusal comments the other two actions carry.
        if let Some(n) = n {
            tally.entry(n).or_default().denials += 1;
        }

        // Before the refusal below, because a subject-side `rule=N` is exactly where a
        // candidate is worth checking: #120's `subjectside-before-N` row measured an
        // `allow`, so "nothing this tool can emit resolves it" is not "nothing resolves
        // it". The first record of a key decides for all of them; `stale_exe` is the only
        // input two records sharing a key can differ on, and it already gives `unknown`.
        if let Some((host, sets_agree, proposed)) = proposed {
            let key = check::key(&record, n);
            match checked.iter_mut().find(|(seen, _, _)| *seen == key) {
                Some((_, count, _)) => *count += 1,
                None => {
                    let verdict = check::verdict(
                        &record,
                        n,
                        stale.as_deref(),
                        rules,
                        host,
                        sets_agree,
                        proposed,
                    );
                    checked.push((key, 1, verdict));
                }
            }
        }

        if let Some(rules) = rules {
            match n.map(|n| (n, n.checked_sub(1).and_then(|i| rules.get(i)))) {
                // Not under `check`: its verdict line above already answers for this
                // record, and "no path rule can resolve this" is what #120's
                // `subjectside-before-N` row measured to be false for a candidate.
                Some((_, Some(r))) if r.refuses() && proposed.is_some() => continue,
                Some((n, Some(r))) if r.refuses() => {
                    out.diagnostics.push(Diagnostic {
                        line: Some(line),
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
                        line: Some(line),
                        msg,
                        artifact,
                    });
                }
                // A `TrustFile` carries no exe, so the note would be noise there.
                if let (Some(execed), Suggestion::Rule { .. }) = (&stale, &suggestion) {
                    out.diagnostics.push(Diagnostic {
                        line: Some(line),
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
                let is_rule = matches!(suggestion, Suggestion::Rule { .. });
                if is_rule {
                    rules_emitted += 1;
                } else {
                    trust_emitted += 1;
                }
                // The same count, per rule, for `why`'s verdict column.
                if let Some(t) = n.and_then(|n| tally.get_mut(&n)) {
                    if is_rule {
                        t.rules += 1;
                    } else {
                        t.trust += 1;
                    }
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
                line: Some(line),
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
        // The `rule=` of every record that produced a rule, deduplicated: the placement
        // note has to name the file those rules have to be merged ahead of. That is the
        // tally's own `rules` count, incremented at the same place as the emission, so a
        // rule whose records all became trust entries is not one of them.
        let denied: BTreeSet<usize> = tally
            .iter()
            .filter(|(_, t)| t.rules != 0)
            .map(|(&n, _)| n)
            .collect();
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

    out.why = why_report(&tally, rules, rules_d);
    out.check = check::report(&checked);

    out.diagnostics = collapse(out.diagnostics);

    // §9's exit 2 is "input consumed but unparseable" — not "no denials found". A log
    // full of allow records is a successful run with nothing to suggest.
    out.consumed_but_unparseable = source.content > 0 && source.parsed == 0;
    out
}

/// The daemon source: one record per line, steps 1 to 5 of the pass's ladder.
///
/// A line that yields no field at all counts as content and not as parsed, which is the
/// whole of §9's exit 2: the daemon interleaves prose with records and prose is not a
/// parse failure.
fn daemon_records(input: &[u8]) -> Source {
    let mut source = Source::default();
    for (i, raw) in input.split(|&b| b == b'\n').enumerate() {
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
        source.content += 1;
        let record = parse::parse(payload);
        if names(&record).is_empty() {
            continue;
        }
        source.parsed += 1;
        source.records.push((i + 1, record, payload.len()));
    }
    source
}

/// Every field name in the record, both sides. The corruption test reads all of them
/// and so does the "no fields at all" test, and neither may look at one side only.
fn names(record: &Record) -> Vec<&[u8]> {
    record
        .subject
        .iter()
        .chain(record.object.iter().flatten())
        .map(|(k, _)| k.as_slice())
        .collect()
}

/// The `why` artifact: one line per denying rule, ascending, in aligned columns.
///
/// Columns are `rule=N`, the rules.d file, the denial count, the verdict and the rule
/// text. The first four are bounded -- a filename, a count, a fixed verdict vocabulary
/// -- so they are padded to the widest value in the run; the text is the only free-form
/// field, so it goes last and pads nothing and one long `pattern=` shifts no column. A
/// column that is empty for every row (no rules file, so no file, verdict or text)
/// collapses along with its separator, and trailing spaces are trimmed per line.
fn why_report(
    tally: &BTreeMap<usize, Tally>,
    rules: Option<&[rules::Rule]>,
    rules_d: &[rules_d::File],
) -> Vec<u8> {
    let rows: Vec<[String; 5]> = tally
        .iter()
        .map(|(&n, t)| {
            let file = rules
                .and_then(|compiled| rules_d::locate(rules_d, compiled, n))
                .map(|i| rules_d[i].name.clone())
                .unwrap_or_default();
            // No rules file, or a number it does not have: nothing to quote and no
            // verdict to reach, so both cells stay empty.
            let rule = rules.and_then(|compiled| n.checked_sub(1).and_then(|i| compiled.get(i)));
            let (verdict, text) = match rule {
                Some(r) if r.refuses() => {
                    ("subject-side, nothing to emit".to_string(), r.text.clone())
                }
                Some(r) => {
                    let counts: Vec<String> = [("rules", t.rules), ("trust", t.trust)]
                        .iter()
                        .filter(|(_, c)| *c > 0)
                        .map(|(kind, c)| format!("{kind}: {c}"))
                        .collect();
                    // The run's own per-line notes already say why nothing came out.
                    let verdict = if counts.is_empty() {
                        "nothing to emit".to_string()
                    } else {
                        counts.join(", ")
                    };
                    (verdict, r.text.clone())
                }
                None => (String::new(), String::new()),
            };
            [
                format!("rule={n}"),
                file,
                t.denials.to_string(),
                verdict,
                text,
            ]
        })
        .collect();

    let mut widths = [0usize; 4];
    for row in &rows {
        for (w, cell) in widths.iter_mut().zip(row) {
            *w = (*w).max(cell.len());
        }
    }

    let mut out = Vec::new();
    for row in &rows {
        let mut line = String::new();
        for (i, &w) in widths.iter().enumerate() {
            if w == 0 {
                continue;
            }
            match i {
                // Right-aligned, so the digits line up under each other.
                2 => line.push_str(&format!("{:>w$} denials", row[2], w = w)),
                _ => line.push_str(&format!("{:<w$}", row[i], w = w)),
            }
            line.push_str("  ");
        }
        line.push_str(&row[4]);
        // Writing into a Vec cannot fail.
        let _ = writeln!(out, "{}", line.trim_end());
    }
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
        let o = analyze(b"", Some(&format("rule,uid,gid,:,path")), None, &[], None);
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
        let o = analyze(SHORT, Some(&f), None, &[], None);
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
        let o = analyze(SHORT, None, None, &[], None);
        assert!(!notes(&o).contains("truncated"), "{}", notes(&o));

        // With the field present it emits, which is what "not truncated" has to mean.
        let whole = [&SHORT[..SHORT.len() - 1], b" trust=0\n"].concat();
        let o = analyze(&whole, None, None, &[], None);
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
        let o = analyze(record, Some(&f), None, &[], None);
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
        let o = analyze(&record, None, None, &[], None);
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
        let o = analyze(&input, Some(&f), None, &[], None);
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
        let o = analyze(input, None, None, &[], None);
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
        let o = analyze(TRUSTED, None, None, &[], None);
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
        let o = analyze(&input, None, None, &[], None);
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
        let o = analyze(&input, None, None, &[], None);
        assert_eq!(
            String::from_utf8(o.rules).unwrap(),
            "allow perm=execute exe=/usr/bin/bash : path=/tmp/gaps/trusted-ls\n\
             allow perm=open exe=/usr/bin/bash : path=/tmp/gaps/trusted-ls\n"
        );
    }

    #[test]
    fn a_denial_with_no_trust_field_emits_a_rule_and_says_why() {
        let input = b"dec=deny_audit perm=open exe=/usr/bin/bash : path=/tmp/x\n";
        let o = analyze(input, None, None, &[], None);
        assert_eq!(
            String::from_utf8(o.rules.clone()).unwrap(),
            "allow perm=open exe=/usr/bin/bash : path=/tmp/x\n"
        );
        let text = notes(&o);
        assert!(text.contains("line 1: no trust= in this record"), "{text}");
    }

    /// The shipped `pattern=ld_so` deny at its real position: the first five rules of a
    /// default Rocky 9 set, so `rule=5` indexes the deny and not one of its neighbours.
    fn ld_so() -> Vec<rules::Rule> {
        rules::parse(
            b"allow perm=any uid=0 : dir=/var/tmp/\n\
              allow perm=any uid=0 trust=1 : all\n\
              allow perm=open exe=/usr/bin/rpm : all\n\
              allow perm=open exe=/usr/bin/python3.9 comm=dnf : all\n\
              deny_audit perm=any pattern=ld_so : all\n",
        )
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
            let o = analyze(input.as_bytes(), None, Some(&ld_so()), &[], None);
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
        let rules = vec![rules::Rule::new("deny_audit perm=execute all : all")];
        let input = b"rule=1 dec=deny_audit perm=execute pid=1 exe=/usr/bin/bash : \
                      path=/tmp/gaps/trusted-ls trust=1\n";
        let o = analyze(input, None, Some(&rules), &[], None);
        let text = notes(&o);
        assert!(o.rules.starts_with(b"allow perm=execute"), "{text}");
        assert!(text.contains("not read"), "generic note: {text}");
        assert!(!text.contains("does not match"), "{text}");
    }

    #[test]
    fn an_unprefixed_file_is_named_a_filename_not_declined() {
        // `local.rules` sorts last of all, so any numbered name sorts before it.
        let rule = rules::Rule::new("deny_audit perm=execute all : all");
        let rules_d = vec![rules_d::File {
            name: "local.rules".into(),
            rules: vec![rule.clone()],
            sets: Vec::new(),
        }];
        let input = b"rule=1 dec=deny_audit perm=execute pid=1 exe=/usr/bin/bash : \
                      path=/tmp/gaps/trusted-ls trust=1\n";
        let o = analyze(input, None, Some(&[rule]), &rules_d, None);
        let text = notes(&o);
        assert!(
            text.contains(
                "new file: rules.d/1-rulesteward.rules (sorts before local.rules, rule=1)"
            ),
            "{text}"
        );
    }

    /// D-d: one line per distinct denial, in first-seen order, with a count. A real log
    /// repeats one denial thousands of times and the verdict for all of them is the same,
    /// so repeating the line would bury the one that differs.
    #[test]
    fn the_check_report_is_one_line_per_denial_with_the_repeats_counted() {
        let rule = rules::Rule::new("deny_audit perm=execute all : all");
        let host = vec![rules_d::File {
            name: "90-deny-execute.rules".into(),
            rules: vec![rule.clone()],
            sets: Vec::new(),
        }];
        let mut proposed = vec![rules_d::File {
            name: "00-cand.rules".into(),
            rules: vec![rules::Rule::new(
                "allow perm=execute all : path=/tmp/gaps/trusted-ls",
            )],
            sets: Vec::new(),
        }];
        proposed.extend(host.clone());
        let denial = "rule=1 dec=deny_audit perm=execute pid=1 exe=/usr/bin/bash : \
                      path=/tmp/gaps/trusted-ls trust=1\n";
        let other = denial.replace("trusted-ls", "other-ls");
        let input = format!("{denial}{other}{denial}");
        let o = analyze(
            input.as_bytes(),
            None,
            Some(&[rule]),
            &host,
            Some(check::Proposal::Merged(&proposed)),
        );
        let report = String::from_utf8(o.check.clone()).unwrap();
        let lines: Vec<&str> = report.lines().collect();
        assert_eq!(lines.len(), 2, "two distinct denials: {report}");
        assert!(
            lines[0].starts_with("allowed ") && lines[0].contains("(2 denials)"),
            "the repeat is counted, not repeated: {report}"
        );
        assert!(
            lines[1].starts_with("denied ") && lines[1].contains("(1 denials)"),
            "and the second denial keeps its own line: {report}"
        );
    }

    /// #120 `subjectside-before-N`: a candidate ahead of a subject-side rule N allowed the
    /// access, so `check` gives the record a verdict and never the refusal comment.
    #[test]
    fn check_gives_a_subject_side_denial_a_verdict_and_no_refusal() {
        let input = b"rule=5 dec=deny_audit perm=open pid=1 exe=/usr/bin/bash : \
                      path=/usr/bin/grep trust=1\n";
        let o = analyze(
            input,
            None,
            Some(&ld_so()),
            &[],
            Some(check::Proposal::Merged(&[])),
        );
        assert!(o.diagnostics.is_empty(), "{:?}", o.diagnostics);
        assert!(o.check.starts_with(b"unknown "), "{:?}", o.check);
        assert!(o.rules.is_empty() && o.trust.is_empty());
    }

    #[test]
    fn a_rule_number_the_file_does_not_have_is_one_note_and_v1_behaviour() {
        let input = b"rule=99 dec=deny_audit perm=open pid=1 exe=/usr/bin/bash : \
                      path=/tmp/x trust=0\n";
        let o = analyze(input, None, Some(&ld_so()), &[], None);
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
        let rules = rules::parse(
            b"allow perm=any uid=0 : dir=/var/tmp/\n\
              allow perm=any uid=0 trust=1 : all\n\
              allow perm=open exe=/usr/bin/rpm : all\n",
        );
        let input = b"rule=3 dec=deny_audit perm=open pid=1 exe=/usr/bin/bash : \
                      path=/tmp/x trust=0\n";
        let o = analyze(input, None, Some(&rules), &[], None);
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
        let o = analyze(input, None, Some(&ld_so()), &[], None);
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
        let o = analyze(input.as_bytes(), None, None, &[], None);
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
        let o = analyze(input.as_bytes(), None, None, &[], None);
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
        let o = analyze(input, None, None, &[], None);
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

    /// `why`'s three verdict shapes in one run: a subject-side refusal, a rule that
    /// produced both kinds of suggestion, and one that produced neither.
    #[test]
    fn the_why_report_names_a_verdict_per_rule_in_number_order() {
        let rules = rules::parse(
            b"deny_audit perm=any pattern=ld_so : all\n\
              deny_audit perm=open all : all\n\
              deny_audit perm=execute all : all\n",
        );
        let input = b"rule=1 dec=deny_audit perm=open pid=1 exe=/usr/bin/bash : \
                      path=/tmp/ld trust=0\n\
                      rule=2 dec=deny_audit perm=open pid=1 exe=/usr/bin/bash : \
                      path=/tmp/untrusted trust=0\n\
                      rule=2 dec=deny_audit perm=open pid=1 exe=/usr/bin/bash : \
                      path=/tmp/trusted trust=1\n\
                      rule=3 dec=deny_audit perm=execute pid=1 exe=/usr/bin/bash : \
                      path=/tmp/unknown trust=9\n";
        let o = analyze(input, None, Some(&rules), &[], None);
        assert_eq!(
            String::from_utf8(o.why.clone()).unwrap(),
            "rule=1  1 denials  subject-side, nothing to emit  \
             deny_audit perm=any pattern=ld_so : all\n\
             rule=2  2 denials  rules: 1, trust: 1             \
             deny_audit perm=open all : all\n\
             rule=3  1 denials  nothing to emit                \
             deny_audit perm=execute all : all\n"
        );
    }

    #[test]
    fn a_why_line_without_a_rules_file_is_the_number_and_the_count() {
        // No rules file means no filename, no verdict and no text for any row, so all
        // three columns collapse along with their separators and nothing trails.
        let input = b"rule=1 dec=deny_audit perm=open pid=1 exe=/usr/bin/bash : \
                      path=/tmp/a trust=0\n\
                      rule=1 dec=deny_audit perm=open pid=1 exe=/usr/bin/bash : \
                      path=/tmp/b trust=0\n";
        let o = analyze(input, None, None, &[], None);
        assert_eq!(
            String::from_utf8(o.why.clone()).unwrap(),
            "rule=1  2 denials\n"
        );
    }

    #[test]
    fn one_long_rule_text_lengthens_its_own_line_and_shifts_no_column() {
        // The text is the only free-form column, so it goes last and pads nothing: an
        // outlier makes its own line longer and leaves every other line untouched.
        let rules = rules::parse(
            b"deny_audit perm=open all : all\n\
              deny_audit perm=open all : ftype=application/x-sharedlib,application/x-executable,text/x-shellscript\n",
        );
        let input = b"rule=1 dec=deny_audit perm=open pid=1 exe=/usr/bin/bash : \
                      path=/tmp/a trust=0\n\
                      rule=2 dec=deny_audit perm=open pid=1 exe=/usr/bin/bash : \
                      path=/tmp/b trust=0\n";
        let o = analyze(input, None, Some(&rules), &[], None);
        let why = String::from_utf8(o.why.clone()).unwrap();
        let lines: Vec<&str> = why.lines().collect();
        assert_eq!(lines.len(), 2, "{why}");
        assert_eq!(
            lines[0].find("denials"),
            lines[1].find("denials"),
            "counts are not aligned: {why}"
        );
        assert!(
            lines[1].len() > lines[0].len() + 40,
            "the long text must lengthen only its own line: {why}"
        );
    }
}
