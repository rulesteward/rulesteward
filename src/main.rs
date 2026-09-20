//! `rulesteward` — audit2why/audit2allow for host policy systems.
//!
//! This binary is the only place in the tree permitted to touch fs, io, env or the
//! clock (DESIGN.md §3). Everything under `fapolicyd/` is a pure function of its
//! input and returns diagnostics as data.

mod cli;
mod fapolicyd;

use clap::Parser;
use cli::{Cli, Domain, FapolicydAction};
use fapolicyd::check::Proposal;
use fapolicyd::model::{Artifact, Diagnostic};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;

/// DESIGN.md §9. `0` success, `1` usage or I/O error, `2` input consumed but
/// unparseable. Note that clap's own default for a usage error is `2`, which §9
/// reserves for unparseable input — hence `try_parse` and the explicit mapping in
/// `main`, rather than letting clap exit on our behalf. All four actions map the same
/// way: an empty artifact is still exit `0`, and `check`'s unreadable `<PATH>` is `1`
/// because no candidate was read at all.
const EXIT_OK: u8 = 0;
const EXIT_USAGE: u8 = 1;
const EXIT_UNPARSEABLE: u8 = 2;

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(e) => {
            // --help and --version arrive here as "errors" and are successes.
            let ok = matches!(
                e.kind(),
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
            );
            let _ = e.print();
            return ExitCode::from(if ok { EXIT_OK } else { EXIT_USAGE });
        }
    };

    match cli.domain {
        Domain::Fapolicyd {
            conf,
            no_conf,
            action,
        } => run_fapolicyd(conf, no_conf, action),
    }
}

/// The one writer in the tree. Diagnostics go to stdout as `#` comments ahead of the
/// artifact they explain, so `rulesteward fapolicyd rules > 89-rulesteward.rules` is a
/// file the daemon reads and the notes are its header. stderr carries errors only: the
/// flag conflict, the stdin read and the stdout write, each of which means the user
/// has no artifact at all.
fn run_fapolicyd(conf: Option<PathBuf>, no_conf: bool, action: FapolicydAction) -> ExitCode {
    // clap's own `conflicts_with` only fires when both flags land in the same
    // subcommand's matches: `--no-conf rules --conf X` is split across two levels
    // and slips straight through it. The conflict is checked by hand instead, so all
    // four orderings are rejected the same way.
    if no_conf && conf.is_some() {
        let _ = writeln!(
            std::io::stderr().lock(),
            "rulesteward: --no-conf cannot be used with --conf <PATH>\n\
             usage: rulesteward fapolicyd [--conf <PATH> | --no-conf] \
             <rules|trust|why|check <PATH>>"
        );
        return ExitCode::from(EXIT_USAGE);
    }

    // #158: with no PATH the candidates are the rules.d/ beside --conf, which --no-conf
    // does not read. There is no useful degradation — every verdict would be unknown
    // against a directory nothing was read from — so it is a usage error naming both ways
    // out, like the conflict above.
    if no_conf && matches!(action, FapolicydAction::Check { path: None }) {
        let _ = writeln!(
            std::io::stderr().lock(),
            "rulesteward: check with no PATH reads the rules.d/ beside --conf, \
             which --no-conf skips\n\
             usage: name a PATH to check, or drop --no-conf"
        );
        return ExitCode::from(EXIT_USAGE);
    }

    let mut input = Vec::new();
    if let Err(e) = std::io::stdin().lock().read_to_end(&mut input) {
        let _ = writeln!(std::io::stderr().lock(), "rulesteward: reading stdin: {e}");
        return ExitCode::from(EXIT_USAGE);
    }

    // D1's ladder, step 1 and 2 (DESIGN.md §6). The read lives here so the libraries
    // stay pure; they receive an already-parsed field list or nothing at all.
    let (syslog_format, conf_note, rules, rules_note, loaded_sets, listing, compiled) = if no_conf {
        (None, None, None, None, Vec::new(), Vec::new(), false)
    } else {
        let (f, fnote) = match read_syslog_format(conf.as_deref()) {
            Ok(fields) => (Some(fields), None),
            Err(note) => (None, Some(note)),
        };
        // Every `Err` from `read_rules` is a read that produced no rules at all, which
        // is the same thing as compiled.rules not winning.
        let (r, rnote, loaded_sets, compiled) = match read_rules(conf.as_deref()) {
            Ok((rules, sets, won)) => (Some(rules), None, sets, won),
            Err(note) => (None, Some(note), Vec::new(), false),
        };
        // Only when compiled.rules won. A legacy fapolicyd.rules is what the daemon
        // enforced, so whatever rules.d/ holds is not where that rule= came from.
        let d = if compiled {
            read_rules_d(conf.as_deref())
        } else {
            Vec::new()
        };
        (f, fnote, r, rnote, loaded_sets, d, compiled)
    };

    // The candidate read (#121), before the host listing is merged, so `check` can sort
    // its file into the same listing rather than into a second merge order. Unreadable is
    // a usage error and not a note: the user named this path, and a verdict against rules
    // that were not read would be a verdict about nothing.
    let merged = match &action {
        FapolicydAction::Check { path: Some(path) } => match read_candidates(path, &listing) {
            Ok(named) => Some(fapolicyd::rules_d::files(named)),
            Err(e) => {
                let _ = writeln!(std::io::stderr().lock(), "rulesteward: {e}");
                return ExitCode::from(EXIT_USAGE);
            }
        },
        _ => None,
    };
    let rules_d = fapolicyd::rules_d::files(listing);
    // The directory's `%set` definitions against the ones the daemon loaded, in merge
    // order because fagenrules concatenates. A set is in no rule's text and in no rule
    // number, so this is the only place an edited one is visible at all; what it holds is
    // never expanded (#139), so the answer is a bool and the library refuses on it. Only
    // the no-PATH proposal is gated on it: the same hazard through a candidate `PATH` is
    // #139's too.
    let sets_agree = rules_d.iter().flat_map(|f| &f.sets).eq(&loaded_sets);
    // With no PATH the proposal is that same listing, read as it is on disk now (#158).
    let proposal = match (&action, merged.as_deref()) {
        (FapolicydAction::Check { .. }, Some(files)) => Some(Proposal::Merged(files)),
        (FapolicydAction::Check { .. }, None) => Some(Proposal::OnDisk { sets_agree }),
        _ => None,
    };

    // What the default PATH has to say for itself, both of them "nothing is proposed"
    // reached two ways: a legacy fapolicyd.rules is the file the daemon enforced, so
    // rules.d/ is not in effect at all, and a rules.d/ that still merges to
    // compiled.rules proposes nothing either — which is not the same answer as every
    // candidate having been checked and none matching.
    let default_note = match (&action, rules.as_deref()) {
        (FapolicydAction::Check { path: None }, Some(_)) if !compiled => Some(format!(
            "{} is the file the daemon loads, so rules.d/ is not in effect and nothing \
             is proposed",
            conf_dir(conf.as_deref()).join("fapolicyd.rules").display()
        )),
        // Rule for rule AND set for set: a `rules.d/` whose only edit is a `%set`
        // definition merges to the loaded rules and is not what the daemon loaded.
        (FapolicydAction::Check { path: None }, Some(loaded))
            if sets_agree && merges_to(&rules_d, loaded) =>
        {
            Some(format!(
                "{} merges to the rules the daemon loaded; nothing is proposed and every \
                 denial is denied again",
                conf_dir(conf.as_deref()).join("rules.d").display()
            ))
        }
        _ => None,
    };

    // Both grouping flags belong to `rules` and change only what it writes (#138), so
    // every other action passes the pair that means "one rule per denial".
    let (dir_min, dir_system) = match &action {
        FapolicydAction::Rules {
            dir_min,
            dir_system,
        } => (*dir_min, *dir_system),
        _ => (None, false),
    };

    let outcome = fapolicyd::analyze(
        &input,
        syslog_format.as_deref(),
        rules.as_deref(),
        &rules_d,
        proposal,
        dir_min,
        dir_system,
    );

    // `why` has no artifact of its own to keep diagnostics for, so `None` means
    // "run-level only": every diagnostic that describes the run rather than a line.
    let (wanted, artifact) = match action {
        FapolicydAction::Rules { .. } => (Some(Artifact::Rules), &outcome.rules),
        FapolicydAction::Trust => (Some(Artifact::Trust), &outcome.trust),
        FapolicydAction::Why => (None, &outcome.why),
        // `Both` rather than `None`: a check line is a verdict per record, so the
        // per-line diagnostics that say a record could not be used at all belong beside
        // it, while the notes about emitting a rule or a trust entry do not.
        FapolicydAction::Check { .. } => (Some(Artifact::Both), &outcome.check),
    };
    let mut bytes = Vec::new();
    // The conf and rules reads happen here and not in the pass, so their notes arrive
    // as strings and become comments exactly like the pass's own. Both describe the
    // host rather than a suggestion, so both are `Both`.
    let host_notes = conf_note
        .into_iter()
        .chain(rules_note)
        .chain(default_note)
        .map(|msg| Diagnostic {
            line: None,
            msg,
            artifact: Artifact::Both,
        });
    for d in host_notes.chain(outcome.diagnostics) {
        let keep = match wanted {
            Some(w) => d.artifact == w || d.artifact == Artifact::Both,
            None => d.line.is_none(),
        };
        if !keep {
            continue;
        }
        // Writing into a Vec cannot fail; the one write that can is below.
        let _ = match d.line {
            Some(n) => writeln!(bytes, "# rulesteward: line {n}: {}", d.msg),
            None => writeln!(bytes, "# rulesteward: {}", d.msg),
        };
    }
    bytes.extend_from_slice(artifact);

    let mut out = std::io::stdout().lock();
    if let Err(e) = out.write_all(&bytes).and_then(|()| out.flush()) {
        // A closed pipe or a full disk means the suggestions never reached anyone.
        // Saying so on stderr is the difference between that and an empty answer.
        let _ = writeln!(std::io::stderr().lock(), "rulesteward: writing stdout: {e}");
        return ExitCode::from(EXIT_USAGE);
    }

    ExitCode::from(if outcome.consumed_but_unparseable {
        EXIT_UNPARSEABLE
    } else {
        EXIT_OK
    })
}

/// Returns the parsed `syslog_format` field list, or a note when the read failed.
/// A failed read is never fatal: §6 step 2 expects `Permission denied` for any user
/// outside the `fapolicyd` group, because /etc/fapolicyd is mode 750 root:fapolicyd.
fn read_syslog_format(conf: Option<&std::path::Path>) -> Result<Vec<String>, String> {
    let path = conf.unwrap_or(std::path::Path::new(fapolicyd::DEFAULT_CONF_PATH));
    match std::fs::read(path) {
        Ok(bytes) => match fapolicyd::conf::syslog_format(&bytes) {
            Some(fields) => Ok(fields),
            None => Err(format!(
                "{} names no syslog_format; falling back to the 511-byte truncation test",
                path.display()
            )),
        },
        Err(e) => Err(format!(
            "cannot read {} ({e}); falling back to the 511-byte truncation test",
            path.display()
        )),
    }
}

/// The directory the daemon keeps its rules in: the conf's own, because that is where
/// the daemon's are.
fn conf_dir(conf: Option<&std::path::Path>) -> std::path::PathBuf {
    conf.unwrap_or(std::path::Path::new(fapolicyd::DEFAULT_CONF_PATH))
        .parent()
        .unwrap_or(std::path::Path::new(""))
        .to_path_buf()
}

/// Would fagenrules write exactly the rules the daemon loaded (#158)? Rule for rule and
/// in order, which is what fagenrules concatenates; a `%set` is in neither side, because
/// `rules::parse` drops it from both.
fn merges_to(files: &[fapolicyd::rules_d::File], loaded: &[fapolicyd::rules::Rule]) -> bool {
    files
        .iter()
        .flat_map(|f| &f.rules)
        .map(|r| &r.text)
        .eq(loaded.iter().map(|r| &r.text))
}

/// What the daemon loaded: its rules, the `%set` definitions beside them, and whether
/// `compiled.rules` is the file it came from.
type LoadedRules = (Vec<fapolicyd::rules::Rule>, Vec<Vec<u8>>, bool);

/// The daemon's `open_file()`: /etc/fapolicyd/fapolicyd.rules first, compiled.rules
/// only when that open fails (research `rule-files.md`). The daemon never opens
/// rules.d/ either, so the bool beside the rules is "compiled.rules won", which is the
/// only case where reading rules.d/ says anything about the rule that denied.
///
/// Nothing here is a failure and everything is a note: the packaged /etc/fapolicyd is
/// mode 750 root:fapolicyd, so this read failing is the ordinary case. There is also no
/// unparsable case, because every line that is not blank, `#` or `%set` is a rule.
///
/// The `%set` lines come back beside the rules, out of the same bytes: they are dropped
/// from the numbering but they decide what the rules naming them match, so #158 compares
/// them against the directory's own and this is the read that already has them.
fn read_rules(conf: Option<&std::path::Path>) -> Result<LoadedRules, String> {
    let dir = conf_dir(conf);
    let legacy = dir.join("fapolicyd.rules");
    let compiled = dir.join("compiled.rules");

    // `or_else` on the read and not on an existence test: the daemon's precedence is
    // "the first open that succeeds", so an unreadable fapolicyd.rules falls through
    // exactly as it does for the daemon. fapolicyd-cli --list instead refuses when both
    // exist; we mirror the daemon, because the rule=N in the record came from it.
    let (which, bytes, won) = match std::fs::read(&legacy) {
        Ok(bytes) => (&legacy, bytes, false),
        Err(_) => match std::fs::read(&compiled) {
            Ok(bytes) => (&compiled, bytes, true),
            Err(e) => {
                return Err(format!(
                    "cannot read {} or {} ({e}); rule= will not be checked against a rule",
                    legacy.display(),
                    compiled.display()
                ));
            }
        },
    };

    let rules = fapolicyd::rules::parse(&bytes);
    if rules.is_empty() {
        return Err(format!(
            "{} contains no rules; rule= will not be checked against a rule",
            which.display()
        ));
    }
    Ok((rules, fapolicyd::rules::sets(&bytes), won))
}

/// Every `rules.d/` component file beside the conf, in whatever order the directory
/// yields them, for `rules_d::files` to filter and sort. Not the daemon's read — the
/// daemon never opens these — but fagenrules' input, which is what says which file a
/// `rule=` came from.
///
/// Any error is an empty merge and no note: the directory is mode 750 like the rest of
/// /etc/fapolicyd, and a host that cannot be told which file denied still gets the
/// generic placement note. Nothing here is worth a second line of stderr.
fn read_rules_d(conf: Option<&std::path::Path>) -> Vec<(String, Vec<u8>)> {
    let Ok(entries) = std::fs::read_dir(conf_dir(conf).join("rules.d")) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|e| {
            Some((
                e.file_name().into_string().ok()?,
                std::fs::read(e.path()).ok()?,
            ))
        })
        .collect()
}

/// `check`'s candidate rules (#121): `path` as a whole proposed `rules.d/`, or one rules
/// file sorted into the host's listing under its own name.
///
/// The file form replaces the host's file of the same name and leaves the ordering to
/// `rules_d::files`, so the filename decides placement exactly as it does on the host and
/// there is no second merge order to keep honest. A name that does not end in `.rules` is
/// refused rather than checked, because fagenrules would not merge it and every verdict
/// from it would be about a file the daemon never reads.
///
/// Every error here is the user's own path, so all of them are `EXIT_USAGE` and none is a
/// note: unlike the host reads above, there is nothing to degrade to.
fn read_candidates(
    path: &std::path::Path,
    host: &[(String, Vec<u8>)],
) -> Result<Vec<(String, Vec<u8>)>, String> {
    let failed =
        |what: &std::path::Path, e: std::io::Error| format!("reading {}: {e}", what.display());

    if path.is_dir() {
        let mut named = Vec::new();
        for entry in std::fs::read_dir(path).map_err(|e| failed(path, e))? {
            let entry = entry.map_err(|e| failed(path, e))?;
            // read_dir yields directories too, and `files` filters by name only.
            if !entry.path().is_file() {
                continue;
            }
            let name = entry
                .file_name()
                .into_string()
                .map_err(|n| format!("{}: {n:?} is not a usable filename", path.display()))?;
            named.push((
                name,
                std::fs::read(entry.path()).map_err(|e| failed(&entry.path(), e))?,
            ));
        }
        return Ok(named);
    }

    // The read first: a path that does not exist deserves that answer and not a lecture
    // about its extension.
    let bytes = std::fs::read(path).map_err(|e| failed(path, e))?;
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default()
        .to_string();
    if !name.ends_with(".rules") {
        return Err(format!(
            "{}: a candidate file has to be named *.rules, or fagenrules will not merge it",
            path.display()
        ));
    }
    let mut named: Vec<(String, Vec<u8>)> =
        host.iter().filter(|(n, _)| *n != name).cloned().collect();
    named.push((name, bytes));
    Ok(named)
}
