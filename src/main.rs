//! `rulesteward` — audit2why/audit2allow for host policy systems.
//!
//! This binary is the only place in the tree permitted to touch fs, io, env or the
//! clock (DESIGN.md §3). Everything under `fapolicyd/` is a pure function of its
//! input and returns diagnostics as data.

mod cli;
mod fapolicyd;

use clap::Parser;
use cli::{Cli, Domain, FapolicydAction};
use fapolicyd::model::{Artifact, Diagnostic};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;

/// DESIGN.md §9. `0` success, `1` usage or I/O error, `2` input consumed but
/// unparseable. Note that clap's own default for a usage error is `2`, which §9
/// reserves for unparseable input — hence `try_parse` and the explicit mapping in
/// `main`, rather than letting clap exit on our behalf. `rules`, `trust` and `why` map
/// the same way: an empty artifact is still exit `0`.
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
             usage: rulesteward fapolicyd [--conf <PATH> | --no-conf] <rules|trust|why>"
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
    let (syslog_format, conf_note, rules, rules_note, rules_d) = if no_conf {
        (None, None, None, None, Vec::new())
    } else {
        let (f, fnote) = match read_syslog_format(conf.as_deref()) {
            Ok(fields) => (Some(fields), None),
            Err(note) => (None, Some(note)),
        };
        // Every `Err` from `read_rules` is a read that produced no rules at all, which
        // is the same thing as compiled.rules not winning.
        let (r, rnote, compiled) = match read_rules(conf.as_deref()) {
            Ok((rules, won)) => (Some(rules), None, won),
            Err(note) => (None, Some(note), false),
        };
        // Only when compiled.rules won. A legacy fapolicyd.rules is what the daemon
        // enforced, so whatever rules.d/ holds is not where that rule= came from.
        let d = if compiled {
            fapolicyd::rules_d::files(read_rules_d(conf.as_deref()))
        } else {
            Vec::new()
        };
        (f, fnote, r, rnote, d)
    };

    let outcome = fapolicyd::analyze(&input, syslog_format.as_deref(), rules.as_deref(), &rules_d);

    // `why` has no artifact of its own to keep diagnostics for, so `None` means
    // "run-level only": every diagnostic that describes the run rather than a line.
    let (wanted, artifact) = match action {
        FapolicydAction::Rules => (Some(Artifact::Rules), &outcome.rules),
        FapolicydAction::Trust => (Some(Artifact::Trust), &outcome.trust),
        FapolicydAction::Why => (None, &outcome.why),
    };
    let mut bytes = Vec::new();
    // The conf and rules reads happen here and not in the pass, so their notes arrive
    // as strings and become comments exactly like the pass's own. Both describe the
    // host rather than a suggestion, so both are `Both`.
    let host_notes = conf_note
        .into_iter()
        .chain(rules_note)
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

/// The daemon's `open_file()`: /etc/fapolicyd/fapolicyd.rules first, compiled.rules
/// only when that open fails (research `rule-files.md`). The daemon never opens
/// rules.d/ either, so the bool beside the rules is "compiled.rules won", which is the
/// only case where reading rules.d/ says anything about the rule that denied.
///
/// Nothing here is a failure and everything is a note: the packaged /etc/fapolicyd is
/// mode 750 root:fapolicyd, so this read failing is the ordinary case. There is also no
/// unparsable case, because every line that is not blank, `#` or `%set` is a rule.
fn read_rules(
    conf: Option<&std::path::Path>,
) -> Result<(Vec<fapolicyd::rules::Rule>, bool), String> {
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
    Ok((rules, won))
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
