//! `rulesteward` — audit2why/audit2allow for host policy systems.
//!
//! This binary is the only place in the tree permitted to touch fs, io, env or the
//! clock (DESIGN.md §3). Everything under `fapolicyd/` is a pure function of its
//! input and returns diagnostics as data.

mod fapolicyd;

use clap::{Parser, Subcommand};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;

/// DESIGN.md §9. `0` success, `1` usage or I/O error, `2` input consumed but
/// unparseable. Note that clap's own default for a usage error is `2`, which §9
/// reserves for unparseable input — hence `try_parse` and the explicit mapping in
/// `main`, rather than letting clap exit on our behalf.
const EXIT_OK: u8 = 0;
const EXIT_USAGE: u8 = 1;
const EXIT_UNPARSEABLE: u8 = 2;

#[derive(Parser)]
#[command(
    name = "rulesteward",
    version,
    about = "Turn host policy denial records into the rules that would allow them",
    // §9: the domain slot must stay spendable. clap v4 already defaults
    // `infer_subcommands` to false, so `rulesteward fapo analyze` is rejected; this
    // is stated rather than set so nobody "helpfully" turns inference on.
    subcommand_required = true,
    arg_required_else_help = false
)]
struct Cli {
    #[command(subcommand)]
    domain: Domain,
}

#[derive(Subcommand)]
enum Domain {
    /// Analyse fapolicyd denial records.
    ///
    /// --conf and --no-conf belong to this domain, not to the action and not to the
    /// root (D9, DESIGN.md §9), so they are accepted on either side of the action and
    /// a second action inherits them.
    Fapolicyd {
        /// Path to fapolicyd.conf, for truncation detection (DESIGN.md §6).
        #[arg(long, value_name = "PATH", global = true)]
        conf: Option<PathBuf>,

        /// Skip the conf read entirely. Correct when the log came from another host:
        /// validating against the wrong host's syslog_format is worse than none.
        #[arg(long, global = true)]
        no_conf: bool,

        #[command(subcommand)]
        action: FapolicydAction,
    },
}

#[derive(Subcommand)]
enum FapolicydAction {
    /// Read denial records on stdin, write rules and fapolicyd-cli commands on stdout.
    Analyze,
}

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
        } => match action {
            FapolicydAction::Analyze => run_fapolicyd_analyze(conf, no_conf),
        },
    }
}

fn run_fapolicyd_analyze(conf: Option<PathBuf>, no_conf: bool) -> ExitCode {
    // clap's own `conflicts_with` only fires when both flags land in the same
    // subcommand's matches: `--no-conf analyze --conf X` is split across two levels
    // and slips straight through it. The conflict is checked by hand instead, so all
    // four orderings are rejected the same way.
    if no_conf && conf.is_some() {
        let _ = writeln!(
            std::io::stderr().lock(),
            "rulesteward: --no-conf cannot be used with --conf <PATH>\n\
             usage: rulesteward fapolicyd [--conf <PATH> | --no-conf] analyze"
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
    let (syslog_format, conf_note, rules, rules_note) = if no_conf {
        (None, None, None, None)
    } else {
        let (f, fnote) = read_syslog_format(conf.as_deref());
        let (r, rnote) = read_rules(conf.as_deref());
        (f, fnote, r, rnote)
    };

    let outcome = fapolicyd::analyze(&input, syslog_format.as_deref(), rules.as_deref());

    let mut err = std::io::stderr().lock();
    if let Some(note) = conf_note {
        let _ = writeln!(err, "rulesteward: {note}");
    }
    if let Some(note) = rules_note {
        let _ = writeln!(err, "rulesteward: {note}");
    }
    for d in &outcome.diagnostics {
        let _ = match d.line {
            Some(n) => writeln!(err, "rulesteward: line {n}: {}", d.msg),
            None => writeln!(err, "rulesteward: {}", d.msg),
        };
    }

    let mut out = std::io::stdout().lock();
    if let Err(e) = out.write_all(&outcome.stdout).and_then(|()| out.flush()) {
        // A closed pipe or a full disk means the suggestions never reached anyone.
        // Saying so on stderr is the difference between that and an empty answer.
        let _ = writeln!(err, "rulesteward: writing stdout: {e}");
        return ExitCode::from(EXIT_USAGE);
    }

    ExitCode::from(if outcome.consumed_but_unparseable {
        EXIT_UNPARSEABLE
    } else {
        EXIT_OK
    })
}

/// Returns the parsed `syslog_format` field list, plus a note when the read failed.
/// A failed read is never fatal: §6 step 2 expects `Permission denied` for any user
/// outside the `fapolicyd` group, because /etc/fapolicyd is mode 750 root:fapolicyd.
fn read_syslog_format(conf: Option<&std::path::Path>) -> (Option<Vec<String>>, Option<String>) {
    let path = conf.unwrap_or(std::path::Path::new(fapolicyd::DEFAULT_CONF_PATH));
    match std::fs::read(path) {
        Ok(bytes) => match fapolicyd::conf::syslog_format(&bytes) {
            Some(fields) => (Some(fields), None),
            None => (
                None,
                Some(format!(
                    "{} names no syslog_format; falling back to the 511-byte truncation test",
                    path.display()
                )),
            ),
        },
        Err(e) => (
            None,
            Some(format!(
                "cannot read {} ({e}); falling back to the 511-byte truncation test",
                path.display()
            )),
        ),
    }
}

/// The daemon's `open_file()`: /etc/fapolicyd/fapolicyd.rules first, compiled.rules
/// only when that open fails (research `rule-files.md`). Both from the conf's own
/// directory, because that is where the daemon's are. rules.d/ is never read — the
/// daemon never opens it either.
///
/// Nothing here is a failure and everything is a note: the packaged /etc/fapolicyd is
/// mode 750 root:fapolicyd, so this read failing is the ordinary case. There is also no
/// unparsable case, because every line that is not blank, `#` or `%set` is a rule.
fn read_rules(
    conf: Option<&std::path::Path>,
) -> (Option<Vec<fapolicyd::rules::Rule>>, Option<String>) {
    let path = conf.unwrap_or(std::path::Path::new(fapolicyd::DEFAULT_CONF_PATH));
    let dir = path.parent().unwrap_or(std::path::Path::new(""));
    let legacy = dir.join("fapolicyd.rules");
    let compiled = dir.join("compiled.rules");

    // `or_else` on the read and not on an existence test: the daemon's precedence is
    // "the first open that succeeds", so an unreadable fapolicyd.rules falls through
    // exactly as it does for the daemon. fapolicyd-cli --list instead refuses when both
    // exist; we mirror the daemon, because the rule=N in the record came from it.
    let (which, bytes) = match std::fs::read(&legacy) {
        Ok(bytes) => (&legacy, bytes),
        Err(_) => match std::fs::read(&compiled) {
            Ok(bytes) => (&compiled, bytes),
            Err(e) => {
                return (
                    None,
                    Some(format!(
                        "cannot read {} or {} ({e}); rule= will not be checked against a rule",
                        legacy.display(),
                        compiled.display()
                    )),
                );
            }
        },
    };

    let rules = fapolicyd::rules::parse(&bytes);
    if rules.is_empty() {
        return (
            None,
            Some(format!(
                "{} contains no rules; rule= will not be checked against a rule",
                which.display()
            )),
        );
    }
    (Some(rules), None)
}
