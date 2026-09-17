//! The command surface: the clap types and the two `--help` epilogues, DESIGN.md §9.
//!
//! Its own file so `build.rs` can `#[path]`-include it and render the man page and the
//! bash completion from the same definitions the binary parses with. That include is
//! why this file stays self-contained: `clap` and `std::path` only, nothing from
//! `fapolicyd/` and nothing from `main.rs`.

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "rulesteward",
    version,
    about = "Turn host policy denial records into the rules that would allow them",
    // §9: the domain slot must stay spendable. clap v4 already defaults
    // `infer_subcommands` to false, so `rulesteward fapo rules` is rejected; this
    // is stated rather than set so nobody "helpfully" turns inference on.
    subcommand_required = true,
    arg_required_else_help = false
)]
pub struct Cli {
    #[command(subcommand)]
    pub domain: Domain,
}

#[derive(Subcommand)]
pub enum Domain {
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

/// One result each (DESIGN.md §9). All three run the same pass over the same input;
/// what differs is which part of its answer is written, so a log needing two of them is
/// two runs. `rules` and `trust` are the audit2allow half and write artifacts a target
/// reads; `why` is the audit2why half and writes a report for the reader.
#[derive(Subcommand)]
pub enum FapolicydAction {
    /// Read denial records on stdin, write a rules.d fragment on stdout.
    // The two D12 advisories are the same on every run, so they are printed by
    // `--help` and not beside the rule (DESIGN.md §8.1).
    #[command(after_long_help = RULES_AFTER_LONG_HELP)]
    Rules,
    /// Read denial records on stdin, write fapolicyd-cli trust commands on stdout.
    #[command(after_long_help = TRUST_AFTER_LONG_HELP)]
    Trust,
    /// Read denial records on stdin, write one line per denying rule on stdout: number,
    /// rules.d file, text, denial count and verdict.
    #[command(after_long_help = WHY_AFTER_LONG_HELP)]
    Why,
}

/// `--help` only, never `-h`: standing advice, not a usage reminder.
const RULES_AFTER_LONG_HELP: &str = "\
Before adding the rule:
  A rule placed in /etc/fapolicyd/rules.d/ has no effect on a host that still
  has a legacy /etc/fapolicyd/fapolicyd.rules, and the daemon logs nothing about
  it. Check which file the daemon loads first.

  Validate the rules file before reloading and check the daemon afterwards:
  fapolicyd-cli --reload-rules exits 0 even when the reload crashed the daemon or
  left it allowing everything.

Where the rule goes:
  rules.d/ is merged in filename order (natural sort, `ls -1v`: 2- before 10-,
  unprefixed files last) and the first match wins, so the new file must sort
  before the file holding the rule that denied. rule=N in a record is that rule's
  position in compiled.rules with %set lines dropped, and fagenrules --check
  shows the merged order.";

/// DESIGN.md §8.3. Both facts are properties of fapolicyd-cli and not of the input, so
/// they belong here rather than beside every trust entry.
const TRUST_AFTER_LONG_HELP: &str = "\
Before running these commands:
  fapolicyd-cli --file add writes the trust file and contacts no daemon; the
  running daemon only picks the entry up after fapolicyd-cli --update, which is
  why both are emitted.

  --file add rewrites its destination file with \"w\", so any comments you have
  hand-written into fapolicyd.trust or a trust.d/ fragment are destroyed. Do not
  annotate those files.";

/// What the rule number in the report is, since the report is built around it.
const WHY_AFTER_LONG_HELP: &str = "\
Reading the report:
  rule=N in a record is that rule's position in compiled.rules (or
  fapolicyd.rules) counting every line that is not blank, a comment or a %set;
  fagenrules --check shows the merged order.";
