//! The command surface: the clap types and the two `--help` epilogues, DESIGN.md §9.
//!
//! Its own file so `build.rs` can `#[path]`-include it and render the man page and the
//! bash completion from the same definitions the binary parses with. That include is
//! why this file stays self-contained: `clap` and `std::path` only, nothing from
//! `fapolicyd/` and nothing from `main.rs`.

use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "rulesteward",
    version,
    about = "Turn host policy denial records into the rules that would allow them",
    // §9: the domain slot must stay spendable. clap v4 already defaults
    // `infer_subcommands` to false, so `rulesteward fapo rules` is rejected; this
    // is stated rather than set so nobody "helpfully" turns inference on.
    subcommand_required = true
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

        /// How to write the result: the report, or the JSON document DESIGN.md §9.1
        /// describes. `json` and `json-compact` differ in whitespace and nothing else.
        /// Every action writes one.
        #[arg(
            long,
            value_enum,
            default_value_t = Format::Text,
            global = true,
            value_name = "FORMAT"
        )]
        format: Format,

        #[command(subcommand)]
        action: FapolicydAction,
    },
}

/// `--format`'s three values. A domain flag like `--conf` (D9, DESIGN.md §9), so it is
/// accepted on either side of the action and a second action inherits it.
#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Format {
    /// The bare result lines plus `# rulesteward:` comments.
    Text,
    /// One indented JSON document.
    Json,
    /// The same document on one line, for a consumer reading a stream of them.
    JsonCompact,
}

/// One result each (DESIGN.md §9). All four run the same pass over the same input; what
/// differs is which part of its answer is written, so a log needing two of them is two
/// runs. `rules` and `trust` are the audit2allow half and write artifacts a target reads;
/// `why` and `check` are the audit2why half and write a report for the reader.
#[derive(Subcommand)]
pub enum FapolicydAction {
    /// Read denial records on stdin, write a rules.d fragment on stdout.
    // The two D12 advisories are the same on every run, so they are printed by
    // `--help` and not beside the rule (DESIGN.md §8.1).
    #[command(after_long_help = RULES_AFTER_LONG_HELP)]
    Rules {
        /// Replace N or more rules that share a perm, an exe and a parent directory with
        /// one dir= rule for that directory. Defaults to 5 when the flag is given no
        /// value. A dir= rule allows every path under that directory, which is more than
        /// the log showed, so the comment above each one names every path it replaced.
        #[arg(
            long,
            value_name = "N",
            num_args = 0..=1,
            default_missing_value = "5",
            // Below 2 there is no group: one path would become a whole subtree.
            value_parser = clap::builder::RangedU64ValueParser::<usize>::new().range(2..),
        )]
        dir_min: Option<usize>,

        /// Group under a directory the system shares too -- /usr/bin, /etc, /opt, /tmp
        /// and the rest -- which --dir-min alone refuses. On one of those, a dir= rule
        /// allows every path any package or any other user has put there, so give this
        /// only when allowing the whole directory is what you mean.
        #[arg(long, requires = "dir_min")]
        dir_system: bool,
    },
    /// Read denial records on stdin, write fapolicyd-cli trust commands on stdout.
    #[command(after_long_help = TRUST_AFTER_LONG_HELP)]
    Trust,
    /// Read denial records on stdin, write one line per denying rule on stdout: number,
    /// rules.d file, text, denial count and verdict.
    #[command(after_long_help = WHY_AFTER_LONG_HELP)]
    Why,
    /// Read denial records on stdin, write one line per denial on stdout saying whether
    /// the candidate rules would have allowed it: allowed, denied or unknown. With no
    /// PATH the candidates are the host's own rules.d/ as it is on disk now.
    #[command(after_long_help = CHECK_AFTER_LONG_HELP)]
    Check {
        /// A rules file to merge into the host's rules.d/, or a whole proposed rules.d/
        /// directory to use in its place. Omit it to check the host's own rules.d/ beside
        /// --conf against the rules the daemon loaded.
        #[arg(value_name = "PATH")]
        path: Option<PathBuf>,
    },
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

/// The three verdicts and the one thing a reader must not conclude from `unknown`. Both
/// are properties of the action and not of an input, so they belong here.
const CHECK_AFTER_LONG_HELP: &str = "\
Reading the verdicts:
  allowed  a candidate that the daemon reaches before the rule that denied
           matches this record, and it is an allow rule.
  denied   the first candidate to match is a deny rule, or none matches and the
           rule that denied denies again.
  unknown  the candidates cannot be evaluated against this record. The line names
           the reason: an attribute no log record can decide (pattern=, uid=,
           sha256hash=, a dir= keyword), a candidate with no perm= or a %set the
           daemon will not load (either fails the reload and discards the whole
           ruleset), a rules.d/ that no longer agrees with
           compiled.rules, or a record whose exe= this tool had to rewrite.

  unknown is not \"denied\". It is the one answer that is never wrong, and a
  verdict this tool will not guess at is one to test on a host.

What PATH is:
  a *.rules file, merged into the host's rules.d/ under its own name -- the
  filename decides where it lands in the merged order, so 00-new.rules is
  reached before every shipped rule and 99-new.rules after all of them. Or a
  directory, used as the whole proposed rules.d/ in place of the host's.

  The host's own rules.d/ and compiled.rules are read beside --conf, exactly as
  the other actions read them; --no-conf leaves every verdict unknown.

With no PATH:
  the candidates are the host's own rules.d/ beside --conf, as it is on disk
  now, and the baseline is compiled.rules -- what the daemon actually loaded.
  That is the question an operator who edited rules.d/ in place and has not run
  fagenrules yet is asking. A rules.d/ that still merges to compiled.rules
  proposes nothing and says so. --no-conf gives it nowhere to read from and is
  a usage error.";

/// What the rule number in the report is, since the report is built around it.
const WHY_AFTER_LONG_HELP: &str = "\
Reading the report:
  rule=N in a record is that rule's position in compiled.rules (or
  fapolicyd.rules) counting every line that is not blank, a comment or a %set;
  fagenrules --check shows the merged order.";
