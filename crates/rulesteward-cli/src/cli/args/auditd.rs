use clap::Parser;
use std::path::PathBuf;

use crate::cli::{HumanJsonCsvFormat, HumanJsonFormat, TargetSelector};

/// Arguments for `rulesteward auditd cost` (#85).
///
/// Calculates the estimated cost and volume of auditd event traffic.
#[derive(Debug, Parser)]
pub struct CostArgs {
    /// auditd rules file or directory to analyze.
    #[arg(long, value_name = "DIR")]
    pub rules: PathBuf,

    /// Measure real per-key event rate AND per-event size from a captured audit
    /// log (optional).
    ///
    /// Both the per-key event RATE and the per-event SIZE are measured from the
    /// log (issue #307): each event's on-disk bytes -- the SYSCALL record plus its
    /// companion PATH/CWD/EOE records sharing one serial -- are summed and
    /// attributed to that event's key, so execve-heavy logs are sized by their
    /// real bytes instead of the flat ~1200 B ENRICHED assumption. Supply this to
    /// replace the assumed rates and byte size with this host's measured values.
    #[arg(long, value_name = "FILE")]
    pub from_log: Option<PathBuf>,

    /// USD per decimal GB (10^9 bytes), printed with currency in output.
    #[arg(long, value_name = "USD", default_value_t = 5.00)]
    pub price_per_gb: f64,

    /// (not yet implemented) emit noise-reduction recommendations.
    ///
    /// Currently a no-op: prints a `[NOT YET IMPLEMENTED]` notice to stderr and
    /// exits 0 with unchanged stdout (no recommendations are produced).
    #[arg(long)]
    pub recommend: bool,

    /// Output format (human | json | csv).
    ///
    /// `csv` emits the flat per-rule table only; the aggregate totals and the
    /// confidence note stay on the human and JSON surfaces (#64 / CC-3).
    #[arg(long, value_enum, default_value_t = HumanJsonCsvFormat::Human)]
    pub format: HumanJsonCsvFormat,
}

/// Arguments for `rulesteward auditd lint` (#193, session 6a).
#[derive(Debug, Parser)]
pub struct AuditdLintArgs {
    /// The audit rules to lint: a rules.d/ directory (analyzed in augenrules
    /// load order) or a single .rules file (defaults to /etc/audit/rules.d/)
    #[arg(value_name = "PATH")]
    pub path: Option<PathBuf>,

    /// Output format (human | json; SARIF and CSV are not offered for this
    /// verb per the locked output contracts CC-3/CC-4).
    #[arg(long, value_enum, default_value_t = HumanJsonFormat::Human)]
    pub format: HumanJsonFormat,

    /// Also fold `AppArmor` msgtype record names (`APPARMOR_DENIED`, etc.).
    /// Enable when linting rules for an AppArmor-enabled audit build
    /// (Debian/Ubuntu); off by default (RHEL/fapolicyd targets do not
    /// recognize these names).
    #[arg(long)]
    pub apparmor: bool,

    /// Target RHEL release for the STIG missing-audit-rule baseline
    /// (auto|rhel8|rhel9|rhel10). Enables the version-aware `au-W06` check: an
    /// audit rule the selected release's STIG requires but this ruleset does
    /// not contain (or contains with a different key) is flagged. `auto`
    /// detects the release from the host's /etc/os-release, falling back
    /// (with a warning) to version-agnostic when detection fails. With no
    /// `--target`, au-W06 does not run (version-agnostic: every other au-
    /// code still does).
    #[arg(long, value_enum)]
    pub target: Option<TargetSelector>,
}
