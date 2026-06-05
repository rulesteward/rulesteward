//! clap derive definitions for the `rulesteward` CLI.
//!
//! Wired into the binary via `lib.rs` (added in Task 4) and `main.rs`
//! (rewritten in Task 11). Subcommand tree matches spec §6.1.

use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

// ---- Trust-DB subcommand format and filter enums ----
// ---- Shared format enum for explain / cost / triage (human|json only; no SARIF) ----

/// Output format for explain, cost, and triage subcommands.
///
/// Intentionally separate from `OutputFormat` (which carries a `Sarif` arm
/// that has no meaning for these operations) and from `TrustdbFormat` (kept
/// distinct for readability at each call site).
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum HumanJsonFormat {
    Human,
    Json,
}

/// Output format for the `report` subcommand (human | json | csv).
///
/// Distinct from `HumanJsonFormat`: `report` additionally supports a CSV
/// surface (one row per grant) via the generic `output::csv` helper.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum HumanJsonCsvFormat {
    Human,
    Json,
    Csv,
}

/// Output format for trust-DB subcommands.
///
/// Intentionally separate from `OutputFormat` (which carries a `Sarif` arm
/// that has no meaning for trust-DB operations).
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum TrustdbFormat {
    Human,
    Json,
}

/// Filter trust-DB entries by their source database.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum TrustSourceFilter {
    Rpm,
    File,
    Deb,
    Unknown,
}

#[derive(Debug, Parser)]
#[command(
    name = "rulesteward",
    version,
    about = "RuleSteward - fapolicyd / SELinux / auditd policy linter"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: TopCommand,
}

#[derive(Debug, Subcommand)]
pub enum TopCommand {
    /// fapolicyd rule operations
    #[command(subcommand)]
    Fapolicyd(FapolicydCommand),

    /// `SELinux` operations
    #[command(subcommand)]
    Selinux(SelinuxCommand),

    /// auditd operations
    #[command(subcommand)]
    Auditd(AuditdCommand),

    /// Print shell-completion script for the given shell
    Completions(CompletionsArgs),

    /// Generate the `rulesteward.1` man page into a directory (release tooling).
    /// Hidden: invoked by the release workflow, not an end-user command.
    #[command(hide = true)]
    Mangen(MangenArgs),
}

#[derive(Debug, Parser)]
pub struct MangenArgs {
    /// Directory to write `rulesteward.1` into (created if absent).
    #[arg(value_name = "OUTDIR")]
    pub outdir: PathBuf,
}

#[derive(Debug, Subcommand)]
pub enum FapolicydCommand {
    /// Lint fapolicyd rule files (unprivileged, no daemon)
    Lint(LintArgs),
    /// Simulate a workload against a rule set (which rule decides each access)
    Simulate(SimulateArgs),
    /// Explain a FANOTIFY denial from the audit log
    Explain(ExplainArgs),
    /// Build the exception register: every effective allow grant, with drift
    Report(ReportArgs),
    // The remaining no-op stubs below are hidden so the CLI does not advertise
    // commands that do nothing yet. NOTE: `hide` removes them from `--help` but
    // clap_complete 4.6.5 still lists them in generated completions (accepted
    // limitation; see e2e_completions.rs).
    /// (stub) Container-runtime detection
    #[command(hide = true)]
    ContainerCheck,
    /// Trust database operations (read-only)
    #[command(subcommand)]
    Trustdb(TrustdbCommand),
    /// (stub) Migrate legacy fapolicyd.rules to rules.d/
    #[command(hide = true)]
    Migrate,
    /// Run a composite health check on a live fapolicyd deployment.
    ///
    /// Runs 13 read-only checks and reports a pass/warn/fail scorecard.
    /// Exit 0 = all checks pass; 1 = warnings present; 2 = failures present.
    Doctor(DoctorArgs),
}

#[derive(Debug, Parser)]
pub struct LintArgs {
    /// Path to the rules.d/ directory to lint (defaults to /etc/fapolicyd/rules.d/)
    #[arg(value_name = "PATH")]
    pub path: Option<PathBuf>,

    /// Single-file mode - lint exactly this file
    #[arg(long, value_name = "FILE", conflicts_with = "path")]
    pub file: Option<PathBuf>,

    /// Output format
    #[arg(long, value_enum, default_value_t = OutputFormat::Human)]
    pub format: OutputFormat,

    /// Cross-check path=/exe= literals against this fapolicyd trust DB
    /// (read-only); enables fapd-W06 (path in neither trust DB nor on disk)
    #[arg(long, value_name = "PATH")]
    pub against_trustdb: Option<PathBuf>,

    /// Report trust-DB entries not referenced by any rule (fapd-X01). Requires
    /// `--against-trustdb`; off by default (a real trust DB lists ~every system file).
    #[arg(long)]
    pub report_orphans: bool,

    /// Target RHEL release for version-aware checks (rhel8/rhel9/rhel10). Omit to
    /// lint the version-agnostic dialect (no version-divergent diagnostics).
    #[arg(long, value_enum)]
    pub target: Option<TargetVersionArg>,

    /// Validate `uid=`/`gid=` literals against the host identity database via
    /// `getent` (read-only); enables fapd-W05. Off by default (the check spawns a
    /// `getent` subprocess that may query SSSD/LDAP/AD).
    #[arg(long)]
    pub check_identities: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum OutputFormat {
    Human,
    Json,
    Sarif,
}

/// CLI value-enum for `--target`. Mirrors the fapolicyd domain `TargetVersion`
/// so the domain crate stays clap-free (the same layering as
/// `TrustSourceFilter` -> `TrustSource`). The variant names are the accepted
/// `--target` values (`rhel8`/`rhel9`/`rhel10`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum TargetVersionArg {
    Rhel8,
    Rhel9,
    Rhel10,
}

impl From<TargetVersionArg> for rulesteward_fapolicyd::TargetVersion {
    fn from(arg: TargetVersionArg) -> Self {
        match arg {
            TargetVersionArg::Rhel8 => rulesteward_fapolicyd::TargetVersion::Rhel8,
            TargetVersionArg::Rhel9 => rulesteward_fapolicyd::TargetVersion::Rhel9,
            TargetVersionArg::Rhel10 => rulesteward_fapolicyd::TargetVersion::Rhel10,
        }
    }
}

/// Arguments for `rulesteward fapolicyd explain` (#72/#73/#74).
///
/// Explains a FANOTIFY denial record in the context of a rule set and
/// optional trust DB.
#[derive(Debug, Parser)]
pub struct ExplainArgs {
    /// The kernel FANOTIFY denial record or ausearch block to explain.
    #[arg(long, value_name = "FILE")]
    pub record: PathBuf,

    /// The rules.d/ directory the denial references.
    #[arg(long, value_name = "DIR")]
    pub ruleset: PathBuf,

    /// Read-only trust DB for replaying trust facts (optional).
    #[arg(long, value_name = "PATH")]
    pub trustdb: Option<PathBuf>,

    /// Output format.
    #[arg(long, value_enum, default_value_t = HumanJsonFormat::Human)]
    pub format: HumanJsonFormat,
}

/// Arguments for `rulesteward fapolicyd simulate` (spec §6.1).
///
/// Replays a workload of access attempts against a rule set (optionally with a
/// trust DB) and reports which rule decides each access. The body is
/// implemented in the `feat-simulate` pipeline; this struct is the frozen
/// Phase-0 arg contract.
#[derive(Debug, Parser)]
pub struct SimulateArgs {
    /// The rules.d/ directory to replay the workload against.
    #[arg(long, value_name = "DIR")]
    pub rules: PathBuf,

    /// Workload of access attempts to replay (`-` reads from stdin).
    #[arg(long, value_name = "FILE")]
    pub workload: PathBuf,

    /// Trust DB path (reserved; not yet consulted - see issue #127).
    ///
    /// The argument is accepted but the DB is not read this round: subject and
    /// object trust are taken from the workload's `trust`/`subjTrust`/`objTrust`
    /// fields (defaulting to Unknown when absent). Passing this flag emits a
    /// note on stderr so the caller knows the DB is not being used.
    #[arg(long, value_name = "PATH")]
    pub trustdb: Option<PathBuf>,

    /// Output format.
    #[arg(long, value_enum, default_value_t = HumanJsonFormat::Human)]
    pub format: HumanJsonFormat,
}

/// Arguments for `rulesteward fapolicyd report` (spec §6.1 + f2 §6).
///
/// Builds the exception register (every effective allow grant) and optionally
/// computes drift against a prior snapshot. The body is implemented in the
/// `feat-report` pipeline; this struct is the frozen Phase-0 arg contract.
/// Mirrors `LintArgs`' positional-`[PATH]` + `--file` target convention.
#[derive(Debug, Parser)]
pub struct ReportArgs {
    /// Path to the rules.d/ directory to report on (defaults to /etc/fapolicyd/rules.d/)
    #[arg(value_name = "PATH")]
    pub path: Option<PathBuf>,

    /// Single-file mode - report on exactly this file
    #[arg(long, value_name = "FILE", conflicts_with = "path")]
    pub file: Option<PathBuf>,

    /// Output format (human | json | csv).
    #[arg(long, value_enum, default_value_t = HumanJsonCsvFormat::Human)]
    pub format: HumanJsonCsvFormat,

    /// Cross-check grants against this read-only fapolicyd trust DB.
    #[arg(long, value_name = "DIR")]
    pub against_trustdb: Option<PathBuf>,

    /// Compute drift against a previously-written register snapshot (JSON).
    #[arg(long, value_name = "FILE")]
    pub diff_against: Option<PathBuf>,

    /// Exit non-zero when drift is detected (for CI gating).
    #[arg(long)]
    pub fail_on_drift: bool,

    /// Enumerate trust-DB entries referenced by grants in the report.
    #[arg(long)]
    pub enumerate_trust: bool,
}

/// Arguments for `rulesteward auditd cost` (#85).
///
/// Calculates the estimated cost and volume of auditd event traffic.
#[derive(Debug, Parser)]
pub struct CostArgs {
    /// auditd rules file or directory to analyze.
    #[arg(long, value_name = "DIR")]
    pub rules: PathBuf,

    /// Measure real event rate from a captured audit log (optional).
    #[arg(long, value_name = "FILE")]
    pub from_log: Option<PathBuf>,

    /// USD per decimal GB (10^9 bytes), printed with currency in output.
    #[arg(long, value_name = "USD", default_value_t = 5.00)]
    pub price_per_gb: f64,

    /// (not yet implemented) emit noise-reduction recommendations.
    #[arg(long)]
    pub recommend: bool,

    /// Output format.
    #[arg(long, value_enum, default_value_t = HumanJsonFormat::Human)]
    pub format: HumanJsonFormat,
}

/// Arguments for `rulesteward fapolicyd doctor` (#76/#77/#78).
///
/// Runs 13 read-only deployment health checks and reports a scorecard.
#[derive(Debug, Parser)]
pub struct DoctorArgs {
    /// Output format.
    #[arg(long, value_enum, default_value_t = HumanJsonFormat::Human)]
    pub format: HumanJsonFormat,

    /// Rules directory to lint as part of the health check
    /// (defaults to /etc/fapolicyd/rules.d/).
    #[arg(long, value_name = "DIR", hide = true)]
    pub rules_dir: Option<std::path::PathBuf>,
}

/// Arguments for `rulesteward selinux triage` (#94).
///
/// Triages `SELinux` AVC denials. The `--emit-te` flag activates te-emit mode
/// (emits a self-contained base-module `.te`) instead of a triage report.
/// te-emit is NOT a separate verb; it is a mode flag on triage.
///
/// At least one of `--audit-log` or `--record` must be supplied; this is
/// validated by the triage command at run time, not by clap, so neither
/// field is `required`.
#[derive(Debug, Parser)]
pub struct TriageArgs {
    /// Scan a full audit log for AVCs.
    #[arg(long, value_name = "FILE")]
    pub audit_log: Option<PathBuf>,

    /// A single AVC record file (mutually exclusive with --audit-log).
    ///
    /// At least one of --record or --audit-log must be supplied (validated at
    /// run time, not by clap; the command errors if neither is present).
    #[arg(long, value_name = "FILE", conflicts_with = "audit_log")]
    pub record: Option<PathBuf>,

    /// Time window to scan (e.g. 1h, 2d).
    #[arg(long, value_name = "WINDOW")]
    pub since: Option<String>,

    /// Output format.
    #[arg(long, value_enum, default_value_t = HumanJsonFormat::Human)]
    pub format: HumanJsonFormat,

    /// Emit a self-contained base-module .te instead of a triage report.
    #[arg(long)]
    pub emit_te: bool,

    /// Module name for the emitted .te (used with --emit-te).
    #[arg(long, value_name = "NAME")]
    pub module_name: Option<String>,

    /// Write output to FILE instead of stdout.
    #[arg(short = 'o', long = "output", value_name = "FILE")]
    pub output: Option<PathBuf>,
}

/// Trust-DB subcommands.
#[derive(Debug, Subcommand)]
pub enum TrustdbCommand {
    /// List entries from the trust DB
    List(TrustdbListArgs),
    /// Check whether specific paths match the trust DB
    Check(TrustdbCheckArgs),
    /// Diff trust-DB entries against on-disk reality or a second DB
    Diff(TrustdbDiffArgs),
    /// Report trust-DB entries whose paths no longer exist on disk
    Stale(TrustdbStaleArgs),
}

/// Arguments for `rulesteward fapolicyd trustdb list`.
#[derive(Debug, Parser)]
pub struct TrustdbListArgs {
    /// Path to the fapolicyd trust-DB directory (defaults to /var/lib/fapolicyd/)
    #[arg(value_name = "DIR")]
    pub db: Option<PathBuf>,

    /// Output format
    #[arg(long, value_enum, default_value_t = TrustdbFormat::Human)]
    pub format: TrustdbFormat,

    /// Filter entries by source database
    #[arg(long, value_enum)]
    pub source: Option<TrustSourceFilter>,
}

/// Arguments for `rulesteward fapolicyd trustdb check`.
#[derive(Debug, Parser)]
pub struct TrustdbCheckArgs {
    /// Path to the fapolicyd trust-DB directory
    #[arg(long, value_name = "DIR")]
    pub db: Option<PathBuf>,

    /// Paths to check against the trust DB
    #[arg(value_name = "PATH", required = true, num_args = 1..)]
    pub paths: Vec<PathBuf>,

    /// Output format
    #[arg(long, value_enum, default_value_t = TrustdbFormat::Human)]
    pub format: TrustdbFormat,
}

/// Arguments for `rulesteward fapolicyd trustdb diff`.
#[derive(Debug, Parser)]
pub struct TrustdbDiffArgs {
    /// Path to the fapolicyd trust-DB directory
    #[arg(long, value_name = "DIR")]
    pub db: Option<PathBuf>,

    /// Compare against a second trust DB instead of on-disk reality
    #[arg(long, value_name = "DIR")]
    pub against: Option<PathBuf>,

    /// Output format
    #[arg(long, value_enum, default_value_t = TrustdbFormat::Human)]
    pub format: TrustdbFormat,
}

/// Arguments for `rulesteward fapolicyd trustdb stale`.
#[derive(Debug, Parser)]
pub struct TrustdbStaleArgs {
    /// Path to the fapolicyd trust-DB directory
    #[arg(long, value_name = "DIR")]
    pub db: Option<PathBuf>,

    /// Output format
    #[arg(long, value_enum, default_value_t = TrustdbFormat::Human)]
    pub format: TrustdbFormat,
}

#[derive(Debug, Subcommand)]
pub enum SelinuxCommand {
    /// Triage `SELinux` AVCs
    Triage(TriageArgs),
}

#[derive(Debug, Subcommand)]
pub enum AuditdCommand {
    /// auditd cost calculator
    Cost(CostArgs),
}

#[derive(Debug, Parser)]
pub struct CompletionsArgs {
    /// Shell to generate completions for
    #[arg(value_enum)]
    pub shell: CompletionShell,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum CompletionShell {
    Bash,
    Zsh,
    Fish,
    Elvish,
    PowerShell,
    Tcsh,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// --against-trustdb <PATH> must still parse correctly (existing field, no regression).
    #[test]
    fn lint_args_against_trustdb_parses() {
        let cli = Cli::try_parse_from([
            "rulesteward",
            "fapolicyd",
            "lint",
            "somedir",
            "--against-trustdb",
            "/var/lib/fapolicyd",
        ]);
        assert!(
            cli.is_ok(),
            "--against-trustdb must parse successfully, got: {cli:?}"
        );
        if let Ok(Cli {
            command: TopCommand::Fapolicyd(FapolicydCommand::Lint(args)),
        }) = cli
        {
            assert_eq!(
                args.against_trustdb.as_deref(),
                Some(std::path::Path::new("/var/lib/fapolicyd")),
                "--against-trustdb value must round-trip"
            );
        } else {
            panic!("expected Fapolicyd(Lint(_))");
        }
    }

    /// --report-orphans must parse (field does not exist yet -> clap rejects the
    /// unknown flag -> `try_parse_from` returns Err -> `is_ok()` is FALSE -> RED at runtime).
    ///
    /// After the implementer adds `report_orphans: bool` to `LintArgs`, the
    /// `try_parse_from` call will succeed and `is_ok()` will be TRUE -> GREEN.
    #[test]
    fn lint_args_report_orphans_parses_and_defaults_false() {
        let cli = Cli::try_parse_from([
            "rulesteward",
            "fapolicyd",
            "lint",
            "somedir",
            "--report-orphans",
        ]);
        // RED: --report-orphans is an unknown flag until the field is added.
        assert!(
            cli.is_ok(),
            "--report-orphans must parse successfully once the field is added to LintArgs; \
             got: {cli:?}"
        );
        // GREEN (compile-coupled): verify the field value after parse succeeds.
        // NOTE: this arm does NOT compile until `report_orphans` is added to LintArgs.
        // The compile error is an acceptable RED signal.
        if let Ok(Cli {
            command: TopCommand::Fapolicyd(FapolicydCommand::Lint(args)),
        }) = cli
        {
            assert!(
                args.report_orphans,
                "--report-orphans flag must set report_orphans = true"
            );
        } else {
            panic!("expected Fapolicyd(Lint(_))");
        }
    }

    /// Default parse (no --report-orphans) must leave `report_orphans` = false.
    /// NOTE: compile-coupled to the `report_orphans` field existing on `LintArgs`.
    #[test]
    fn lint_args_report_orphans_defaults_false() {
        let cli = Cli::try_parse_from(["rulesteward", "fapolicyd", "lint", "somedir"]);
        assert!(cli.is_ok(), "plain lint parse must succeed: {cli:?}");
        // Compile-coupled: will not compile until `report_orphans` is in LintArgs.
        if let Ok(Cli {
            command: TopCommand::Fapolicyd(FapolicydCommand::Lint(args)),
        }) = cli
        {
            assert!(
                !args.report_orphans,
                "report_orphans must default to false when flag is absent"
            );
        } else {
            panic!("expected Fapolicyd(Lint(_))");
        }
    }

    // -- Section 3d: trustdb clap-contract tests (GREEN; the tree is frozen) --
    // These pin the frozen subcommand surface: a future edit that drops a verb,
    // renames a flag, or relaxes a required-arg constraint breaks them.

    /// `trustdb list <DIR> --format json --source rpm` parses, the positional
    /// DIR round-trips, and `--source` maps to the Rpm filter.
    #[test]
    fn trustdb_list_parses_positional_db_format_and_source() {
        let cli = Cli::try_parse_from([
            "rulesteward",
            "fapolicyd",
            "trustdb",
            "list",
            "/var/lib/fapolicyd",
            "--format",
            "json",
            "--source",
            "rpm",
        ])
        .expect("trustdb list must parse");
        let Cli {
            command: TopCommand::Fapolicyd(FapolicydCommand::Trustdb(TrustdbCommand::List(args))),
        } = cli
        else {
            panic!("expected Trustdb(List(_))");
        };
        assert_eq!(
            args.db.as_deref(),
            Some(std::path::Path::new("/var/lib/fapolicyd")),
            "positional DIR must round-trip"
        );
        assert!(
            matches!(args.format, TrustdbFormat::Json),
            "--format json must select Json"
        );
        assert!(
            matches!(args.source, Some(TrustSourceFilter::Rpm)),
            "--source rpm must select Rpm"
        );
    }

    /// `trustdb list` with no positional DIR parses (db is optional) and
    /// defaults `--format` to Human, `--source` to None.
    #[test]
    fn trustdb_list_defaults_when_args_absent() {
        let cli = Cli::try_parse_from(["rulesteward", "fapolicyd", "trustdb", "list"])
            .expect("trustdb list with no args must parse");
        let Cli {
            command: TopCommand::Fapolicyd(FapolicydCommand::Trustdb(TrustdbCommand::List(args))),
        } = cli
        else {
            panic!("expected Trustdb(List(_))");
        };
        assert!(
            args.db.is_none(),
            "DIR must be optional and default to None"
        );
        assert!(
            matches!(args.format, TrustdbFormat::Human),
            "--format must default to Human"
        );
        assert!(args.source.is_none(), "--source must default to None");
    }

    /// `--source` rejects a value not in {rpm,file,deb,unknown}.
    #[test]
    fn trustdb_list_rejects_unknown_source_value() {
        let cli = Cli::try_parse_from([
            "rulesteward",
            "fapolicyd",
            "trustdb",
            "list",
            "--source",
            "bogus",
        ]);
        assert!(cli.is_err(), "an invalid --source value must be rejected");
    }

    /// `trustdb check --db <DIR> <PATH>...` parses with multiple paths.
    #[test]
    fn trustdb_check_parses_db_and_multiple_paths() {
        let cli = Cli::try_parse_from([
            "rulesteward",
            "fapolicyd",
            "trustdb",
            "check",
            "--db",
            "/var/lib/fapolicyd",
            "/usr/bin/ls",
            "/usr/bin/cat",
        ])
        .expect("trustdb check must parse");
        let Cli {
            command: TopCommand::Fapolicyd(FapolicydCommand::Trustdb(TrustdbCommand::Check(args))),
        } = cli
        else {
            panic!("expected Trustdb(Check(_))");
        };
        assert_eq!(
            args.db.as_deref(),
            Some(std::path::Path::new("/var/lib/fapolicyd")),
            "--db value must round-trip"
        );
        assert_eq!(
            args.paths,
            vec![
                std::path::PathBuf::from("/usr/bin/ls"),
                std::path::PathBuf::from("/usr/bin/cat"),
            ],
            "all positional paths must be collected in order"
        );
    }

    /// `trustdb check` with ZERO paths must fail (`paths` is `required = true`,
    /// `num_args = 1..`). Pins the required-arg constraint.
    #[test]
    fn trustdb_check_requires_at_least_one_path() {
        let cli = Cli::try_parse_from([
            "rulesteward",
            "fapolicyd",
            "trustdb",
            "check",
            "--db",
            "/var/lib/fapolicyd",
        ]);
        assert!(
            cli.is_err(),
            "trustdb check with no paths must be a parse error"
        );
    }

    /// `trustdb diff --db <A> --against <B>` parses both DB dirs.
    #[test]
    fn trustdb_diff_parses_db_and_against() {
        let cli = Cli::try_parse_from([
            "rulesteward",
            "fapolicyd",
            "trustdb",
            "diff",
            "--db",
            "/a",
            "--against",
            "/b",
        ])
        .expect("trustdb diff must parse");
        let Cli {
            command: TopCommand::Fapolicyd(FapolicydCommand::Trustdb(TrustdbCommand::Diff(args))),
        } = cli
        else {
            panic!("expected Trustdb(Diff(_))");
        };
        assert_eq!(args.db.as_deref(), Some(std::path::Path::new("/a")));
        assert_eq!(
            args.against.as_deref(),
            Some(std::path::Path::new("/b")),
            "--against must round-trip"
        );
    }

    /// `trustdb diff` with no `--against` parses (DB-vs-disk mode); `against`
    /// is None.
    #[test]
    fn trustdb_diff_against_is_optional() {
        let cli =
            Cli::try_parse_from(["rulesteward", "fapolicyd", "trustdb", "diff", "--db", "/a"])
                .expect("trustdb diff without --against must parse");
        let Cli {
            command: TopCommand::Fapolicyd(FapolicydCommand::Trustdb(TrustdbCommand::Diff(args))),
        } = cli
        else {
            panic!("expected Trustdb(Diff(_))");
        };
        assert!(
            args.against.is_none(),
            "--against must be optional (DB-vs-disk mode)"
        );
    }

    /// `trustdb stale --db <DIR> --format json` parses.
    #[test]
    fn trustdb_stale_parses_db_and_format() {
        let cli = Cli::try_parse_from([
            "rulesteward",
            "fapolicyd",
            "trustdb",
            "stale",
            "--db",
            "/var/lib/fapolicyd",
            "--format",
            "json",
        ])
        .expect("trustdb stale must parse");
        let Cli {
            command: TopCommand::Fapolicyd(FapolicydCommand::Trustdb(TrustdbCommand::Stale(args))),
        } = cli
        else {
            panic!("expected Trustdb(Stale(_))");
        };
        assert_eq!(
            args.db.as_deref(),
            Some(std::path::Path::new("/var/lib/fapolicyd"))
        );
        assert!(matches!(args.format, TrustdbFormat::Json));
    }

    /// An unknown trustdb verb is rejected (pins the closed verb set).
    #[test]
    fn trustdb_rejects_unknown_subcommand() {
        let cli = Cli::try_parse_from(["rulesteward", "fapolicyd", "trustdb", "frobnicate"]);
        assert!(cli.is_err(), "unknown trustdb subcommand must be rejected");
    }

    // -- Phase 0 (version-target): --target value-enum + --check-identities flag --

    /// Helper: parse `lint somedir <extra args>` and return the `LintArgs`.
    fn parse_lint(extra: &[&str]) -> LintArgs {
        let mut cmdline = vec!["rulesteward", "fapolicyd", "lint", "somedir"];
        cmdline.extend_from_slice(extra);
        let cli = Cli::try_parse_from(cmdline).expect("lint args must parse");
        let Cli {
            command: TopCommand::Fapolicyd(FapolicydCommand::Lint(args)),
        } = cli
        else {
            panic!("expected Fapolicyd(Lint(_))");
        };
        args
    }

    /// `--target rhel8|rhel9|rhel10` parses to the matching arg variant.
    /// RED until the `target` field + `TargetVersionArg` value-enum exist.
    #[test]
    fn lint_args_target_parses_each_rhel() {
        for (flag, expected) in [
            ("rhel8", TargetVersionArg::Rhel8),
            ("rhel9", TargetVersionArg::Rhel9),
            ("rhel10", TargetVersionArg::Rhel10),
        ] {
            let args = parse_lint(&["--target", flag]);
            assert_eq!(
                args.target,
                Some(expected),
                "--target {flag} must parse to {expected:?}"
            );
        }
    }

    /// No `--target` leaves `target` = None (implicit 1.4.x dialect, no regression).
    #[test]
    fn lint_args_target_defaults_none() {
        assert!(
            parse_lint(&[]).target.is_none(),
            "absent --target must default to None"
        );
    }

    /// An invalid `--target` value is rejected (pins the closed rhel set).
    #[test]
    fn lint_args_target_rejects_unknown_value() {
        let cli = Cli::try_parse_from([
            "rulesteward",
            "fapolicyd",
            "lint",
            "somedir",
            "--target",
            "rhel7",
        ]);
        assert!(cli.is_err(), "an invalid --target value must be rejected");
    }

    /// `--check-identities` sets the flag; absence leaves it false (opt-in).
    #[test]
    fn lint_args_check_identities_parses_and_defaults_false() {
        assert!(
            parse_lint(&["--check-identities"]).check_identities,
            "--check-identities must set the flag true"
        );
        assert!(
            !parse_lint(&[]).check_identities,
            "check_identities must default to false (opt-in)"
        );
    }

    /// The CLI value-enum converts to the fapolicyd domain `TargetVersion`.
    /// Keeps the domain crate clap-free (mirrors `TrustSourceFilter` -> `TrustSource`).
    #[test]
    fn target_arg_converts_to_domain_version() {
        use rulesteward_fapolicyd::TargetVersion;
        assert_eq!(
            TargetVersion::from(TargetVersionArg::Rhel8),
            TargetVersion::Rhel8
        );
        assert_eq!(
            TargetVersion::from(TargetVersionArg::Rhel9),
            TargetVersion::Rhel9
        );
        assert_eq!(
            TargetVersion::from(TargetVersionArg::Rhel10),
            TargetVersion::Rhel10
        );
    }

    // -- Phase 0 (v0.2): ExplainArgs, CostArgs, TriageArgs parse-contract tests --

    /// Helper: extract `ExplainArgs` from a parsed CLI.
    fn parse_explain(extra: &[&str]) -> ExplainArgs {
        let mut cmdline = vec!["rulesteward", "fapolicyd", "explain"];
        cmdline.extend_from_slice(extra);
        let cli = Cli::try_parse_from(cmdline).expect("explain args must parse");
        let Cli {
            command: TopCommand::Fapolicyd(FapolicydCommand::Explain(args)),
        } = cli
        else {
            panic!("expected Fapolicyd(Explain(_))");
        };
        args
    }

    /// `fapolicyd explain --record F --ruleset D` parses; fields round-trip.
    #[test]
    fn explain_args_record_and_ruleset_required_parse() {
        let args = parse_explain(&[
            "--record",
            "/tmp/denial.log",
            "--ruleset",
            "/etc/fapolicyd/rules.d",
        ]);
        assert_eq!(args.record, PathBuf::from("/tmp/denial.log"));
        assert_eq!(args.ruleset, PathBuf::from("/etc/fapolicyd/rules.d"));
        assert!(args.trustdb.is_none(), "--trustdb must default to None");
        assert!(
            matches!(args.format, HumanJsonFormat::Human),
            "--format must default to Human"
        );
    }

    /// `--trustdb` is optional and round-trips.
    #[test]
    fn explain_args_trustdb_optional() {
        let args = parse_explain(&[
            "--record",
            "/tmp/denial.log",
            "--ruleset",
            "/etc/fapolicyd/rules.d",
            "--trustdb",
            "/var/lib/fapolicyd",
        ]);
        assert_eq!(
            args.trustdb.as_deref(),
            Some(std::path::Path::new("/var/lib/fapolicyd")),
        );
    }

    /// `--format json` selects `Json`.
    #[test]
    fn explain_args_format_json_parses() {
        let args = parse_explain(&[
            "--record",
            "/tmp/denial.log",
            "--ruleset",
            "/etc/fapolicyd/rules.d",
            "--format",
            "json",
        ]);
        assert!(matches!(args.format, HumanJsonFormat::Json));
    }

    /// Missing `--record` is a parse error.
    #[test]
    fn explain_args_missing_record_is_parse_error() {
        let cli = Cli::try_parse_from([
            "rulesteward",
            "fapolicyd",
            "explain",
            "--ruleset",
            "/etc/fapolicyd/rules.d",
        ]);
        assert!(cli.is_err(), "missing --record must be a parse error");
    }

    /// Missing `--ruleset` is a parse error.
    #[test]
    fn explain_args_missing_ruleset_is_parse_error() {
        let cli = Cli::try_parse_from([
            "rulesteward",
            "fapolicyd",
            "explain",
            "--record",
            "/tmp/denial.log",
        ]);
        assert!(cli.is_err(), "missing --ruleset must be a parse error");
    }

    /// Helper: extract `CostArgs` from a parsed CLI.
    fn parse_cost(extra: &[&str]) -> CostArgs {
        let mut cmdline = vec!["rulesteward", "auditd", "cost"];
        cmdline.extend_from_slice(extra);
        let cli = Cli::try_parse_from(cmdline).expect("cost args must parse");
        let Cli {
            command: TopCommand::Auditd(AuditdCommand::Cost(args)),
        } = cli
        else {
            panic!("expected Auditd(Cost(_))");
        };
        args
    }

    /// `auditd cost --rules D` parses; required field round-trips.
    #[test]
    fn cost_args_rules_required_parses() {
        let args = parse_cost(&["--rules", "/etc/audit/rules.d"]);
        assert_eq!(args.rules, PathBuf::from("/etc/audit/rules.d"));
        assert!(args.from_log.is_none(), "--from-log must default to None");
        assert!(!args.recommend, "--recommend must default to false");
        assert!(
            (args.price_per_gb - 5.00).abs() < 1e-9,
            "--price-per-gb must default to 5.00, got {}",
            args.price_per_gb,
        );
        assert!(matches!(args.format, HumanJsonFormat::Human));
    }

    /// Optional fields all parse correctly.
    #[test]
    fn cost_args_optional_fields_parse() {
        let args = parse_cost(&[
            "--rules",
            "/etc/audit/rules.d",
            "--from-log",
            "/var/log/audit/audit.log",
            "--recommend",
            "--price-per-gb",
            "7.50",
            "--format",
            "json",
        ]);
        assert_eq!(
            args.from_log.as_deref(),
            Some(std::path::Path::new("/var/log/audit/audit.log")),
        );
        assert!(args.recommend, "--recommend must set the flag");
        assert!(
            (args.price_per_gb - 7.50).abs() < 1e-9,
            "--price-per-gb 7.50 must round-trip, got {}",
            args.price_per_gb,
        );
        assert!(matches!(args.format, HumanJsonFormat::Json));
    }

    /// Helper: extract `TriageArgs` from a parsed CLI.
    fn parse_triage(extra: &[&str]) -> TriageArgs {
        let mut cmdline = vec!["rulesteward", "selinux", "triage"];
        cmdline.extend_from_slice(extra);
        let cli = Cli::try_parse_from(cmdline).expect("triage args must parse");
        let Cli {
            command: TopCommand::Selinux(SelinuxCommand::Triage(args)),
        } = cli
        else {
            panic!("expected Selinux(Triage(_))");
        };
        args
    }

    /// `selinux triage --record F` parses.
    #[test]
    fn triage_args_record_parses() {
        let args = parse_triage(&["--record", "/tmp/avc.log"]);
        assert_eq!(
            args.record.as_deref(),
            Some(std::path::Path::new("/tmp/avc.log")),
        );
        assert!(args.audit_log.is_none());
    }

    /// `selinux triage --audit-log F` parses.
    #[test]
    fn triage_args_audit_log_parses() {
        let args = parse_triage(&["--audit-log", "/var/log/audit/audit.log"]);
        assert_eq!(
            args.audit_log.as_deref(),
            Some(std::path::Path::new("/var/log/audit/audit.log")),
        );
        assert!(args.record.is_none());
    }

    /// `--record` and `--audit-log` together are a parse error (`conflicts_with`).
    #[test]
    fn triage_args_record_and_audit_log_conflict() {
        let cli = Cli::try_parse_from([
            "rulesteward",
            "selinux",
            "triage",
            "--record",
            "/tmp/avc.log",
            "--audit-log",
            "/var/log/audit/audit.log",
        ]);
        assert!(
            cli.is_err(),
            "--record and --audit-log together must be a parse error"
        );
    }

    /// `--emit-te --module-name N -o /tmp/x.te` all parse.
    #[test]
    fn triage_args_emit_te_flags_parse() {
        let args = parse_triage(&[
            "--record",
            "/tmp/avc.log",
            "--emit-te",
            "--module-name",
            "mymodule",
            "-o",
            "/tmp/x.te",
        ]);
        assert!(args.emit_te, "--emit-te must set the flag");
        assert_eq!(args.module_name.as_deref(), Some("mymodule"));
        assert_eq!(
            args.output.as_deref(),
            Some(std::path::Path::new("/tmp/x.te")),
        );
    }

    /// `--format json` and `--since 1h` parse.
    #[test]
    fn triage_args_format_and_since_parse() {
        let args = parse_triage(&[
            "--audit-log",
            "/var/log/audit/audit.log",
            "--format",
            "json",
            "--since",
            "1h",
        ]);
        assert!(matches!(args.format, HumanJsonFormat::Json));
        assert_eq!(args.since.as_deref(), Some("1h"));
    }

    // -- Phase 0 (v0.2 round 2): SimulateArgs / ReportArgs parse-contract tests --

    /// Helper: extract `SimulateArgs` from a parsed CLI.
    fn parse_simulate(extra: &[&str]) -> SimulateArgs {
        let mut cmdline = vec!["rulesteward", "fapolicyd", "simulate"];
        cmdline.extend_from_slice(extra);
        let cli = Cli::try_parse_from(cmdline).expect("simulate args must parse");
        let Cli {
            command: TopCommand::Fapolicyd(FapolicydCommand::Simulate(args)),
        } = cli
        else {
            panic!("expected Fapolicyd(Simulate(_))");
        };
        args
    }

    /// `fapolicyd simulate --rules D --workload F` parses; required fields
    /// round-trip and the optionals default. RED until `Simulate` becomes a
    /// tuple variant carrying `SimulateArgs`.
    #[test]
    fn simulate_args_rules_and_workload_required_parse() {
        let args = parse_simulate(&["--rules", "/etc/fapolicyd/rules.d", "--workload", "/tmp/wl"]);
        assert_eq!(args.rules, PathBuf::from("/etc/fapolicyd/rules.d"));
        assert_eq!(args.workload, PathBuf::from("/tmp/wl"));
        assert!(args.trustdb.is_none(), "--trustdb must default to None");
        assert!(
            matches!(args.format, HumanJsonFormat::Human),
            "--format must default to Human"
        );
    }

    /// `--workload -` (stdin sentinel) parses as the literal path `-`; the
    /// simulate pipeline interprets it, not clap.
    #[test]
    fn simulate_args_workload_dash_is_stdin_sentinel() {
        let args = parse_simulate(&["--rules", "/r", "--workload", "-"]);
        assert_eq!(args.workload, PathBuf::from("-"));
    }

    /// `--trustdb` is optional and round-trips; `--format json` selects Json.
    #[test]
    fn simulate_args_optional_fields_parse() {
        let args = parse_simulate(&[
            "--rules",
            "/r",
            "--workload",
            "/w",
            "--trustdb",
            "/var/lib/fapolicyd",
            "--format",
            "json",
        ]);
        assert_eq!(
            args.trustdb.as_deref(),
            Some(std::path::Path::new("/var/lib/fapolicyd")),
        );
        assert!(matches!(args.format, HumanJsonFormat::Json));
    }

    /// Missing `--rules` or `--workload` is a parse error (both required).
    #[test]
    fn simulate_args_missing_required_is_parse_error() {
        assert!(
            Cli::try_parse_from(["rulesteward", "fapolicyd", "simulate", "--workload", "/w"])
                .is_err(),
            "missing --rules must be a parse error"
        );
        assert!(
            Cli::try_parse_from(["rulesteward", "fapolicyd", "simulate", "--rules", "/r"]).is_err(),
            "missing --workload must be a parse error"
        );
    }

    /// Helper: extract `ReportArgs` from a parsed CLI.
    fn parse_report(extra: &[&str]) -> ReportArgs {
        let mut cmdline = vec!["rulesteward", "fapolicyd", "report"];
        cmdline.extend_from_slice(extra);
        let cli = Cli::try_parse_from(cmdline).expect("report args must parse");
        let Cli {
            command: TopCommand::Fapolicyd(FapolicydCommand::Report(args)),
        } = cli
        else {
            panic!("expected Fapolicyd(Report(_))");
        };
        args
    }

    /// `fapolicyd report` (no args) parses; the positional path defaults to None
    /// and every flag defaults off / Human.
    #[test]
    fn report_args_default_parse() {
        let args = parse_report(&[]);
        assert!(args.path.is_none(), "positional path must default to None");
        assert!(args.file.is_none());
        assert!(matches!(args.format, HumanJsonCsvFormat::Human));
        assert!(args.against_trustdb.is_none());
        assert!(args.diff_against.is_none());
        assert!(!args.fail_on_drift);
        assert!(!args.enumerate_trust);
    }

    /// `--format csv` selects the CSV surface.
    #[test]
    fn report_args_format_csv_parses() {
        assert!(matches!(
            parse_report(&["--format", "csv"]).format,
            HumanJsonCsvFormat::Csv
        ));
    }

    /// The positional path round-trips; `--file` conflicts with it.
    #[test]
    fn report_args_positional_path_and_file_conflict() {
        let args = parse_report(&["/etc/fapolicyd/rules.d"]);
        assert_eq!(
            args.path.as_deref(),
            Some(std::path::Path::new("/etc/fapolicyd/rules.d")),
        );
        let args = parse_report(&["--file", "/some/40-x.rules"]);
        assert_eq!(
            args.file.as_deref(),
            Some(std::path::Path::new("/some/40-x.rules")),
        );
        // positional + --file together is a parse error (conflicts_with).
        assert!(
            Cli::try_parse_from([
                "rulesteward",
                "fapolicyd",
                "report",
                "/dir",
                "--file",
                "/f.rules",
            ])
            .is_err(),
            "positional path and --file together must be a parse error"
        );
    }

    /// All report flags parse together.
    #[test]
    fn report_args_all_flags_parse() {
        let args = parse_report(&[
            "/r",
            "--against-trustdb",
            "/var/lib/fapolicyd",
            "--diff-against",
            "/tmp/prev.json",
            "--fail-on-drift",
            "--enumerate-trust",
        ]);
        assert_eq!(
            args.against_trustdb.as_deref(),
            Some(std::path::Path::new("/var/lib/fapolicyd")),
        );
        assert_eq!(
            args.diff_against.as_deref(),
            Some(std::path::Path::new("/tmp/prev.json")),
        );
        assert!(args.fail_on_drift);
        assert!(args.enumerate_trust);
    }
}
