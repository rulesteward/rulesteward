//! clap derive definitions for the `rulesteward` CLI.
//!
//! Wired into the binary via `lib.rs` (added in Task 4) and `main.rs`
//! (rewritten in Task 11). Subcommand tree matches spec §6.1.

use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

// ---- Trust-DB subcommand format and filter enums ----

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
}

#[derive(Debug, Subcommand)]
pub enum FapolicydCommand {
    /// Lint fapolicyd rule files (unprivileged, no daemon)
    Lint(LintArgs),
    // The six no-op stubs below (and `selinux triage` / `auditd cost`) are hidden
    // for v0.1.0 so the CLI does not advertise commands that do nothing yet. NOTE:
    // `hide` removes them from `--help` but clap_complete 4.6.5 still lists them in
    // generated completions (accepted limitation; see e2e_completions.rs).
    /// (stub) Simulate a workload against a rule set
    #[command(hide = true)]
    Simulate,
    /// (stub) Explain a FANOTIFY denial from the audit log
    #[command(hide = true)]
    Explain,
    /// (stub) Status + recent-denials report
    #[command(hide = true)]
    Report,
    /// (stub) Container-runtime detection
    #[command(hide = true)]
    ContainerCheck,
    /// Trust database operations (read-only)
    #[command(subcommand)]
    Trustdb(TrustdbCommand),
    /// (stub) Migrate legacy fapolicyd.rules to rules.d/
    #[command(hide = true)]
    Migrate,
    /// (stub) Daemon health + config sanity check
    #[command(hide = true)]
    Doctor,
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
    /// (stub) Triage `SELinux` AVCs
    #[command(hide = true)]
    Triage,
}

#[derive(Debug, Subcommand)]
pub enum AuditdCommand {
    /// (stub) auditd cost calculator
    #[command(hide = true)]
    Cost,
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
}
