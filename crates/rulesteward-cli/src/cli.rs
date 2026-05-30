//! clap derive definitions for the `rulesteward` CLI.
//!
//! Wired into the binary via `lib.rs` (added in Task 4) and `main.rs`
//! (rewritten in Task 11). Subcommand tree matches spec §6.1.

use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

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
    /// (stub) Simulate a workload against a rule set
    Simulate,
    /// (stub) Explain a FANOTIFY denial from the audit log
    Explain,
    /// (stub) Status + recent-denials report
    Report,
    /// (stub) Container-runtime detection
    ContainerCheck,
    /// (stub) Trust database operations
    Trustdb,
    /// (stub) Migrate legacy fapolicyd.rules to rules.d/
    Migrate,
    /// (stub) Daemon health + config sanity check
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
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum OutputFormat {
    Human,
    Json,
    Sarif,
}

#[derive(Debug, Subcommand)]
pub enum SelinuxCommand {
    /// (stub) Triage `SELinux` AVCs
    Triage,
}

#[derive(Debug, Subcommand)]
pub enum AuditdCommand {
    /// (stub) auditd cost calculator
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
}
