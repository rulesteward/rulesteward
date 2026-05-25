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
    about = "RuleSteward — fapolicyd / SELinux / auditd policy linter"
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

    /// Single-file mode — lint exactly this file
    #[arg(long, value_name = "FILE", conflicts_with = "path")]
    pub file: Option<PathBuf>,

    /// Output format
    #[arg(long, value_enum, default_value_t = OutputFormat::Human)]
    pub format: OutputFormat,

    /// (stub) Cross-check rules against this trust DB
    #[arg(long, value_name = "PATH")]
    pub against_trustdb: Option<PathBuf>,
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
