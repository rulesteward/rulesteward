//! clap derive definitions for the `rulesteward` CLI.
//!
//! Wired into the binary via `lib.rs` (added in Task 4) and `main.rs`
//! (rewritten in Task 11). Subcommand tree matches spec §6.1.

use clap::{Parser, Subcommand, ValueEnum};
// Only used by the inline test module below (via its glob `use super::*;`);
// every production use of `PathBuf` moved into `cli::args::*` with the structs.
#[allow(unused_imports)]
use std::path::PathBuf;

mod args;
pub use args::*;

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

/// Output format for `trustdb list` (human | json | csv).
///
/// Distinct from `TrustdbFormat`: only `list` is a flat-row verb, so only it
/// gains the CSV surface (#64 / CC-3). `check` / `diff` / `stale` keep the
/// human|json `TrustdbFormat`.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum TrustdbListFormat {
    Human,
    Json,
    Csv,
}

/// Filter trust-DB entries by their source database.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum TrustSourceFilter {
    Rpm,
    File,
    Deb,
    Unknown,
}

/// CLI value-enum for the `--integrity` override flag on the vs-disk trust-DB
/// verbs (`check` / `diff` / `stale`). Mirrors the fapolicyd domain
/// `IntegrityMode` so the domain crate stays clap-free (the same layering as
/// `TrustSourceFilter` -> `TrustSource`).
///
/// The accepted values are EXACTLY `{none, size, ima, sha256}`; clap rejects any
/// other token with a parse error (non-zero exit). This is intentionally
/// STRICTER than the conf-file path: a `--config` file with an unknown
/// `integrity` value keeps the daemon-faithful unknown->none behaviour
/// (`fapolicyd.conf(5)` parity), but an explicit unknown `--integrity` flag is a
/// user typo that must be surfaced, not silently weakened (#292).
///
/// `Sha256` pins its value name to `sha256` (clap's default kebab-case would
/// render `sha-256`, which the spec rejects as an invalid keyword).
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum IntegrityLevelArg {
    None,
    Size,
    Ima,
    #[value(name = "sha256")]
    Sha256,
}

impl From<IntegrityLevelArg> for rulesteward_fapolicyd::IntegrityMode {
    fn from(arg: IntegrityLevelArg) -> Self {
        match arg {
            IntegrityLevelArg::None => rulesteward_fapolicyd::IntegrityMode::None,
            IntegrityLevelArg::Size => rulesteward_fapolicyd::IntegrityMode::Size,
            IntegrityLevelArg::Ima => rulesteward_fapolicyd::IntegrityMode::Ima,
            IntegrityLevelArg::Sha256 => rulesteward_fapolicyd::IntegrityMode::Sha256,
        }
    }
}

#[derive(Debug, Parser)]
#[command(
    name = "rulesteward",
    version,
    about = "RuleSteward - fapolicyd / sshd_config / SELinux / auditd policy linter",
    long_about = "RuleSteward - fapolicyd / sshd_config / SELinux / auditd policy linter.\n\
\n\
OUTPUT FORMATS (locked policy, #65 / CC-4):\n\
  human  default; human-readable text.\n\
  json   versioned JSON envelope { schemaVersion, kind, ... } for structured\n\
         state (lint, report, auditd cost, trustdb, simulate, explain, triage).\n\
         New optional fields and new kinds are additive; the version bumps only\n\
         on a breaking change.\n\
  sarif  lint only: FINDINGS ONLY (SARIF 2.1.0); not used for inventory/metrics.\n\
         --sarif-include-pass adds per-check pass results for clean rules (#137).\n\
  csv    flat-row verbs only (report, trustdb list, auditd cost per-rule): one\n\
         rectangular RFC-4180 CSV table; aggregate totals stay in json/human.\n\
\n\
OSCAL / HDF compliance exports are deferred paid exporters; the register payload\n\
is pre-designed to map to OSCAL, but no exporter is built in this release."
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

    /// `sshd_config` operations
    #[command(subcommand)]
    Sshd(SshdCommand),

    /// `sysctl.d` / `sysctl.conf` operations
    #[command(subcommand)]
    Sysctl(SysctlCommand),

    /// `sudoers` operations
    #[command(subcommand)]
    Sudoers(SudoersCommand),

    /// Print shell-completion script for the given shell
    Completions(CompletionsArgs),

    /// Generate the `rulesteward.1` man page into a directory (release tooling).
    /// Hidden: invoked by the release workflow, not an end-user command.
    #[command(hide = true)]
    Mangen(MangenArgs),
}

#[derive(Debug, Subcommand)]
pub enum FapolicydCommand {
    /// Lint fapolicyd rule files (unprivileged, no daemon)
    #[command(after_long_help = r"Examples:
  # Lint the default rules.d/ (/etc/fapolicyd/rules.d/), human output
  rulesteward fapolicyd lint

  # Lint a specific rules.d/ directory
  rulesteward fapolicyd lint /etc/fapolicyd/rules.d

  # Lint a single rules file
  rulesteward fapolicyd lint --file 50-myrules.rules

  # SARIF 2.1.0 with per-check pass coverage, version-aware for RHEL 9
  rulesteward fapolicyd lint --format sarif --sarif-include-pass --target rhel9

  # Cross-check path=/exe= against a trust DB and report unreferenced entries
  rulesteward fapolicyd lint --against-trustdb /var/lib/fapolicyd/trust.db --report-orphans")]
    Lint(LintArgs),
    /// Simulate a workload against a rule set (which rule decides each access)
    ///
    /// Statically replays each access in the workload against the rule set and
    /// reports the deciding rule. Some rule predicates cannot be resolved
    /// statically: `pattern=` rules depend on runtime process ancestry and are
    /// treated as not-evaluable; `ftype=` needs real MIME detection of the target
    /// file, which simulation does not perform. A trust DB marks a file "trusted"
    /// by presence, but the daemon's runtime `integrity` re-check (sha256 / size)
    /// can still mark an on-disk-modified file untrusted at exec time. `--trustdb`
    /// resolves trust the workload omits (workload-supplied trust always wins).
    #[command(after_long_help = r"Examples:
  # Replay a workload against a rules.d/ directory
  rulesteward fapolicyd simulate --rules /etc/fapolicyd/rules.d --workload accesses.txt

  # Read the workload from stdin
  cat accesses.txt | rulesteward fapolicyd simulate --rules /etc/fapolicyd/rules.d --workload -

  # Resolve trust the workload omits from a read-only trust DB, JSON output
  rulesteward fapolicyd simulate --rules /etc/fapolicyd/rules.d --workload accesses.txt --trustdb /var/lib/fapolicyd/trust.db --format json")]
    Simulate(SimulateArgs),
    /// Explain a FANOTIFY denial from the audit log
    Explain(ExplainArgs),
    /// Build the exception register: every effective allow grant, with drift
    Report(ReportArgs),
    /// Detect container runtimes and warn about fapolicyd's namespace limits
    ///
    /// Detects podman/Docker/containerd/CRI-O/Kubernetes/RHCOS on the host and
    /// flags the known fapolicyd namespace-awareness limitation (RHEL-114562).
    /// Exit 0 = no risk, 1 = WARN, 2 = HIGH, 3 = RHCOS (unsupported).
    ContainerCheck(ContainerCheckArgs),
    /// Trust database operations (read-only)
    #[command(subcommand)]
    Trustdb(TrustdbCommand),
    /// Migrate a legacy fapolicyd.rules into the modern rules.d/ layout
    ///
    /// Moves a single-file `fapolicyd.rules` to `rules.d/99-migrated.rules`
    /// (preserving comments + ordering), rewrites the deprecated `sha256hash=`
    /// attribute to `filehash=`, and handles the coexistence trap (both layouts
    /// present stops the daemon starting). Read-only by default (dry-run);
    /// `--apply` writes the drop-in and MOVES (removes) the legacy file;
    /// `--delete-legacy` is required only to migrate a dir that already has both.
    #[command(after_long_help = r"Examples:
  # Dry-run: show the plan migrating a RHEL 8 ruleset to RHEL 9 (changes nothing)
  rulesteward fapolicyd migrate --from rhel8 --to rhel9 --rules-dir /etc/fapolicyd

  # Apply: write rules.d/99-migrated.rules and MOVE (remove) the legacy file
  rulesteward fapolicyd migrate --from rhel8 --to rhel9 --rules-dir /etc/fapolicyd --apply

  # Apply when the dir already has BOTH fapolicyd.rules and rules.d/ (coexistence trap)
  rulesteward fapolicyd migrate --from rhel8 --to rhel9 --rules-dir /etc/fapolicyd --apply --delete-legacy

  # Dry-run plus a standalone markdown migration report
  rulesteward fapolicyd migrate --from rhel8 --to rhel9 --rules-dir /etc/fapolicyd --report migration.md")]
    Migrate(MigrateArgs),
    /// Run a composite health check on a live fapolicyd deployment.
    ///
    /// Runs 13 read-only checks and reports a pass/warn/fail scorecard.
    /// Exit 0 = all checks pass; 1 = warnings present; 2 = failures present.
    Doctor(DoctorArgs),
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

/// The same `--target` value-enum maps to the sshd domain's `TargetVersion`
/// (the version-aware sshd-W01..W04 baseline selector). One CLI surface, one
/// `From` per backend domain, so each domain crate stays clap-free.
impl From<TargetVersionArg> for rulesteward_sshd::TargetVersion {
    fn from(arg: TargetVersionArg) -> Self {
        match arg {
            TargetVersionArg::Rhel8 => rulesteward_sshd::TargetVersion::Rhel8,
            TargetVersionArg::Rhel9 => rulesteward_sshd::TargetVersion::Rhel9,
            TargetVersionArg::Rhel10 => rulesteward_sshd::TargetVersion::Rhel10,
        }
    }
}

/// The same `--target` value-enum maps to the sysctld domain's `TargetVersion`
/// (the version-aware `sysctld-W02` STIG-baseline selector, issue #335). One CLI
/// surface, one `From` per backend domain, so each domain crate stays clap-free.
impl From<TargetVersionArg> for rulesteward_sysctld::TargetVersion {
    fn from(arg: TargetVersionArg) -> Self {
        match arg {
            TargetVersionArg::Rhel8 => rulesteward_sysctld::TargetVersion::Rhel8,
            TargetVersionArg::Rhel9 => rulesteward_sysctld::TargetVersion::Rhel9,
            TargetVersionArg::Rhel10 => rulesteward_sysctld::TargetVersion::Rhel10,
        }
    }
}

/// CLI value-enum for `--target` on the version-aware lint verbs: `auto` triggers
/// host detection from `/etc/os-release`, the explicit values pin a baseline. The
/// command layer resolves this to a concrete `TargetVersionArg` (or the
/// version-agnostic `None`) via [`crate::commands::target_probe::resolve_target`]
/// (epic #251: target resolution lives in the command layer, never in a lint pass).
/// Kept separate from `TargetVersionArg` so the domain `From` impls stay total
/// (`Auto` never reaches them).
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum TargetSelector {
    /// Detect the target from the host's `/etc/os-release`; fall back to the
    /// version-agnostic dialect (with a warning) when detection fails.
    Auto,
    Rhel8,
    Rhel9,
    Rhel10,
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

#[derive(Debug, Subcommand)]
pub enum SelinuxCommand {
    /// Triage `SELinux` AVCs
    ///
    /// Classifies `SELinux` AVC denials and suggests next steps. A record-only floor
    /// classifier always runs; passing `--policy <FILE>` adds authoritative
    /// categorization by replaying each denial against the binary policy.
    ///
    /// Limitations: only plain type-enforcement (TE) denials are fixable with an
    /// `allow` rule. Constraint (MLS / MCS), RBAC role, and typebounds denials are
    /// NOT TE-allowable; triage reports them but never emits an allow for them.
    /// Permissive-mode denials (the access was not actually blocked) are reported
    /// with a caveat banner and a suggested allow, but the suggestion is never
    /// auto-applied (triage is read-only).
    Triage(TriageArgs),
}

#[derive(Debug, Subcommand)]
pub enum AuditdCommand {
    /// auditd cost calculator
    ///
    /// Estimates SIEM ingest volume and cost from auditd rules. The result is a
    /// band (low / typical / high), not a guarantee.
    ///
    /// What IS predictable from the rules (f3 5.1): which rules fire, their
    /// additive-vs-suppressive direction, and a per-rule volume tier. Suppressive
    /// rules (`never`, `exclude`) contribute zero volume. Without `--from-log`,
    /// each event is sized at a fixed 1200 bytes ENRICHED (900 RAW).
    ///
    /// What is NOT predictable from the rules alone (f3 5.2): the real event rate,
    /// the PATH-record multiplier, and rule interaction on a live host. Pass
    /// `--from-log <FILE>` to ground the estimate in measured per-key counts AND
    /// measured per-event on-disk bytes from a captured audit log (issue #307), so
    /// both the rate and the event size come from the host instead of the defaults.
    ///
    /// Cost assumes ingest-based SIEM pricing (USD per decimal GB via
    /// `--price-per-gb`, default $5.00), not Splunk-style workload/compute pricing.
    Cost(CostArgs),

    /// Semantic ruleset lint (#193)
    ///
    /// Statically analyzes an audit ruleset for semantic problems no load-time
    /// check reports: duplicate rules across rules.d/ files (au-W01), rules
    /// shadowed by an earlier broader rule (au-W02), rules unreachable after
    /// the `-e 2` lock line (au-E01), exclude/never rules suppressing events an
    /// always rule intends to record (au-W03), comparison operators that
    /// are invalid for a field's type and would make auditctl reject the rule
    /// (au-E02), fields used on a filter list the kernel rejects for that field,
    /// which aborts the rule load (au-E04), and syscall rules pinned to one ABI
    /// (`arch=b32`/`b64`) with no companion on the opposite ABI, leaving the
    /// other ABI unaudited (au-W04).
    ///
    /// Read-only. Exit codes follow the shared scheme: 0 clean, 1 warnings,
    /// 2 errors, 3 tool failure, 5 unparseable rules (au-F01).
    Lint(AuditdLintArgs),
}

#[derive(Debug, Subcommand)]
pub enum SshdCommand {
    /// Lint an `sshd_config` file (#149)
    ///
    /// Parses an `sshd_config` file (whole-line `#` comments, case-insensitive
    /// keywords, `Match` blocks, `Include` directives) and runs the `sshd_config`
    /// lint passes over it. All 13 sshd- codes are active: sshd-E01 (unknown
    /// directive), sshd-E02 (duplicate global), sshd-E03 (unresolved Include),
    /// sshd-E04 (Match-illegal directive), sshd-F01 (parse error), sshd-F02
    /// (drop-in override of a required global), and the warnings sshd-W01
    /// (STIG-required missing), sshd-W02 (weaker than baseline), sshd-W03 (weak
    /// algorithm), sshd-W04 (deprecated directive), sshd-W05 (permissive Match
    /// override), sshd-W06 (algorithm-prefix reintroduction), and sshd-W07
    /// (cross-Match first-value-wins shadow).
    ///
    /// Read-only. Exit codes follow the shared scheme: 0 clean, 1 warnings,
    /// 2 errors, 3 tool failure, 5 unparseable config (sshd-F01).
    Lint(SshdLintArgs),
}

#[derive(Debug, Subcommand)]
pub enum SysctlCommand {
    /// Lint a `sysctl.d`/`sysctl.conf` file (#150)
    ///
    /// Parses a kernel-parameter assignment file (`/etc/sysctl.conf`,
    /// `/etc/sysctl.d/*.conf`, etc.: whole-line `#`/`;` comments, `key = value`
    /// assignments) and runs the `sysctl.d` lint passes over it: sysctld-F01 (parse
    /// error), sysctld-W01 (last-wins conflict: the same key assigned different
    /// effective values across the drop-in precedence order), and - when a
    /// `--target rhel8|rhel9|rhel10` baseline is selected - the version-aware
    /// sysctld-W02 STIG kernel-hardening baseline check (#335). `--system` opts in
    /// to a cross-directory precedence scan (issue #420): it enumerates the full
    /// standard search path (`/etc/sysctl.d`, `/run/sysctl.d`,
    /// `/usr/local/lib/sysctl.d`, `/usr/lib/sysctl.d`) plus `/etc/sysctl.conf`,
    /// applies same-basename directory masking and the global lexicographic merge,
    /// reruns F01/W01/W02 over the merged set, and adds sysctld-W03 (a key's
    /// effective winner sits in a lower-precedence directory, a masked drop-in
    /// silently drops a key, or the procps/systemd appliers disagree).
    ///
    /// Read-only (nothing is written; `--root` makes the scan hermetic). Exit codes
    /// follow the shared scheme: 0 clean, 1 warnings, 2 errors, 3 tool failure,
    /// 5 unparseable config (sysctld-F01).
    Lint(SysctlLintArgs),
}

#[derive(Debug, Subcommand)]
pub enum SudoersCommand {
    /// Lint a `sudoers` file or `sudoers.d` directory
    ///
    /// Parses a `sudoers(5)` policy file (line-continuation joins, `#` comment
    /// disambiguation, `Defaults` entries, alias definitions, `@include` /
    /// `@includedir` directives, and user specifications) and runs all `sudoers`
    /// lint passes over it. It detects:
    ///
    /// - parse errors / malformed lines (sudo-F01);
    /// - undefined alias references and dead (never-referenced) aliases
    ///   (sudo-E01 / sudo-W03);
    /// - passwordless run-anything grants - NOPASSWD on the reserved `ALL`
    ///   (sudo-W01) or on a `Cmnd_Alias` that transitively expands to `ALL`
    ///   (sudo-W02);
    /// - `Defaults` settings that weaken the sudo hardening baseline - `targetpw`,
    ///   `rootpw`, `visiblepw`, `!authenticate`, `!use_pty` - or a required
    ///   hardening absent from the whole resolved config: `use_pty` or I/O logging
    ///   (`logfile` / `log_output`) not set anywhere (CIS Benchmark 1.3.2 / 1.3.3)
    ///   (sudo-W04).
    ///
    /// A directory target (e.g. `/etc/sudoers.d`) lints each eligible drop-in
    /// (sorted; names ending in `~` or containing `.` are skipped, per the man
    /// page). Read-only. Exit codes follow the shared scheme: 0 clean, 1 warnings,
    /// 2 errors, 3 tool failure, 5 unparseable config (sudo-F01).
    Lint(SudoersLintArgs),
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

    // --- session 6a Phase 0: auditd lint (#193) + migrate --report (#212) ---

    /// `auditd lint` with no args: path defaults to None (the command substitutes
    /// /etc/audit/rules.d/), format defaults to human.
    #[test]
    fn auditd_lint_parses_with_defaults() {
        let cli = Cli::try_parse_from(["rulesteward", "auditd", "lint"]);
        assert!(cli.is_ok(), "bare `auditd lint` must parse, got: {cli:?}");
        if let Ok(Cli {
            command: TopCommand::Auditd(AuditdCommand::Lint(args)),
        }) = cli
        {
            assert!(args.path.is_none(), "positional path must default to None");
            assert!(
                matches!(args.format, HumanJsonFormat::Human),
                "format must default to human"
            );
        } else {
            panic!("expected Auditd(Lint(_))");
        }
    }

    /// `auditd lint <PATH> --format json`: positional path + the json format.
    /// human|json ONLY by type (locked CC-4: SARIF is fapolicyd-lint-only;
    /// CC-3: lint is not a flat-row verb, no CSV).
    #[test]
    fn auditd_lint_parses_path_and_json_format() {
        let cli = Cli::try_parse_from([
            "rulesteward",
            "auditd",
            "lint",
            "/etc/audit/rules.d",
            "--format",
            "json",
        ]);
        assert!(cli.is_ok(), "got: {cli:?}");
        if let Ok(Cli {
            command: TopCommand::Auditd(AuditdCommand::Lint(args)),
        }) = cli
        {
            assert_eq!(
                args.path.as_deref(),
                Some(std::path::Path::new("/etc/audit/rules.d"))
            );
            assert!(matches!(args.format, HumanJsonFormat::Json));
        } else {
            panic!("expected Auditd(Lint(_))");
        }
    }

    /// `auditd lint --format sarif` must be REJECTED by the value enum (CC-4).
    #[test]
    fn auditd_lint_rejects_sarif_format() {
        let cli = Cli::try_parse_from(["rulesteward", "auditd", "lint", "--format", "sarif"]);
        assert!(cli.is_err(), "sarif must not be a valid auditd lint format");
    }

    /// `fapolicyd migrate --report <PATH>` (#212, owner decision D1): opt-in
    /// report artifact path; absent by default (read-only-by-default).
    #[test]
    fn migrate_report_flag_parses_and_defaults_to_none() {
        let base = [
            "rulesteward",
            "fapolicyd",
            "migrate",
            "--from",
            "rhel8",
            "--to",
            "rhel9",
            "--rules-dir",
            "/etc/fapolicyd",
        ];
        let cli = Cli::try_parse_from(base);
        assert!(cli.is_ok(), "got: {cli:?}");
        if let Ok(Cli {
            command: TopCommand::Fapolicyd(FapolicydCommand::Migrate(args)),
        }) = cli
        {
            assert!(args.report.is_none(), "--report must default to None");
        } else {
            panic!("expected Fapolicyd(Migrate(_))");
        }

        let with_report = Cli::try_parse_from(
            base.iter()
                .copied()
                .chain(["--report", "/tmp/migration-report.md"]),
        );
        assert!(with_report.is_ok(), "got: {with_report:?}");
        if let Ok(Cli {
            command: TopCommand::Fapolicyd(FapolicydCommand::Migrate(args)),
        }) = with_report
        {
            assert_eq!(
                args.report.as_deref(),
                Some(std::path::Path::new("/tmp/migration-report.md")),
                "--report value must round-trip"
            );
        } else {
            panic!("expected Fapolicyd(Migrate(_))");
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

    /// The top-level long help documents the locked output-format policy (#65 /
    /// CC-4): SARIF = findings only, JSON envelope + CSV for structured state,
    /// OSCAL/HDF deferred. Pins the policy text so a future edit that drops it is
    /// a test failure (the man page is generated from this help, so this also
    /// guards the man page).
    #[test]
    fn long_help_documents_output_format_policy() {
        use clap::CommandFactory;
        let help = Cli::command().render_long_help().to_string();
        assert!(
            help.contains("SARIF"),
            "policy must mention SARIF; got:\n{help}"
        );
        assert!(
            help.to_lowercase().contains("findings"),
            "policy must state SARIF is findings-only; got:\n{help}"
        );
        assert!(
            help.contains("CSV"),
            "policy must mention CSV for flat-row verbs; got:\n{help}"
        );
        assert!(
            help.to_uppercase().contains("OSCAL"),
            "policy must note OSCAL is deferred; got:\n{help}"
        );
    }

    /// Regression (#197): the top-level long help must NOT describe
    /// `--sarif-include-pass` as "reserved". The flag became functional in
    /// #137/#172 (it adds per-check pass results for clean rules); the stale
    /// "reserved" wording lingered only in this `long_about` prose. The man page
    /// is generated from this help, so this also guards the man page.
    #[test]
    fn long_help_does_not_call_sarif_include_pass_reserved() {
        use clap::CommandFactory;
        let help = Cli::command().render_long_help().to_string();
        assert!(
            help.contains("--sarif-include-pass"),
            "long help must still document the flag; got:\n{help}"
        );
        // Positive lock on the corrected wording: the help must SAY the flag is
        // functional, not merely omit "reserved" (which a future unrelated edit
        // could satisfy without describing the flag at all).
        assert!(
            help.contains("adds per-check pass results"),
            "long help must describe --sarif-include-pass as functional \
             (the corrected #137 wording); got:\n{help}"
        );
        assert!(
            !help.to_lowercase().contains("reserved"),
            "long help must not call --sarif-include-pass 'reserved' \
             (functional since #137); got:\n{help}"
        );
    }

    /// Regression: the top-level `about`/`long_about` tagline must name ALL FOUR
    /// backends, including `sshd`. The tagline historically read
    /// `fapolicyd / SELinux / auditd policy linter` and was not updated when the
    /// `sshd_config` backend shipped, so `rulesteward --help` (and the generated
    /// man page) understated coverage. Targets the tagline strings directly, not
    /// `render_long_help` (which would name `sshd` via the auto-listed
    /// subcommand and mask the gap).
    #[test]
    fn top_level_tagline_names_all_four_backends() {
        use clap::CommandFactory;
        let cmd = Cli::command();
        let about = cmd.get_about().map(ToString::to_string).unwrap_or_default();
        let long_about = cmd
            .get_long_about()
            .map(ToString::to_string)
            .unwrap_or_default();
        for backend in ["fapolicyd", "sshd", "SELinux", "auditd"] {
            assert!(
                about.contains(backend),
                "short `about` tagline must name {backend}; got: {about}"
            );
            assert!(
                long_about.contains(backend),
                "`long_about` tagline must name {backend}; got: {long_about}"
            );
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
            matches!(args.format, TrustdbListFormat::Json),
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
            matches!(args.format, TrustdbListFormat::Human),
            "--format must default to Human"
        );
        assert!(args.source.is_none(), "--source must default to None");
    }

    /// `trustdb list --format csv` selects the CSV surface (#64). `csv` is a
    /// `list`-only format; check/diff/stale keep the human|json `TrustdbFormat`.
    #[test]
    fn trustdb_list_args_format_csv_parses() {
        let cli = Cli::try_parse_from([
            "rulesteward",
            "fapolicyd",
            "trustdb",
            "list",
            "--format",
            "csv",
        ])
        .expect("trustdb list --format csv must parse");
        let Cli {
            command: TopCommand::Fapolicyd(FapolicydCommand::Trustdb(TrustdbCommand::List(args))),
        } = cli
        else {
            panic!("expected Trustdb(List(_))");
        };
        assert!(
            matches!(args.format, TrustdbListFormat::Csv),
            "--format csv must select Csv"
        );
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

    /// `--target auto|rhel8|rhel9|rhel10` parses to the matching selector variant.
    #[test]
    fn lint_args_target_parses_each_rhel() {
        for (flag, expected) in [
            ("auto", TargetSelector::Auto),
            ("rhel8", TargetSelector::Rhel8),
            ("rhel9", TargetSelector::Rhel9),
            ("rhel10", TargetSelector::Rhel10),
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

    /// `--sarif-include-pass` parses and defaults to false (#65 / #137). The flag
    /// is functional since #137 (it adds per-check pass results for clean rules);
    /// this test pins the opt-in parse contract.
    #[test]
    fn lint_args_sarif_include_pass_parses_and_defaults_false() {
        assert!(
            parse_lint(&["--sarif-include-pass"]).sarif_include_pass,
            "--sarif-include-pass must set the flag true"
        );
        assert!(
            !parse_lint(&[]).sarif_include_pass,
            "sarif_include_pass must default to false (opt-in)"
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
        assert!(matches!(args.format, HumanJsonCsvFormat::Human));
    }

    /// `auditd cost --format csv` selects the CSV per-rule surface (#64).
    #[test]
    fn cost_args_format_csv_parses() {
        let args = parse_cost(&["--rules", "/etc/audit/rules.d", "--format", "csv"]);
        assert!(
            matches!(args.format, HumanJsonCsvFormat::Csv),
            "--format csv must select Csv"
        );
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
        assert!(matches!(args.format, HumanJsonCsvFormat::Json));
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
