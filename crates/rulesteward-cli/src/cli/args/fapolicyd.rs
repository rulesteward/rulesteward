use clap::Parser;
use std::path::PathBuf;

use crate::cli::{
    HumanJsonCsvFormat, HumanJsonFormat, OutputFormat, TargetSelector, TargetVersionArg,
};

#[derive(Debug, Parser)]
pub struct LintArgs {
    /// Path to the rules.d/ directory to lint (defaults to /etc/fapolicyd/rules.d/)
    #[arg(value_name = "PATH")]
    pub path: Option<PathBuf>,

    /// Single-file mode - lint exactly this file
    #[arg(long, value_name = "FILE", conflicts_with = "path")]
    pub file: Option<PathBuf>,

    /// Output format (human | json | sarif). SARIF is findings-only (SARIF 2.1.0).
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

    /// Target RHEL release for version-aware checks (auto|rhel8|rhel9|rhel10).
    /// `auto` detects the baseline from the host's /etc/os-release, falling back
    /// (with a warning) to the version-agnostic dialect when detection fails. Omit
    /// `--target` to lint the version-agnostic dialect (no version-divergent
    /// diagnostics).
    #[arg(long, value_enum)]
    pub target: Option<TargetSelector>,

    /// Validate `uid=`/`gid=` literals against the host identity database via
    /// `getent` (read-only); enables fapd-W05. Off by default (the check spawns a
    /// `getent` subprocess that may query SSSD/LDAP/AD).
    #[arg(long)]
    pub check_identities: bool,

    /// Additionally emit SARIF `kind:"pass"` results attesting per-check
    /// coverage: one pass per `fapd-` check that ran and was clean, plus a
    /// `tool.driver.rules[]` catalog of the checks that ran. Only meaningful
    /// with `--format sarif` (ignored for human/json).
    ///
    /// "Ran" respects the run's gates: a conditional check (e.g. fapd-W05 needs
    /// `--check-identities`, fapd-W06 needs `--against-trustdb`, fapd-E06 needs
    /// `--target`) is only attested when its gate is on, so coverage is never
    /// claimed for a check that did not execute. Off by default; SARIF output is
    /// unchanged unless this flag is set (#137).
    #[arg(long)]
    pub sarif_include_pass: bool,
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

/// Arguments for `rulesteward fapolicyd migrate` (#187, spec §6.1).
///
/// Migrates a legacy single-file `fapolicyd.rules` into the modern `rules.d/`
/// layout. Read-only by default: prints the migration plan and writes nothing
/// unless `--apply` is given. `--from`/`--to` are the upgrade context and are
/// validated (`from <= to`); the rule grammar is stable across rhel8/9/10, so
/// the transforms today are the file-layout move + the `sha256hash=` ->
/// `filehash=` deprecation.
#[derive(Debug, Parser)]
pub struct MigrateArgs {
    /// Source RHEL release the ruleset is migrating FROM (rhel8/rhel9/rhel10).
    #[arg(long, value_enum)]
    pub from: TargetVersionArg,

    /// Target RHEL release the ruleset is migrating TO (rhel8/rhel9/rhel10).
    #[arg(long, value_enum)]
    pub to: TargetVersionArg,

    /// The fapolicyd config root holding `fapolicyd.rules` and/or `rules.d/`.
    #[arg(long, value_name = "DIR")]
    pub rules_dir: PathBuf,

    /// Write the migrated `rules.d/` file to disk. Without it, migrate is a
    /// read-only dry-run that prints the plan and changes nothing.
    #[arg(long)]
    pub apply: bool,

    /// Authorize migrating a directory that ALREADY has both `fapolicyd.rules`
    /// and `rules.d/*.rules` (the pre-existing coexistence trap that stops the
    /// daemon starting): required to proceed in that case. The legacy file is
    /// removed as part of the move on `--apply` regardless of this flag -- the
    /// flag only gates acting on a dir that already has rules.d/ content.
    #[arg(long)]
    pub delete_legacy: bool,

    /// Output format.
    #[arg(long, value_enum, default_value_t = HumanJsonFormat::Human)]
    pub format: HumanJsonFormat,

    /// Also write a standalone markdown migration report (audit trail of every
    /// rewrite, the file moved, rules unchanged, and the resulting layout) to
    /// this path. Opt-in (#212): without the flag no report is written. Works
    /// in both dry-run and --apply modes; a dry-run report documents the PLAN.
    #[arg(long, value_name = "PATH")]
    pub report: Option<PathBuf>,
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

    /// Read-only fapolicyd trust DB consulted to resolve trust the workload
    /// omits (#127).
    ///
    /// Opened read-only: locked when the trust-DB directory is writable (to
    /// prevent torn reads under a live daemon), with a `NO_LOCK` fallback
    /// otherwise (#317). For any side whose trust the workload left unset, a
    /// path PRESENT in the DB resolves to trusted and an ABSENT
    /// path to untrusted; workload-supplied `trust`/`subjTrust`/`objTrust` always
    /// takes priority. When a `filehash=`/`sha256hash=` rule needs the object's
    /// hash and the workload omits it, the object file is hashed on demand.
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

/// Arguments for `rulesteward fapolicyd container-check` (#175).
///
/// Detects container runtimes and reports fapolicyd namespace-limitation risk.
/// The default run is unprivileged and uses only cheap probes; `--deep` (root)
/// additionally reads `fapolicyd-cli --dump-db` and `ausearch` for evidence
/// (which annotates findings but never changes their severity).
#[derive(Debug, Parser)]
pub struct ContainerCheckArgs {
    /// Output format.
    #[arg(long, value_enum, default_value_t = HumanJsonFormat::Human)]
    pub format: HumanJsonFormat,

    /// Gather extra evidence from the running daemon (requires root): trust-DB
    /// coverage of runtime binaries and recent denial counts. Evidence-only:
    /// it enriches findings but does not change the verdict or exit code.
    #[arg(long)]
    pub deep: bool,

    /// Rules directory to scan for an `allow exe=/usr/bin/crun` rule
    /// (defaults to /etc/fapolicyd/rules.d/).
    #[arg(long, value_name = "DIR", hide = true)]
    pub rules_dir: Option<std::path::PathBuf>,
}
