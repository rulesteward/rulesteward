use clap::Parser;
use std::path::PathBuf;

use crate::cli::{IntegrityLevelArg, TrustSourceFilter, TrustdbFormat, TrustdbListFormat};

/// Arguments for `rulesteward fapolicyd trustdb list`.
#[derive(Debug, Parser)]
pub struct TrustdbListArgs {
    /// Path to the fapolicyd trust-DB directory (defaults to /var/lib/fapolicyd/)
    #[arg(value_name = "DIR")]
    pub db: Option<PathBuf>,

    /// Output format (human | json | csv).
    #[arg(long, value_enum, default_value_t = TrustdbListFormat::Human)]
    pub format: TrustdbListFormat,

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

    /// Path to fapolicyd.conf (default: /etc/fapolicyd/fapolicyd.conf). The
    /// `integrity` key controls which verdicts raise the exit code. When the
    /// file is not found, STRICT mode (sha256) is assumed.
    #[arg(long, value_name = "FILE")]
    pub config: Option<PathBuf>,

    /// Override the integrity enforcement level (none|size|ima|sha256). Takes
    /// precedence over --config (and the daemon default).
    #[arg(long, value_name = "LEVEL", value_enum)]
    pub integrity: Option<IntegrityLevelArg>,
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

    /// Path to fapolicyd.conf (default: /etc/fapolicyd/fapolicyd.conf). The
    /// `integrity` key controls which verdicts raise the exit code (vs-disk mode
    /// only; DB-vs-DB mode ignores integrity gating). When the file is not found,
    /// STRICT mode (sha256) is assumed.
    #[arg(long, value_name = "FILE")]
    pub config: Option<PathBuf>,

    /// Override the integrity enforcement level (none|size|ima|sha256). Takes
    /// precedence over --config (and the daemon default).
    #[arg(long, value_name = "LEVEL", value_enum)]
    pub integrity: Option<IntegrityLevelArg>,
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

    /// Path to fapolicyd.conf (default: /etc/fapolicyd/fapolicyd.conf). The
    /// `integrity` key controls which verdicts raise the exit code. When the
    /// file is not found, STRICT mode (sha256) is assumed.
    #[arg(long, value_name = "FILE")]
    pub config: Option<PathBuf>,

    /// Override the integrity enforcement level (none|size|ima|sha256). Takes
    /// precedence over --config (and the daemon default).
    #[arg(long, value_name = "LEVEL", value_enum)]
    pub integrity: Option<IntegrityLevelArg>,
}
