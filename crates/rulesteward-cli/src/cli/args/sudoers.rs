use clap::Parser;
use std::path::PathBuf;

use crate::cli::OutputFormat;

/// Arguments for `rulesteward sudoers lint` (#329).
#[derive(Debug, Parser)]
pub struct SudoersLintArgs {
    /// The `sudoers` file or `sudoers.d` directory to lint (defaults to
    /// `/etc/sudoers`)
    #[arg(value_name = "PATH")]
    pub path: Option<PathBuf>,

    /// Output format (human | json | sarif; CSV is not offered for this verb
    /// per the locked output contract CC-3). SARIF is findings-only here:
    /// `--sarif-include-pass` coverage attestation stays fapolicyd-only (CC-4).
    #[arg(long, value_enum, default_value_t = OutputFormat::Human)]
    pub format: OutputFormat,
}
