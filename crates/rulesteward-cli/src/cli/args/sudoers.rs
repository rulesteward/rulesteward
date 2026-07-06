use clap::Parser;
use std::path::PathBuf;

use crate::cli::HumanJsonFormat;

/// Arguments for `rulesteward sudoers lint` (#329).
#[derive(Debug, Parser)]
pub struct SudoersLintArgs {
    /// The `sudoers` file or `sudoers.d` directory to lint (defaults to
    /// `/etc/sudoers`)
    #[arg(value_name = "PATH")]
    pub path: Option<PathBuf>,

    /// Output format (human | json; SARIF and CSV are not offered for this verb
    /// per the locked output contracts CC-3/CC-4).
    #[arg(long, value_enum, default_value_t = HumanJsonFormat::Human)]
    pub format: HumanJsonFormat,
}
