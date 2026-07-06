use clap::Parser;
use std::path::PathBuf;

use crate::cli::CompletionShell;

#[derive(Debug, Parser)]
pub struct MangenArgs {
    /// Directory to write `rulesteward.1` into (created if absent).
    #[arg(value_name = "OUTDIR")]
    pub outdir: PathBuf,
}

#[derive(Debug, Parser)]
pub struct CompletionsArgs {
    /// Shell to generate completions for
    #[arg(value_enum)]
    pub shell: CompletionShell,
}
