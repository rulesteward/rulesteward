//! Body of `rulesteward completions <shell>`. Emits a shell-completion
//! script to stdout for the user to redirect into the shell's
//! completion directory.

use clap::CommandFactory;
use clap_complete::{
    generate,
    shells::{Bash, Elvish, Fish, PowerShell, Zsh},
};
use std::io;

use crate::cli::{Cli, CompletionShell, CompletionsArgs};
use crate::exit_code::EXIT_CLEAN;

#[must_use]
pub fn run(args: &CompletionsArgs) -> i32 {
    let mut cmd = Cli::command();
    let bin_name = "rulesteward";
    let mut stdout = io::stdout().lock();
    match args.shell {
        CompletionShell::Bash => generate(Bash, &mut cmd, bin_name, &mut stdout),
        CompletionShell::Zsh => generate(Zsh, &mut cmd, bin_name, &mut stdout),
        CompletionShell::Fish => generate(Fish, &mut cmd, bin_name, &mut stdout),
        CompletionShell::Elvish => generate(Elvish, &mut cmd, bin_name, &mut stdout),
        CompletionShell::PowerShell => generate(PowerShell, &mut cmd, bin_name, &mut stdout),
    }
    EXIT_CLEAN
}
