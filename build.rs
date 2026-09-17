//! Generates the man page and the bash completion into OUT_DIR on every build
//! (#79). Nothing under src/ reads OUT_DIR, so none of this runs in the shipped
//! binary -- but it is not byte-neutral: measured 2026-09-17, moving the clap types
//! into src/cli.rs shrank .text by 3688 bytes and the build-dependencies moved the
//! bin's metadata hash, so the sum is no longer v0.4.0's. It is still reproducible,
//! which is what musl.sh's sum is for: two checkouts at different paths gave one sum.
// The `cargo:` directives are the build-script protocol and the [lints] table
// applies here too.
#![allow(clippy::print_stdout)]

#[path = "src/cli.rs"]
mod cli;

use clap::CommandFactory;
use std::path::PathBuf;

fn main() -> std::io::Result<()> {
    println!("cargo:rerun-if-changed=src/cli.rs");
    let out = PathBuf::from(std::env::var_os("OUT_DIR").expect("cargo sets OUT_DIR"));
    let mut cmd = cli::Cli::command();
    let mut page = Vec::new();
    clap_mangen::Man::new(cmd.clone()).render(&mut page)?;
    std::fs::write(out.join("rulesteward.1"), page)?;
    clap_complete::generate_to(clap_complete::Shell::Bash, &mut cmd, "rulesteward", &out)?;
    Ok(())
}
