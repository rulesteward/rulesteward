//! Body of the hidden `rulesteward mangen <OUTDIR>` subcommand: render the CLI's
//! `clap` command tree to a roff man page (`rulesteward.1`) via `clap_mangen`. The
//! release workflow runs this against the freshly-built binary to produce the
//! packaged man page (spec section 11). Generating from `Cli::command()` at runtime
//! (rather than a `build.rs`) avoids the cross-crate `include!` problem: the CLI
//! depends on `rulesteward_fapolicyd` types a build script cannot resolve.

use clap::CommandFactory;

use crate::cli::{Cli, MangenArgs};
use crate::exit_code::{EXIT_CLEAN, EXIT_TOOL_FAILURE};

pub fn run(args: &MangenArgs) -> anyhow::Result<i32> {
    if let Err(e) = std::fs::create_dir_all(&args.outdir) {
        eprintln!("error: creating {}: {e}", args.outdir.display());
        return Ok(EXIT_TOOL_FAILURE);
    }
    let out = args.outdir.join("rulesteward.1");
    match render_manpage() {
        Ok(bytes) => match std::fs::write(&out, bytes) {
            Ok(()) => {
                println!("{}", out.display());
                Ok(EXIT_CLEAN)
            }
            Err(e) => {
                eprintln!("error: writing {}: {e}", out.display());
                Ok(EXIT_TOOL_FAILURE)
            }
        },
        Err(e) => {
            eprintln!("error: rendering man page: {e}");
            Ok(EXIT_TOOL_FAILURE)
        }
    }
}

/// Render the top-level `rulesteward` command tree to roff bytes.
fn render_manpage() -> std::io::Result<Vec<u8>> {
    let cmd = Cli::command();
    let mut buf = Vec::new();
    clap_mangen::Man::new(cmd).render(&mut buf)?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    // Unit-level guard complementing the e2e test: the rendered bytes are a
    // non-empty roff document with a `.TH` title header and the tool name. Kills a
    // mutant that returns empty bytes or drops the title macro.
    #[test]
    fn render_manpage_emits_troff_with_title_header() {
        let bytes = render_manpage().expect("render");
        let s = String::from_utf8(bytes).expect("roff output is utf-8");
        assert!(!s.is_empty(), "rendered man page must be non-empty");
        assert!(s.contains(".TH"), "must contain a .TH roff title header");
        assert!(
            s.to_uppercase().contains("RULESTEWARD"),
            "must name the tool in the title"
        );
    }

    #[test]
    fn run_writes_rulesteward_1_and_returns_clean() {
        let dir = tempfile::tempdir().expect("tempdir");
        let args = MangenArgs {
            outdir: dir.path().to_path_buf(),
        };
        let code = run(&args).expect("run never errors");
        assert_eq!(code, EXIT_CLEAN);
        let page: &Path = &dir.path().join("rulesteward.1");
        assert!(page.exists(), "rulesteward.1 must be written");
        assert!(
            !std::fs::read(page).unwrap().is_empty(),
            "rulesteward.1 must be non-empty"
        );
    }
}
