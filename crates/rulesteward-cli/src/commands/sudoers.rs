//! Body of `rulesteward sudoers <subcommand>`.
//!
//! Issue #329 - the `sudoers(5)` backend Phase-0 command shell. The parser and
//! semantic lint passes live in `rulesteward_sudoers` (the crate owns the `sudo-`
//! codes and the mutation gate); this shell does target resolution, source-map
//! staging, rendering, and exit-code mapping only. There is NO `--target` rail
//! (the sudo STIG findings are version-agnostic).

use crate::cli::{SudoersCommand, SudoersLintArgs};
use crate::exit_code::{self, EXIT_TOOL_FAILURE};
use rulesteward_sudoers::{SudoersLintContext, lints, resolve};

/// Schema version for the `sudoers-lint` payload kind (CC-1).
/// Bumps only on a breaking change (field removal, rename, retype).
const SUDOERS_LINT_SCHEMA_VERSION: u32 = 1;

/// Default lint target: where sudo reads its primary policy from.
const DEFAULT_SUDOERS: &str = "/etc/sudoers";

pub fn run(cmd: SudoersCommand) -> anyhow::Result<i32> {
    match cmd {
        SudoersCommand::Lint(args) => Ok(lint(&args)),
    }
}

fn lint(args: &SudoersLintArgs) -> i32 {
    let path = args
        .path
        .clone()
        .unwrap_or_else(|| std::path::PathBuf::from(DEFAULT_SUDOERS));

    // Resolve the target into the SudoersFiles to lint: a single file -> one
    // parsed file; a sudoers.d directory -> each eligible drop-in (#334 seam). A
    // read failure (missing / unreadable path) is a tool failure (read-only tool).
    let files = match resolve::resolve_target(&path) {
        Ok(files) => files,
        Err(e) => {
            eprintln!("sudoers lint: cannot read {}: {e}", path.display());
            return EXIT_TOOL_FAILURE;
        }
    };

    let ctx = SudoersLintContext::default();
    let diags = lints::lint(&files, &ctx);

    // Stage each file's source (keyed by display path, the diagnostics' source_id
    // convention) so the human renderer can resolve ariadne snippets for anchored
    // findings. sudo-F01 anchors a genuine malformed line in real source text
    // (non-empty byte span, source_id set, ariadne renders a caret snippet); a
    // missing/cyclic @include marker has no real backing source, so it stays
    // unanchored and renders plainly (#382).
    //
    // A missing/cyclic @include marker (`resolve::malformed_marker`) carries the
    // SAME path as the including file but an EMPTY `source` (#401). Several
    // segments can share one path (the file's own content plus zero or more
    // resolution markers, in either order), so a plain last-write-wins `insert`
    // can let a later empty marker overwrite an already-staged real source,
    // blanking every anchored diagnostic for that path. Skip empty sources
    // entirely: an empty marker never clobbers a real source, and real-vs-real
    // for the same path stays last-write-wins.
    let mut sources = std::collections::BTreeMap::new();
    for file in &files {
        if !file.source.is_empty() {
            sources.insert(file.path.display().to_string(), file.source.clone());
        }
    }

    crate::output::emit_lint(
        args.format,
        "sudoers-lint",
        SUDOERS_LINT_SCHEMA_VERSION,
        &diags,
        &sources,
    );

    exit_code::compute(&diags, false)
}

#[cfg(test)]
mod lint_shell_tests {
    use super::lint;
    use crate::cli::{HumanJsonFormat, SudoersLintArgs};
    use crate::exit_code::{EXIT_CLEAN, EXIT_RULE_PARSE_ERROR, EXIT_TOOL_FAILURE};

    fn args(path: &std::path::Path, format: HumanJsonFormat) -> SudoersLintArgs {
        SudoersLintArgs {
            path: Some(path.to_path_buf()),
            format,
        }
    }

    // A STIG-clean sudoers file: env_reset, the required hardening (use_pty +
    // logfile + timestamp_timeout, satisfying the #347 / #363 merged missing-required
    // check), two user-specs, and a #includedir. Verified `visudo -c` clean.
    const CLEAN_SUDOERS: &str = "\
Defaults env_reset
Defaults use_pty
Defaults logfile=/var/log/sudo.log
Defaults timestamp_timeout=5
root ALL=(ALL:ALL) ALL
%wheel ALL=(ALL) ALL
#includedir /etc/sudoers.d
";

    #[test]
    fn missing_path_exits_tool_failure() {
        let a = args(
            std::path::Path::new("/nonexistent/329/sudoers"),
            HumanJsonFormat::Human,
        );
        assert_eq!(lint(&a), EXIT_TOOL_FAILURE);
    }

    #[test]
    fn clean_file_exits_zero() {
        let dir = tempfile::tempdir().expect("tempdir");
        let f = dir.path().join("sudoers");
        std::fs::write(&f, CLEAN_SUDOERS).expect("write");
        let a = args(&f, HumanJsonFormat::Json);
        assert_eq!(lint(&a), EXIT_CLEAN);
    }

    #[test]
    fn malformed_file_exits_five() {
        // A garbage line maps to sudo-F01 -> exit 5 (shared scheme).
        let dir = tempfile::tempdir().expect("tempdir");
        let f = dir.path().join("sudoers");
        std::fs::write(&f, "this is not valid sudoers\n").expect("write");
        let a = args(&f, HumanJsonFormat::Human);
        assert_eq!(lint(&a), EXIT_RULE_PARSE_ERROR);
    }

    #[test]
    fn clean_directory_exits_zero() {
        // A sudoers.d directory with clean drop-ins lints clean. A 00-defaults
        // drop-in supplies the #347 / #363-required hardening (use_pty + logfile +
        // timestamp_timeout) so the merged missing-required check is satisfied across
        // the directory.
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("00-defaults"),
            "Defaults use_pty\nDefaults logfile=/var/log/sudo.log\nDefaults timestamp_timeout=5\n",
        )
        .expect("w");
        std::fs::write(dir.path().join("10-alice"), "alice ALL=(ALL) ALL\n").expect("w");
        std::fs::write(dir.path().join("20-bob"), "bob ALL=(ALL) ALL\n").expect("w");
        let a = args(dir.path(), HumanJsonFormat::Human);
        assert_eq!(lint(&a), EXIT_CLEAN);
    }
}
