//! Body of `rulesteward sysctl <subcommand>`.
//!
//! Issue #150 - the `sysctl.d`/`sysctl.conf` backend Phase-0 command shell. The
//! semantic lint passes live in `rulesteward_sysctld` (the crate owns the
//! `sysctld-` codes and the mutation gate); this shell does source-map staging,
//! rendering, and exit-code mapping only.

use serde::Serialize;

use crate::cli::{HumanJsonFormat, SysctlCommand, SysctlLintArgs};
use crate::exit_code::{self, EXIT_TOOL_FAILURE};
use crate::output::json::render_envelope;

/// Schema version for the `sysctl-lint` payload kind (CC-1).
/// Bumps only on a breaking change (field removal, rename, retype).
const SYSCTL_LINT_SCHEMA_VERSION: u32 = 1;

/// Default lint target: the primary system sysctl config file.
const DEFAULT_SYSCTL_CONF: &str = "/etc/sysctl.conf";

pub fn run(cmd: SysctlCommand) -> anyhow::Result<i32> {
    match cmd {
        SysctlCommand::Lint(args) => Ok(lint(&args)),
    }
}

/// JSON payload for the `sysctl-lint` envelope kind (CC-1).
#[derive(Serialize)]
struct SysctlLintPayload<'a> {
    diagnostics: &'a [rulesteward_core::Diagnostic],
}

fn lint(args: &SysctlLintArgs) -> i32 {
    let path = args
        .path
        .clone()
        .unwrap_or_else(|| std::path::PathBuf::from(DEFAULT_SYSCTL_CONF));

    // A directory target is a `sysctl.d/` drop-in directory: enumerate its
    // `*.conf` files in lexicographic order and run the cross-file last-wins W01
    // pass (issue #150). The full cross-DIRECTORY search-path precedence (/etc vs
    // /run vs /usr/lib) is a deferred follow-up; this reasons within one directory.
    // Each finding is anchored to the real drop-in file it came from. Dir-mode v1
    // does not stage per-file sources, so the human renderer prints findings as
    // plain `file:line:col` (no ariadne snippet); staging the drop-in sources for
    // snippet rendering is a deferred follow-up.
    if path.is_dir() {
        let diags = rulesteward_sysctld::parser::lint_dir(&path);
        let sources = std::collections::BTreeMap::new();
        emit(args, &diags, &sources);
        return exit_code::compute(&diags, false);
    }

    // A path that is neither a file nor a directory (e.g. missing) is a tool
    // failure.
    if !path.is_file() {
        eprintln!("sysctl lint: not a file or directory: {}", path.display());
        return EXIT_TOOL_FAILURE;
    }

    let source = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("sysctl lint: cannot read {}: {e}", path.display());
            return EXIT_TOOL_FAILURE;
        }
    };

    let diags = rulesteward_sysctld::parser::lint_str(&source, &path);

    // Stage the source (keyed by display path, the diagnostics' source_id
    // convention) so the human renderer can show ariadne snippets when the
    // F01/W01 passes anchor findings.
    let mut sources = std::collections::BTreeMap::new();
    sources.insert(path.display().to_string(), source);
    emit(args, &diags, &sources);

    exit_code::compute(&diags, false)
}

/// Render `diags` via the format the operator selected and print non-empty
/// output. Shared by the file and directory paths so both surface identical
/// human / JSON envelopes.
fn emit(
    args: &SysctlLintArgs,
    diags: &[rulesteward_core::Diagnostic],
    sources: &std::collections::BTreeMap<String, String>,
) {
    let output = match args.format {
        HumanJsonFormat::Human => crate::output::human::render(diags, sources),
        HumanJsonFormat::Json => render_envelope(
            "sysctl-lint",
            SYSCTL_LINT_SCHEMA_VERSION,
            &SysctlLintPayload { diagnostics: diags },
        ),
    };
    if !output.is_empty() {
        print!("{output}");
    }
}
