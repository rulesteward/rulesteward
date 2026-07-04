//! Body of `rulesteward sysctl <subcommand>`.
//!
//! Issue #150 - the `sysctl.d`/`sysctl.conf` backend Phase-0 command shell. The
//! semantic lint passes live in `rulesteward_sysctld` (the crate owns the
//! `sysctld-` codes and the mutation gate); this shell does source-map staging,
//! rendering, and exit-code mapping only.

use crate::cli::{SysctlCommand, SysctlLintArgs};
use crate::commands::target_probe::{HostTargetProbe, LiveTargetProbe, resolve_target};
use crate::exit_code::{self, EXIT_TOOL_FAILURE};

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

fn lint(args: &SysctlLintArgs) -> i32 {
    lint_with_probe(args, &LiveTargetProbe)
}

/// `lint` with the host probe injected, so the `--target auto` resolution path is
/// unit-testable without reading the test host's `/etc/os-release`. `lint` supplies
/// the real [`LiveTargetProbe`]; tests supply a fake.
fn lint_with_probe(args: &SysctlLintArgs, probe: &dyn HostTargetProbe) -> i32 {
    // Resolve --target in the command layer (epic #251): explicit value as-is,
    // `auto` from the host probe, omitted -> version-agnostic (no W02). A failed
    // `auto` degrades to version-agnostic with a warning, never an error (read-only
    // tool). The concrete domain target is what the W02 baseline pass consumes.
    let resolved = resolve_target(args.target, probe);
    if let Some(warning) = &resolved.warning {
        eprintln!("sysctl lint: {warning}");
    }
    let target: Option<rulesteward_sysctld::TargetVersion> = resolved.target.map(Into::into);

    // --system (issue #420): scan the full standard sysctl.d search path
    // (optionally rooted at --root for hermetic testing / chroot-linting)
    // instead of a single <path>, adding the cross-directory sysctld-W03 pass
    // (lower-precedence-directory override, masked-drop-in key drop, and
    // procps/systemd applier divergence). `lint_system` performs the real
    // enumerate/mask/merge and reruns F01/W01/W02 over the merged set. clap's
    // `conflicts_with`/`requires` on SysctlLintArgs already reject --system + a
    // positional path, and --root without --system.
    if args.system {
        let (diags, sources) =
            rulesteward_sysctld::system::lint_system(args.root.as_deref(), target);
        crate::output::emit_lint(
            args.format,
            "sysctl-lint",
            SYSCTL_LINT_SCHEMA_VERSION,
            &diags,
            &sources,
        );
        return exit_code::compute(&diags, false);
    }

    let path = args
        .path
        .clone()
        .unwrap_or_else(|| std::path::PathBuf::from(DEFAULT_SYSCTL_CONF));

    // A directory target is a `sysctl.d/` drop-in directory: enumerate its
    // `*.conf` files in lexicographic order and run the cross-file last-wins W01
    // pass (issue #150), plus the version-aware W02 STIG baseline when a target is
    // selected (#335). The full cross-DIRECTORY search-path precedence (/etc vs
    // /run vs /usr/lib) is a deferred follow-up; this reasons within one directory.
    // Each finding is anchored to the real drop-in file it came from, and
    // `lint_dir_with_target` returns the staged source of every drop-in it read
    // (keyed by display path) so the human renderer shows an ariadne snippet for a
    // cross-file W01 or a present-but-insecure W02 (issue #337).
    if path.is_dir() {
        let (diags, sources) = rulesteward_sysctld::parser::lint_dir_with_target(&path, target);
        crate::output::emit_lint(
            args.format,
            "sysctl-lint",
            SYSCTL_LINT_SCHEMA_VERSION,
            &diags,
            &sources,
        );
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

    let diags = rulesteward_sysctld::parser::lint_str_with_target(&source, &path, target);

    // Stage the file's source keyed by its display path (the `source_id` convention the
    // F01/W01 and present-but-insecure W02 diagnostics set), so the human renderer takes
    // the ariadne path and shows a source snippet anchored at the real offending line via
    // each finding's byte span (issue #337). A MISSING-key W02 carries no source_id and
    // renders as a plain `file:0:0` line. `source` is moved in after the borrow ends.
    let mut sources = std::collections::BTreeMap::new();
    sources.insert(path.display().to_string(), source);
    crate::output::emit_lint(
        args.format,
        "sysctl-lint",
        SYSCTL_LINT_SCHEMA_VERSION,
        &diags,
        &sources,
    );

    exit_code::compute(&diags, false)
}
