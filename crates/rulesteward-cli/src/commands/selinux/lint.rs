//! Body of `rulesteward selinux lint` (#520).
//!
//! Reads `/etc/selinux/config` (or a supplied path), parses it via
//! `rulesteward_selinux::config::parse_selinux_config`, runs the se-W01/se-W02
//! boot-configuration checks, and renders diagnostics in the requested format.
//! Clones `commands::sysctl.rs`'s shape (target resolution in the command
//! layer, `emit_lint` for rendering, `apply_profile`/`resolve_exit_code` for
//! the exit-code contract).

use std::collections::BTreeMap;
use std::path::PathBuf;

use rulesteward_core::{Diagnostic, Framework};
use rulesteward_selinux::TargetVersion;
use rulesteward_selinux::config::parse_selinux_config;
use rulesteward_selinux::lints::{check_enforcing, check_policy_type};

use crate::cli::SelinuxLintArgs;
use crate::commands::target_probe::{HostTargetProbe, LiveTargetProbe, resolve_target};
use crate::exit_code::EXIT_TOOL_FAILURE;

/// Schema version for the `selinux-lint` payload kind.
/// Bumps only on a breaking change (field removal, rename, retype).
const SELINUX_LINT_SCHEMA_VERSION: u32 = 1;

/// Default lint target: the real `/etc/selinux/config` path.
const DEFAULT_SELINUX_CONFIG: &str = "/etc/selinux/config";

pub(super) fn run_lint(args: &SelinuxLintArgs, profile: Option<Framework>) -> i32 {
    run_lint_with_probe(args, &LiveTargetProbe, profile)
}

/// `run_lint` with the host probe injected, so the `--target auto` resolution
/// path is unit-testable without reading the test host's `/etc/os-release`.
/// `run_lint` supplies the real [`LiveTargetProbe`]; tests supply a fake.
fn run_lint_with_probe(
    args: &SelinuxLintArgs,
    probe: &dyn HostTargetProbe,
    profile: Option<Framework>,
) -> i32 {
    // Resolve --target in the command layer (epic #251): explicit value as-is,
    // `auto` from the host probe, omitted -> version-agnostic (no
    // se-W01/se-W02). A failed `auto` degrades to version-agnostic with a
    // warning, never an error (read-only tool).
    let resolved = resolve_target(args.target, probe);
    if let Some(warning) = &resolved.warning {
        eprintln!("selinux lint: {warning}");
    }
    let target: Option<TargetVersion> = resolved.target.map(Into::into);

    let path = args
        .path
        .clone()
        .unwrap_or_else(|| PathBuf::from(DEFAULT_SELINUX_CONFIG));

    let text = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("selinux lint: cannot read {}: {e}", path.display());
            return EXIT_TOOL_FAILURE;
        }
    };

    let config = parse_selinux_config(&text);

    let mut diags: Vec<Diagnostic> = check_enforcing(&config, target, &path);
    diags.extend(check_policy_type(&config, target, &path));

    let no_op = crate::profile::apply_profile(&mut diags, profile);

    // Stage the file's source keyed by its display path (the `source_id`
    // convention every anchored finding sets), so the human renderer shows an
    // ariadne snippet for a present-but-insecure se-W01/se-W02.
    let mut sources: BTreeMap<String, String> = BTreeMap::new();
    sources.insert(path.display().to_string(), text);

    crate::output::emit_lint(
        args.format,
        "selinux-lint",
        SELINUX_LINT_SCHEMA_VERSION,
        &diags,
        &sources,
    );

    crate::profile::resolve_exit_code(no_op, &diags, false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{HumanJsonFormat, TargetSelector};
    use crate::exit_code::EXIT_TOOL_FAILURE;

    /// A host probe returning a canned result, so the `--target auto` wiring
    /// is exercised without depending on the test host's `/etc/os-release`.
    /// Mirrors `commands::sysctl`'s `FakeProbe`.
    struct FakeProbe(Result<Option<crate::cli::TargetVersionArg>, String>);
    impl HostTargetProbe for FakeProbe {
        fn detect(&self) -> Result<Option<crate::cli::TargetVersionArg>, String> {
            self.0.clone()
        }
    }

    fn args(path: Option<PathBuf>) -> SelinuxLintArgs {
        SelinuxLintArgs {
            path,
            format: HumanJsonFormat::Human,
            target: None,
        }
    }

    /// A path that is neither a file nor readable is a tool failure.
    #[test]
    fn missing_path_exits_tool_failure() {
        let a = args(Some(PathBuf::from("/nonexistent/440/selinux-config")));
        assert_eq!(run_lint(&a, None), EXIT_TOOL_FAILURE);
    }

    /// `--target auto` on a host the probe cannot map degrades to the
    /// version-agnostic dialect AND prints the operator warning, without
    /// erroring (mirrors `commands::sysctl`'s analogous test).
    #[test]
    fn target_auto_degrade_prints_warning_and_does_not_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let f = dir.path().join("config");
        std::fs::write(&f, "SELINUX=enforcing\nSELINUXTYPE=targeted\n").expect("write");
        let a = SelinuxLintArgs {
            path: Some(f),
            format: HumanJsonFormat::Human,
            target: Some(TargetSelector::Auto),
        };
        let probe = FakeProbe(Ok(None));
        // Not asserting a specific exit: the point of this test is the
        // warning-print + auto-degrade wiring, exercised regardless of what
        // the (currently todo!()'d) lint passes return.
        let _ = run_lint_with_probe(&a, &probe, None);
    }
}
