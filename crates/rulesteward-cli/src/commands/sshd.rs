//! Body of `rulesteward sshd <subcommand>`.
//!
//! Issue #149 - the `sshd_config` backend Phase-0 command shell. The semantic lint
//! passes live in `rulesteward_sshd::lints` (the crate owns the `sshd-` codes and
//! the mutation gate); this shell does target resolution, source-map staging,
//! rendering, and exit-code mapping only.

use serde::Serialize;

use crate::cli::{HumanJsonFormat, SshdCommand, SshdLintArgs};
use crate::commands::target_probe::{HostTargetProbe, LiveTargetProbe, resolve_target};
use crate::exit_code::{self, EXIT_TOOL_FAILURE};
use crate::output::json::render_envelope;
use rulesteward_sshd::{SshdLintContext, lints, parser::parse_config_str_located};

/// Schema version for the `sshd-lint` payload kind (CC-1).
/// Bumps only on a breaking change (field removal, rename, retype).
const SSHD_LINT_SCHEMA_VERSION: u32 = 1;

/// Default lint target: where sshd reads its primary config from.
const DEFAULT_SSHD_CONFIG: &str = "/etc/ssh/sshd_config";

pub fn run(cmd: SshdCommand) -> anyhow::Result<i32> {
    match cmd {
        SshdCommand::Lint(args) => Ok(lint(&args)),
    }
}

/// JSON payload for the `sshd-lint` envelope kind (CC-1).
#[derive(Serialize)]
struct SshdLintPayload<'a> {
    diagnostics: &'a [rulesteward_core::Diagnostic],
}

fn lint(args: &SshdLintArgs) -> i32 {
    lint_with_probe(args, &LiveTargetProbe)
}

/// `lint` with the host probe injected, so the `--target auto` resolution path is
/// unit-testable without reading the test host's `/etc/os-release`. `lint` supplies
/// the real [`LiveTargetProbe`]; tests supply a fake.
fn lint_with_probe(args: &SshdLintArgs, probe: &dyn HostTargetProbe) -> i32 {
    let path = args
        .path
        .clone()
        .unwrap_or_else(|| std::path::PathBuf::from(DEFAULT_SSHD_CONFIG));

    // Resolve --target in the command layer (epic #251): explicit value as-is,
    // `auto` from the host probe, omitted -> version-agnostic. A failed `auto`
    // degrades to version-agnostic with a warning, never an error (read-only tool).
    let resolved = resolve_target(args.target, probe);
    if let Some(warning) = &resolved.warning {
        eprintln!("sshd lint: {warning}");
    }
    let ctx = SshdLintContext {
        target: resolved.target.map(Into::into),
        single_file: !path.is_dir(),
    };

    // A directory target is the standard /etc/ssh layout: a main `sshd_config`
    // plus a `sshd_config.d/` drop-in directory. It routes to the cross-file
    // sshd-F02 override check (#149 Wave C). Sources are not staged for the
    // directory mode (F02 diagnostics are anchored to the offending drop-in
    // file). A file target keeps the single-file pass path.
    if path.is_dir() {
        let diags = lints::drop_in::lint_drop_in(&path, &ctx);
        let sources = std::collections::BTreeMap::new();
        let output = match args.format {
            HumanJsonFormat::Human => crate::output::human::render(&diags, &sources),
            HumanJsonFormat::Json => render_envelope(
                "sshd-lint",
                SSHD_LINT_SCHEMA_VERSION,
                &SshdLintPayload {
                    diagnostics: &diags,
                },
            ),
        };
        if !output.is_empty() {
            print!("{output}");
        }
        return exit_code::compute(&diags, false);
    }

    // A path that is neither a file nor a directory (e.g. missing) is a tool
    // failure.
    if !path.is_file() {
        eprintln!("sshd lint: not a file or directory: {}", path.display());
        return EXIT_TOOL_FAILURE;
    }

    let source = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("sshd lint: cannot read {}: {e}", path.display());
            return EXIT_TOOL_FAILURE;
        }
    };

    // Stage the source (keyed by display path, the diagnostics' source_id
    // convention) so the human renderer can show ariadne snippets.
    let mut sources = std::collections::BTreeMap::new();
    let mut diags: Vec<rulesteward_core::Diagnostic> = Vec::new();
    match parse_config_str_located(&source, &path) {
        Ok(blocks) => {
            diags.extend(lints::lint(&blocks, &path, &ctx));
        }
        // A syntax error short-circuits the semantic passes: sshd-F01 -> exit 5.
        Err(errs) => diags.extend(errs.iter().map(lints::parse_error_to_diagnostic)),
    }
    sources.insert(path.display().to_string(), source);

    let output = match args.format {
        HumanJsonFormat::Human => crate::output::human::render(&diags, &sources),
        HumanJsonFormat::Json => render_envelope(
            "sshd-lint",
            SSHD_LINT_SCHEMA_VERSION,
            &SshdLintPayload {
                diagnostics: &diags,
            },
        ),
    };
    if !output.is_empty() {
        print!("{output}");
    }

    exit_code::compute(&diags, false)
}

#[cfg(test)]
mod lint_shell_tests {
    use super::{HostTargetProbe, lint, lint_with_probe};
    use crate::cli::{HumanJsonFormat, SshdLintArgs, TargetSelector, TargetVersionArg};
    use crate::exit_code::{EXIT_CLEAN, EXIT_RULE_PARSE_ERROR, EXIT_TOOL_FAILURE};

    /// A host probe returning a canned result, so the `--target auto` wiring is
    /// exercised without depending on the test host's /etc/os-release.
    struct FakeProbe(Result<Option<TargetVersionArg>, String>);
    impl HostTargetProbe for FakeProbe {
        fn detect(&self) -> Result<Option<TargetVersionArg>, String> {
            self.0.clone()
        }
    }

    fn args(path: &std::path::Path, format: HumanJsonFormat) -> SshdLintArgs {
        SshdLintArgs {
            path: Some(path.to_path_buf()),
            format,
            target: None,
        }
    }

    // A fully STIG-compliant config: all RHEL9-required directives present with
    // baseline-correct values, no weak crypto, no deprecated keywords, no
    // structural issues. Verified lint-clean under both target=None (the RHEL8
    // floor) and --target rhel9. Wave B made the W01/W02 passes real, so a minimal
    // config is no longer "clean" (it is missing STIG-required directives).
    const CLEAN_CONFIG: &str = "\
Banner /etc/issue.net
LogLevel VERBOSE
PubkeyAuthentication yes
PermitEmptyPasswords no
PermitRootLogin no
UsePAM yes
HostbasedAuthentication no
PermitUserEnvironment no
RekeyLimit 1G 1h
ClientAliveCountMax 1
ClientAliveInterval 300
Compression no
GSSAPIAuthentication no
KerberosAuthentication no
IgnoreRhosts yes
IgnoreUserKnownHosts yes
X11Forwarding no
StrictModes yes
PrintLastLog yes
X11UseLocalhost yes
";

    #[test]
    fn missing_path_exits_tool_failure() {
        let a = args(
            std::path::Path::new("/nonexistent/149/sshd_config"),
            HumanJsonFormat::Human,
        );
        assert_eq!(lint(&a), EXIT_TOOL_FAILURE);
    }

    #[test]
    fn directory_target_with_clean_dropins_exits_zero() {
        // F02 (#149 Wave C) accepts a directory target: the standard /etc/ssh
        // layout (a main `sshd_config` plus a `sshd_config.d/` drop-in
        // directory) routes to the cross-file drop-in override check. A directory
        // whose drop-ins do not override the hardened main file produces no F02
        // finding and exits 0 (this is GREEN against the empty stub today; the
        // F02-FIRES cases live in the rulesteward-sshd unit + e2e tests).
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("sshd_config"), CLEAN_CONFIG).expect("write main");
        let dropin_dir = dir.path().join("sshd_config.d");
        std::fs::create_dir_all(&dropin_dir).expect("mkdir sshd_config.d");
        std::fs::write(dropin_dir.join("50-clean.conf"), "PermitRootLogin no\n")
            .expect("write drop-in");
        let a = args(dir.path(), HumanJsonFormat::Human);
        assert_eq!(
            lint(&a),
            EXIT_CLEAN,
            "a directory with clean drop-ins is accepted and exits 0"
        );
    }

    #[test]
    fn clean_config_exits_zero() {
        let dir = tempfile::tempdir().expect("tempdir");
        let f = dir.path().join("sshd_config");
        std::fs::write(&f, CLEAN_CONFIG).expect("write");
        let a = args(&f, HumanJsonFormat::Json);
        assert_eq!(lint(&a), EXIT_CLEAN);
    }

    #[test]
    fn unparseable_config_exits_five() {
        // An unterminated quote maps to sshd-F01 -> exit 5 (shared scheme).
        let dir = tempfile::tempdir().expect("tempdir");
        let f = dir.path().join("sshd_config");
        std::fs::write(&f, "Banner \"/etc/issue\n").expect("write");
        let a = args(&f, HumanJsonFormat::Human);
        assert_eq!(lint(&a), EXIT_RULE_PARSE_ERROR);
    }

    #[test]
    fn target_flag_is_accepted() {
        // --target is plumbed into the lint context; a fully RHEL9-compliant
        // config lints clean under --target rhel9 (exit 0).
        let dir = tempfile::tempdir().expect("tempdir");
        let f = dir.path().join("sshd_config");
        std::fs::write(&f, CLEAN_CONFIG).expect("write");
        let a = SshdLintArgs {
            path: Some(f),
            format: HumanJsonFormat::Human,
            target: Some(TargetSelector::Rhel9),
        };
        assert_eq!(lint(&a), EXIT_CLEAN);
    }

    #[test]
    fn target_auto_threads_the_probed_target() {
        // `--target auto` resolves via the host probe; a probe that detects rhel9
        // makes a fully RHEL9-compliant config lint clean (exit 0), proving the
        // resolved target is threaded into the lint context.
        let dir = tempfile::tempdir().expect("tempdir");
        let f = dir.path().join("sshd_config");
        std::fs::write(&f, CLEAN_CONFIG).expect("write");
        let a = SshdLintArgs {
            path: Some(f),
            format: HumanJsonFormat::Human,
            target: Some(TargetSelector::Auto),
        };
        let probe = FakeProbe(Ok(Some(TargetVersionArg::Rhel9)));
        assert_eq!(lint_with_probe(&a, &probe), EXIT_CLEAN);
    }

    #[test]
    fn target_auto_degrades_gracefully_when_unmappable() {
        // A non-RHEL host (probe yields None) must NOT error: `--target auto`
        // falls back to the version-agnostic dialect, under which the
        // RHEL8-floor-clean config still exits 0.
        let dir = tempfile::tempdir().expect("tempdir");
        let f = dir.path().join("sshd_config");
        std::fs::write(&f, CLEAN_CONFIG).expect("write");
        let a = SshdLintArgs {
            path: Some(f),
            format: HumanJsonFormat::Human,
            target: Some(TargetSelector::Auto),
        };
        let probe = FakeProbe(Ok(None));
        assert_eq!(lint_with_probe(&a, &probe), EXIT_CLEAN);
    }
}
