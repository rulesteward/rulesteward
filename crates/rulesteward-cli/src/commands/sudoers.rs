//! Body of `rulesteward sudoers <subcommand>`.
//!
//! Issue #329 - the `sudoers(5)` backend Phase-0 command shell. The parser and
//! semantic lint passes live in `rulesteward_sudoers` (the crate owns the `sudo-`
//! codes and the mutation gate); this shell does target resolution, source-map
//! staging, rendering, and exit-code mapping only. There is NO `--target` rail
//! (the sudo STIG findings are version-agnostic).

use crate::cli::{SudoersCommand, SudoersLintArgs};
use crate::exit_code::EXIT_TOOL_FAILURE;
use rulesteward_core::Framework;
use rulesteward_sudoers::{SudoersLintContext, lints, resolve};

/// Schema version for the `sudoers-lint` payload kind (CC-1).
/// Bumps only on a breaking change (field removal, rename, retype).
const SUDOERS_LINT_SCHEMA_VERSION: u32 = 1;

/// Default lint target: where sudo reads its primary policy from.
const DEFAULT_SUDOERS: &str = "/etc/sudoers";

pub fn run(cmd: SudoersCommand, profile: Option<Framework>) -> anyhow::Result<i32> {
    match cmd {
        SudoersCommand::Lint(args) => Ok(lint(&args, profile)),
    }
}

fn lint(args: &SudoersLintArgs, profile: Option<Framework>) -> i32 {
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
    let mut diags = lints::lint(&files, &ctx);

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

    let no_op = crate::profile::apply_profile(&mut diags, profile);

    if let Err(e) = crate::output::emit_lint(
        args.format,
        "sudoers-lint",
        SUDOERS_LINT_SCHEMA_VERSION,
        &diags,
        &sources,
    ) {
        eprintln!("sudoers lint: rendering {:?} output: {e}", args.format);
        return EXIT_TOOL_FAILURE;
    }

    crate::profile::resolve_exit_code(no_op, &diags, false)
}

#[cfg(test)]
mod lint_shell_tests {
    use super::lint;
    use crate::cli::{OutputFormat, SudoersLintArgs};
    use crate::exit_code::{EXIT_CLEAN, EXIT_RULE_PARSE_ERROR, EXIT_TOOL_FAILURE, EXIT_WARNINGS};
    use crate::output::json;
    use rulesteward_sudoers::{SudoersLintContext, lints, resolve};

    fn args(path: &std::path::Path, format: OutputFormat) -> SudoersLintArgs {
        SudoersLintArgs {
            path: Some(path.to_path_buf()),
            format,
        }
    }

    // A STIG-clean sudoers file: env_reset, the required hardening (use_pty +
    // logfile + timestamp_timeout, satisfying the #347 / #363 merged missing-required
    // check), two user-specs, and a #includedir. Verified `visudo -c` clean.
    //
    // The `#includedir` target is a caller-supplied path rather than a literal
    // `/etc/sudoers.d` (#466): the resolver in `rulesteward_sudoers::resolve`
    // FOLLOWS `#includedir` into the given directory (an absolute path is used
    // verbatim, not joined to anything), so a hardcoded `/etc/sudoers.d` made
    // this fixture read the HOST's real drop-in directory. On a host with a
    // readable NOPASSWD drop-in that flips the asserted exit code. Pointing the
    // directive at a test-owned tempdir keeps the fixture hermetic.
    fn clean_sudoers(includedir: &std::path::Path) -> String {
        format!(
            "\
Defaults env_reset
Defaults use_pty
Defaults logfile=/var/log/sudo.log
Defaults timestamp_timeout=5
root ALL=(ALL:ALL) ALL
%wheel ALL=(ALL) ALL
#includedir {}
",
            includedir.display()
        )
    }

    #[test]
    fn missing_path_exits_tool_failure() {
        let a = args(
            std::path::Path::new("/nonexistent/329/sudoers"),
            OutputFormat::Human,
        );
        assert_eq!(lint(&a, None), EXIT_TOOL_FAILURE);
    }

    #[test]
    fn clean_file_exits_zero() {
        let dir = tempfile::tempdir().expect("tempdir");
        let f = dir.path().join("sudoers");
        // The includedir target is a test-owned, EMPTY tempdir (not the host's
        // real /etc/sudoers.d) so this stays hermetic (#466).
        let dropins = dir.path().join("sudoers.d");
        std::fs::create_dir(&dropins).expect("mkdir dropins");
        std::fs::write(&f, clean_sudoers(&dropins)).expect("write");
        let a = args(&f, OutputFormat::Json);
        assert_eq!(lint(&a, None), EXIT_CLEAN);
    }

    /// Companion to `clean_file_exits_zero` (#466): same fixture shape, but the
    /// includedir tempdir now holds a NOPASSWD-on-ALL drop-in. Proves the
    /// hermetic rewrite above did not lose `#includedir`-following coverage: the
    /// linter must still follow the directive into the drop-in and raise
    /// `sudo-W01` (a Warning, so `EXIT_WARNINGS` / exit 1 per
    /// `exit_code::compute`) -- the same diagnostic a real
    /// `/etc/sudoers.d/*NOPASSWD*` drop-in would have raised on a populated
    /// host, grounded against the `sudo-W01` firing tests in
    /// `rulesteward_sudoers::lints::tags` (NOPASSWD effective + `CmndItem::All`).
    #[test]
    fn clean_file_with_dropin_nopasswd_all_exits_one_w01() {
        let dir = tempfile::tempdir().expect("tempdir");
        let f = dir.path().join("sudoers");
        let dropins = dir.path().join("sudoers.d");
        std::fs::create_dir(&dropins).expect("mkdir dropins");
        std::fs::write(dropins.join("99-nopasswd"), "ALL ALL=(ALL) NOPASSWD: ALL\n")
            .expect("write dropin");
        std::fs::write(&f, clean_sudoers(&dropins)).expect("write");
        let a = args(&f, OutputFormat::Human);
        assert_eq!(lint(&a, None), EXIT_WARNINGS);
    }

    #[test]
    fn malformed_file_exits_five() {
        // A garbage line maps to sudo-F01 -> exit 5 (shared scheme).
        let dir = tempfile::tempdir().expect("tempdir");
        let f = dir.path().join("sudoers");
        std::fs::write(&f, "this is not valid sudoers\n").expect("write");
        let a = args(&f, OutputFormat::Human);
        assert_eq!(lint(&a, None), EXIT_RULE_PARSE_ERROR);
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
        let a = args(dir.path(), OutputFormat::Human);
        assert_eq!(lint(&a, None), EXIT_CLEAN);
    }

    /// CLI-level pin for #485 (sudo-W04 silent on an empty linted FILE): an
    /// empty top-level file must exit `EXIT_WARNINGS` (the resolver's phantom
    /// segment carries the three sudo-W04 merged-absence findings, all
    /// Warnings) AND those findings must actually RENDER through the same
    /// pipeline `lint()` drives -- not just be produced by the resolver/lint
    /// layer already pinned in `rulesteward_sudoers`. Cheap insurance given
    /// #401's history in this crate (an empty synthetic `source` clobbering a
    /// real source in this file's `BTreeMap` staging, guarded by `if
    /// !file.source.is_empty()` at line 64 above) -- a synthesized empty file
    /// is exactly that shape again. Verified the guard degrades gracefully
    /// (a missing `sources` entry falls back to plain-format rendering in
    /// `output::human::render`, it does not drop the finding), but this pins
    /// the end-to-end outcome so a future refactor of either layer cannot
    /// silently regress it.
    #[test]
    fn empty_file_exits_warnings_and_renders_absence_findings() {
        let dir = tempfile::tempdir().expect("tempdir");
        let f = dir.path().join("sudoers");
        std::fs::write(&f, "").expect("write byte-empty file");

        let a = args(&f, OutputFormat::Json);
        assert_eq!(
            lint(&a, None),
            EXIT_WARNINGS,
            "an empty linted file must exit EXIT_WARNINGS (the three sudo-W04 \
             merged-absence findings are Warnings), not EXIT_CLEAN"
        );

        // Drive the SAME resolve -> lint -> render pipeline `lint()` uses
        // internally, so the rendered TEXT is actually asserted (not just the
        // exit code above).
        let files = resolve::resolve_target(&f).expect("resolve a byte-empty file");
        let diags = lints::lint(&files, &SudoersLintContext::default());
        let rendered =
            json::render_lint_envelope("sudoers-lint", super::SUDOERS_LINT_SCHEMA_VERSION, &diags);
        assert!(
            rendered.contains("sudo-W04"),
            "the rendered JSON envelope must actually carry the sudo-W04 \
             findings, not just an empty diagnostics array; got {rendered}"
        );
        assert!(
            rendered.contains("use_pty"),
            "the rendered JSON envelope must name the use_pty absence \
             finding; got {rendered}"
        );
    }
}
