//! sshd-E03: unresolved `Include`. See [`e03`].

use std::path::{Path, PathBuf};

use rulesteward_core::{Diagnostic, Severity};

use crate::ast::Block;
use crate::lints::{SshdLintContext, anchored};

/// sshd-E03: `Include` references a path or glob that resolves to nothing.
///
/// Resolves each literal `Include` argument against the config's directory (the
/// `/etc/ssh/` rule for the real `sshd_config`; see `include_base_dir`) and flags
/// any pattern that matches no existing file (see `include_pattern_resolves`).
#[must_use]
pub fn e03(blocks: &[Block], file: &Path, _ctx: &SshdLintContext) -> Vec<Diagnostic> {
    // Relative includes resolve against the directory of the file being linted,
    // which equals sshd's "/etc/ssh" rule for the real /etc/ssh/sshd_config.
    let base_dir = include_base_dir(file);

    let mut diags = Vec::new();
    for block in blocks {
        // Include directives may appear in the global block AND inside Match blocks.
        let directives = match block {
            Block::Global(directives) => directives,
            Block::Match(match_block) => &match_block.body,
        };
        for directive in directives {
            if !directive.keyword.eq_ignore_ascii_case("include") {
                continue;
            }
            // One Include line may carry several patterns; flag each that resolves
            // to nothing. sshd silently ignores a broken Include, so this surfaces
            // otherwise-invisible config drift.
            for pattern in &directive.args {
                if !include_pattern_resolves(&base_dir, pattern) {
                    diags.push(anchored(
                        Severity::Error,
                        "sshd-E03",
                        directive.span.clone(),
                        format!("Include '{pattern}' resolves to no files"),
                        file,
                        directive.line,
                    ));
                }
            }
        }
    }
    diags
}

/// The directory a relative `Include` resolves against: the linted file's parent,
/// or the current directory when the path has no parent component.
fn include_base_dir(file: &Path) -> PathBuf {
    match file.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

/// Whether an `Include` pattern resolves to at least one existing FILE, applying
/// the operator-chosen "skip benign empty-glob" rule: a glob whose directory
/// exists but currently matches no files is treated as resolved (the stock
/// `Include /etc/ssh/sshd_config.d/*.conf` on a system with no drop-ins).
///
/// sshd includes configuration FILES, not directories: an `Include` that resolves
/// only to a directory loads nothing (verified with `sshd -T`), so a match must be
/// a regular file (`is_file` follows symlinks) to count as resolved.
fn include_pattern_resolves(base_dir: &Path, pattern: &str) -> bool {
    let resolved = if Path::new(pattern).is_absolute() {
        PathBuf::from(pattern)
    } else {
        base_dir.join(pattern)
    };

    // `glob` resolves a literal path (no metacharacters) and a wildcard pattern
    // uniformly, yielding only paths that exist on disk.
    let Ok(matches) = glob::glob(&resolved.to_string_lossy()) else {
        // An unparseable glob pattern is not E03's concern; do not flag it.
        return true;
    };
    // `flatten` deliberately skips per-entry `GlobError`s (e.g. an unreadable
    // directory during the walk): an I/O hiccup mid-walk must not manufacture an
    // E03 finding for a config that may be perfectly valid.
    if matches.flatten().any(|p| p.is_file()) {
        return true;
    }

    // No file matched. A literal path is simply missing/not-a-file (a finding). A
    // glob is benign only when the directory it expands within exists.
    if has_glob_metacharacters(pattern) {
        glob_is_benign_empty(&resolved)
    } else {
        false
    }
}

/// Whether a pattern contains a glob(7) metacharacter (`*`, `?`, or `[`).
fn has_glob_metacharacters(pattern: &str) -> bool {
    pattern.contains(['*', '?', '['])
}

/// Whether a zero-match glob is the benign "directory present, no files yet" case
/// rather than drift. True only for a trailing-filename glob (`<dir>/<glob>`)
/// whose containing directory exists. A glob in a parent component (`sub*/x.conf`)
/// has no single literal containing directory, so a zero match there is treated as
/// a finding (the intended directory structure did not expand to anything).
fn glob_is_benign_empty(resolved: &Path) -> bool {
    let Some(parent) = resolved.parent() else {
        return false;
    };
    if has_glob_metacharacters(&parent.to_string_lossy()) {
        return false;
    }
    parent.is_dir()
}

#[cfg(test)]
mod e03_helper_tests {
    //! Unit tests for the E03 filesystem helpers (the path/glob cases that need
    //! real directory state live in `tests/test_lints_e03_include.rs`).

    use super::{glob_is_benign_empty, include_base_dir};
    use std::path::{Path, PathBuf};

    #[test]
    fn base_dir_is_the_parent_directory() {
        assert_eq!(
            include_base_dir(Path::new("/etc/ssh/sshd_config")),
            PathBuf::from("/etc/ssh")
        );
    }

    #[test]
    fn base_dir_falls_back_to_dot_for_a_bare_filename() {
        // A path with no directory component (parent is the empty string) must
        // resolve relative includes against ".", not "".
        assert_eq!(
            include_base_dir(Path::new("sshd_config")),
            PathBuf::from(".")
        );
    }

    #[test]
    fn benign_empty_is_true_only_for_a_trailing_glob_over_an_existing_dir() {
        let dir = tempfile::tempdir().unwrap();
        let existing = dir.path().join("dropin.d");
        std::fs::create_dir(&existing).unwrap();
        // Trailing-filename glob over an existing directory: benign.
        assert!(glob_is_benign_empty(&existing.join("*.conf")));
        // Trailing glob over a missing directory: not benign (a finding).
        assert!(!glob_is_benign_empty(&dir.path().join("missing.d/*.conf")));
        // Glob in a parent component: never benign (no single literal dir).
        assert!(!glob_is_benign_empty(&dir.path().join("sub*/x.conf")));
    }
}
