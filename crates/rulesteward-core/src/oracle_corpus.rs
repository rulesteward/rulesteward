//! Corpus-root resolution for the differential oracle harnesses (session 9k-1).
//!
//! Every Tier-1 replay test (`crates/<crate>/tests/<lane>_corpus_oracle.rs`)
//! reads a committed corpus by default, and the matching `just diff-<lane>`
//! recipe re-points that SAME test binary at a freshly captured corpus via an
//! environment variable. That is what makes the two tiers one code path: the
//! drift check cannot rot separately from the replay, because they are the
//! same assertions over a different root.
//!
//! # Why this lives in `rulesteward-core` rather than being copied per lane
//!
//! This resolution is the one fragment of the harness whose failure mode is
//! SILENT. If the recipe and the test disagree about the variable name, or an
//! empty override quietly falls back to the committed corpus, then `just
//! diff-<lane>` re-verifies the committed corpus against itself and prints
//! `OK`: a green run that compared nothing, which is exactly the #572 failure
//! the whole program exists to eliminate. This program has already shipped and
//! caught one fail-open environment predicate (see `requirement_declared` in
//! `crates/rulesteward-selinux/tests/te_emit_checkmodule.rs`). Triplicating
//! that logic across three lanes is how such a bug recurs, so it is written
//! once, here, and covered by the table tests below.
//!
//! # Fail-closed rules
//!
//! - Variable UNSET -> use the committed corpus, mode [`CorpusMode::Committed`].
//! - Variable set to a blank value (empty, or whitespace only) -> ERROR. Never
//!   fall back to the committed corpus. `VAR="$WORK/corpus"` under an unset
//!   `WORK` produces exactly this, and a silent fallback would make the drift
//!   check compare the committed corpus with itself.
//! - Variable set to a non-blank value -> use it, mode [`CorpusMode::Fresh`].
//! - Either way, the resolved root must be an existing directory, or ERROR
//!   naming the absolute path. A typo'd path is not a reason to compare nothing.
//!
//! Note the value is handled as an [`OsStr`], not a `String`: a filesystem path
//! need not be valid UTF-8, and treating a non-UTF-8 override as "unset" would
//! be fail-open by another route.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

/// Which corpus a replay test is reading.
///
/// Carried into the test's sentinel banner so the `just diff-<lane>` recipe can
/// confirm the fresh capture was actually read before it classifies any exit
/// code. That grep is the only guard that catches a variable-name typo between
/// the recipe and the test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CorpusMode {
    /// The corpus committed to the repository (the default, used by `just test`).
    Committed,
    /// A freshly captured corpus supplied via the override variable.
    Fresh,
}

impl CorpusMode {
    /// The lowercase word used in the sentinel banner (`mode=committed`).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::Fresh => "fresh",
        }
    }
}

impl std::fmt::Display for CorpusMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why a corpus root could not be resolved.
///
/// Every variant is a hard failure. There is deliberately no "fall back to the
/// committed corpus" recovery: that recovery IS the bug this module prevents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CorpusRootError {
    /// The override variable was set to an empty or whitespace-only value.
    OverrideBlank {
        /// The variable that was set blank.
        env_var: String,
    },
    /// The resolved root is not an existing directory.
    MissingDirectory {
        /// `Some` when the path came from the override, `None` for the committed default.
        env_var: Option<String>,
        /// The path that was checked.
        path: PathBuf,
    },
}

impl std::fmt::Display for CorpusRootError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OverrideBlank { env_var } => write!(
                f,
                "{env_var} is set but blank; refusing to fall back to the committed corpus \
                 (a blank override would silently re-verify the committed corpus against \
                 itself and report success having compared nothing)"
            ),
            Self::MissingDirectory {
                env_var: Some(env_var),
                path,
            } => write!(
                f,
                "{env_var} points at {}, which is not an existing directory",
                path.display()
            ),
            Self::MissingDirectory {
                env_var: None,
                path,
            } => write!(
                f,
                "the committed corpus directory {} does not exist",
                path.display()
            ),
        }
    }
}

impl std::error::Error for CorpusRootError {}

/// Decide which root to read and in which mode, without touching the filesystem.
///
/// Split out from [`checked_corpus_root`] so the blank/unset/set decision -- the
/// part with the fail-open risk -- is table-testable on its own.
///
/// # Errors
/// [`CorpusRootError::OverrideBlank`] when `raw` is `Some` but blank.
pub fn select_corpus_root(
    env_var: &str,
    raw: Option<&OsStr>,
    default_root: &Path,
) -> Result<(PathBuf, CorpusMode), CorpusRootError> {
    let Some(value) = raw else {
        return Ok((default_root.to_path_buf(), CorpusMode::Committed));
    };

    // Lossy is correct for the BLANK test specifically: a non-UTF-8 value maps to
    // replacement characters, which are not whitespace, so it stays non-blank and
    // is honoured as a real override below. Only the emptiness question is asked
    // of the lossy form; the PATH is built from the original bytes.
    if value.to_string_lossy().trim().is_empty() {
        return Err(CorpusRootError::OverrideBlank {
            env_var: env_var.to_string(),
        });
    }

    Ok((PathBuf::from(value), CorpusMode::Fresh))
}

/// Resolve a corpus root and confirm it is an existing directory.
///
/// Takes the raw environment value as an argument rather than reading the
/// process environment, so tests can cover every case without mutating global
/// state (which would race other tests in the same binary).
///
/// # Errors
/// [`CorpusRootError::OverrideBlank`] for a blank override;
/// [`CorpusRootError::MissingDirectory`] when the resolved root is not a directory.
pub fn checked_corpus_root(
    env_var: &str,
    raw: Option<&OsStr>,
    default_root: &Path,
) -> Result<(PathBuf, CorpusMode), CorpusRootError> {
    let (root, mode) = select_corpus_root(env_var, raw, default_root)?;

    // `is_dir`, not `exists`: a root pointed at a stray regular file would
    // otherwise pass here and then enumerate zero scenarios downstream, which is
    // the vacuous-success shape this module exists to prevent.
    if !root.is_dir() {
        return Err(CorpusRootError::MissingDirectory {
            env_var: match mode {
                CorpusMode::Fresh => Some(env_var.to_string()),
                CorpusMode::Committed => None,
            },
            path: root,
        });
    }

    Ok((root, mode))
}

/// Read `env_var` from the process environment, resolve the corpus root, and
/// ANNOUNCE it on stderr.
///
/// The announcement lives here rather than at each call site, and that placement
/// is load-bearing. `just diff-<lane>-branch` proves a run read the corpus it was
/// handed by grepping for this banner, but that grep is EXISTENTIAL: it shows
/// that something read the right tree, never that nothing read a different one. A
/// binary resolving the corpus correctly in one place and from a compiled-in
/// `CARGO_MANIFEST_DIR` in another satisfies it completely.
///
/// That is not hypothetical. `rulesteward-selinux`'s `policy_corpus::archive_path`
/// was exactly that shape: it read `_policies/policies.tar.zst` from the manifest
/// dir while `scenarios()` honoured the override, so a branch differential would
/// have replayed one tree's scenarios against another tree's policy fixtures and
/// reported nothing. It was found by reading the code, not by the instrument.
///
/// Announcing from the single resolver is what makes a MISDIRECTED resolution
/// visible: a call that reaches this function with a variable the driver did not
/// set announces `mode=committed`, and the driver refuses the run.
///
/// It does NOT close the bypass class, and an earlier version of this comment
/// claimed it did. A corpus read that never calls this function announces nothing
/// at all, matches neither half of the driver's guard, and passes. That is
/// precisely the shape of the `archive_path` bug described above. Nothing
/// mechanically forces a read through here, so a new corpus read has to be routed
/// through it by hand.
///
/// Emitting from a library is a deliberate exception to the usual rule. This
/// module exists only to serve replay-test harnesses, whose stderr IS the
/// instrument's input.
///
/// # Panics
/// On any [`CorpusRootError`]. A replay test has no exit-code vocabulary of its
/// own (a failed assertion is just 101), so panicking with the full message is
/// how the reason reaches the recipe's log.
#[must_use]
pub fn resolve_corpus_root(
    sentinel: &str,
    env_var: &str,
    default_root: &Path,
) -> (PathBuf, CorpusMode) {
    // `var_os`, not `var`: `var` returns Err for a non-UTF-8 value, and
    // `.ok()`-ing that away would silently turn a real override into "unset",
    // which is the fail-open behaviour this module rejects.
    let raw = std::env::var_os(env_var);
    let (root, mode) = match checked_corpus_root(env_var, raw.as_deref(), default_root) {
        Ok(resolved) => resolved,
        Err(e) => panic!("{e}"),
    };
    // Before the caller can touch the filesystem, so an unreadable corpus root
    // still leaves a banner naming the path that could not be read. The only
    // fallible step ahead of it is this function's own resolution, which panics
    // with the reason rather than failing silently.
    eprintln!("{}", sentinel_banner(sentinel, mode, &root));
    (root, mode)
}

/// Render the banner a replay test MUST print before it asserts anything.
///
/// `just diff-<lane>` refuses to classify the fresh run's exit code until it has
/// grepped for this line with `mode=fresh`. That grep is the only thing standing
/// between the harness and its worst silent failure: if the recipe and the test
/// disagree about the override variable's NAME, the "fresh" run reads the
/// committed corpus, agrees with itself, and exits 0. No count floor, no positive
/// control and no exit code can see that.
///
/// `mode` precedes `corpus` deliberately, so the recipe's guard is a single
/// fixed-string match on a prefix (`"<SENTINEL>: mode=fresh corpus="`) and stays
/// correct for a corpus path containing spaces.
#[must_use]
pub fn sentinel_banner(sentinel: &str, mode: CorpusMode, root: &Path) -> String {
    format!("{sentinel}: mode={mode} corpus={}", root.display())
}

/// Render the scenario-count line a replay test MUST print alongside the banner.
///
/// CONTRIBUTING's rc-0 rule is that a success line carries a non-zero count; the
/// recipe reads this line to satisfy it. The test still asserts its own floor
/// independently -- this line is what lets the RECIPE refuse to report success
/// for a run that compared nothing, without re-deriving the count itself.
#[must_use]
pub fn sentinel_count(sentinel: &str, scenarios: usize) -> String {
    format!("{sentinel}: scenarios={scenarios}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A directory that certainly exists: this crate's own manifest directory.
    fn real_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    }

    /// A path under a real directory that certainly does not exist.
    fn missing_dir() -> PathBuf {
        real_dir().join("this-directory-does-not-exist-9k1")
    }

    const VAR: &str = "RS_ORACLE_CORPUS_TESTLANE";

    #[test]
    fn unset_selects_the_committed_corpus() {
        let default = real_dir();
        let (root, mode) = select_corpus_root(VAR, None, &default).expect("unset is not an error");
        assert_eq!(root, default);
        assert_eq!(mode, CorpusMode::Committed);
    }

    #[test]
    fn a_set_value_selects_the_fresh_corpus() {
        let default = real_dir();
        let override_path = missing_dir();
        let (root, mode) = select_corpus_root(VAR, Some(override_path.as_os_str()), &default)
            .expect("a non-blank override is not a selection error");
        assert_eq!(root, override_path);
        assert_eq!(mode, CorpusMode::Fresh);
    }

    /// The single most important case in this file. `VAR="$WORK/corpus"` under an
    /// unset `WORK` yields an empty string; falling back to the committed corpus
    /// there would make `just diff-<lane>` compare the committed corpus with
    /// itself and print OK.
    #[test]
    fn a_blank_override_is_an_error_and_never_falls_back() {
        let default = real_dir();
        for blank in ["", " ", "   ", "\t", "\n", " \t\n "] {
            let err = select_corpus_root(VAR, Some(OsStr::new(blank)), &default)
                .expect_err("a blank override must be an error");
            assert_eq!(
                err,
                CorpusRootError::OverrideBlank {
                    env_var: VAR.to_string()
                },
                "blank value {blank:?} must be rejected, not treated as unset"
            );
        }
    }

    #[test]
    fn the_blank_error_message_names_the_variable() {
        let default = real_dir();
        let err =
            select_corpus_root(VAR, Some(OsStr::new("")), &default).expect_err("blank is an error");
        let msg = err.to_string();
        assert!(msg.contains(VAR), "message must name the variable: {msg}");
    }

    /// A path is not required to be valid UTF-8. Treating a non-UTF-8 override as
    /// "unset" would be fail-open, so it must resolve as a normal Fresh override.
    #[test]
    fn a_non_utf8_override_is_honoured_not_ignored() {
        use std::os::unix::ffi::OsStrExt as _;
        let default = real_dir();
        let raw = OsStr::from_bytes(b"/tmp/rs-\xff-corpus");
        let (root, mode) = select_corpus_root(VAR, Some(raw), &default)
            .expect("a non-UTF-8 override is a real override");
        assert_eq!(root, PathBuf::from(raw));
        assert_eq!(mode, CorpusMode::Fresh);
    }

    #[test]
    fn checked_accepts_an_existing_committed_root() {
        let default = real_dir();
        let (root, mode) =
            checked_corpus_root(VAR, None, &default).expect("the manifest dir exists");
        assert_eq!(root, default);
        assert_eq!(mode, CorpusMode::Committed);
    }

    #[test]
    fn checked_rejects_a_missing_override_directory() {
        let default = real_dir();
        let missing = missing_dir();
        let err = checked_corpus_root(VAR, Some(missing.as_os_str()), &default)
            .expect_err("a missing override directory must be an error");
        assert_eq!(
            err,
            CorpusRootError::MissingDirectory {
                env_var: Some(VAR.to_string()),
                path: missing.clone(),
            }
        );
        let msg = err.to_string();
        assert!(msg.contains(VAR), "message must name the variable: {msg}");
        assert!(
            msg.contains(&missing.display().to_string()),
            "message must name the path: {msg}"
        );
    }

    #[test]
    fn checked_rejects_a_missing_committed_directory() {
        let missing = missing_dir();
        let err = checked_corpus_root(VAR, None, &missing)
            .expect_err("a missing committed corpus must be an error");
        assert_eq!(
            err,
            CorpusRootError::MissingDirectory {
                env_var: None,
                path: missing.clone(),
            }
        );
    }

    /// A regular FILE is not a directory. `is_dir` rather than `exists` is what
    /// makes a corpus root pointed at a stray file fail rather than enumerate zero
    /// scenarios.
    #[test]
    fn checked_rejects_a_file_masquerading_as_a_corpus_root() {
        let default = real_dir();
        let a_file = real_dir().join("Cargo.toml");
        assert!(a_file.is_file(), "fixture precondition: Cargo.toml exists");
        let err = checked_corpus_root(VAR, Some(a_file.as_os_str()), &default)
            .expect_err("a file is not a corpus directory");
        assert_eq!(
            err,
            CorpusRootError::MissingDirectory {
                env_var: Some(VAR.to_string()),
                path: a_file,
            }
        );
    }

    #[test]
    fn checked_propagates_the_blank_override_error() {
        let default = real_dir();
        let err = checked_corpus_root(VAR, Some(OsStr::new("  ")), &default)
            .expect_err("blank must still be an error after the directory check is added");
        assert_eq!(
            err,
            CorpusRootError::OverrideBlank {
                env_var: VAR.to_string()
            }
        );
    }

    /// Pins the exact byte shape the `just diff-<lane>` recipes match with
    /// `grep -qF`. If this rendering changes without the recipe changing, the
    /// guard silently stops guarding, so the literal is asserted here rather
    /// than merely described.
    #[test]
    fn the_sentinel_banner_renders_the_shape_the_recipes_grep_for() {
        let root = PathBuf::from("/tmp/fresh");
        assert_eq!(
            sentinel_banner("RS-DIFF-AUDITD", CorpusMode::Fresh, &root),
            "RS-DIFF-AUDITD: mode=fresh corpus=/tmp/fresh"
        );
        assert_eq!(
            sentinel_banner("RS-DIFF-AUDITD", CorpusMode::Committed, &root),
            "RS-DIFF-AUDITD: mode=committed corpus=/tmp/fresh"
        );
    }

    /// `mode` precedes `corpus` so the recipe's fixed-string guard is a prefix
    /// match that survives a corpus path containing spaces. A committed run must
    /// NOT match the fresh guard.
    #[test]
    fn the_fresh_guard_prefix_matches_only_a_fresh_run() {
        let spaced = PathBuf::from("/tmp/a dir/fresh");
        let guard = "RS-DIFF-SUDOERS: mode=fresh corpus=";

        let fresh = sentinel_banner("RS-DIFF-SUDOERS", CorpusMode::Fresh, &spaced);
        assert!(fresh.starts_with(guard), "fresh run must match: {fresh}");
        assert!(
            fresh.ends_with("/tmp/a dir/fresh"),
            "the path must survive verbatim: {fresh}"
        );

        let committed = sentinel_banner("RS-DIFF-SUDOERS", CorpusMode::Committed, &spaced);
        assert!(
            !committed.contains(guard),
            "a committed run must not satisfy the fresh guard: {committed}"
        );
    }

    #[test]
    fn the_count_line_carries_the_number_the_recipe_reads() {
        assert_eq!(
            sentinel_count("RS-DIFF-SYSCTLD", 22),
            "RS-DIFF-SYSCTLD: scenarios=22"
        );
        // Zero must still RENDER; refusing it is the recipe's job, and a panic
        // here would hide the vacuous run behind a different failure.
        assert_eq!(
            sentinel_count("RS-DIFF-SYSCTLD", 0),
            "RS-DIFF-SYSCTLD: scenarios=0"
        );
    }

    #[test]
    fn mode_words_are_stable_for_the_sentinel_banner() {
        // The `just diff-<lane>` recipes grep for `mode=fresh` literally. Changing
        // these strings silently breaks that guard, so they are pinned here.
        assert_eq!(CorpusMode::Committed.as_str(), "committed");
        assert_eq!(CorpusMode::Fresh.as_str(), "fresh");
        assert_eq!(CorpusMode::Fresh.to_string(), "fresh");
    }
}
