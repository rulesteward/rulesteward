//! fapd-F02 - file-layout coexistence. fapolicyd refuses to start when both
//! the deprecated `fapolicyd.rules` file AND any `rules.d/*.rules` exist.

use std::path::Path;

use rulesteward_core::{Diagnostic, Severity};

/// Return an fapd-F02 diagnostic if `rules_root` contains BOTH `fapolicyd.rules`
/// AND a `rules.d/` directory with at least one top-level `.rules` file.
#[must_use]
pub fn check_layout(rules_root: &Path) -> Option<Diagnostic> {
    let legacy = rules_root.join("fapolicyd.rules");
    let rulesd = rules_root.join("rules.d");

    if !legacy.is_file() {
        return None;
    }
    if !rulesd.is_dir() {
        return None;
    }
    if !directory_has_rules_files(&rulesd) {
        return None;
    }

    Some(super::file_level(
        Severity::Fatal,
        "fapd-F02",
        "fapolicyd refuses to start when both `fapolicyd.rules` and `rules.d/` contain rules - remove one",
        legacy,
    ))
}

/// True when `dir` (a `rules.d/`) contains at least one non-dotfile entry
/// (regular file OR subdirectory, any extension).
///
/// Models the fagenrules daemon-level coexistence guard:
///
/// ```text
/// if [ -e ${OldDestinationFile} ]; then
///   if [ $(ls ${SourceRulesDir} | wc -w) -gt 0 ]; then
///     ... "Error - both old and new rules exist" exit 1 ...
///   fi
/// fi
/// ```
///
/// `ls` without `-a` omits entries whose name starts with `.`, so dotfiles
/// never appear in the word count and never trigger the abort.  Every other
/// entry -- files of any extension, subdirectories, symlinks -- is counted
/// by `wc -w` and causes the daemon to refuse startup.
///
/// Shared by the fapd-F02 layout lint and `fapolicyd migrate` so both agree
/// on what "rules.d/ has content" means (the coexistence trigger), not just
/// what fapolicyd would load as rules.
#[must_use]
pub fn directory_has_rules_files(dir: &Path) -> bool {
    let Ok(read) = std::fs::read_dir(dir) else {
        return false;
    };
    read.filter_map(Result::ok).any(|e| {
        let name = e.file_name();
        // OsStr's encoding is ASCII-transparent: a leading 0x2E byte always
        // means `.` (no multi-byte char starts with an ASCII byte), so this
        // equals the lossy-string check without the per-entry allocation.
        // `ls` without `-a` omits dotfiles; `wc -w` counts everything else.
        name.as_encoded_bytes().first() != Some(&b'.')
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn tempdir() -> tempfile::TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    // --- baseline silent cases ---

    #[test]
    fn check_layout_silent_when_neither_present() {
        let dir = tempdir();
        assert!(check_layout(dir.path()).is_none());
    }

    #[test]
    fn check_layout_silent_when_only_legacy_file() {
        let dir = tempdir();
        fs::write(dir.path().join("fapolicyd.rules"), b"").unwrap();
        assert!(check_layout(dir.path()).is_none());
    }

    #[test]
    fn check_layout_silent_when_only_rules_d() {
        // No legacy file means no conflict -- the daemon's legacy-gated `elif`
        // never runs, so fapd-F02 must not fire.
        let dir = tempdir();
        fs::create_dir(dir.path().join("rules.d")).unwrap();
        fs::write(dir.path().join("rules.d/40-x.rules"), b"").unwrap();
        assert!(check_layout(dir.path()).is_none());
    }

    #[test]
    fn check_layout_silent_when_rules_d_empty() {
        let dir = tempdir();
        fs::write(dir.path().join("fapolicyd.rules"), b"").unwrap();
        fs::create_dir(dir.path().join("rules.d")).unwrap();
        assert!(check_layout(dir.path()).is_none());
    }

    #[test]
    fn check_layout_silent_when_bak_file_only() {
        let dir = tempdir();
        fs::write(dir.path().join("fapolicyd.rules.bak"), b"").unwrap();
        assert!(check_layout(dir.path()).is_none());
    }

    // --- regression: existing fire/silent behavior preserved after the widen ---

    /// legacy + rules.d/40-x.rules must still fire fapd-F02 (a `.rules` file
    /// is counted by `ls | wc -w` and was already counted by the old gate).
    #[test]
    fn check_layout_fires_when_both_present_with_rules_file() {
        let dir = tempdir();
        fs::write(dir.path().join("fapolicyd.rules"), b"").unwrap();
        fs::create_dir(dir.path().join("rules.d")).unwrap();
        fs::write(dir.path().join("rules.d/40-x.rules"), b"").unwrap();
        let d = check_layout(dir.path()).expect("fapd-F02 fires");
        assert_eq!(d.code.as_ref(), "fapd-F02");
    }

    /// legacy + rules.d/ with ONLY a dotfile (`.40-x.rules`) must NOT fire.
    /// fagenrules's `ls | wc -w` uses bare `ls` which omits dotfiles, so
    /// fapolicyd's own daemon-level guard never triggers for a dotfiles-only dir.
    #[test]
    fn check_layout_silent_when_rules_d_only_has_dotfile_rules() {
        // `check_layout` must return None (no fapd-F02) when `fapolicyd.rules`
        // exists alongside a `rules.d/` whose sole `.rules` entry is a dotfile.
        // fagenrules enumerates rules via:
        //   for rules in $(/bin/ls -1v ${SourceRulesDir} | grep "\.rules$")
        // `ls` without `-a` omits leading-dot filenames, so the dotfile
        // `.40-x.rules` never reaches fapolicyd. From fapolicyd's perspective
        // `rules.d/` is empty, meaning there is no real conflict with the
        // legacy `fapolicyd.rules` file and fapd-F02 must NOT fire.
        let dir = tempdir();
        fs::write(
            dir.path().join("fapolicyd.rules"),
            b"allow perm=open all : all",
        )
        .unwrap();
        let rulesd = dir.path().join("rules.d");
        fs::create_dir(&rulesd).unwrap();
        fs::write(rulesd.join(".40-x.rules"), b"deny perm=execute all : all").unwrap();
        assert!(
            check_layout(dir.path()).is_none(),
            "check_layout must not fire fapd-F02 when rules.d/ contains \
             only dotfile .rules entries; fagenrules uses `ls` without `-a` \
             so dotfiles are never seen and there is no effective conflict"
        );
    }

    /// No legacy file + rules.d/ containing only a README -> silent.
    /// The daemon's legacy-gated `elif` never runs without `fapolicyd.rules`.
    #[test]
    fn check_layout_silent_when_no_legacy_and_rules_d_has_readme() {
        let dir = tempdir();
        fs::create_dir(dir.path().join("rules.d")).unwrap();
        fs::write(dir.path().join("rules.d/README"), b"documentation").unwrap();
        assert!(
            check_layout(dir.path()).is_none(),
            "fapd-F02 is legacy-gated; without fapolicyd.rules it must never fire"
        );
    }

    // --- dotfile guard tests ---

    #[test]
    fn directory_has_rules_files_ignores_dotfile_rules() {
        // A dotfile like `.40-x.rules` must NOT count as a rules file because
        // fagenrules enumerates rules via:
        //   for rules in $(/bin/ls -1v ${SourceRulesDir} | grep "\.rules$")
        // `ls` without `-a` does not list entries whose names start with `.`,
        // so `.40-x.rules` is never passed to `grep` and never reaches
        // fapolicyd. A directory whose only `.rules`-extension entry is a
        // dotfile therefore has zero effective rules from fapolicyd's view.
        let dir = tempdir();
        let rulesd = dir.path().join("rules.d");
        fs::create_dir(&rulesd).unwrap();
        // create dotfile only - `ls` without -a omits it, so fagenrules never sees it
        fs::write(rulesd.join(".40-x.rules"), b"deny perm=execute all : all").unwrap();
        assert!(
            !directory_has_rules_files(&rulesd),
            "directory_has_rules_files must return false when the only \
             .rules entry is a dotfile (.40-x.rules); fagenrules enumerates \
             via `/bin/ls -1v | grep '\\.rules$'` and `ls` without `-a` \
             omits leading-dot filenames"
        );
    }

    #[test]
    fn directory_has_rules_files_ignores_hidden_dotfile_rules() {
        // Same invariant as above but with a different dotfile name to ensure
        // the check covers the general leading-dot case, not just `.40-x.rules`.
        // fagenrules uses `/bin/ls -1v <dir> | grep '\.rules$'`; `ls` without
        // `-a` silently omits any filename that starts with `.`, so dotfiles
        // never reach fapolicyd regardless of their suffix.
        let dir = tempdir();
        let rulesd = dir.path().join("rules.d");
        fs::create_dir(&rulesd).unwrap();
        fs::write(rulesd.join(".hidden.rules"), b"allow perm=open all : all").unwrap();
        assert!(
            !directory_has_rules_files(&rulesd),
            "directory_has_rules_files must return false when the only \
             .rules entry is a dotfile (.hidden.rules); `ls` without `-a` \
             omits leading-dot filenames so fagenrules never sees it"
        );
    }

    // --- widen: fagenrules `ls | wc -w` parity (RED until implementation lands) ---
    //
    // fagenrules's daemon-level conflict gate in fagenrules is:
    //   if [ -e ${OldDestinationFile} ]; then
    //     if [ $(ls ${SourceRulesDir} | wc -w) -gt 0 ]; then
    //       ... "Error - both old and new rules exist" exit 1 ...
    //     fi
    //   fi
    // `ls` without `-a` counts every non-dotfile entry regardless of extension
    // or whether it is a file or a subdirectory.  The current implementation
    // gates on `*.rules` files only; these tests assert the widened behavior.

    /// legacy + rules.d/ containing only a `README` file (no `.rules` extension)
    /// must fire fapd-F02.  `ls | wc -w` counts `README`; the daemon aborts.
    #[test]
    fn check_layout_fires_when_rules_d_has_only_readme() {
        let dir = tempdir();
        fs::write(dir.path().join("fapolicyd.rules"), b"").unwrap();
        fs::create_dir(dir.path().join("rules.d")).unwrap();
        fs::write(dir.path().join("rules.d/README"), b"documentation").unwrap();
        let d = check_layout(dir.path()).expect(
            "fapd-F02 must fire: fagenrules `ls | wc -w` counts README as a non-dotfile entry",
        );
        assert_eq!(d.code.as_ref(), "fapd-F02");
    }

    /// legacy + rules.d/ containing only a `notes.txt` file must fire fapd-F02.
    /// Any non-dotfile entry -- any extension -- is counted by `ls | wc -w`.
    #[test]
    fn check_layout_fires_when_rules_d_has_only_txt_file() {
        let dir = tempdir();
        fs::write(dir.path().join("fapolicyd.rules"), b"").unwrap();
        fs::create_dir(dir.path().join("rules.d")).unwrap();
        fs::write(dir.path().join("rules.d/notes.txt"), b"notes").unwrap();
        let d = check_layout(dir.path()).expect(
            "fapd-F02 must fire: fagenrules `ls | wc -w` counts notes.txt as a non-dotfile entry",
        );
        assert_eq!(d.code.as_ref(), "fapd-F02");
    }

    /// legacy + rules.d/ containing only a plain subdirectory (`sub/`) must fire
    /// fapd-F02.  `ls` lists subdirectory names; `wc -w` counts them.
    #[test]
    fn check_layout_fires_when_rules_d_has_only_plain_subdir() {
        let dir = tempdir();
        fs::write(dir.path().join("fapolicyd.rules"), b"").unwrap();
        fs::create_dir_all(dir.path().join("rules.d/sub")).unwrap();
        let d = check_layout(dir.path())
            .expect("fapd-F02 must fire: fagenrules `ls | wc -w` counts subdirectory `sub/`");
        assert_eq!(d.code.as_ref(), "fapd-F02");
    }

    /// legacy + rules.d/ containing only a subdirectory named `nested.rules/`
    /// must fire fapd-F02.  A directory with a `.rules` suffix is still a
    /// non-dotfile entry counted by `ls | wc -w`; the daemon does not
    /// distinguish files from directories in this check.
    ///
    /// (Inverts the pre-widen `check_layout_silent_when_rules_d_only_holds_subdirectory`
    /// expectation -- updated here as the test-author because the implementer must
    /// never silently edit a frozen test.)
    #[test]
    fn check_layout_fires_when_rules_d_has_only_subdir_named_dot_rules() {
        let dir = tempdir();
        fs::write(dir.path().join("fapolicyd.rules"), b"").unwrap();
        fs::create_dir_all(dir.path().join("rules.d/nested.rules")).unwrap();
        let d = check_layout(dir.path()).expect(
            "fapd-F02 must fire: `nested.rules/` is a non-dotfile entry; \
             fagenrules `ls | wc -w` counts it regardless of type",
        );
        assert_eq!(d.code.as_ref(), "fapd-F02");
    }
}
