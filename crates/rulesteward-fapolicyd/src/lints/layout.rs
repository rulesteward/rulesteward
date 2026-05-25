//! F02 - file-layout coexistence. fapolicyd refuses to start when both the
//! deprecated `fapolicyd.rules` file AND any `rules.d/*.rules` exist.

use std::path::Path;

use rulesteward_core::{Diagnostic, Severity};

/// Return an F02 diagnostic if `rules_root` contains BOTH `fapolicyd.rules`
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

    Some(Diagnostic::new(
        Severity::Fatal,
        "F02",
        0..0,
        "fapolicyd refuses to start when both `fapolicyd.rules` and `rules.d/` contain rules - remove one",
        legacy,
        0,
        0,
    ))
}

fn directory_has_rules_files(dir: &Path) -> bool {
    let Ok(read) = std::fs::read_dir(dir) else {
        return false;
    };
    read.filter_map(Result::ok).any(|e| {
        let p = e.path();
        p.is_file() && p.extension().and_then(|s| s.to_str()) == Some("rules")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn tempdir() -> tempfile::TempDir {
        tempfile::tempdir().expect("tempdir")
    }

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
    fn check_layout_fires_when_both_present() {
        let dir = tempdir();
        fs::write(dir.path().join("fapolicyd.rules"), b"").unwrap();
        fs::create_dir(dir.path().join("rules.d")).unwrap();
        fs::write(dir.path().join("rules.d/40-x.rules"), b"").unwrap();
        let d = check_layout(dir.path()).expect("F02 fires");
        assert_eq!(d.code.as_ref(), "F02");
    }

    #[test]
    fn check_layout_silent_when_bak_file_only() {
        let dir = tempdir();
        fs::write(dir.path().join("fapolicyd.rules.bak"), b"").unwrap();
        assert!(check_layout(dir.path()).is_none());
    }

    #[test]
    fn check_layout_silent_when_rules_d_only_holds_subdirectory() {
        // A directory named `foo.rules/` inside `rules.d/` must NOT count
        // as a rules file. `directory_has_rules_files` filters on `is_file()`.
        let dir = tempdir();
        fs::write(dir.path().join("fapolicyd.rules"), b"").unwrap();
        fs::create_dir_all(dir.path().join("rules.d/nested.rules")).unwrap();
        assert!(
            check_layout(dir.path()).is_none(),
            "a subdirectory with a `.rules` name must not trip F02"
        );
    }
}
