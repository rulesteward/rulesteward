//! Include / directory resolution seam (#334).
//!
//! Freezes the entrypoint the CLI calls so the #334 pipeline fills the body
//! without touching the CLI. [`resolve_target`] turns a path into the list of
//! [`SudoersFile`]s to lint:
//! * a single FILE -> one parsed file,
//! * a DIRECTORY -> each eligible drop-in, parsed, in sorted lexical order.
//!
//! # Phase-0 scope vs #334
//! Phase 0 implements ONLY the directory-enumeration rule from `sudoers(5)`:
//! `@includedir` reads each file in the directory, SKIPPING names that end in `~`
//! or CONTAIN a `.`, in sorted lexical order. It does NOT follow `@include` /
//! `@includedir` DIRECTIVES found inside a file, does NOT do nested / relative
//! resolution, and does NOT apply last-match ordering across files - those are
//! #334's job (marked with a `// #334:` extension-point comment below). This
//! minimal body is real, testable logic; #334 extends it.

use std::io;
use std::path::Path;

use crate::ast::SudoersFile;
use crate::parser::parse;

/// Resolve a lint target path into the [`SudoersFile`]s to lint.
///
/// A FILE is read and parsed into one [`SudoersFile`]. A DIRECTORY is enumerated:
/// each entry whose name is `sudoers.d`-eligible (does not end in `~`, does not
/// contain a `.`) is read and parsed, in sorted lexical order.
///
/// # Errors
/// Returns the underlying [`io::Error`] if the path cannot be read (an unreadable
/// file, or a directory that cannot be enumerated). An individual unreadable
/// drop-in inside a directory is skipped (best-effort), not a hard error - the
/// rest of the directory still lints.
pub fn resolve_target(path: &Path) -> io::Result<Vec<SudoersFile>> {
    if path.is_dir() {
        return resolve_dir(path);
    }
    // A single file (or a path that is not a directory): read + parse it. A read
    // error (missing / unreadable) propagates so the CLI can map it to a tool
    // failure.
    let source = std::fs::read_to_string(path)?;
    Ok(vec![parse(&source, path)])
}

/// Enumerate a `sudoers.d`-style directory: parse each eligible drop-in in sorted
/// lexical order.
fn resolve_dir(dir: &Path) -> io::Result<Vec<SudoersFile>> {
    let mut names: Vec<std::path::PathBuf> = std::fs::read_dir(dir)?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.is_file() && is_eligible_dropin(p))
        .collect();
    // sudoers(5): files are parsed in sorted lexical order.
    names.sort();

    let mut files = Vec::with_capacity(names.len());
    for path in names {
        // A drop-in we cannot read (non-UTF8, permission) is skipped best-effort;
        // the rest of the directory still lints. (A hard error is reserved for a
        // directory that cannot be enumerated at all, handled by `read_dir?`.)
        if let Ok(source) = std::fs::read_to_string(&path) {
            files.push(parse(&source, &path));
        }
    }
    // #334: directive-following of @include / @includedir found INSIDE these
    // parsed files, nested / relative path resolution, and last-match ordering
    // across the merged file set are NOT done here - they extend this seam.
    Ok(files)
}

/// Whether a directory entry's file name is an eligible `sudoers.d` drop-in.
///
/// `sudoers(5)` (`@includedir`): skip names that END IN `~` (editor backups) or
/// CONTAIN a `.` (e.g. RPM `.rpmsave` / `.rpmnew` / dotted package names). A name
/// that is not valid UTF-8 is treated as ineligible (conservative).
fn is_eligible_dropin(path: &Path) -> bool {
    match path.file_name().and_then(|n| n.to_str()) {
        Some(name) => !name.ends_with('~') && !name.contains('.'),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::{is_eligible_dropin, resolve_target};
    use std::path::Path;

    #[test]
    fn single_file_resolves_to_one_parsed_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let f = dir.path().join("sudoers");
        std::fs::write(&f, "root ALL=(ALL) ALL\n").expect("write");
        let files = resolve_target(&f).expect("resolve a file");
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].path, f);
        assert!(matches!(
            files[0].lines[0].kind,
            crate::ast::LineKind::UserSpec(_)
        ));
    }

    #[test]
    fn missing_file_is_an_io_error() {
        let err = resolve_target(Path::new("/nonexistent/329/sudoers"));
        assert!(err.is_err(), "a missing file propagates the io::Error");
    }

    #[test]
    fn directory_parses_eligible_dropins_in_sorted_order() {
        let dir = tempfile::tempdir().expect("tempdir");
        // Eligible drop-ins (no `.`, no trailing `~`), written out of order.
        std::fs::write(dir.path().join("20-bob"), "bob ALL=(ALL) ALL\n").expect("w");
        std::fs::write(dir.path().join("10-alice"), "alice ALL=(ALL) ALL\n").expect("w");
        // Ineligible: a `.`-containing name (RPM leftover) and a `~` backup.
        std::fs::write(dir.path().join("10-alice.rpmsave"), "garbage\n").expect("w");
        std::fs::write(dir.path().join("30-carol~"), "garbage\n").expect("w");

        let files = resolve_target(dir.path()).expect("resolve a dir");
        // Only the two eligible files, in sorted order: 10-alice then 20-bob.
        assert_eq!(files.len(), 2, "ineligible names are skipped: {files:?}");
        assert!(files[0].path.ends_with("10-alice"));
        assert!(files[1].path.ends_with("20-bob"));
    }

    #[test]
    fn dropin_eligibility_skips_dot_and_tilde_names() {
        assert!(is_eligible_dropin(Path::new("/etc/sudoers.d/10-foo")));
        assert!(!is_eligible_dropin(Path::new(
            "/etc/sudoers.d/10-foo.rpmnew"
        )));
        assert!(!is_eligible_dropin(Path::new("/etc/sudoers.d/10-foo~")));
        assert!(!is_eligible_dropin(Path::new("/etc/sudoers.d/.hidden")));
    }

    #[test]
    fn empty_directory_resolves_to_no_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        let files = resolve_target(dir.path()).expect("resolve empty dir");
        assert!(files.is_empty());
    }
}
