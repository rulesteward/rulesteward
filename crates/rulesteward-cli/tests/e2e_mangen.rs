//! End-to-end test for the hidden `rulesteward mangen <OUTDIR>` subcommand, which
//! the release workflow invokes to generate the packaged man page. RED before the
//! subcommand exists (clap rejects the unknown subcommand -> non-zero exit).

use assert_cmd::Command;

#[test]
fn mangen_writes_troff_manpage() {
    let dir = tempfile::tempdir().expect("tempdir");
    Command::cargo_bin("rulesteward")
        .expect("binary built")
        .arg("mangen")
        .arg(dir.path())
        .assert()
        .success();

    let page = dir.path().join("rulesteward.1");
    let body = std::fs::read_to_string(&page)
        .unwrap_or_else(|e| panic!("mangen must write {}: {e}", page.display()));
    assert!(!body.is_empty(), "man page must be non-empty");
    assert!(
        body.contains(".TH"),
        "man page must carry a .TH roff title header; got start: {:?}",
        body.chars().take(80).collect::<String>()
    );
    assert!(
        body.to_lowercase().contains("rulesteward"),
        "man page must name the tool"
    );
}

/// An `<OUTDIR>` whose PARENT is not writable makes `create_dir_all` fail:
/// exit `EXIT_TOOL_FAILURE` = 3. Relies on chmod 0555 reliably denying write
/// for the non-root user this suite runs as (both locally and in CI).
#[test]
fn mangen_outdir_parent_unwritable_exits_tool_failure() {
    use std::os::unix::fs::PermissionsExt as _;

    let parent = tempfile::tempdir().expect("tempdir");
    std::fs::set_permissions(parent.path(), std::fs::Permissions::from_mode(0o555))
        .expect("chmod 0555 (read+search, no write)");
    let outdir = parent.path().join("newsubdir");

    let assert = Command::cargo_bin("rulesteward")
        .expect("binary built")
        .arg("mangen")
        .arg(&outdir)
        .assert();

    // Restore write permission unconditionally so the tempdir's own Drop
    // cleanup can still remove it.
    let _ = std::fs::set_permissions(parent.path(), std::fs::Permissions::from_mode(0o755));

    assert
        .failure()
        .code(3)
        .stderr(predicates::str::contains("error: creating"));
}

/// An `<OUTDIR>` that already exists but is not writable makes the
/// `rulesteward.1` write fail - distinct from the parent-unwritable arm above
/// (`create_dir_all` on an already-existing directory is a no-op success).
#[test]
fn mangen_outdir_unwritable_exits_tool_failure() {
    use std::os::unix::fs::PermissionsExt as _;

    let outdir = tempfile::tempdir().expect("tempdir");
    std::fs::set_permissions(outdir.path(), std::fs::Permissions::from_mode(0o555))
        .expect("chmod 0555 (read+search, no write)");

    let assert = Command::cargo_bin("rulesteward")
        .expect("binary built")
        .arg("mangen")
        .arg(outdir.path())
        .assert();

    let _ = std::fs::set_permissions(outdir.path(), std::fs::Permissions::from_mode(0o755));

    assert
        .failure()
        .code(3)
        .stderr(predicates::str::contains("error: writing"));
}
