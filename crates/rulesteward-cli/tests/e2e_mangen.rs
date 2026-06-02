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
