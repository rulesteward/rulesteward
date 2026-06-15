//! Trap-corpus driver: every `*.conf` fixture under `tests/corpus/traps/<code>/`
//! must fire `<code>` when run through the full lint dispatcher. Mirrors the
//! fapolicyd trap-corpus pattern (`tests/corpus/traps/<code>/`).
//!
//! The fixtures are the human-readable, version-controlled record of what each
//! structural lint catches; this driver keeps them honest. E03 fixtures use an
//! absolute, guaranteed-absent path so the filesystem check is host-independent
//! (the richer E03 filesystem cases live in `test_lints_e03_include.rs`).

use std::fs;
use std::path::{Path, PathBuf};

use rulesteward_sshd::SshdLintContext;
use rulesteward_sshd::lints;
use rulesteward_sshd::parser::parse_config_str_located;

fn traps_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus/traps")
}

#[test]
fn every_trap_fixture_fires_its_code() {
    let root = traps_root();
    let mut checked = 0;

    let mut code_dirs: Vec<PathBuf> = fs::read_dir(&root)
        .expect("traps corpus directory exists")
        .map(|e| e.expect("readable entry").path())
        .filter(|p| p.is_dir())
        .collect();
    code_dirs.sort();

    for code_dir in code_dirs {
        let code = code_dir
            .file_name()
            .expect("code directory name")
            .to_string_lossy()
            .to_string();

        let mut fixtures: Vec<PathBuf> = fs::read_dir(&code_dir)
            .expect("readable code directory")
            .map(|e| e.expect("readable entry").path())
            .filter(|p| p.extension().and_then(|x| x.to_str()) == Some("conf"))
            .collect();
        fixtures.sort();

        for fixture in fixtures {
            let source = fs::read_to_string(&fixture).expect("read fixture");
            let blocks = parse_config_str_located(&source, &fixture)
                .unwrap_or_else(|e| panic!("trap {} must parse: {e:?}", fixture.display()));
            let diags = lints::lint(&blocks, &fixture, &SshdLintContext::default());
            let codes: Vec<&str> = diags.iter().map(|d| d.code.as_ref()).collect();
            assert!(
                codes.contains(&code.as_str()),
                "trap {} must fire {code}, got {codes:?}",
                fixture.display()
            );
            checked += 1;
        }
    }

    assert!(
        checked >= 6,
        "expected at least 6 trap fixtures across E02/E03/E04, ran {checked}"
    );
}
