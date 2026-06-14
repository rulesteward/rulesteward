//! Happy-corpus driver: every fixture in `tests/corpus/happy/` must parse
//! cleanly and yield at least one real directive. Mirrors the fapolicyd /
//! auditd happy-corpus drivers. A regression that breaks a real-world config
//! shape fails here even when the unit tests still pass.

use std::path::{Path, PathBuf};

use rulesteward_sshd::ast::Block;
use rulesteward_sshd::parser::parse_config_str_located;

fn happy_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/corpus/happy")
}

/// Load every `*.conf` fixture as `(filename, body)`, sorted for determinism.
fn load_happy_corpus() -> Vec<(String, String)> {
    let dir = happy_dir();
    let mut out = Vec::new();
    for entry in std::fs::read_dir(&dir).expect("corpus/happy dir must exist") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) == Some("conf") {
            let body = std::fs::read_to_string(&path).expect("read fixture");
            let name = path
                .file_name()
                .expect("file name")
                .to_string_lossy()
                .into_owned();
            out.push((name, body));
        }
    }
    out.sort();
    out
}

/// Total directive count across the global block and every Match body.
fn directive_count(blocks: &[Block]) -> usize {
    blocks
        .iter()
        .map(|b| match b {
            Block::Global(ds) => ds.len(),
            Block::Match(m) => m.body.len(),
        })
        .sum()
}

#[test]
fn every_happy_fixture_parses_cleanly() {
    let corpus = load_happy_corpus();
    assert!(
        corpus.len() >= 8,
        "expected at least 8 happy fixtures, found {}",
        corpus.len()
    );
    for (name, body) in &corpus {
        match parse_config_str_located(body, Path::new(name)) {
            Ok(blocks) => {
                assert!(
                    matches!(blocks.first(), Some(Block::Global(_))),
                    "{name}: blocks[0] must be the global block"
                );
                assert!(
                    directive_count(&blocks) >= 1,
                    "{name}: a happy fixture must contain at least one real directive"
                );
            }
            Err(errs) => panic!("{name} should parse cleanly but reported {errs:?}"),
        }
    }
}

#[test]
fn match_heavy_fixture_yields_multiple_match_blocks() {
    // Guards the corpus's coverage of Match scoping (not just a flat directive
    // list): the match-heavy fixture must produce several Match blocks.
    let body = std::fs::read_to_string(happy_dir().join("match-heavy.conf")).expect("fixture");
    let blocks = parse_config_str_located(&body, Path::new("match-heavy.conf")).expect("parses");
    let match_blocks = blocks
        .iter()
        .filter(|b| matches!(b, Block::Match(_)))
        .count();
    assert!(
        match_blocks >= 4,
        "match-heavy.conf should exercise >= 4 Match blocks, got {match_blocks}"
    );
}
