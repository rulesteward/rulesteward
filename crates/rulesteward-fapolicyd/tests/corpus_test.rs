//! Happy-path corpus driver.
//!
//! Walks every `*.rules` file under `tests/corpus/happy/` (copied from the
//! Session-1 chumsky spike) and asserts that `parse_rules_file` returns
//! `Ok(entries)` with a non-empty `Vec<Entry>` for each file.
//!
//! On failure, prints which file failed and every diagnostic that fired
//! before panicking — first-run debuggability is the whole point.
//!
//! NOTE (mutation-test resilience): we do not merely assert "Ok". We also
//! assert that the returned `Vec<Entry>` is non-empty AND that at least one
//! entry is an `Entry::Rule`. A mutant returning `Ok(vec![])` or
//! `Ok(vec![Entry::Blank { line: 1 }])` from `parse_rules_file` would
//! survive a bare `is_ok()` check but is killed by these structural asserts.

use std::path::PathBuf;

use rulesteward_fapolicyd::{Entry, parse_rules_file};

fn happy_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/corpus/happy")
}

/// Returns the list of (filename, body) tuples for every `*.rules` file in
/// the happy corpus, sorted by filename for deterministic test output.
fn load_happy_corpus() -> Vec<(String, String)> {
    let dir = happy_dir();
    let mut out: Vec<(String, String)> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read happy corpus dir {}: {e}", dir.display()))
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("rules") {
                return None;
            }
            let name = path.file_name()?.to_string_lossy().into_owned();
            let body = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("read happy corpus file {}: {e}", path.display()));
            Some((name, body))
        })
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

#[test]
fn parses_full_corpus() {
    let corpus = load_happy_corpus();

    // Sanity floor: at least the 11 files originally copied from the spike.
    // New happy-corpus files are welcome; deletions are the failure mode the
    // guard catches.
    assert!(
        corpus.len() >= 11,
        "expected ≥11 happy-corpus files under tests/corpus/happy/, found {} — \
         files were deleted without updating this assertion",
        corpus.len()
    );

    let mut any_failed = false;
    for (filename, body) in &corpus {
        match parse_rules_file(body) {
            Ok(entries) => {
                assert!(
                    !entries.is_empty(),
                    "{filename}: parse returned Ok but Vec<Entry> is empty — \
                     the parser likely silently dropped every line",
                );
                let content_count = entries
                    .iter()
                    .filter(|e| matches!(e, Entry::Rule(_) | Entry::SetDefinition { .. }))
                    .count();
                assert!(
                    content_count >= 1,
                    "{filename}: parse returned Ok with {} entries but ZERO are Rule or \
                     SetDefinition — the parser silently dropped every content line",
                    entries.len(),
                );
            }
            Err(diags) => {
                any_failed = true;
                eprintln!(
                    "--- {filename}: parse FAILED with {} diagnostic(s):",
                    diags.len()
                );
                for d in &diags {
                    eprintln!(
                        "    [{}] line {}:{} span {:?}  {}",
                        d.code, d.line, d.column, d.span, d.message,
                    );
                }
            }
        }
    }

    assert!(
        !any_failed,
        "one or more happy-corpus files failed to parse — see stderr above for per-file diagnostics",
    );
}
