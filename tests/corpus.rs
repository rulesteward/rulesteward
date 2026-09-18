//! The full-corpus sweep. Off by default.
//!
//! The 121-log corpus lives in the private rulesteward-research repo, reached here
//! through the gitignored `research` symlink, so public CI cannot run this and does
//! not try. Locally: `cargo test --features full-corpus`.
//!
//! This is a robustness sweep, not a correctness one — it has no expected output. It
//! asserts the two things that must hold for every capture on every release: the tool
//! never panics, and it never drops a denial record silently. Anything it cannot act
//! on has to say why, in the artifact it could not write.
#![cfg(feature = "full-corpus")]

mod common;

use std::path::PathBuf;

#[test]
fn every_capture_is_either_acted_on_or_explained() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("research/docs/fixtures/raw");
    if !dir.is_dir() {
        panic!("no {}; the research symlink is missing", dir.display());
    }

    let mut logs: Vec<PathBuf> = std::fs::read_dir(&dir)
        .expect("read corpus")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "log"))
        .collect();
    logs.sort();
    assert!(
        logs.len() > 100,
        "expected the full corpus, found {}",
        logs.len()
    );

    let mut failures = Vec::new();
    for log in &logs {
        let input = std::fs::read(log).expect("read log");
        // The `#` test has to match the tool's (analyze.rs step 1), leading whitespace
        // and all. The conf-validate captures annotate their only denial records as
        // indented `# record: ...` lines; those are comments, so producing nothing for
        // them is the correct answer and counting them here would call it a drop.
        let denials = input
            .split(|&b| b == b'\n')
            .filter(|l| !l.trim_ascii_start().starts_with(b"#"))
            .filter(|l| l.windows(8).any(|w| w == b"dec=deny"))
            .count();

        let name = log.file_name().unwrap().to_string_lossy();

        // Both actions: the sweep has to cover every line either artifact can write.
        for action in ["rules", "trust"] {
            let out = common::run(&["fapolicyd", action, "--no-conf"], &input);

            let Some(code) = out.status.code() else {
                failures.push(format!(
                    "{name} {action}: killed by a signal — panic or crash"
                ));
                continue;
            };
            if !(0..=2).contains(&code) {
                failures.push(format!(
                    "{name} {action}: exit {code} is outside §9's 0/1/2"
                ));
            }
            if denials > 0 && out.stdout.is_empty() {
                failures.push(format!(
                    "{name} {action}: {denials} denial records went in and nothing came out — \
                     a silent drop is the one outcome that is never acceptable"
                ));
            }
            // §9: one artifact per action, comments and result lines and nothing else.
            // Every non-comment line must be something a user can paste.
            let result = if action == "rules" {
                &b"allow "[..]
            } else {
                &b"fapolicyd-cli "[..]
            };
            for line in out.stdout.split(|&b| b == b'\n').filter(|l| !l.is_empty()) {
                if !line.starts_with(b"# ") && !line.starts_with(result) {
                    failures.push(format!(
                        "{name} {action}: stdout line belongs to neither the comments nor the \
                         artifact: {}",
                        String::from_utf8_lossy(line)
                    ));
                    break;
                }
            }
            if !out.stderr.is_empty() {
                failures.push(format!(
                    "{name} {action}: stderr carries errors only, and got: {}",
                    String::from_utf8_lossy(&out.stderr)
                ));
            }
        }
    }

    assert!(
        failures.is_empty(),
        "\n{} of {} logs failed:\n\n{}",
        failures.len(),
        logs.len(),
        failures.join("\n")
    );
}
