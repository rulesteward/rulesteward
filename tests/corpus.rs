//! The full-corpus sweep. Off by default.
//!
//! The 121-log corpus lives in the private rulesteward-research repo, reached here
//! through the gitignored `research` symlink, so public CI cannot run this and does
//! not try. Locally: `cargo test --features full-corpus`.
//!
//! This is a robustness sweep, not a correctness one — it has no expected output. It
//! asserts the two things that must hold for every capture on every release: the tool
//! never panics, and it never drops a denial record silently. Anything it cannot act
//! on has to say why.
#![cfg(feature = "full-corpus")]

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

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
            .filter(|l| find(l, b"dec=deny").is_some())
            .count();

        let mut child = Command::new(env!("CARGO_BIN_EXE_rulesteward"))
            .args(["fapolicyd", "analyze", "--no-conf"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn");
        child
            .stdin
            .take()
            .unwrap()
            .write_all(&input)
            .expect("write");
        let out = child.wait_with_output().expect("wait");
        let name = log.file_name().unwrap().to_string_lossy();

        let Some(code) = out.status.code() else {
            failures.push(format!("{name}: killed by a signal — panic or crash"));
            continue;
        };
        if !(0..=2).contains(&code) {
            failures.push(format!("{name}: exit {code} is outside §9's 0/1/2"));
        }
        if denials > 0 && out.stdout.is_empty() && out.stderr.is_empty() {
            failures.push(format!(
                "{name}: {denials} denial records went in and nothing came out — \
                 a silent drop is the one outcome that is never acceptable"
            ));
        }
        // §9: stdout is bare lines. Every one must be something a user can paste.
        for line in out.stdout.split(|&b| b == b'\n').filter(|l| !l.is_empty()) {
            if !line.starts_with(b"fapolicyd-cli ") && !line.starts_with(b"allow ") {
                failures.push(format!(
                    "{name}: stdout line is neither a command nor a rule: {}",
                    String::from_utf8_lossy(line)
                ));
                break;
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

fn find(buf: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.len() > buf.len() {
        return None;
    }
    (0..=buf.len() - needle.len()).find(|&i| buf[i..].starts_with(needle))
}
