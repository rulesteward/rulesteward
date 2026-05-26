//! Adversarial trap-corpus snapshot driver.
//!
//! For each trap input under `tests/corpus/traps/<code>/`, drive it through
//! `parse_rules_file` (and `lint` when parsing succeeds) and snapshot the
//! resulting diagnostics in a deterministic, mutation-test-killing format.
//!
//! ## Why a hand-formatted snapshot (not yaml / debug)?
//!
//! `insta::assert_yaml_snapshot!` would need `serde::Serialize` on a custom
//! helper struct, which would require adding a `serde` dev-dep - the agent
//! brief forbids new deps. `assert_debug_snapshot!` would tie the snapshot
//! to the `Debug` representation of `Vec<Diagnostic>`, which is verbose,
//! noisy, and Rust-version-sensitive.
//!
//! Instead each diagnostic is rendered as a single line:
//!     `[CODE] sev=Severity line=L col=C span=START..END :: message`
//! This is deterministic, diff-friendly, and pins every field a mutant
//! could touch: severity (5 options), code (string), line (usize), column
//! (usize), span (Range<usize>), and message (String). A mutant that
//! flips `Severity::Warning -> Severity::Error`, or shifts a span by one
//! byte, or drops the message, all produce a snapshot diff.
//!
//! ## Naming
//!
//! Snapshot names are `<code>__<file_stem>` so review surface is
//! self-documenting (`F01__missing-colon.snap`, etc.). F02 scenarios are
//! named `F02__<scenario_dir>`.
//!
//! ## What ships when
//!
//! No `.snap` files exist yet - they are generated on the first impl-green
//! run by `INSTA_UPDATE=always cargo test --test snapshot_test` or the
//! `cargo insta review` workflow. Until the parser/lint bodies land, every
//! snapshot test panics inside `todo!()` - that is the TDD discipline.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use insta::{Settings, assert_snapshot};
use rulesteward_core::Diagnostic;
use rulesteward_fapolicyd::{check_layout, lint, parse_rules_file};

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn traps_dir(code: &str) -> PathBuf {
    manifest_dir().join("tests/corpus/traps").join(code)
}

/// List every `.rules` file in `<traps>/<code>/`, sorted by filename for
/// deterministic snapshot ordering across CI runs.
fn list_rules_files(code: &str) -> Vec<PathBuf> {
    let dir = traps_dir(code);
    let mut out: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read traps dir {}: {e}", dir.display()))
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.is_file() && p.extension().and_then(|s| s.to_str()) == Some("rules"))
        .collect();
    out.sort();
    out
}

/// List every immediate subdirectory of `<traps>/F02/`, sorted by name -
/// these are the layout scenarios (each contains a representative
/// `fapolicyd.rules` and/or `rules.d/`).
fn list_layout_scenarios() -> Vec<PathBuf> {
    let dir = traps_dir("F02");
    let mut out: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read F02 traps dir {}: {e}", dir.display()))
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    out.sort();
    out
}

/// Render diagnostics into the deterministic line-per-diagnostic snapshot
/// shape described in the module doc. The `outcome` header on line 1 is
/// either `parse=ok` or `parse=err` - itself a mutation-killing assertion
/// (flipping the success/failure branch in the parser changes line 1).
fn render(outcome: &str, diags: &[Diagnostic]) -> String {
    let mut s = String::new();
    s.push_str(outcome);
    writeln!(s, "\ndiagnostics={}", diags.len()).expect("write to String never fails");
    if diags.is_empty() {
        s.push_str("(no diagnostics)\n");
        return s;
    }
    // Sort diagnostics for deterministic snapshot order, since lint passes
    // may emit in any order. Sort key: (line, column, span.start, code).
    let mut sorted: Vec<&Diagnostic> = diags.iter().collect();
    sorted.sort_by(|a, b| {
        a.line
            .cmp(&b.line)
            .then(a.column.cmp(&b.column))
            .then(a.span.start.cmp(&b.span.start))
            .then(a.code.as_ref().cmp(b.code.as_ref()))
    });
    for d in sorted {
        writeln!(
            s,
            "[{code}] sev={sev:?} line={line} col={col} span={start}..{end} :: {msg}",
            code = d.code,
            sev = d.severity,
            line = d.line,
            col = d.column,
            start = d.span.start,
            end = d.span.end,
            msg = d.message,
        )
        .expect("write to String never fails");
    }
    s
}

/// Single-shot driver: parse, optionally lint, render, snapshot. Snapshot
/// name = `<code>__<file_stem>`.
fn drive_file(code: &str, path: &Path) {
    let src = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("read trap input {}: {e}", path.display()));
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or_else(|| panic!("trap input {} has no UTF-8 file stem", path.display()))
        .to_owned();
    // file_path passed to `lint` is the relative path under tests/ so the
    // PathBuf in the Diagnostic is reproducible across machines.
    let rel_path = Path::new("tests/corpus/traps")
        .join(code)
        .join(path.file_name().expect("trap file has a name"));

    let rendered = match parse_rules_file(&src) {
        Ok(entries) => {
            let diags = lint(&entries, &src, &rel_path);
            render("parse=ok", &diags)
        }
        Err(diags) => render("parse=err", &diags),
    };

    let snapshot_name = format!("{code}__{stem}");
    // Override the snapshot path so all snaps land in tests/snapshots/ with
    // the predictable name above - keeps the review surface tidy.
    let mut settings = Settings::clone_current();
    settings.set_snapshot_path(manifest_dir().join("tests/snapshots"));
    settings.set_prepend_module_to_snapshot(false);
    settings.bind(|| {
        assert_snapshot!(snapshot_name, rendered);
    });
}

// ---------------------------------------------------------------------------
// F01 - syntax errors / unknown directives. Parser-driven; lint never runs.
// ---------------------------------------------------------------------------

#[test]
fn f01_traps() {
    let files = list_rules_files("F01");
    assert!(
        files.len() >= 4,
        "F01 trap corpus must have ≥4 files (boundary/near-miss/pathological), found {}",
        files.len(),
    );
    for path in &files {
        drive_file("F01", path);
    }
}

// ---------------------------------------------------------------------------
// F03 - mixed modern + legacy syntax in one file. Lint-walker-driven.
// ---------------------------------------------------------------------------

#[test]
fn f03_traps() {
    let files = list_rules_files("F03");
    assert!(
        files.len() >= 4,
        "F03 trap corpus must have ≥4 files, found {}",
        files.len(),
    );
    for path in &files {
        drive_file("F03", path);
    }
}

// ---------------------------------------------------------------------------
// E01 - unknown attribute name. Lint-walker-driven, one E01 per offender.
// ---------------------------------------------------------------------------

#[test]
fn e01_traps() {
    let files = list_rules_files("E01");
    assert!(
        files.len() >= 4,
        "E01 trap corpus must have ≥4 files, found {}",
        files.len(),
    );
    for path in &files {
        drive_file("E01", path);
    }
}

// ---------------------------------------------------------------------------
// E02 - invalid attribute value (non-hex filehash, malformed uid, ...).
// Lint-walker-driven, one E02 per offending value.
// ---------------------------------------------------------------------------

#[test]
fn e02_traps() {
    let files = list_rules_files("E02");
    assert!(
        files.len() >= 4,
        "E02 trap corpus must have ≥4 files, found {}",
        files.len(),
    );
    for path in &files {
        drive_file("E02", path);
    }
}

// ---------------------------------------------------------------------------
// E03 - macro reference to undefined `%setname`. Lint-walker-driven, one
// E03 per offending reference. Single-pass walk: definition must appear
// above reference (forward references fire E03).
// ---------------------------------------------------------------------------

#[test]
fn e03_traps() {
    let files = list_rules_files("E03");
    assert!(
        files.len() >= 4,
        "E03 trap corpus must have ≥4 files, found {}",
        files.len(),
    );
    for path in &files {
        drive_file("E03", path);
    }
}

// ---------------------------------------------------------------------------
// E04 - macro reference (`%setname`) in `trust=` or `pattern=` attribute
// value. fapolicyd does not substitute macros in these positions regardless
// of whether the macro is defined. Lint-walker-driven; independent of E03.
// ---------------------------------------------------------------------------

#[test]
fn e04_traps() {
    let files = list_rules_files("E04");
    assert!(
        files.len() >= 4,
        "E04 trap corpus must have ≥4 files, found {}",
        files.len(),
    );
    for path in &files {
        drive_file("E04", path);
    }
}

// ---------------------------------------------------------------------------
// W02 - broad allow on execute / any with `all : all`. Lint-walker-driven.
// ---------------------------------------------------------------------------

#[test]
fn w02_traps() {
    let files = list_rules_files("W02");
    assert!(
        files.len() >= 4,
        "W02 trap corpus must have ≥4 files, found {}",
        files.len(),
    );
    for path in &files {
        drive_file("W02", path);
    }
}

// ---------------------------------------------------------------------------
// W03 - inline trailing `# comment`. Parser pre-pass-driven.
// ---------------------------------------------------------------------------

#[test]
fn w03_traps() {
    let files = list_rules_files("W03");
    assert!(
        files.len() >= 4,
        "W03 trap corpus must have ≥4 files, found {}",
        files.len(),
    );
    for path in &files {
        drive_file("W03", path);
    }
}

// ---------------------------------------------------------------------------
// F02 - file-layout coexistence. Filesystem-driven via `check_layout`.
// ---------------------------------------------------------------------------

#[test]
fn f02_layout_traps() {
    let scenarios = list_layout_scenarios();
    assert!(
        scenarios.len() >= 4,
        "F02 layout scenarios must be ≥4 directories, found {}",
        scenarios.len(),
    );
    for scenario_dir in &scenarios {
        let scenario_name = scenario_dir
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or_else(|| panic!("scenario dir {} has no UTF-8 name", scenario_dir.display()))
            .to_owned();

        let diag_opt = check_layout(scenario_dir);

        // Render: single-line outcome on line 1, then the diagnostic line if
        // any. We do NOT use `Debug` of `Option<Diagnostic>` - that would
        // include the absolute `file: PathBuf` which is host-specific.
        let mut rendered = String::new();
        match &diag_opt {
            None => rendered.push_str("layout=ok\nno-diagnostic\n"),
            Some(d) => {
                rendered.push_str("layout=trip\n");
                // Render `file` as the scenario-relative path so snaps are
                // reproducible across machines. We only check the file
                // basename and the parent directory name.
                let file_display = d.file.strip_prefix(scenario_dir).map_or_else(
                    |_| {
                        d.file
                            .file_name()
                            .and_then(|s| s.to_str())
                            .unwrap_or("<unknown>")
                            .to_owned()
                    },
                    |p| p.display().to_string(),
                );
                writeln!(
                    rendered,
                    "[{code}] sev={sev:?} line={line} col={col} span={start}..{end} file={file} :: {msg}",
                    code = d.code,
                    sev = d.severity,
                    line = d.line,
                    col = d.column,
                    start = d.span.start,
                    end = d.span.end,
                    file = file_display,
                    msg = d.message,
                )
                .expect("write to String never fails");
            }
        }

        let snapshot_name = format!("F02__{scenario_name}");
        let mut settings = Settings::clone_current();
        settings.set_snapshot_path(manifest_dir().join("tests/snapshots"));
        settings.set_prepend_module_to_snapshot(false);
        settings.bind(|| {
            assert_snapshot!(snapshot_name, rendered);
        });
    }
}
