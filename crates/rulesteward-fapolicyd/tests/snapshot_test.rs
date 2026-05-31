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
//! self-documenting (`fapd-F01__missing-colon.snap`, etc.). fapd-F02 scenarios
//! are named `fapd-F02__<scenario_dir>`.
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
use rulesteward_fapolicyd::{
    Entry, LintContext, TrustDb, check_layout, collect_macro_names, fagenrules_cmp, lint,
    lint_cross_file, lint_orphans, lint_with_context, parse_rules_file,
};

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

/// List every immediate subdirectory of `<traps>/fapd-F02/`, sorted by name -
/// these are the layout scenarios (each contains a representative
/// `fapolicyd.rules` and/or `rules.d/`).
fn list_layout_scenarios() -> Vec<PathBuf> {
    let dir = traps_dir("fapd-F02");
    let mut out: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read fapd-F02 traps dir {}: {e}", dir.display()))
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

    let rendered = match parse_rules_file(&src, &rel_path) {
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
// fapd-F01 - syntax errors / unknown directives. Parser-driven; lint never runs.
// ---------------------------------------------------------------------------

#[test]
fn f01_traps() {
    let files = list_rules_files("fapd-F01");
    assert!(
        files.len() >= 4,
        "fapd-F01 trap corpus must have ≥4 files (boundary/near-miss/pathological), found {}",
        files.len(),
    );
    for path in &files {
        drive_file("fapd-F01", path);
    }
}

// ---------------------------------------------------------------------------
// fapd-F03 - mixed modern + legacy syntax in one file. Lint-walker-driven.
// ---------------------------------------------------------------------------

#[test]
fn f03_traps() {
    let files = list_rules_files("fapd-F03");
    assert!(
        files.len() >= 4,
        "fapd-F03 trap corpus must have ≥4 files, found {}",
        files.len(),
    );
    for path in &files {
        drive_file("fapd-F03", path);
    }
}

// ---------------------------------------------------------------------------
// fapd-E01 - unknown attribute name. Lint-walker-driven, one fapd-E01 per
// offender.
// ---------------------------------------------------------------------------

#[test]
fn e01_traps() {
    let files = list_rules_files("fapd-E01");
    assert!(
        files.len() >= 4,
        "fapd-E01 trap corpus must have ≥4 files, found {}",
        files.len(),
    );
    for path in &files {
        drive_file("fapd-E01", path);
    }
}

// ---------------------------------------------------------------------------
// fapd-E02 - invalid attribute value (non-hex filehash, malformed uid, ...).
// Lint-walker-driven, one fapd-E02 per offending value.
// ---------------------------------------------------------------------------

#[test]
fn e02_traps() {
    let files = list_rules_files("fapd-E02");
    assert!(
        files.len() >= 4,
        "fapd-E02 trap corpus must have ≥4 files, found {}",
        files.len(),
    );
    for path in &files {
        drive_file("fapd-E02", path);
    }
}

// ---------------------------------------------------------------------------
// fapd-E03 - macro reference to undefined `%setname`. Lint-walker-driven, one
// fapd-E03 per offending reference. Single-pass walk: definition must appear
// above reference (forward references fire fapd-E03).
// ---------------------------------------------------------------------------

#[test]
fn e03_traps() {
    let files = list_rules_files("fapd-E03");
    assert!(
        files.len() >= 4,
        "fapd-E03 trap corpus must have ≥4 files, found {}",
        files.len(),
    );
    for path in &files {
        drive_file("fapd-E03", path);
    }
}

// ---------------------------------------------------------------------------
// fapd-E04 - macro reference (`%setname`) in `trust=` or `pattern=` attribute
// value. fapolicyd does not substitute macros in these positions regardless
// of whether the macro is defined. Lint-walker-driven; independent of fapd-E03.
// ---------------------------------------------------------------------------

#[test]
fn e04_traps() {
    let files = list_rules_files("fapd-E04");
    assert!(
        files.len() >= 4,
        "fapd-E04 trap corpus must have ≥4 files, found {}",
        files.len(),
    );
    for path in &files {
        drive_file("fapd-E04", path);
    }
}

// ---------------------------------------------------------------------------
// fapd-E05 - macro `%name=` set definition whose values mix numeric (parses as
// i64) and string (everything else). Lint-walker-driven; one fapd-E05 per
// offending SetDefinition. Single-value sets are trivially homogeneous.
// ---------------------------------------------------------------------------

#[test]
fn e05_traps() {
    let files = list_rules_files("fapd-E05");
    assert!(
        files.len() >= 4,
        "fapd-E05 trap corpus must have ≥4 files, found {}",
        files.len(),
    );
    for path in &files {
        drive_file("fapd-E05", path);
    }
}

// ---------------------------------------------------------------------------
// fapd-W02 - broad allow on execute / any with `all : all`. Lint-walker-driven.
// ---------------------------------------------------------------------------

#[test]
fn w02_traps() {
    let files = list_rules_files("fapd-W02");
    assert!(
        files.len() >= 4,
        "fapd-W02 trap corpus must have ≥4 files, found {}",
        files.len(),
    );
    for path in &files {
        drive_file("fapd-W02", path);
    }
}

// ---------------------------------------------------------------------------
// fapd-W07 - deprecated `sha256hash=` attribute name (recommend `filehash=`).
// Lint-walker-driven, one fapd-W07 per offending `Attr::Kv { key: "sha256hash" }`.
// fapd-W07 ignores the value entirely - only the attribute NAME matters;
// value-shape validation belongs to fapd-E02 separately.
// ---------------------------------------------------------------------------

#[test]
fn w07_traps() {
    let files = list_rules_files("fapd-W07");
    assert!(
        files.len() >= 4,
        "fapd-W07 trap corpus must have ≥4 files, found {}",
        files.len(),
    );
    for path in &files {
        drive_file("fapd-W07", path);
    }
}

// ---------------------------------------------------------------------------
// fapd-W01 - rule shadowing (this rule unreachable due to earlier broader
// rule). Lint-walker-driven; pairwise subsume check over `Entry::Rule`s.
// 4 mechanisms: decision-terminal precondition, perm subsume, predicate-list
// subsume (literal-equal + Attr::All shortcut + macro expansion), dir-prefix
// cross-attribute hierarchy. Fixtures force each mechanism in turn.
// ---------------------------------------------------------------------------

#[test]
fn w01_traps() {
    let files = list_rules_files("fapd-W01");
    assert!(
        files.len() >= 8,
        "fapd-W01 trap corpus must have >= 8 files, found {}",
        files.len(),
    );
    for path in &files {
        drive_file("fapd-W01", path);
    }
}

// ---------------------------------------------------------------------------
// fapd-W03 - inline trailing `# comment`. Parser pre-pass-driven.
// ---------------------------------------------------------------------------

#[test]
fn w03_traps() {
    let files = list_rules_files("fapd-W03");
    assert!(
        files.len() >= 4,
        "fapd-W03 trap corpus must have ≥4 files, found {}",
        files.len(),
    );
    for path in &files {
        drive_file("fapd-W03", path);
    }
}

// ---------------------------------------------------------------------------
// fapd-S02 - macro `%name=` set definition appearing AFTER the first rule in
// the file. Lint-walker-driven (Style severity). Single-pass walk: the
// "file top" window is closed only by the first `Entry::Rule`; comments and
// blank lines do NOT close it. One fapd-S02 per offending SetDefinition.
// ---------------------------------------------------------------------------

#[test]
fn s02_traps() {
    let files = list_rules_files("fapd-S02");
    assert!(
        files.len() >= 4,
        "fapd-S02 trap corpus must have >= 4 files, found {}",
        files.len(),
    );
    for path in &files {
        drive_file("fapd-S02", path);
    }
}

// ---------------------------------------------------------------------------
// fapd-W08 - `dir=` value missing its trailing slash. Lint-walker-driven
// (per-file); checks literal `dir=` values AND `dir=%setref` macro expansions.
// Fixtures: fires, clean (trailing slash), both sides, and %setref dir (fires
// per slash-less expanded value / clean when the expansion ends with `/`).
// ---------------------------------------------------------------------------

#[test]
fn w08_traps() {
    let files = list_rules_files("fapd-W08");
    assert!(
        files.len() >= 4,
        "fapd-W08 trap corpus must have >= 4 files, found {}",
        files.len(),
    );
    for path in &files {
        drive_file("fapd-W08", path);
    }
}

// ---------------------------------------------------------------------------
// fapd-F02 - file-layout coexistence. Filesystem-driven via `check_layout`.
// ---------------------------------------------------------------------------

#[test]
fn f02_layout_traps() {
    let scenarios = list_layout_scenarios();
    assert!(
        scenarios.len() >= 4,
        "fapd-F02 layout scenarios must be ≥4 directories, found {}",
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

        let snapshot_name = format!("fapd-F02__{scenario_name}");
        let mut settings = Settings::clone_current();
        settings.set_snapshot_path(manifest_dir().join("tests/snapshots"));
        settings.set_prepend_module_to_snapshot(false);
        settings.bind(|| {
            assert_snapshot!(snapshot_name, rendered);
        });
    }
}

// ---------------------------------------------------------------------------
// fapd-W04 / fapd-C01 - cross-`rules.d/` passes. Directory-scenario-driven via
// `lint_cross_file` over `<scenario>/rules.d/*.rules` in fagenrules load order.
// ---------------------------------------------------------------------------

/// List immediate subdirectories (scenarios) of `<traps>/<code>/`, sorted.
fn list_cross_file_scenarios(code: &str) -> Vec<PathBuf> {
    let dir = traps_dir(code);
    let mut out: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read {code} traps dir {}: {e}", dir.display()))
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    out.sort();
    out
}

/// Drive one cross-file scenario: enumerate `<scenario>/rules.d/*.rules` in
/// fagenrules (`ls -v`) order, parse each using a host-independent
/// `rules.d/<name>` path (so the snapshot is reproducible), run
/// `lint_cross_file`, and snapshot. Snapshot name = `<code>__<scenario>`.
fn drive_cross_file_scenario(code: &str, scenario_dir: &Path) {
    let rules_d = scenario_dir.join("rules.d");
    let mut files: Vec<PathBuf> = std::fs::read_dir(&rules_d)
        .unwrap_or_else(|e| panic!("read rules.d {}: {e}", rules_d.display()))
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.is_file() && p.extension().and_then(|s| s.to_str()) == Some("rules"))
        .collect();
    files.sort_by(|a, b| fagenrules_cmp(a, b));

    let scenario_name = scenario_dir
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or_else(|| panic!("scenario {} has no UTF-8 name", scenario_dir.display()))
        .to_owned();

    let mut parsed: Vec<(PathBuf, Vec<Entry>)> = Vec::new();
    for path in &files {
        let src = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("read fixture {}: {e}", path.display()));
        let entries = match parse_rules_file(&src, path) {
            Ok(entries) => entries,
            Err(diags) => {
                panic!(
                    "cross-file fixture {} must parse cleanly: {diags:?}",
                    path.display()
                )
            }
        };
        let rel = Path::new("rules.d").join(path.file_name().expect("rules file has a name"));
        parsed.push((rel, entries));
    }

    let diags = lint_cross_file(&parsed);

    // Cross-file snapshots span multiple files, so include `file=` (the
    // per-file `render` omits it). Sort deterministically.
    let mut sorted: Vec<&Diagnostic> = diags.iter().collect();
    sorted.sort_by(|a, b| {
        a.file
            .cmp(&b.file)
            .then(a.line.cmp(&b.line))
            .then(a.span.start.cmp(&b.span.start))
            .then(a.code.as_ref().cmp(b.code.as_ref()))
    });

    let mut rendered = String::new();
    writeln!(
        rendered,
        "files={}\ndiagnostics={}",
        files.len(),
        diags.len()
    )
    .expect("write to String never fails");
    if sorted.is_empty() {
        rendered.push_str("(no diagnostics)\n");
    } else {
        for d in sorted {
            writeln!(
                rendered,
                "[{code}] sev={sev:?} line={line} col={col} span={start}..{end} file={file} :: {msg}",
                code = d.code,
                sev = d.severity,
                line = d.line,
                col = d.column,
                start = d.span.start,
                end = d.span.end,
                file = d.file.display(),
                msg = d.message,
            )
            .expect("write to String never fails");
        }
    }

    let snapshot_name = format!("{code}__{scenario_name}");
    let mut settings = Settings::clone_current();
    settings.set_snapshot_path(manifest_dir().join("tests/snapshots"));
    settings.set_prepend_module_to_snapshot(false);
    settings.bind(|| {
        assert_snapshot!(snapshot_name, rendered);
    });
}

#[test]
fn w04_cross_file_traps() {
    let scenarios = list_cross_file_scenarios("fapd-W04");
    assert!(
        scenarios.len() >= 4,
        "fapd-W04 scenarios must be >= 4 directories, found {}",
        scenarios.len(),
    );
    for scenario in &scenarios {
        drive_cross_file_scenario("fapd-W04", scenario);
    }
}

#[test]
fn c01_cross_file_traps() {
    let scenarios = list_cross_file_scenarios("fapd-C01");
    assert!(
        scenarios.len() >= 2,
        "fapd-C01 scenarios must be >= 2 directories, found {}",
        scenarios.len(),
    );
    for scenario in &scenarios {
        drive_cross_file_scenario("fapd-C01", scenario);
    }
}

#[test]
fn c02_cross_file_traps() {
    let scenarios = list_cross_file_scenarios("fapd-C02");
    assert!(
        scenarios.len() >= 3,
        "fapd-C02 scenarios must be >= 3 directories, found {}",
        scenarios.len(),
    );
    for scenario in &scenarios {
        drive_cross_file_scenario("fapd-C02", scenario);
    }
}

#[test]
fn w10_cross_file_traps() {
    let scenarios = list_cross_file_scenarios("fapd-W10");
    assert!(
        scenarios.len() >= 2,
        "fapd-W10 scenarios must be >= 2 directories, found {}",
        scenarios.len(),
    );
    for scenario in &scenarios {
        drive_cross_file_scenario("fapd-W10", scenario);
    }
}

// ---------------------------------------------------------------------------
// B.3 - fapd-E03 cross-file (E03-xfile) and fapd-W09 single-file snapshot drivers.
//
// `drive_cross_file_e03_scenario` mirrors the CLI two-phase loop:
//   - enumerate rules.d/*.rules in fagenrules_cmp order
//   - for each file: lint_with_context with earlier_macros=Some(&union_so_far),
//     single_file=false
//   - collect diagnostics, then extend union with this file's macro names
//
// `drive_file_w09` is the single-file driver: lint_with_context with
// single_file=true, earlier_macros=None.
//
// NO .snap files are generated here. The tests are RED on missing snapshots
// until the implement phase runs `INSTA_UPDATE=always cargo test`. That is the
// intended TDD-RED state.
// ---------------------------------------------------------------------------

/// Drive one cross-file E03 scenario: enumerate `<scenario>/rules.d/*.rules` in
/// fagenrules order, run the two-phase per-file lint (maintaining a running
/// `earlier` set), and snapshot. Snapshot name = `fapd-E03-xfile__<scenario>`.
fn drive_cross_file_e03_scenario(scenario_dir: &Path) {
    let code = "fapd-E03-xfile";
    let rules_d = scenario_dir.join("rules.d");
    let mut files: Vec<PathBuf> = std::fs::read_dir(&rules_d)
        .unwrap_or_else(|e| panic!("read rules.d {}: {e}", rules_d.display()))
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.is_file() && p.extension().and_then(|s| s.to_str()) == Some("rules"))
        .collect();
    files.sort_by(|a, b| fagenrules_cmp(a, b));

    let scenario_name = scenario_dir
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or_else(|| panic!("scenario {} has no UTF-8 name", scenario_dir.display()))
        .to_owned();

    let mut all_diags: Vec<rulesteward_core::Diagnostic> = Vec::new();
    let mut earlier: std::collections::HashSet<String> = std::collections::HashSet::new();

    for path in &files {
        let src = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("read fixture {}: {e}", path.display()));
        let entries = match parse_rules_file(&src, path) {
            Ok(entries) => entries,
            Err(diags) => {
                panic!(
                    "cross-file E03 fixture {} must parse cleanly: {diags:?}",
                    path.display()
                )
            }
        };
        let rel = Path::new("rules.d").join(path.file_name().expect("rules file has a name"));
        let ctx = LintContext {
            earlier_macros: Some(&earlier),
            single_file: false,
            ..Default::default()
        };
        let file_diags = lint_with_context(&entries, &src, &rel, &ctx);
        all_diags.extend(file_diags);
        // Fold this file's macro definitions into the running earlier set.
        earlier.extend(collect_macro_names(&entries));
    }

    // Sort deterministically: file, then line, then span.start, then code.
    let mut sorted: Vec<&rulesteward_core::Diagnostic> = all_diags.iter().collect();
    sorted.sort_by(|a, b| {
        a.file
            .cmp(&b.file)
            .then(a.line.cmp(&b.line))
            .then(a.span.start.cmp(&b.span.start))
            .then(a.code.as_ref().cmp(b.code.as_ref()))
    });

    let mut rendered = String::new();
    writeln!(rendered, "files={}", files.len()).expect("write to String never fails");
    writeln!(rendered, "diagnostics={}", all_diags.len()).expect("write to String never fails");
    if sorted.is_empty() {
        rendered.push_str("(no diagnostics)\n");
    } else {
        for d in sorted {
            writeln!(
                rendered,
                "[{code}] sev={sev:?} line={line} col={col} span={start}..{end} file={file} :: {msg}",
                code = d.code,
                sev = d.severity,
                line = d.line,
                col = d.column,
                start = d.span.start,
                end = d.span.end,
                file = d.file.display(),
                msg = d.message,
            )
            .expect("write to String never fails");
        }
    }

    let snapshot_name = format!("{code}__{scenario_name}");
    let mut settings = Settings::clone_current();
    settings.set_snapshot_path(manifest_dir().join("tests/snapshots"));
    settings.set_prepend_module_to_snapshot(false);
    settings.bind(|| {
        assert_snapshot!(snapshot_name, rendered);
    });
}

/// Single-file W09 driver: parse `path`, run `lint_with_context` with
/// `single_file=true, earlier_macros=None`, and snapshot.
/// Snapshot name = `fapd-W09__<stem>`.
fn drive_file_w09(path: &Path) {
    let code = "fapd-W09";
    let src = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("read trap input {}: {e}", path.display()));
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or_else(|| panic!("trap input {} has no UTF-8 file stem", path.display()))
        .to_owned();
    let rel_path = Path::new("tests/corpus/traps")
        .join(code)
        .join(path.file_name().expect("trap file has a name"));

    let rendered = match parse_rules_file(&src, &rel_path) {
        Ok(entries) => {
            let ctx = LintContext {
                single_file: true,
                ..Default::default()
            };
            let diags = lint_with_context(&entries, &src, &rel_path, &ctx);
            render("parse=ok", &diags)
        }
        Err(diags) => render("parse=err", &diags),
    };

    let snapshot_name = format!("{code}__{stem}");
    let mut settings = Settings::clone_current();
    settings.set_snapshot_path(manifest_dir().join("tests/snapshots"));
    settings.set_prepend_module_to_snapshot(false);
    settings.bind(|| {
        assert_snapshot!(snapshot_name, rendered);
    });
}

#[test]
fn e03_xfile_traps() {
    let scenarios = list_cross_file_scenarios("fapd-E03-xfile");
    assert!(
        scenarios.len() >= 2,
        "fapd-E03-xfile scenarios must be >= 2 directories, found {}",
        scenarios.len(),
    );
    for scenario in &scenarios {
        drive_cross_file_e03_scenario(scenario);
    }
}

#[test]
fn w09_traps() {
    let files = list_rules_files("fapd-W09");
    assert!(
        files.len() >= 4,
        "fapd-W09 trap corpus must have >= 4 files, found {}",
        files.len(),
    );
    for path in &files {
        drive_file_w09(path);
    }
}

// ---------------------------------------------------------------------------
// B.5 - Stock-ruleset regression pin.
//
// Runs the cross-file-aware two-phase lint over the REAL happy corpus
// (`tests/corpus/happy/*.rules`) in fagenrules load order, and asserts ZERO
// diagnostics with code fapd-E03.
//
// The stock ruleset has `10-languages.rules` defining `%languages` and
// `70-trusted-lang.rules` referencing it - a cross-file backward reference that
// the current per-file resolution incorrectly flags as fapd-E03.
//
// This test is RED now and GREEN after the implement phase.
// ---------------------------------------------------------------------------

#[test]
fn stock_ruleset_happy_corpus_zero_e03_cross_file() {
    let happy = manifest_dir().join("tests/corpus/happy");
    let mut files: Vec<PathBuf> = std::fs::read_dir(&happy)
        .unwrap_or_else(|e| panic!("read happy corpus dir {}: {e}", happy.display()))
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.is_file() && p.extension().and_then(|s| s.to_str()) == Some("rules"))
        .collect();
    files.sort_by(|a, b| fagenrules_cmp(a, b));

    // Sanity: the corpus must contain the two cross-file files we care about.
    let names: Vec<&str> = files
        .iter()
        .filter_map(|p| p.file_name().and_then(|s| s.to_str()))
        .collect();
    assert!(
        names.contains(&"10-languages.rules"),
        "happy corpus must contain 10-languages.rules (defines %%languages): found {names:?}",
    );
    assert!(
        names.contains(&"70-trusted-lang.rules"),
        "happy corpus must contain 70-trusted-lang.rules (references %%languages): found {names:?}",
    );

    let mut all_e03: Vec<rulesteward_core::Diagnostic> = Vec::new();
    let mut earlier: std::collections::HashSet<String> = std::collections::HashSet::new();

    for path in &files {
        let src = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("read happy corpus file {}: {e}", path.display()));
        let rel =
            Path::new("tests/corpus/happy").join(path.file_name().expect("rules file has a name"));
        let entries = match parse_rules_file(&src, &rel) {
            Ok(entries) => entries,
            Err(diags) => panic!(
                "happy corpus file {} must parse cleanly: {diags:?}",
                path.display()
            ),
        };
        let ctx = LintContext {
            earlier_macros: Some(&earlier),
            single_file: false,
            ..Default::default()
        };
        let diags = lint_with_context(&entries, &src, &rel, &ctx);
        all_e03.extend(diags.into_iter().filter(|d| d.code.as_ref() == "fapd-E03"));
        earlier.extend(collect_macro_names(&entries));
    }

    assert!(
        all_e03.is_empty(),
        "stock ruleset happy corpus must have ZERO fapd-E03 with cross-file-aware lint; \
         fapd-E03 false positives: {all_e03:#?}",
    );
}

// ---------------------------------------------------------------------------
// Trust-DB fixture builder helpers
//
// REPRODUCIBILITY: W06 traps use guaranteed-absent /nonexistent/rs-trap/...
// paths so Path::exists() is stable across CI hosts.
// ---------------------------------------------------------------------------

/// Read the newline-separated keys from a `_trustdb-keys.txt` file in `dir`
/// and build a tempfile LMDB trust.db fixture from them. Returns the `TrustDb`
/// handle (read-only) and the `tempfile::TempDir` whose lifetime keeps the dir
/// alive.
///
/// # Panics
///
/// Panics if the keys file is missing, the LMDB env cannot be created, or any
/// key cannot be inserted.
#[allow(unsafe_code)]
fn build_fixture_trustdb(dir: &Path) -> (TrustDb, tempfile::TempDir) {
    let keys_path = dir.join("_trustdb-keys.txt");
    let keys_text = std::fs::read_to_string(&keys_path)
        .unwrap_or_else(|e| panic!("read {}: {e}", keys_path.display()));
    let keys: Vec<&str> = keys_text.lines().filter(|l| !l.trim().is_empty()).collect();

    let tmp = tempfile::tempdir().expect("tempdir for fixture trustdb");
    // SAFETY: opens a freshly-created tempdir LMDB env RW to build a test
    // fixture; no other process touches it. heed's open is unsafe (mmap).
    let env = unsafe {
        heed::EnvOpenOptions::new()
            .max_dbs(1)
            .open(tmp.path())
            .expect("build_fixture_trustdb: failed to open LMDB env")
    };
    let mut wtxn = env
        .write_txn()
        .expect("build_fixture_trustdb: write_txn failed");
    let db: heed::Database<heed::types::Bytes, heed::types::Bytes> = env
        .create_database(&mut wtxn, Some("trust.db"))
        .expect("build_fixture_trustdb: create_database failed");
    for key in &keys {
        // Value mimics fapolicyd: "<src_int> <size> <sha256_hex>"
        let value = b"1 12345 aabbccdd0011223344556677889900aabbccdd0011223344556677889900aabb";
        db.put(&mut wtxn, key.as_bytes(), value)
            .expect("build_fixture_trustdb: put failed");
    }
    wtxn.commit().expect("build_fixture_trustdb: commit failed");
    drop(env); // flush + close before re-opening read-only

    let trust_db =
        rulesteward_fapolicyd::open_trustdb_readonly(tmp.path()).expect("open_trustdb_readonly");
    (trust_db, tmp)
}

// ---------------------------------------------------------------------------
// fapd-W06 - path=/exe= literal not in trust DB and not on disk.
// Trust-DB-aware per-file snapshot driver.
// ---------------------------------------------------------------------------

/// Parse one `.rules` file, open the W06 fixture trust.db, run
/// `lint_with_context` with `LintContext{ trustdb: Some(&db) }`, and snapshot
/// under `fapd-W06__<stem>`. The fixture DB is built from the shared
/// `_trustdb-keys.txt` in the `fapd-W06/` trap directory.
fn drive_file_with_trustdb_w06(path: &Path) {
    let code = "fapd-W06";
    let src = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("read trap input {}: {e}", path.display()));
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or_else(|| panic!("trap input {} has no UTF-8 file stem", path.display()))
        .to_owned();
    let rel_path = Path::new("tests/corpus/traps")
        .join(code)
        .join(path.file_name().expect("trap file has a name"));

    let (db, _tmp) = build_fixture_trustdb(&traps_dir(code));

    let rendered = match parse_rules_file(&src, &rel_path) {
        Ok(entries) => {
            let ctx = LintContext {
                trustdb: Some(&db),
                ..Default::default()
            };
            let diags = lint_with_context(&entries, &src, &rel_path, &ctx);
            render("parse=ok", &diags)
        }
        Err(diags) => render("parse=err", &diags),
    };

    let snapshot_name = format!("{code}__{stem}");
    let mut settings = Settings::clone_current();
    settings.set_snapshot_path(manifest_dir().join("tests/snapshots"));
    settings.set_prepend_module_to_snapshot(false);
    settings.bind(|| {
        assert_snapshot!(snapshot_name, rendered);
    });
}

#[test]
fn w06_traps() {
    let files = list_rules_files("fapd-W06");
    assert!(
        files.len() >= 4,
        "fapd-W06 trap corpus must have >= 4 files, found {}",
        files.len(),
    );
    for path in &files {
        drive_file_with_trustdb_w06(path);
    }
}

// ---------------------------------------------------------------------------
// fapd-W05 - uid=/gid= literal not found in the host identity database.
// Identity-check-aware per-file snapshot driver.
//
// Corpus fixtures may only use universally-stable identities:
//   - uid=0 is guaranteed to resolve on every POSIX host (getent passwd 0 -> root)
//   - uid=4294967294 is guaranteed ABSENT on any real host (getent exit 2)
//   - %macroref values are skipped (no literal to check)
//
// The driver builds a LintContext with check_identities=true and uses the REAL
// getent path (walk()), so snapshot output is stable only for the
// universally-stable fixtures above. Hermetically untestable cases (e.g.,
// a specific username that exists on one CI host but not another) are covered
// by the unit tests in identity.rs via the injectable mock resolver.
// ---------------------------------------------------------------------------

/// Parse one `.rules` file, run `lint_with_context` with
/// `LintContext{ check_identities: true }`, and snapshot under `fapd-W05__<stem>`.
fn drive_file_w05(path: &Path) {
    let code = "fapd-W05";
    let src = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("read trap input {}: {e}", path.display()));
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or_else(|| panic!("trap input {} has no UTF-8 file stem", path.display()))
        .to_owned();
    let rel_path = Path::new("tests/corpus/traps")
        .join(code)
        .join(path.file_name().expect("trap file has a name"));

    let rendered = match parse_rules_file(&src, &rel_path) {
        Ok(entries) => {
            let ctx = LintContext {
                check_identities: true,
                ..Default::default()
            };
            let diags = lint_with_context(&entries, &src, &rel_path, &ctx);
            render("parse=ok", &diags)
        }
        Err(diags) => render("parse=err", &diags),
    };

    let snapshot_name = format!("{code}__{stem}");
    let mut settings = Settings::clone_current();
    settings.set_snapshot_path(manifest_dir().join("tests/snapshots"));
    settings.set_prepend_module_to_snapshot(false);
    settings.bind(|| {
        assert_snapshot!(snapshot_name, rendered);
    });
}

#[test]
fn w05_traps() {
    let files = list_rules_files("fapd-W05");
    assert!(
        files.len() >= 3,
        "fapd-W05 trap corpus must have >= 3 files, found {}",
        files.len(),
    );
    for path in &files {
        drive_file_w05(path);
    }
}

// ---------------------------------------------------------------------------
// fapd-X01 - trust DB entries not referenced by any rule (orphan summary).
// Scenario-driven snapshot driver using lint_orphans.
// ---------------------------------------------------------------------------

/// List immediate subdirectories (scenarios) of `<traps>/fapd-X01/`, sorted.
fn list_x01_scenarios() -> Vec<PathBuf> {
    let dir = traps_dir("fapd-X01");
    let mut out: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read fapd-X01 traps dir {}: {e}", dir.display()))
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    out.sort();
    out
}

/// Drive one X01 scenario: enumerate `<scenario>/rules.d/*.rules` in
/// fagenrules order, parse each, build the fixture DB from
/// `<scenario>/_trustdb-keys.txt`, run `lint_orphans`, and snapshot.
/// Snapshot name = `fapd-X01__<scenario>`.
fn drive_scenario_x01(scenario_dir: &Path) {
    let code = "fapd-X01";
    let rules_d = scenario_dir.join("rules.d");
    let mut files: Vec<PathBuf> = std::fs::read_dir(&rules_d)
        .unwrap_or_else(|e| panic!("read rules.d {}: {e}", rules_d.display()))
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.is_file() && p.extension().and_then(|s| s.to_str()) == Some("rules"))
        .collect();
    files.sort_by(|a, b| fagenrules_cmp(a, b));

    let scenario_name = scenario_dir
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or_else(|| panic!("scenario {} has no UTF-8 name", scenario_dir.display()))
        .to_owned();

    let mut parsed: Vec<(PathBuf, Vec<Entry>)> = Vec::new();
    for path in &files {
        let src = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("read fixture {}: {e}", path.display()));
        let entries = match parse_rules_file(&src, path) {
            Ok(entries) => entries,
            Err(diags) => {
                panic!(
                    "X01 scenario fixture {} must parse cleanly: {diags:?}",
                    path.display()
                )
            }
        };
        let rel = Path::new("rules.d").join(path.file_name().expect("rules file has a name"));
        parsed.push((rel, entries));
    }

    let (db, _tmp) = build_fixture_trustdb(scenario_dir);
    let diags = lint_orphans(&parsed, &db);

    // X01 emits at most one summary diagnostic. Render with a db= line so the
    // snapshot pins the scenario path shape without using the absolute tempdir.
    let mut rendered = String::new();
    writeln!(rendered, "files={}", files.len()).expect("write to String never fails");
    writeln!(rendered, "diagnostics={}", diags.len()).expect("write to String never fails");
    if diags.is_empty() {
        rendered.push_str("(no diagnostics)\n");
    } else {
        for d in &diags {
            // db.path() is the tempdir - render the diagnostic without it to
            // keep the snapshot host-independent. We use file= "<trustdb>" as
            // a stable placeholder.
            writeln!(
                rendered,
                "[{code}] sev={sev:?} span={start}..{end} :: {msg}",
                code = d.code,
                sev = d.severity,
                start = d.span.start,
                end = d.span.end,
                msg = d.message,
            )
            .expect("write to String never fails");
        }
    }

    let snapshot_name = format!("{code}__{scenario_name}");
    let mut settings = Settings::clone_current();
    settings.set_snapshot_path(manifest_dir().join("tests/snapshots"));
    settings.set_prepend_module_to_snapshot(false);
    settings.bind(|| {
        assert_snapshot!(snapshot_name, rendered);
    });
}

#[test]
fn x01_traps() {
    let scenarios = list_x01_scenarios();
    assert!(
        scenarios.len() >= 3,
        "fapd-X01 scenario corpus must have >= 3 directories, found {}",
        scenarios.len(),
    );
    for scenario in &scenarios {
        drive_scenario_x01(scenario);
    }
}
