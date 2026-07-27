//! Differential-oracle adapter for the `sysctld` backend (session 9k-1 Lane B,
//! #499, issue #593).
//!
//! This module is the product side of the Tier-1 replay test described in
//! `CONTRIBUTING.md` "Differential oracle contract". It lets
//! `crates/rulesteward-sysctld/tests/sysctld_corpus_oracle.rs` compare
//! `RuleSteward`'s computed effective value for a scenario's tracked sysctl key
//! against the value the REAL `systemd-sysctl` daemon computed for the same
//! merged tree, recorded verbatim (via `SYSTEMD_LOG_LEVEL=debug` apply-mode
//! output) in the committed corpus under `tests/corpus/sysctld-oracle/`.
//!
//! # Why this lives in `src/` and not in the test
//!
//! The materializer, the inventory recomputation and the transcript classifier
//! are the logic whose being wrong would make the differential report success
//! while checking nothing. Keeping them here subjects them to `just ci`
//! clippy, the coverage floor and the mutation gate; a `tests/`-only or
//! feature-gated home would silently drop all three. Before this extraction
//! `.cargo/mutants.toml`'s pre-registered glob for this file matched no file
//! at all, which reports "0 mutants" - indistinguishable from "every mutant
//! caught" - the exact vacuity this session exists to close.
//!
//! # The materializer equivalence guard
//!
//! Two independent thin materializers exist by necessity: [`materialize`]
//! (for the `tempdir()` replay this test performs) and `materialize.sh` (run
//! inside the `rs-oracleN` container by `capture_sysctld.sh`, since
//! `systemd-sysctl` has no `--root` - see CLAUDE.md "Measured sysctld oracle
//! facts"). If they silently diverge, the differential compares apples to
//! oranges. Every scenario's `tree.plan` therefore carries a `---`-delimited
//! VENDORED inventory block (the expected filesystem shape, recomputed via
//! globs, never by replaying the plan) that [`compute_inventory`]'s freshly
//! recomputed inventory must equal exactly - a materializer divergence becomes
//! a hard, readable, docker-free Tier-1 failure. See `PROVENANCE.md` "Corpus
//! format" for the full schema.
//!
//! # Scope of the equivalence guard
//!
//! [`compute_inventory`] covers the four standard search directories
//! (`etc|run|usr/local/lib|usr/lib` + `sysctl.d`), the `lib -> usr/lib`
//! merged-usr alias, and `etc/sysctl.conf`. One scenario
//! (`slot-symlink-misdirected-593`) materializes a file OUTSIDE this scope
//! (`etc/rs9k1-hidden.conf`, deliberately outside every search directory -
//! that is the whole point of the #593 bug); that file is real for the
//! materialization step but is NOT part of the vendored inventory block,
//! since the guard's job is to protect the standard search-path locations
//! where the actual precedence/masking logic runs, not arbitrary
//! scenario-specific paths.
//!
//! # Never split this file into an `oracle/` directory
//!
//! `.cargo/mutants.toml`'s `examine_globs` allowlist names this exact file
//! path (`crates/rulesteward-sysctld/src/oracle.rs`). Splitting it into a
//! directory (`oracle/mod.rs` plus submodules) makes that glob match NOTHING,
//! silently reinstating the exact vacuity this extraction was built to
//! close: a `cargo mutants` summary reads "0 mutants examined" identically to
//! "every mutant caught". If this file ever genuinely needs splitting, update
//! the `mutants.toml` glob in the SAME commit and confirm `total_mutants > 0`
//! for the new path afterward - never trust the exit code alone.

use std::fs;
use std::os::unix::fs::{FileTypeExt, symlink};
use std::path::{Component, Path};

/// The four standard `sysctl.d` search directories, matching `crate::system`'s
/// own `search_dirs` (rank irrelevant here - the equivalence guard only needs
/// to know WHERE to glob, not precedence).
const STANDARD_DIRS: &[&str] = &[
    "etc/sysctl.d",
    "run/sysctl.d",
    "usr/local/lib/sysctl.d",
    "usr/lib/sysctl.d",
];

// ---------------------------------------------------------------------------
// tree.plan: TSV `TYPE\tRELPATH\tARG`, split into a materialize section and a
// `---`-delimited vendored inventory section. See materialize.sh's doc comment
// for the shared algorithm description.
// ---------------------------------------------------------------------------

/// One filesystem entry, either a `tree.plan` instruction (materialize
/// section) or a recorded/recomputed inventory row (vendored section).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct InvEntry {
    ty: char,
    relpath: String,
    detail: String,
}

/// Parse one `tree.plan` line (`TYPE\tRELPATH\tARG`) into an [`InvEntry`].
///
/// Fail-closed (CONTRIBUTING rule 3): an empty type field is a corpus
/// authoring defect, not a silently accepted blank entry.
#[must_use]
pub fn parse_plan_line(line: &str) -> InvEntry {
    let mut parts = line.splitn(3, '\t');
    let ty = parts
        .next()
        .and_then(|s| s.chars().next())
        .unwrap_or_else(|| panic!("tree.plan: empty type field in line {line:?}"));
    let relpath = parts.next().unwrap_or_default().to_string();
    let arg = parts.next().unwrap_or_default().to_string();
    InvEntry {
        ty,
        relpath,
        detail: arg,
    }
}

/// Split a `tree.plan` file's text into `(materialize_entries,
/// vendored_inventory_entries)`. Blank lines and `#`-prefixed comment lines
/// are dropped from both sections; the line consisting of exactly `---`
/// switches from the materialize section to the inventory section.
///
/// Fail-closed (CONTRIBUTING rule 3): a plan with zero materialize entries, or
/// with no `---` marker at all, is a corpus authoring defect, not a silently
/// accepted empty scenario.
#[must_use]
pub fn parse_tree_plan(text: &str) -> (Vec<InvEntry>, Vec<InvEntry>) {
    let mut materialize = Vec::new();
    let mut inventory = Vec::new();
    let mut in_inventory = false;
    let mut saw_marker = false;
    for line in text.lines() {
        if line == "---" {
            in_inventory = true;
            saw_marker = true;
            continue;
        }
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let entry = parse_plan_line(line);
        if in_inventory {
            inventory.push(entry);
        } else {
            materialize.push(entry);
        }
    }
    assert!(
        saw_marker,
        "tree.plan has no '---' vendored-inventory marker"
    );
    assert!(
        !materialize.is_empty(),
        "tree.plan has zero materialize entries before '---'"
    );
    assert!(
        !inventory.is_empty(),
        "tree.plan has zero vendored inventory entries after '---'"
    );
    (materialize, inventory)
}

/// Materialize a scenario's `tree.plan` onto `root` (a fresh `tempdir()`),
/// copying regular-file content from `content_dir`. Ports `materialize.sh`
/// exactly - see that file's doc comment for the one shared algorithm
/// description both sides implement.
///
/// `#[doc(hidden)]`: this function WRITES to `root` on the caller's behalf
/// and trusts every `relpath` it is given (see the fail-closed checks below
/// for what it does reject). It has exactly one caller today
/// (`tests/sysctld_corpus_oracle.rs`, always with a fresh `tempfile::tempdir()`)
/// and no product caller - it is test-support infrastructure, not a general
/// "materialize a plan onto any path" API a future feature should build on.
#[doc(hidden)]
pub fn materialize(root: &Path, content_dir: &Path, entries: &[InvEntry]) {
    for d in STANDARD_DIRS {
        fs::create_dir_all(root.join(d)).unwrap_or_else(|e| panic!("mkdir {d}: {e}"));
    }
    for e in entries {
        assert!(
            !e.relpath.starts_with("lib/"),
            "tree.plan declares a path under lib/ ({}) - the merged-usr alias is \
             created automatically and must never be declared directly",
            e.relpath
        );
        // Fail-closed against a relpath that could escape `root` entirely:
        // `Path::join` REPLACES the base when given an absolute path, `..`
        // components traverse lexically and `create_dir_all` below actually
        // creates whatever that resolves to, and a truncated plan line (a
        // bare "d" with nothing after the tab) yields an EMPTY relpath whose
        // `.parent()` is `root`'s own PARENT. This matters because `root` is
        // not always committed, reviewed data - `RS_ORACLE_CORPUS_SYSCTLD`
        // repoints this same replay at a freshly captured, not-yet-trusted
        // tree in fresh mode. Same family as the `lib/` guard above and the
        // `/dev/null`-only symlink-target guard below; this closes the gap
        // between them.
        assert!(
            !e.relpath.is_empty(),
            "tree.plan entry has an empty relpath (a truncated plan line?) - refusing to \
             materialize onto root's own parent directory"
        );
        assert!(
            !e.relpath.starts_with('/'),
            "tree.plan declares an absolute relpath ({}) - Path::join would replace `root` \
             entirely instead of nesting under it",
            e.relpath
        );
        assert!(
            !Path::new(&e.relpath)
                .components()
                .any(|c| matches!(c, Component::ParentDir)),
            "tree.plan declares a relpath containing '..' ({}) - this would let \
             materialization escape `root`",
            e.relpath
        );
        let dest = root.join(&e.relpath);
        let parent = dest
            .parent()
            .unwrap_or_else(|| panic!("{} has no parent", e.relpath));
        fs::create_dir_all(parent).unwrap_or_else(|e2| panic!("mkdir {}: {e2}", parent.display()));
        match e.ty {
            'd' => {
                fs::create_dir_all(&dest).unwrap_or_else(|e2| panic!("mkdir {}: {e2}", e.relpath));
            }
            'f' => {
                let src = content_dir.join(&e.relpath);
                fs::copy(&src, &dest).unwrap_or_else(|e2| {
                    panic!("copy {} -> {}: {e2}", src.display(), dest.display())
                });
            }
            'l' => {
                if let Some(stripped) = e.detail.strip_prefix('/') {
                    assert_eq!(
                        stripped, "dev/null",
                        "the only permitted absolute symlink target is /dev/null, got {:?}",
                        e.detail
                    );
                }
                symlink(&e.detail, &dest)
                    .unwrap_or_else(|e2| panic!("symlink {} -> {}: {e2}", e.detail, e.relpath));
            }
            other => panic!(
                "tree.plan type '{other}' is not supported by the Rust replay materializer \
                 (a 'p' FIFO entry is deliberately unsupported here: no committed scenario uses \
                 one live, since a .conf FIFO hangs systemd-sysctl indefinitely - see \
                 PROVENANCE.md finding (b))"
            ),
        }
    }
    let lib = root.join("lib");
    let _ = fs::remove_file(&lib);
    let usr_lib = root.join("usr/lib");
    fs::create_dir_all(&usr_lib).unwrap_or_else(|e| panic!("mkdir {}: {e}", usr_lib.display()));
    symlink("usr/lib", &lib).unwrap_or_else(|e| panic!("symlink lib -> usr/lib: {e}"));
}

/// Classify one filesystem entry for the inventory: `(type, detail)`. `detail`
/// is the raw (unresolved) symlink target for a symlink, empty otherwise.
#[must_use]
pub fn classify_entry(path: &Path) -> (char, String) {
    let meta = fs::symlink_metadata(path)
        .unwrap_or_else(|e| panic!("symlink_metadata {}: {e}", path.display()));
    let ft = meta.file_type();
    if ft.is_symlink() {
        let target =
            fs::read_link(path).unwrap_or_else(|e| panic!("read_link {}: {e}", path.display()));
        ('l', target.to_string_lossy().into_owned())
    } else if ft.is_dir() {
        ('d', String::new())
    } else if ft.is_fifo() {
        ('p', String::new())
    } else {
        ('f', String::new())
    }
}

/// Recompute the canonical tree inventory by GLOBBING the materialized root -
/// never by replaying the plan - so a materializer bug that creates an extra
/// or wrongly-typed entry is caught. Scope: the four standard search
/// directories (as a `d` entry plus their non-recursive contents), the
/// `lib -> usr/lib` alias, and `etc/sysctl.conf` if present. See this
/// module's doc "Scope of the equivalence guard".
#[must_use]
pub fn compute_inventory(root: &Path) -> Vec<InvEntry> {
    let mut out = Vec::new();
    for d in STANDARD_DIRS {
        out.push(InvEntry {
            ty: 'd',
            relpath: (*d).to_string(),
            detail: String::new(),
        });
        let dirpath = root.join(d);
        // `.flatten()` would silently DROP a per-entry read_dir error instead
        // of naming it - not a false pass (a dropped entry shortens the
        // inventory, so the vendored assert_eq! still fires), but it fails as
        // a confusing "materializers have diverged" instead of the real
        // "read_dir entry failed: EACCES".
        let mut names: Vec<_> = fs::read_dir(&dirpath)
            .unwrap_or_else(|e| panic!("read_dir {}: {e}", dirpath.display()))
            .map(|entry| {
                entry
                    .unwrap_or_else(|e| panic!("read_dir entry under {}: {e}", dirpath.display()))
                    .file_name()
            })
            .collect();
        names.sort();
        for name in names {
            let full = dirpath.join(&name);
            let (ty, detail) = classify_entry(&full);
            let relpath = format!("{d}/{}", name.to_string_lossy());
            out.push(InvEntry {
                ty,
                relpath,
                detail,
            });
        }
    }
    let lib = root.join("lib");
    let (ty, detail) = classify_entry(&lib);
    out.push(InvEntry {
        ty,
        relpath: "lib".to_string(),
        detail,
    });
    let etc_conf = root.join("etc/sysctl.conf");
    if etc_conf.symlink_metadata().is_ok() {
        let (ty, detail) = classify_entry(&etc_conf);
        out.push(InvEntry {
            ty,
            relpath: "etc/sysctl.conf".to_string(),
            detail,
        });
    }
    out.sort();
    out
}

// ---------------------------------------------------------------------------
// Oracle transcript parsing (the "recorded oracle verdict")
// ---------------------------------------------------------------------------

/// Slice out the `SYSTEMD_LOG_LEVEL=debug` apply-mode section of a captured
/// transcript (between the `=== APPLY-DEBUG ===` and the next `=== ` marker
/// AT THE START OF A LINE, or end of string). Panics if the marker is absent.
/// This is fail-closed parsing (CONTRIBUTING rule 3): a transcript missing
/// this section cannot yield a verdict at all, which must not be silently
/// read as "unset".
#[must_use]
pub fn apply_debug_section(transcript: &str) -> &str {
    let start_marker = "=== APPLY-DEBUG ===";
    let start = transcript
        .find(start_marker)
        .unwrap_or_else(|| panic!("transcript has no '{start_marker}' section"))
        + start_marker.len();
    let rest = &transcript[start..];
    // Anchored to a line start ("\n=== ", not bare "=== "): an unanchored
    // search would truncate the section early if any real daemon log line
    // happened to contain "=== " mid-line. The failure direction matters -
    // a truncated section reads as "key never set" (None), which is a
    // LEGITIMATE expected value for some scenarios (e.g.
    // slot-symlink-absent-divergence), so a silent truncation would not even
    // look wrong on its own. Defence in depth: that scenario also pins
    // RuleSteward's own value independently in
    // tests/sysctld_corpus_oracle.rs, but this is the right fix regardless.
    let end = rest.find("\n=== ").unwrap_or(rest.len());
    &rest[..end]
}

/// Convert a dotted sysctl key to its `/proc/sys` path form. A TRIVIAL
/// dot-to-slash replace, valid for every key this corpus's scenarios actually
/// track (none embed a literal dot inside an interface name, e.g. `eth0.200`).
/// It is NOT a port of `canonical_key`'s asymmetric first-separator rule
/// (that function is `pub(crate)` in [`crate::parser`] and is exercised
/// directly by that crate's own unit tests). The one scenario that DOES probe
/// the asymmetric rule (`key-grammar-asymmetric-separator`) compares the raw
/// transcript text directly instead of going through this helper.
#[must_use]
pub fn dotted_to_procpath(key: &str) -> String {
    // The name promises a general conversion; the body is a trivial replace.
    // sysctl's real separator rule is genuinely asymmetric (`parser.rs`'s
    // `canonical_key` implements it), so a key that already contains a `/`
    // is exactly the shape this function is NOT equipped to handle correctly
    // - turn that comment into something a test run can actually fail.
    debug_assert!(
        !key.contains('/'),
        "dotted_to_procpath: {key:?} already contains '/' - this is a TRIVIAL dot-to-slash \
         replace, not canonical_key's asymmetric first-separator rule; a key with a literal \
         '/' needs that real canonicalization instead"
    );
    key.replace('.', "/")
}

/// Find the real oracle's effective value for `proc_path` in the apply-debug
/// section: the value of the LAST `Setting '<proc_path>' to '<value>'` line
/// (tolerating the optional `/proc/sys/` prefix - el8's systemd 239 omits it,
/// el9/el10 include it; confirmed empirically 2026-07-25). `None` means the
/// real oracle never set this key at all (UNSET).
#[must_use]
pub fn oracle_setting_value(apply_section: &str, proc_path: &str) -> Option<String> {
    let mut found = None;
    for line in apply_section.lines() {
        let Some(after_marker) = line
            .find("Setting '")
            .map(|i| &line[i + "Setting '".len()..])
        else {
            continue;
        };
        let after_prefix = after_marker
            .strip_prefix("/proc/sys/")
            .unwrap_or(after_marker);
        let Some(after_key) = after_prefix.strip_prefix(proc_path) else {
            continue;
        };
        let Some(after_to) = after_key.strip_prefix("' to '") else {
            continue;
        };
        let Some(end) = after_to.find('\'') else {
            continue;
        };
        found = Some(after_to[..end].to_string());
    }
    found
}

/// Whether the apply-debug section contains an `Overwriting earlier
/// assignment of <proc_path>` line - the real oracle's own signal that two
/// entries were considered the SAME canonical key.
#[must_use]
pub fn oracle_overwrote(apply_section: &str, proc_path: &str) -> bool {
    apply_section.contains(&format!("Overwriting earlier assignment of {proc_path} "))
}

/// Whether the transcript's apply-debug section shows a REJECT signal: a
/// parse-level or file-level failure the daemon explicitly logs, distinct
/// from a `/proc/sys` write failure (which is expected and harmless under the
/// read-only sandbox - see CLAUDE.md "Apply mode WRITES"). Used by the
/// corpus-wide two-sided positive control.
#[must_use]
pub fn oracle_shows_reject_signal(apply_section: &str) -> bool {
    apply_section.contains("Line is not an assignment") || apply_section.contains("Is a directory")
}

/// Whether the transcript's apply-debug section shows an ACCEPT signal: at
/// least one `Setting '` line (a value the real oracle resolved and attempted
/// to apply, regardless of whether the write itself then failed against the
/// read-only /proc/sys sandbox).
#[must_use]
pub fn oracle_shows_accept_signal(apply_section: &str) -> bool {
    apply_section.contains("Setting '")
}
