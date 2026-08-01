//! Data-driven `sysctld` differential-oracle corpus (session 9k-1 Lane B, #499).
//!
//! Tier-1 replay half of the sysctld differential (see CONTRIBUTING.md
//! "Differential oracle contract"). Reads the committed corpus of
//! `(tree.plan, recorded systemd-sysctl transcript)` pairs under
//! `tests/corpus/sysctld-oracle/`, materializes each scenario's tree onto a
//! fresh `tempdir()`, runs [`rulesteward_sysctld::system::lint_system`] over
//! it, and asserts `RuleSteward`'s computed effective value for the scenario's
//! tracked key agrees with the value the REAL `systemd-sysctl` daemon computed
//! (extracted verbatim from the recorded transcript's `SYSTEMD_LOG_LEVEL=debug`
//! apply-mode output). No hand-authored "expected value" appears anywhere in
//! this file or in `scenario.meta` - both sides derive their answer from their
//! own primary source (`RuleSteward`'s own diagnostic text vs. the real daemon's
//! own debug log), which is the whole point of a differential.
//!
//! # Where the model logic lives
//!
//! The tree-materializer, the inventory recomputation and the transcript
//! classifier live in [`rulesteward_sysctld::oracle`], not in this file: that
//! module doc covers the materializer equivalence guard (two independent
//! materializers - this file's `tempdir()` replay and `materialize.sh`, run
//! inside the `rs-oracleN` container - that must agree bit-for-bit on the
//! resulting tree shape) and its scope in full. This file keeps only the
//! corpus-enumeration glue ([`ScenarioMeta`], [`scenarios`], [`corpus_root`]),
//! [`rulesteward_verdict`] (reading `RuleSteward`'s own answer out of its
//! `sysctld-W02`/`W04` diagnostic text, which is specific to this test's
//! comparison and not part of the reusable oracle adapter), and the
//! data-driven test itself.
//!
//! # Why `rulesteward_verdict` stays in this file, not the oracle adapter
//!
//! Defensible to extract too in principle, but [`rulesteward_verdict`] is
//! called by 19 of this corpus's 22 scenarios: only
//! `key-grammar-malformed-line-reject` (`key: NONE`, comparing the REJECT
//! signal instead of a merged value), `key-grammar-asymmetric-separator`
//! (comparing the raw transcript's canonical-key handling directly, since its
//! key is not necessarily STIG/CIS tracked in dotted-slash form for an
//! interface name), and `slot-symlink-misdirected-593` (post-fix the key's
//! value is compliant under both baselines, so no `sysctld-W02`/`W04`
//! diagnostic ever names it, and `rulesteward_verdict` would panic before
//! reaching a value to extract - the honest observation is the ABSENCE of a
//! finding, asserted directly against `diags`) skip it. `key-grammar-dash-prefix-identity`
//! and `slot-symlink-absent-divergence` both call it despite ALSO comparing a
//! transcript signal directly, precisely so `RuleSteward`'s own value is pinned
//! alongside the oracle's rather than the oracle side being checked alone.
//! Keeping it here (rather than moving it beside `oracle_setting_value` in
//! [`rulesteward_sysctld::oracle`]) is still the right call: it reads
//! DIAGNOSTIC MESSAGE TEXT (`sysctld-W02`/`W04`), which is specific to what
//! THIS test compares, not a reusable adapter capability - and it is still
//! exercised by `just ci`'s ordinary `cargo test`, just not by `cargo
//! mutants`'s `src/`-scoped glob.
//!
//! # XFAIL policy
//!
//! [`XFAIL`] is currently EMPTY. Its sole entry, `slot-symlink-misdirected-593`
//! (issue #593), is FIXED (`RuleSteward` session 9m lane 2): `enumerate()` now
//! gates the 99-slot content-skip on `slot_symlink_ok`, so a symlink at the
//! `99-sysctl.conf` slot that resolves to anything OTHER than
//! `/etc/sysctl.conf` is followed and parsed like any ordinary drop-in instead
//! of being silently dropped. The scenario keeps its own special-case arm
//! below (see that arm for why it cannot use the generic `rulesteward_verdict`
//! comparison): its post-fix value is compliant on both baselines, so the
//! honest post-fix observation is the ABSENCE of a `sysctld-W02`/`W04` finding.
//! The oracle's own `Some("2")` is pinned alongside it too, but that pin only
//! guards against CORPUS corruption (a flipped or emptied `=== APPLY-DEBUG ===`
//! transcript section) - it reads the recorded transcript and never touches
//! `lint_system`, so it cannot detect a broken product. The arm's separate
//! `sources` assertion (the misdirected symlink was actually READ) is what
//! closes the product-side vacuity gap: a `lint_system` stub returning nothing
//! would otherwise satisfy the absence assertion outright.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

use rulesteward_core::Diagnostic;
use rulesteward_core::oracle_corpus::{resolve_corpus_root, sentinel_banner, sentinel_count};
use rulesteward_sysctld::TargetVersion;
use rulesteward_sysctld::oracle::{
    apply_debug_section, compute_inventory, dotted_to_procpath, materialize, oracle_overwrote,
    oracle_setting_value, oracle_shows_accept_signal, oracle_shows_reject_signal, parse_plan_line,
    parse_tree_plan,
};
use rulesteward_sysctld::system::lint_system;

/// Sentinel every run must print before asserting anything (frozen Phase-0
/// identifier - `scripts/rs-oracle-diff.sh` greps for it verbatim).
const SENTINEL: &str = "RS-DIFF-SYSCTLD";

/// Floor on the number of enumerated scenario directories. Raise this
/// deliberately, in the same commit that grows the corpus. Currently every
/// scenario in every one of the five categories described in the session task
/// (6 precedence, 5 slot-symlink, 4 key-grammar, 3 baseline-vendor-inventory,
/// 4 degenerate) - see each scenario's own `scenario.meta` `comment:` field for
/// its grounding.
const SCENARIO_FLOOR: usize = 22;

/// Scenarios whose current behavior is a KNOWN, already-verified divergence
/// from the real oracle. `(scenario_id, issue_number)`. Landing an entry here
/// documents a bug without letting the test-author silently fix the
/// implementation (impl-blind barrier) or silently accept the wrong answer as
/// if it were correct.
const XFAIL: &[(&str, u32)] = &[];

// ---------------------------------------------------------------------------
// scenario.meta: a flat `key: value` line format, hand-parsed.
//
// No serde_json dependency: rulesteward-sysctld does not otherwise depend on
// it, and per the session task's own claims discipline a new Cargo.toml +
// Cargo.lock edit is contended surface shared with the other two 9k-1 lanes.
// tree.plan alone (this file's TSV format) already carries everything BOTH
// sides need to parse, so scenario.meta only needs a handful of flat scalar
// fields - a two-line grep+trim reader is the right tool for that shape, not
// a general-purpose parser. See PROVENANCE.md "Why no serde_json".
// ---------------------------------------------------------------------------

struct ScenarioMeta {
    id: String,
    /// One or more oracle images this scenario was captured against, e.g.
    /// `["rs-oracle9"]`. Parallel to `targets` by position.
    images: Vec<String>,
    /// One or more `RuleSteward` target versions to lint against, parallel to
    /// `images` by position.
    targets: Vec<TargetVersion>,
    /// The dotted sysctl key this scenario tracks, or `None` for a scenario
    /// (`key-grammar-malformed-line-reject`) that compares the REJECT signal
    /// rather than a merged value.
    key: Option<String>,
}

/// Read one `key: value` field. Trims surrounding whitespace on the value.
/// Panics if the field is absent - a missing required field is a corpus
/// authoring defect, not a soft `None` (fail-closed: CONTRIBUTING rule 3).
fn meta_field(text: &str, key: &str) -> String {
    let prefix = format!("{key}:");
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix(&prefix) {
            return rest.trim().to_string();
        }
    }
    panic!("scenario.meta missing required field '{key}:'");
}

fn parse_target(s: &str) -> TargetVersion {
    match s {
        "rhel8" => TargetVersion::Rhel8,
        "rhel9" => TargetVersion::Rhel9,
        "rhel10" => TargetVersion::Rhel10,
        other => panic!("scenario.meta: unknown target '{other}' (expected rhel8/rhel9/rhel10)"),
    }
}

impl ScenarioMeta {
    fn load(dir: &Path) -> ScenarioMeta {
        let path = dir.join("scenario.meta");
        let text =
            fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let id = meta_field(&text, "id");
        let images: Vec<String> = meta_field(&text, "images")
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        let targets: Vec<TargetVersion> = meta_field(&text, "targets")
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(parse_target)
            .collect();
        assert!(
            !images.is_empty(),
            "{id}: scenario.meta 'images:' must name at least one oracle image"
        );
        assert_eq!(
            images.len(),
            targets.len(),
            "{id}: scenario.meta 'images:' and 'targets:' must be parallel (same length): {images:?} vs {targets:?}"
        );
        let key_raw = meta_field(&text, "key");
        let key = if key_raw == "NONE" {
            None
        } else {
            Some(key_raw)
        };
        ScenarioMeta {
            id,
            images,
            targets,
            key,
        }
    }
}

// ---------------------------------------------------------------------------
// Enumeration
// ---------------------------------------------------------------------------

fn corpus_root() -> PathBuf {
    let (root, mode) = resolve_corpus_root(
        "RS_ORACLE_CORPUS_SYSCTLD",
        Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/corpus/sysctld-oracle"
        )),
    );
    eprintln!("{}", sentinel_banner(SENTINEL, mode, &root));
    root
}

/// Enumerate every scenario directory (anything with a `scenario.meta`,
/// skipping `_`-prefixed directories and the two shared shell scripts, which
/// are plain files and so already excluded by `is_dir()`). Sorted by id for
/// deterministic output.
fn scenarios(root: &Path) -> Vec<(PathBuf, ScenarioMeta)> {
    let mut out = Vec::new();
    let entries =
        fs::read_dir(root).unwrap_or_else(|e| panic!("read corpus dir {}: {e}", root.display()));
    for entry in entries.flatten() {
        let dir = entry.path();
        if !dir.is_dir() {
            continue;
        }
        let name = dir
            .file_name()
            .and_then(OsStr::to_str)
            .unwrap_or_default()
            .to_string();
        if name.starts_with('_') {
            continue;
        }
        if !dir.join("scenario.meta").is_file() {
            continue;
        }
        out.push((dir.clone(), ScenarioMeta::load(&dir)));
    }
    out.sort_by(|a, b| a.1.id.cmp(&b.1.id));
    out
}

// ---------------------------------------------------------------------------
// RuleSteward's own verdict, read out of the sysctld-W02/W04 diagnostic text.
// ---------------------------------------------------------------------------

/// Find `RuleSteward`'s own effective-value verdict for `key` among `diags`:
/// `Some(value)` from a `sysctld-W02`/`sysctld-W04` "insecure"/"outside the
/// benchmark-accepted set" message (extracting the backtick-quoted value
/// verbatim), or `None` from a "is unset" message. Panics if `key` is tracked
/// by neither W02 nor W04 at all (every scenario picks a value that is
/// non-compliant for its target, so a diagnostic must always fire - a
/// scenario whose key is untracked by the shipped baselines is a corpus
/// authoring defect, not a silent pass).
fn rulesteward_verdict(diags: &[Diagnostic], key: &str) -> Option<String> {
    let quoted = format!("`{key}`");
    for d in diags {
        if d.code != "sysctld-W02" && d.code != "sysctld-W04" {
            continue;
        }
        if !d.message.contains(&quoted) {
            continue;
        }
        if d.message.contains(&format!("{quoted} is unset")) {
            return None;
        }
        let marker = format!("{quoted} = `");
        if let Some(pos) = d.message.find(&marker) {
            let rest = &d.message[pos + marker.len()..];
            if let Some(end) = rest.find('`') {
                return Some(rest[..end].to_string());
            }
        }
    }
    panic!(
        "no sysctld-W02/W04 diagnostic named key {key:?} at all (neither insecure nor unset) - \
         either the scenario's chosen value is actually compliant, or the key is not tracked by \
         the shipped baseline for this target; diagnostics seen: {:#?}",
        diags
            .iter()
            .map(|d| (d.code.as_ref(), d.message.as_str()))
            .collect::<Vec<_>>()
    );
}

// ---------------------------------------------------------------------------
// The main data-driven test
// ---------------------------------------------------------------------------

#[test]
#[allow(clippy::too_many_lines)] // data-driven harness; per-scenario arms inline
fn sysctld_corpus_oracle_matches_the_recorded_verdicts() {
    let root = corpus_root();
    let scenarios = scenarios(&root);

    eprintln!("{}", sentinel_count(SENTINEL, scenarios.len()));
    assert!(
        scenarios.len() >= SCENARIO_FLOOR,
        "expected >= {SCENARIO_FLOOR} enumerated scenarios, found {}",
        scenarios.len()
    );

    let mut xfail_hit: Vec<String> = Vec::new();
    let mut saw_accept = false;
    let mut saw_reject = false;
    let mut version_banners: BTreeMap<String, String> = BTreeMap::new();

    for (dir, meta) in &scenarios {
        let plan_text = fs::read_to_string(dir.join("tree.plan"))
            .unwrap_or_else(|e| panic!("{}: read tree.plan: {e}", meta.id));
        let (materialize_entries, vendored_inventory) = parse_tree_plan(&plan_text);

        for (image, target) in meta.images.iter().zip(meta.targets.iter()) {
            let tmp = tempfile::tempdir().unwrap_or_else(|e| panic!("{}: tempdir: {e}", meta.id));
            let content_dir = dir.join("content");
            materialize(tmp.path(), &content_dir, &materialize_entries);

            // The materializer equivalence guard: recompute the inventory via
            // globs (never by replaying the plan) and compare to the vendored
            // block. A divergence here is a materializer bug, not oracle
            // drift, and needs no docker to see.
            let recomputed = compute_inventory(tmp.path());
            let mut vendored_sorted = vendored_inventory.clone();
            vendored_sorted.sort();
            assert_eq!(
                recomputed, vendored_sorted,
                "{}: materialized filesystem inventory does not match the vendored ## tree \
                 block in tree.plan - the Rust replay materializer and materialize.sh have \
                 diverged",
                meta.id
            );

            let oracle_file = dir.join(format!("oracle-{image}.txt"));
            let transcript = fs::read_to_string(&oracle_file)
                .unwrap_or_else(|e| panic!("{}: read {}: {e}", meta.id, oracle_file.display()));
            let apply_section = apply_debug_section(&transcript);

            // Per-version control (below): read the banner ONLY from the
            // scenario the control names, keyed by SCENARIO id, not by image.
            // Keying by image previously let the LAST scenario alphabetically
            // to use a given image silently win that image's entry - every
            // scenario sharing an image happens to capture the identical real
            // banner, so the bug was invisible until a reviewer corrupted the
            // baseline scenarios' OWN transcripts specifically and the control
            // still passed (it was never reading those transcripts at all).
            if meta.id.starts_with("baseline-vendor-inventory-")
                && let Some(idx) = transcript.find("=== VERSION ===")
            {
                let banner = transcript[idx + "=== VERSION ===".len()..]
                    .lines()
                    .find(|l| !l.trim().is_empty())
                    .unwrap_or("")
                    .trim()
                    .to_string();
                version_banners.insert(meta.id.clone(), banner);
            }

            if oracle_shows_accept_signal(apply_section) {
                saw_accept = true;
            }
            if oracle_shows_reject_signal(apply_section) {
                saw_reject = true;
            }

            let Some(key) = &meta.key else {
                // key-grammar-malformed-line-reject: the point IS the reject
                // signal, not a merged value. Assert it directly here too, so
                // this scenario fails loudly on its own if the reject signal
                // ever disappears (not just via the corpus-wide control).
                assert!(
                    oracle_shows_reject_signal(apply_section),
                    "{}: scenario has no tracked key (key: NONE) and must demonstrate the \
                     reject signal itself",
                    meta.id
                );
                continue;
            };

            // The two key-grammar identity scenarios compare the raw
            // transcript's canonical-key handling directly rather than a
            // W02/W04 message (their key is not necessarily STIG/CIS
            // tracked in dotted-slash form for an interface name).
            if meta.id == "key-grammar-asymmetric-separator" {
                let proc_path = "net/ipv4/conf/lo/forwarding";
                assert!(
                    oracle_overwrote(apply_section, proc_path),
                    "{}: expected the real oracle to treat the dot-first and slash-first \
                     forms as the SAME canonical key (an 'Overwriting earlier assignment of \
                     {proc_path}' line)",
                    meta.id
                );
                let oracle_value = oracle_setting_value(apply_section, proc_path);
                assert_eq!(
                    oracle_value.as_deref(),
                    Some("0"),
                    "{}: expected the real oracle's winning value to be 0 (the later, \
                     slash-first assignment)",
                    meta.id
                );
                continue;
            }
            if meta.id == "key-grammar-dash-prefix-identity" {
                let proc_path = "kernel/randomize_va_space";
                assert!(
                    oracle_overwrote(apply_section, proc_path),
                    "{}: expected the dash-prefixed and plain forms of the same key to be \
                     recognized as the SAME canonical key by the real oracle",
                    meta.id
                );
                let oracle_value = oracle_setting_value(apply_section, proc_path);
                assert_eq!(
                    oracle_value.as_deref(),
                    Some("0"),
                    "{}: expected the real oracle's winning value to be 0 (the later, \
                     plain-form assignment)",
                    meta.id
                );
                // Pin RuleSteward's OWN value too, not just the oracle's: a corruption
                // sweep found this scenario's recorded value was otherwise unchecked
                // (flipping the transcript's `to '0'` to any other digit left the suite
                // green), which the `oracle_overwrote` identity check alone cannot see
                // since it only tests for the presence of the "Overwriting" line.
                let (diags, _sources) = lint_system(Some(tmp.path()), Some(*target));
                let rs_value = rulesteward_verdict(&diags, key);
                assert_eq!(
                    rs_value, oracle_value,
                    "{}: RuleSteward's effective value for `{key}` ({rs_value:?}) disagrees \
                     with the real oracle's ({oracle_value:?})",
                    meta.id
                );
                continue;
            }

            let proc_path = dotted_to_procpath(key);
            let oracle_value = oracle_setting_value(apply_section, &proc_path);

            // slot-symlink-absent-divergence: no 99-sysctl.conf slot exists, so
            // the real systemd-sysctl oracle never reads /etc/sysctl.conf at all
            // (confirmed above: no 'Parsing /etc/sysctl.conf' line). This is the
            // scenario's whole point (see its scenario.meta comment: "so procps
            // ... and systemd DIVERGE (W03-b)"), not a bug in either side: RuleSteward's
            // own sysctld-W02/W04 baseline pass deliberately reasons over the
            // PROCPS-merged view (system.rs's `merged`, which always appends
            // `/etc/sysctl.conf` dead-last per `sysctl --system`'s real behavior,
            // regardless of the 99-sysctl.conf slot), so `rulesteward_verdict`
            // would report RuleSteward's procps-view answer here - an
            // apples-to-oranges comparison against this test's systemd oracle for
            // exactly the scenario designed to exercise that divergence. Compare
            // the oracle's own transcript signal directly instead, matching the
            // key-grammar special cases above.
            if meta.id == "slot-symlink-absent-divergence" {
                assert_eq!(
                    oracle_value, None,
                    "{}: expected the real systemd-sysctl oracle to leave `{key}` unset \
                     (no 99-sysctl.conf slot, so systemd never reads /etc/sysctl.conf)",
                    meta.id
                );
                // Pin RuleSteward's own PROCPS-view value too, not just the oracle's
                // side: an assertion naming only `oracle_value` is satisfiable
                // VACUOUSLY by anything that makes the oracle read as unset,
                // including a corrupted/race-emptied apply-debug section. Computing
                // and pinning `rs_value` independently (it never reads the
                // transcript at all - it comes from `lint_system` over the
                // materialized filesystem) makes this a genuine two-sided pin of the
                // documented procps/systemd divergence, not a one-sided guess.
                let (diags, _sources) = lint_system(Some(tmp.path()), Some(*target));
                let rs_value = rulesteward_verdict(&diags, key);
                assert_eq!(
                    rs_value.as_deref(),
                    Some("0"),
                    "{}: expected RuleSteward's own PROCPS-view answer to be Some(\"0\") - if \
                     this changed, either the scenario's content changed or system.rs's merged \
                     view no longer includes /etc/sysctl.conf unconditionally; re-ground this \
                     scenario's pin rather than silently adjusting it",
                    meta.id
                );
                assert_ne!(
                    rs_value, oracle_value,
                    "{}: RuleSteward's own PROCPS-view answer ({rs_value:?}) now matches the \
                     real systemd oracle's ({oracle_value:?}) - the documented procps/systemd \
                     applier divergence (sysctld-W03-b's whole reason for existing) that this \
                     scenario exists to pin has disappeared. That is a real regression (or a \
                     deliberate model change this test must be updated to reflect), not \
                     something to skip past",
                    meta.id
                );
                continue;
            }

            // slot-symlink-misdirected-593 (#593, FIXED in RuleSteward session 9m
            // lane 2): the 99-slot symlink targets a real file OTHER than
            // ../sysctl.conf (etc/rs9k1-hidden.conf, outside the sysctl.d search
            // dirs so it is never independently enumerated). The real oracle
            // never special-cases the 99-sysctl.conf filename: it just follows the
            // symlink and parses it like any other drop-in, landing on a value (2)
            // that is COMPLIANT under both the STIG (baseline.rs VALUE_2,
            // RHEL-09-213070) and CIS (cis.rs 1.5.1 VALUE_2) baselines for this
            // key. So post-fix RuleSteward emits NO sysctld-W02/W04 for it at all
            // - `rulesteward_verdict` would PANIC (its fail-closed guard fires
            // when no such diagnostic names the key) before ever reaching a value
            // to compare. The honest acceptance criterion for a FALSE-POSITIVE fix
            // is the ABSENCE of a finding, so assert that directly instead of
            // routing through `rulesteward_verdict`.
            //
            // Two SEPARATE assertions guard two SEPARATE vacuity classes (an
            // earlier version of this comment wrongly conflated them - corrected
            // in rework): the oracle-side `Some("2")` pin below guards against
            // CORPUS corruption (a flipped or emptied `=== APPLY-DEBUG ===`
            // transcript section) - it reads only the recorded transcript and
            // never touches `lint_system`, so it CANNOT detect a broken product.
            // The `sources` assertion further down is what guards the PRODUCT
            // side: it fails a `lint_system` stub returning
            // `(vec![], BTreeMap::new())`, which would otherwise satisfy "no
            // W02/W04 names the key" vacuously by reading nothing at all.
            if meta.id == "slot-symlink-misdirected-593" {
                assert_eq!(
                    oracle_value.as_deref(),
                    Some("2"),
                    "{}: expected the real oracle's value to remain 2 (it follows the \
                     misdirected symlink to a compliant value) - if this changed, \
                     re-ground this scenario's pin rather than widening it",
                    meta.id
                );

                let (diags, sources) = lint_system(Some(tmp.path()), Some(*target));
                assert!(
                    sources
                        .keys()
                        .any(|k| k.ends_with("etc/sysctl.d/99-sysctl.conf")),
                    "{}: the misdirected 99-slot symlink must actually be READ (staged \
                     as a source) - a stub or a still-buggy enumerate() that skips it \
                     entirely would otherwise satisfy the absence assertion below \
                     vacuously",
                    meta.id
                );
                let quoted_key = format!("`{key}`");
                assert!(
                    !diags.iter().any(|d| {
                        (d.code == "sysctld-W02" || d.code == "sysctld-W04")
                            && d.message.contains(&quoted_key)
                    }),
                    "{}: expected no sysctld-W02/W04 finding for {quoted_key} once the \
                     misdirected symlink is followed and its compliant value applies; \
                     got: {diags:?}",
                    meta.id
                );
                continue;
            }

            let (diags, _sources) = lint_system(Some(tmp.path()), Some(*target));
            let rs_value = rulesteward_verdict(&diags, key);

            if let Some((_, issue)) = XFAIL.iter().find(|(id, _)| *id == meta.id) {
                assert_ne!(
                    rs_value, oracle_value,
                    "{}: XFAIL #{issue} was expected to still diverge (RuleSteward={rs_value:?}, \
                     oracle={oracle_value:?}) - if this now matches, the bug is fixed: remove \
                     this scenario from XFAIL, not the assertion",
                    meta.id
                );
                xfail_hit.push(meta.id.clone());
            } else {
                assert_eq!(
                    rs_value, oracle_value,
                    "{}: RuleSteward's effective value for `{key}` ({rs_value:?}) disagrees \
                     with the real oracle's ({oracle_value:?}) on {image}/{target:?}",
                    meta.id
                );
            }
        }
    }

    // The two-sided positive control (CONTRIBUTING rule 2): the corpus must
    // hold at least one input the real oracle ACCEPTS and one it REJECTS. If
    // both come back with the same verdict the *oracle* is broken, not the
    // product - and that must never be reported as either clean or drift.
    if !saw_accept || !saw_reject {
        eprintln!(
            "{SENTINEL}: ORACLE-BROKEN corpus-wide positive control failed \
             (saw_accept={saw_accept}, saw_reject={saw_reject})"
        );
        panic!(
            "positive control failed: the corpus must contain at least one oracle ACCEPT \
             transcript (a 'Setting \\'' line) and one REJECT transcript (a parse/file-level \
             rejection) - saw_accept={saw_accept}, saw_reject={saw_reject}"
        );
    }

    // Per-version control: the three baseline-vendor-inventory scenarios'
    // captured `--version` banners must be PAIRWISE DISTINCT, guarding against
    // "all three transcripts are secretly the same file" (CONTRIBUTING: "add a
    // control pinning a known version divergence"). Keyed by scenario id (not
    // image), and read only from those three scenarios' own transcripts above -
    // see that collection site for why keying by image was wrong.
    let banners: Vec<(&String, &String)> = version_banners.iter().collect();
    // Fewer than 3 banners means the per-version divergence control below
    // cannot even run (a missing or malformed baseline-vendor-inventory-
    // el{8,9,10} scenario), which is the SAME "the positive control cannot do
    // its job" failure class as the pairwise-identical check further down,
    // not ordinary product drift - so it gets the same {SENTINEL}: ORACLE-
    // BROKEN treatment rather than being left to fail as an unmarked assert
    // that scripts/rs-oracle-diff.sh's grep would misclassify as rc 1 DRIFT.
    if banners.len() < 3 {
        eprintln!(
            "{SENTINEL}: ORACLE-BROKEN found only {} captured --version banner(s) for the \
             baseline-vendor-inventory-el{{8,9,10}} scenarios (expected >= 3); the per-version \
             divergence control cannot run without all three",
            banners.len()
        );
    }
    assert!(
        banners.len() >= 3,
        "expected >= 3 captured --version banners (one per baseline-vendor-inventory-el{{8,9,10}} \
         scenario), got {}: {:?}",
        banners.len(),
        banners
    );
    for i in 0..banners.len() {
        for j in (i + 1)..banners.len() {
            assert_ne!(
                banners[i].1, banners[j].1,
                "{SENTINEL}: ORACLE-BROKEN {} and {} captured IDENTICAL --version banners - the \
                 three rs-oracle images are secretly the same file",
                banners[i].0, banners[j].0
            );
        }
    }

    assert_eq!(
        xfail_hit.len(),
        XFAIL.len(),
        "every XFAIL scenario must have been enumerated and hit exactly once: expected {:?}, hit {xfail_hit:?}",
        XFAIL.iter().map(|(id, _)| *id).collect::<Vec<_>>()
    );
    if !xfail_hit.is_empty() {
        eprintln!("XFAILed (documented divergences, not fixed by this test): {xfail_hit:?}");
    }
}

// ---------------------------------------------------------------------------
// Unit tests pinning the extraction logic itself against synthetic input, so
// the mutation gate has something to bite on beyond the corpus's own values
// (adversarial test-first: a test is only worth writing if a wrong
// implementation fails it). The functions under test now live in
// `rulesteward_sysctld::oracle`; `rulesteward_verdict` stays local to this
// file (imported via `super::` below), since it is specific to this test's
// own W02/W04 diagnostic-text comparison rather than the reusable adapter.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod extraction_unit_tests {
    use super::{
        apply_debug_section, dotted_to_procpath, oracle_overwrote, oracle_setting_value,
        oracle_shows_accept_signal, oracle_shows_reject_signal, parse_plan_line, parse_tree_plan,
        rulesteward_verdict,
    };
    use rulesteward_core::{Diagnostic, Severity};

    #[test]
    fn dotted_to_procpath_replaces_every_dot() {
        assert_eq!(
            dotted_to_procpath("kernel.randomize_va_space"),
            "kernel/randomize_va_space"
        );
        assert_eq!(dotted_to_procpath("fs.suid_dumpable"), "fs/suid_dumpable");
    }

    #[test]
    fn oracle_setting_value_tolerates_the_el8_missing_prefix() {
        // el9/el10 include the /proc/sys/ prefix; el8's systemd 239 omits it
        // (measured 2026-07-25). Both must extract the same value.
        let with_prefix = "Setting '/proc/sys/kernel/randomize_va_space' to '0'\n";
        let without_prefix = "Setting 'kernel/randomize_va_space' to '0'\n";
        assert_eq!(
            oracle_setting_value(with_prefix, "kernel/randomize_va_space"),
            Some("0".to_string())
        );
        assert_eq!(
            oracle_setting_value(without_prefix, "kernel/randomize_va_space"),
            Some("0".to_string())
        );
    }

    #[test]
    fn oracle_setting_value_is_none_when_key_never_applied() {
        let transcript = "Parsing /etc/sysctl.d/10-a.conf\n";
        assert_eq!(
            oracle_setting_value(transcript, "kernel/randomize_va_space"),
            None
        );
    }

    #[test]
    fn oracle_setting_value_does_not_confuse_a_prefix_key_with_the_target() {
        // A DIFFERENT key that happens to share a prefix
        // (kernel/randomize_va_space_extra) must not satisfy a strip_prefix
        // lookup for kernel/randomize_va_space - the trailing "' to '" anchor
        // is what prevents this false match.
        let transcript = "Setting '/proc/sys/kernel/randomize_va_space_extra' to '9'\n";
        assert_eq!(
            oracle_setting_value(transcript, "kernel/randomize_va_space"),
            None,
            "a longer key sharing this key's prefix must not be mistaken for it"
        );
    }

    #[test]
    fn oracle_overwrote_detects_the_real_marker() {
        let transcript =
            "Overwriting earlier assignment of kernel/randomize_va_space at 'x.conf:1'.\n";
        assert!(oracle_overwrote(transcript, "kernel/randomize_va_space"));
        assert!(!oracle_overwrote(transcript, "fs/suid_dumpable"));
    }

    #[test]
    fn oracle_overwrote_does_not_confuse_a_prefix_key_with_the_target() {
        // A DIFFERENT key that happens to share a prefix
        // (kernel/randomize_va_space_extra) must not satisfy a search for
        // kernel/randomize_va_space - the trailing space baked into
        // `oracle_overwrote`'s own format string ("...assignment of {proc_path} ")
        // is the anchor that prevents this false match, mirroring
        // `oracle_setting_value_does_not_confuse_a_prefix_key_with_the_target`.
        let transcript =
            "Overwriting earlier assignment of kernel/randomize_va_space_extra at 'x.conf:1'.\n";
        assert!(
            !oracle_overwrote(transcript, "kernel/randomize_va_space"),
            "a longer key sharing this key's prefix must not be mistaken for it"
        );
    }

    #[test]
    fn apply_debug_section_stops_at_the_next_marker() {
        let transcript = "=== CAT-CONFIG ===\nignored\n=== APPLY-DEBUG ===\nSetting 'x' to 'y'\n=== VERSION ===\nsystemd 252\n";
        let section = apply_debug_section(transcript);
        assert!(section.contains("Setting 'x' to 'y'"));
        assert!(
            !section.contains("systemd 252"),
            "must not bleed into the VERSION section: {section:?}"
        );
        assert!(
            !section.contains("ignored"),
            "must not include the CAT-CONFIG section: {section:?}"
        );
    }

    #[test]
    #[should_panic(expected = "no '=== APPLY-DEBUG ===' section")]
    fn apply_debug_section_fails_closed_on_a_missing_marker() {
        let _ = apply_debug_section("no markers here at all");
    }

    #[test]
    fn reject_and_accept_signals_are_distinct() {
        let reject = "/etc/sysctl.d/10-bad.conf:1: Line is not an assignment, ignoring: x\n";
        let accept = "Setting '/proc/sys/kernel/randomize_va_space' to '0'\n";
        assert!(oracle_shows_reject_signal(reject));
        assert!(!oracle_shows_accept_signal(reject));
        assert!(oracle_shows_accept_signal(accept));
        assert!(!oracle_shows_reject_signal(accept));
    }

    #[test]
    fn rulesteward_verdict_extracts_the_insecure_value_verbatim() {
        let diags = vec![Diagnostic::new(
            Severity::Warning,
            "sysctld-W02",
            0..0,
            "STIG-required key `kernel.randomize_va_space` = `0` is insecure (RHEL-09-213070 requires `2`)",
            "/etc/sysctl.d/x.conf",
            0,
            0,
        )];
        assert_eq!(
            rulesteward_verdict(&diags, "kernel.randomize_va_space"),
            Some("0".to_string())
        );
    }

    #[test]
    fn rulesteward_verdict_reads_unset_as_none() {
        let diags = vec![Diagnostic::new(
            Severity::Warning,
            "sysctld-W02",
            0..0,
            "STIG-required key `kernel.randomize_va_space` is unset (RHEL-09-213070 requires `2`)",
            "/etc/sysctl.d",
            0,
            0,
        )];
        assert_eq!(
            rulesteward_verdict(&diags, "kernel.randomize_va_space"),
            None
        );
    }

    #[test]
    fn rulesteward_verdict_reads_the_w04_message_shape_too() {
        let diags = vec![Diagnostic::new(
            Severity::Warning,
            "sysctld-W04",
            0..0,
            "CIS-required key `kernel.randomize_va_space` = `0` is outside the benchmark-accepted set (1.1.1 requires `2`)",
            "/etc/sysctl.d/x.conf",
            0,
            0,
        )];
        assert_eq!(
            rulesteward_verdict(&diags, "kernel.randomize_va_space"),
            Some("0".to_string())
        );
    }

    #[test]
    #[should_panic(expected = "no sysctld-W02/W04 diagnostic named key")]
    fn rulesteward_verdict_fails_closed_when_key_is_untracked() {
        let diags: Vec<Diagnostic> = Vec::new();
        rulesteward_verdict(&diags, "kernel.randomize_va_space");
    }

    #[test]
    fn parse_tree_plan_splits_at_the_marker() {
        let text = "f\tetc/sysctl.d/x.conf\t\n---\nd\tetc/sysctl.d\t\nf\tetc/sysctl.d/x.conf\t\n";
        let (materialize_entries, inventory) = parse_tree_plan(text);
        // Assert the actual entries, not just counts: a corruption that swapped
        // the type or relpath of an entry while preserving vector LENGTHS would
        // pass a lengths-only assertion silently.
        assert_eq!(
            materialize_entries,
            vec![parse_plan_line("f\tetc/sysctl.d/x.conf\t")]
        );
        assert_eq!(
            inventory,
            vec![
                parse_plan_line("d\tetc/sysctl.d\t"),
                parse_plan_line("f\tetc/sysctl.d/x.conf\t"),
            ]
        );
    }

    #[test]
    fn parse_tree_plan_skips_blank_and_comment_lines_in_both_sections() {
        // Adversarial-sweep finding: `parse_tree_plan`'s blank-line/comment-line
        // skip used `line.is_empty() || line.starts_with('#')`; a mutant
        // replacing `||` with `&&` survived because no test exercised a
        // tree.plan with a blank or `#`-comment line in EITHER section. Under
        // that mutant the guard can never be true (a line cannot be both empty
        // AND start with '#'), so every blank/comment line would be fed to
        // `parse_plan_line` instead of being skipped - panicking outright on a
        // blank line, and silently fabricating a bogus entry for a comment line.
        let text = "f\tetc/sysctl.d/x.conf\t\n\n# a materialize comment\n---\n\
                    d\tetc/sysctl.d\t\n\n# an inventory comment\nf\tetc/sysctl.d/x.conf\t\n";
        let (materialize_entries, inventory) = parse_tree_plan(text);
        assert_eq!(
            materialize_entries,
            vec![parse_plan_line("f\tetc/sysctl.d/x.conf\t")],
            "blank/comment lines must not become materialize entries"
        );
        assert_eq!(
            inventory,
            vec![
                parse_plan_line("d\tetc/sysctl.d\t"),
                parse_plan_line("f\tetc/sysctl.d/x.conf\t"),
            ],
            "blank/comment lines must not become inventory entries"
        );
    }

    #[test]
    #[should_panic(expected = "zero materialize entries")]
    fn parse_tree_plan_fails_closed_on_an_empty_materialize_section() {
        let _ = parse_tree_plan("---\nd\tetc/sysctl.d\t\n");
    }

    #[test]
    #[should_panic(expected = "no '---'")]
    fn parse_tree_plan_fails_closed_without_a_marker() {
        let _ = parse_tree_plan("f\tetc/sysctl.d/x.conf\t\n");
    }
}
