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
//! # XFAIL policy
//!
//! One scenario ([`XFAIL`]) asserts the CURRENT (wrong) behavior rather than
//! oracle agreement: `slot-symlink-misdirected-593` (issue #593). Landing it
//! xfailed documents a real, already-verified bug without blocking on a fix
//! this test-author must not make (impl-blind barrier).

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

use rulesteward_core::Diagnostic;
use rulesteward_core::oracle_corpus::{resolve_corpus_root, sentinel_banner, sentinel_count};
use rulesteward_sysctld::TargetVersion;
use rulesteward_sysctld::oracle::{
    apply_debug_section, compute_inventory, dotted_to_procpath, materialize, oracle_overwrote,
    oracle_setting_value, oracle_shows_accept_signal, oracle_shows_reject_signal, parse_tree_plan,
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
const XFAIL: &[(&str, u32)] = &[("slot-symlink-misdirected-593", 593)];

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

            if let Some(idx) = transcript.find("=== VERSION ===") {
                let banner = transcript[idx + "=== VERSION ===".len()..]
                    .lines()
                    .find(|l| !l.trim().is_empty())
                    .unwrap_or("")
                    .trim()
                    .to_string();
                version_banners.insert(image.clone(), banner);
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
    // control pinning a known version divergence").
    let banners: Vec<(&String, &String)> = version_banners.iter().collect();
    assert!(
        banners.len() >= 3,
        "expected >= 3 captured --version banners (one per rs-oracle8/9/10), got {}: {:?}",
        banners.len(),
        banners
    );
    for i in 0..banners.len() {
        for j in (i + 1)..banners.len() {
            assert_ne!(
                banners[i].1, banners[j].1,
                "ORACLE-BROKEN: {} and {} captured IDENTICAL --version banners - the three \
                 rs-oracle images are secretly the same file",
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
        oracle_shows_accept_signal, oracle_shows_reject_signal, parse_tree_plan,
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
        assert_eq!(materialize_entries.len(), 1);
        assert_eq!(inventory.len(), 2);
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
