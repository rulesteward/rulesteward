//! Data-driven `SELinux` denial-corpus oracle (#101, epic #139 Lane B).
//!
//! Wires the EXISTING 69-scenario `SELinux` denial corpus (45 grammar + 21 xver +
//! 3 vm-live, generated at corpus run `20260603T004238Z`, `RS_COMMIT` `d5999cc`)
//! into a single data-driven test with three layers:
//!
//! 1. **FLOOR** (all scenarios, no policy): every scenario's `denials.txt` is
//!    parsed by the frozen [`parse_avc`] and grouped by [`group_denials`]; the
//!    floor `DenialKind` of the groups is asserted against the manifest
//!    `floor_label`. Parse-without-error is itself an assertion.
//! 2. **AUTHORITATIVE** (policy-aware): for every scenario whose contexts the
//!    STOCK binary policy defines, [`categorize`] is replayed against the mapped
//!    stock policy (`policy.31` el8 / `policy.33` el9 / `policy.35` el10) and the
//!    result is asserted against the manifest `authoritative_category`.
//! 3. **CROSS-VERSION** (xver scenarios): each xver denial is replayed against
//!    BOTH the el9 baseline (`policy.33`) and the scenario's own version; the
//!    `xver_baseline.buckets_match` field gates whether the two categories must
//!    be equal (the one documented divergence is the el8 BADSCON case).
//!
//! # The corpus is GREEN against current code (impl already shipped)
//!
//! This is a REGRESSION oracle, not a barrier RED test: the floor classifier
//! ([`crate::denial`]) and the authoritative categorizer ([`crate::categorize`])
//! both already shipped, so every layer is expected GREEN. A scenario that
//! disagrees with current code is a FINDING (see the `FLOOR_XFAIL` / `AUTH_XFAIL`
//! consts); a LARGE rewrite implied by a failure is an `ARCHITECTURE-HALT`, not a
//! silent source edit.
//!
//! # Two layers of scope-out (both expected, NOT findings)
//!
//! - **Floor parse-only / no-floor-label**: VM-live scenarios carry a `null`
//!   `floor_label` (their floor "varies" per record pattern) and the one VM-live
//!   scenario with no `denials.txt` ([`A1_PARSE_EXCLUDED`]) is excluded from the
//!   parse loop entirely (it ships only an aggregated per-domain summary). Both
//!   stay counted toward the `>= 69` floor guard.
//! - **Authoritative synthetic-type scope-out** ([`SYNTHETIC_SCOPE_OUT`]): seven
//!   grammar/xver scenarios use SYNTHETIC types (`rsbnd_child_t`,
//!   `rsbnd_parent_t`, `rscons_src_t`/`rscons_tgt_t`) absent from the stock
//!   policy. Against stock they return [`DenialKind::ContextInvalid`] (BADSCON),
//!   not their manifest `Constraint`/`Bounds`/`TeAllowable` category, because the
//!   corpus built dedicated bounds/cons policies for them that we do NOT vendor.
//!   They stay covered by the floor layer + `known_answer_categorize.rs`.
//!
//! # Stale-doc note
//!
//! The corpus `ORACLES.md` says `categorize()` shells out to `audit2why`; the
//! REAL impl uses libsepol FFI (`sepol_compute_av_reason_buffer`). This test
//! asserts ONLY against manifest fields and the real `categorize` return, never
//! against the audit2why mechanism. See `tests/corpus/selinux/PROVENANCE.md`.

#![cfg(feature = "authoritative-categorizer")]

mod support;

use std::path::{Path, PathBuf};

use rulesteward_selinux::{
    CategorizeError, DenialKind, ReplayOutcome, categorize, categorize_with_outcome, group_denials,
    parse_avc,
};
use serde_json::Value;
use support::policy_corpus::policy;

// ---------------------------------------------------------------------------
// Scope-out allowlists (every entry is an EXPECTED skip, never a FINDING)
// ---------------------------------------------------------------------------

/// VM-live scenario that ships NO `denials.txt` (only an aggregated
/// `oracle/avc-summary.json` of per-domain patterns). It is EXCLUDED from the
/// floor parse loop because there are no raw AVC records to parse, but it is
/// still COUNTED toward the `>= 69` floor guard via its `manifest.json` (the
/// parse loop covers 68; the count guard sees 69). Per orchestrator answer A1.
const A1_PARSE_EXCLUDED: &str = "rocky10-live-avc-capture";

/// Authoritative-layer synthetic-type scope-outs (issue #139 grounding).
///
/// These seven scenarios use SYNTHETIC types the STOCK policy does not define
/// (`rsbnd_child_t`/`rsbnd_parent_t` for typebounds, `rscons_src_t`/
/// `rscons_tgt_t` for the type-attribute constraint). The corpus ships dedicated
/// `_policies/policy.bounds` / `policy.cons` for them, which we deliberately do
/// NOT vendor (#101 vendors only the three stock policies). Replayed against the
/// stock policy they therefore return [`DenialKind::ContextInvalid`] (BADSCON),
/// NOT their manifest `Constraint`/`Bounds`/`TeAllowable` category. This is a
/// scope decision, NOT a categorizer bug: the categorizer is exercised on these
/// types by `known_answer_categorize.rs` (which DOES ship a bounds policy), and
/// the floor layer still covers them here. Each scope-out is CONFIRMED empirically
/// below (we assert each one really does return `ContextInvalid` against stock).
const SYNTHETIC_SCOPE_OUT: &[&str] = &[
    // typebounds (rsbnd_child_t / rsbnd_parent_t): Bounds vs stock -> ContextInvalid
    "rocky10-typebounds-denial",
    "rocky10-typebounds-multi",
    "rocky8-xver-typebounds",
    // type-attribute constraint (rscons_src_t/rscons_tgt_t): Constraint vs stock -> ContextInvalid
    "rocky9-constraint-matching-context",
    "rocky8-xver-constraint-matching-context",
    "rocky10-xver-constraint-matching-context",
    // cross-host policy (rsbnd_parent_t): TeAllowable vs stock -> ContextInvalid
    "rocky9-cross-host-policy",
];

/// FLOOR-layer FINDINGS: scenarios whose FLOOR classifier output disagrees with
/// the manifest `floor_label` for a reason that is NOT a scope-out. Per the
/// locked findings policy these are xfailed in the FLOOR layer ONLY (NOT a source
/// change) and reported; they are still asserted normally in the AUTHORITATIVE
/// layer if their category is in scope.
///
/// Now EMPTY: the one former finding (#141, `rocky10-container-runtime`) is
/// RESOLVED. `classify_floor` now implements minimal MCS category-free dominance
/// (an MCS subject with categories dominates a category-free object of the same
/// sensitivity), so `container_t (s0:c123,c456) -> default_t:file (s0)` correctly
/// classifies `TeAllowable` (floor `none`) instead of `MlsSuspected`. The const
/// is kept (like `AUTH_XFAIL`) so the xfail-enumeration guard can assert it stays
/// empty.
const FLOOR_XFAIL: &[&str] = &[];

// AUTHORITATIVE-layer FINDINGS: scenarios whose `categorize` output disagrees
// with the manifest `authoritative_category` for a reason that is NOT the
// synthetic-type scope-out AND NOT the locked Reason(0)-tolerance rule below.
// (All nine previously-provisional xfails have been RESOLVED by the tolerance
// rule; no entries remain here. The list is kept as a named constant so the
// xfail-enumeration guard at the bottom of the authoritative test can still
// assert it is empty.)
const AUTH_XFAIL: &[&str] = &[];

// ---------------------------------------------------------------------------
// Manifest model (only the fields #101 asserts on)
// ---------------------------------------------------------------------------

/// The slice of a scenario `manifest.json` this oracle reads.
struct Manifest {
    /// Scenario id (== directory name).
    id: String,
    /// `authoritative_category`: `"TeAllowable"` / `"Constraint"` / `"Bounds"` /
    /// `"BADSCON"`, or a non-replay sentinel (`"NOT_COMPUTED_no_policy"` /
    /// `"n/a"` / JSON `null`) that scopes the scenario out of the authoritative
    /// layer.
    authoritative_category: Option<String>,
    /// `floor_label`: `"none"` / `"MlsSuspected"` / `"RoleSuspected"` /
    /// `"Permissive"`, or JSON `null` (VM-live: floor varies per record, so no
    /// single label is asserted).
    floor_label: Option<String>,
    /// `policyvers` (xver scenarios only; grammar scenarios are `null` and map
    /// from the `rockyN-` id prefix).
    policyvers: Option<u32>,
    /// `xver_baseline.buckets_match` (xver scenarios only).
    buckets_match: Option<bool>,
}

impl Manifest {
    fn load(dir: &Path) -> Manifest {
        let path = dir.join("manifest.json");
        let raw = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let v: Value = serde_json::from_str(&raw)
            .unwrap_or_else(|e| panic!("parse JSON {}: {e}", path.display()));

        // Most scenarios use `id`; the VM-live scenarios use the
        // `selinux-scenario-v1` schema, which names the field `scenario_id`
        // instead. Accept either (verified: exactly 68 use `id`, 1 uses
        // `scenario_id`, none use both).
        let id = v["id"]
            .as_str()
            .or_else(|| v["scenario_id"].as_str())
            .unwrap_or_else(|| {
                panic!(
                    "{}: manifest missing string `id`/`scenario_id`",
                    path.display()
                )
            })
            .to_string();

        // A JSON `null` and an absent key both become `None`; a present string
        // stays `Some(..)`. The non-replay sentinels stay as their literal
        // strings and are filtered in the authoritative layer.
        let authoritative_category = v["authoritative_category"].as_str().map(str::to_string);
        let floor_label = v["floor_label"].as_str().map(str::to_string);

        let policyvers = v["policyvers"].as_u64().map(|n| {
            u32::try_from(n)
                .unwrap_or_else(|_| panic!("{}: policyvers {n} out of u32 range", path.display()))
        });

        let buckets_match = v["xver_baseline"]["buckets_match"].as_bool();

        Manifest {
            id,
            authoritative_category,
            floor_label,
            policyvers,
            buckets_match,
        }
    }
}

// ---------------------------------------------------------------------------
// Enumeration + small helpers
// ---------------------------------------------------------------------------

fn corpus_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus/selinux")
}

/// Enumerate every scenario directory: `tests/corpus/selinux/*/manifest.json`
/// whose directory name does NOT start with `_` (skips `_policies`). Returns
/// `(scenario_dir, Manifest)` sorted by id for deterministic output.
fn scenarios() -> Vec<(PathBuf, Manifest)> {
    let root = corpus_root();
    let mut out = Vec::new();
    let entries = std::fs::read_dir(&root)
        .unwrap_or_else(|e| panic!("read corpus dir {}: {e}", root.display()));
    for entry in entries.flatten() {
        let dir = entry.path();
        if !dir.is_dir() {
            continue;
        }
        let name = dir
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or_default()
            .to_string();
        if name.starts_with('_') {
            continue; // _policies (and any future underscore dir)
        }
        if !dir.join("manifest.json").is_file() {
            continue;
        }
        out.push((dir.clone(), Manifest::load(&dir)));
    }
    out.sort_by(|a, b| a.1.id.cmp(&b.1.id));
    out
}

/// Map a scenario to its stock policy version.
///
/// Prefer the explicit `policyvers` manifest field (xver scenarios carry 31/35).
/// Grammar scenarios have `policyvers: null`, so fall back to the `rockyN-` id
/// prefix: `rocky8 -> 31`, `rocky9 -> 33`, `rocky10 -> 35`. Panics on an id that
/// matches no known prefix (a corpus shape change we want surfaced, not guessed).
fn policy_vers_for(m: &Manifest) -> u32 {
    if let Some(v) = m.policyvers {
        return v;
    }
    prefix_vers(&m.id)
}

/// Map a `rockyN-` id prefix to its policy version. `rocky10` is checked before
/// `rocky1`-style shorter prefixes (none exist, but ordering is explicit).
fn prefix_vers(id: &str) -> u32 {
    if id.starts_with("rocky10") {
        35
    } else if id.starts_with("rocky9") {
        33
    } else if id.starts_with("rocky8") {
        31
    } else {
        panic!("scenario id {id:?} has no rocky8/9/10 prefix and no policyvers field");
    }
}

/// Map a manifest `authoritative_category` string to the [`DenialKind`] the real
/// [`categorize`] must return. Dead-simple match; explicit panic on an unknown
/// category so a corpus shape change is surfaced, never silently mapped.
///
/// `"BADSCON"` maps to [`DenialKind::ContextInvalid`] (the libsepol replay
/// rejects the context before classification -- the el8 role-dyntransition case).
fn expected_kind(category: &str) -> DenialKind {
    match category {
        "BADSCON" => DenialKind::ContextInvalid,
        "TeAllowable" => DenialKind::TeAllowable,
        "Constraint" => DenialKind::Constraint,
        "Bounds" => DenialKind::Bounds,
        other => panic!("unknown authoritative_category {other:?} (corpus shape changed?)"),
    }
}

/// `true` if the manifest `authoritative_category` is a real replay category
/// (one [`expected_kind`] understands). The non-replay sentinels
/// (`NOT_COMPUTED_no_policy`, `n/a`, JSON `null`) return `false` and scope the
/// scenario out of the authoritative + cross-version layers.
fn is_replay_category(m: &Manifest) -> bool {
    matches!(
        m.authoritative_category.as_deref(),
        Some("BADSCON" | "TeAllowable" | "Constraint" | "Bounds")
    )
}

/// Read a scenario's `denials.txt`. Panics if absent (callers must not call this
/// for the parse-excluded scenario).
fn read_denials(dir: &Path, file: &str) -> String {
    let path = dir.join(file);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// The `denials.txt` variants for a scenario, in `(variant_vers, filename)` form.
///
/// Most scenarios have a single `denials.txt` (`variant_vers` = the scenario's
/// mapped policy version). The dual-format scenario `rocky8-vs-rocky10-format`
/// instead ships `denials.el8.txt` + `denials.el10.txt`; per orchestrator answer
/// A2 each variant is parsed AND replayed against its OWN policy (el8 -> 31,
/// el10 -> 35), both asserting the same manifest categories. This helper
/// generalises to any `denials.elN.txt` layout.
fn denial_variants(dir: &Path, m: &Manifest) -> Vec<(u32, String)> {
    let el8 = dir.join("denials.el8.txt");
    let el10 = dir.join("denials.el10.txt");
    if el8.is_file() || el10.is_file() {
        let mut v = Vec::new();
        if el8.is_file() {
            v.push((31, "denials.el8.txt".to_string()));
        }
        if dir.join("denials.el9.txt").is_file() {
            v.push((33, "denials.el9.txt".to_string()));
        }
        if el10.is_file() {
            v.push((35, "denials.el10.txt".to_string()));
        }
        return v;
    }
    vec![(policy_vers_for(m), "denials.txt".to_string())]
}

// ---------------------------------------------------------------------------
// Layer 1: FLOOR (record-only, no policy) -- all scenarios
// ---------------------------------------------------------------------------

/// FLOOR: parse every scenario's denials and assert the floor classifier output
/// matches the manifest `floor_label`.
///
/// Per-scenario rules (task spec):
/// - parse-without-error is itself an assertion (a parse failure fails the test);
/// - `floor_label == null` (VM-live): parse only, no label compare (floor varies
///   per record pattern);
/// - `floor_label == "none"`: assert NO group is `MlsSuspected` / `RoleSuspected`
///   / `Permissive`;
/// - single-group, non-`none` label: assert the group's kind equals the label;
/// - multi-group, non-`none` label: assert the label is PRESENT among the groups'
///   kinds.
///
/// The parse-excluded VM-live scenario ([`A1_PARSE_EXCLUDED`]) is skipped here
/// but still contributes to the `>= 69` count guard (asserted separately).
/// Per-variant for `denials.elN.txt` layouts (answer A2).
#[test]
fn floor_layer_matches_manifest_label() {
    let scenarios = scenarios();
    let mut parsed_count = 0usize;
    let mut xfail_hit = Vec::new();

    for (dir, m) in &scenarios {
        if m.id == A1_PARSE_EXCLUDED {
            // No denials.txt; aggregated summary only. Counted, not parsed (A1).
            continue;
        }
        if FLOOR_XFAIL.contains(&m.id.as_str()) {
            // Known FLOOR finding: parse it (parse-without-error still asserted)
            // but skip the floor_label comparison. See FLOOR_XFAIL docs.
            let raw = read_denials(dir, "denials.txt");
            let denials = parse_avc(&raw).unwrap_or_else(|e| {
                panic!("FLOOR(xfail) {}: parse_avc still must succeed: {e}", m.id)
            });
            assert!(
                !group_denials(&denials).is_empty(),
                "FLOOR(xfail) {}: must still group to >=1 group",
                m.id
            );
            xfail_hit.push(m.id.clone());
            parsed_count += 1;
            continue;
        }

        for (_vers, file) in denial_variants(dir, m) {
            let raw = read_denials(dir, &file);
            let denials = parse_avc(&raw)
                .unwrap_or_else(|e| panic!("FLOOR {} ({file}): parse_avc failed: {e}", m.id));
            assert!(
                !denials.is_empty(),
                "FLOOR {} ({file}): parsed zero AVC records",
                m.id
            );
            let groups = group_denials(&denials);
            assert!(
                !groups.is_empty(),
                "FLOOR {} ({file}): grouped to zero groups",
                m.id
            );

            match m.floor_label.as_deref() {
                // VM-live: floor varies per pattern; parse-only assertion.
                None => {}
                Some("none") => {
                    for g in &groups {
                        assert!(
                            !matches!(
                                g.kind,
                                DenialKind::MlsSuspected
                                    | DenialKind::RoleSuspected
                                    | DenialKind::Permissive
                            ),
                            "FLOOR {} ({file}): floor_label=none but group {}->{}:{} is {:?}",
                            m.id,
                            g.source_type,
                            g.target_type,
                            g.tclass,
                            g.kind
                        );
                    }
                }
                Some(label) => {
                    let want = floor_kind(label);
                    if groups.len() == 1 {
                        assert_eq!(
                            groups[0].kind, want,
                            "FLOOR {} ({file}): single group must be {label} ({want:?})",
                            m.id
                        );
                    } else {
                        assert!(
                            groups.iter().any(|g| g.kind == want),
                            "FLOOR {} ({file}): floor_label={label} ({want:?}) not present among {} groups: {:?}",
                            m.id,
                            groups.len(),
                            groups.iter().map(|g| g.kind).collect::<Vec<_>>()
                        );
                    }
                }
            }
            parsed_count += 1;
        }
    }

    // Count guard: 69 manifests enumerated (the parse-excluded scenario is
    // counted via its manifest; the dual-format scenario is parsed twice, once
    // per variant, so the PARSE count exceeds the scenario count).
    assert!(
        scenarios.len() >= 69,
        "expected >= 69 enumerated scenarios, found {}",
        scenarios.len()
    );
    assert!(
        parsed_count >= 68,
        "expected >= 68 parsed scenario-variants (69 minus the 1 parse-excluded), got {parsed_count}"
    );

    assert_eq!(
        xfail_hit.len(),
        FLOOR_XFAIL.len(),
        "every FLOOR_XFAIL scenario must have been enumerated and xfailed"
    );
    if !xfail_hit.is_empty() {
        eprintln!(
            "FLOOR xfailed (FINDINGs #139, floor_label mismatch, NOT scope-outs): {xfail_hit:?}"
        );
    }
}

/// Map a non-`none` floor label string to its [`DenialKind`]. Panics on an
/// unknown label so a corpus shape change is surfaced.
fn floor_kind(label: &str) -> DenialKind {
    match label {
        "MlsSuspected" => DenialKind::MlsSuspected,
        "RoleSuspected" => DenialKind::RoleSuspected,
        "Permissive" => DenialKind::Permissive,
        "none" => DenialKind::TeAllowable, // unused (handled by the `none` arm) but explicit
        other => panic!("unknown floor_label {other:?} (corpus shape changed?)"),
    }
}

// ---------------------------------------------------------------------------
// Layer 2: AUTHORITATIVE (policy replay) -- in-scope scenarios
// ---------------------------------------------------------------------------

/// Assert one denial from a `manifest authoritative_category == "TeAllowable"` scenario
/// against the Reason(0)-tolerance rule (LOCKED user decision, #139).
///
/// Acceptable outcomes (EITHER is OK):
/// - `Ok(TeAllowable)` -- genuine TE gap in the stock policy.
/// - `Ok(ContextInvalid)` + `ReplayOutcome::Reason(0)` -- stock policy ALREADY
///   ALLOWS the access; corpus manifest is stale (derived from `audit2allow` which
///   emits an allow unconditionally regardless of whether access is already granted).
///
/// Rejected outcomes (hard panic):
/// - `Ok(ContextInvalid)` + `ReplayOutcome::BadContext` -- context undefined in
///   policy (BADSCON/BADTCON); NOT the already-allowed case.
/// - `Ok(Constraint | Bounds | ...)` -- wrong category entirely.
/// - `Err(UnknownPermission)` for any scenario other than `rocky9-hex-perm-token`
///   (the 0x4000 hex perm sub-case is scenario-specific).
/// - Any other `Err`.
fn assert_te_allowable_tolerance(
    scenario_id: &str,
    file: &str,
    source_type: &str,
    target_type: &str,
    tclass: &str,
    vers: u32,
    result: Result<(DenialKind, ReplayOutcome), CategorizeError>,
) {
    match result {
        Ok((DenialKind::TeAllowable, _outcome)) => {
            // Genuine TE gap: the exact expected outcome.
        }
        Ok((DenialKind::ContextInvalid, ReplayOutcome::Reason(0))) => {
            // Already-allowed: stock policy grants the access the host denied
            // (D8 / #122). Corpus manifest is stale. ACCEPTABLE per the tolerance.
        }
        Ok((DenialKind::ContextInvalid, ReplayOutcome::BadContext)) => {
            panic!(
                "AUTH(tolerance) {scenario_id} ({file}) {source_type}->{target_type}:{tclass} \
                 vs policy.{vers}: got ContextInvalid via BadContext (undefined context -- \
                 BADSCON/BADTCON), but manifest says TeAllowable; the Reason(0) tolerance does \
                 NOT cover BadContext (distinct sub-case). If the corpus triple uses a real \
                 domain this is a categorizer or corpus bug.",
            );
        }
        Ok((got_kind, got_outcome)) => {
            panic!(
                "AUTH(tolerance) {scenario_id} ({file}) {source_type}->{target_type}:{tclass} \
                 vs policy.{vers}: got ({got_kind:?}, {got_outcome:?}), but manifest says \
                 TeAllowable. Acceptable: TeAllowable or ContextInvalid+Reason(0) only. \
                 This is NOT a categorizer bug the tolerance covers.",
            );
        }
        Err(CategorizeError::UnknownPermission {
            ref perm,
            tclass: ref perm_tclass,
        }) => {
            // Hex-perm sub-case: the 0x4000 residual token is unknown to libsepol
            // for class `file`. Only rocky9-hex-perm-token is expected here.
            assert_eq!(
                scenario_id, "rocky9-hex-perm-token",
                "AUTH(hex-perm) {scenario_id} ({file}) {source_type}->{target_type}:{tclass} \
                 vs policy.{vers}: got UnknownPermission({perm:?} for {perm_tclass:?}), but only \
                 rocky9-hex-perm-token is expected to yield this error. \
                 If another scenario now has a hex perm, update this assertion.",
            );
        }
        Err(e) => {
            panic!(
                "AUTH {scenario_id} ({file}) {source_type}->{target_type}:{tclass} \
                 vs policy.{vers}: categorize_with_outcome errored unexpectedly: {e}",
            );
        }
    }
}

/// AUTHORITATIVE: for every scenario whose contexts the stock policy defines,
/// replay each denial through [`categorize_with_outcome`] against the mapped
/// stock policy and assert the result equals the manifest `authoritative_category`.
///
/// # Reason(0)-tolerance rule (LOCKED user decision, #139)
///
/// For every scenario whose manifest `authoritative_category == "TeAllowable"`,
/// each denial triple is ACCEPTABLE iff the result is either:
///
/// - `Ok(DenialKind::TeAllowable)` -- a genuine TE gap in the stock policy, OR
/// - `Ok(DenialKind::ContextInvalid)` AND `ReplayOutcome::Reason(0)` -- the
///   stock policy ALREADY ALLOWS the access (D8 / locked decision #122). The
///   corpus's `authoritative_category` field was derived from the STALE `audit2allow`
///   oracle (which emits an allow regardless of whether the access is already
///   granted), so reason==0 triples within a `TeAllowable`-labelled scenario
///   are a corpus-staleness artefact, NOT a categorizer bug.
///
/// Any other result (Constraint, Bounds, `ContextInvalid` via `BadContext`) is a
/// HARD FAILURE: the tolerance is a PRECISE invariant ("a TeAllowable-labelled
/// denial against the stock policy is either a genuine TE gap OR already-allowed;
/// never a constraint/bounds/undefined-context problem"), NOT a blanket accept.
///
/// # Hex-perm sub-case (rocky9-hex-perm-token)
///
/// The residual `0x4000` hex permission token is rejected by libsepol as
/// [`CategorizeError::UnknownPermission`] for class `file`. That triple yields
/// `Err(CategorizeError::UnknownPermission { .. })` and is asserted specifically
/// as such -- it is NOT folded into the Reason(0) tolerance.
///
/// # Scope
///
/// - INCLUDE: `TeAllowable` grammar (real domains), xver, and the BADSCON fixture.
/// - SCOPE OUT (NOT asserted, NOT a finding): the synthetic-type scenarios in
///   [`SYNTHETIC_SCOPE_OUT`] (their stock-policy result is `ContextInvalid`, which
///   this test CONFIRMS); and the non-replay sentinels
///   (`NOT_COMPUTED_no_policy` / `n/a` / `null`).
/// - Per-variant for `denials.elN.txt` layouts: each variant replays against its
///   OWN policy version (answer A2).
#[test]
#[allow(clippy::too_many_lines)] // data-driven harness; sub-loops extracted to helpers
fn authoritative_layer_matches_manifest_category() {
    let scenarios = scenarios();
    let mut asserted = 0usize;
    let mut synthetic_confirmed = 0usize;
    // No AUTH_XFAIL entries remain (all nine resolved by the tolerance rule).
    // The enumeration guard below asserts AUTH_XFAIL stays empty.
    let mut xfail_hit = Vec::<String>::new();

    for (dir, m) in &scenarios {
        if AUTH_XFAIL.contains(&m.id.as_str()) {
            // No entries in AUTH_XFAIL; this branch is unreachable but kept so
            // the guard at the bottom still fires if any entry is accidentally added.
            xfail_hit.push(m.id.clone());
            continue;
        }
        if m.id == A1_PARSE_EXCLUDED {
            continue; // no denials.txt to replay
        }

        // Synthetic-type scope-out: do NOT assert the manifest category; instead
        // CONFIRM the documented stock-policy behaviour (ContextInvalid). This
        // turns the scope-out into a positive, checked invariant.
        if SYNTHETIC_SCOPE_OUT.contains(&m.id.as_str()) {
            for (vers, file) in denial_variants(dir, m) {
                let raw = read_denials(dir, &file);
                let denials = parse_avc(&raw)
                    .unwrap_or_else(|e| panic!("AUTH {} ({file}): parse_avc failed: {e}", m.id));
                for d in &denials {
                    let (got, _outcome) =
                        categorize_with_outcome(d, policy(vers)).unwrap_or_else(|e| {
                            panic!("AUTH(synthetic) {} ({file}): categorize errored: {e}", m.id)
                        });
                    assert_eq!(
                        got,
                        DenialKind::ContextInvalid,
                        "AUTH(synthetic) {} ({file}) {}->{}:{}: synthetic type must be \
                         ContextInvalid against stock policy.{vers} (corpus ships a dedicated \
                         bounds/cons policy we do not vendor); if this changed, the scope-out \
                         rationale is stale",
                        m.id,
                        d.source_type,
                        d.target_type,
                        d.tclass
                    );
                    synthetic_confirmed += 1;
                }
            }
            continue;
        }

        // Non-replay sentinels (no-policy / n/a / null) scope out silently.
        if !is_replay_category(m) {
            continue;
        }

        let is_te_allowable_scenario = m.authoritative_category.as_deref() == Some("TeAllowable");
        let want = expected_kind(m.authoritative_category.as_deref().unwrap());

        for (vers, file) in denial_variants(dir, m) {
            let raw = read_denials(dir, &file);
            let denials = parse_avc(&raw)
                .unwrap_or_else(|e| panic!("AUTH {} ({file}): parse_avc failed: {e}", m.id));

            for d in &denials {
                if is_te_allowable_scenario {
                    // Reason(0)-tolerance rule + hex-perm sub-case: see
                    // `assert_te_allowable_tolerance` for the full invariant.
                    assert_te_allowable_tolerance(
                        &m.id,
                        &file,
                        &d.source_type,
                        &d.target_type,
                        &d.tclass,
                        vers,
                        categorize_with_outcome(d, policy(vers)),
                    );
                } else {
                    // Non-TeAllowable scenarios (BADSCON / Constraint / Bounds):
                    // assert the exact kind; no tolerance applied.
                    let (got, _outcome) =
                        categorize_with_outcome(d, policy(vers)).unwrap_or_else(|e| {
                            panic!("AUTH {} ({file}): categorize errored: {e}", m.id)
                        });
                    assert_eq!(
                        got,
                        want,
                        "AUTH {} ({file}) {}->{}:{}: categorize vs policy.{vers} must be {:?} \
                         (manifest authoritative_category={:?})",
                        m.id,
                        d.source_type,
                        d.target_type,
                        d.tclass,
                        want,
                        m.authoritative_category
                    );
                }
            }
            asserted += 1;
        }
    }

    // Sanity floors: the in-scope authoritative set and the synthetic-confirm set
    // must both be non-trivial, so a future enumeration regression that silently
    // drops all scenarios cannot pass this test vacuously.
    assert!(
        asserted >= 20,
        "expected >= 20 authoritative scenario-variants asserted, got {asserted}"
    );
    assert_eq!(
        SYNTHETIC_SCOPE_OUT.len(),
        7,
        "expected exactly 7 documented synthetic-type scope-outs"
    );
    assert!(
        synthetic_confirmed >= SYNTHETIC_SCOPE_OUT.len(),
        "every synthetic scope-out must have at least one confirmed ContextInvalid denial \
         (got {synthetic_confirmed} confirms for {} scenarios)",
        SYNTHETIC_SCOPE_OUT.len()
    );

    // AUTH_XFAIL must stay empty (all nine previously-provisional xfails are now
    // resolved by the Reason(0)-tolerance rule and the hex-perm specific assertion).
    assert_eq!(
        AUTH_XFAIL.len(),
        0,
        "AUTH_XFAIL must be empty (all divergences are now covered by the tolerance rule); \
         found {} entries: {AUTH_XFAIL:?}",
        AUTH_XFAIL.len()
    );
    assert_eq!(
        xfail_hit.len(),
        AUTH_XFAIL.len(),
        "every AUTH_XFAIL scenario must have been enumerated and xfailed"
    );
}

// ---------------------------------------------------------------------------
// Layer 3: CROSS-VERSION bucket stability -- xver scenarios
// ---------------------------------------------------------------------------

/// CROSS-VERSION: for each xver scenario, replay every denial against BOTH the
/// el9 baseline (`policy.33`) and the scenario's own version, and gate on the
/// manifest `xver_baseline.buckets_match`:
///
/// - `buckets_match == true`: `categorize(d, p33) == categorize(d, p_elX)` (the
///   authoritative bucket is stable across policy versions).
/// - `buckets_match == false`: the documented divergence -- ONLY
///   `rocky8-xver-role-dyntransition`, where the el9 category is `Constraint` and
///   the el8 (`policy.31`) category is `ContextInvalid` (BADSCON: `system_r` is
///   not in el8 `staff_u`).
///
/// xver scenarios are detected by a present `xver_baseline.buckets_match` field.
/// Synthetic-type xver scenarios (`*-constraint-matching-context`,
/// `*-typebounds`) are EXCLUDED here: against the stock policy they are
/// `ContextInvalid` on every version, so a stability assertion would be
/// trivially-true and misleading. They remain covered by the floor layer.
#[test]
fn cross_version_bucket_stability() {
    let scenarios = scenarios();
    let mut checked = 0usize;
    let mut divergence_checked = 0usize;

    for (dir, m) in &scenarios {
        // Neither current FINDING (FLOOR_XFAIL / AUTH_XFAIL) is an xver scenario,
        // but exclude them defensively so a finding can never silently corrupt the
        // cross-version gate if a future finding IS an xver scenario.
        if FLOOR_XFAIL.contains(&m.id.as_str()) || AUTH_XFAIL.contains(&m.id.as_str()) {
            continue;
        }
        let Some(buckets_match) = m.buckets_match else {
            continue; // not an xver scenario
        };
        // Synthetic-type xver scenarios are ContextInvalid on every version
        // against stock; excluding them keeps the stability check meaningful.
        if SYNTHETIC_SCOPE_OUT.contains(&m.id.as_str()) {
            continue;
        }

        let elx = policy_vers_for(m);
        let raw = read_denials(dir, "denials.txt");
        let denials =
            parse_avc(&raw).unwrap_or_else(|e| panic!("XVER {}: parse_avc failed: {e}", m.id));

        for d in &denials {
            let el9 = categorize(d, policy(33))
                .unwrap_or_else(|e| panic!("XVER {}: categorize(el9) errored: {e}", m.id));
            let elx_kind = categorize(d, policy(elx))
                .unwrap_or_else(|e| panic!("XVER {}: categorize(el{elx}) errored: {e}", m.id));

            if buckets_match {
                assert_eq!(
                    el9, elx_kind,
                    "XVER {} {}->{}:{}: buckets_match=true requires el9==el{elx}, got {el9:?} vs {elx_kind:?}",
                    m.id, d.source_type, d.target_type, d.tclass
                );
            } else {
                // The single documented divergence: el9 Constraint, el8 BADSCON.
                assert_eq!(
                    m.id, "rocky8-xver-role-dyntransition",
                    "XVER: the only buckets_match=false scenario must be \
                     rocky8-xver-role-dyntransition, found {}",
                    m.id
                );
                assert_eq!(elx, 31, "XVER divergence scenario must map to policy.31");
                assert_eq!(
                    el9,
                    DenialKind::Constraint,
                    "XVER {}: el9 baseline must be Constraint",
                    m.id
                );
                assert_eq!(
                    elx_kind,
                    DenialKind::ContextInvalid,
                    "XVER {}: el8 must be ContextInvalid (BADSCON: system_r not in el8 staff_u)",
                    m.id
                );
                divergence_checked += 1;
            }
        }
        checked += 1;
    }

    // The non-synthetic xver set: 21 total minus the 3 synthetic xver scenarios
    // (rocky8-xver-typebounds, rocky8-xver-constraint-matching-context,
    // rocky10-xver-constraint-matching-context) = 18 stability-checked scenarios.
    assert!(
        checked >= 18,
        "expected >= 18 cross-version-checked xver scenarios, got {checked}"
    );
    assert_eq!(
        divergence_checked, 1,
        "exactly one buckets_match=false divergence denial must be checked, got {divergence_checked}"
    );
}
