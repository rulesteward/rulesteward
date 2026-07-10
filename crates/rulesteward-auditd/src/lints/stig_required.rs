//! au-W06: the ruleset is missing audit rules required by the applicable RHEL
//! STIG (issue #474). Version-aware: fires only under an explicit `--target`
//! (the portable default stays silent), mirroring the sysctld-W02 STIG
//! baseline pattern (#341).
//!
//! Phase-0 stub (session 7c): the entrypoint signature and the
//! [`TargetVersion`] enum are frozen here so the fan-out pipeline fills only
//! this file's body. The pinned per-RHEL-major required-rules tables are
//! derived from the DISA XCCDF benchmarks (RHEL 8 V2R4 / RHEL 9 V2R7 /
//! RHEL 10 V1R1) by `tools/auditd-stig-update`; matching is KEY-SENSITIVE
//! with a distinct present-but-key-differs message (locked decisions,
//! 2026-07-10).
//!
//! Test-author pass (session 7c-v0_6-wave3, P2): the shapes below
//! ([`BaselineRule`], [`StigBaselineEntry`]/[`stig_baseline`],
//! [`w06_with_baseline`]) are added as SIGNATURES beyond the frozen stub
//! above. `RHEL8_REQUIRED`/`RHEL9_REQUIRED`/`RHEL10_REQUIRED` are empty
//! placeholders: the REAL per-product data (61/67/75 grounded lines) is
//! deliberately left for the implementer to populate from
//! `tools/auditd-stig-update derive`'s paste-ready output, per this
//! dispatch's explicit instruction - do not hand-transcribe it here. The real
//! MATCHING algorithm (`w06_with_baseline`'s body) is `todo!()` for the same
//! reason: it is the implementer's job (see the doc comment on
//! [`w06_with_baseline`] for the full grounded matcher spec, sourced from the
//! P2 grounding doc Part C.5). [`w06_with_baseline`] is `pub` (not
//! `pub(crate)`) specifically so the frozen scenario tests in
//! `tests/test_lints_stig_required.rs` (a separate integration-test crate)
//! can inject a small, appendix-cited test-local baseline directly, WITHOUT
//! depending on the shipped (still-empty) `RHEL*_REQUIRED` tables - that
//! keeps the frozen adversarial tests meaningful today while still honoring
//! "leave the real table content to the implementer."

use rulesteward_core::Diagnostic;

use super::LintOptions;
use crate::ast::LocatedRule;

/// RHEL release whose STIG audit-rule baseline to check against. Clap-free
/// (the CLI maps its `--target` value-enum into this via a `From` impl);
/// mirrors `rulesteward_sysctld::TargetVersion` so each domain crate stays
/// clap-free.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetVersion {
    Rhel8,
    Rhel9,
    Rhel10,
}

/// au-W06 missing-required-STIG-rules pass. `target == None` (portable mode)
/// stays silent by contract; `Some(t)` dispatches to [`w06_with_baseline`]
/// against the shipped table for `t`. The shipped tables are empty
/// placeholders until the implementer populates them (see the module doc),
/// so this returns `Vec::new()` for every target today - dispatcher output
/// stays byte-identical until the tables AND the matcher both land.
#[must_use]
pub fn w06(
    rules: &[LocatedRule],
    opts: LintOptions,
    target: Option<TargetVersion>,
) -> Vec<Diagnostic> {
    match target {
        None => Vec::new(),
        Some(t) => w06_with_baseline(rules, opts, baseline_for(t)),
    }
}

/// One STIG-required audit rule line: DISA's Group V-number, the RHEL STIG
/// control id (shown in au-W06 messages), and the canonical required
/// `rules.d` line text (auditd rules.d syntax; extraction source =
/// check-content, see `tools/auditd-stig-update/src/xccdf.rs`'s module doc).
/// `pub` (not `pub(crate)`) for two independent external consumers: (1)
/// `tools/auditd-stig-update`, which imports it for the drift `check`/`derive`
/// subcommands (mirrors `rulesteward_sysctld::baseline::StigEntry`), and (2)
/// the frozen scenario tests in `tests/test_lints_stig_required.rs`, which
/// build small test-local `&[BaselineRule]` slices to inject into
/// [`w06_with_baseline`] directly (see the module doc for why).
/// `Copy`: all fields are `&'static str`, so passing this type around never
/// needs a clone.
#[derive(Debug, Clone, Copy)]
pub struct BaselineRule {
    pub v_number: &'static str,
    pub stig_id: &'static str,
    pub line: &'static str,
}

/// The grounded baseline table for `target`. EMPTY placeholders (see the
/// module doc): populated by the implementer from `auditd-stig-update
/// derive`'s paste-ready output, one `BaselineRule` literal per derived row.
const RHEL8_REQUIRED: &[BaselineRule] = &[];
const RHEL9_REQUIRED: &[BaselineRule] = &[];
const RHEL10_REQUIRED: &[BaselineRule] = &[];

fn baseline_for(target: TargetVersion) -> &'static [BaselineRule] {
    match target {
        TargetVersion::Rhel8 => RHEL8_REQUIRED,
        TargetVersion::Rhel9 => RHEL9_REQUIRED,
        TargetVersion::Rhel10 => RHEL10_REQUIRED,
    }
}

/// The STIG baseline for `target` (the pub accessor for the drift test):
/// `tools/auditd-stig-update`'s `check`/`derive` subcommands import this to
/// diff the shipped table against a live/fixture-derived DISA XCCDF.
#[must_use]
pub fn stig_baseline(target: TargetVersion) -> &'static [BaselineRule] {
    baseline_for(target)
}

/// The real au-W06 matcher, taking an EXPLICIT `baseline` slice (see the
/// module doc for why this is `pub` and separate from `w06`'s frozen
/// `target`-based signature). `todo!()` body: this is the implementer's
/// pass, per the P2 dispatch's "the implementer + tool derive fill real
/// content" instruction. An empty `baseline` short-circuits to `Vec::new()`
/// BEFORE the `todo!()` so wiring/e2e tests that exercise `--target` against
/// the still-empty shipped tables observe clean exit-0 plumbing rather than a
/// spurious panic; a NON-empty baseline (the frozen scenario tests in
/// `tests/test_lints_stig_required.rs` always pass one) reaches the real,
/// currently-`todo!()`, matching algorithm.
///
/// # Grounded matcher spec (P2 grounding doc Part C.5; implementer fills the body)
///
/// For each `BaselineRule` in `baseline`:
/// 1. Parse `rule.line` via [`crate::parser`] (the SAME parser rules.d files
///    go through - `rulesteward_auditd::parser::parse_rules_str`, taking the
///    first parsed `AuditRule`) into the required `AuditRule`.
/// 2. Search `rules` (the full parsed ruleset) for a same-variant
///    (`Watch`-vs-`Watch` or `Syscall`-vs-`Syscall`) rule that matches on
///    EVERY axis:
///    - **Watch path:** plain string compare (or trailing-slash-normalized;
///      `is_dir` is NOT part of the comparison - grounding Part B.7.2).
///    - **Watch perms:** exact `PermBits` equality.
///    - **Key (both variants):** the UNIFIED key - `key.clone().or_else(||
///      fields.iter().find(|f| f.field == AuditField::Key).map(|f|
///      f.value.clone()))` on EACH side, then compare with `==`
///      (case-sensitive, trimmed) - this is the "`-k` == `-F key=`"
///      equivalence (locked decision), implemented as a lookup-time unify,
///      NOT a `canonical_value` fold.
///    - **`-F` fields (Syscall only), EXCLUDING any `AuditField::Key` entry**
///      (already consumed by the key-unify step): compare as a SET - same
///      size, and for every predicate a matching predicate on the other side
///      with the same `field`, same `op`, and
///      `canonical_value(field_type(field), value, opts) ==
///      canonical_value(field_type(field), other_value, opts)` (reuse
///      [`super::value::canonical_value`] directly; this is exactly the `I0`
///      branch of [`super::value::implies`], NOT `implies`/`disjoint`
///      themselves).
///    - **`-C` field-comparisons (Syscall only):** SET of `(left, op,
///      right)` triples, enum equality on all three (both operands are
///      field NAMES, never values, so no `canonical_value` step here).
///    - **`syscalls` (Syscall only):** SET of case-sensitive strings (NOT
///      ordered - grounding Part B.5.12/C.1 proves DISA's own text and a
///      live kernel round-trip both disagree on order).
///    - **`list`/`action`/`prepend` (Syscall only):** exact enum/bool
///      equality.
/// 3. Classify the verdict for this required line:
///    - **Satisfied:** a rule matches on every axis INCLUDING the key -> no
///      diagnostic.
///    - **Present-but-key-differs (the locked distinct finding):** a rule
///      matches every axis EXCEPT the key -> ONE `au-W06` `Warning`
///      diagnostic per such required line, with a message DISTINCT from the
///      missing case (name both the STIG id and that a same-shape rule with
///      a different key exists).
///    - **Missing:** no rule matches even excluding the key -> ONE `au-W06`
///      `Warning` diagnostic naming the STIG id and the missing line/watch.
/// 4. Anchor each diagnostic per the sysctld-W02 precedent
///    (`crates/rulesteward-sysctld/src/lints/baseline.rs`'s `w02_baseline`
///    doc comment): this is a MISSING-rule finding with no single offending
///    span in the user's ruleset, so anchor at the whole-ruleset/first-file
///    span (line 0, no `source_id`), not a specific existing rule's span.
#[must_use]
pub fn w06_with_baseline(
    rules: &[LocatedRule],
    opts: LintOptions,
    baseline: &[BaselineRule],
) -> Vec<Diagnostic> {
    if baseline.is_empty() {
        return Vec::new();
    }
    let _ = (rules, opts);
    todo!("P2 implementer: the C.5 matcher, see this fn's doc comment")
}
