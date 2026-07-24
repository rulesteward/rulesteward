//! sudo hardening-baseline Defaults lint pass (#333, #347): sudo-W04 (a `Defaults`
//! setting weaker than, OR a required hardening absent from, the sudo security
//! baseline).
//!
//! # Grounding
//!
//! W04 covers two complementary baselines.
//!
//! ## Weakening-present (per-file, #333) -- fire on presence
//!
//! A mix of DISA RHEL 8 / RHEL 9 sudo STIG controls (`!authenticate` and the
//! `targetpw` / `rootpw` / `runaspw` family) and CIS / general-hardening
//! controls with no DISA `stigid@` mapping (`use_pty`, `visiblepw`). Each
//! finding cites its grounded control id and framework inline (see the
//! per-setting list below).
//!
//! These IDs were RE-GROUNDED 2026-06-29 (#355, #359) against
//! ComplianceAsCode/content commit `65ccea603ee2c305fdb4c6f54cb911449d969d55`
//! (the `stigid@ol8` keys) plus the DISA RHEL 9 4320xx cluster. The earlier
//! `[VERIFY]` IDs were mismapped: the RHEL-08 `!authenticate` and pw IDs were
//! swapped, and `use_pty`/`visiblepw` were wrongly attributed to DISA STIG
//! (both are CIS / general-hardening controls with no `stigid@` mapping). The
//! `tests::w04_weakening_findings_cite_grounded_controls` drift-guard pins these.
//!
//! - `!authenticate` -- bypasses per-invocation re-authentication.
//!   DISA STIG RHEL-08-010381 / RHEL-09-432025 / RHEL-10-600530
//!   (ComplianceAsCode `sudo_remove_no_authenticate`; RHEL-10-600530 grounded
//!   #563, 9i lane-7, against the DISA RHEL 10 STIG V1R1 XCCDF).
//! - `targetpw` / `rootpw` / `runaspw` -- prompts for the target/root/runas
//!   user's password rather than the invoking user's, breaking PAM/audit
//!   accountability.
//!   DISA STIG RHEL-08-010383 / RHEL-09-432020 / RHEL-10-600550
//!   (ComplianceAsCode `sudoers_validate_passwd`; RHEL-10-600550 grounded
//!   #563, 9i lane-7, against the DISA RHEL 10 STIG V1R1 XCCDF).
//! - `visiblepw` -- allows sudo to proceed when the password would be visible
//!   (e.g. when a tty is not associated with stdin).
//!   CIS / general hardening; no DISA sudo STIG control.
//! - `!use_pty` (explicit negation of the pty requirement) -- deliberately
//!   disabling pseudo-terminal allocation is a present weakening.
//!   CIS Benchmark 5.2.2 / PCI-DSS Req-10.2.5; no DISA sudo STIG control
//!   (ComplianceAsCode `sudo_add_use_pty` carries no `stigid@` key; the
//!   RHEL-08-010382 it formerly cited is the unrelated "restrict privilege
//!   elevation to authorized personnel" control).
//! - `timestamp_timeout` with a NEGATIVE value (e.g. `-1`) -- the sudo credential
//!   cache then never expires, so a user re-authenticates once and is trusted
//!   indefinitely. A non-negative value (0 or positive) is compliant. This is a
//!   value-conditional weakening (handled in `check_file`'s non-negated arm, not
//!   the name-presence `WEAKENING_PRESENT` table).
//!   DISA STIG RHEL-08-010384 / RHEL-09-432015 / RHEL-10-600540
//!   (ComplianceAsCode `sudo_require_reauthentication`, #363; RHEL-10-600540
//!   grounded #563, 9i lane-7, against the DISA RHEL 10 STIG V1R1 XCCDF).
//!
//! ## Missing-required (merged, #347, #363) -- fire on absence / conflict
//!
//! The sudo `use_pty` and I/O-logging (`logfile` / `log_output`) hardening,
//! checked over the MERGED resolved config set (all included files together),
//! firing ONCE at the top-level file -- not per-file -- to avoid the per-fragment
//! false positive (a `sudoers.d` drop-in flagged for missing `use_pty` when the
//! main `/etc/sudoers` sets it). Analogous to sshd-W01. See
//! [`check_merged_required`].
//!
//! The `use_pty` / I/O-logging requirements are NOT DISA STIG controls: primary
//! sources (ComplianceAsCode `sudo_add_use_pty` / `sudo_custom_logfile` rule.yml;
//! the RHEL 8 V2R7 / RHEL 9 V2R8 / RHEL 10 V1R1 STIG sudo clusters) confirm neither
//! carries a `stigid@` mapping. They are CIS Benchmark 5.2.2 (use_pty) / 5.2.3
//! (logfile) + PCI-DSS Req-10.2.5 controls, and are cited as such (#526
//! renumber, LOCKED post-A0 2026-07-18; the stale "1.3.2"/"1.3.3" ids
//! were an older CIS benchmark generation's numbering).
//!
//! `timestamp_timeout` (#363) IS a DISA STIG control (RHEL-08-010384 /
//! RHEL-09-432015 / RHEL-10-600540, ComplianceAsCode
//! `sudo_require_reauthentication`) and fires here
//! in two merged ways: ABSENT (no explicit `timestamp_timeout` anywhere -- the
//! STIG's PRIMARY trigger) and CONFLICTING (the key set to 2+ DISTINCT values
//! across the merged files, leaving the effective timeout ambiguous). A single
//! negative value is the per-file weakening above; a single non-negative value is
//! compliant.
//!
//! # Scope design
//!
//! Weakening-present checks fire for EVERY `Defaults` scope (global, `@host`,
//! `:user`, `!cmnd`, `>runas`). A scoped weakening (`Defaults:someuser
//! !authenticate`) is still a finding: any user that matches the scope can
//! run sudo without re-authentication.
//!
//! # Version-agnostic
//!
//! These findings apply across all supported RHEL versions (no `--target` rail;
//! the context struct carries no target field).

// Setting names appear as plain string literals throughout this module.
// Wrapping them all in backticks in comments would bury the signal.
#![allow(clippy::doc_markdown)]

use std::path::Path;

use rulesteward_core::{ControlRef, Diagnostic, Framework, Severity, Span};

use crate::ast::{DefaultsScope, LineKind, SudoersFile};
use crate::lints::{SudoersLintContext, anchored};

// ---------------------------------------------------------------------------
// Weakening settings: fire when any of these appear (any scope).
// ---------------------------------------------------------------------------

/// Non-negated settings that weaken the sudo security posture below the sudo
/// hardening baseline when present. Each tuple is
/// `(name_as_written, human_explanation, grounded_citation, typed_controls)`;
/// the citation (control id + framework) is appended to the diagnostic so an
/// operator can cross-reference the finding, and `typed_controls` is the SAME
/// mapping as typed `(Framework, id)` pairs (#503, v0.7) so the free-text
/// citation and the structured `ControlRef`s can never drift apart. It is
/// re-grounded per the module doc and pinned by
/// `tests::w04_weakening_findings_cite_grounded_controls` (the free text) and
/// `tests::w04_pw_family_findings_carry_stig_controls` (the typed form).
///
/// A `WEAKENING_PRESENT` row: `(name, explanation, citation, typed controls)`.
/// A type alias per `clippy::type_complexity` -- the inline 4-tuple-of-slices
/// form trips the lint.
type WeakeningRow = (
    &'static str,
    &'static str,
    &'static str,
    &'static [(Framework, &'static str)],
);

/// Note: `!authenticate` is NOT in this table because it is a NEGATED setting
/// (`DefaultSetting { negated: true, name: "authenticate" }`); it is handled
/// separately in `check_file`'s negated arm. This table covers settings that
/// are dangerous when present WITHOUT a `!` prefix.
const WEAKENING_PRESENT: &[WeakeningRow] = &[
    // targetpw: prompts for the target user's password rather than the invoking
    // user's -- breaks PAM accountability chain.
    (
        "targetpw",
        "prompts for the target user's password instead of the invoking user's; \
         breaks PAM accountability (re-auth must use the user's own credentials)",
        "DISA STIG RHEL-08-010383 / RHEL-09-432020 / RHEL-10-600550",
        &PW_FAMILY_CONTROLS,
    ),
    // rootpw: prompts for root's password -- also breaks accountability.
    (
        "rootpw",
        "prompts for the root password instead of the invoking user's; \
         breaks PAM accountability (re-auth must use the user's own credentials)",
        "DISA STIG RHEL-08-010383 / RHEL-09-432020 / RHEL-10-600550",
        &PW_FAMILY_CONTROLS,
    ),
    // runaspw: prompts for the run-as user's password.
    (
        "runaspw",
        "prompts for the run-as user's password instead of the invoking user's; \
         breaks PAM accountability (re-auth must use the user's own credentials)",
        "DISA STIG RHEL-08-010383 / RHEL-09-432020 / RHEL-10-600550",
        &PW_FAMILY_CONTROLS,
    ),
    // visiblepw: allows sudo when the password would be echoed in plain text.
    // No bare control id in the citation ("CIS / general hardening; not a DISA
    // STIG control"), so NO typed control is attached (#503 documented
    // exclusion; see `tests::w04_visiblepw_finding_has_no_controls`).
    (
        "visiblepw",
        "allows sudo to proceed when the password would be visible on the terminal; \
         the CIS / general hardening baseline requires this to be disabled",
        "CIS / general hardening; not a DISA STIG control",
        &[],
    ),
];

// ---------------------------------------------------------------------------
// Typed ControlRef mappings (#503, v0.7): one `const` per DISTINCT citation,
// shared by every emit site that cites it, so the typed form can never drift
// from the free-text citation at a second call site (grep the const name to
// find every site it backs).
// ---------------------------------------------------------------------------

/// `targetpw` / `rootpw` / `runaspw`: DISA STIG RHEL-08-010383 /
/// RHEL-09-432020 / RHEL-10-600550 (`WEAKENING_PRESENT` rows above).
/// RHEL-10-600550 (#563, 9i lane-7) grounded against the DISA RHEL 10 STIG
/// V1R1 XCCDF (Group V-281210 / SV-281210r1166582_rule, "RHEL 10 must use
/// the invoking user's password for privilege escalation when using
/// \"sudo\""; see `lane-7-sudoersids-report.md`).
const PW_FAMILY_CONTROLS: [(Framework, &str); 3] = [
    (Framework::Stig, "RHEL-08-010383"),
    (Framework::Stig, "RHEL-09-432020"),
    (Framework::Stig, "RHEL-10-600550"),
];

/// `!authenticate`: DISA STIG RHEL-08-010381 / RHEL-09-432025 /
/// RHEL-10-600530 (`check_file`'s negated arm). RHEL-10-600530 (#563, 9i
/// lane-7) grounded against the DISA RHEL 10 STIG V1R1 XCCDF (Group
/// V-281208 / SV-281208r1166576_rule, "RHEL 10 must require users to
/// reauthenticate for privilege escalation"; see
/// `lane-7-sudoersids-report.md`).
const AUTHENTICATE_CONTROLS: [(Framework, &str); 3] = [
    (Framework::Stig, "RHEL-08-010381"),
    (Framework::Stig, "RHEL-09-432025"),
    (Framework::Stig, "RHEL-10-600530"),
];

/// The verbatim CaC title for a product-invariant CIS control id, drawn from
/// the single-source `lints::cis` table (#526: the `use_pty` / I/O-logging
/// `Framework::Cis` refs below never re-type a title literal -- they look it
/// up here). `use_pty` (5.2.2) and I/O-logging (5.2.3) are PRODUCT-INVARIANT
/// (see `lints::cis` module doc), so any target yields the same title;
/// `Rhel8` is used arbitrarily.
fn cis_title(id: &str) -> &'static str {
    crate::lints::cis::cis_baseline(crate::lints::cis::TargetVersion::Rhel8)
        .iter()
        .find(|c| c.id == id)
        .unwrap_or_else(|| panic!("lints::cis::cis_baseline must contain {id}"))
        .title
}

/// `use_pty`: CIS Benchmark 5.2.2 (RENUMBERED #526, LOCKED post-A0
/// 2026-07-18, was the stale "1.3.2"; id + title drawn from `lints::cis`) /
/// PCI-DSS Req-10.2.5 (unaffected by the renumber, no title). Shared by the
/// per-file `!use_pty` negation (`check_file`) and the merged
/// missing-`use_pty` (`check_merged_required`) findings -- same control, two
/// emit sites.
fn use_pty_controls() -> Vec<ControlRef> {
    vec![
        ControlRef::new(Framework::Cis, "5.2.2").with_name(cis_title("5.2.2")),
        ControlRef::new(Framework::Pci, "Req-10.2.5"),
    ]
}

/// I/O logging (`logfile=` / `log_output`): CIS Benchmark 5.2.3 (RENUMBERED
/// #526, LOCKED post-A0 2026-07-18, was the stale "1.3.3"; id + title drawn
/// from `lints::cis`) / PCI-DSS Req-10.2.5 (unaffected by the renumber, no
/// title) (`check_merged_required`'s missing-I/O-log finding).
fn io_log_controls() -> Vec<ControlRef> {
    vec![
        ControlRef::new(Framework::Cis, "5.2.3").with_name(cis_title("5.2.3")),
        ControlRef::new(Framework::Pci, "Req-10.2.5"),
    ]
}

/// `timestamp_timeout`: DISA STIG RHEL-08-010384 / RHEL-09-432015 /
/// RHEL-10-600540. Shared by the per-file NEGATIVE-value weakening
/// (`check_file`) and the merged ABSENT/CONFLICTING findings
/// (`check_merged_required`) -- same control, three emit sites.
/// RHEL-10-600540 (#563, 9i lane-7) grounded against the DISA RHEL 10 STIG
/// V1R1 XCCDF (Group V-281209 / SV-281209r1166579_rule, "RHEL 10 must
/// require reauthentication when using the \"sudo\" command"; see
/// `lane-7-sudoersids-report.md`).
const TIMESTAMP_TIMEOUT_CONTROLS: [(Framework, &str); 3] = [
    (Framework::Stig, "RHEL-08-010384"),
    (Framework::Stig, "RHEL-09-432015"),
    (Framework::Stig, "RHEL-10-600540"),
];

/// Build the typed `ControlRef` vec for a `(Framework, id)` pair slice. The
/// single conversion point every emit site's `.with_controls(controls(&X))`
/// call goes through.
pub(crate) fn controls(pairs: &[(Framework, &str)]) -> Vec<ControlRef> {
    pairs
        .iter()
        .map(|&(framework, id)| ControlRef::new(framework, id))
        .collect()
}

/// sudo-W04: a `Defaults` setting is weaker than the sudo STIG baseline.
///
/// # Checks
///
/// **Weakening present** (per-file, [`check_file`]): `!authenticate` (any scope),
/// `targetpw`, `rootpw`, `runaspw`, `visiblepw`, `!use_pty`, and a NEGATIVE
/// `timestamp_timeout` -- fires at the offending `Defaults` line.
///
/// **Missing required / conflicting** (merged, [`check_merged_required`], #347,
/// #363): fires once at the top-level file if a positive `use_pty` is not set
/// anywhere in the resolved tree, once if no I/O logging (`logfile=` or
/// `log_output`) is set anywhere, once if `timestamp_timeout` is set nowhere, and
/// once if `timestamp_timeout` is set to 2+ distinct values across the merged files.
///
/// See module-level doc for grounding and scope design.
#[must_use]
pub fn w04(files: &[SudoersFile], _ctx: &SudoersLintContext) -> Vec<Diagnostic> {
    let mut diags = Vec::new();
    for file in files {
        diags.extend(check_file(file));
    }
    diags.extend(check_merged_required(files));
    diags
}

/// Run all W04 checks for one file.
fn check_file(file: &SudoersFile) -> Vec<Diagnostic> {
    let mut diags = Vec::new();

    for line in &file.lines {
        let LineKind::Defaults(defaults) = &line.kind else {
            continue;
        };

        for setting in &defaults.settings {
            let name = setting.name.as_str();

            // --- Negated checks ---
            if setting.negated {
                if let Some(d) = negated_weakening(
                    name,
                    &defaults.scope,
                    line.span.clone(),
                    &file.path,
                    line.line,
                ) {
                    diags.push(d);
                }
                continue; // done with this negated setting
            }

            // --- Non-negated checks ---

            // `timestamp_timeout` with a NEGATIVE value: a value-conditional
            // weakening (not mere name-presence), so it is handled here rather than
            // via the `WEAKENING_PRESENT` name table. A negative timeout (e.g. -1)
            // makes the sudo credential cache NEVER expire, so a user re-authenticates
            // once and is then trusted indefinitely. A non-negative value (0 or
            // positive) is compliant. DISA STIG RHEL-08-010384 / RHEL-09-432015 /
            // RHEL-10-600540.
            if name == "timestamp_timeout"
                && setting
                    .value
                    .as_deref()
                    .and_then(parse_signed_minutes)
                    .is_some_and(|v| v < 0.0)
            {
                diags.push(
                    anchored(
                        Severity::Warning,
                        "sudo-W04",
                        line.span.clone(),
                        format!(
                            "Defaults setting 'timestamp_timeout' {} sets a negative value: \
                             the sudo credential cache never expires, so a user is \
                             re-authenticated once and trusted indefinitely; STIG requires \
                             re-authentication (a non-negative timeout) \
                             (DISA STIG RHEL-08-010384 / RHEL-09-432015 / RHEL-10-600540)",
                            scope_paren(&defaults.scope),
                        ),
                        &file.path,
                        line.line,
                    )
                    .with_controls(controls(&TIMESTAMP_TIMEOUT_CONTROLS)),
                );
            }

            // Fire for weakening non-negated settings (all entries in the table;
            // `!authenticate` is handled in the negated arm above).
            for &(weakening_name, explanation, citation, row_controls) in WEAKENING_PRESENT {
                if name == weakening_name {
                    diags.push(
                        anchored(
                            Severity::Warning,
                            "sudo-W04",
                            line.span.clone(),
                            format!(
                                "Defaults setting '{name}' {} weakens sudo security: \
                                 {explanation} ({citation})",
                                scope_paren(&defaults.scope),
                            ),
                            &file.path,
                            line.line,
                        )
                        .with_controls(controls(row_controls)),
                    );
                }
            }
        }
    }

    diags
}

/// Build the diagnostic for a NEGATED weakening setting (`!authenticate` /
/// `!use_pty`), or `None` for any other negated setting. Factored out of
/// [`check_file`] to keep it under clippy's line-count gate; the message text
/// and typed controls are unchanged from the inline arms this replaces.
fn negated_weakening(
    name: &str,
    scope: &DefaultsScope,
    span: Span,
    file: &Path,
    line_no: usize,
) -> Option<Diagnostic> {
    match name {
        // `!authenticate`: disables per-invocation password re-authentication.
        // DISA STIG RHEL-08-010381 / RHEL-09-432025 / RHEL-10-600530.
        "authenticate" => Some(
            anchored(
                Severity::Warning,
                "sudo-W04",
                span,
                format!(
                    "Defaults setting '!authenticate' {} disables \
                     per-invocation sudo re-authentication; \
                     STIG requires authentication for every invocation \
                     (DISA STIG RHEL-08-010381 / RHEL-09-432025 / RHEL-10-600530)",
                    scope_paren(scope),
                ),
                file,
                line_no,
            )
            .with_controls(controls(&AUTHENTICATE_CONTROLS)),
        ),
        // `!use_pty`: explicit negation of the pty requirement.
        // CIS Benchmark 5.2.2 / PCI-DSS Req-10.2.5; no DISA sudo STIG control.
        "use_pty" => Some(
            anchored(
                Severity::Warning,
                "sudo-W04",
                span,
                format!(
                    "Defaults setting '!use_pty' {} disables \
                     pseudo-terminal allocation; the CIS / PCI hardening \
                     baseline requires 'Defaults use_pty' to prevent I/O \
                     redirection attacks \
                     (CIS Benchmark 5.2.2 / PCI-DSS Req-10.2.5; \
                     not a DISA STIG control)",
                    scope_paren(scope),
                ),
                file,
                line_no,
            )
            .with_controls(use_pty_controls()),
        ),
        _ => None,
    }
}

/// Scan the merged file set for the presence signals [`check_merged_required`]
/// needs: whether a positive `use_pty` / I/O-logging setting appears ANYWHERE,
/// whether a negated `!timestamp_timeout` clear appears anywhere, and the set
/// of DISTINCT `timestamp_timeout` values seen (first-seen order). Factored out
/// of `check_merged_required` to keep it under clippy's line-count gate; the
/// scanning logic is unchanged from the loop this replaces.
///
/// Returns `(has_use_pty, has_io_log, has_negated_timestamp_timeout,
/// distinct_timestamp_values)`.
///
/// Distinct `timestamp_timeout` values are canonicalised through
/// `parse_signed_minutes` and re-rendered so `=5` / `=05` / `=5.0` collapse to
/// one entry (they ARE the same timeout); the canonical strings are the dedup
/// key, avoiding fragile direct `f64` equality. The key is built from `v + 0.0`
/// so signed zero normalizes (`-0.0` -> `0.0`), preventing a spurious `=0` vs
/// `=-0` "conflict" (both are the same compliant value, 0). A negated
/// `Defaults !timestamp_timeout` clears the timeout, which sudo treats as
/// re-prompt-on-every-invocation -- functionally identical to `=0` and
/// therefore COMPLIANT (#363 user decision); it SATISFIES the presence/absence
/// requirement but contributes NO value to conflict detection and fires no
/// weakening, so it is tracked separately from the positive-value list.
fn scan_merged_settings(files: &[SudoersFile]) -> (bool, bool, bool, Vec<String>) {
    let mut has_use_pty = false;
    let mut has_io_log = false;
    let mut has_negated_timestamp_timeout = false;
    let mut timestamp_values: Vec<String> = Vec::new();
    for file in files {
        for line in &file.lines {
            let LineKind::Defaults(defaults) = &line.kind else {
                continue;
            };
            for setting in &defaults.settings {
                if setting.negated {
                    // A negated `timestamp_timeout` is a COMPLIANT clear (counts as
                    // present, no value, no conflict). Every other negated setting
                    // (`!use_pty` / `!log_output`) is a clear, not a positive set, so
                    // it does not satisfy its requirement.
                    if setting.name == "timestamp_timeout" {
                        has_negated_timestamp_timeout = true;
                    }
                    continue;
                }
                match setting.name.as_str() {
                    "use_pty" => has_use_pty = true,
                    "logfile" | "log_output" => has_io_log = true,
                    "timestamp_timeout" => {
                        if let Some(v) = setting.value.as_deref().and_then(parse_signed_minutes) {
                            // Normalize signed zero (`-0.0` -> `0.0`) before keying.
                            let canonical = (v + 0.0).to_string();
                            if !timestamp_values.contains(&canonical) {
                                timestamp_values.push(canonical);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    (
        has_use_pty,
        has_io_log,
        has_negated_timestamp_timeout,
        timestamp_values,
    )
}

/// sudo-W04 missing-required hardening, checked over the MERGED resolved slice
/// (#347, #363). Unlike the per-file weakening checks in [`check_file`], this runs
/// ONCE across every file `resolve_target` produced (the top-level file plus its
/// `@include`/`@includedir` drop-ins) and fires:
///
/// * once if a positive `use_pty` is not set ANYWHERE in the tree,
/// * once if no I/O logging (`logfile=` or `log_output`) is set anywhere,
/// * once if `timestamp_timeout` is set NOWHERE in the tree (#363, the STIG's
///   primary trigger), and
/// * once if `timestamp_timeout` is set to 2+ DISTINCT values across the merged
///   files (#363, an ambiguous effective timeout). Because the sudoers model
///   retains every parsed occurrence (no last-wins collapse), the distinct values
///   are detectable directly from the merged AST.
///
/// Running over the merged set (not per-file) is what prevents the per-fragment
/// false positive a naive per-file check produces: a `sudoers.d` drop-in must not
/// be flagged for "missing use_pty" when the main `/etc/sudoers` sets it. This
/// mirrors the sshd-W01 merged-config required-directive check.
///
/// # Grounded semantics
///
/// * **Negation never satisfies.** A `!use_pty` / `!log_output` is a deliberate
///   weakening (already a per-file finding); it does NOT count as positively set,
///   so an explicit `Defaults !use_pty` correctly draws both a weakening finding
///   and this absence finding.
/// * **Any scope satisfies.** A positive `use_pty` in any scope (global or
///   `Defaults:user` / `@host` / ...) counts. This matches the CIS audit check,
///   which greps for any `use_pty` occurrence rather than requiring a
///   global-scope setting.
/// * **I/O logging alternatives.** Per `sudoers(5)`, `log_output` enables
///   pseudo-terminal session logging and `logfile` sets the sudo log destination;
///   either satisfies the requirement (matching issue #347's scope). `log_input`
///   alone is intentionally not counted.
///
/// Absence findings anchor at the top-level file (`files[0]`) with the missing-key
/// convention (span `0..0`, line `0`): there is no offending line to caret.
fn check_merged_required(files: &[SudoersFile]) -> Vec<Diagnostic> {
    let Some(top) = files.first() else {
        // No resolved files at all -> nothing to require against.
        return Vec::new();
    };

    let (has_use_pty, has_io_log, has_negated_timestamp_timeout, timestamp_values) =
        scan_merged_settings(files);

    let mut diags = Vec::new();
    if !has_use_pty {
        diags.push(
            anchored(
                Severity::Warning,
                "sudo-W04",
                0..0,
                "required 'Defaults use_pty' is not set anywhere in the resolved \
                 sudoers configuration; without it sudo does not allocate a \
                 pseudo-terminal, leaving privileged sessions open to I/O redirection \
                 (CIS Benchmark 5.2.2 / PCI-DSS Req-10.2.5; not a DISA STIG control)",
                &top.path,
                0,
            )
            .with_controls(use_pty_controls()),
        );
    }
    if !has_io_log {
        diags.push(
            anchored(
                Severity::Warning,
                "sudo-W04",
                0..0,
                "required sudo I/O logging is not configured anywhere in the resolved \
                 sudoers configuration (no 'Defaults logfile=' or 'Defaults \
                 log_output'); privileged command sessions are not recorded for audit \
                 (CIS Benchmark 5.2.3 / PCI-DSS Req-10.2.5; not a DISA STIG control)",
                &top.path,
                0,
            )
            .with_controls(io_log_controls()),
        );
    }
    // timestamp_timeout (#363, DISA STIG RHEL-08-010384 / RHEL-09-432015 /
    // RHEL-10-600540, ComplianceAsCode `sudo_require_reauthentication`):
    //
    // * ABSENT (no explicit `Defaults timestamp_timeout=` anywhere) is the STIG's
    //   PRIMARY trigger: the compiled-in default applies and the requirement is not
    //   demonstrably met by the configuration.
    // * CONFLICTING (2+ DISTINCT values across the merged files) leaves the
    //   effective timeout ambiguous, which the STIG also flags.
    //
    // A single non-negative value is compliant (a single negative value is the
    // per-file weakening handled in `check_file`). A negated `!timestamp_timeout`
    // anywhere is a compliant clear that satisfies the requirement (so ABSENT does
    // not fire) but never contributes to the distinct-value set, so it cannot create
    // a conflict.
    match timestamp_values.as_slice() {
        // No POSITIVE value set. If a negated clear is present that is compliant
        // (requirement satisfied); otherwise the requirement is genuinely absent.
        [] if !has_negated_timestamp_timeout => diags.push(
            anchored(
                Severity::Warning,
                "sudo-W04",
                0..0,
                "required 'Defaults timestamp_timeout' is not set anywhere in the \
                 resolved sudoers configuration; without an explicit re-authentication \
                 timeout sudo relies on the compiled-in default, so the policy does not \
                 demonstrably require re-authentication \
                 (DISA STIG RHEL-08-010384 / RHEL-09-432015 / RHEL-10-600540)",
                &top.path,
                0,
            )
            .with_controls(controls(&TIMESTAMP_TIMEOUT_CONTROLS)),
        ),
        [] => {}        // negated `!timestamp_timeout` only: compliant clear, nothing fires.
        [_single] => {} // exactly one value: unambiguous (compliance handled elsewhere).
        _multiple => diags.push(
            anchored(
                Severity::Warning,
                "sudo-W04",
                0..0,
                "conflicting 'Defaults timestamp_timeout' values are set across the \
                 resolved sudoers configuration (the key is given more than one distinct \
                 value); the effective re-authentication timeout is ambiguous \
                 (DISA STIG RHEL-08-010384 / RHEL-09-432015 / RHEL-10-600540)",
                &top.path,
                0,
            )
            .with_controls(controls(&TIMESTAMP_TIMEOUT_CONTROLS)),
        ),
    }
    diags
}

/// Parse a `timestamp_timeout` value as a signed (and possibly fractional) number
/// of minutes. `sudoers(5)` accepts an integer or a fractional value (e.g. `0.5`),
/// and a value `< 0` means the credential cache never expires. Returns `None` when
/// the value is not a usable finite number (a malformed value is not this check's
/// concern).
///
/// This is a tiny `f64` parse, not a new value-interpreter: the sudoers AST stores
/// the raw `name=value` string. `f64::from_str` is STRICTLY BROADER than sudo's own
/// parser -- it also accepts `inf` / `infinity` / `nan`, which sudo rejects (verified
/// via `visudo -c`). We filter those surplus forms out with `is_finite()` so a
/// non-finite token returns `None` (no usable timeout) rather than a poisonous
/// `NaN`/`inf` that would break the conflict-dedup numeric comparison. Never panics.
fn parse_signed_minutes(value: &str) -> Option<f64> {
    value.trim().parse::<f64>().ok().filter(|v| v.is_finite())
}

/// Human-readable parenthetical naming the `Defaults` scope, used in diagnostic
/// messages. A global `Defaults` reads naturally as `(global scope)`; a scoped
/// `Defaults` names the binding, e.g. `(user:alice scope)` / `(host:web1 scope)`.
fn scope_paren(scope: &DefaultsScope) -> String {
    match scope {
        DefaultsScope::Global => "(global scope)".to_string(),
        DefaultsScope::Host(h) => format!("(host:{h} scope)"),
        DefaultsScope::User(u) => format!("(user:{u} scope)"),
        DefaultsScope::Cmnd(c) => format!("(cmnd:{c} scope)"),
        DefaultsScope::Runas(r) => format!("(runas:{r} scope)"),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lints::SudoersLintContext;
    use crate::parser::parse;
    use crate::resolve;
    use std::path::Path;

    const CTX: SudoersLintContext = SudoersLintContext {};
    const SUDOERS_PATH: &str = "/etc/sudoers";

    /// Parse a single sudoers source string into a one-element slice.
    fn parse_one(src: &str) -> Vec<SudoersFile> {
        vec![parse(src, Path::new(SUDOERS_PATH))]
    }

    /// Parse several `(path, source)` pairs into a merged slice, in evaluation
    /// order -- the shape `resolve_target` produces for a main file plus its
    /// `@include`/`@includedir` drop-ins. `parts[0]` is the top-level file.
    fn parse_files(parts: &[(&str, &str)]) -> Vec<SudoersFile> {
        parts.iter().map(|(p, s)| parse(s, Path::new(p))).collect()
    }

    /// W04 absence findings (the merged missing-required check) anchor at line 0
    /// (the missing-key convention); weakening-present findings sit at the real
    /// `Defaults` line (>= 1). The line number is the discriminator.
    fn w04_absence(diags: &[Diagnostic]) -> Vec<&Diagnostic> {
        diags
            .iter()
            .filter(|d| d.code == "sudo-W04" && d.line == 0)
            .collect()
    }

    /// Run w04 on a source string and return the diagnostics.
    fn lint_w04(src: &str) -> Vec<Diagnostic> {
        let files = parse_one(src);
        w04(&files, &CTX)
    }

    /// Extract only the W04 codes from a diagnostic list.
    fn w04_codes(diags: &[Diagnostic]) -> Vec<&str> {
        diags
            .iter()
            .filter(|d| d.code == "sudo-W04")
            .map(|d| d.code.as_ref())
            .collect()
    }

    // -----------------------------------------------------------------------
    // Weakening-present: !authenticate
    // -----------------------------------------------------------------------

    /// `Defaults !authenticate` fires W04.
    ///
    /// Grounding: DISA STIG RHEL-08-010381 / RHEL-09-432025.
    /// Fixture verified valid by `visudo -c`.
    #[test]
    fn w04_fires_for_not_authenticate_global() {
        // Fixture: Defaults !authenticate (global scope).
        // visudo -c: "parsed OK"
        let diags = lint_w04("Defaults !authenticate\nroot ALL=(ALL:ALL) ALL\n");
        let w04_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-W04").collect();
        assert!(
            w04_diags
                .iter()
                .any(|d| d.message.contains("!authenticate")),
            "W04 must fire for 'Defaults !authenticate'; got {diags:?}"
        );
    }

    /// Scoped `Defaults:someuser !authenticate` still fires W04.
    /// A per-user weakening is still a finding.
    ///
    /// Grounding: DISA STIG RHEL-08-010381 / RHEL-09-432025.
    /// Fixture verified valid by `visudo -c`.
    #[test]
    fn w04_fires_for_not_authenticate_user_scope() {
        // Fixture: Defaults:someuser !authenticate
        // visudo -c: "parsed OK"
        let diags = lint_w04("Defaults:someuser !authenticate\nroot ALL=(ALL:ALL) ALL\n");
        let w04_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-W04").collect();
        assert!(
            w04_diags
                .iter()
                .any(|d| d.message.contains("!authenticate")),
            "W04 must fire for scoped 'Defaults:someuser !authenticate'; got {diags:?}"
        );
        assert!(
            w04_diags
                .iter()
                .any(|d| d.message.contains("user:someuser")),
            "W04 message must name the scope 'user:someuser'; got {w04_diags:?}"
        );
    }

    /// The W04 `!authenticate` diagnostic anchors at the offending line (not line 0).
    #[test]
    fn w04_not_authenticate_anchors_at_defaults_line() {
        let diags = lint_w04("Defaults !authenticate\nroot ALL=(ALL:ALL) ALL\n");
        let w04_diags: Vec<_> = diags
            .iter()
            .filter(|d| d.code == "sudo-W04" && d.message.contains("!authenticate"))
            .collect();
        assert_eq!(
            w04_diags.len(),
            1,
            "exactly one W04 for !authenticate; got {w04_diags:?}"
        );
        assert_eq!(
            w04_diags[0].line, 1,
            "W04 must anchor at line 1 (the Defaults line)"
        );
    }

    // -----------------------------------------------------------------------
    // Weakening-present: targetpw / rootpw / runaspw
    // -----------------------------------------------------------------------

    /// `Defaults targetpw` fires W04.
    ///
    /// Grounding: DISA STIG RHEL-08-010383 / RHEL-09-432020.
    /// Fixture verified valid by `visudo -c`.
    #[test]
    fn w04_fires_for_targetpw() {
        // Fixture: Defaults targetpw
        // visudo -c: "parsed OK"
        let diags = lint_w04("Defaults targetpw\nroot ALL=(ALL:ALL) ALL\n");
        let w04_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-W04").collect();
        assert!(
            w04_diags.iter().any(|d| d.message.contains("targetpw")),
            "W04 must fire for 'Defaults targetpw'; got {diags:?}"
        );
    }

    /// `Defaults rootpw` fires W04.
    ///
    /// Grounding: DISA STIG RHEL-08-010383 / RHEL-09-432020.
    /// Fixture verified valid by `visudo -c`.
    #[test]
    fn w04_fires_for_rootpw() {
        // Fixture: Defaults rootpw
        // visudo -c: "parsed OK"
        let diags = lint_w04("Defaults rootpw\nroot ALL=(ALL:ALL) ALL\n");
        let w04_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-W04").collect();
        assert!(
            w04_diags.iter().any(|d| d.message.contains("rootpw")),
            "W04 must fire for 'Defaults rootpw'; got {diags:?}"
        );
    }

    /// `Defaults runaspw` fires W04.
    ///
    /// Grounding: DISA STIG RHEL-08-010383 / RHEL-09-432020.
    /// Fixture verified valid by `visudo -c`.
    #[test]
    fn w04_fires_for_runaspw() {
        // Fixture: Defaults runaspw
        // visudo -c: "parsed OK"
        let diags = lint_w04("Defaults runaspw\nroot ALL=(ALL:ALL) ALL\n");
        let w04_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-W04").collect();
        assert!(
            w04_diags.iter().any(|d| d.message.contains("runaspw")),
            "W04 must fire for 'Defaults runaspw'; got {diags:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Weakening-present: visiblepw
    // -----------------------------------------------------------------------

    /// `Defaults visiblepw` fires W04.
    ///
    /// Grounding: CIS / general hardening; no DISA sudo STIG control.
    /// Fixture verified valid by `visudo -c`.
    #[test]
    fn w04_fires_for_visiblepw() {
        // Fixture: Defaults visiblepw
        // visudo -c: "parsed OK"
        let diags = lint_w04("Defaults visiblepw\nroot ALL=(ALL:ALL) ALL\n");
        let w04_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-W04").collect();
        assert!(
            w04_diags.iter().any(|d| d.message.contains("visiblepw")),
            "W04 must fire for 'Defaults visiblepw'; got {diags:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Weakening-present: !use_pty
    // -----------------------------------------------------------------------

    /// `Defaults !use_pty` fires W04 (explicit negation of the pty requirement).
    ///
    /// Grounding: CIS Benchmark 5.2.2 / PCI-DSS Req-10.2.5; no DISA sudo STIG control.
    /// Fixture verified valid by `visudo -c`.
    #[test]
    fn w04_fires_for_not_use_pty_explicit() {
        // Fixture: Defaults !use_pty (explicit negation)
        // visudo -c: "parsed OK"
        let diags = lint_w04("Defaults !use_pty\nroot ALL=(ALL:ALL) ALL\n");
        let w04_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-W04").collect();
        assert!(
            w04_diags
                .iter()
                .any(|d| d.message.contains("!use_pty") || d.message.contains("use_pty")),
            "W04 must fire for explicit '!use_pty'; got {diags:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Grounding drift-guard: each W04 weakening finding cites the CORRECT
    // control id / framework.
    // -----------------------------------------------------------------------

    /// Each W04 weakening finding must cite its grounded control id / framework.
    ///
    /// Re-grounded 2026-06-29 against ComplianceAsCode/content commit
    /// `65ccea603ee2c305fdb4c6f54cb911449d969d55` (`stigid@ol8` keys) + DISA
    /// stigviewer (RHEL 8 V2R7 / RHEL 9 4320xx cluster):
    /// - `!authenticate` -> DISA STIG RHEL-08-010381 / RHEL-09-432025
    /// - `targetpw` / `rootpw` / `runaspw` -> DISA STIG RHEL-08-010383 / RHEL-09-432020
    /// - `use_pty` (incl. `!use_pty`) -> CIS Benchmark 5.2.2 / PCI-DSS Req-10.2.5
    ///   (no DISA sudo STIG control)
    /// - `visiblepw` -> CIS / general hardening (no DISA STIG control)
    /// - `timestamp_timeout` (negative value) -> DISA STIG RHEL-08-010384 /
    ///   RHEL-09-432015 (ComplianceAsCode `sudo_require_reauthentication`, #363)
    ///
    /// If this fails, RE-RUN the grounding pass against a pinned ComplianceAsCode
    /// commit + DISA -- do NOT just edit the string to make it pass (#355, #359, #363).
    ///
    /// `use_pty`'s CIS id is RENUMBERED (#526, LOCKED post-A0 2026-07-18): the
    /// stale "1.3.2" (an older CIS benchmark generation's numbering, surviving
    /// in ComplianceAsCode only as a `cis@sle12`/`cis@sle15` rule reference) is
    /// WRONG for the pinned commit `519b5fe8ce338cfa25d53065bcb3759aafe8d36d`,
    /// whose `sudo_add_use_pty` control anchors at "5.2.2" (uniform across
    /// rhel8/rhel9/rhel10; see `lints::cis`). RED until the implementer swaps
    /// the `USE_PTY_CONTROLS` id and the matching message-text literal.
    #[test]
    fn w04_weakening_findings_cite_grounded_controls() {
        // Each finding's message must contain the grounded citation.
        let must_cite = [
            ("Defaults !authenticate\n", "RHEL-08-010381"),
            ("Defaults !authenticate\n", "RHEL-09-432025"),
            ("Defaults targetpw\n", "RHEL-08-010383"),
            ("Defaults targetpw\n", "RHEL-09-432020"),
            ("Defaults rootpw\n", "RHEL-08-010383"),
            ("Defaults runaspw\n", "RHEL-08-010383"),
            ("Defaults !use_pty\n", "CIS Benchmark 5.2.2"),
            ("Defaults !use_pty\n", "PCI-DSS Req-10.2.5"),
            ("Defaults visiblepw\n", "CIS / general hardening"),
            // timestamp_timeout negative value (#363): per-file weakening finding.
            ("Defaults timestamp_timeout=-1\n", "RHEL-08-010384"),
            ("Defaults timestamp_timeout=-1\n", "RHEL-09-432015"),
        ];
        for (defaults, needle) in must_cite {
            let src = format!("{defaults}root ALL=(ALL:ALL) ALL\n");
            let diags = lint_w04(&src);
            assert!(
                diags
                    .iter()
                    .any(|d| d.code == "sudo-W04" && d.message.contains(needle)),
                "W04 finding for {defaults:?} must cite '{needle}'; got {diags:?}"
            );
        }

        // The mis-grounded ids found in #355/#359 must NOT reappear in their
        // respective findings (the swapped pair, and the bogus use_pty STIG id).
        // The #526 entries guard the RENUMBER regression direction: the stale CIS
        // ids "1.3.2"/"1.3.3" must not survive the swap to "5.2.2"/"5.2.3" -- one
        // guard per renumbered anchor (use_pty AND I/O-logging), mirroring each
        // other so neither renumber can silently regress alone.
        let must_not_cite = [
            ("Defaults !authenticate\n", "010383"), // swapped: !authenticate is 010381
            ("Defaults targetpw\n", "010381"),      // swapped: pw family is 010383
            ("Defaults !use_pty\n", "RHEL-08-010382"), // use_pty has no DISA STIG id
            ("Defaults !use_pty\n", "RHEL-09-432020"), // 432020 is the pw control, not use_pty
            ("Defaults !use_pty\n", "1.3.2"), // #526 renumber: the stale CIS id must not reappear
            // I/O-log-absent fixture (use_pty + timestamp_timeout set, no
            // logfile/log_output -- the same fixture
            // `w04_missing_io_log_finding_carries_cis_and_pci_controls` uses):
            // the stale "1.3.3" must not survive the swap to "5.2.3" either.
            ("Defaults use_pty\nDefaults timestamp_timeout=5\n", "1.3.3"), // #526 renumber: the stale I/O-log CIS id must not reappear
        ];
        for (defaults, bad) in must_not_cite {
            let src = format!("{defaults}root ALL=(ALL:ALL) ALL\n");
            let diags = lint_w04(&src);
            assert!(
                diags
                    .iter()
                    .filter(|d| d.code == "sudo-W04")
                    .all(|d| !d.message.contains(bad)),
                "W04 finding for {defaults:?} must NOT cite the mis-grounded '{bad}'; got {diags:?}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Typed ControlRef backfill (#503, v0.7): each W04 weakening finding
    // gains typed `rulesteward_core::ControlRef` entries mirroring its
    // free-text citation (frozen above and pinned by
    // `w04_weakening_findings_cite_grounded_controls`). Messages stay
    // BYTE-IDENTICAL; only `Diagnostic::controls` is populated. RED until the
    // implementer wires `.with_controls(...)` at each emit site.
    // -----------------------------------------------------------------------

    /// The `targetpw` / `rootpw` / `runaspw` pw-family weakenings ALL cite the
    /// SAME control, DISA STIG RHEL-08-010383 / RHEL-09-432020 / RHEL-10-600550
    /// (`WEAKENING_PRESENT` rows at stig.rs:116/123/130), and all fire from the
    /// SAME generic loop (stig.rs:258-273). Each finding must carry THREE typed
    /// `ControlRef`s, all `Framework::Stig`, in citation order (RHEL-08, then
    /// RHEL-09, then RHEL-10). Looping over all THREE fixtures (mirroring the
    /// `w04_weakening_findings_cite_grounded_controls` drift-guard, which
    /// enumerates the same three) closes the omission survivor: a wrong impl
    /// that keys controls off the tested NAME (`"targetpw" => pair, _ => []`)
    /// would pass a targetpw-only test yet ship rootpw + runaspw empty. The
    /// mutation gate cannot backstop an omission, so it is pinned here.
    ///
    /// #563 (9i lane-7): extended from a dual RHEL-08/RHEL-09 pin to a triple
    /// RHEL-08/RHEL-09/RHEL-10 pin (was `len() == 2`, `controls[0]`/`[1]`
    /// only) -- `RHEL-10-600550` grounded against the DISA RHEL 10 STIG V1R1
    /// XCCDF (Group V-281210 / SV-281210r1166582_rule, "RHEL 10 must use the
    /// invoking user's password for privilege escalation when using
    /// \"sudo\""; see `lane-7-sudoersids-report.md`). This is an EXHAUSTIVE
    /// length assertion that the RHEL-10 addition breaks, so it is updated in
    /// place per the discipline in the lane-7 brief rather than left stale-red.
    #[test]
    fn w04_pw_family_findings_carry_stig_controls() {
        use rulesteward_core::Framework;

        for name in ["targetpw", "rootpw", "runaspw"] {
            let src = format!("Defaults {name}\nroot ALL=(ALL:ALL) ALL\n");
            let diags = lint_w04(&src);
            let finding = diags
                .iter()
                .find(|d| d.code == "sudo-W04" && d.message.contains(name))
                .unwrap_or_else(|| panic!("W04 fires for {name}"));
            assert_eq!(
                finding.controls.len(),
                3,
                "{name}'s triple RHEL-08/RHEL-09/RHEL-10 citation must become \
                 three ControlRefs; got {:?}",
                finding.controls
            );
            assert_eq!(finding.controls[0].framework, Framework::Stig);
            assert_eq!(finding.controls[0].id, "RHEL-08-010383");
            assert_eq!(finding.controls[1].framework, Framework::Stig);
            assert_eq!(finding.controls[1].id, "RHEL-09-432020");
            assert_eq!(finding.controls[2].framework, Framework::Stig);
            assert_eq!(finding.controls[2].id, "RHEL-10-600550");
        }
    }

    /// `Defaults !use_pty` cites CIS Benchmark 5.2.2 AND PCI-DSS Req-10.2.5
    /// (stig.rs:211-212, the negated `use_pty` arm of `check_file`). The dual
    /// CROSS-framework citation must become TWO typed `ControlRef`s: one
    /// `Framework::Cis` (id `"5.2.2"`, RENUMBERED #526 -- LOCKED post-A0
    /// 2026-07-18, was the stale "1.3.2"; see `lints::cis`) carrying the CaC
    /// title via `.with_name(..)`, and one `Framework::Pci` (bare id
    /// `"Req-10.2.5"`, unaffected by the renumber, no name), in citation order
    /// (CIS first, then PCI, matching the message text's
    /// "CIS Benchmark ... / PCI-DSS ..." order). RED until the implementer
    /// swaps `USE_PTY_CONTROLS`'s id to "5.2.2" and attaches the title.
    #[test]
    fn w04_not_use_pty_finding_carries_cis_and_pci_controls() {
        use rulesteward_core::Framework;

        let diags = lint_w04("Defaults !use_pty\nroot ALL=(ALL:ALL) ALL\n");
        let finding = diags
            .iter()
            .find(|d| d.code == "sudo-W04" && d.message.contains("use_pty"))
            .expect("W04 fires for !use_pty");
        assert_eq!(
            finding.controls.len(),
            2,
            "!use_pty's CIS+PCI citation must become two ControlRefs; got {:?}",
            finding.controls
        );
        assert_eq!(finding.controls[0].framework, Framework::Cis);
        assert_eq!(
            finding.controls[0].id, "5.2.2",
            "#526 renumber: use_pty's CIS id is 5.2.2 (was the stale 1.3.2)"
        );
        assert_eq!(
            finding.controls[0].name.as_deref(),
            Some("Ensure sudo commands use pty (Automated)"),
            "#526: the renumbered CIS ref carries the verbatim CaC title via .with_name(..)"
        );
        assert_eq!(finding.controls[1].framework, Framework::Pci);
        assert_eq!(finding.controls[1].id, "Req-10.2.5");
        assert!(
            finding.controls[1].name.is_none(),
            "the bare PCI ref carries no name (only the renumbered CIS ref gains \
             one via .with_name(..)); got {:?}",
            finding.controls[1].name
        );
    }

    /// `Defaults !authenticate` cites DISA STIG RHEL-08-010381 AND
    /// RHEL-09-432025 AND RHEL-10-600530 (stig.rs:192, the negated
    /// `authenticate` arm of `check_file`). All three ids are
    /// `Framework::Stig`, in citation order (RHEL-08, RHEL-09, RHEL-10).
    ///
    /// #563 (9i lane-7): extended from a dual pin to a triple pin (was
    /// `len() == 2`, `controls[0]`/`[1]` only) -- `RHEL-10-600530` grounded
    /// against the DISA RHEL 10 STIG V1R1 XCCDF (Group V-281208 /
    /// SV-281208r1166576_rule, "RHEL 10 must require users to reauthenticate
    /// for privilege escalation"; see `lane-7-sudoersids-report.md`). This is
    /// an EXHAUSTIVE length assertion that the RHEL-10 addition breaks, so it
    /// is updated in place per the discipline in the lane-7 brief rather than
    /// left stale-red.
    #[test]
    fn w04_not_authenticate_finding_carries_stig_controls() {
        use rulesteward_core::Framework;

        let diags = lint_w04("Defaults !authenticate\nroot ALL=(ALL:ALL) ALL\n");
        let finding = diags
            .iter()
            .find(|d| d.code == "sudo-W04" && d.message.contains("!authenticate"))
            .expect("W04 fires for !authenticate");
        assert_eq!(
            finding.controls.len(),
            3,
            "!authenticate's triple RHEL-08/RHEL-09/RHEL-10 citation must \
             become three ControlRefs; got {:?}",
            finding.controls
        );
        assert_eq!(finding.controls[0].framework, Framework::Stig);
        assert_eq!(finding.controls[0].id, "RHEL-08-010381");
        assert_eq!(finding.controls[1].framework, Framework::Stig);
        assert_eq!(finding.controls[1].id, "RHEL-09-432025");
        assert_eq!(finding.controls[2].framework, Framework::Stig);
        assert_eq!(finding.controls[2].id, "RHEL-10-600530");
    }

    /// A NEGATIVE `Defaults timestamp_timeout=-1` (the per-file weakening,
    /// line >= 1) cites DISA STIG RHEL-08-010384 AND RHEL-09-432015 AND
    /// RHEL-10-600540 (stig.rs:248, the negative-value arm of `check_file`).
    /// All three ids are `Framework::Stig`, in citation order. `use_pty` +
    /// `logfile` are present so ONLY the per-file timestamp weakening is the
    /// timestamp finding under test (no merged absent/conflict finding
    /// fires).
    ///
    /// #563 (9i lane-7): extended from a dual pin to a triple pin (was
    /// `len() == 2`, `controls[0]`/`[1]` only) -- `RHEL-10-600540` grounded
    /// against the DISA RHEL 10 STIG V1R1 XCCDF (Group V-281209 /
    /// SV-281209r1166579_rule, "RHEL 10 must require reauthentication when
    /// using the \"sudo\" command"; see `lane-7-sudoersids-report.md`). This
    /// is an EXHAUSTIVE length assertion that the RHEL-10 addition breaks, so
    /// it is updated in place per the discipline in the lane-7 brief rather
    /// than left stale-red.
    #[test]
    fn w04_negative_timestamp_timeout_finding_carries_stig_controls() {
        use rulesteward_core::Framework;

        let diags = lint_w04(
            "Defaults timestamp_timeout=-1\nDefaults use_pty\nDefaults logfile=/var/log/sudo.log\nroot ALL=(ALL:ALL) ALL\n",
        );
        let finding = diags
            .iter()
            .find(|d| {
                d.code == "sudo-W04" && d.line >= 1 && d.message.contains("timestamp_timeout")
            })
            .expect("W04 fires for negative timestamp_timeout");
        assert_eq!(
            finding.controls.len(),
            3,
            "negative timestamp_timeout's triple RHEL-08/RHEL-09/RHEL-10 \
             citation must become three ControlRefs; got {:?}",
            finding.controls
        );
        assert_eq!(finding.controls[0].framework, Framework::Stig);
        assert_eq!(finding.controls[0].id, "RHEL-08-010384");
        assert_eq!(finding.controls[1].framework, Framework::Stig);
        assert_eq!(finding.controls[1].id, "RHEL-09-432015");
        assert_eq!(finding.controls[2].framework, Framework::Stig);
        assert_eq!(finding.controls[2].id, "RHEL-10-600540");
    }

    /// The merged-required MISSING `use_pty` absence finding (line 0) cites
    /// CIS Benchmark 5.2.2 AND PCI-DSS Req-10.2.5 (stig.rs:382, the
    /// `!has_use_pty` branch of `check_merged_required`). Its controls must be
    /// `Framework::Cis` (id `"5.2.2"`, RENUMBERED #526 -- LOCKED post-A0
    /// 2026-07-18, was the stale "1.3.2") carrying the CaC title via
    /// `.with_name(..)`, then `Framework::Pci` (id `"Req-10.2.5"`, unaffected,
    /// no name), matching the `!use_pty` per-file finding's pair (same
    /// control, different emit site -- pins that the impl wires the renumber
    /// at BOTH sites, not just the per-file one). Fixture:
    /// `timestamp_timeout=5` present so the timestamp absence does not fire;
    /// no I/O log so ONLY the use_pty and I/O-log absences fire, and we
    /// select the use_pty one.
    #[test]
    fn w04_missing_use_pty_finding_carries_cis_and_pci_controls() {
        use rulesteward_core::Framework;

        let diags =
            lint_w04("Defaults env_reset\nDefaults timestamp_timeout=5\nroot ALL=(ALL:ALL) ALL\n");
        let finding = w04_absence(&diags)
            .into_iter()
            .find(|d| d.message.contains("use_pty"))
            .expect("the merged missing-use_pty absence finding fires");
        assert_eq!(
            finding.controls.len(),
            2,
            "missing use_pty's CIS+PCI citation must become two ControlRefs; \
             got {:?}",
            finding.controls
        );
        assert_eq!(finding.controls[0].framework, Framework::Cis);
        assert_eq!(
            finding.controls[0].id, "5.2.2",
            "#526 renumber: use_pty's CIS id is 5.2.2 (was the stale 1.3.2)"
        );
        assert_eq!(
            finding.controls[0].name.as_deref(),
            Some("Ensure sudo commands use pty (Automated)"),
            "#526: the renumbered CIS ref carries the verbatim CaC title via .with_name(..)"
        );
        assert_eq!(finding.controls[1].framework, Framework::Pci);
        assert_eq!(finding.controls[1].id, "Req-10.2.5");
        assert!(
            finding.controls[1].name.is_none(),
            "the bare PCI ref carries no name (only the renumbered CIS ref gains \
             one via .with_name(..)); got {:?}",
            finding.controls[1].name
        );
    }

    /// The merged-required MISSING I/O-logging absence finding (line 0) cites
    /// CIS Benchmark 5.2.3 AND PCI-DSS Req-10.2.5 (stig.rs:395, the
    /// `!has_io_log` branch of `check_merged_required`). Its controls must be
    /// `Framework::Cis` (id `"5.2.3"`, RENUMBERED #526 -- LOCKED post-A0
    /// 2026-07-18, was the stale "1.3.3", DISTINCT from use_pty's `5.2.2`)
    /// carrying the CaC title via `.with_name(..)`, then `Framework::Pci` (id
    /// `"Req-10.2.5"`, unaffected, no name). The absence finding's message
    /// names "logging"; use_pty is present so only the I/O-log (and
    /// timestamp) absences fire, and we select the logging one.
    #[test]
    fn w04_missing_io_log_finding_carries_cis_and_pci_controls() {
        use rulesteward_core::Framework;

        let diags =
            lint_w04("Defaults use_pty\nDefaults timestamp_timeout=5\nroot ALL=(ALL:ALL) ALL\n");
        let finding = w04_absence(&diags)
            .into_iter()
            .find(|d| d.message.contains("logging"))
            .expect("the merged missing-I/O-logging absence finding fires");
        // #526 adversarial-review fix: the FREE-TEXT message must also carry the
        // renumbered id, mirroring `use_pty`'s must_cite guard in
        // `w04_weakening_findings_cite_grounded_controls` -- without this, an
        // impl could renumber the TYPED ControlRef to 5.2.3 while the message
        // literal (`check_merged_required`'s `!has_io_log` branch) still cites
        // the stale 1.3.3, violating the module's own no-drift invariant.
        assert!(
            finding.message.contains("CIS Benchmark 5.2.3"),
            "#526 renumber: the missing-I/O-log message must cite 'CIS Benchmark \
             5.2.3' (not the stale 1.3.3); got {:?}",
            finding.message
        );
        assert_eq!(
            finding.controls.len(),
            2,
            "missing I/O logging's CIS+PCI citation must become two ControlRefs; \
             got {:?}",
            finding.controls
        );
        assert_eq!(finding.controls[0].framework, Framework::Cis);
        assert_eq!(
            finding.controls[0].id, "5.2.3",
            "#526 renumber: I/O logging's CIS id is 5.2.3 (was the stale 1.3.3)"
        );
        assert_eq!(
            finding.controls[0].name.as_deref(),
            Some("Ensure sudo log file exists (Automated)"),
            "#526: the renumbered CIS ref carries the verbatim CaC title via .with_name(..)"
        );
        assert_eq!(finding.controls[1].framework, Framework::Pci);
        assert_eq!(finding.controls[1].id, "Req-10.2.5");
        assert!(
            finding.controls[1].name.is_none(),
            "the bare PCI ref carries no name (only the renumbered CIS ref gains \
             one via .with_name(..)); got {:?}",
            finding.controls[1].name
        );
    }

    /// The merged-required ABSENT `timestamp_timeout` finding (line 0, the
    /// STIG's PRIMARY trigger) cites DISA STIG RHEL-08-010384 AND
    /// RHEL-09-432015 (stig.rs:425, the `[] if !has_negated_timestamp_timeout`
    /// arm of `check_merged_required`). Both ids are `Framework::Stig`, in
    /// citation order. `use_pty` + `logfile` present so ONLY the
    /// timestamp_timeout absence fires. Same control-id pair as the per-file
    /// negative weakening, DIFFERENT emit site -- pins that the impl wires
    /// controls at the merged-absent site too (a partial impl fails).
    /// #563 (9i lane-7): extended from a dual pin to a triple pin (was
    /// `len() == 2`, `controls[0]`/`[1]` only) -- `RHEL-10-600540` grounded
    /// against the DISA RHEL 10 STIG V1R1 XCCDF (Group V-281209 /
    /// SV-281209r1166579_rule; same control as the per-file negative
    /// weakening above, DIFFERENT emit site; see `lane-7-sudoersids-report.md`).
    /// This is an EXHAUSTIVE length assertion that the RHEL-10 addition
    /// breaks, so it is updated in place per the discipline in the lane-7
    /// brief rather than left stale-red.
    #[test]
    fn w04_missing_timestamp_timeout_finding_carries_stig_controls() {
        use rulesteward_core::Framework;

        let diags = lint_w04(
            "Defaults use_pty\nDefaults logfile=/var/log/sudo.log\nroot ALL=(ALL:ALL) ALL\n",
        );
        let finding = w04_absence(&diags)
            .into_iter()
            .find(|d| d.message.contains("timestamp_timeout"))
            .expect("the merged absent timestamp_timeout finding fires");
        assert_eq!(
            finding.controls.len(),
            3,
            "absent timestamp_timeout's triple RHEL-08/RHEL-09/RHEL-10 \
             citation must become three ControlRefs; got {:?}",
            finding.controls
        );
        assert_eq!(finding.controls[0].framework, Framework::Stig);
        assert_eq!(finding.controls[0].id, "RHEL-08-010384");
        assert_eq!(finding.controls[1].framework, Framework::Stig);
        assert_eq!(finding.controls[1].id, "RHEL-09-432015");
        assert_eq!(finding.controls[2].framework, Framework::Stig);
        assert_eq!(finding.controls[2].id, "RHEL-10-600540");
    }

    /// The merged-required CONFLICTING `timestamp_timeout` finding (line 0, 2+
    /// distinct values) cites DISA STIG RHEL-08-010384 AND RHEL-09-432015
    /// (stig.rs:438, the `_multiple` arm of `check_merged_required`). Both ids
    /// are `Framework::Stig`, in citation order. Two merged files set `=5` and
    /// `=30`; the conflict finding's message contains "conflict".
    /// #563 (9i lane-7): extended from a dual pin to a triple pin (was
    /// `len() == 2`, `controls[0]`/`[1]` only) -- `RHEL-10-600540` grounded
    /// against the DISA RHEL 10 STIG V1R1 XCCDF (Group V-281209 /
    /// SV-281209r1166579_rule; same control, third emit site; see
    /// `lane-7-sudoersids-report.md`). This is an EXHAUSTIVE length assertion
    /// that the RHEL-10 addition breaks, so it is updated in place per the
    /// discipline in the lane-7 brief rather than left stale-red.
    #[test]
    fn w04_conflicting_timestamp_timeout_finding_carries_stig_controls() {
        use rulesteward_core::Framework;

        let files = parse_files(&[
            (
                "/etc/sudoers",
                "Defaults timestamp_timeout=5\nDefaults use_pty\nDefaults logfile=/var/log/sudo.log\nroot ALL=(ALL:ALL) ALL\n",
            ),
            ("/etc/sudoers.d/20-other", "Defaults timestamp_timeout=30\n"),
        ]);
        let diags = w04(&files, &CTX);
        let finding = w04_absence(&diags)
            .into_iter()
            .find(|d| d.message.contains("timestamp_timeout") && d.message.contains("conflict"))
            .expect("the merged conflicting timestamp_timeout finding fires");
        assert_eq!(
            finding.controls.len(),
            3,
            "conflicting timestamp_timeout's triple RHEL-08/RHEL-09/RHEL-10 \
             citation must become three ControlRefs; got {:?}",
            finding.controls
        );
        assert_eq!(finding.controls[0].framework, Framework::Stig);
        assert_eq!(finding.controls[0].id, "RHEL-08-010384");
        assert_eq!(finding.controls[1].framework, Framework::Stig);
        assert_eq!(finding.controls[1].id, "RHEL-09-432015");
        assert_eq!(finding.controls[2].framework, Framework::Stig);
        assert_eq!(finding.controls[2].id, "RHEL-10-600540");
    }

    /// `visiblepw`'s citation is "CIS / general hardening; not a DISA STIG
    /// control" (stig.rs:137) -- it carries NO bare numeric control id. There
    /// is no grounded id to attach, so a `visiblepw` finding must carry an
    /// EMPTY `controls` vec: the deliberate exclusion is documented here rather
    /// than by inventing a `Cis` id the citation text does not provide. (If a
    /// grounded CIS id for visiblepw is later established, this guard is the
    /// place the decision is revisited.)
    #[test]
    fn w04_visiblepw_finding_has_no_controls() {
        let diags = lint_w04("Defaults visiblepw\nroot ALL=(ALL:ALL) ALL\n");
        let finding = diags
            .iter()
            .find(|d| d.code == "sudo-W04" && d.message.contains("visiblepw"))
            .expect("W04 fires for visiblepw");
        assert!(
            finding.controls.is_empty(),
            "visiblepw cites 'CIS / general hardening' with no bare id, so it \
             carries no typed control (no invented id); got {:?}",
            finding.controls
        );
    }

    /// A finding with NO compliance citation in its free text must carry an
    /// EMPTY `controls` vec. This suite backfills typed controls for exactly
    /// the citation-bearing sudoers findings: sudo-W01 (Stig), sudo-W05 (Stig),
    /// and sudo-W04's per-file (`!authenticate` Stig, targetpw/rootpw/runaspw
    /// Stig, `!use_pty` Cis+Pci, negative `timestamp_timeout` Stig) and
    /// merged-required (missing `use_pty` Cis+Pci, missing I/O-log Cis+Pci,
    /// absent + conflicting `timestamp_timeout` Stig) emit sites; `visiblepw`
    /// is the documented no-id exclusion. `sudo-F01` (a malformed-line parse
    /// Fatal, `f01.rs`) cites no compliance control at all, so it is the
    /// empty-controls guard against over-eager backfill (e.g. accidentally
    /// defaulting every `Diagnostic` to some control).
    #[test]
    fn f01_malformed_line_finding_has_no_controls() {
        use crate::lints::f01::f01;

        let files = parse_one("frobnicate\nroot ALL=(ALL:ALL) ALL\n");
        let diags = f01(&files, &CTX);
        assert_eq!(diags.len(), 1, "one malformed line -> one sudo-F01");
        assert!(
            diags[0].controls.is_empty(),
            "a sudo-F01 parse failure carries no compliance control; got {:?}",
            diags[0].controls
        );
    }

    // -----------------------------------------------------------------------
    // #563 (9i lane-7): RHEL-10 STIG control ids for W04
    // -----------------------------------------------------------------------
    //
    // Grounded against the DISA RHEL 10 STIG V1R1 XCCDF
    // (`U_RHEL_10_STIG_V1R1_Manual-xccdf.xml`, fetched from
    // dl.dod.cyber.mil; full citations table in
    // `/mnt/side-projects/9i-closeout/lane-7-sudoersids-report.md`):
    // - `!authenticate` -> RHEL-10-600530 (V-281208)
    // - `targetpw`/`rootpw`/`runaspw` -> RHEL-10-600550 (V-281210)
    // - `timestamp_timeout` -> RHEL-10-600540 (V-281209)
    // Sanity anchor: RHEL-10-600520 (W06, tags.rs:401) was located in the
    // same fetched XCCDF (V-281207), confirming the numbering series.

    /// Each affected W04 weakening finding's message must cite its new
    /// RHEL-10 id, mirroring `w04_weakening_findings_cite_grounded_controls`'
    /// must-cite shape but scoped to the RHEL-10 additions only. RED until
    /// the implementer appends the RHEL-10 id to the `WEAKENING_PRESENT`
    /// free-text citation strings (and the matching typed control consts).
    #[test]
    fn rhel10_w04_weakening_findings_cite_grounded_controls() {
        let must_cite = [
            ("Defaults !authenticate\n", "RHEL-10-600530"),
            ("Defaults targetpw\n", "RHEL-10-600550"),
            ("Defaults rootpw\n", "RHEL-10-600550"),
            ("Defaults runaspw\n", "RHEL-10-600550"),
            ("Defaults timestamp_timeout=-1\n", "RHEL-10-600540"),
        ];
        for (defaults, needle) in must_cite {
            let src = format!("{defaults}root ALL=(ALL:ALL) ALL\n");
            let diags = lint_w04(&src);
            assert!(
                diags
                    .iter()
                    .any(|d| d.code == "sudo-W04" && d.message.contains(needle)),
                "W04 finding for {defaults:?} must cite '{needle}'; got {diags:?}"
            );
        }

        // Per-control pin: each finding's own weakening message must NOT pick
        // up a SIBLING RHEL-10 id from one of the other two new controls in
        // this same lane (guards against the 3 new ids getting swapped
        // between `AUTHENTICATE_CONTROLS` / `PW_FAMILY_CONTROLS` /
        // `TIMESTAMP_TIMEOUT_CONTROLS`), mirroring the pre-existing
        // RHEL-08/RHEL-09 `must_not_cite` pattern above.
        //
        // Round-6 fix: the `!authenticate` and `targetpw` fixtures set no
        // `timestamp_timeout` anywhere, so `lint_w04` ALSO emits the merged
        // missing-required absence finding (#347/#363) for
        // `timestamp_timeout` on those same fixtures -- and once the
        // implementer appends the grounded `RHEL-10-600540` id to
        // `TIMESTAMP_TIMEOUT_CONTROLS` (this same lane's own change), that
        // absence finding's message legitimately contains "RHEL-10-600540".
        // That is a DIFFERENT, correctly-cited finding, not
        // cross-contamination of the `!authenticate`/`targetpw` weakening
        // finding under test (same defect class as the use_pty/visiblepw
        // guard fixed in round 4), so each check is scoped to the specific
        // weakening finding by filtering on `focus` (a substring unique to
        // that finding's own message -- "authenticate" / "targetpw" --
        // which the merged timestamp-absence message never contains) before
        // asserting the sibling-id ban. A non-empty positive-control assert
        // guards against the filter itself silently matching nothing.
        let must_not_cite = [
            ("Defaults !authenticate\n", "authenticate", "RHEL-10-600550"), // pw-family id, not authenticate's
            ("Defaults !authenticate\n", "authenticate", "RHEL-10-600540"), // timestamp id, not authenticate's
            ("Defaults targetpw\n", "targetpw", "RHEL-10-600530"), // authenticate id, not pw-family's
            ("Defaults targetpw\n", "targetpw", "RHEL-10-600540"), // timestamp id, not pw-family's
            (
                "Defaults timestamp_timeout=-1\n",
                "timestamp_timeout",
                "RHEL-10-600530",
            ), // authenticate id, not timestamp's
            (
                "Defaults timestamp_timeout=-1\n",
                "timestamp_timeout",
                "RHEL-10-600550",
            ), // pw-family id, not timestamp's
        ];
        for (defaults, focus, bad) in must_not_cite {
            let src = format!("{defaults}root ALL=(ALL:ALL) ALL\n");
            let diags = lint_w04(&src);
            let scoped: Vec<_> = diags
                .iter()
                .filter(|d| d.code == "sudo-W04" && d.message.contains(focus))
                .collect();
            assert!(
                !scoped.is_empty(),
                "W04 finding for {defaults:?} must include a '{focus}' \
                 weakening finding to guard; got {diags:?}"
            );
            assert!(
                scoped.iter().all(|d| !d.message.contains(bad)),
                "W04 '{focus}' weakening finding for {defaults:?} must NOT \
                 cite the sibling id '{bad}'; got {scoped:?}"
            );
        }

        // Cross-contamination guard: `!use_pty` (CIS/PCI, no DISA sudo STIG
        // control) and `visiblepw` (CIS/general, no DISA STIG control) have
        // NO RHEL-10 equivalent in the fetched XCCDF -- the WEAKENING finding
        // for each must NOT pick up any RHEL-10-6005xx id.
        //
        // Both fixtures set no `timestamp_timeout` anywhere, so `lint_w04`
        // ALSO emits the merged missing-required absence finding (#347/#363)
        // for `timestamp_timeout` -- and once the implementer appends the
        // grounded RHEL-10-600540 id to `TIMESTAMP_TIMEOUT_CONTROLS` (per
        // this same lane), that absence finding's message legitimately
        // contains "RHEL-10-6005...". That is a DIFFERENT, correctly-cited
        // finding, not cross-contamination of the use_pty/visiblepw
        // weakening finding under test, so the guard filters to the
        // specific weakening finding by name before asserting the ban (the
        // timestamp absence message never contains "use_pty" or
        // "visiblepw" -- see `check_merged_required`'s message text).
        for (defaults, setting_name, bad) in [
            ("Defaults !use_pty\n", "use_pty", "RHEL-10-6005"),
            ("Defaults visiblepw\n", "visiblepw", "RHEL-10-6005"),
        ] {
            let src = format!("{defaults}root ALL=(ALL:ALL) ALL\n");
            let diags = lint_w04(&src);
            let weakening: Vec<_> = diags
                .iter()
                .filter(|d| d.code == "sudo-W04" && d.message.contains(setting_name))
                .collect();
            assert!(
                !weakening.is_empty(),
                "W04 finding for {defaults:?} must include a '{setting_name}' \
                 weakening finding to guard; got {diags:?}"
            );
            assert!(
                weakening.iter().all(|d| !d.message.contains(bad)),
                "W04 '{setting_name}' weakening finding for {defaults:?} must \
                 NOT cite any RHEL-10 sudo STIG id (no grounded equivalent \
                 exists); got {weakening:?}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Clean file: no W04 when no weakening Defaults present
    // -----------------------------------------------------------------------

    /// A STIG-clean file (no weakening AND the required hardening present) fires
    /// NO W04. The `use_pty` + `logfile` + `timestamp_timeout` lines satisfy the
    /// merged missing-required check (#347, #363), so neither a weakening nor an
    /// absence finding fires.
    ///
    /// Fixture verified valid by `visudo -c`.
    #[test]
    fn w04_clean_when_no_weakening_defaults() {
        // Fixture: the required hardening present, no weakening settings.
        // timestamp_timeout=5 added (#363) so the new absence check is satisfied.
        // visudo -c: "parsed OK"
        let diags = lint_w04(
            "Defaults env_reset\n\
             Defaults use_pty\n\
             Defaults logfile=/var/log/sudo.log\n\
             Defaults timestamp_timeout=5\n\
             root ALL=(ALL:ALL) ALL\n\
             %wheel ALL=(ALL) ALL\n",
        );
        let w04_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-W04").collect();
        assert!(
            w04_diags.is_empty(),
            "a STIG-clean file must produce no W04; got {w04_diags:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Non-STIG Defaults: no false positives
    // -----------------------------------------------------------------------

    /// `Defaults env_reset` alone does NOT fire W04 (it is not a STIG finding).
    #[test]
    fn w04_env_reset_is_not_a_stig_finding() {
        // Fixture: only env_reset (no other Defaults).
        // visudo -c: "parsed OK"
        let diags = lint_w04("Defaults env_reset\nroot ALL=(ALL:ALL) ALL\n");
        // env_reset specifically must not appear in any W04 message
        let env_reset_diags: Vec<_> = diags
            .iter()
            .filter(|d| d.code == "sudo-W04" && d.message.contains("env_reset"))
            .collect();
        assert!(
            env_reset_diags.is_empty(),
            "'Defaults env_reset' must not trigger W04 as a weakening; got {env_reset_diags:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Scope label helper
    // -----------------------------------------------------------------------

    #[test]
    fn scope_paren_global_reads_global_scope() {
        // A global `Defaults` must read naturally as `(global scope)`, NOT the
        // awkward `(scope)` the old empty-prefix produced.
        assert_eq!(scope_paren(&DefaultsScope::Global), "(global scope)");
    }

    #[test]
    fn scope_paren_user_includes_username() {
        assert_eq!(
            scope_paren(&DefaultsScope::User("alice".into())),
            "(user:alice scope)"
        );
    }

    #[test]
    fn scope_paren_host_includes_hostname() {
        assert_eq!(
            scope_paren(&DefaultsScope::Host("myhost".into())),
            "(host:myhost scope)"
        );
    }

    // -----------------------------------------------------------------------
    // Diagnostic structural invariants
    // -----------------------------------------------------------------------

    #[test]
    fn w04_diagnostics_have_correct_code_and_severity() {
        let diags = lint_w04(
            "Defaults !authenticate\nDefaults use_pty\nDefaults logfile=/var/log/sudo.log\nroot ALL=(ALL:ALL) ALL\n",
        );
        for d in diags.iter().filter(|d| d.code == "sudo-W04") {
            assert_eq!(d.code.as_ref(), "sudo-W04");
            assert_eq!(
                d.severity,
                Severity::Warning,
                "sudo-W04 must always be Warning severity"
            );
            assert!(
                d.source_id.is_some(),
                "anchored diagnostics must have a source_id (ariadne key)"
            );
        }
    }

    #[test]
    fn w04_codes_helper_filters_correctly() {
        let diags = lint_w04(
            "Defaults !authenticate\nDefaults use_pty\nDefaults logfile=/var/log/sudo.log\nroot ALL=(ALL:ALL) ALL\n",
        );
        let codes = w04_codes(&diags);
        assert!(!codes.is_empty(), "should have at least one W04 code");
        assert!(codes.iter().all(|&c| c == "sudo-W04"));
    }

    // -----------------------------------------------------------------------
    // Missing-required hardening (#347): merged absence checks.
    //
    // The check runs ONCE over the whole resolved slice (not per-file) and fires
    // at most twice: once if `use_pty` is never positively set anywhere, once if
    // no I/O logging (`logfile=` or `log_output`) is set anywhere. Absence
    // findings anchor at the top-level file (`files[0]`), line 0.
    // -----------------------------------------------------------------------

    /// A file with neither `use_pty` nor I/O logging (but WITH timestamp_timeout, so
    /// only the use_pty and logging requirements are unmet) fires exactly two
    /// absence findings (one per missing requirement).
    #[test]
    fn w04_absence_fires_twice_when_both_missing() {
        // timestamp_timeout=5 present (#363) so ONLY use_pty + I/O logging are
        // missing -> exactly two absence findings.
        // visudo -c: "parsed OK"
        let diags =
            lint_w04("Defaults env_reset\nDefaults timestamp_timeout=5\nroot ALL=(ALL:ALL) ALL\n");
        let absent = w04_absence(&diags);
        assert_eq!(
            absent.len(),
            2,
            "neither use_pty nor I/O logging set -> two absence findings; got {absent:?}"
        );
        assert!(
            absent.iter().any(|d| d.message.contains("use_pty")),
            "one absence finding must name use_pty; got {absent:?}"
        );
        assert!(
            absent.iter().any(|d| d.message.contains("logging")),
            "one absence finding must name I/O logging; got {absent:?}"
        );
    }

    /// All requirements satisfied in one file -> no absence findings.
    #[test]
    fn w04_absence_suppressed_when_both_present() {
        // timestamp_timeout=5 added (#363) so all three requirements are met.
        // visudo -c: "parsed OK"
        let diags = lint_w04(
            "Defaults use_pty\nDefaults logfile=/var/log/sudo.log\nDefaults timestamp_timeout=5\nroot ALL=(ALL:ALL) ALL\n",
        );
        assert!(
            w04_absence(&diags).is_empty(),
            "use_pty + logfile + timestamp_timeout all present -> no absence findings; got {diags:?}"
        );
    }

    /// `log_output` is an accepted alternative to `logfile=` for the I/O-logging
    /// requirement (sudoers(5): both enable pseudo-terminal session logging).
    #[test]
    fn w04_absence_log_output_satisfies_io_logging() {
        // timestamp_timeout=5 present (#363) so it does not contribute a spurious
        // absence; this test targets the I/O-logging requirement only.
        // visudo -c: "parsed OK"
        let diags = lint_w04(
            "Defaults use_pty\nDefaults log_output\nDefaults timestamp_timeout=5\nroot ALL=(ALL:ALL) ALL\n",
        );
        let absent = w04_absence(&diags);
        assert!(
            absent.iter().all(|d| !d.message.contains("logging")),
            "log_output must satisfy the I/O-logging requirement; got {absent:?}"
        );
    }

    /// Explicit `!use_pty` does NOT satisfy the positive requirement: it fires a
    /// weakening finding (line >= 1) AND the absence finding (line 0).
    #[test]
    fn w04_absence_negated_use_pty_does_not_satisfy() {
        // timestamp_timeout=5 present (#363) so only the use_pty requirement is at
        // issue here.
        // visudo -c: "parsed OK"
        let diags = lint_w04(
            "Defaults !use_pty\nDefaults logfile=/var/log/sudo.log\nDefaults timestamp_timeout=5\nroot ALL=(ALL:ALL) ALL\n",
        );
        // The weakening finding for the explicit negation sits at the real line.
        assert!(
            diags
                .iter()
                .any(|d| d.code == "sudo-W04" && d.line >= 1 && d.message.contains("!use_pty")),
            "explicit !use_pty must still fire a weakening finding; got {diags:?}"
        );
        // The positive use_pty requirement is still unmet -> absence finding fires.
        let absent = w04_absence(&diags);
        assert!(
            absent.iter().any(|d| d.message.contains("use_pty")),
            "!use_pty must NOT satisfy the positive requirement; got {absent:?}"
        );
        // I/O logging IS present, so no logging-absence finding.
        assert!(
            absent.iter().all(|d| !d.message.contains("logging")),
            "logfile present -> no I/O-logging absence; got {absent:?}"
        );
    }

    /// Across a multi-file resolved slice where NO file sets the requirements, the
    /// absence check fires ONCE total (two findings), not once per file. This is
    /// the per-fragment false positive the merged check exists to prevent.
    #[test]
    fn w04_absence_fires_once_across_merged_slice_not_per_file() {
        // timestamp_timeout=5 in the top file (#363) so only use_pty + I/O logging
        // are unmet -> two absence findings, demonstrating "once per requirement
        // across the merged slice, not per file".
        let files = parse_files(&[
            (
                "/etc/sudoers",
                "Defaults env_reset\nDefaults timestamp_timeout=5\nroot ALL=(ALL:ALL) ALL\n",
            ),
            ("/etc/sudoers.d/10-a", "alice ALL=(ALL) ALL\n"),
            ("/etc/sudoers.d/20-b", "bob ALL=(ALL) NOPASSWD: /bin/ls\n"),
        ]);
        let diags = w04(&files, &CTX);
        let absent = w04_absence(&diags);
        assert_eq!(
            absent.len(),
            2,
            "three files, none hardened -> two absence findings total, not six; got {absent:?}"
        );
    }

    /// A drop-in that sets the hardening satisfies the requirement for the whole
    /// merged tree, even when the top-level file does not set it. The per-fragment
    /// FP (flag the main file for "missing use_pty" when a drop-in sets it) must
    /// NOT occur.
    #[test]
    fn w04_absence_drop_in_satisfies_top_level() {
        let files = parse_files(&[
            (
                "/etc/sudoers",
                "Defaults env_reset\nroot ALL=(ALL:ALL) ALL\n",
            ),
            (
                "/etc/sudoers.d/10-hardening",
                "Defaults use_pty\nDefaults logfile=/var/log/sudo.log\nDefaults timestamp_timeout=5\n",
            ),
        ]);
        let diags = w04(&files, &CTX);
        assert!(
            w04_absence(&diags).is_empty(),
            "a drop-in setting the hardening satisfies the merged tree; got {diags:?}"
        );
    }

    /// Absence findings anchor at the TOP-LEVEL file (`files[0]`), line 0, with a
    /// source-id set (the missing-key convention), regardless of which drop-ins
    /// follow.
    #[test]
    fn w04_absence_anchors_at_top_level_file() {
        // timestamp_timeout=5 present (#363) so exactly the use_pty + I/O-logging
        // absence findings remain; both must anchor at the top-level file.
        let files = parse_files(&[
            (
                "/etc/sudoers",
                "Defaults env_reset\nDefaults timestamp_timeout=5\nroot ALL=(ALL:ALL) ALL\n",
            ),
            ("/etc/sudoers.d/10-a", "alice ALL=(ALL) ALL\n"),
        ]);
        let diags = w04(&files, &CTX);
        let absent = w04_absence(&diags);
        assert_eq!(absent.len(), 2, "two absence findings; got {absent:?}");
        for d in &absent {
            assert_eq!(d.line, 0, "absence findings anchor at line 0");
            assert_eq!(d.span, 0..0, "absence findings carry an empty span");
            assert_eq!(
                d.severity,
                Severity::Warning,
                "absence findings are Warning severity"
            );
            assert_eq!(
                d.source_id.as_deref(),
                Some("/etc/sudoers"),
                "absence findings anchor at the top-level file path"
            );
        }
    }

    /// An empty resolved slice yields no findings (guard against indexing
    /// `files[0]` on an empty input).
    ///
    /// NOT the #485 bug: this pins `w04`'s defensive handling of a genuinely
    /// empty `Vec<SudoersFile>`, which still occurs for a top-level DIRECTORY
    /// target with zero eligible drop-ins (`resolve::tests::
    /// empty_directory_resolves_to_no_files` -- there is no singular top-level
    /// file to anchor a line-0 finding against). #485 is specifically about a
    /// top-level FILE target that resolves to zero entries; the orchestrator's
    /// locked decision is BROAD -- ANY top-level FILE that resolves to zero
    /// entries synthesizes one phantom segment, not just a byte-empty or
    /// whitespace-only source (see `byte_empty_file_fires_all_three_absence_findings_via_resolver`
    /// / `whitespace_only_file_fires_all_three_absence_findings_via_resolver` /
    /// `file_with_only_empty_includedir_fires_all_three_absence_findings_via_resolver`
    /// below). Post-fix, this artificial empty-slice input is no longer
    /// reachable from ANY top-level FILE target -- only from an empty
    /// top-level DIRECTORY, or a caller constructing `&[]` by hand.
    #[test]
    fn w04_absence_empty_slice_no_findings() {
        let diags = w04(&[], &CTX);
        assert!(
            diags.is_empty(),
            "an empty slice produces no diagnostics; got {diags:?}"
        );
    }

    /// A scoped positive `Defaults:alice use_pty` satisfies the requirement: the
    /// CIS audit check greps for any `use_pty` occurrence, so any non-negated
    /// setting (any scope) anywhere in the merged tree counts.
    #[test]
    fn w04_absence_scoped_use_pty_satisfies() {
        // visudo -c: "parsed OK"
        let diags = lint_w04(
            "Defaults:alice use_pty\nDefaults logfile=/var/log/sudo.log\nDefaults timestamp_timeout=5\nroot ALL=(ALL:ALL) ALL\n",
        );
        let absent = w04_absence(&diags);
        assert!(
            absent.iter().all(|d| !d.message.contains("use_pty")),
            "a scoped positive use_pty satisfies the requirement; got {absent:?}"
        );
    }

    // -----------------------------------------------------------------------
    // timestamp_timeout (#363): DISA STIG RHEL-08-010384 / RHEL-09-432015.
    //
    // The STIG `sudo_require_reauthentication` rule has THREE failure modes:
    //   * NEGATIVE value (< 0, e.g. -1) -> credential cache never expires (per-file
    //     weakening, fires at the offending Defaults line);
    //   * ABSENT from the merged tree (no explicit timestamp_timeout anywhere) ->
    //     the STIG's PRIMARY trigger (merged missing-required, fires at line 0);
    //   * CONFLICTING (2+ distinct values across the merged files) -> ambiguous
    //     policy (merged, fires at line 0).
    // A single non-negative value (0 or positive) is COMPLIANT.
    // -----------------------------------------------------------------------

    /// `Defaults timestamp_timeout=-1` (never-expire credential cache) fires W04 as
    /// a per-file weakening, citing the timestamp_timeout STIG control.
    ///
    /// Grounding: DISA STIG RHEL-08-010384 / RHEL-09-432015
    /// (ComplianceAsCode `sudo_require_reauthentication`).
    /// Fixture verified valid by `visudo -c`.
    #[test]
    fn w04_fires_for_negative_timestamp_timeout() {
        // Fixture: Defaults timestamp_timeout=-1 (credential cache never expires).
        // visudo -c: "parsed OK"
        let diags = lint_w04(
            "Defaults timestamp_timeout=-1\nDefaults use_pty\nDefaults logfile=/var/log/sudo.log\nroot ALL=(ALL:ALL) ALL\n",
        );
        let w04_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-W04").collect();
        assert!(
            w04_diags
                .iter()
                .any(|d| d.message.contains("timestamp_timeout")
                    && d.message.contains("RHEL-08-010384")),
            "W04 must fire for negative timestamp_timeout citing RHEL-08-010384; got {diags:?}"
        );
    }

    /// The negative-timestamp_timeout weakening finding anchors at the offending
    /// `Defaults` line (>= 1), not at line 0 (the absence convention).
    #[test]
    fn w04_negative_timestamp_timeout_anchors_at_defaults_line() {
        let diags = lint_w04(
            "Defaults use_pty\nDefaults timestamp_timeout=-1\nDefaults logfile=/var/log/sudo.log\nroot ALL=(ALL:ALL) ALL\n",
        );
        let neg: Vec<_> = diags
            .iter()
            .filter(|d| {
                d.code == "sudo-W04" && d.line >= 1 && d.message.contains("timestamp_timeout")
            })
            .collect();
        assert_eq!(
            neg.len(),
            1,
            "exactly one weakening W04 for the negative timestamp_timeout; got {neg:?}"
        );
        assert_eq!(
            neg[0].line, 2,
            "the negative-value weakening anchors at the Defaults line (line 2)"
        );
    }

    /// `timestamp_timeout=0` (re-authenticate every invocation) is COMPLIANT: it is
    /// non-negative, so no weakening finding fires and the presence satisfies the
    /// absence check.
    #[test]
    fn w04_timestamp_timeout_zero_is_compliant() {
        // visudo -c: "parsed OK"
        let diags = lint_w04(
            "Defaults timestamp_timeout=0\nDefaults use_pty\nDefaults logfile=/var/log/sudo.log\nroot ALL=(ALL:ALL) ALL\n",
        );
        assert!(
            diags
                .iter()
                .all(|d| !(d.code == "sudo-W04" && d.message.contains("timestamp_timeout"))),
            "timestamp_timeout=0 is compliant (no weakening, no absence); got {diags:?}"
        );
    }

    /// A positive `timestamp_timeout=15` is COMPLIANT: no weakening, and its
    /// presence satisfies the merged absence check.
    #[test]
    fn w04_timestamp_timeout_positive_is_compliant() {
        // visudo -c: "parsed OK"
        let diags = lint_w04(
            "Defaults timestamp_timeout=15\nDefaults use_pty\nDefaults logfile=/var/log/sudo.log\nroot ALL=(ALL:ALL) ALL\n",
        );
        assert!(
            diags
                .iter()
                .all(|d| !(d.code == "sudo-W04" && d.message.contains("timestamp_timeout"))),
            "timestamp_timeout=15 is compliant (no weakening, no absence); got {diags:?}"
        );
    }

    /// A merged tree with NO `timestamp_timeout` anywhere fires the absence finding
    /// (the STIG's primary trigger), at line 0, citing the timestamp_timeout control.
    #[test]
    fn w04_absence_fires_when_timestamp_timeout_missing() {
        // use_pty + logfile present (so those absence findings are suppressed), but
        // NO timestamp_timeout -> the timestamp_timeout absence finding fires.
        // visudo -c: "parsed OK"
        let diags = lint_w04(
            "Defaults use_pty\nDefaults logfile=/var/log/sudo.log\nroot ALL=(ALL:ALL) ALL\n",
        );
        let absent = w04_absence(&diags);
        assert!(
            absent
                .iter()
                .any(|d| d.message.contains("timestamp_timeout")
                    && d.message.contains("RHEL-08-010384")),
            "an absent timestamp_timeout must fire a line-0 W04 citing RHEL-08-010384; got {absent:?}"
        );
    }

    /// A scoped positive `Defaults:alice timestamp_timeout=5` satisfies the absence
    /// requirement (any non-negated occurrence in any scope counts), mirroring the
    /// use_pty scoped-satisfaction rule.
    #[test]
    fn w04_absence_scoped_timestamp_timeout_satisfies() {
        // visudo -c: "parsed OK"
        let diags = lint_w04(
            "Defaults:alice timestamp_timeout=5\nDefaults use_pty\nDefaults logfile=/var/log/sudo.log\nroot ALL=(ALL:ALL) ALL\n",
        );
        let absent = w04_absence(&diags);
        assert!(
            absent
                .iter()
                .all(|d| !d.message.contains("timestamp_timeout")),
            "a scoped positive timestamp_timeout satisfies the absence requirement; got {absent:?}"
        );
    }

    /// A drop-in setting `timestamp_timeout` satisfies the requirement for the whole
    /// merged tree even when the top-level file omits it (no per-fragment FP).
    #[test]
    fn w04_absence_timestamp_timeout_drop_in_satisfies_top_level() {
        let files = parse_files(&[
            (
                "/etc/sudoers",
                "Defaults env_reset\nDefaults use_pty\nDefaults logfile=/var/log/sudo.log\nroot ALL=(ALL:ALL) ALL\n",
            ),
            (
                "/etc/sudoers.d/10-hardening",
                "Defaults timestamp_timeout=5\n",
            ),
        ]);
        let diags = w04(&files, &CTX);
        let absent = w04_absence(&diags);
        assert!(
            absent
                .iter()
                .all(|d| !d.message.contains("timestamp_timeout")),
            "a drop-in timestamp_timeout satisfies the merged tree; got {absent:?}"
        );
    }

    /// CONFLICTING: two merged files set `timestamp_timeout` to DISTINCT values
    /// (`=5` and `=30`) -> a line-0 W04 conflict finding citing the control.
    #[test]
    fn w04_fires_for_conflicting_timestamp_timeout() {
        let files = parse_files(&[
            (
                "/etc/sudoers",
                "Defaults timestamp_timeout=5\nDefaults use_pty\nDefaults logfile=/var/log/sudo.log\nroot ALL=(ALL:ALL) ALL\n",
            ),
            ("/etc/sudoers.d/20-other", "Defaults timestamp_timeout=30\n"),
        ]);
        let diags = w04(&files, &CTX);
        let absent = w04_absence(&diags);
        assert!(
            absent
                .iter()
                .any(|d| d.message.contains("timestamp_timeout")
                    && d.message.contains("conflict")
                    && d.message.contains("RHEL-08-010384")),
            "two distinct timestamp_timeout values must fire a line-0 conflict W04 citing \
             RHEL-08-010384; got {absent:?}"
        );
    }

    /// The SAME `timestamp_timeout` value set twice across files is NOT a conflict:
    /// the value is unambiguous, so no conflict finding fires (and the presence
    /// satisfies the absence check).
    #[test]
    fn w04_no_conflict_when_same_timestamp_timeout_value_repeated() {
        let files = parse_files(&[
            (
                "/etc/sudoers",
                "Defaults timestamp_timeout=5\nDefaults use_pty\nDefaults logfile=/var/log/sudo.log\nroot ALL=(ALL:ALL) ALL\n",
            ),
            ("/etc/sudoers.d/20-other", "Defaults timestamp_timeout=5\n"),
        ]);
        let diags = w04(&files, &CTX);
        assert!(
            diags.iter().all(|d| !(d.code == "sudo-W04"
                && d.message.contains("timestamp_timeout")
                && d.message.contains("conflict"))),
            "the same value repeated is not a conflict; got {diags:?}"
        );
    }

    /// Signed-zero must not produce a spurious conflict: `timestamp_timeout=0` in
    /// one file and `timestamp_timeout=-0` in another are the SAME numeric value
    /// (0, compliant), so no conflict finding fires. (`(-0.0).to_string()` is "-0"
    /// while `(0.0).to_string()` is "0"; the dedup key must normalize signed zero.)
    #[test]
    fn w04_no_conflict_for_signed_zero_timestamp_timeout() {
        let files = parse_files(&[
            (
                "/etc/sudoers",
                "Defaults timestamp_timeout=0\nDefaults use_pty\nDefaults logfile=/var/log/sudo.log\nroot ALL=(ALL:ALL) ALL\n",
            ),
            ("/etc/sudoers.d/20-other", "Defaults timestamp_timeout=-0\n"),
        ]);
        let diags = w04(&files, &CTX);
        assert!(
            diags.iter().all(|d| !(d.code == "sudo-W04"
                && d.message.contains("timestamp_timeout")
                && d.message.contains("conflict"))),
            "0 and -0 are the same value; no conflict must fire; got {diags:?}"
        );
    }

    /// Differently-WRITTEN spellings of the same numeric value (`5`, `5.0`, `+5`)
    /// across merged files canonicalize to one entry, so NO conflict fires. Pins
    /// the canonical-collapse path of the dedup key.
    #[test]
    fn w04_no_conflict_for_equal_values_written_differently() {
        let files = parse_files(&[
            (
                "/etc/sudoers",
                "Defaults timestamp_timeout=5\nDefaults use_pty\nDefaults logfile=/var/log/sudo.log\nroot ALL=(ALL:ALL) ALL\n",
            ),
            ("/etc/sudoers.d/10-a", "Defaults timestamp_timeout=5.0\n"),
            ("/etc/sudoers.d/20-b", "Defaults timestamp_timeout=+5\n"),
        ]);
        let diags = w04(&files, &CTX);
        assert!(
            diags.iter().all(|d| !(d.code == "sudo-W04"
                && d.message.contains("timestamp_timeout")
                && d.message.contains("conflict"))),
            "5, 5.0 and +5 are the same value; no conflict must fire; got {diags:?}"
        );
    }

    /// A negated `Defaults !timestamp_timeout` is valid sudoers (cvtsudoers exports
    /// `{"timestamp_timeout": false}`); sudo treats a cleared timeout as
    /// re-prompt-on-every-invocation, functionally identical to `=0`. USER DECISION
    /// (#363): treat it as COMPLIANT -- it satisfies the absence requirement (no
    /// ABSENT finding), fires no weakening, and does not participate in conflict
    /// detection. With use_pty + logfile present, NO timestamp_timeout W04 of any
    /// kind fires.
    #[test]
    fn w04_negated_timestamp_timeout_is_compliant() {
        // visudo -c: "parsed OK"
        let diags = lint_w04(
            "Defaults !timestamp_timeout\nDefaults use_pty\nDefaults logfile=/var/log/sudo.log\nroot ALL=(ALL:ALL) ALL\n",
        );
        assert!(
            diags
                .iter()
                .all(|d| !(d.code == "sudo-W04" && d.message.contains("timestamp_timeout"))),
            "a negated !timestamp_timeout is compliant: no W04 of any kind; got {diags:?}"
        );
    }

    /// `parse_signed_minutes` rejects non-finite (`inf`/`infinity`/`nan`) and other
    /// forms sudo's own parser rejects: they are NOT valid timeouts, so they return
    /// `None` (treated as no usable value) rather than a finite f64 that would
    /// poison conflict dedup. A bare `inf` with use_pty + logfile present therefore
    /// behaves like an absent/unusable value: the ABSENT finding fires (no value was
    /// usable), and NO conflict/weakening fires.
    #[test]
    fn w04_non_finite_timestamp_timeout_is_not_a_usable_value() {
        assert_eq!(
            parse_signed_minutes("inf"),
            None,
            "inf is not a valid timeout"
        );
        assert_eq!(
            parse_signed_minutes("infinity"),
            None,
            "infinity is not a valid timeout"
        );
        assert_eq!(
            parse_signed_minutes("nan"),
            None,
            "nan is not a valid timeout"
        );
        assert_eq!(
            parse_signed_minutes("-inf"),
            None,
            "-inf is not a valid timeout"
        );
        // A finite value still parses.
        assert_eq!(parse_signed_minutes("15"), Some(15.0));
        assert_eq!(parse_signed_minutes("-1"), Some(-1.0));
    }

    /// With three missing requirements (no use_pty, no I/O logging, no
    /// timestamp_timeout) the merged absence check fires exactly THREE findings.
    #[test]
    fn w04_absence_fires_three_times_when_all_missing() {
        // visudo -c: "parsed OK"
        let diags = lint_w04("Defaults env_reset\nroot ALL=(ALL:ALL) ALL\n");
        let absent = w04_absence(&diags);
        assert_eq!(
            absent.len(),
            3,
            "use_pty + I/O logging + timestamp_timeout all missing -> three absence \
             findings; got {absent:?}"
        );
        assert!(
            absent
                .iter()
                .any(|d| d.message.contains("timestamp_timeout")),
            "one absence finding must name timestamp_timeout; got {absent:?}"
        );
    }

    // -----------------------------------------------------------------------
    // #485: sudo-W04 silent on an empty/whitespace-only linted FILE.
    //
    // `parse_one`/`lint_w04` above call `parser::parse` directly and BYPASS
    // `resolve::resolve_target`, so they cannot observe this bug: the resolver's
    // blank-only-segment drop (resolve.rs, the `flush` closure around line 146)
    // is what collapses an empty/whitespace-only top-level FILE to a zero-length
    // `Vec<SudoersFile>`, at which point `check_merged_required`'s
    // `files.first()` guard (line ~488) silently returns no findings. Every test
    // in this block drives the REAL `resolve::resolve_target` path so the bug
    // (and its fix) is actually observable.
    // -----------------------------------------------------------------------

    /// REGRESSION GUARD (verified via `resolve::resolve_target`, not the
    /// `parse_one`/`lint_w04` unit helpers which cannot see this): a
    /// comment-only file is NOT dropped by the resolver -- `LineKind::Comment`
    /// is distinct from `LineKind::Blank`, so the file's one logical line
    /// survives the blank-only-segment flush and the resolved slice carries
    /// ONE `SudoersFile`. Today this ALREADY fires all three merged-absence
    /// findings (use_pty, I/O logging, timestamp_timeout), matching the unit-level
    /// count pinned by `w04_absence_fires_three_times_when_all_missing`. This
    /// test must keep passing UNCHANGED after #485's fix lands (only the
    /// byte-empty / whitespace-only case is currently broken).
    #[test]
    fn comment_only_file_already_fires_all_three_absence_findings_via_resolver() {
        let dir = tempfile::tempdir().expect("tempdir");
        let f = dir.path().join("sudoers");
        std::fs::write(&f, "# just a comment\n").expect("write comment-only file");

        let files = resolve::resolve_target(&f).expect("resolve a comment-only file");
        assert_eq!(
            files.len(),
            1,
            "a comment-only file retains its one resolved segment (LineKind::Comment \
             survives the resolver's blank-only-segment drop); got {files:?}"
        );

        let diags = w04(&files, &CTX);
        let absent = w04_absence(&diags);
        assert_eq!(
            absent.len(),
            3,
            "a comment-only file already fires all three merged-absence findings \
             (use_pty, I/O logging, timestamp_timeout) via the real resolver path; \
             got {absent:?}"
        );
        assert!(
            absent.iter().any(|d| d.message.contains("use_pty")),
            "one absence finding must name use_pty; got {absent:?}"
        );
        assert!(
            absent.iter().any(|d| d.message.contains("logging")),
            "one absence finding must name I/O logging; got {absent:?}"
        );
        assert!(
            absent
                .iter()
                .any(|d| d.message.contains("timestamp_timeout")),
            "one absence finding must name timestamp_timeout; got {absent:?}"
        );
        for d in &absent {
            assert_eq!(d.line, 0, "absence findings anchor at line 0");
            assert_eq!(
                d.file, f,
                "absence findings anchor at the linted file's own path"
            );
        }
    }

    /// RED (#485, frozen): a byte-empty (0-byte) linted FILE must fire all three
    /// merged-absence findings (use_pty, I/O logging, timestamp_timeout), exactly
    /// matching the comment-only case above -- the orchestrator's locked decision
    /// is that empty is not a special "nothing to require against" case, it is the
    /// STRONGEST case (a merged config that is empty definitionally lacks every
    /// requirement). Today this is silent: the resolver's blank-only-segment drop
    /// (resolve.rs's `flush` closure) collapses a byte-empty top-level file to a
    /// zero-length `Vec<SudoersFile>`, and `check_merged_required`'s `files.first()`
    /// guard then returns no findings at all. That is the bug this test pins the
    /// fix for.
    #[test]
    fn byte_empty_file_fires_all_three_absence_findings_via_resolver() {
        let dir = tempfile::tempdir().expect("tempdir");
        let f = dir.path().join("sudoers");
        std::fs::write(&f, "").expect("write byte-empty file");

        let files = resolve::resolve_target(&f).expect("resolve a byte-empty file");
        assert_eq!(
            files.len(),
            1,
            "a byte-empty top-level file must resolve to ONE (synthesized) segment \
             so the merged-absence check has a top-level file to anchor findings \
             against, matching the comment-only case above; got {files:?}"
        );
        assert_eq!(
            files[0],
            parse("", &f),
            "the synthesized phantom segment must be EXACTLY what `parse()` \
             produces for the file's own (byte-empty) raw source text, not a \
             hand-fabricated `SudoersFile {{ source: String::new(), lines: \
             Vec::new(), .. }}` that happens to also carry zero settings; \
             pins the phantom's `source`/`lines` fields, not just its count; \
             got {files:?}"
        );

        let diags = w04(&files, &CTX);
        let absent = w04_absence(&diags);
        assert_eq!(
            absent.len(),
            3,
            "a byte-empty file must fire all three merged-absence findings \
             (use_pty, I/O logging, timestamp_timeout), matching the comment-only \
             case; got {absent:?}"
        );
        assert!(
            absent.iter().any(|d| d.message.contains("use_pty")),
            "one absence finding must name use_pty; got {absent:?}"
        );
        assert!(
            absent.iter().any(|d| d.message.contains("logging")),
            "one absence finding must name I/O logging; got {absent:?}"
        );
        assert!(
            absent
                .iter()
                .any(|d| d.message.contains("timestamp_timeout")),
            "one absence finding must name timestamp_timeout; got {absent:?}"
        );
        for d in &absent {
            assert_eq!(d.line, 0, "absence findings anchor at line 0");
            assert_eq!(
                d.file, f,
                "absence findings anchor at the linted file's own path"
            );
        }
    }

    /// RED (#485, frozen): a whitespace-only linted FILE (spaces/tabs/blank
    /// lines, no byte content that trims to non-empty) must fire the same three
    /// merged-absence findings as the byte-empty case above. `classify_logical_line`
    /// (parser.rs) treats a line whose trimmed text is empty as `LineKind::Blank`
    /// exactly like a truly empty line, so a whitespace-only file hits the SAME
    /// resolver blank-only-segment drop as the byte-empty case -- this is not a
    /// distinct code path, but pinned separately since #485 names it explicitly
    /// alongside byte-empty.
    #[test]
    fn whitespace_only_file_fires_all_three_absence_findings_via_resolver() {
        let dir = tempfile::tempdir().expect("tempdir");
        let f = dir.path().join("sudoers");
        let source = "   \n\t\n\n  \t  \n";
        std::fs::write(&f, source).expect("write whitespace-only file");

        let files = resolve::resolve_target(&f).expect("resolve a whitespace-only file");
        assert_eq!(
            files.len(),
            1,
            "a whitespace-only top-level file must resolve to ONE (synthesized) \
             segment so the merged-absence check has a top-level file to anchor \
             findings against, matching the comment-only case above; got {files:?}"
        );
        assert_eq!(
            files[0],
            parse(source, &f),
            "the synthesized phantom segment must be EXACTLY what `parse()` \
             produces for the file's own (whitespace-only) raw source text -- \
             its real `Blank`-classified lines, not a hand-fabricated \
             `SudoersFile {{ source: String::new(), lines: Vec::new(), .. }}` \
             that happens to also carry zero settings; pins the phantom's \
             `source`/`lines` fields, not just its count; got {files:?}"
        );

        let diags = w04(&files, &CTX);
        let absent = w04_absence(&diags);
        assert_eq!(
            absent.len(),
            3,
            "a whitespace-only file must fire all three merged-absence findings \
             (use_pty, I/O logging, timestamp_timeout), matching the comment-only \
             case; got {absent:?}"
        );
        assert!(
            absent.iter().any(|d| d.message.contains("use_pty")),
            "one absence finding must name use_pty; got {absent:?}"
        );
        assert!(
            absent.iter().any(|d| d.message.contains("logging")),
            "one absence finding must name I/O logging; got {absent:?}"
        );
        assert!(
            absent
                .iter()
                .any(|d| d.message.contains("timestamp_timeout")),
            "one absence finding must name timestamp_timeout; got {absent:?}"
        );
        for d in &absent {
            assert_eq!(d.line, 0, "absence findings anchor at line 0");
            assert_eq!(
                d.file, f,
                "absence findings anchor at the linted file's own path"
            );
        }
    }

    /// PIN (#485, frozen): the BROAD-vs-NARROW discriminator. The orchestrator's
    /// locked decision is BROAD: sudo-W04 fires whenever a linted FILE resolves to
    /// ZERO files, regardless of WHY -- not narrowly scoped to a byte-empty or
    /// whitespace-only SOURCE. A non-empty top-level FILE whose ONLY content is an
    /// `@includedir` directive pointing at an EMPTY directory resolves to zero
    /// entries from `resolve_parsed`'s own perspective: the file's own lines are
    /// entirely the include directive (flushed as an empty pending, nothing
    /// pushed), and the `@includedir` itself contributes no drop-ins (the target
    /// directory is empty). A NARROW fix gated on `source.trim().is_empty()` would
    /// NOT catch this -- the raw source is NOT blank, it has real directive text
    /// (`@includedir empty.d`) -- so it would stay silent here even though this
    /// test's byte-empty/whitespace-only siblings above pass under EITHER
    /// candidate impl. This is the ONE fixture that separates them: BROAD passes,
    /// NARROW fails.
    #[test]
    fn file_with_only_empty_includedir_fires_all_three_absence_findings_via_resolver() {
        let dir = tempfile::tempdir().expect("tempdir");
        let empty_inc = dir.path().join("empty.d");
        std::fs::create_dir_all(&empty_inc).expect("mkdir empty.d");
        let f = dir.path().join("sudoers");
        let source = "@includedir empty.d\n";
        std::fs::write(&f, source).expect("write includedir-only file");

        let files =
            resolve::resolve_target(&f).expect("resolve a file with only an empty includedir");
        assert_eq!(
            files.len(),
            1,
            "a top-level file whose ONLY content is an @includedir at an EMPTY \
             directory resolves to zero entries from resolve_parsed's own \
             perspective (the file's own lines are entirely the include \
             directive; the includedir contributes no drop-ins) -- the BROAD \
             fix must synthesize ONE phantom segment for the whole target \
             whenever resolution produces zero files, regardless of why (a \
             NARROW `source.trim().is_empty()` gate would leave this at 0, \
             since the raw source is NOT blank); got {files:?}"
        );
        assert_eq!(
            files[0],
            parse(source, &f),
            "the synthesized phantom segment must be EXACTLY what `parse()` \
             produces for the file's own raw source text (including its real \
             `Include` line), not a hand-fabricated `SudoersFile {{ source: \
             String::new(), lines: Vec::new(), .. }}`; got {files:?}"
        );

        let diags = w04(&files, &CTX);
        let absent = w04_absence(&diags);
        assert_eq!(
            absent.len(),
            3,
            "an @includedir-only file pointing at an empty directory must fire \
             all three merged-absence findings (use_pty, I/O logging, \
             timestamp_timeout) -- this is the case a NARROW \
             `source.trim().is_empty()` fix would wrongly leave silent; got \
             {absent:?}"
        );
        assert!(
            absent.iter().any(|d| d.message.contains("use_pty")),
            "one absence finding must name use_pty; got {absent:?}"
        );
        assert!(
            absent.iter().any(|d| d.message.contains("logging")),
            "one absence finding must name I/O logging; got {absent:?}"
        );
        assert!(
            absent
                .iter()
                .any(|d| d.message.contains("timestamp_timeout")),
            "one absence finding must name timestamp_timeout; got {absent:?}"
        );
        for d in &absent {
            assert_eq!(d.line, 0, "absence findings anchor at line 0");
            assert_eq!(
                d.file, f,
                "absence findings anchor at the linted file's own path"
            );
        }
    }

    /// PIN (#485, frozen): the fix's LOCATION discriminator. A DIRECTORY target
    /// whose only drop-in is byte-empty must resolve to ZERO files and fire NO
    /// sudo-W04 -- the #485 zero-result synthesis is scoped to
    /// `resolve_target_with_host`'s single-FILE branch ONLY; it must NOT reach
    /// into the per-drop-in resolution a DIRECTORY target performs. Firing here
    /// would reintroduce exactly the per-fragment false positive the
    /// merged-required design exists to avoid (module doc above,
    /// "Missing-required (merged, #347, #363)"): a `sudoers.d` drop-in flagged on
    /// its own is precisely the FP #347 exists to prevent, and a directory target
    /// has no singular top-level FILE to anchor a merged finding against in the
    /// first place. Distinct from `resolve::tests::empty_directory_resolves_to_no_files`
    /// (a dir with ZERO eligible entries): this fixture has ONE eligible drop-in
    /// whose CONTENT is empty, exercising the per-file zero-result fork itself
    /// rather than the eligible-entries enumeration.
    ///
    /// Kills a wrong impl that places the #485 zero-result check inside
    /// `resolve_parsed` (fires once per FILE processed, including each directory
    /// drop-in) instead of `resolve_target_with_host`'s FILE branch (fires once,
    /// only for a single top-level FILE target): that wrong impl synthesizes a
    /// phantom for the empty drop-in itself, producing `files.len() == 1` and
    /// THREE spurious sudo-W04 findings anchored at the drop-in's own path.
    /// EMPIRICALLY VERIFIED: with the wrong impl in place this assertion fails
    /// (`files.len()` is 1, not 0, and `diags` is non-empty); with the intended
    /// BROAD fix scoped to the FILE branch this test passes.
    #[test]
    fn directory_target_with_only_a_byte_empty_dropin_resolves_to_no_files_and_fires_no_w04() {
        let root = tempfile::tempdir().expect("tempdir");
        let dropin_dir = root.path().join("sudoers.d");
        std::fs::create_dir_all(&dropin_dir).expect("mkdir sudoers.d");
        std::fs::write(dropin_dir.join("10-empty"), "").expect("write byte-empty dropin");

        let files = resolve::resolve_target(&dropin_dir).expect("resolve directory target");
        assert_eq!(
            files.len(),
            0,
            "a DIRECTORY target whose only drop-in is byte-empty must resolve to \
             ZERO files: the #485 fix applies only to a top-level FILE target, \
             never to a per-drop-in resolution inside a directory target; got \
             {files:?}"
        );

        let diags = w04(&files, &CTX);
        assert!(
            diags.is_empty(),
            "an empty resolved slice (no top-level FILE to anchor a \
             merged-absence finding against) fires NO sudo-W04, matching \
             `w04_absence_empty_slice_no_findings`; got {diags:?}"
        );
    }

    /// PIN (#485, frozen): the fix's SCOPE discriminator (companion to the
    /// directory-target guard above). A parent file with a real rule of its own
    /// PLUS an `@include` of a byte-empty child must resolve to EXACTLY ONE
    /// segment (the parent's own content) -- the empty child contributes NOTHING,
    /// because the #485 zero-result synthesis fires only when resolving the WHOLE
    /// top-level FILE target ends with `out` EMPTY overall, not on each individual
    /// `resolve_parsed` call made along the way.
    ///
    /// Kills the same wrong impl as the directory-target guard above, from a
    /// different angle: a per-call fork (checking `out.len() == before` inside
    /// `resolve_parsed` itself) sees the NESTED child's resolution contribute zero
    /// of its OWN segments and synthesizes a phantom for the child anyway, even
    /// though the parent already pushed a real segment into `out` -- producing
    /// `files.len() == 2` (`[parent, phantom-child]`) instead of the correct 1.
    /// EMPIRICALLY VERIFIED: with the wrong impl in place `files.len()` is 2, not
    /// 1; with the intended BROAD fix scoped to the FILE branch this test passes.
    #[test]
    fn parent_rule_with_byte_empty_include_resolves_to_exactly_one_segment() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("parent"),
            "root ALL=(ALL:ALL) ALL\n@include child\n",
        )
        .expect("w parent");
        std::fs::write(dir.path().join("child"), "").expect("w byte-empty child");

        let files = resolve::resolve_target(&dir.path().join("parent")).expect("resolve");
        assert_eq!(
            files.len(),
            1,
            "a parent with a real rule plus an @include of a byte-empty child \
             resolves to EXACTLY the parent's own segment; the byte-empty child \
             contributes no phantom (the #485 fix is scoped to the WHOLE \
             top-level FILE target ending empty, not to each individual \
             resolve_parsed call); got {files:?}"
        );
        assert!(
            files[0].path.ends_with("parent"),
            "the one resolved segment is the parent's own content, not a \
             phantom for the empty child; got {files:?}"
        );
    }
}
