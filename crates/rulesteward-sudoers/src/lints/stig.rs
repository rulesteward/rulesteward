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
//!   DISA STIG RHEL-08-010381 / RHEL-09-432025
//!   (ComplianceAsCode `sudo_remove_no_authenticate`).
//! - `targetpw` / `rootpw` / `runaspw` -- prompts for the target/root/runas
//!   user's password rather than the invoking user's, breaking PAM/audit
//!   accountability.
//!   DISA STIG RHEL-08-010383 / RHEL-09-432020
//!   (ComplianceAsCode `sudoers_validate_passwd`).
//! - `visiblepw` -- allows sudo to proceed when the password would be visible
//!   (e.g. when a tty is not associated with stdin).
//!   CIS / general hardening; no DISA sudo STIG control.
//! - `!use_pty` (explicit negation of the pty requirement) -- deliberately
//!   disabling pseudo-terminal allocation is a present weakening.
//!   CIS Benchmark 1.3.2 / PCI-DSS Req-10.2.5; no DISA sudo STIG control
//!   (ComplianceAsCode `sudo_add_use_pty` carries no `stigid@` key; the
//!   RHEL-08-010382 it formerly cited is the unrelated "restrict privilege
//!   elevation to authorized personnel" control).
//! - `timestamp_timeout` with a NEGATIVE value (e.g. `-1`) -- the sudo credential
//!   cache then never expires, so a user re-authenticates once and is trusted
//!   indefinitely. A non-negative value (0 or positive) is compliant. This is a
//!   value-conditional weakening (handled in `check_file`'s non-negated arm, not
//!   the name-presence `WEAKENING_PRESENT` table).
//!   DISA STIG RHEL-08-010384 / RHEL-09-432015
//!   (ComplianceAsCode `sudo_require_reauthentication`, #363).
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
//! carries a `stigid@` mapping. They are CIS Benchmark 1.3.2 (use_pty) / 1.3.3
//! (logfile) + PCI-DSS Req-10.2.5 controls, and are cited as such.
//!
//! `timestamp_timeout` (#363) IS a DISA STIG control (RHEL-08-010384 /
//! RHEL-09-432015, ComplianceAsCode `sudo_require_reauthentication`) and fires here
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

use rulesteward_core::{Diagnostic, Severity};

use crate::ast::{DefaultsScope, LineKind, SudoersFile};
use crate::lints::{SudoersLintContext, anchored};

// ---------------------------------------------------------------------------
// Weakening settings: fire when any of these appear (any scope).
// ---------------------------------------------------------------------------

/// Non-negated settings that weaken the sudo security posture below the sudo
/// hardening baseline when present. Each tuple is
/// `(name_as_written, human_explanation, grounded_citation)`; the citation
/// (control id + framework) is appended to the diagnostic so an operator can
/// cross-reference the finding. It is re-grounded per the module doc and pinned
/// by `tests::w04_weakening_findings_cite_grounded_controls`.
///
/// Note: `!authenticate` is NOT in this table because it is a NEGATED setting
/// (`DefaultSetting { negated: true, name: "authenticate" }`); it is handled
/// separately in `check_file`'s negated arm. This table covers settings that
/// are dangerous when present WITHOUT a `!` prefix.
const WEAKENING_PRESENT: &[(&str, &str, &str)] = &[
    // targetpw: prompts for the target user's password rather than the invoking
    // user's -- breaks PAM accountability chain.
    (
        "targetpw",
        "prompts for the target user's password instead of the invoking user's; \
         breaks PAM accountability (re-auth must use the user's own credentials)",
        "DISA STIG RHEL-08-010383 / RHEL-09-432020",
    ),
    // rootpw: prompts for root's password -- also breaks accountability.
    (
        "rootpw",
        "prompts for the root password instead of the invoking user's; \
         breaks PAM accountability (re-auth must use the user's own credentials)",
        "DISA STIG RHEL-08-010383 / RHEL-09-432020",
    ),
    // runaspw: prompts for the run-as user's password.
    (
        "runaspw",
        "prompts for the run-as user's password instead of the invoking user's; \
         breaks PAM accountability (re-auth must use the user's own credentials)",
        "DISA STIG RHEL-08-010383 / RHEL-09-432020",
    ),
    // visiblepw: allows sudo when the password would be echoed in plain text.
    (
        "visiblepw",
        "allows sudo to proceed when the password would be visible on the terminal; \
         the CIS / general hardening baseline requires this to be disabled",
        "CIS / general hardening; not a DISA STIG control",
    ),
];

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
                match name {
                    // `!authenticate`: disables per-invocation password re-authentication.
                    // DISA STIG RHEL-08-010381 / RHEL-09-432025.
                    "authenticate" => {
                        diags.push(anchored(
                            Severity::Warning,
                            "sudo-W04",
                            line.span.clone(),
                            format!(
                                "Defaults setting '!authenticate' {} disables \
                                 per-invocation sudo re-authentication; \
                                 STIG requires authentication for every invocation \
                                 (DISA STIG RHEL-08-010381 / RHEL-09-432025)",
                                scope_paren(&defaults.scope),
                            ),
                            &file.path,
                            line.line,
                        ));
                    }
                    // `!use_pty`: explicit negation of the pty requirement.
                    // CIS Benchmark 1.3.2 / PCI-DSS Req-10.2.5; no DISA sudo STIG control.
                    "use_pty" => {
                        diags.push(anchored(
                            Severity::Warning,
                            "sudo-W04",
                            line.span.clone(),
                            format!(
                                "Defaults setting '!use_pty' {} disables \
                                 pseudo-terminal allocation; the CIS / PCI hardening \
                                 baseline requires 'Defaults use_pty' to prevent I/O \
                                 redirection attacks \
                                 (CIS Benchmark 1.3.2 / PCI-DSS Req-10.2.5; \
                                 not a DISA STIG control)",
                                scope_paren(&defaults.scope),
                            ),
                            &file.path,
                            line.line,
                        ));
                    }
                    _ => {}
                }
                continue; // done with this negated setting
            }

            // --- Non-negated checks ---

            // `timestamp_timeout` with a NEGATIVE value: a value-conditional
            // weakening (not mere name-presence), so it is handled here rather than
            // via the `WEAKENING_PRESENT` name table. A negative timeout (e.g. -1)
            // makes the sudo credential cache NEVER expire, so a user re-authenticates
            // once and is then trusted indefinitely. A non-negative value (0 or
            // positive) is compliant. DISA STIG RHEL-08-010384 / RHEL-09-432015.
            if name == "timestamp_timeout"
                && setting
                    .value
                    .as_deref()
                    .and_then(parse_signed_minutes)
                    .is_some_and(|v| v < 0.0)
            {
                diags.push(anchored(
                    Severity::Warning,
                    "sudo-W04",
                    line.span.clone(),
                    format!(
                        "Defaults setting 'timestamp_timeout' {} sets a negative value: \
                         the sudo credential cache never expires, so a user is \
                         re-authenticated once and trusted indefinitely; STIG requires \
                         re-authentication (a non-negative timeout) \
                         (DISA STIG RHEL-08-010384 / RHEL-09-432015)",
                        scope_paren(&defaults.scope),
                    ),
                    &file.path,
                    line.line,
                ));
            }

            // Fire for weakening non-negated settings (all entries in the table;
            // `!authenticate` is handled in the negated arm above).
            for &(weakening_name, explanation, citation) in WEAKENING_PRESENT {
                if name == weakening_name {
                    diags.push(anchored(
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
                    ));
                }
            }
        }
    }

    diags
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

    let mut has_use_pty = false;
    let mut has_io_log = false;
    // Distinct `timestamp_timeout` values seen across the WHOLE merged tree, in
    // first-seen order. The sudoers model retains every occurrence (no last-wins
    // collapse), so 2+ distinct values is a detectable conflict. Each value is
    // canonicalised through `parse_signed_minutes` and re-rendered so `=5` / `=05` /
    // `=5.0` collapse to one entry (they ARE the same timeout); the canonical
    // strings are the dedup key, avoiding fragile direct `f64` equality. The key is
    // built from `v + 0.0` so signed zero normalizes (`-0.0` -> `0.0`), preventing a
    // spurious `=0` vs `=-0` "conflict" (both are the same compliant value, 0).
    let mut timestamp_values: Vec<String> = Vec::new();
    // A `Defaults !timestamp_timeout` (negated) clears the timeout, which sudo
    // treats as re-prompt-on-every-invocation -- functionally identical to `=0` and
    // therefore COMPLIANT (#363 user decision). It SATISFIES the presence/absence
    // requirement but contributes NO value to conflict detection and fires no
    // weakening, so it is tracked separately from the positive-value list.
    let mut has_negated_timestamp_timeout = false;
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

    let mut diags = Vec::new();
    if !has_use_pty {
        diags.push(anchored(
            Severity::Warning,
            "sudo-W04",
            0..0,
            "required 'Defaults use_pty' is not set anywhere in the resolved \
             sudoers configuration; without it sudo does not allocate a \
             pseudo-terminal, leaving privileged sessions open to I/O redirection \
             (CIS Benchmark 1.3.2 / PCI-DSS Req-10.2.5; not a DISA STIG control)",
            &top.path,
            0,
        ));
    }
    if !has_io_log {
        diags.push(anchored(
            Severity::Warning,
            "sudo-W04",
            0..0,
            "required sudo I/O logging is not configured anywhere in the resolved \
             sudoers configuration (no 'Defaults logfile=' or 'Defaults \
             log_output'); privileged command sessions are not recorded for audit \
             (CIS Benchmark 1.3.3 / PCI-DSS Req-10.2.5; not a DISA STIG control)",
            &top.path,
            0,
        ));
    }
    // timestamp_timeout (#363, DISA STIG RHEL-08-010384 / RHEL-09-432015,
    // ComplianceAsCode `sudo_require_reauthentication`):
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
        [] if !has_negated_timestamp_timeout => diags.push(anchored(
            Severity::Warning,
            "sudo-W04",
            0..0,
            "required 'Defaults timestamp_timeout' is not set anywhere in the \
             resolved sudoers configuration; without an explicit re-authentication \
             timeout sudo relies on the compiled-in default, so the policy does not \
             demonstrably require re-authentication \
             (DISA STIG RHEL-08-010384 / RHEL-09-432015)",
            &top.path,
            0,
        )),
        [] => {}        // negated `!timestamp_timeout` only: compliant clear, nothing fires.
        [_single] => {} // exactly one value: unambiguous (compliance handled elsewhere).
        _multiple => diags.push(anchored(
            Severity::Warning,
            "sudo-W04",
            0..0,
            "conflicting 'Defaults timestamp_timeout' values are set across the \
             resolved sudoers configuration (the key is given more than one distinct \
             value); the effective re-authentication timeout is ambiguous \
             (DISA STIG RHEL-08-010384 / RHEL-09-432015)",
            &top.path,
            0,
        )),
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
    /// Grounding: CIS Benchmark 1.3.2 / PCI-DSS Req-10.2.5; no DISA sudo STIG control.
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
    /// - `use_pty` (incl. `!use_pty`) -> CIS Benchmark 1.3.2 / PCI-DSS Req-10.2.5
    ///   (no DISA sudo STIG control)
    /// - `visiblepw` -> CIS / general hardening (no DISA STIG control)
    /// - `timestamp_timeout` (negative value) -> DISA STIG RHEL-08-010384 /
    ///   RHEL-09-432015 (ComplianceAsCode `sudo_require_reauthentication`, #363)
    ///
    /// If this fails, RE-RUN the grounding pass against a pinned ComplianceAsCode
    /// commit + DISA -- do NOT just edit the string to make it pass (#355, #359, #363).
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
            ("Defaults !use_pty\n", "CIS Benchmark 1.3.2"),
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
        let must_not_cite = [
            ("Defaults !authenticate\n", "010383"), // swapped: !authenticate is 010381
            ("Defaults targetpw\n", "010381"),      // swapped: pw family is 010383
            ("Defaults !use_pty\n", "RHEL-08-010382"), // use_pty has no DISA STIG id
            ("Defaults !use_pty\n", "RHEL-09-432020"), // 432020 is the pw control, not use_pty
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
}
