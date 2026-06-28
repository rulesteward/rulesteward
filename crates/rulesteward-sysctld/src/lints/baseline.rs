//! `sysctld-W02` - the STIG kernel-hardening baseline check (issue #335).
//!
//! Fires when a STIG-required sysctl key is, in the effective config:
//! * ABSENT (unset) -> one Warning anchored at the file/dir (no source line), or
//! * PRESENT but set to a value outside the STIG-accepted set -> one Warning
//!   anchored at the offending assignment's real line/span (an ariadne snippet,
//!   exactly like `sysctld-W01` anchors its dead line).
//!
//! W02 is version-aware: it runs only when a `--target` baseline is selected
//! (rhel8/rhel9/rhel10); with no target the backend stays version-agnostic and
//! emits no W02. The baseline tables are transcribed verbatim from
//! `rulesteward-docs/sysctld-stig-baseline-grounding.md`, which grounds every
//! key + accepted-value set against ComplianceAsCode/content at the pinned commit
//! `519b5fe8ce338cfa25d53065bcb3759aafe8d36d` (the controls file is the
//! authoritative key set; each rule.yml `sysctlval` / `_value.var` default is the
//! accepted value, resolved per product) and was gated by the
//! source-adversarial-reviewer.
//!
//! Two STIG-listed keys are DELIBERATELY EXCLUDED because neither is settable via
//! `/etc/sysctl.d` on RHEL (so flagging them "missing" would be an unfixable false
//! positive): `crypto.fips_enabled` (boot-time `fips=1`, read-only in /proc/sys)
//! and `kernel.exec-shield` (a GRUB `noexec` / 32-bit-only check on RHEL). See the
//! grounding doc's "Flagged" section.

use std::path::Path;

use rulesteward_core::{Diagnostic, Severity, anchored};

use crate::parser::{ParsedAssignment, canonical_key, effective_values};

/// RHEL release whose STIG sysctl baseline to check against. Clap-free (the CLI
/// maps its `--target` value-enum into this via a `From` impl); mirrors
/// `rulesteward_sshd::TargetVersion` so each domain crate stays clap-free.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetVersion {
    Rhel8,
    Rhel9,
    Rhel10,
}

/// How a key's value is compared against the STIG-accepted set.
#[derive(Clone, Copy)]
pub(crate) enum ValueKind {
    /// Integer sysctl: compare by the kernel's EFFECTIVE value. The kernel parses
    /// an int sysctl with base-0 radix (`strtoul_lenient(p, &p, 0, val)` in
    /// `proc_get_long`), so `0x1` / `01` are the same effective value as `1`. A raw
    /// string compare would over-flag those compliant forms.
    Int,
    /// String sysctl (e.g. `kernel.core_pattern`, OVAL datatype `string`):
    /// exact-match the trimmed value verbatim, no numeric normalization.
    Exact,
}

/// One STIG-required kernel-hardening key.
pub(crate) struct BaselineKey {
    /// The sysctl key in DOTTED form, as the STIG lists it and operators write it
    /// (e.g. `net.ipv4.conf.all.rp_filter`). Canonicalized via
    /// [`crate::parser::canonical_key`] for the effective-value-map lookup, and
    /// shown verbatim in the diagnostic message.
    pub(crate) key: &'static str,
    /// The STIG-accepted value(s). Most keys have exactly one (`["1"]`); a few
    /// accept a set (e.g. `kernel.kptr_restrict` on rhel9/rhel10 accepts `1` OR
    /// `2`). A present assignment whose effective value is not in this set fires W02.
    pub(crate) accepted: &'static [&'static str],
    /// The STIG control id (e.g. `RHEL-09-213010`), surfaced in the message.
    pub(crate) stig_id: &'static str,
    /// Whether the value compares numerically ([`ValueKind::Int`]) or as an exact
    /// string ([`ValueKind::Exact`], the string-typed `kernel.core_pattern`).
    pub(crate) kind: ValueKind,
}

/// The grounded baseline table for `target`.
pub(crate) fn baseline_for(target: TargetVersion) -> &'static [BaselineKey] {
    match target {
        TargetVersion::Rhel8 => RHEL8_BASELINE,
        TargetVersion::Rhel9 => RHEL9_BASELINE,
        TargetVersion::Rhel10 => RHEL10_BASELINE,
    }
}

// Accepted-value sets, named for readability. Most STIG keys require a single
// value; the set-valued ones are spelled out so a divergence is obvious.
const DISABLE: &[&str] = &["0"];
const ENABLE: &[&str] = &["1"];
const VALUE_2: &[&str] = &["2"];
const ONE_OR_TWO: &[&str] = &["1", "2"];
/// `kernel.core_pattern` is a STRING-typed key; the STIG requires this exact value
/// (pipe a crashing process to `/bin/false`, i.e. produce no core dump).
const NO_CORE_DUMP: &[&str] = &["|/bin/false"];

// ---------------------------------------------------------------------------
// Grounded baseline tables (Phase 0 / issue #335), transcribed from
// rulesteward-docs/sysctld-stig-baseline-grounding.md @ pinned commit
// 519b5fe8ce338cfa25d53065bcb3759aafe8d36d, gated by the adversarial reviewer.
// `crypto.fips_enabled` and `kernel.exec-shield` are intentionally excluded
// (not /etc/sysctl.d-settable on RHEL).
// ---------------------------------------------------------------------------

/// RHEL 8 STIG sysctl baseline (28 keys; `RHEL-08-*` ID series).
const RHEL8_BASELINE: &[BaselineKey] = &[
    k("fs.protected_hardlinks", ENABLE, "RHEL-08-010374"),
    k("fs.protected_symlinks", ENABLE, "RHEL-08-010373"),
    k_exact("kernel.core_pattern", NO_CORE_DUMP, "RHEL-08-010671"),
    k("kernel.dmesg_restrict", ENABLE, "RHEL-08-010375"),
    k("kernel.kexec_load_disabled", ENABLE, "RHEL-08-010372"),
    k("kernel.kptr_restrict", ENABLE, "RHEL-08-040283"),
    k("kernel.perf_event_paranoid", VALUE_2, "RHEL-08-010376"),
    k("kernel.randomize_va_space", VALUE_2, "RHEL-08-010430"),
    k("kernel.unprivileged_bpf_disabled", ENABLE, "RHEL-08-040281"),
    k("kernel.yama.ptrace_scope", ENABLE, "RHEL-08-040282"),
    k("net.core.bpf_jit_harden", VALUE_2, "RHEL-08-040286"),
    k(
        "net.ipv4.conf.all.accept_redirects",
        DISABLE,
        "RHEL-08-040279",
    ),
    k(
        "net.ipv4.conf.all.accept_source_route",
        DISABLE,
        "RHEL-08-040239",
    ),
    k("net.ipv4.conf.all.forwarding", DISABLE, "RHEL-08-040259"),
    k("net.ipv4.conf.all.rp_filter", ONE_OR_TWO, "RHEL-08-040285"),
    k(
        "net.ipv4.conf.all.send_redirects",
        DISABLE,
        "RHEL-08-040220",
    ),
    k(
        "net.ipv4.conf.default.accept_redirects",
        DISABLE,
        "RHEL-08-040209",
    ),
    k(
        "net.ipv4.conf.default.accept_source_route",
        DISABLE,
        "RHEL-08-040249",
    ),
    k(
        "net.ipv4.conf.default.send_redirects",
        DISABLE,
        "RHEL-08-040270",
    ),
    k(
        "net.ipv4.icmp_echo_ignore_broadcasts",
        ENABLE,
        "RHEL-08-040230",
    ),
    k("net.ipv6.conf.all.accept_ra", DISABLE, "RHEL-08-040261"),
    k(
        "net.ipv6.conf.all.accept_redirects",
        DISABLE,
        "RHEL-08-040280",
    ),
    k(
        "net.ipv6.conf.all.accept_source_route",
        DISABLE,
        "RHEL-08-040240",
    ),
    k("net.ipv6.conf.all.forwarding", DISABLE, "RHEL-08-040260"),
    k("net.ipv6.conf.default.accept_ra", DISABLE, "RHEL-08-040262"),
    k(
        "net.ipv6.conf.default.accept_redirects",
        DISABLE,
        "RHEL-08-040210",
    ),
    k(
        "net.ipv6.conf.default.accept_source_route",
        DISABLE,
        "RHEL-08-040250",
    ),
    k("user.max_user_namespaces", DISABLE, "RHEL-08-040284"),
];

/// RHEL 9 STIG sysctl baseline (33 keys; `RHEL-09-*` ID series).
const RHEL9_BASELINE: &[BaselineKey] = &[
    k("fs.protected_hardlinks", ENABLE, "RHEL-09-213030"),
    k("fs.protected_symlinks", ENABLE, "RHEL-09-213035"),
    k_exact("kernel.core_pattern", NO_CORE_DUMP, "RHEL-09-213040"),
    k("kernel.dmesg_restrict", ENABLE, "RHEL-09-213010"),
    k("kernel.kexec_load_disabled", ENABLE, "RHEL-09-213020"),
    // DIVERGENCE: rhel9/rhel10 accept 1 OR 2 (rhel8 accepts only 1).
    k("kernel.kptr_restrict", ONE_OR_TWO, "RHEL-09-213025"),
    k("kernel.perf_event_paranoid", VALUE_2, "RHEL-09-213015"),
    k("kernel.randomize_va_space", VALUE_2, "RHEL-09-213070"),
    k("kernel.unprivileged_bpf_disabled", ENABLE, "RHEL-09-213075"),
    k("kernel.yama.ptrace_scope", ENABLE, "RHEL-09-213080"),
    k("net.core.bpf_jit_harden", VALUE_2, "RHEL-09-251045"),
    k(
        "net.ipv4.conf.all.accept_redirects",
        DISABLE,
        "RHEL-09-253015",
    ),
    k(
        "net.ipv4.conf.all.accept_source_route",
        DISABLE,
        "RHEL-09-253020",
    ),
    k("net.ipv4.conf.all.forwarding", DISABLE, "RHEL-09-253075"),
    k("net.ipv4.conf.all.log_martians", ENABLE, "RHEL-09-253025"),
    // DIVERGENCE: rhel9 accepts ONLY 1 (rhel8/rhel10 accept 1 OR 2).
    k("net.ipv4.conf.all.rp_filter", ENABLE, "RHEL-09-253035"),
    k(
        "net.ipv4.conf.all.send_redirects",
        DISABLE,
        "RHEL-09-253065",
    ),
    k(
        "net.ipv4.conf.default.accept_redirects",
        DISABLE,
        "RHEL-09-253040",
    ),
    k(
        "net.ipv4.conf.default.accept_source_route",
        DISABLE,
        "RHEL-09-253045",
    ),
    k(
        "net.ipv4.conf.default.log_martians",
        ENABLE,
        "RHEL-09-253030",
    ),
    k("net.ipv4.conf.default.rp_filter", ENABLE, "RHEL-09-253050"),
    k(
        "net.ipv4.conf.default.send_redirects",
        DISABLE,
        "RHEL-09-253070",
    ),
    k(
        "net.ipv4.icmp_echo_ignore_broadcasts",
        ENABLE,
        "RHEL-09-253055",
    ),
    k(
        "net.ipv4.icmp_ignore_bogus_error_responses",
        ENABLE,
        "RHEL-09-253060",
    ),
    k("net.ipv4.tcp_syncookies", ENABLE, "RHEL-09-253010"),
    k("net.ipv6.conf.all.accept_ra", DISABLE, "RHEL-09-254010"),
    k(
        "net.ipv6.conf.all.accept_redirects",
        DISABLE,
        "RHEL-09-254015",
    ),
    k(
        "net.ipv6.conf.all.accept_source_route",
        DISABLE,
        "RHEL-09-254020",
    ),
    k("net.ipv6.conf.all.forwarding", DISABLE, "RHEL-09-254025"),
    k("net.ipv6.conf.default.accept_ra", DISABLE, "RHEL-09-254030"),
    k(
        "net.ipv6.conf.default.accept_redirects",
        DISABLE,
        "RHEL-09-254035",
    ),
    k(
        "net.ipv6.conf.default.accept_source_route",
        DISABLE,
        "RHEL-09-254040",
    ),
    k("user.max_user_namespaces", DISABLE, "RHEL-09-213105"),
];

/// RHEL 10 STIG sysctl baseline (32 keys; `RHEL-10-*` ID series).
/// Differs from rhel9: `all.rp_filter` accepts 1 OR 2, and
/// `user.max_user_namespaces` is NOT in the rhel10 baseline.
const RHEL10_BASELINE: &[BaselineKey] = &[
    k("fs.protected_hardlinks", ENABLE, "RHEL-10-701070"),
    k("fs.protected_symlinks", ENABLE, "RHEL-10-701080"),
    k_exact("kernel.core_pattern", NO_CORE_DUMP, "RHEL-10-701090"),
    k("kernel.dmesg_restrict", ENABLE, "RHEL-10-701030"),
    k("kernel.kexec_load_disabled", ENABLE, "RHEL-10-701050"),
    k("kernel.kptr_restrict", ONE_OR_TWO, "RHEL-10-701060"),
    k("kernel.perf_event_paranoid", VALUE_2, "RHEL-10-701040"),
    k("kernel.randomize_va_space", VALUE_2, "RHEL-10-701130"),
    k("kernel.unprivileged_bpf_disabled", ENABLE, "RHEL-10-800030"),
    k("kernel.yama.ptrace_scope", ENABLE, "RHEL-10-701140"),
    k("net.core.bpf_jit_harden", VALUE_2, "RHEL-10-800050"),
    k(
        "net.ipv4.conf.all.accept_redirects",
        DISABLE,
        "RHEL-10-800090",
    ),
    k(
        "net.ipv4.conf.all.accept_source_route",
        DISABLE,
        "RHEL-10-800100",
    ),
    k("net.ipv4.conf.all.forwarding", DISABLE, "RHEL-10-800210"),
    k("net.ipv4.conf.all.log_martians", ENABLE, "RHEL-10-800110"),
    k("net.ipv4.conf.all.rp_filter", ONE_OR_TWO, "RHEL-10-800130"),
    k(
        "net.ipv4.conf.all.send_redirects",
        DISABLE,
        "RHEL-10-800190",
    ),
    k(
        "net.ipv4.conf.default.accept_redirects",
        DISABLE,
        "RHEL-10-800140",
    ),
    k(
        "net.ipv4.conf.default.accept_source_route",
        DISABLE,
        "RHEL-10-800150",
    ),
    k(
        "net.ipv4.conf.default.log_martians",
        ENABLE,
        "RHEL-10-800120",
    ),
    k("net.ipv4.conf.default.rp_filter", ENABLE, "RHEL-10-800160"),
    k(
        "net.ipv4.conf.default.send_redirects",
        DISABLE,
        "RHEL-10-800200",
    ),
    k(
        "net.ipv4.icmp_echo_ignore_broadcasts",
        ENABLE,
        "RHEL-10-800170",
    ),
    k(
        "net.ipv4.icmp_ignore_bogus_error_responses",
        ENABLE,
        "RHEL-10-800180",
    ),
    k("net.ipv4.tcp_syncookies", ENABLE, "RHEL-10-800080"),
    k("net.ipv6.conf.all.accept_ra", DISABLE, "RHEL-10-800220"),
    k(
        "net.ipv6.conf.all.accept_redirects",
        DISABLE,
        "RHEL-10-800230",
    ),
    k(
        "net.ipv6.conf.all.accept_source_route",
        DISABLE,
        "RHEL-10-800240",
    ),
    k("net.ipv6.conf.all.forwarding", DISABLE, "RHEL-10-800250"),
    k("net.ipv6.conf.default.accept_ra", DISABLE, "RHEL-10-800260"),
    k(
        "net.ipv6.conf.default.accept_redirects",
        DISABLE,
        "RHEL-10-800270",
    ),
    k(
        "net.ipv6.conf.default.accept_source_route",
        DISABLE,
        "RHEL-10-800280",
    ),
];

/// Terse table constructor for an INT-typed key (the common case).
const fn k(
    key: &'static str,
    accepted: &'static [&'static str],
    stig_id: &'static str,
) -> BaselineKey {
    BaselineKey {
        key,
        accepted,
        stig_id,
        kind: ValueKind::Int,
    }
}

/// Constructor for a STRING-typed key (compared verbatim, no numeric normalization).
/// Only `kernel.core_pattern` is string-typed in the STIG sysctl baseline.
const fn k_exact(
    key: &'static str,
    accepted: &'static [&'static str],
    stig_id: &'static str,
) -> BaselineKey {
    BaselineKey {
        key,
        accepted,
        stig_id,
        kind: ValueKind::Exact,
    }
}

/// Run the STIG baseline pass over the effective (precedence-ordered) assignments
/// for `target`. `anchor` is the file (single-file mode) or directory (drop-in
/// mode) a MISSING key is reported against (it has no source line). A
/// present-but-insecure key is anchored at its real assignment instead.
#[must_use]
pub(crate) fn w02_baseline(
    assignments: &[ParsedAssignment],
    target: TargetVersion,
    anchor: &Path,
) -> Vec<Diagnostic> {
    // The effective value of each key is its winning (last) assignment - the same
    // last-wins map sysctld-W01 reasons over, so W01 and W02 agree on identity.
    let effective = effective_values(assignments);

    let mut diags = Vec::new();
    for key in baseline_for(target) {
        let canonical = canonical_key(key.key);
        match effective.get(canonical.as_str()) {
            // Unset across the effective config: a STIG gap with no source line, so
            // anchor at the file/dir (line 0, no source_id -> plain `file:0:0` line).
            None => diags.push(Diagnostic::new(
                Severity::Warning,
                "sysctld-W02",
                0..0,
                missing_message(key),
                anchor.to_path_buf(),
                0,
                0,
            )),
            // Present: a value outside the STIG-accepted set is insecure, anchored
            // at the real assignment (its span/line -> ariadne snippet). A value in
            // the set is compliant and emits nothing.
            Some(&idx) => {
                let assignment = &assignments[idx];
                if !is_compliant(key, &assignment.value) {
                    diags.push(anchored(
                        Severity::Warning,
                        "sysctld-W02",
                        assignment.span.clone(),
                        insecure_message(key, &assignment.value),
                        assignment.file.clone(),
                        assignment.line,
                    ));
                }
            }
        }
    }
    diags
}

/// Render the accepted set for the message: a single value as `requires <v>`, a
/// set as `requires one of <v1>, <v2>`, so the operator sees which value(s) are
/// compliant.
fn requirement_phrase(accepted: &[&str]) -> String {
    if let [only] = accepted {
        format!("requires `{only}`")
    } else {
        let list = accepted
            .iter()
            .map(|v| format!("`{v}`"))
            .collect::<Vec<_>>()
            .join(", ");
        format!("requires one of {list}")
    }
}

fn missing_message(key: &BaselineKey) -> String {
    format!(
        "STIG-required key `{}` is unset ({} {})",
        key.key,
        key.stig_id,
        requirement_phrase(key.accepted),
    )
}

fn insecure_message(key: &BaselineKey, found: &str) -> String {
    format!(
        "STIG-required key `{}` = `{}` is insecure ({} {})",
        key.key,
        found,
        key.stig_id,
        requirement_phrase(key.accepted),
    )
}

/// Whether `value` (a present assignment's trimmed value) is STIG-compliant for
/// `key`: an exact-string match for a [`ValueKind::Exact`] key, or an effective
/// integer match (the kernel's base-0 parse) for a [`ValueKind::Int`] key, so the
/// kernel-equivalent forms `0x1` / `01` of `1` are accepted.
fn is_compliant(key: &BaselineKey, value: &str) -> bool {
    match key.kind {
        ValueKind::Exact => key.accepted.contains(&value),
        ValueKind::Int => match parse_sysctl_int(value) {
            Some(found) => key
                .accepted
                .iter()
                .any(|accepted| parse_sysctl_int(accepted) == Some(found)),
            // Not a parseable integer -> not the required value (flag it).
            None => false,
        },
    }
}

/// Parse an integer sysctl value the way the kernel does: base-0 radix detection
/// (`0x`/`0X` -> hex, a leading `0` -> octal, otherwise decimal) with an optional
/// single leading `-`. Returns `None` for anything that is not a clean integer (so
/// it is flagged, never silently accepted). Mirrors
/// `strtoul_lenient(p, &p, 0, val)` / `_parse_integer_fixup_radix` in the kernel.
fn parse_sysctl_int(value: &str) -> Option<i64> {
    let value = value.trim();
    let (negative, digits) = match value.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, value),
    };
    let (radix, body) = if let Some(hex) = digits
        .strip_prefix("0x")
        .or_else(|| digits.strip_prefix("0X"))
    {
        (16, hex)
    } else if digits.len() > 1 && digits.starts_with('0') {
        (8, &digits[1..])
    } else {
        (10, digits)
    };
    // `from_str_radix` accepts a leading sign; the kernel does not (the one leading
    // `-` was already split off), so reject any remaining sign in `body`.
    if body.is_empty() || body.starts_with('+') || body.starts_with('-') {
        return None;
    }
    // An out-of-`i64` magnitude makes `from_str_radix` return `Err` -> `None`, so
    // an absurd value is flagged rather than silently wrapped.
    let magnitude = i64::from_str_radix(body, radix).ok()?;
    Some(if negative { -magnitude } else { magnitude })
}

#[cfg(test)]
mod tests {
    use super::{
        BaselineKey, RHEL8_BASELINE, RHEL9_BASELINE, RHEL10_BASELINE, TargetVersion, ValueKind,
        baseline_for, is_compliant, parse_sysctl_int, requirement_phrase,
    };
    use crate::parser::canonical_key;

    fn all_tables() -> [(TargetVersion, &'static [BaselineKey]); 3] {
        [
            (TargetVersion::Rhel8, RHEL8_BASELINE),
            (TargetVersion::Rhel9, RHEL9_BASELINE),
            (TargetVersion::Rhel10, RHEL10_BASELINE),
        ]
    }

    #[test]
    fn baseline_tables_have_the_grounded_sizes() {
        // Pins completeness against the grounding doc (controls-file key counts
        // minus the 2 deliberately-excluded non-sysctl keys: fips_enabled,
        // exec-shield). A dropped/added key changes one of these counts.
        assert_eq!(RHEL8_BASELINE.len(), 28, "rhel8 STIG sysctl key count");
        assert_eq!(RHEL9_BASELINE.len(), 33, "rhel9 STIG sysctl key count");
        assert_eq!(RHEL10_BASELINE.len(), 32, "rhel10 STIG sysctl key count");
    }

    #[test]
    fn baseline_for_returns_the_matching_table() {
        assert_eq!(
            baseline_for(TargetVersion::Rhel8).len(),
            RHEL8_BASELINE.len()
        );
        assert_eq!(
            baseline_for(TargetVersion::Rhel9).len(),
            RHEL9_BASELINE.len()
        );
        assert_eq!(
            baseline_for(TargetVersion::Rhel10).len(),
            RHEL10_BASELINE.len()
        );
    }

    #[test]
    fn no_duplicate_keys_per_target_by_canonical_form() {
        // Two table keys must not canonicalize to the same /proc/sys path (that
        // would double-count or shadow a key in the lookup).
        for (t, table) in all_tables() {
            let mut seen = std::collections::HashSet::new();
            for k in table {
                assert!(
                    seen.insert(canonical_key(k.key)),
                    "{t:?} has a duplicate key {:?}",
                    k.key
                );
            }
        }
    }

    #[test]
    fn every_key_has_a_nonempty_accepted_set_and_stig_id() {
        for (t, table) in all_tables() {
            for k in table {
                assert!(
                    !k.accepted.is_empty(),
                    "{t:?} key {:?} has no accepted values",
                    k.key
                );
                assert!(
                    k.accepted.iter().all(|v| !v.is_empty()),
                    "{t:?} key {:?} has an empty accepted value",
                    k.key
                );
                assert!(
                    !k.stig_id.is_empty(),
                    "{t:?} key {:?} has an empty STIG id",
                    k.key
                );
            }
        }
    }

    #[test]
    fn excluded_non_sysctl_keys_are_absent_from_every_table() {
        // The two STIG keys that are NOT writable via /etc/sysctl.d on RHEL must
        // never appear (flagging them "missing" would be an unfixable false
        // positive). Pins the deliberate exclusion against an accidental re-add.
        for (t, table) in all_tables() {
            for excluded in ["crypto.fips_enabled", "kernel.exec-shield"] {
                assert!(
                    !table.iter().any(|k| k.key == excluded),
                    "{t:?} must not include the non-sysctl-settable key {excluded:?}"
                );
            }
        }
    }

    #[test]
    fn requirement_phrase_singular_vs_set() {
        assert_eq!(requirement_phrase(&["1"]), "requires `1`");
        assert_eq!(requirement_phrase(&["1", "2"]), "requires one of `1`, `2`");
    }

    #[test]
    fn parse_sysctl_int_uses_base0_radix() {
        // Kernel base-0 semantics (strtoul_lenient): 0x->hex, leading 0->octal, else decimal.
        assert_eq!(parse_sysctl_int("1"), Some(1));
        assert_eq!(parse_sysctl_int("0x1"), Some(1));
        assert_eq!(parse_sysctl_int("0X2"), Some(2));
        assert_eq!(parse_sysctl_int("01"), Some(1)); // octal 01 == 1
        assert_eq!(parse_sysctl_int("010"), Some(8)); // octal 010 == 8
        assert_eq!(parse_sysctl_int("0xff"), Some(255));
        assert_eq!(parse_sysctl_int("0"), Some(0));
        assert_eq!(parse_sysctl_int("00"), Some(0));
        assert_eq!(parse_sysctl_int("-1"), Some(-1));
        // Not clean integers -> None (so the value is flagged, never silently accepted).
        assert_eq!(parse_sysctl_int("enabled"), None);
        assert_eq!(parse_sysctl_int("+1"), None, "kernel rejects a leading +");
        assert_eq!(parse_sysctl_int("0x"), None);
        assert_eq!(parse_sysctl_int("08"), None, "8 is not an octal digit");
        assert_eq!(
            parse_sysctl_int("1 # ok"),
            None,
            "trailing junk is not a clean int"
        );
        assert_eq!(parse_sysctl_int(""), None);
    }

    #[test]
    fn is_compliant_int_normalizes_but_exact_does_not() {
        let int_key = BaselineKey {
            key: "kernel.kptr_restrict",
            accepted: &["1", "2"],
            stig_id: "X",
            kind: ValueKind::Int,
        };
        assert!(is_compliant(&int_key, "1"));
        assert!(is_compliant(&int_key, "0x2"), "0x2 == 2 is in the set");
        assert!(!is_compliant(&int_key, "0"), "0 is not in {{1,2}}");
        assert!(!is_compliant(&int_key, "junk"));

        let str_key = BaselineKey {
            key: "kernel.core_pattern",
            accepted: &["|/bin/false"],
            stig_id: "X",
            kind: ValueKind::Exact,
        };
        assert!(is_compliant(&str_key, "|/bin/false"));
        assert!(
            !is_compliant(&str_key, "|/bin/true"),
            "a different string is non-compliant"
        );
    }

    #[test]
    fn core_pattern_is_the_only_string_typed_key() {
        // Pins that exactly the string-typed keys use exact matching: only
        // kernel.core_pattern, in every target's table.
        for (_t, table) in all_tables() {
            for key in table {
                let is_exact = matches!(key.kind, ValueKind::Exact);
                assert_eq!(
                    is_exact,
                    key.key == "kernel.core_pattern",
                    "{:?} kind (Exact={is_exact}) must match being core_pattern",
                    key.key
                );
            }
        }
    }
}
