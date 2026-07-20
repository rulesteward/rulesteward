//! `sysctld` CIS kernel-hardening baseline table + the `sysctld-W04` emit pass
//! (issue #527, Wave-3 CIS).
//!
//! Companion to the STIG baseline in [`crate::lints::baseline`]: a per-product
//! (rhel8/rhel9/rhel10) table of the CIS-Benchmark-required sysctl keys, each with
//! its CIS control id, the `ComplianceAsCode` control TITLE, and the
//! benchmark-accepted value set (selection-resolved). The table is grounded in
//! ComplianceAsCode/content CIS profiles at the pinned commit
//! `519b5fe8ce338cfa25d53065bcb3759aafe8d36d` (control ids + titles ONLY; never CIS
//! benchmark prose, which is license-restricted). The products DIVERGE sharply:
//! rhel8 (cis v4.0.0) and rhel10 (cis v1.0.1) carry 33 keys, rhel9 (cis v2.0.0)
//! only 25, with per-product control ids, titles, and accepted-value sets.
//!
//! Value comparison reuses the crate's effective-value machinery
//! ([`crate::parser::effective_values`]) and mirrors the STIG baseline's
//! comparison semantics: base-0 integer compare, SET-valued acceptance. Every
//! sysctld CIS key is integer-typed (the CIS sysctl set has no string-typed key
//! such as the STIG baseline's `kernel.core_pattern`), so unlike
//! [`crate::lints::baseline::ValueKind`] there is no exact-string variant here.
//!
//! [`w04_baseline`] is the emit pass: it runs the table above over the effective
//! (precedence-ordered) assignments for a `--target` product, firing one
//! `sysctld-W04` per CIS-required key that is unset or set to a value outside the
//! benchmark-accepted set - mirroring [`crate::lints::baseline::w02_baseline`]'s
//! missing/insecure-branch anchoring exactly (a MISSING key anchors at the
//! file/dir with no source line; a present-but-out-of-set key anchors at its real
//! assignment). W04 is ADDITIVE to the untouched STIG `sysctld-W02`: both passes
//! run side by side, each carrying its own framework's [`ControlRef`], wired into
//! [`crate::parser::lint_str_with_target`] / [`crate::parser::lint_dir_with_target`]
//! exactly like the STIG W02 wiring.

use std::path::Path;

use rulesteward_core::{ControlRef, Diagnostic, Framework, Severity, anchored};

use crate::lints::baseline::TargetVersion;
use crate::parser::{ParsedAssignment, canonical_key, effective_values};

/// One CIS-Benchmark kernel-hardening control: the sysctl key, its CIS-Benchmark
/// control id, the `ComplianceAsCode` control title, the benchmark-accepted value
/// set, and whether it is integer-typed. This single public struct is BOTH the
/// grounded table row AND the stable public view external dev tooling imports
/// (unlike the STIG side, which projects a crate-private `BaselineKey` into a
/// separate public [`crate::lints::baseline::StigEntry`]); [`cis_baseline`] returns
/// a `&'static [CisControl]` directly, mirroring the
/// [`crate::lints::baseline::baseline_for`] static-slice idiom. `CisControl` is the
/// name standardized across the Wave-3 CIS backend crates.
pub struct CisControl {
    /// Dotted sysctl key, as the CIS benchmark lists it and operators write it
    /// (e.g. `net.ipv4.conf.all.rp_filter`).
    pub key: &'static str,
    /// The CIS-Benchmark control id for `key` in this product (e.g. `1.5.4`). The
    /// id DIVERGES per product (e.g. `net.ipv4.ip_forward` is `3.3.1.1` on
    /// rhel8/rhel10 but `3.3.1` on rhel9).
    pub cis_id: &'static str,
    /// The `ComplianceAsCode` control title for `key` in this product (e.g.
    /// `Ensure IP forwarding is disabled (Automated)`). Diverges per product.
    pub title: &'static str,
    /// The benchmark-accepted value(s), selection-resolved. Most keys accept a
    /// single value; a few accept a SET (e.g. `net.ipv4.conf.all.rp_filter`
    /// accepts `1` OR `2` on rhel8/rhel10 but only `1` on rhel9).
    pub accepted: &'static [&'static str],
    /// `true` for an integer-typed key (kernel base-0 compare). Every sysctld CIS
    /// key is integer-typed.
    pub numeric: bool,
}

/// The grounded CIS baseline for `target`, as a static slice (mirrors the
/// [`crate::lints::baseline::baseline_for`] static-slice idiom). Consumed by the
/// CIS baseline pass and by external dev tooling.
#[must_use]
pub fn cis_baseline(target: TargetVersion) -> &'static [CisControl] {
    match target {
        TargetVersion::Rhel8 => RHEL8_CIS,
        TargetVersion::Rhel9 => RHEL9_CIS,
        TargetVersion::Rhel10 => RHEL10_CIS,
    }
}

// Accepted-value sets, named for readability (mirrors baseline.rs). Most CIS
// sysctld keys require a single value; the set-valued ones are spelled out so a
// divergence is obvious.
const DISABLE: &[&str] = &["0"];
const ENABLE: &[&str] = &["1"];
const VALUE_2: &[&str] = &["2"];
const ONE_OR_TWO: &[&str] = &["1", "2"];

/// Terse table-row constructor. Every sysctld CIS key is integer-typed, so unlike
/// baseline.rs's `k`/`k_exact` pair there is only one constructor.
const fn c(
    key: &'static str,
    cis_id: &'static str,
    title: &'static str,
    accepted: &'static [&'static str],
) -> CisControl {
    CisControl {
        key,
        cis_id,
        title,
        accepted,
        numeric: true,
    }
}

// ---------------------------------------------------------------------------
// Grounded CIS baseline tables (Wave-3 CIS / issue #527), transcribed from the
// `tools/cis-update derive --values` grounding at the pinned commit
// 519b5fe8ce338cfa25d53065bcb3759aafe8d36d (SELECTION-AWARE resolved values;
// control ids + `ComplianceAsCode` titles ONLY, never CIS benchmark prose).
// ---------------------------------------------------------------------------

/// RHEL 8 CIS sysctl baseline (cis v4.0.0; 33 keys).
const RHEL8_CIS: &[CisControl] = &[
    c(
        "fs.protected_hardlinks",
        "1.5.2",
        "Ensure fs.protected_hardlinks is configured (Automated)",
        ENABLE,
    ),
    c(
        "fs.protected_symlinks",
        "1.5.3",
        "Ensure fs.protected_symlinks is configured (Automated)",
        ENABLE,
    ),
    c(
        "fs.suid_dumpable",
        "1.5.4",
        "Ensure fs.suid_dumpable is configured (Automated)",
        DISABLE,
    ),
    c(
        "kernel.dmesg_restrict",
        "1.5.5",
        "Ensure kernel.dmesg_restrict is configured (Automated)",
        ENABLE,
    ),
    // DIVERGENCE: rhel8 accepts only 1 (rhel10 accepts 1 OR 2); ABSENT on rhel9.
    c(
        "kernel.kptr_restrict",
        "1.5.6",
        "Ensure kernel.kptr_restrict is configured (Automated)",
        ENABLE,
    ),
    c(
        "kernel.randomize_va_space",
        "1.5.8",
        "Ensure kernel.randomize_va_space is configured (Automated)",
        VALUE_2,
    ),
    c(
        "kernel.yama.ptrace_scope",
        "1.5.7",
        "Ensure kernel.yama.ptrace_scope is configured (Automated)",
        ENABLE,
    ),
    c(
        "net.ipv4.conf.all.accept_redirects",
        "3.3.1.8",
        "Ensure net.ipv4.conf.all.accept_redirects is configured (Automated)",
        DISABLE,
    ),
    c(
        "net.ipv4.conf.all.accept_source_route",
        "3.3.1.14",
        "Ensure net.ipv4.conf.all.accept_source_route is configured (Automated)",
        DISABLE,
    ),
    c(
        "net.ipv4.conf.all.forwarding",
        "3.3.1.2",
        "Ensure net.ipv4.conf.all.forwarding is configured (Automated)",
        DISABLE,
    ),
    c(
        "net.ipv4.conf.all.log_martians",
        "3.3.1.16",
        "Ensure net.ipv4.conf.all.log_martians is configured (Automated)",
        ENABLE,
    ),
    // DIVERGENCE: rhel8/rhel10 accept 1 OR 2 (rhel9 accepts ONLY 1).
    c(
        "net.ipv4.conf.all.rp_filter",
        "3.3.1.12",
        "Ensure net.ipv4.conf.all.rp_filter is configured (Automated)",
        ONE_OR_TWO,
    ),
    c(
        "net.ipv4.conf.all.secure_redirects",
        "3.3.1.10",
        "Ensure net.ipv4.conf.all.secure_redirects is configured (Automated)",
        DISABLE,
    ),
    c(
        "net.ipv4.conf.all.send_redirects",
        "3.3.1.4",
        "Ensure net.ipv4.conf.all.send_redirects is configured (Automated)",
        DISABLE,
    ),
    c(
        "net.ipv4.conf.default.accept_redirects",
        "3.3.1.9",
        "Ensure net.ipv4.conf.default.accept_redirects is configured (Automated)",
        DISABLE,
    ),
    c(
        "net.ipv4.conf.default.accept_source_route",
        "3.3.1.15",
        "Ensure net.ipv4.conf.default.accept_source_route is configured (Automated)",
        DISABLE,
    ),
    c(
        "net.ipv4.conf.default.forwarding",
        "3.3.1.3",
        "Ensure net.ipv4.conf.default.forwarding is configured (Automated)",
        DISABLE,
    ),
    c(
        "net.ipv4.conf.default.log_martians",
        "3.3.1.17",
        "Ensure net.ipv4.conf.default.log_martians is configured (Automated)",
        ENABLE,
    ),
    c(
        "net.ipv4.conf.default.rp_filter",
        "3.3.1.13",
        "Ensure net.ipv4.conf.default.rp_filter is configured (Automated)",
        ENABLE,
    ),
    c(
        "net.ipv4.conf.default.secure_redirects",
        "3.3.1.11",
        "Ensure net.ipv4.conf.default.secure_redirects is configured (Automated)",
        DISABLE,
    ),
    c(
        "net.ipv4.conf.default.send_redirects",
        "3.3.1.5",
        "Ensure net.ipv4.conf.default.send_redirects is configured (Automated)",
        DISABLE,
    ),
    c(
        "net.ipv4.icmp_echo_ignore_broadcasts",
        "3.3.1.7",
        "Ensure net.ipv4.icmp_echo_ignore_broadcasts is configured (Automated)",
        ENABLE,
    ),
    c(
        "net.ipv4.icmp_ignore_bogus_error_responses",
        "3.3.1.6",
        "Ensure net.ipv4.icmp_ignore_bogus_error_responses is configured (Automated)",
        ENABLE,
    ),
    // DIVERGENCE: rhel8/rhel10 id 3.3.1.1 (rhel9 id 3.3.1); title "is configured"
    // (rhel9 uses the descriptive "IP forwarding is disabled" title).
    c(
        "net.ipv4.ip_forward",
        "3.3.1.1",
        "Ensure net.ipv4.ip_forward is configured (Automated)",
        DISABLE,
    ),
    c(
        "net.ipv4.tcp_syncookies",
        "3.3.1.18",
        "Ensure net.ipv4.tcp_syncookies is configured (Automated)",
        ENABLE,
    ),
    c(
        "net.ipv6.conf.all.accept_ra",
        "3.3.2.7",
        "Ensure net.ipv6.conf.all.accept_ra is configured (Automated)",
        DISABLE,
    ),
    c(
        "net.ipv6.conf.all.accept_redirects",
        "3.3.2.3",
        "Ensure net.ipv6.conf.all.accept_redirects is configured (Automated)",
        DISABLE,
    ),
    c(
        "net.ipv6.conf.all.accept_source_route",
        "3.3.2.5",
        "Ensure net.ipv6.conf.all.accept_source_route is configured (Automated)",
        DISABLE,
    ),
    c(
        "net.ipv6.conf.all.forwarding",
        "3.3.2.1",
        "Ensure net.ipv6.conf.all.forwarding is configured (Automated)",
        DISABLE,
    ),
    c(
        "net.ipv6.conf.default.accept_ra",
        "3.3.2.8",
        "Ensure net.ipv6.conf.default.accept_ra is configured (Automated)",
        DISABLE,
    ),
    c(
        "net.ipv6.conf.default.accept_redirects",
        "3.3.2.4",
        "Ensure net.ipv6.conf.default.accept_redirects is configured (Automated)",
        DISABLE,
    ),
    c(
        "net.ipv6.conf.default.accept_source_route",
        "3.3.2.6",
        "Ensure net.ipv6.conf.default.accept_source_route is configured (Automated)",
        DISABLE,
    ),
    c(
        "net.ipv6.conf.default.forwarding",
        "3.3.2.2",
        "Ensure net.ipv6.conf.default.forwarding is configured (Automated)",
        DISABLE,
    ),
];

/// RHEL 9 CIS sysctl baseline (cis v2.0.0; a much smaller benchmark, 25 keys).
/// `fs.suid_dumpable` and `kernel.kptr_restrict` are NOT in this table (absent
/// from the rhel9 CIS benchmark entirely). Control ids and titles diverge sharply
/// from rhel8/rhel10 - rhel9 groups several sysctl keys under one shared id (e.g.
/// `3.3.1` covers both `net.ipv4.ip_forward` and `net.ipv6.conf.all.forwarding`)
/// and uses descriptive `ComplianceAsCode` titles rather than the "is configured"
/// phrasing rhel8/rhel10 use.
const RHEL9_CIS: &[CisControl] = &[
    c(
        "kernel.randomize_va_space",
        "1.5.1",
        "Ensure address space layout randomization is enabled (Automated)",
        VALUE_2,
    ),
    c(
        "kernel.yama.ptrace_scope",
        "1.5.2",
        "Ensure ptrace_scope is restricted (Automated)",
        ENABLE,
    ),
    c(
        "net.ipv4.conf.all.accept_redirects",
        "3.3.5",
        "Ensure icmp redirects are not accepted (Automated)",
        DISABLE,
    ),
    c(
        "net.ipv4.conf.all.accept_source_route",
        "3.3.8",
        "Ensure source routed packets are not accepted (Automated)",
        DISABLE,
    ),
    c(
        "net.ipv4.conf.all.log_martians",
        "3.3.9",
        "Ensure suspicious packets are logged (Automated)",
        ENABLE,
    ),
    // DIVERGENCE: rhel9 accepts ONLY 1 (rhel8/rhel10 accept 1 OR 2).
    c(
        "net.ipv4.conf.all.rp_filter",
        "3.3.7",
        "Ensure reverse path filtering is enabled (Automated)",
        ENABLE,
    ),
    c(
        "net.ipv4.conf.all.secure_redirects",
        "3.3.6",
        "Ensure secure icmp redirects are not accepted (Automated)",
        DISABLE,
    ),
    c(
        "net.ipv4.conf.all.send_redirects",
        "3.3.2",
        "Ensure packet redirect sending is disabled (Automated)",
        DISABLE,
    ),
    c(
        "net.ipv4.conf.default.accept_redirects",
        "3.3.5",
        "Ensure icmp redirects are not accepted (Automated)",
        DISABLE,
    ),
    c(
        "net.ipv4.conf.default.accept_source_route",
        "3.3.8",
        "Ensure source routed packets are not accepted (Automated)",
        DISABLE,
    ),
    c(
        "net.ipv4.conf.default.log_martians",
        "3.3.9",
        "Ensure suspicious packets are logged (Automated)",
        ENABLE,
    ),
    c(
        "net.ipv4.conf.default.rp_filter",
        "3.3.7",
        "Ensure reverse path filtering is enabled (Automated)",
        ENABLE,
    ),
    c(
        "net.ipv4.conf.default.secure_redirects",
        "3.3.6",
        "Ensure secure icmp redirects are not accepted (Automated)",
        DISABLE,
    ),
    c(
        "net.ipv4.conf.default.send_redirects",
        "3.3.2",
        "Ensure packet redirect sending is disabled (Automated)",
        DISABLE,
    ),
    c(
        "net.ipv4.icmp_echo_ignore_broadcasts",
        "3.3.4",
        "Ensure broadcast icmp requests are ignored (Automated)",
        ENABLE,
    ),
    c(
        "net.ipv4.icmp_ignore_bogus_error_responses",
        "3.3.3",
        "Ensure bogus icmp responses are ignored (Automated)",
        ENABLE,
    ),
    // DIVERGENCE: rhel9 id 3.3.1 (rhel8/rhel10 id 3.3.1.1); descriptive title
    // (rhel8/rhel10 use the "is configured" phrasing).
    c(
        "net.ipv4.ip_forward",
        "3.3.1",
        "Ensure IP forwarding is disabled (Automated)",
        DISABLE,
    ),
    c(
        "net.ipv4.tcp_syncookies",
        "3.3.10",
        "Ensure tcp syn cookies is enabled (Automated)",
        ENABLE,
    ),
    c(
        "net.ipv6.conf.all.accept_ra",
        "3.3.11",
        "Ensure IPv6 router advertisements are not accepted (Automated)",
        DISABLE,
    ),
    c(
        "net.ipv6.conf.all.accept_redirects",
        "3.3.5",
        "Ensure icmp redirects are not accepted (Automated)",
        DISABLE,
    ),
    c(
        "net.ipv6.conf.all.accept_source_route",
        "3.3.8",
        "Ensure source routed packets are not accepted (Automated)",
        DISABLE,
    ),
    c(
        "net.ipv6.conf.all.forwarding",
        "3.3.1",
        "Ensure IP forwarding is disabled (Automated)",
        DISABLE,
    ),
    c(
        "net.ipv6.conf.default.accept_ra",
        "3.3.11",
        "Ensure IPv6 router advertisements are not accepted (Automated)",
        DISABLE,
    ),
    c(
        "net.ipv6.conf.default.accept_redirects",
        "3.3.5",
        "Ensure icmp redirects are not accepted (Automated)",
        DISABLE,
    ),
    c(
        "net.ipv6.conf.default.accept_source_route",
        "3.3.8",
        "Ensure source routed packets are not accepted (Automated)",
        DISABLE,
    ),
];

/// RHEL 10 CIS sysctl baseline (cis v1.0.1; 33 keys). Same key set and ids as
/// rhel8, EXCEPT `kernel.kptr_restrict` accepts 1 OR 2 (rhel8 accepts only 1). The
/// two `net.ipv6...forwarding` titles carry the double space verbatim from the
/// grounded `ComplianceAsCode` title text.
const RHEL10_CIS: &[CisControl] = &[
    c(
        "fs.protected_hardlinks",
        "1.5.2",
        "Ensure fs.protected_hardlinks is configured (Automated)",
        ENABLE,
    ),
    c(
        "fs.protected_symlinks",
        "1.5.3",
        "Ensure fs.protected_symlinks is configured (Automated)",
        ENABLE,
    ),
    c(
        "fs.suid_dumpable",
        "1.5.4",
        "Ensure fs.suid_dumpable is configured (Automated)",
        DISABLE,
    ),
    c(
        "kernel.dmesg_restrict",
        "1.5.5",
        "Ensure kernel.dmesg_restrict is configured (Automated)",
        ENABLE,
    ),
    c(
        "kernel.kptr_restrict",
        "1.5.6",
        "Ensure kernel.kptr_restrict is configured (Automated)",
        ONE_OR_TWO,
    ),
    c(
        "kernel.randomize_va_space",
        "1.5.8",
        "Ensure kernel.randomize_va_space is configured (Automated)",
        VALUE_2,
    ),
    c(
        "kernel.yama.ptrace_scope",
        "1.5.7",
        "Ensure kernel.yama.ptrace_scope is configured (Automated)",
        ENABLE,
    ),
    c(
        "net.ipv4.conf.all.accept_redirects",
        "3.3.1.8",
        "Ensure net.ipv4.conf.all.accept_redirects is configured (Automated)",
        DISABLE,
    ),
    c(
        "net.ipv4.conf.all.accept_source_route",
        "3.3.1.14",
        "Ensure net.ipv4.conf.all.accept_source_route is configured (Automated)",
        DISABLE,
    ),
    c(
        "net.ipv4.conf.all.forwarding",
        "3.3.1.2",
        "Ensure net.ipv4.conf.all.forwarding is configured (Automated)",
        DISABLE,
    ),
    c(
        "net.ipv4.conf.all.log_martians",
        "3.3.1.16",
        "Ensure net.ipv4.conf.all.log_martians is configured (Automated)",
        ENABLE,
    ),
    c(
        "net.ipv4.conf.all.rp_filter",
        "3.3.1.12",
        "Ensure net.ipv4.conf.all.rp_filter is configured (Automated)",
        ONE_OR_TWO,
    ),
    c(
        "net.ipv4.conf.all.secure_redirects",
        "3.3.1.10",
        "Ensure net.ipv4.conf.all.secure_redirects is configured (Automated)",
        DISABLE,
    ),
    c(
        "net.ipv4.conf.all.send_redirects",
        "3.3.1.4",
        "Ensure net.ipv4.conf.all.send_redirects is configured (Automated)",
        DISABLE,
    ),
    c(
        "net.ipv4.conf.default.accept_redirects",
        "3.3.1.9",
        "Ensure net.ipv4.conf.default.accept_redirects is configured (Automated)",
        DISABLE,
    ),
    c(
        "net.ipv4.conf.default.accept_source_route",
        "3.3.1.15",
        "Ensure net.ipv4.conf.default.accept_source_route is configured (Automated)",
        DISABLE,
    ),
    c(
        "net.ipv4.conf.default.forwarding",
        "3.3.1.3",
        "Ensure net.ipv4.conf.default.forwarding is configured (Automated)",
        DISABLE,
    ),
    c(
        "net.ipv4.conf.default.log_martians",
        "3.3.1.17",
        "Ensure net.ipv4.conf.default.log_martians is configured (Automated)",
        ENABLE,
    ),
    c(
        "net.ipv4.conf.default.rp_filter",
        "3.3.1.13",
        "Ensure net.ipv4.conf.default.rp_filter is configured (Automated)",
        ENABLE,
    ),
    c(
        "net.ipv4.conf.default.secure_redirects",
        "3.3.1.11",
        "Ensure net.ipv4.conf.default.secure_redirects is configured (Automated)",
        DISABLE,
    ),
    c(
        "net.ipv4.conf.default.send_redirects",
        "3.3.1.5",
        "Ensure net.ipv4.conf.default.send_redirects is configured (Automated)",
        DISABLE,
    ),
    c(
        "net.ipv4.icmp_echo_ignore_broadcasts",
        "3.3.1.7",
        "Ensure net.ipv4.icmp_echo_ignore_broadcasts is configured (Automated)",
        ENABLE,
    ),
    c(
        "net.ipv4.icmp_ignore_bogus_error_responses",
        "3.3.1.6",
        "Ensure net.ipv4.icmp_ignore_bogus_error_responses is configured (Automated)",
        ENABLE,
    ),
    c(
        "net.ipv4.ip_forward",
        "3.3.1.1",
        "Ensure net.ipv4.ip_forward is configured (Automated)",
        DISABLE,
    ),
    c(
        "net.ipv4.tcp_syncookies",
        "3.3.1.18",
        "Ensure net.ipv4.tcp_syncookies is configured (Automated)",
        ENABLE,
    ),
    c(
        "net.ipv6.conf.all.accept_ra",
        "3.3.2.7",
        "Ensure net.ipv6.conf.all.accept_ra is configured (Automated)",
        DISABLE,
    ),
    c(
        "net.ipv6.conf.all.accept_redirects",
        "3.3.2.3",
        "Ensure net.ipv6.conf.all.accept_redirects is configured (Automated)",
        DISABLE,
    ),
    c(
        "net.ipv6.conf.all.accept_source_route",
        "3.3.2.5",
        "Ensure net.ipv6.conf.all.accept_source_route is configured (Automated)",
        DISABLE,
    ),
    c(
        "net.ipv6.conf.all.forwarding",
        "3.3.2.1",
        "Ensure  net.ipv6.conf.all.forwarding is configured (Automated)",
        DISABLE,
    ),
    c(
        "net.ipv6.conf.default.accept_ra",
        "3.3.2.8",
        "Ensure net.ipv6.conf.default.accept_ra is configured (Automated)",
        DISABLE,
    ),
    c(
        "net.ipv6.conf.default.accept_redirects",
        "3.3.2.4",
        "Ensure net.ipv6.conf.default.accept_redirects is configured (Automated)",
        DISABLE,
    ),
    c(
        "net.ipv6.conf.default.accept_source_route",
        "3.3.2.6",
        "Ensure net.ipv6.conf.default.accept_source_route is configured (Automated)",
        DISABLE,
    ),
    c(
        "net.ipv6.conf.default.forwarding",
        "3.3.2.2",
        "Ensure  net.ipv6.conf.default.forwarding is configured (Automated)",
        DISABLE,
    ),
];

// ---------------------------------------------------------------------------
// The `sysctld-W04` emit pass (Option B, user DECISION): a standalone
// version-aware CIS baseline check, mirroring `w02_baseline` exactly.
// ---------------------------------------------------------------------------

/// Run the CIS baseline pass over the effective (precedence-ordered) assignments
/// for `target`, emitting `sysctld-W04`. `anchor` is the file (single-file mode)
/// or directory (drop-in mode) a MISSING key is reported against (it has no
/// source line); a present-but-out-of-set key is anchored at its real assignment
/// instead. Mirrors [`crate::lints::baseline::w02_baseline`]'s shape: same
/// effective-value lookup, same missing/insecure branch split, same anchoring.
#[must_use]
pub(crate) fn w04_baseline(
    assignments: &[ParsedAssignment],
    target: TargetVersion,
    anchor: &Path,
) -> Vec<Diagnostic> {
    // The effective value of each key is its winning (last) assignment - the same
    // last-wins map sysctld-W01/W02 reason over, so every pass agrees on identity.
    let effective = effective_values(assignments);

    let mut diags = Vec::new();
    for entry in cis_baseline(target) {
        let canonical = canonical_key(entry.key);
        match effective.get(canonical.as_str()) {
            // Unset across the effective config: a CIS gap with no source line, so
            // anchor at the file/dir (line 0, no source_id -> plain `file:0:0` line).
            None => diags.push(
                Diagnostic::new(
                    Severity::Warning,
                    "sysctld-W04",
                    0..0,
                    missing_message(entry),
                    anchor.to_path_buf(),
                    0,
                    0,
                )
                .with_controls(vec![
                    ControlRef::new(Framework::Cis, entry.cis_id).with_name(entry.title),
                ]),
            ),
            // Present: a value outside the benchmark-accepted set is flagged,
            // anchored at the real assignment (its span/line -> ariadne snippet). A
            // value in the set is compliant and emits nothing.
            Some(&idx) => {
                let assignment = &assignments[idx];
                if !is_compliant(entry, &assignment.value) {
                    diags.push(
                        anchored(
                            Severity::Warning,
                            "sysctld-W04",
                            assignment.span.clone(),
                            insecure_message(entry, &assignment.value),
                            assignment.file.clone(),
                            assignment.line,
                        )
                        .with_controls(vec![
                            ControlRef::new(Framework::Cis, entry.cis_id).with_name(entry.title),
                        ]),
                    );
                }
            }
        }
    }
    diags
}

/// Render the accepted set for the message: a single value as `requires <v>`, a
/// set as `requires one of <v1>, <v2>`, so the operator sees which value(s) are
/// compliant. Mirrors `baseline::requirement_phrase`.
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

fn missing_message(entry: &CisControl) -> String {
    format!(
        "CIS-required key `{}` is unset ({} {})",
        entry.key,
        entry.cis_id,
        requirement_phrase(entry.accepted),
    )
}

fn insecure_message(entry: &CisControl, found: &str) -> String {
    format!(
        "CIS-required key `{}` = `{}` is outside the benchmark-accepted set ({} {})",
        entry.key,
        found,
        entry.cis_id,
        requirement_phrase(entry.accepted),
    )
}

/// Whether `value` (a present assignment's trimmed value) is CIS-compliant for
/// `entry`: an effective integer match (the kernel's base-0 parse), so the
/// kernel-equivalent forms `0x1` / `01` of `1` are accepted. Every sysctld CIS key
/// is integer-typed, so unlike `baseline::is_compliant` there is no exact-string
/// branch.
fn is_compliant(entry: &CisControl, value: &str) -> bool {
    match parse_sysctl_int(value) {
        Some(found) => entry
            .accepted
            .iter()
            .any(|accepted| parse_sysctl_int(accepted) == Some(found)),
        // Not a parseable integer -> not the required value (flag it).
        None => false,
    }
}

/// Parse an integer sysctl value the way the kernel does: base-0 radix detection
/// (`0x`/`0X` -> hex, a leading `0` -> octal, otherwise decimal) with an optional
/// single leading `-`. Returns `None` for anything that is not a clean integer (so
/// it is flagged, never silently accepted). Mirrors `baseline::parse_sysctl_int`
/// (`strtoul_lenient(p, &p, 0, val)` / `_parse_integer_fixup_radix` in the
/// kernel), duplicated here (rather than imported) so this module stays
/// self-contained; both wrappers delegate to the same shared
/// [`rulesteward_core::parse_base0_u64`] magnitude parser.
fn parse_sysctl_int(value: &str) -> Option<i64> {
    let value = value.trim();
    let (negative, digits) = match value.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, value),
    };
    let magnitude = i64::try_from(rulesteward_core::parse_base0_u64(digits)?).ok()?;
    Some(if negative { -magnitude } else { magnitude })
}

#[cfg(test)]
mod tests {
    use super::{
        CisControl, RHEL8_CIS, RHEL9_CIS, RHEL10_CIS, c, is_compliant, parse_sysctl_int,
        requirement_phrase,
    };

    #[test]
    fn requirement_phrase_singular_vs_set() {
        assert_eq!(requirement_phrase(&["1"]), "requires `1`");
        assert_eq!(requirement_phrase(&["1", "2"]), "requires one of `1`, `2`");
    }

    #[test]
    fn parse_sysctl_int_uses_base0_radix() {
        assert_eq!(parse_sysctl_int("1"), Some(1));
        assert_eq!(parse_sysctl_int("0x1"), Some(1));
        assert_eq!(parse_sysctl_int("0X2"), Some(2));
        assert_eq!(parse_sysctl_int("01"), Some(1)); // octal 01 == 1
        assert_eq!(parse_sysctl_int("0"), Some(0));
        assert_eq!(parse_sysctl_int("-1"), Some(-1));
        assert_eq!(parse_sysctl_int("enabled"), None);
        assert_eq!(parse_sysctl_int("+1"), None, "kernel rejects a leading +");
        assert_eq!(parse_sysctl_int(""), None);
    }

    #[test]
    fn is_compliant_normalizes_the_effective_integer() {
        let entry = CisControl {
            key: "kernel.kptr_restrict",
            cis_id: "X",
            title: "test",
            accepted: &["1", "2"],
            numeric: true,
        };
        assert!(is_compliant(&entry, "1"));
        assert!(is_compliant(&entry, "0x2"), "0x2 == 2 is in the set");
        assert!(!is_compliant(&entry, "0"), "0 is not in {{1,2}}");
        assert!(!is_compliant(&entry, "junk"));
    }

    #[test]
    fn c_constructor_carries_every_field_through_and_sets_numeric_true() {
        // `c` is the terse table constructor every RHEL8/9/10 CIS row above is
        // built with, but every call site is inside a `const` table initializer,
        // so the constructor body runs at COMPILE time (const evaluation) -
        // llvm-cov never sees it execute even though it builds every real table
        // entry (mirrors baseline.rs's identical note about `k`/`k_exact`).
        // Calling it here, at runtime, in a non-const binding is the only way to
        // exercise the function body under coverage.
        let entry: CisControl = c("test.int.key", "TEST-1.1", "Test title", &["1", "2"]);
        assert_eq!(entry.key, "test.int.key");
        assert_eq!(entry.cis_id, "TEST-1.1");
        assert_eq!(entry.title, "Test title");
        assert_eq!(entry.accepted, ["1", "2"]);
        assert!(entry.numeric, "`c` must always build a numeric entry");
    }

    #[test]
    fn every_table_row_key_is_unique_within_its_product() {
        for (name, table) in [
            ("rhel8", RHEL8_CIS),
            ("rhel9", RHEL9_CIS),
            ("rhel10", RHEL10_CIS),
        ] {
            let mut seen = std::collections::HashSet::new();
            for entry in table {
                assert!(
                    seen.insert(entry.key),
                    "{name} has a duplicate key {:?}",
                    entry.key
                );
            }
        }
    }
}
