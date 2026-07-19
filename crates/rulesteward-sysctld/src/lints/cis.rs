//! `sysctld` CIS kernel-hardening baseline table (issue #527, Wave-3 CIS).
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
//! such as the STIG baseline's `kernel.core_pattern`).

use crate::lints::baseline::TargetVersion;

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
pub fn cis_baseline(_target: TargetVersion) -> &'static [CisControl] {
    // Test-author scaffold (lane-3c barrier): the RED table tests in
    // `tests/cis.rs` call this and are RED against this `todo!()`. The implementer
    // fills the per-product grounded tables so each assertion turns green.
    todo!("lane-3c: per-product CIS sysctl baseline table (#527)")
}
