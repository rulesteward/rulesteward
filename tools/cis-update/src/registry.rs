//! The shipped-table registry: which (family, product) CIS tables the backend
//! crates actually ship, projected into the drift-comparison shape.
//!
//! All four Wave-3 families (sshd #525, sudoers #526, sysctld #527, auditd
//! #528) are ARMED: each family mod projects distinct control ids off its
//! crate's `pub cis_baseline`-style accessor via a path-dep. `Pending` is
//! reserved for backends without a CIS lane yet (fapolicyd / selinux, filed
//! only after this wave per the #518 verdict shape); `check` reports a Pending
//! slot as an explicit per-family SKIPPED line - never a vacuous OK.

use crate::family::Family;

/// One shipped control row projected for comparison: the named registry-to-diff
/// projection boundary. Ids-only - the one surface all four table shapes
/// guarantee.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShippedControl {
    pub id: String,
}

/// A (family, product) shipped-table slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Shipped {
    /// No lane has landed this family's CIS table yet; `lane_issue` is the
    /// tracking issue the skip line points at.
    Pending { lane_issue: u32 },
    /// The family's shipped table via its crate's accessor.
    Table(Vec<ShippedControl>),
}

/// The shipped table for `family` on `product`.
pub fn shipped(family: Family, product: &str) -> Result<Shipped, String> {
    match family {
        Family::Auditd => auditd::shipped(product),
        Family::Sshd => sshd::shipped(product),
        Family::Sudoers => sudoers::shipped(product),
        Family::Sysctld => sysctld::shipped(product),
    }
}

mod auditd {
    use super::{Shipped, ShippedControl};
    use rulesteward_auditd::lints::stig_required::TargetVersion;

    pub(super) fn shipped(product: &str) -> Result<Shipped, String> {
        let target = match product {
            "rhel8" => TargetVersion::Rhel8,
            "rhel9" => TargetVersion::Rhel9,
            "rhel10" => TargetVersion::Rhel10,
            other => return Err(format!("auditd: unknown product {other:?}")),
        };
        // One row per (control, rule) mapping (66/68/75) -> distinct control
        // ids (25/24/40); the drift diff is id-set-based, so project distinct
        // ids in table order.
        let mut seen = std::collections::BTreeSet::new();
        Ok(Shipped::Table(
            rulesteward_auditd::lints::cis::cis_baseline(target)
                .iter()
                .filter(|c| seen.insert(c.control_id))
                .map(|c| ShippedControl {
                    id: c.control_id.to_string(),
                })
                .collect(),
        ))
    }
}

mod sshd {
    use super::{Shipped, ShippedControl};
    use rulesteward_sshd::TargetVersion;

    pub(super) fn shipped(product: &str) -> Result<Shipped, String> {
        let target = match product {
            "rhel8" => TargetVersion::Rhel8,
            "rhel9" => TargetVersion::Rhel9,
            "rhel10" => TargetVersion::Rhel10,
            other => return Err(format!("sshd: unknown product {other:?}")),
        };
        // 16 rule-mapping rows -> 15 distinct control ids (the ClientAlive
        // control maps two directives under one id); the drift diff is
        // id-set-based, so project distinct ids in table order.
        let mut seen = std::collections::BTreeSet::new();
        Ok(Shipped::Table(
            rulesteward_sshd::lints::cis::cis_baseline(target)
                .iter()
                .filter(|c| seen.insert(c.id))
                .map(|c| ShippedControl {
                    id: c.id.to_string(),
                })
                .collect(),
        ))
    }
}

mod sudoers {
    use super::{Shipped, ShippedControl};
    use rulesteward_sudoers::TargetVersion;

    pub(super) fn shipped(product: &str) -> Result<Shipped, String> {
        let target = match product {
            "rhel8" => TargetVersion::Rhel8,
            "rhel9" => TargetVersion::Rhel9,
            "rhel10" => TargetVersion::Rhel10,
            other => return Err(format!("sudoers: unknown product {other:?}")),
        };
        Ok(Shipped::Table(
            rulesteward_sudoers::lints::cis::cis_baseline(target)
                .iter()
                .map(|c| ShippedControl {
                    id: c.id.to_string(),
                })
                .collect(),
        ))
    }
}

mod sysctld {
    use super::{Shipped, ShippedControl};
    use rulesteward_sysctld::lints::baseline::TargetVersion;

    pub(super) fn shipped(product: &str) -> Result<Shipped, String> {
        let target = match product {
            "rhel8" => TargetVersion::Rhel8,
            "rhel9" => TargetVersion::Rhel9,
            "rhel10" => TargetVersion::Rhel10,
            other => return Err(format!("sysctld: unknown product {other:?}")),
        };
        // Per-KEY rows share a control id when one control maps several keys
        // (rhel9: 25 key rows, 13 distinct ids); the drift diff is
        // id-set-based, so project distinct ids in table order.
        let mut seen = std::collections::BTreeSet::new();
        Ok(Shipped::Table(
            rulesteward_sysctld::lints::cis::cis_baseline(target)
                .iter()
                .filter(|c| seen.insert(c.cis_id))
                .map(|c| ShippedControl {
                    id: c.cis_id.to_string(),
                })
                .collect(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::{Shipped, shipped};
    use crate::family::Family;

    #[test]
    fn sudoers_slots_ship_their_five_controls_on_every_product() {
        // Lane 3b (#526) landed: the sudoers family projects off
        // rulesteward_sudoers::lints::cis::cis_baseline on all three products.
        for product in ["rhel8", "rhel9", "rhel10"] {
            let Shipped::Table(rows) = shipped(Family::Sudoers, product).unwrap() else {
                panic!("{product}/sudoers: expected a shipped table, got Pending");
            };
            let ids: Vec<&str> = rows.iter().map(|r| r.id.as_str()).collect();
            assert_eq!(
                ids,
                ["5.2.2", "5.2.3", "5.2.4", "5.2.5", "5.2.6"],
                "{product}"
            );
        }
    }

    #[test]
    fn sshd_slots_ship_fifteen_distinct_ids_with_the_product_specific_banner_id() {
        // Lane 3a (#525): 16 rule-mapping rows, 15 distinct control ids (the
        // ClientAlive control maps two directives under one id). The banner id
        // is the 3-way product differentiator (grounded in
        // derive-rhel{8,9,10}-sshd.txt at the pin).
        for (product, banner) in [("rhel8", "5.1.7"), ("rhel9", "5.1.8"), ("rhel10", "5.1.5")] {
            let Shipped::Table(rows) = shipped(Family::Sshd, product).unwrap() else {
                panic!("{product}/sshd: expected a shipped table, got Pending");
            };
            let distinct: std::collections::BTreeSet<&str> =
                rows.iter().map(|r| r.id.as_str()).collect();
            assert_eq!(distinct.len(), 15, "{product}");
            assert!(distinct.contains(banner), "{product}: banner id {banner}");
            assert!(
                distinct.iter().all(|id| id.starts_with("5.1.")),
                "{product}"
            );
        }
    }

    #[test]
    fn sysctld_slots_ship_distinct_control_ids_with_the_ip_forward_divergence() {
        // Lane 3c (#527): per-KEY rows project to distinct control ids
        // (rhel8 33/33, rhel9 25 key rows -> 13 distinct ids, rhel10 33/33).
        // net.ipv4.ip_forward is the grounded per-product id divergence:
        // 3.3.1.1 on rhel8/rhel10 but 3.3.1 on rhel9.
        for (product, distinct_ids, ip_forward) in [
            ("rhel8", 33, "3.3.1.1"),
            ("rhel9", 13, "3.3.1"),
            ("rhel10", 33, "3.3.1.1"),
        ] {
            let Shipped::Table(rows) = shipped(Family::Sysctld, product).unwrap() else {
                panic!("{product}/sysctld: expected a shipped table, got Pending");
            };
            let distinct: std::collections::BTreeSet<&str> =
                rows.iter().map(|r| r.id.as_str()).collect();
            assert_eq!(distinct.len(), distinct_ids, "{product}");
            assert!(distinct.contains(ip_forward), "{product}: {ip_forward}");
        }
    }

    #[test]
    fn auditd_slots_ship_per_product_distinct_control_ids() {
        // Lane 3d (#528): one row per rule mapping (66/68/75) -> distinct
        // control ids 25/24/40; the per-product counts differing kills a
        // shared-superset projection. max_log_file's 6.3.2.1 is a grounded
        // all-products anchor.
        for (product, distinct_ids) in [("rhel8", 25), ("rhel9", 24), ("rhel10", 40)] {
            let Shipped::Table(rows) = shipped(Family::Auditd, product).unwrap() else {
                panic!("{product}/auditd: expected a shipped table, got Pending");
            };
            let distinct: std::collections::BTreeSet<&str> =
                rows.iter().map(|r| r.id.as_str()).collect();
            assert_eq!(distinct.len(), distinct_ids, "{product}");
            assert!(distinct.contains("6.3.2.1"), "{product}: 6.3.2.1");
        }
    }

    #[test]
    fn shipped_rejects_unknown_products_for_armed_families() {
        assert!(shipped(Family::Sudoers, "rhel7").is_err());
    }
}
