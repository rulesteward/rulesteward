//! The shipped-table registry: which (family, product) CIS tables the backend
//! crates actually ship, projected into the drift-comparison shape.
//!
//! At the #524 foundation every slot is `Pending` (no lane has landed): `check`
//! must say so explicitly per family - never a vacuous OK. Lane integration
//! (orchestrator-owned) replaces ONE family mod's body with a projection off that
//! crate's new `pub cis_baseline`-style accessor + adds the path-dep; the other
//! families' arms are untouched, so each lane wiring is a small isolated edit.

use crate::family::Family;

/// One shipped control row projected for comparison. Ids-only today (the one
/// surface all four table shapes guarantee); a struct so a lane's projection can
/// grow fields later without reshaping [`Shipped`].
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
    let _ = product;
    match family {
        Family::Auditd => auditd::shipped(product),
        Family::Sshd => sshd::shipped(product),
        Family::Sudoers => sudoers::shipped(product),
        Family::Sysctld => sysctld::shipped(product),
    }
}

mod auditd {
    use super::Shipped;
    pub(super) fn shipped(_product: &str) -> Result<Shipped, String> {
        Ok(Shipped::Pending { lane_issue: 528 })
    }
}

mod sshd {
    use super::Shipped;
    pub(super) fn shipped(_product: &str) -> Result<Shipped, String> {
        Ok(Shipped::Pending { lane_issue: 525 })
    }
}

mod sudoers {
    use super::Shipped;
    pub(super) fn shipped(_product: &str) -> Result<Shipped, String> {
        Ok(Shipped::Pending { lane_issue: 526 })
    }
}

mod sysctld {
    use super::Shipped;
    pub(super) fn shipped(_product: &str) -> Result<Shipped, String> {
        Ok(Shipped::Pending { lane_issue: 527 })
    }
}

#[cfg(test)]
mod tests {
    use super::{Shipped, shipped};
    use crate::family::Family;

    #[test]
    fn all_twelve_foundation_slots_are_pending_with_their_lane_issue() {
        for product in ["rhel8", "rhel9", "rhel10"] {
            for (family, lane) in [
                (Family::Sshd, 525),
                (Family::Sudoers, 526),
                (Family::Sysctld, 527),
                (Family::Auditd, 528),
            ] {
                assert_eq!(
                    shipped(family, product).unwrap(),
                    Shipped::Pending { lane_issue: lane },
                    "{product}/{family:?}"
                );
            }
        }
    }
}
