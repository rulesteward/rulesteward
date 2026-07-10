//! Compare a derived msgtype table pair (from [`crate::parse`]) against the
//! SHIPPED `rulesteward-auditd` tables, per the drift contract fixed for
//! issue #476:
//!
//! 1. the derived BASE table must equal the shipped `MSGTYPE_NAMES` const
//!    entry-for-entry (name AND number), and
//! 2. the derived `WITH_APPARMOR` table must equal the shipped
//!    `APPARMOR_MSGTYPE_NAMES` const entry-for-entry -
//!
//! with the two tables compared SEPARATELY, never merged (AppArmor folding is
//! opt-in in the linter; a derive tool that merged them would claim an
//! equivalence a non-AppArmor daemon does not make).
//!
//! Equality is name/number CONTENT equality (maps), not sequence order:
//! `msg_typetab.h` is not strictly number-sorted (`MAC_CHECK` 1134 precedes
//! `SYSTEM_BOOT` 1127 in file order) while the shipped consts are
//! number-grouped - same 189 pairs, different order.

use std::collections::BTreeMap;

use crate::parse::DerivedTables;

/// Project the shipped `rulesteward-auditd` msgtype consts (`MSGTYPE_NAMES` /
/// `APPARMOR_MSGTYPE_NAMES`, via the public accessors
/// `rulesteward_auditd::lints::value::{base_msgtype_names,
/// apparmor_msgtype_names}` added for #476) into a [`DerivedTables`], for
/// comparison against a derived (parsed-from-headers) pair. This is a
/// PROJECTION of the real, imported consts (via the path-dep) - not a
/// hardcoded copy - so it tracks `msgtype.rs` automatically as it changes
/// (see `shipped_tables_project_the_real_msgtype_consts` below).
#[must_use]
pub fn shipped_tables() -> DerivedTables {
    use rulesteward_auditd::lints::value::{apparmor_msgtype_names, base_msgtype_names};

    DerivedTables {
        base: base_msgtype_names()
            .iter()
            .map(|&(n, num)| (n.to_string(), num))
            .collect(),
        apparmor: apparmor_msgtype_names()
            .iter()
            .map(|&(n, num)| (n.to_string(), num))
            .collect(),
    }
}

/// Human-readable drift lines between `derived` and `shipped`: for EACH of
/// the two tables (labeled so a report line is unambiguous about which table
/// drifted), a line per name present on one side but not the other, and a
/// line per shared name whose numbers disagree. Empty == in sync. Lines are
/// sorted for stable output.
#[must_use]
pub fn drift(derived: &DerivedTables, shipped: &DerivedTables) -> Vec<String> {
    let mut out = Vec::new();
    out.extend(table_drift("base", &derived.base, &shipped.base));
    out.extend(table_drift(
        "apparmor",
        &derived.apparmor,
        &shipped.apparmor,
    ));
    out.sort();
    out
}

/// Symmetric name diff + number-mismatch lines for ONE table, labeled so a
/// report line unambiguously names which of the two (separately-compared)
/// tables drifted.
fn table_drift(
    label: &str,
    derived: &BTreeMap<String, u32>,
    shipped: &BTreeMap<String, u32>,
) -> Vec<String> {
    let mut out = Vec::new();
    for (name, num) in derived {
        match shipped.get(name) {
            None => out.push(format!(
                "{label}: {name} present in the derived (upstream header) table but missing from the shipped table"
            )),
            Some(shipped_num) if shipped_num != num => out.push(format!(
                "{label}: {name} number mismatch: derived {num}, shipped {shipped_num}"
            )),
            _ => {}
        }
    }
    for name in shipped.keys() {
        if !derived.contains_key(name) {
            out.push(format!(
                "{label}: {name} present in the shipped table but missing from the derived (upstream header) table"
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::{self, DerivedTables};
    use rulesteward_auditd::lints::value::{apparmor_msgtype_names, base_msgtype_names};
    use std::collections::BTreeMap;

    const MSG_TYPETAB: &str = include_str!("../tests/fixtures/3bfa048/msg_typetab.h");
    const AUDIT_RECORDS: &str = include_str!("../tests/fixtures/3bfa048/audit-records.h");
    const KERNEL_AUDIT_H: &str = include_str!("../tests/fixtures/linux-v6.6/audit.h");

    /// Parse + resolve the real fixture set into the derived tables (the
    /// exact pipeline `derive`/`check` will run).
    fn derive_real() -> DerivedTables {
        let t = parse::parse_typetab(MSG_TYPETAB).expect("typetab parses");
        let records = parse::parse_defines(AUDIT_RECORDS).expect("records parse");
        let kernel = parse::parse_defines(KERNEL_AUDIT_H).expect("kernel parses");
        parse::resolve(&t, &records, &kernel).expect("resolves")
    }

    fn map(pairs: &[(&str, u32)]) -> BTreeMap<String, u32> {
        pairs.iter().map(|(k, v)| (k.to_string(), *v)).collect()
    }

    /// [`shipped_tables`] must be a PROJECTION of the real
    /// `rulesteward-auditd` consts (imported via the path-dep accessors), NOT
    /// a hardcoded copy of their current content. The expectation below is
    /// BUILT from the accessors at test runtime, so an implementation that
    /// hardcodes today's 189/8 content would pass today but FAIL the moment
    /// `msgtype.rs` changes - exactly the silent-drift-defeat this test
    /// exists to make impossible (mirrors fapolicyd-attr-update's
    /// `shipped_registry_projects_the_real_attrs_consts`).
    #[test]
    fn shipped_tables_project_the_real_msgtype_consts() {
        // Anti-vacuity spot-check on the IMPORTS themselves: if the path-dep
        // or the accessors were broken in a way that yielded empty slices, an
        // empty-vs-empty projection comparison would pass vacuously. Pin the
        // currently-known shape of the real consts (msgtype.rs: 189 base +
        // 8 AppArmor entries; SYSCALL=1300, KERNEL=2000, APPARMOR=1500) so a
        // hollow import is loud.
        assert_eq!(base_msgtype_names().len(), 189);
        assert_eq!(apparmor_msgtype_names().len(), 8);
        assert!(base_msgtype_names().contains(&("SYSCALL", 1300)));
        assert!(base_msgtype_names().contains(&("KERNEL", 2000)));
        assert!(apparmor_msgtype_names().contains(&("APPARMOR", 1500)));

        let expected = DerivedTables {
            base: base_msgtype_names()
                .iter()
                .map(|&(n, num)| (n.to_string(), num))
                .collect(),
            apparmor: apparmor_msgtype_names()
                .iter()
                .map(|&(n, num)| (n.to_string(), num))
                .collect(),
        };
        assert_eq!(
            shipped_tables(),
            expected,
            "shipped_tables() must project the real msgtype.rs consts, not a hardcoded copy"
        );
    }

    /// THE drift-gate known-answer (GREEN-case): the tables derived from the
    /// pinned fixtures equal the shipped consts EXACTLY - map equality
    /// (name AND number, both tables) AND an empty drift report. This is the
    /// assertion that makes `check` exit 0 meaningful: the shipped
    /// `MSGTYPE_NAMES` (189) / `APPARMOR_MSGTYPE_NAMES` (8) were hand-derived
    /// from these same pinned sources, verified mechanically at authoring
    /// time (2026-07-10, session 7c P1).
    #[test]
    fn drift_real_fixtures_is_zero() {
        let derived = derive_real();
        let shipped = shipped_tables();
        assert_eq!(
            derived.base, shipped.base,
            "derived base table must equal shipped MSGTYPE_NAMES entry-for-entry"
        );
        assert_eq!(
            derived.apparmor, shipped.apparmor,
            "derived AppArmor table must equal shipped APPARMOR_MSGTYPE_NAMES entry-for-entry"
        );
        let d = drift(&derived, &shipped);
        assert!(d.is_empty(), "drift report must be empty: {d:?}");
    }

    /// A renamed entry must produce non-empty drift naming the entry.
    /// Anti-vacuity: an identical pair must report ZERO drift, proving the
    /// non-empty result detects the injected divergence and is not a `drift`
    /// bug that always reports drift regardless of input.
    #[test]
    fn drift_detects_a_renamed_entry() {
        let shipped = DerivedTables {
            base: map(&[("SYSCALL", 1300), ("PATH", 1302)]),
            apparmor: map(&[]),
        };
        let mut derived = shipped.clone();
        derived.base.remove("SYSCALL");
        derived.base.insert("SYSCALLX".to_string(), 1300);

        let d = drift(&derived, &shipped);
        assert!(!d.is_empty(), "a renamed entry must produce drift");
        assert!(
            d.iter().any(|l| l.contains("SYSCALL")),
            "the drift must name the offending entry: {d:?}"
        );
        assert!(
            drift(&shipped, &shipped).is_empty(),
            "an identical pair must report zero drift"
        );
    }

    /// A NUMBER change on a shared name (upstream renumbering a record type)
    /// must produce non-empty drift naming the entry - a name-only diff would
    /// miss it entirely.
    #[test]
    fn drift_detects_a_number_change() {
        let shipped = DerivedTables {
            base: map(&[("SYSCALL", 1300), ("PATH", 1302)]),
            apparmor: map(&[]),
        };
        let mut derived = shipped.clone();
        derived.base.insert("PATH".to_string(), 1399);

        let d = drift(&derived, &shipped);
        assert!(!d.is_empty(), "a number change must produce drift");
        assert!(
            d.iter().any(|l| l.contains("PATH")),
            "the drift must name the renumbered entry: {d:?}"
        );
    }

    /// Isolates the `table_drift` `None` match arm (a name present in
    /// `derived` but absent from `shipped`) from the OTHER direction (a name
    /// present in `shipped` but absent from `derived`): `derived` here is
    /// `shipped` plus exactly one extra name, so nothing fires the
    /// shipped-only loop. `drift_detects_a_renamed_entry` and
    /// `drift_detects_a_table_misplacement` both exercise this direction
    /// too, but always alongside a shipped-only message that ALSO contains
    /// the same substring their `any(|l| l.contains(...))` assertions check
    /// for - so deleting the `None` arm (falls through to the `_ => {}`
    /// catch-all) silently drops only this direction's line while the other
    /// direction's line still satisfies those loose assertions. Asserting
    /// the exact single-line output here has nothing else to fall back on:
    /// kills `registry.rs:76:13` "delete match arm None in table_drift".
    #[test]
    fn table_drift_reports_derived_only_entry_when_nothing_else_drifts() {
        let shipped = map(&[("SYSCALL", 1300)]);
        let derived = map(&[("SYSCALL", 1300), ("NEWTYPE", 1400)]);
        let out = table_drift("base", &derived, &shipped);
        assert_eq!(
            out,
            vec![
                "base: NEWTYPE present in the derived (upstream header) table but missing from the shipped table"
                    .to_string()
            ],
            "a derived-only entry, with nothing else drifting, must still be reported"
        );
    }

    /// The two tables are compared SEPARATELY: an entry that migrated from
    /// the AppArmor table into the base table (same name, same number) is
    /// drift in BOTH tables, not a wash. An implementation that unions the
    /// two tables before comparing reports zero drift here and fails.
    #[test]
    fn drift_detects_a_table_misplacement() {
        let shipped = DerivedTables {
            base: map(&[("SYSCALL", 1300)]),
            apparmor: map(&[("APPARMOR", 1500)]),
        };
        let derived = DerivedTables {
            base: map(&[("SYSCALL", 1300), ("APPARMOR", 1500)]),
            apparmor: map(&[]),
        };
        let d = drift(&derived, &shipped);
        assert!(
            !d.is_empty(),
            "a base<->apparmor migration must be drift, not a union wash"
        );
        assert!(
            d.iter().any(|l| l.contains("APPARMOR")),
            "the drift must name the migrated entry: {d:?}"
        );
    }
}
