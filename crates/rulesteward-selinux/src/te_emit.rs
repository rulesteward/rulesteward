//! `SELinux` Type Enforcement (.te) rule emitter.
//!
//! Produces a self-contained base-module `.te` file that `checkmodule -M -m`
//! accepts. The emitted module uses the low-level BASE-MODULE syntax
//! (`module NAME 1.0;` + `require { ... }` + `allow` rules), NOT the m4
//! refpolicy form (`policy_module(...)`) which fails checkmodule (f4 §3.1).
//!
//! # Narrowness invariants (f4 §2.5)
//!
//! 1. No interface macros (no `auth_read_shadow()` etc.).
//! 2. No `typeattribute` directives.
//! 3. Exact perm set only - no perm-set expansion or padding.
//! 4. No unrelated types.
//! 5. One `allow` rule per `(source_type, target_type, tclass)` triple.
//! 6. `Permissive` groups are never emitted as `allow` rules.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use crate::denial::{DenialGroup, DenialKind};

/// Default module name used when the caller passes `None`.
///
/// Must satisfy `^[A-Za-z][A-Za-z0-9._-]*$` (f4 §3.1 / audit2allow name
/// validation). "local" is a safe, descriptive, letter-starting identifier.
const DEFAULT_MODULE_NAME: &str = "local";

/// Emit a self-contained base-module `.te` for the given denial groups.
///
/// # Format (f4 §3.1 + the hand-validated `narrow.te` grounding artifact)
///
/// ```text
/// module NAME 1.0;
///
/// require {
///     type source_t;
///     type target_t;
///     class file { getattr read };
///     class dir read;
/// }
///
/// allow source_t target_t:file { getattr read };
/// allow source_t target_t:dir read;
/// ```
///
/// Rules:
/// - Each type appears exactly ONCE in the `require` block.
/// - Each class appears exactly ONCE with the union of all perms across
///   every group that references that class (`BTreeSet`-sorted alphabetically).
/// - One `allow` rule per group; multi-perm uses the brace form, single-perm
///   uses the bare form.
/// - [`DenialKind::Permissive`] groups are silently skipped (f4 §2.5
///   invariant 6): the access was not actually blocked, so auto-suggesting an
///   `allow` could grant unintended access.
/// - The output always ends with a trailing newline.
#[must_use]
pub fn emit_te(groups: &[DenialGroup], module_name: Option<&str>) -> String {
    let name = module_name.unwrap_or(DEFAULT_MODULE_NAME);

    // -- Collect require-block items (one pass over ALL groups) ---------------

    // Deduplicated types (source + target), alphabetical via BTreeSet.
    let mut types: BTreeSet<&str> = BTreeSet::new();

    // Class -> union-of-perms across ALL groups referencing that class.
    // BTreeMap keeps classes alphabetical; BTreeSet keeps perms alphabetical.
    let mut class_perms: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();

    for g in groups {
        types.insert(&g.source_type);
        types.insert(&g.target_type);
        let entry = class_perms.entry(&g.tclass).or_default();
        for p in &g.perms {
            entry.insert(p.as_str());
        }
    }

    // -- Build the output string ----------------------------------------------

    let mut out = String::new();

    // 1. Header
    let _ = writeln!(out, "module {name} 1.0;");

    // 2. Require block (always emitted; checkmodule accepts an empty require
    //    block, which is what we produce for zero-group input).
    out.push('\n');
    out.push_str("require {\n");
    for t in &types {
        let _ = writeln!(out, "\ttype {t};");
    }
    for (cls, perms) in &class_perms {
        let perm_str = format_perms(perms.iter().copied());
        let _ = writeln!(out, "\tclass {cls} {perm_str};");
    }
    out.push_str("}\n");

    // 3. Allow rules (one per group, Permissive skipped).
    let allowable: Vec<&DenialGroup> = groups
        .iter()
        .filter(|g| g.kind != DenialKind::Permissive)
        .collect();

    if !allowable.is_empty() {
        out.push('\n');
        for g in allowable {
            let perm_str = format_perms(g.perms.iter().map(String::as_str));
            let _ = writeln!(
                out,
                "allow {} {}:{} {perm_str};",
                g.source_type, g.target_type, g.tclass
            );
        }
    }

    out
}

/// Format a perm set as the bare form (`read`) for a single perm, or the
/// brace form (`{ getattr read }`) for multiple perms.
///
/// The iterator is consumed in sorted order (`BTreeSet` iterators are already
/// sorted; arbitrary iterators are sorted here).
fn format_perms<'a>(perms: impl IntoIterator<Item = &'a str>) -> String {
    let mut sorted: Vec<&str> = perms.into_iter().collect();
    sorted.sort_unstable();
    sorted.dedup();
    match sorted.as_slice() {
        [] => String::new(), // should not happen in practice
        [single] => (*single).to_string(),
        many => format!("{{ {} }}", many.join(" ")),
    }
}
