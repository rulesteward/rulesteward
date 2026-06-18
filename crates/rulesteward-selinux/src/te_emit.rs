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

use crate::denial::{DenialGroup, DenialKind, is_te_representable};

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
/// - Zero denial groups produce an explanatory comment, NOT a module: a bare
///   `module NAME 1.0;` and an empty `require {}` are both rejected by
///   checkmodule, so there is no valid no-op module to emit (#165).
/// - The output always ends with a trailing newline.
#[must_use]
pub fn emit_te(groups: &[DenialGroup], module_name: Option<&str>) -> String {
    // A checkmodule-valid module needs a non-empty body: a bare `module NAME 1.0;`
    // is rejected ("syntax error"), as is an empty `require {}` (confirmed on
    // el8/el9/el10). With zero denial groups there is nothing to require or allow,
    // so emit an explanatory comment instead of a fake, uncompilable module (#165).
    // The trailing newline preserves the machine-output invariant.
    if groups.is_empty() {
        return "# rulesteward: no SELinux denials to allow; nothing to emit.\n".to_string();
    }

    let name = module_name.unwrap_or(DEFAULT_MODULE_NAME);

    // Partition groups into three buckets:
    // - `emittable`: representable and not Permissive -> produces an allow rule
    // - `permissive`: Permissive kind -> contributes to require block, no allow
    //   (invariant 6; unchanged by this guard per OWNER DECISION C)
    // - `declined`: failed is_te_representable and not Permissive -> comment only
    let emittable: Vec<&DenialGroup> = groups
        .iter()
        .filter(|g| is_te_representable(g) && g.kind != DenialKind::Permissive)
        .collect();
    let permissive_groups: Vec<&DenialGroup> = groups
        .iter()
        .filter(|g| g.kind == DenialKind::Permissive)
        .collect();
    let declined: Vec<&DenialGroup> = groups
        .iter()
        .filter(|g| !is_te_representable(g) && g.kind != DenialKind::Permissive)
        .collect();

    // Groups that contribute to the require block: emittable + permissive.
    // (Declined groups are unrepresentable as TE identifiers; including them in
    // the require block would itself be uncompilable.)
    let require_groups: Vec<&DenialGroup> = emittable
        .iter()
        .chain(permissive_groups.iter())
        .copied()
        .collect();

    // If nothing is representable or permissive, emit a comment-only output
    // (mirrors the zero-denial convention, #165).
    if require_groups.is_empty() {
        let mut out = "# rulesteward: no SELinux denials to allow; nothing to emit.\n".to_string();
        for g in &declined {
            let _ = writeln!(
                out,
                "# rulesteward: declined (not TE-representable): {} {}:{} {{{}}}",
                g.source_type,
                g.target_type,
                g.tclass,
                g.perms
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>()
                    .join(" ")
            );
        }
        return out;
    }

    // -- Collect require-block items (one pass over require_groups) -----------

    // Deduplicated types (source + target), alphabetical via BTreeSet.
    let mut types: BTreeSet<&str> = BTreeSet::new();

    // Class -> union-of-perms across require_groups referencing that class.
    // BTreeMap keeps classes alphabetical; BTreeSet keeps perms alphabetical.
    let mut class_perms: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();

    for g in &require_groups {
        types.insert(&g.source_type);
        types.insert(&g.target_type);
        let entry = class_perms.entry(&g.tclass).or_default();
        for p in &g.perms {
            entry.insert(p.as_str());
        }
    }

    // -- Build the output string ----------------------------------------------

    let mut out = String::new();

    // Decline comments for non-representable groups (before module header so
    // comments appear at the top, mirroring the zero-denial comment convention).
    for g in &declined {
        let _ = writeln!(
            out,
            "# rulesteward: declined (not TE-representable): {} {}:{} {{{}}}",
            g.source_type,
            g.target_type,
            g.tclass,
            g.perms
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .join(" ")
        );
    }

    // 1. Header
    let _ = writeln!(out, "module {name} 1.0;");

    // 2. Require block. `require_groups` is non-empty (checked above), and every
    //    group contributes a source and target type, so `types` always has
    //    content - the require block is never empty.
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

    // 3. Allow rules (one per emittable group; Permissive skipped - invariant 6).
    if !emittable.is_empty() {
        out.push('\n');
        for g in emittable {
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
