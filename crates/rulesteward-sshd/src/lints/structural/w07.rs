//! sshd-W07: cross-`Match` first-value-wins shadow. See [`w07`]. The
//! CIDR/port/glob geometry primitives live in [`super::matching`].

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::net::IpAddr;
use std::path::Path;

use rulesteward_core::{Diagnostic, Severity};

use crate::ast::{Block, MatchBlock};
use crate::lints::{SshdLintContext, anchored, is_unconditional_match_all};

use super::E02_ALLOW_REPEAT;
use super::matching::{
    Cidr, cidr_intersects, cidr_list_set, cidr_lists_overlap, cidr_set_difference,
    cidr_set_intersection, glob_match, parse_cidr_list, parse_port_list, port_lists_overlap,
    port_set,
};

/// sshd-W07: the same first-value-wins keyword set to DIFFERENT values in two
/// `Match` blocks whose criteria can be simultaneously satisfied by one
/// connection. sshd applies only the FIRST satisfied block's value and silently
/// drops the later one, so the later (shadowed) instance is a hardening hazard
/// (#302, deferred from #247). Severity Warning: criteria-overlap is a static
/// approximation, so the pass is advisory.
///
/// The pass compares every ordered PAIR of conditional `Match` blocks. Overlap is
/// decided conservatively from the criteria pattern text alone (`sshd_config(5)`
/// `match_pattern_list` semantics): two blocks overlap only when they constrain the
/// SAME set of criterion types and, for each type, their patterns can co-apply
/// (shared literal, `*`/`?` wildcard, a negation-list that still admits the other
/// value, or CIDR containment). Provably-disjoint criteria (`User alice` vs
/// `User bob`, disjoint CIDRs/ports) are the normal per-connection pattern and stay
/// clean, as do CROSS-type pairs (`User` vs `Group`), which can only co-satisfy
/// through NSS group membership a static linter cannot resolve (the conservative
/// v0.3 contract; opt-in resolution is #400).
///
/// Only FIRST-VALUE-WINS keywords fire: accumulating keywords (the shared
/// [`E02_ALLOW_REPEAT`] set sshd-E02 already maintains) union across blocks rather
/// than shadow, so a repeat drops nothing. Same-value repeats are redundant, not a
/// shadow. The LATER instance is flagged, matching sshd-E02's convention.
///
/// Unconditional `Match all` is ALWAYS satisfied, so it participates as an earliest
/// SHADOWER: `Match all K=v` followed by a later conditional `Match ... K=w` (w != v)
/// drops the later value for every connection (verified `sshd -T -C user=bob` on
/// OpenSSH 9.9p1). But by the conservative v0.3 scope a `Match all` block is never
/// itself flagged as a shadowEE - a `Match all` appearing after a conditional stays
/// the effective default for the connections the conditional does not cover, the
/// intended default-plus-exception idiom, not a hazard (owner-decided; #302, #403).
///
/// A later block is flagged not only when an earlier overlapping block wins ALL of
/// its connections with a different value, but also when only a NON-EMPTY
/// SUB-POPULATION of them is won by an earlier DIFFERING block (a partition across
/// three or more blocks, e.g. `Host alpha`=v / `Host beta`=w / `Host alpha,beta`=v:
/// the beta sub-population is shadowed by the middle block even though the first
/// block agrees with the later value for the alpha sub-population). Detection stays
/// FALSE-POSITIVE-FREE: an earlier block covering the later block's WHOLE population
/// with the SAME value suppresses the flag, and region reasoning never crosses
/// criterion types (preserving #400). It may still MISS hard cases but never
/// over-flags (#409).
#[must_use]
pub fn w07(blocks: &[Block], file: &Path, _ctx: &SshdLintContext) -> Vec<Diagnostic> {
    // Every Match block in source order, INCLUDING `Match all`: it is always
    // satisfied, so it can be the earliest block that sets (and thus keeps) a
    // first-value-wins keyword a later conditional block then re-sets.
    let match_blocks: Vec<&MatchBlock> = blocks
        .iter()
        .filter_map(|block| match block {
            Block::Match(m) => Some(m),
            Block::Global(_) => None,
        })
        .collect();

    let mut diags = Vec::new();
    for (j, later) in match_blocks.iter().enumerate() {
        // A `Match all` block is a shadowER, never a shadowEE (owner-decided v0.3
        // scope): being overridden for the users an earlier conditional covers is
        // the intended default-plus-exception idiom, so it is never itself flagged.
        if is_unconditional_match_all(later) {
            continue;
        }
        // The first occurrence of a keyword defines a block's effective value
        // (first-value-wins within the block), so only that first instance can be
        // the one an earlier block shadows.
        let mut seen: HashSet<String> = HashSet::new();
        for directive in &later.body {
            let keyword = directive.keyword_lower();
            if E02_ALLOW_REPEAT.contains(&keyword.as_str()) {
                // Accumulating keyword: unions across blocks, so nothing is dropped.
                continue;
            }
            if !seen.insert(keyword.clone()) {
                // A repeat WITHIN this block is sshd-E02's concern; only the block's
                // first (effective) value can be shadowed by an earlier block.
                continue;
            }
            // sshd applies ONLY the first satisfied block's value. The earlier blocks
            // that both overlap this one AND set the keyword are the candidate winners,
            // in SOURCE ORDER (the first one a given connection satisfies wins it).
            let value = directive.args.as_slice();
            // When this block constrains a SINGLE criterion type, decide the shadow PER
            // SUB-POPULATION (#409): flag iff some non-empty region of this block's
            // connections is won by an earlier block with a DIFFERING value. Otherwise
            // fall back to the block-level winner comparison.
            let shadowed = if let Some(kind) = single_region_type(later) {
                let earlier_setters =
                    region_earlier_setters(&match_blocks[..j], later, &keyword, &kind);
                region_shadow(later, &kind, &keyword, value, &earlier_setters)
            } else {
                let earlier_setters =
                    multitype_earlier_setters(&match_blocks[..j], later, &keyword);
                multitype_shadow(later, &keyword, value, &earlier_setters)
            };
            if shadowed {
                diags.push(anchored(
                    Severity::Warning,
                    "sshd-W07",
                    directive.span.clone(),
                    format!(
                        "first-value-wins directive '{}' is also set in an earlier Match block \
                         whose criteria can match the same connection; sshd applies the first \
                         block's value and silently drops this one",
                        directive.keyword
                    ),
                    file,
                    directive.line,
                ));
            }
        }
    }
    diags
}

/// The arguments of the FIRST occurrence of `keyword_lower` in `block`'s body (the
/// value sshd honors under first-value-wins), or `None` when the block never sets
/// it. Used by [`w07`] to compare an earlier block's effective value against a
/// later block's.
fn first_value_for<'a>(block: &'a MatchBlock, keyword_lower: &str) -> Option<&'a [String]> {
    block
        .body
        .iter()
        .find(|d| d.keyword_lower() == keyword_lower)
        .map(|d| d.args.as_slice())
}

/// The kind of a block's SINGLE region-modeled criterion type, or `None` when the block
/// is not eligible for per-sub-population (#409) reasoning and must use the block-level
/// fallback.
///
/// Region reasoning is exact only inside ONE criterion-type domain. `Some(T)` requires
/// the block to constrain EXACTLY one criterion type, that type be region-modeled
/// (`user`/`group`/`host` name lists, `address`/`localaddress` CIDR, `localport`), and
/// the block NOT trip the preserved repeated-CIDR/port-with-negation guard (a repeated
/// address/port type carrying a `!`, whose exact cross-occurrence remainder is beyond
/// v0.3 scope - routed to the conservative block-level path instead). Because
/// [`match_blocks_overlap`] only pairs blocks with IDENTICAL criterion-type sets (or a
/// `Match all`), a single-type block's every earlier overlapping setter is itself
/// single-type-`T` or `Match all`, so region reasoning never crosses types (preserving
/// the #400 conservative contract).
fn single_region_type(block: &MatchBlock) -> Option<String> {
    let by_type = criteria_by_type(block);
    if by_type.len() != 1 {
        return None;
    }
    let (kind, instances) = by_type.iter().next()?;
    if !matches!(
        kind.as_str(),
        "user" | "group" | "host" | "address" | "localaddress" | "localport"
    ) {
        return None;
    }
    // Preserved conservative guard (mirrors [`match_blocks_overlap`]): a repeated
    // CIDR/port type carrying a negation has no exact cross-occurrence remainder here,
    // so decline region reasoning and let the block-level fallback stay FN-leaning.
    if matches!(kind.as_str(), "address" | "localaddress" | "localport")
        && instances.len() >= 2
        && instances
            .iter()
            .any(|occ| occ.iter().any(|value| value.starts_with('!')))
    {
        return None;
    }
    Some(kind.clone())
}

/// The earlier blocks that set `keyword_lower` and are candidate winners for the
/// per-sub-population (#409) region path of a block whose single criterion type is
/// `kind`, in source order.
///
/// NAME criteria (`user`/`group`/`host`) are selected STRUCTURALLY - an earlier block
/// qualifies iff it is `Match all` or itself single-criterion-type `kind` - NOT via the
/// FN-leaning [`match_blocks_overlap`]. Its name oracle ([`pattern_lists_overlap`])
/// cannot witness a wildcard-vs-wildcard overlap, so it would DROP an agreeing wildcard
/// block (e.g. an earlier `Host *.corp` that AGREES with a later `Host *.corp`) and let
/// the later block be over-flagged against a differing MIDDLE block (#409). The names
/// region path's exact per-witness membership ([`member_of_type`]) then decides real
/// co-satisfaction, so a structurally-included but non-overlapping block simply yields
/// no witness (still FP-free). CIDR/port criteria keep [`match_blocks_overlap`] (no
/// wildcard FN there); their exact set intersection re-tests overlap regardless.
fn region_earlier_setters<'a>(
    earlier_blocks: &[&'a MatchBlock],
    later: &MatchBlock,
    keyword_lower: &str,
    kind: &str,
) -> Vec<&'a MatchBlock> {
    let is_name = matches!(kind, "user" | "group" | "host");
    earlier_blocks
        .iter()
        .copied()
        .filter(|earlier| {
            first_value_for(earlier, keyword_lower).is_some()
                && if is_name {
                    is_unconditional_match_all(earlier)
                        || single_region_type(earlier).as_deref() == Some(kind)
                } else {
                    match_blocks_overlap(earlier, later)
                }
        })
        .collect()
}

/// Dispatch per-sub-population (#409) shadow detection by criterion-type domain. Names
/// use a witness-candidate search; CIDR and port use exact set algebra. Only invoked
/// with a region-modeled `kind` from [`single_region_type`].
fn region_shadow(
    block: &MatchBlock,
    kind: &str,
    keyword_lower: &str,
    value: &[String],
    earlier_setters: &[&MatchBlock],
) -> bool {
    match kind {
        "user" | "group" | "host" => {
            names_region_shadow(block, kind, keyword_lower, value, earlier_setters)
        }
        "address" | "localaddress" => {
            cidr_region_shadow(block, kind, keyword_lower, value, earlier_setters)
        }
        "localport" => port_region_shadow(block, kind, keyword_lower, value, earlier_setters),
        // Unreachable: `single_region_type` only returns the arms above.
        _ => block_level_shadow(keyword_lower, value, earlier_setters),
    }
}

/// The block-level fallback (the pre-#409 rule, extracted verbatim): the winner is the
/// FIRST earlier setter in source order, and the later value is a shadow iff it DIFFERS
/// from the winner's. Used for blocks that constrain 2+ criterion types (region
/// reasoning is single-type only). `earlier_setters` is already filtered to overlapping
/// blocks that set the keyword, so its first element's value is the winner.
fn block_level_shadow(
    keyword_lower: &str,
    value: &[String],
    earlier_setters: &[&MatchBlock],
) -> bool {
    earlier_setters
        .iter()
        .find_map(|earlier| first_value_for(earlier, keyword_lower))
        .is_some_and(|winning| winning != value)
}

/// Per-sub-population shadow for NAME criteria (`User`/`Group`/`Host`). A sub-population
/// is witnessed by a concrete literal name: any user/group/host admitted by both this
/// block and an earlier setter must be a listed literal from one of them (a
/// wildcard-only overlap has no literal witness - the documented v0.3 accepted FN). For
/// each candidate literal that is a member of THIS block, the winner is the first
/// earlier setter it also satisfies; a differing winner value is a real shadow.
fn names_region_shadow(
    block: &MatchBlock,
    kind: &str,
    keyword_lower: &str,
    value: &[String],
    earlier_setters: &[&MatchBlock],
) -> bool {
    // A name matching none of the listed literals, to stand in for "some fresh name"
    // (shared spelling with [`pattern_lists_overlap`]'s sentinel).
    const FRESH: &str = "\u{0}rulesteward-w07-fresh-name\u{0}";
    let mut candidates: Vec<String> = Vec::new();
    collect_name_literals(block, kind, &mut candidates);
    for earlier in earlier_setters {
        collect_name_literals(earlier, kind, &mut candidates);
    }
    candidates.push(FRESH.to_string());
    candidates.iter().any(|name| {
        member_of_type(block, kind, name)
            && earlier_setters
                .iter()
                .find(|earlier| member_of_type(earlier, kind, name))
                .and_then(|winner| first_value_for(winner, keyword_lower))
                .is_some_and(|winning| winning != value)
    })
}

/// Collect the literal (non-glob, non-negated, non-empty) names a block's `kind`
/// criteria list, for the [`names_region_shadow`] witness search. A `Match all` (whose
/// only criterion is the valueless `all`) contributes nothing.
fn collect_name_literals(block: &MatchBlock, kind: &str, out: &mut Vec<String>) {
    if let Some(instances) = criteria_by_type(block).get(kind) {
        for values in instances {
            for value in *values {
                let literal = value.strip_prefix('!').unwrap_or(value);
                if !literal.is_empty() && !literal.contains(['*', '?']) {
                    out.push(literal.to_string());
                }
            }
        }
    }
}

/// Whether the name `x` satisfies EVERY `kind` instance of `block` at once (the
/// AND-across-occurrences membership sshd applies). A `Match all` block admits every
/// connection, so it is a member trivially.
fn member_of_type(block: &MatchBlock, kind: &str, x: &str) -> bool {
    if is_unconditional_match_all(block) {
        return true;
    }
    criteria_by_type(block)
        .get(kind)
        .is_some_and(|instances| instances.iter().all(|values| match_pattern_list(x, values)))
}

/// Per-sub-population shadow for CIDR criteria (`Address`/`LocalAddress`). Walk the
/// earlier setters in source order, carving each one's address set out of the remaining
/// (not-yet-won) part of this block's population: the first setter whose carved region
/// is NON-EMPTY and whose value DIFFERS wins a genuinely-shadowed sub-population. An
/// agreeing setter CONSUMES its region (removing it from `remaining`) so it can never
/// over-flag a later differing block outside its coverage.
fn cidr_region_shadow(
    block: &MatchBlock,
    kind: &str,
    keyword_lower: &str,
    value: &[String],
    earlier_setters: &[&MatchBlock],
) -> bool {
    let mut remaining = cidr_region_set(block, kind);
    for earlier in earlier_setters {
        let (region, rest) = if is_unconditional_match_all(earlier) {
            // `Match all` wins every remaining connection (always satisfied, earliest).
            (remaining.clone(), Vec::new())
        } else {
            let earlier_set = cidr_region_set(earlier, kind);
            (
                cidr_set_intersection(&remaining, &earlier_set),
                cidr_set_difference(&remaining, &earlier_set),
            )
        };
        if !region.is_empty()
            && first_value_for(earlier, keyword_lower).is_some_and(|winning| winning != value)
        {
            return true;
        }
        remaining = rest;
        if remaining.is_empty() {
            break;
        }
    }
    false
}

/// The exact address set of a block's `kind` criterion: the INTERSECTION (AND) across
/// its type-`kind` instances of each instance's [`cidr_list_set`]. A single instance
/// (the common case) is just its own set.
fn cidr_region_set(block: &MatchBlock, kind: &str) -> Vec<Cidr> {
    let by_type = criteria_by_type(block);
    let Some(instances) = by_type.get(kind) else {
        return Vec::new();
    };
    let mut iter = instances.iter();
    let Some(first) = iter.next() else {
        return Vec::new();
    };
    let mut acc = cidr_list_set(first);
    for values in iter {
        acc = cidr_set_intersection(&acc, &cidr_list_set(values));
    }
    acc
}

/// Per-sub-population shadow for `LocalPort` (the exact-set analogue of
/// [`cidr_region_shadow`]). On sshd-valid input a `LocalPort` block is a singleton, so
/// this reduces to single-port equality; the set machinery keeps it uniform with CIDR.
fn port_region_shadow(
    block: &MatchBlock,
    kind: &str,
    keyword_lower: &str,
    value: &[String],
    earlier_setters: &[&MatchBlock],
) -> bool {
    let mut remaining = port_region_set(block, kind);
    for earlier in earlier_setters {
        let (region, rest): (BTreeSet<u32>, BTreeSet<u32>) = if is_unconditional_match_all(earlier)
        {
            (remaining.clone(), BTreeSet::new())
        } else {
            let earlier_set = port_region_set(earlier, kind);
            (
                remaining.intersection(&earlier_set).copied().collect(),
                remaining.difference(&earlier_set).copied().collect(),
            )
        };
        if !region.is_empty()
            && first_value_for(earlier, keyword_lower).is_some_and(|winning| winning != value)
        {
            return true;
        }
        remaining = rest;
        if remaining.is_empty() {
            break;
        }
    }
    false
}

/// The exact port set of a block's `kind` criterion: the INTERSECTION (AND) across its
/// type-`kind` instances of each instance's [`port_set`].
fn port_region_set(block: &MatchBlock, kind: &str) -> BTreeSet<u32> {
    let by_type = criteria_by_type(block);
    let Some(instances) = by_type.get(kind) else {
        return BTreeSet::new();
    };
    let mut iter = instances.iter();
    let Some(first) = iter.next() else {
        return BTreeSet::new();
    };
    let mut acc = port_set(first);
    for values in iter {
        let next = port_set(values);
        acc = acc.intersection(&next).copied().collect();
    }
    acc
}

// ---- Multi-type one-axis reduction (#452, #494) ----
//
// The block-level fallback used for a LATER block constraining 2+ criterion types
// used to select candidate earlier winners via [`match_blocks_overlap`], whose
// exact-type-set gate silently drops a SUBSET predecessor (a bare `Match User alice`
// ahead of a later `Match User alice Address ...`), even though the predecessor is
// unconditionally satisfied by every connection the later block matches (#494). The
// fix below selects earlier setters STRUCTURALLY (subset-or-equal type-set, still
// co-satisfiable per shared axis - [`multitype_earlier_setters`]) and, when exactly
// one axis differs (every other axis is a provable setter no-op -
// [`multitype_reduction_axis`] / [`axis_is_noop`]), reduces to the existing
// single-type region walk on that one axis ([`multitype_axis_shadow`]). Otherwise it
// DECLINES to the coarse [`block_level_shadow`] comparison, still using the
// structurally-selected earlier-setter set rather than `match_blocks_overlap`'s
// exact-type-set gate (G5) - [`multitype_shadow`] is the entry point.

/// Whether one connection can satisfy every combined occurrence of criterion type
/// `kind` across TWO blocks' instance lists at once - the per-type co-satisfiability
/// oracle [`match_blocks_overlap`] uses for its identical-type-set case, reused by
/// [`multitype_earlier_setters`] (#452) for a subset-or-equal type-set: a criterion
/// type is AND-ed across BOTH blocks, so two blocks co-apply on it iff ONE witness
/// satisfies EVERY occurrence of it in `a_insts` AND `b_insts` combined.
fn type_co_satisfiable(kind: &str, a_insts: &[&[String]], b_insts: &[&[String]]) -> bool {
    if a_insts.len() == 1 && b_insts.len() == 1 {
        // One occurrence on each side: the negation-aware pairwise oracle.
        criterion_overlap(kind, a_insts[0], b_insts[0])
    } else {
        // A type repeated on either header is an AND across its occurrences, so the
        // blocks co-apply on it only if one witness satisfies every occurrence in
        // BOTH blocks (the cross-block intersection).
        let combined: Vec<&[String]> = a_insts.iter().chain(b_insts).copied().collect();
        // CONSERVATIVE GUARD: the cross-occurrence CIDR/port witness
        // ([`cidr_instances_have_common_address`] / [`port_instances_have_common_port`])
        // is negation-BLIND - it drops `!` carve-outs - so a repeated CIDR/LocalPort
        // type carrying a negation would be over-approximated into a possible false
        // positive. Computing the true negation-aware intersection across repeated
        // occurrences is out of v0.3 scope, so we treat such a type as
        // non-overlapping: an FN-leaning accepted gap that never risks a false
        // positive. Name lists stay negation-aware via [`match_pattern_list`], so the
        // guard is CIDR/port only.
        if matches!(kind, "address" | "localaddress" | "localport")
            && combined
                .iter()
                .any(|occ| occ.iter().any(|value| value.starts_with('!')))
        {
            false
        } else {
            criterion_instances_have_common_witness(kind, &combined)
        }
    }
}

/// The STRUCTURAL earlier-setter selection for a multi-type LATER block `later`
/// (#452, #494; G1-G3): an earlier block qualifies iff it is `Match all` (G2 -
/// universe, unconditionally satisfied) OR its criterion type-set is a
/// SUBSET-OR-EQUAL of `later`'s (a type of `earlier` OUTSIDE `later`'s type-set
/// excludes it entirely - G3, the same conservative cross-type posture #400 already
/// takes) AND `earlier` is co-satisfiable with `later` on every one of ITS OWN
/// (shared) axes via [`type_co_satisfiable`] - G1's "structurally selected, then
/// co-satisfiability re-tested" rule. This replaces `match_blocks_overlap`'s
/// exact-type-set gate for the multi-type path only; the single-type region path
/// ([`region_earlier_setters`]) is untouched.
fn multitype_earlier_setters<'a>(
    earlier_blocks: &[&'a MatchBlock],
    later: &MatchBlock,
    keyword_lower: &str,
) -> Vec<&'a MatchBlock> {
    let later_types = criteria_by_type(later);
    earlier_blocks
        .iter()
        .copied()
        .filter(|earlier| {
            first_value_for(earlier, keyword_lower).is_some()
                && (is_unconditional_match_all(earlier) || {
                    let earlier_types = criteria_by_type(earlier);
                    earlier_types.iter().all(|(kind, a_insts)| {
                        later_types
                            .get(kind)
                            .is_some_and(|b_insts| type_co_satisfiable(kind, a_insts, b_insts))
                    })
                })
        })
        .collect()
}

/// The EXACT literal set of a block's `kind` NAME criterion (AND across repeated
/// occurrences), or `None` if the type is absent, or if ANY occurrence uses a glob
/// (`*`/`?`) or a negation (`!`). [`axis_is_noop`]'s exact-containment check is
/// undecidable in those cases, so callers must treat the axis as NOT neutral rather
/// than guess (per the design's "unprovable is not neutral" rule).
fn exact_name_set(block: &MatchBlock, kind: &str) -> Option<BTreeSet<String>> {
    let by_type = criteria_by_type(block);
    let instances = by_type.get(kind)?;
    let mut acc: Option<BTreeSet<String>> = None;
    for values in instances {
        let mut set = BTreeSet::new();
        for value in *values {
            if value.starts_with('!') || value.contains(['*', '?']) {
                return None;
            }
            set.insert(value.clone());
        }
        acc = Some(match acc {
            None => set,
            Some(prev) => prev.intersection(&set).cloned().collect(),
        });
    }
    acc
}

/// Whether `earlier` is a NO-OP on axis `axis_kind` relative to `later`'s OWN
/// restriction there (#452): either `earlier` is `Match all` (universe on every
/// axis), `earlier` does not constrain `axis_kind` at all (universe on this one
/// axis - it can never narrow `later`'s population below what it already is there),
/// or `earlier`'s region on `axis_kind` provably COVERS (superset-or-equal of)
/// `later`'s own region there: CIDR via two-way [`cidr_set_difference`] emptiness,
/// `LocalPort` via `BTreeSet` superset, and `User`/`Group`/`Host` via EXACT
/// literal-set containment with NO glob or negation on either side. Anything
/// unprovable (a glob, a negation, an unmodeled type) is conservatively NOT neutral.
fn axis_is_noop(earlier: &MatchBlock, later: &MatchBlock, axis_kind: &str) -> bool {
    if is_unconditional_match_all(earlier) {
        return true;
    }
    if !criteria_by_type(earlier).contains_key(axis_kind) {
        return true;
    }
    match axis_kind {
        "address" | "localaddress" => {
            let earlier_set = cidr_region_set(earlier, axis_kind);
            let later_set = cidr_region_set(later, axis_kind);
            cidr_set_difference(&later_set, &earlier_set).is_empty()
        }
        "localport" => {
            let earlier_set = port_region_set(earlier, axis_kind);
            let later_set = port_region_set(later, axis_kind);
            later_set.is_subset(&earlier_set)
        }
        "user" | "group" | "host" => matches!(
            (exact_name_set(earlier, axis_kind), exact_name_set(later, axis_kind)),
            (Some(e), Some(l)) if l.is_subset(&e)
        ),
        // Unmodeled type: never manufactures a no-op (conservative).
        _ => false,
    }
}

/// The UNIQUE reduction axis (#452) among `later_types`' criterion types, or `None`
/// when zero or 2+ axes qualify. An axis `X` qualifies iff EVERY entry of
/// `earlier_setters` is a no-op ([`axis_is_noop`]) on every OTHER axis of
/// `later_types`; a genuine two-axis partition (no axis is a setter no-op for every
/// selected predecessor) has no qualifying axis, and DECLINES to the block-level
/// fallback (an accepted FN by owner decision - #452 follow-up "Option B", subset-type
/// product carving, is deliberately out of scope here).
fn multitype_reduction_axis(
    later: &MatchBlock,
    later_types: &BTreeMap<String, Vec<&[String]>>,
    earlier_setters: &[&MatchBlock],
) -> Option<String> {
    let axes: Vec<&String> = later_types.keys().collect();
    let mut found: Option<&String> = None;
    for axis in &axes {
        let qualifies = earlier_setters.iter().all(|earlier| {
            axes.iter()
                .filter(|other| **other != *axis)
                .all(|other| axis_is_noop(earlier, later, other))
        });
        if qualifies {
            if found.is_some() {
                return None;
            }
            found = Some(axis);
        }
    }
    found.cloned()
}

/// Whether `later` repeats an `Address`/`LocalAddress`/`LocalPort` criterion type
/// with a negated (`!`) occurrence (G4, #452) - mirrors the existing conservative
/// guard `single_region_type` applies to a SINGLE-type block, independently for the
/// multi-type reduction path: it declines the fine-grained per-axis carve entirely
/// (falling back to [`block_level_shadow`]) rather than compute an exact
/// negation-aware cross-occurrence remainder, which is out of v0.3 scope.
fn later_has_repeated_negated_region(later: &MatchBlock) -> bool {
    criteria_by_type(later).iter().any(|(kind, instances)| {
        matches!(kind.as_str(), "address" | "localaddress" | "localport")
            && instances.len() >= 2
            && instances
                .iter()
                .any(|occ| occ.iter().any(|value| value.starts_with('!')))
    })
}

/// Per-sub-population shadow for the reduction axis `kind` walk of a multi-type
/// later block (#452): the CIDR variant of [`multitype_axis_shadow`]'s dispatch.
/// Unlike the existing single-type [`cidr_region_shadow`] (untouched), an earlier
/// setter that does not constrain `kind` at all is treated as UNIVERSE on it (it was
/// already proven a no-op on every OTHER axis by [`axis_is_noop`], so only its
/// restriction on the walked axis can decide a differing sub-population).
fn multitype_cidr_axis_shadow(
    later: &MatchBlock,
    kind: &str,
    keyword_lower: &str,
    value: &[String],
    earlier_setters: &[&MatchBlock],
) -> bool {
    let mut remaining = cidr_region_set(later, kind);
    for earlier in earlier_setters {
        let constrains_axis = criteria_by_type(earlier).contains_key(kind);
        let (region, rest) = if is_unconditional_match_all(earlier) || !constrains_axis {
            (remaining.clone(), Vec::new())
        } else {
            let earlier_set = cidr_region_set(earlier, kind);
            (
                cidr_set_intersection(&remaining, &earlier_set),
                cidr_set_difference(&remaining, &earlier_set),
            )
        };
        if !region.is_empty()
            && first_value_for(earlier, keyword_lower).is_some_and(|winning| winning != value)
        {
            return true;
        }
        remaining = rest;
        if remaining.is_empty() {
            break;
        }
    }
    false
}

/// The `LocalPort` analogue of [`multitype_cidr_axis_shadow`]: an earlier setter not
/// constraining `kind` is UNIVERSE on it, mirroring [`multitype_cidr_axis_shadow`]
/// (the existing single-type [`port_region_shadow`] stays untouched).
fn multitype_port_axis_shadow(
    later: &MatchBlock,
    kind: &str,
    keyword_lower: &str,
    value: &[String],
    earlier_setters: &[&MatchBlock],
) -> bool {
    let mut remaining = port_region_set(later, kind);
    for earlier in earlier_setters {
        let constrains_axis = criteria_by_type(earlier).contains_key(kind);
        let (region, rest): (BTreeSet<u32>, BTreeSet<u32>) =
            if is_unconditional_match_all(earlier) || !constrains_axis {
                (remaining.clone(), BTreeSet::new())
            } else {
                let earlier_set = port_region_set(earlier, kind);
                (
                    remaining.intersection(&earlier_set).copied().collect(),
                    remaining.difference(&earlier_set).copied().collect(),
                )
            };
        if !region.is_empty()
            && first_value_for(earlier, keyword_lower).is_some_and(|winning| winning != value)
        {
            return true;
        }
        remaining = rest;
        if remaining.is_empty() {
            break;
        }
    }
    false
}

/// The NAME (`User`/`Group`/`Host`) analogue of [`multitype_cidr_axis_shadow`]: a
/// witness-candidate search like the existing single-type [`names_region_shadow`]
/// (untouched), except an earlier setter not constraining `kind` at all is a
/// UNIVERSE member (every candidate name), not a non-member.
fn multitype_names_axis_shadow(
    later: &MatchBlock,
    kind: &str,
    keyword_lower: &str,
    value: &[String],
    earlier_setters: &[&MatchBlock],
) -> bool {
    const FRESH: &str = "\u{0}rulesteward-w07-fresh-name\u{0}";
    let mut candidates: Vec<String> = Vec::new();
    collect_name_literals(later, kind, &mut candidates);
    for earlier in earlier_setters {
        collect_name_literals(earlier, kind, &mut candidates);
    }
    candidates.push(FRESH.to_string());
    let member = |block: &MatchBlock, x: &str| -> bool {
        if is_unconditional_match_all(block) {
            return true;
        }
        match criteria_by_type(block).get(kind) {
            Some(instances) => instances.iter().all(|values| match_pattern_list(x, values)),
            // Doesn't constrain this axis at all: universe, a no-op setter here.
            None => true,
        }
    };
    candidates.iter().any(|name| {
        member(later, name)
            && earlier_setters
                .iter()
                .find(|earlier| member(earlier, name))
                .and_then(|winner| first_value_for(winner, keyword_lower))
                .is_some_and(|winning| winning != value)
    })
}

/// Dispatch the reduction-axis walk by criterion-type domain (the multi-type
/// analogue of [`region_shadow`]). Only invoked with an axis
/// [`multitype_reduction_axis`] selected.
fn multitype_axis_shadow(
    later: &MatchBlock,
    axis: &str,
    keyword_lower: &str,
    value: &[String],
    earlier_setters: &[&MatchBlock],
) -> bool {
    match axis {
        "user" | "group" | "host" => {
            multitype_names_axis_shadow(later, axis, keyword_lower, value, earlier_setters)
        }
        "address" | "localaddress" => {
            multitype_cidr_axis_shadow(later, axis, keyword_lower, value, earlier_setters)
        }
        "localport" => {
            multitype_port_axis_shadow(later, axis, keyword_lower, value, earlier_setters)
        }
        // LIVE defensive fallback for unmodeled-but-valid Match criteria (e.g.
        // `RDomain`): such a block has no region-modeled kind, so it reaches the
        // multitype path even single-type, and its lone axis dispatches here to the
        // conservative block-level comparison. MUST NOT become `unreachable!()` - a
        // linter never panics on valid input. Pinned by
        // `unmodeled_criterion_rdomain_takes_fallback_arm_and_flags`.
        _ => block_level_shadow(keyword_lower, value, earlier_setters),
    }
}

/// Whether every NAME (`User`/`Group`/`Host`) axis of `block` admits at least one
/// witness name: some candidate satisfying the axis's AND-of-instances
/// ([`member_of_type`]), enumerated as the axis's own listed literals plus the
/// FRESH sentinel - exactly the search the axis walk's `member()` machinery runs, so
/// this decides the same lists it decides: a pure-negation, self-negated, or
/// wider-negated-glob list (`!a*,ab`, `!*,alice`) has no witness, while an ordinary
/// satisfiable list has an obvious one (a listed positive literal, or FRESH when a
/// universal positive like `*` admits fresh names). A non-universal glob-only
/// positive (`a*`: no literal, FRESH fails it) is conservatively treated as
/// witness-less - the walk's documented literals+FRESH accepted-FN posture, an FN
/// (suppressed flag) never an FP. Gates the TOP of [`multitype_shadow`] - BOTH
/// multitype routes (#452 rounds 5-7): the DECLINE fallback because
/// [`block_level_shadow`] is MEMBERSHIP-BLIND (it compares first-setter values
/// without asking whether ANY connection satisfies the later block), and the axis
/// WALK because it inspects only the WALKED axis - a witness-less NON-walked axis
/// (a dead `!a*,ab` user list beside a walked address axis) is never consulted by
/// the walk's own `member()` search, which only reruns this enumeration for the
/// reduction axis itself. Suppress-only: it can turn a flag into silence, never
/// silence into a flag, so gating both routes cannot introduce a false positive.
fn name_axes_admit_witness(block: &MatchBlock) -> bool {
    const FRESH: &str = "\u{0}rulesteward-w07-fresh-name\u{0}";
    criteria_by_type(block).iter().all(|(kind, _)| {
        if !matches!(kind.as_str(), "user" | "group" | "host") {
            return true;
        }
        let mut candidates: Vec<String> = Vec::new();
        collect_name_literals(block, kind, &mut candidates);
        candidates.push(FRESH.to_string());
        candidates
            .iter()
            .any(|name| member_of_type(block, kind, name))
    })
}

/// Multi-type (2+ criterion type) LATER-block shadow detection (#452, #494): the
/// entry point the `w07` dispatcher calls once [`multitype_earlier_setters`] (G1-G3)
/// has structurally selected candidate earlier setters. Declines the per-axis
/// reduction (G4: `later` repeats a negated CIDR/port criterion,
/// [`later_has_repeated_negated_region`]; or no/non-unique reduction axis,
/// [`multitype_reduction_axis`]) to the coarse [`block_level_shadow`] comparison,
/// still using the structurally-selected `earlier_setters` rather than
/// `match_blocks_overlap`'s exact-type-set gate (G5). BOTH routes sit behind the
/// top-of-function [`block_matches_nobody`] and [`name_axes_admit_witness`] guards,
/// so neither the walk nor the membership-blind fallback ever flags a nobody later
/// block.
fn multitype_shadow(
    later: &MatchBlock,
    keyword_lower: &str,
    value: &[String],
    earlier_setters: &[&MatchBlock],
) -> bool {
    // INVARIANT: a block that matches NOBODY ([`block_matches_nobody`]:
    // `sshd_config(5)` AND-s all criteria on a header, so a repeated type with no
    // common witness admits no connection) is never a shadowee - nothing it sets is
    // ever applied, so nothing can be shadowed. Sits above BOTH routes: the walk
    // must never carve sub-populations out of an empty population. The EARLIER side
    // needs no twin guard: [`multitype_earlier_setters`] requires
    // [`type_co_satisfiable`] to find a witness satisfying the earlier block's OWN
    // criterion for each shared type (single-instance via [`criterion_overlap`]'s
    // `match_pattern_list`-faithful oracles; repeated via the combined-instance
    // fold, which subsumes the earlier-only instances) - a nobody block cannot
    // provide that witness regardless of instance count, so it is never selected
    // (and `Match all` is never nobody).
    if block_matches_nobody(later) {
        return false;
    }
    // INVARIANT: a witness-less name axis (`!a*,ab`, `!*,alice`) slips
    // [`block_matches_nobody`] (which deliberately does no glob-subsumption math)
    // but still admits no connection, so it too must be suppressed before EITHER
    // route: the DECLINE fallback compares values membership-blind, and the axis
    // WALK inspects only the walked axis, never a dead NON-walked one. The gate is
    // suppress-only (it can turn a flag into silence, never silence into a flag),
    // so it cannot introduce a false positive.
    if !name_axes_admit_witness(later) {
        return false;
    }
    if !later_has_repeated_negated_region(later) {
        let later_types = criteria_by_type(later);
        if let Some(axis) = multitype_reduction_axis(later, &later_types, earlier_setters) {
            return multitype_axis_shadow(later, &axis, keyword_lower, value, earlier_setters);
        }
    }
    // future (#452 follow-up): subset-type product carving (Option B) - declined
    // here deliberately; two-axis partitioned shadows are accepted FNs.
    block_level_shadow(keyword_lower, value, earlier_setters)
}

/// Whether two `Match` blocks can be satisfied by ONE connection, decided
/// conservatively from their criteria pattern text (no NSS / DNS resolution).
///
/// A block that matches NOBODY (a criterion type repeated on its header with no
/// common witness - `sshd_config(5)`: all criteria on the line are AND-ed) can
/// never co-satisfy anything, so any pair involving one is disjoint. An
/// unconditional `Match all` matches EVERY connection, so it overlaps any
/// satisfiable block. Otherwise the blocks overlap only when they constrain the
/// SAME set of criterion types and every shared type can co-apply. Requiring an
/// identical type set is the conservative reading of the v0.3 contract: any
/// asymmetry in criterion types (including a pure CROSS-type pair like `User` vs
/// `Group`) is left clean rather than guessing a membership relation a static linter
/// cannot know (#400).
///
/// A criterion type is AND-ed across BOTH blocks: since a repeated type is an
/// intersection, two blocks co-apply on a type iff ONE witness satisfies EVERY
/// occurrence of it in `a` AND `b` combined - decided by [`type_co_satisfiable`],
/// shared with [`multitype_earlier_setters`]'s subset-or-equal selection (#452).
fn match_blocks_overlap(a: &MatchBlock, b: &MatchBlock) -> bool {
    // A nobody-block co-satisfies nothing (checked first so a `Match all` does not
    // overlap an impossible block).
    if block_matches_nobody(a) || block_matches_nobody(b) {
        return false;
    }
    // `Match all` is always satisfied, so it overlaps any satisfiable block.
    if is_unconditional_match_all(a) || is_unconditional_match_all(b) {
        return true;
    }
    let a_types = criteria_by_type(a);
    let b_types = criteria_by_type(b);
    if a_types.len() != b_types.len() {
        return false;
    }
    a_types.iter().all(|(kind, a_insts)| {
        b_types
            .get(kind)
            .is_some_and(|b_insts| type_co_satisfiable(kind, a_insts, b_insts))
    })
}

/// Whether a NAME (`User`/`Group`/`Host`) pattern list positively matches NOBODY.
/// OpenSSH `match_pattern_list` returns a match only when some POSITIVE (un-negated)
/// pattern matches and no negated one does, so a SINGLE instance list is already
/// unsatisfiable in two shapes:
/// - PURE NEGATION (`!alice`): no un-negated entry at all, so no name ever matches
///   positively - the OpenSSH footgun: it does NOT mean "everyone except alice".
/// - SELF-NEGATION (`!alice,alice`): every un-negated entry also appears negated
///   EXACTLY, so any name a positive pattern admits is vetoed by its own negation.
///
/// An un-negated positive glob or literal that is not exactly negated keeps the
/// list SATISFIABLE (`!alice,*` matches every user except alice), so this must
/// never widen to "contains a negation". Harder unsatisfiable shapes (a WIDER
/// negated glob vetoing a narrower positive, e.g. `!a*,abc` or `!*,alice`) are
/// deliberately treated as satisfiable here - no glob-subsumption math. That
/// residual is closed by the [`name_axes_admit_witness`] gate at the top of
/// [`multitype_shadow`], whose literals+FRESH witness search runs the real
/// `match_pattern_list` semantics and covers BOTH multitype routes, walk and
/// decline (#452 rounds 5-7).
fn name_list_matches_nobody(values: &[String]) -> bool {
    let negated: BTreeSet<&str> = values.iter().filter_map(|v| v.strip_prefix('!')).collect();
    values
        .iter()
        .filter(|v| !v.starts_with('!'))
        .all(|v| negated.contains(v.as_str()))
}

/// Whether a `Match` block can be satisfied by NO connection. `sshd_config(5)`
/// AND-s all criteria on a header, so a criterion TYPE repeated on the same header
/// requires ONE connection to satisfy every occurrence of that type at once (e.g.
/// `Match User alice User bob` needs user == alice AND user == bob - impossible).
/// A block matches nobody iff some repeated type has no single common witness, OR
/// some NAME instance is unsatisfiable ON ITS OWN ([`name_list_matches_nobody`]:
/// a pure-negation or self-negated `match_pattern_list` positively admits no name,
/// regardless of how many instances the type has).
///
/// Other types appearing only once are assumed satisfiable (a single CIDR/port
/// criterion normally admits someone). An unmodeled repeated type is also assumed
/// satisfiable (conservative: [`criterion_overlap`] returns no-overlap for it
/// anyway, so treating it as satisfiable never manufactures a finding). Reasoning
/// per type from the block's OWN criteria only makes this independent of the other
/// block.
fn block_matches_nobody(block: &MatchBlock) -> bool {
    criteria_by_type(block).iter().any(|(kind, instances)| {
        if matches!(kind.as_str(), "user" | "group" | "host")
            && instances
                .iter()
                .any(|values| name_list_matches_nobody(values))
        {
            return true;
        }
        instances.len() >= 2 && !criterion_instances_have_common_witness(kind, instances)
    })
}

/// Whether ONE value satisfies EVERY instance of a repeated criterion type (i.e.
/// the AND across the repeated instances is non-empty). Mirrors the per-type
/// overlap machinery [`criterion_overlap`] uses, but folds the block's own repeated
/// instances rather than two blocks' value lists.
fn criterion_instances_have_common_witness(kind: &str, instances: &[&[String]]) -> bool {
    match kind {
        "user" | "group" | "host" => name_instances_have_common_witness(instances),
        "address" | "localaddress" => cidr_instances_have_common_address(instances),
        "localport" => port_instances_have_common_port(instances),
        // Unmodeled type: assume satisfiable (never manufactures a finding).
        _ => true,
    }
}

/// Whether one name satisfies EVERY `match_pattern_list` instance at once. Reuses
/// the literals-plus-FRESH witness set of [`pattern_lists_overlap`]: a name admitted
/// by all instances is either a listed literal or some fresh name, so testing every
/// literal plus one sentinel decides it. (A witness that only a wildcard-vs-wildcard
/// pairing would admit is the documented v0.3 accepted false negative.)
fn name_instances_have_common_witness(instances: &[&[String]]) -> bool {
    const FRESH: &str = "\u{0}rulesteward-w07-fresh-name\u{0}";
    let mut candidates: Vec<&str> = Vec::new();
    for values in instances {
        for value in *values {
            let literal = value.strip_prefix('!').unwrap_or(value);
            if !literal.is_empty() && !literal.contains(['*', '?']) {
                candidates.push(literal);
            }
        }
    }
    candidates.push(FRESH);
    candidates.iter().any(|name| {
        instances
            .iter()
            .all(|values| match_pattern_list(name, values))
    })
}

/// Whether one address lies in a positive net of EVERY `Address`/`LocalAddress`
/// instance at once. CIDR blocks nest or are disjoint, so a positive net `c` is
/// shared by all instances iff every instance has a positive net that CONTAINS `c`
/// (a supernet-or-equal). Negated entries are ignored (they only shrink the match
/// set, so ignoring them is false-negative-leaning, never false-positive-leaning).
fn cidr_instances_have_common_address(instances: &[&[String]]) -> bool {
    let per_instance: Vec<Vec<(IpAddr, u8)>> =
        instances.iter().map(|v| parse_cidr_list(v)).collect();
    per_instance.iter().flatten().any(|&c| {
        per_instance
            .iter()
            .all(|nets| nets.iter().any(|&n| n.1 <= c.1 && cidr_intersects(n, c)))
    })
}

/// Whether one port is in the positive set of EVERY `LocalPort` instance at once.
/// Negated entries are ignored (false-negative-leaning, never false-positive).
fn port_instances_have_common_port(instances: &[&[String]]) -> bool {
    let per_instance: Vec<Vec<u32>> = instances.iter().map(|v| parse_port_list(v)).collect();
    per_instance
        .iter()
        .flatten()
        .any(|p| per_instance.iter().all(|ports| ports.contains(p)))
}

/// Group a `Match` header's criteria by lowercased criterion keyword, keeping ONE
/// entry per criterion OCCURRENCE (the occurrences are NOT unioned). `sshd_config(5)`
/// AND-s the criteria on a header, so a type that appears more than once is the
/// INTERSECTION of its occurrences, not their union; callers fold the per-occurrence
/// value lists rather than treating them as one OR-list. The map's key set is the
/// block's set of criterion TYPES, which [`match_blocks_overlap`] compares for the
/// same-type-set rule.
fn criteria_by_type(block: &MatchBlock) -> BTreeMap<String, Vec<&[String]>> {
    let mut by_type: BTreeMap<String, Vec<&[String]>> = BTreeMap::new();
    for criterion in &block.criteria {
        by_type
            .entry(criterion.keyword.to_ascii_lowercase())
            .or_default()
            .push(criterion.values.as_slice());
    }
    by_type
}

/// Whether one connection can satisfy both value lists of a shared criterion type.
///
/// `sshd_config(5)` criteria are typed: name lists (`User`/`Group`/`Host`) match by
/// `match_pattern_list` glob semantics, `Address`/`LocalAddress` accept CIDR, and
/// `LocalPort` is a numeric list. An unmodeled criterion type is treated as
/// non-overlapping (conservative: an undecidable type never manufactures a finding).
fn criterion_overlap(kind: &str, a_values: &[String], b_values: &[String]) -> bool {
    match kind {
        "user" | "group" | "host" => pattern_lists_overlap(a_values, b_values),
        "address" | "localaddress" => cidr_lists_overlap(a_values, b_values),
        "localport" => port_lists_overlap(a_values, b_values),
        _ => false,
    }
}

/// Whether some name satisfies BOTH `match_pattern_list` value lists at once.
///
/// The witness search is exact for literal and `*`/`?`-wildcard patterns: any name
/// admitted by both lists must either equal one of the listed literals or be some
/// name distinct from all of them, so testing every literal plus one fresh sentinel
/// decides overlap. (`!bob,*` vs `bob` is disjoint: bob is excluded by the negation
/// and every other name fails the literal `bob`.)
fn pattern_lists_overlap(a: &[String], b: &[String]) -> bool {
    // A name matching none of the listed literals, to witness wildcard-only overlaps
    // (e.g. `*` vs `*`). The NUL bytes keep it distinct from any real criterion value.
    const FRESH: &str = "\u{0}rulesteward-w07-fresh-name\u{0}";
    let mut candidates: Vec<&str> = Vec::new();
    for value in a.iter().chain(b) {
        let literal = value.strip_prefix('!').unwrap_or(value);
        if !literal.is_empty() && !literal.contains(['*', '?']) {
            candidates.push(literal);
        }
    }
    candidates.push(FRESH);
    candidates
        .iter()
        .any(|name| match_pattern_list(name, a) && match_pattern_list(name, b))
}

/// OpenSSH `match_pattern_list`: a value matches iff some POSITIVE pattern matches
/// AND no negated (`!`-prefixed) pattern matches. A negated match fails the whole
/// list immediately, mirroring sshd's early return.
fn match_pattern_list(value: &str, patterns: &[String]) -> bool {
    let mut matched_positive = false;
    for pattern in patterns {
        if let Some(negated) = pattern.strip_prefix('!') {
            if glob_match(negated, value) {
                return false;
            }
        } else if glob_match(pattern, value) {
            matched_positive = true;
        }
    }
    matched_positive
}

#[cfg(test)]
mod w07_tests {
    //! sshd-W07: a first-value-wins keyword set in TWO `Match` blocks whose
    //! criteria can be simultaneously satisfied by one connection. sshd applies
    //! only the FIRST satisfied block's value and silently drops the later one, so
    //! the later (shadowed) instance is a real - if approximate - hardening hazard
    //! (#302, deferred from #247). Severity Warning: criteria-overlap is a static
    //! approximation, so the pass is advisory.
    //!
    //! # Grounding (`sshd_config(5)`; live rocky9 `OpenSSH_9.9p1` differential 2026-06-20)
    //! - Under `Match`: "If a keyword appears in multiple Match blocks that are
    //!   satisfied, only the first instance of the keyword is applied." So two
    //!   simultaneously-satisfied blocks setting the same first-value-wins keyword
    //!   to different values -> the later value is silently dropped (the shadow this
    //!   pass reports; it flags the LATER instance, matching sshd-E02's convention).
    //! - `Match` criteria: "The criteria ... are used only if all of the criteria on
    //!   the line are satisfied." A single connection carries ONE user, its groups,
    //!   one source/local address, and one local port, so it can satisfy two blocks
    //!   at once whenever their criteria are not provably disjoint.
    //! - Overlap is decided per criterion by `sshd_config(5)` pattern semantics:
    //!   comma lists are OR within a criterion; `*`/`?` are wildcards; a leading `!`
    //!   negates, and a pattern-list matches only if some POSITIVE pattern matches
    //!   and no negated pattern matches (OpenSSH `match_pattern_list`), so `!bob,*`
    //!   means "every user except bob"; `Address` accepts CIDR, so a supernet
    //!   contains a host address. Two blocks are flagged only when their criteria
    //!   CAN co-satisfy one connection; provably-disjoint criteria (`User alice` vs
    //!   `User bob`) are the normal, intended pattern and are never flagged - the
    //!   false positive the issue explicitly guards against.
    //!
    //! # Negation-aware CIDR overlap (#403)
    //! `Address`/`LocalAddress` are pattern-list criteria: sshd accepts a
    //! comma-separated list with negation (`Match Address 10.0.0.0/8,!192.168.0.0/16`
    //! parses cleanly on OpenSSH 9.9p1 + 10.2p1). A negated CIDR entry does not
    //! blanket-disable overlap for the whole criterion; it narrows the criterion's
    //! positive match set by exactly the negated range, and overlap is decided
    //! against what remains:
    //! - An IRRELEVANT negation (the negated range does not intersect the other
    //!   block's positive range) leaves the shared range untouched, so the two
    //!   blocks still co-satisfy on it.
    //! - A RELEVANT carve-out that fully COVERS the positive intersection makes
    //!   the two blocks disjoint - no connection can satisfy both.
    //! - A carve-out that only PARTIALLY covers the positive intersection still
    //!   leaves an overlapping remainder, so the blocks still co-satisfy.
    //!
    //! Treating any negated CIDR entry as blanket non-overlapping (rather than
    //! computing the actual remainder) is a real false-negative source: it hides
    //! genuine shadows whenever the negation is irrelevant or only partial.
    //!
    //! `LocalPort` is NOT a pattern-list criterion: sshd parses it with `a2port`,
    //! which accepts exactly ONE port and REJECTS both comma-lists and negation
    //! (`Match LocalPort 22,2222` and `Match LocalPort ...,!443` both fail with an
    //! `Invalid LocalPort ... on Match line` error, rc 255, verified on 9.9p1 +
    //! 10.2p1). So on any sshd-VALID config, `LocalPort` overlap reduces to
    //! single-port equality (`same_single_localport_flags_w07` /
    //! `disjoint_localports_do_not_flag_w07`); any port-list-negation branch in the
    //! impl is defensive-only and unreachable on valid input.
    //!
    //! # Repeated same-type criteria in one Match header are AND-ed (intersection)
    //! `sshd_config(5)`: a Match line's criteria "are used only if ALL of the
    //! criteria on the line are satisfied", so a header that repeats a criterion
    //! type (`Match User alice,carol User bob,carol`, `Match Address 10.0.0.0/8
    //! Address 10.0.0.0/16`) matches the INTERSECTION of its instances, NOT the
    //! union. Consequences W07 must honor (each locked by a test):
    //! - The intersection can be EMPTY (`User alice User bob`, `Address 10.0.0.0/8
    //!   Address 192.168.0.0/16`, `LocalPort 22 LocalPort 2222`) - the block then
    //!   matches nobody and can never shadow.
    //! - A NON-empty intersection that is disjoint from the later block still does
    //!   not shadow (`User alice,carol User bob,carol` ANDs to `carol`, disjoint
    //!   from a later `alice`).
    //! - A non-empty intersection that overlaps the later block DOES shadow.
    //!
    //! An impl that OR-unions the repeated criteria over-matches and false-fires;
    //! `sshd -T -C` on OpenSSH 10.2p1 confirms the AND (intersection) reading.
    //!
    //! # W07 fires only on FIRST-VALUE-WINS keywords set to DIFFERENT values
    //! Two further restrictions the pass must honor (each locked by a negative test):
    //! - ACCUMULATING keywords are EXCLUDED. `sshd_config(5)` says `AcceptEnv`'s
    //!   variables "may be separated by whitespace or spread across multiple
    //!   `AcceptEnv` directives": such keywords union across lines rather than
    //!   shadow, so a repeat across two Match blocks drops nothing. W07's scope is
    //!   the first-value-wins set ONLY; the accumulating set that sshd-E02 already
    //!   maintains (`E02_ALLOW_REPEAT`: `AcceptEnv`, `Port`, `ListenAddress`,
    //!   `HostKey`, `Include`, and the `Allow*`/`Deny*` user/group keywords) never
    //!   fires W07. An
    //!   implementer should REUSE `E02_ALLOW_REPEAT` here rather than re-deriving the
    //!   list (e.g. `SetEnv` is first-value-wins in this codebase's `sshd -T`
    //!   grounding and is deliberately absent from that set, so it IS W07-eligible).
    //! - SAME-value repeats are CLEAN. A shadow is a hazard only when the dropped
    //!   value DIFFERS from the winning one; two co-satisfiable blocks setting the
    //!   same first-value-wins keyword to the SAME value have no behavioral effect,
    //!   so W07 reports drift, not redundancy.
    //!
    //! These tests drive the full dispatcher `lint()` and filter to `sshd-W07`, so
    //! they pin the observable end-to-end contract regardless of which pass emits
    //! it. Every positive fixture uses same-criterion-TYPE overlaps whose
    //! overlap/disjointness is decidable from the pattern text alone.
    //!
    //! # `Match all` is a shadowER, never a shadowEE (owner-decided scope)
    //! An unconditional `Match all` is a Match block whose criteria are ALWAYS
    //! satisfied, so for W07's purposes it participates as the EARLIEST satisfied
    //! setter of any first-value-wins keyword: a later conditional block that sets
    //! the same keyword to a different value IS shadowed and flagged. This is
    //! verified empirically - `sshd -T -C user=bob` on OpenSSH 9.9p1 applies a
    //! leading `Match all X11Forwarding yes` and drops a later `Match User bob
    //! X11Forwarding no`. (Contrast a BARE global directive, which a later Match
    //! OVERRIDES rather than shadows; `global_then_single_match_override_is_clean`
    //! pins that distinct case.) But the decided v0.3 scope is asymmetric: a
    //! `Match all` block is never itself flagged as a shadowEE. A `Match all` that
    //! appears AFTER a conditional stays the effective default for every connection
    //! the earlier conditional does not cover, and being overridden for the covered
    //! population is the intended default-plus-exception idiom, not a hazard.
    //! `match_all_shadows_later_conditional_flags_w07`,
    //! `match_all_same_value_as_later_conditional_is_clean`, and
    //! `match_all_after_a_conditional_is_not_a_shadowee` lock this shape.
    //!
    //! # Cross-type criteria are INTENTIONALLY clean (conservative contract, v0.3)
    //! Two blocks with DIFFERENT criterion types (e.g. `Match User alice` vs
    //! `Match Group admins`) can only co-satisfy if the user is a member of the
    //! group, which a static linter cannot know without resolving NSS membership.
    //! For v0.3 the decided contract is the CONSERVATIVE reading: do NOT flag
    //! cross-type pairs (no shell-out, no membership guessing), accepting the missed
    //! case rather than risking a false positive. Opt-in NSS-backed membership
    //! resolution that would let W07 reason about `User` vs `Group` overlap is a
    //! post-v0.3 follow-up tracked as #400. `cross_type_user_and_group_do_not_flag_w07`
    //! locks this so the implementer cannot accidentally flag it.
    //!
    //! # Per-sub-population cross-Match shadow (#409)
    //! W07 flags a later block when some NON-EMPTY SUB-POPULATION of the connections
    //! it matches is won by an EARLIER block with a DIFFERENT value - even when a
    //! different earlier block agrees with the later value for a DIFFERENT
    //! sub-population. The v0.3 block-level rule missed this: it asked only whether
    //! SOME earlier overlapping block agreed with the later value ANYWHERE, so an
    //! agreeing block covering one sub-population masked a differing block colliding
    //! with another. `Host alpha` yes / `Host beta` no / `Host alpha,beta` yes now
    //! flags line 6 for the beta sub-population (GROUND TRUTH `sshd -T -C host=beta`
    //! -> `x11forwarding no` on OpenSSH 10.2p1: the middle block wins over block 2),
    //! locked by `partitioned_host_sets_flag_beta_subpopulation_w07`,
    //! `partitioned_user_sets_flag_bob_subpopulation_w07`,
    //! `partitioned_cidr_flags_middle_subnet_w07`, and
    //! `partitioned_multiregion_only_part_shadowed_w07` (the last proves a clean
    //! remainder sub-population is NOT over-flagged).
    //!
    //! Detection stays provably FALSE-POSITIVE-FREE (it may still MISS hard cases but
    //! never over-flags): an earlier block that covers the later block's WHOLE
    //! population with the SAME value wins those connections first and SUPPRESSES the
    //! flag, and region reasoning never crosses criterion TYPES (preserving the #400
    //! conservative contract). The over-flag guards are
    //! `agreeing_earlier_block_covering_whole_population_suppresses_flag_w07`,
    //! `partition_all_same_value_is_clean`,
    //! `partition_cross_type_middle_block_is_invisible_clean`,
    //! `partitioned_cidr_carveout_region_empty_does_not_overflag_block2_w07`, and
    //! `single_localport_region_reduces_to_block_level_w07` (single-port equality
    //! must not regress). NOTE the first and fourth guards are NOT diagnostic-free:
    //! their covering block 0 genuinely shadows the MIDDLE block (a true cross-Match
    //! shadow, flagged on line 4 both before and after #409); the guard is that block
    //! 2 (line 6) is not OVER-flagged, so they pin the exact diag set `{line 4}`.
    //!
    //! # Other documented v0.3 accepted false negatives
    //! Besides the cross-type conservative reading above (#400), three further gaps
    //! are intentionally accepted rather than implemented:
    //! - WILDCARD-vs-WILDCARD glob overlap (e.g. `User dev-*` vs `User *-web`, or
    //!   `User a*` vs `User a*`) is a deferred false negative: the overlap oracle
    //!   only witnesses a wildcard pattern against a LITERAL value on the other side
    //!   (a listed literal or a fresh sentinel), not two wildcard patterns against
    //!   each other, so a pair of only-wildcard criteria that could co-satisfy some
    //!   literal user is not flagged. `wildcard_vs_wildcard_is_an_accepted_fn_is_clean`
    //!   locks this.
    //! - REPEATED CIDR/LocalPort criteria carrying a negation (e.g. `Match Address
    //!   10.0.0.0/8,!10.1.0.0/16 Address 10.0.0.0/8`) are treated conservatively as
    //!   non-overlapping: computing the true negation-aware intersection ACROSS
    //!   repeated occurrences of a type is beyond the negation-blind cross-occurrence
    //!   witness, so W07 declines to flag rather than risk a false positive (an
    //!   FN-leaning guard). `repeated_cidr_criteria_with_negation_conservative_no_shadow`
    //!   locks this.
    //! - MULTI-TYPE shadows spanning a GENUINE TWO-AXIS partition remain an accepted
    //!   FN (#452 follow-up, "Option B" subset-type product carving - deliberately
    //!   declined, see the comment at the decline point in `multitype_shadow`). A
    //!   block constraining 2+ criterion TYPES is now DETECTED via a
    //!   single-differing-AXIS reduction (#452, #494): earlier setters are selected
    //!   STRUCTURALLY (`Match all`, or a subset-or-equal criterion type-set that is
    //!   still co-satisfiable per shared axis - including a bare-`User`/bare-`Address`
    //!   SUBSET predecessor `match_blocks_overlap`'s old exact-type-set gate silently
    //!   dropped, #494), and when exactly one axis is left differing (every OTHER
    //!   axis is a provable setter no-op: unconstrained, or an EXACT algebraic cover
    //!   of the later block's own restriction there) the existing single-type region
    //!   walk runs on that one axis. `ce4_452_target_partition_flags_only_the_shadowed_subnet`
    //!   is the issue's own target case (`Match User alice Address 10.1.0.0/16` yes /
    //!   `...Address 10.2.0.0/16` no / `...Address 10.0.0.0/8` yes: GROUND TRUTH
    //!   `sshd -T -C user=alice,addr=10.2.0.5` -> `x11forwarding no` on OpenSSH
    //!   9.9p1/8.0p1); `ce1_agreeing_subset_user_predecessor_flags_middle_not_supernet`,
    //!   `ce2_subset_address_predecessor_constrains_the_differing_axis`, and
    //!   `ce3_differing_subset_user_predecessor_whole_population_shadow` lock the #494
    //!   subset-predecessor fix. What remains an accepted FN: a genuine two-axis
    //!   partition where no axis is a setter no-op for every selected predecessor
    //!   (`accepted_fn_two_differing_axes_declines_to_todays_block_level_result`), an
    //!   unprovable name-axis neutrality check (a glob or negation on either side of a
    //!   would-be no-op axis), and G4 (the later block itself repeats an
    //!   `Address`/`LocalAddress`/`LocalPort` criterion with a negation,
    //!   `g4_repeated_negated_address_does_not_block_a_whole_population_shadow`) -
    //!   these all DECLINE the per-axis reduction and fall back to the coarse
    //!   `block_level_shadow` comparison (still using the new structural selection,
    //!   not `match_blocks_overlap`), so they may still MISS a finer partition but
    //!   never over-flag. The per-type co-satisfiability gate is still enforced during
    //!   selection, not traded away for the axis walk:
    //!   `ce7_disjoint_one_axis_nested_other_axis_stays_clean` and
    //!   `g3_earlier_type_outside_t_is_ignored_entirely` lock this, and
    //!   `ce6_match_all_agreeing_interleave_stays_correct_regression_lock` locks that
    //!   the pre-existing `Match all` interleave is undisturbed.
    //! - HOST case-folding (#495): the impl's `Host` axis matching is case-SENSITIVE
    //!   (`glob_match` compares chars exactly) but sshd lowercases the client
    //!   hostname before Match evaluation, so a `Host` criterion differing from
    //!   another only by case is treated as disjoint (accepted FN) and a mixed-case
    //!   pattern that sshd would never match can still participate in overlap
    //!   reasoning (accepted FP/FN on the host axis only). Parked as the tracked
    //!   follow-up #495.

    use crate::lints::{SshdLintContext, lint};
    use rulesteward_core::{Diagnostic, Severity};
    use std::path::Path;

    /// Parse `src`, run every single-file lint pass with the default (target=None)
    /// context, and keep only the `sshd-W07` diagnostics. Other passes' codes
    /// (e.g. sshd-W01 required-directive on this minimal fixture) are filtered out,
    /// so each assertion pins W07 alone.
    fn w07_diags(src: &str) -> Vec<Diagnostic> {
        let blocks =
            crate::parser::parse_config_str_located(src, Path::new("/etc/ssh/sshd_config"))
                .expect("fixture parses");
        lint(
            &blocks,
            Path::new("/etc/ssh/sshd_config"),
            &SshdLintContext::default(),
        )
        .into_iter()
        .filter(|d| d.code == "sshd-W07")
        .collect()
    }

    // ---- POSITIVE: overlapping same-type criteria + a shared first-value-wins keyword ----

    #[test]
    fn identical_match_criteria_shadow_flags_w07() {
        // Two blocks with IDENTICAL criteria (`User alice`) are trivially
        // co-satisfiable, so the same first-value-wins keyword set to two different
        // values shadows the later line.
        let d = w07_diags(
            "Match User alice\n    X11Forwarding yes\n\
             Match User alice\n    X11Forwarding no\n",
        );
        assert_eq!(d.len(), 1, "exactly one cross-Match shadow");
        assert_eq!(d[0].code, "sshd-W07");
        assert_eq!(d[0].severity, Severity::Warning);
        assert_eq!(
            d[0].line, 4,
            "the LATER (shadowed) instance is flagged, not the winning first one"
        );
    }

    #[test]
    fn identical_group_criteria_shadow_flags_w07() {
        // Overlap is not User-specific: two identical `Group admins` blocks also
        // co-satisfy (any connection whose user is in admins), so the pass must
        // handle every criterion type uniformly, not just `User`.
        let d = w07_diags(
            "Match Group admins\n    X11Forwarding yes\n\
             Match Group admins\n    X11Forwarding no\n",
        );
        assert_eq!(d.len(), 1, "identical Group criteria co-satisfy -> one W07");
        assert_eq!(d[0].line, 4);
    }

    #[test]
    fn same_type_lists_sharing_a_value_flags_w07() {
        // Comma lists are OR within a criterion. `alice,carol` and `carol,dave`
        // share `carol`, so a carol connection satisfies both blocks.
        let d = w07_diags(
            "Match User alice,carol\n    X11Forwarding yes\n\
             Match User carol,dave\n    X11Forwarding no\n",
        );
        assert_eq!(d.len(), 1, "intersecting user lists co-satisfy -> one W07");
        assert_eq!(d[0].line, 4);
    }

    #[test]
    fn wildcard_user_overlaps_specific_user_flags_w07() {
        // `*` matches any user, so `User *` and `User bob` co-satisfy for a bob
        // connection. A correct impl must expand the wildcard, not compare the
        // literal `*` against `bob`.
        let d = w07_diags(
            "Match User *\n    X11Forwarding yes\n\
             Match User bob\n    X11Forwarding no\n",
        );
        assert_eq!(d.len(), 1, "wildcard overlaps the specific user -> one W07");
        assert_eq!(d[0].line, 4);
    }

    #[test]
    fn cidr_supernet_contains_host_address_flags_w07() {
        // `Address` accepts CIDR. 10.1.2.3 is inside 10.0.0.0/8, so a connection
        // from 10.1.2.3 satisfies both blocks.
        let d = w07_diags(
            "Match Address 10.0.0.0/8\n    X11Forwarding yes\n\
             Match Address 10.1.2.3\n    X11Forwarding no\n",
        );
        assert_eq!(d.len(), 1, "host address inside the supernet -> one W07");
        assert_eq!(d[0].line, 4);
    }

    // ---- NEGATIVE: provably-disjoint criteria, or nothing actually shadowed ----

    #[test]
    fn disjoint_users_do_not_flag_w07() {
        // The canonical false positive to avoid: no single connection is both
        // alice and bob, so the two blocks are never both applied. This is the
        // normal, intended per-user pattern the issue calls out.
        assert!(
            w07_diags(
                "Match User alice\n    X11Forwarding yes\n\
                 Match User bob\n    X11Forwarding no\n",
            )
            .is_empty(),
            "disjoint same-type user literals never co-satisfy"
        );
    }

    #[test]
    fn disjoint_user_lists_do_not_flag_w07() {
        // `alice,carol` and `bob,dave` share no value and use no wildcard, so no
        // user matches both lists.
        assert!(
            w07_diags(
                "Match User alice,carol\n    X11Forwarding yes\n\
                 Match User bob,dave\n    X11Forwarding no\n",
            )
            .is_empty(),
            "disjoint user lists never co-satisfy"
        );
    }

    #[test]
    fn disjoint_cidrs_do_not_flag_w07() {
        // 192.168.0.0/16 neither contains nor intersects 10.0.0.0/8, so no source
        // address satisfies both blocks.
        assert!(
            w07_diags(
                "Match Address 10.0.0.0/8\n    X11Forwarding yes\n\
                 Match Address 192.168.0.0/16\n    X11Forwarding no\n",
            )
            .is_empty(),
            "disjoint CIDR ranges never co-satisfy"
        );
    }

    #[test]
    fn disjoint_localports_do_not_flag_w07() {
        // A connection arrives on ONE local port, so `LocalPort 22` and
        // `LocalPort 2222` are mutually exclusive.
        assert!(
            w07_diags(
                "Match LocalPort 22\n    X11Forwarding yes\n\
                 Match LocalPort 2222\n    X11Forwarding no\n",
            )
            .is_empty(),
            "disjoint local ports never co-satisfy"
        );
    }

    #[test]
    fn negated_pattern_excluding_the_user_is_clean() {
        // `!bob,*` matches every user EXCEPT bob (OpenSSH `match_pattern_list`: the
        // negated `!bob` excludes bob, and the positive `*` admits everyone else).
        // It is therefore DISJOINT from `User bob`. A naive impl that reads `*` as
        // "matches everything including bob" would raise a false positive here.
        assert!(
            w07_diags(
                "Match User !bob,*\n    X11Forwarding yes\n\
                 Match User bob\n    X11Forwarding no\n",
            )
            .is_empty(),
            "a pattern-list that negates the other block's sole user is disjoint"
        );
    }

    #[test]
    fn global_then_single_match_override_is_clean() {
        // A global directive overridden inside ONE Match block is the intended
        // mechanism, not a cross-Match shadow: only one Match block sets the
        // keyword, so there is no second satisfiable Match instance to drop.
        assert!(
            w07_diags(
                "X11Forwarding yes\n\
                 Match User bob\n    X11Forwarding no\n",
            )
            .is_empty(),
            "global + a single Match override is the intended pattern, not a shadow"
        );
    }

    #[test]
    fn different_keywords_in_overlapping_blocks_are_clean() {
        // Even with IDENTICAL (fully overlapping) `User alice` criteria, the two
        // blocks set DIFFERENT keywords, so neither value is shadowed. W07 must key
        // on a shared first-value-wins keyword, not merely on two overlapping blocks.
        assert!(
            w07_diags(
                "Match User alice\n    X11Forwarding yes\n\
                 Match User alice\n    PasswordAuthentication no\n",
            )
            .is_empty(),
            "no keyword is shared across the two blocks, so nothing is shadowed"
        );
    }

    #[test]
    fn cross_type_user_and_group_do_not_flag_w07() {
        // Conservative v0.3 contract: `Match User alice` and `Match Group admins`
        // co-satisfy ONLY if alice is a member of admins, which a static linter
        // cannot determine without NSS membership resolution. Rather than guess (and
        // risk a false positive when alice is NOT in admins), W07 leaves cross-type
        // criteria pairs CLEAN for v0.3. Opt-in membership resolution that could
        // flag this is the post-v0.3 follow-up #400. This is the issue's headline
        // "permissive early Match masking a stricter later one" shape, deliberately
        // left unflagged under the conservative reading.
        assert!(
            w07_diags(
                "Match User alice\n    X11Forwarding yes\n\
                 Match Group admins\n    X11Forwarding no\n",
            )
            .is_empty(),
            "cross-type User/Group overlap is unknowable statically, so it is not flagged (#400)"
        );
    }

    #[test]
    fn accumulating_keyword_across_overlapping_blocks_is_clean() {
        // W07 fires ONLY on FIRST-VALUE-WINS keywords. `AcceptEnv` ACCUMULATES:
        // `sshd_config(5)` says its variables "may be separated by whitespace or
        // spread across multiple AcceptEnv directives", so a carol connection
        // (which matches both overlapping User lists) keeps BOTH LANG and LC_TIME -
        // nothing is shadowed. AcceptEnv is in the accumulating set
        // (`E02_ALLOW_REPEAT`), so W07 must exclude it exactly as sshd-E02 does.
        // Guards against an impl that flags any repeated keyword across overlapping
        // blocks regardless of accumulate-vs-shadow semantics.
        assert!(
            w07_diags(
                "Match User alice,carol\n    AcceptEnv LANG\n\
                 Match User carol,dave\n    AcceptEnv LC_TIME\n",
            )
            .is_empty(),
            "accumulating keywords union across blocks, so there is no shadow to flag"
        );
    }

    #[test]
    fn same_value_repeat_across_overlapping_blocks_is_clean() {
        // A shadow is a hazard only when the dropped value DIFFERS from the winning
        // one. Two co-satisfiable `User alice` blocks setting X11Forwarding to the
        // SAME value `yes` have no behavioral effect (the first wins, but the second
        // would have applied the identical value), so W07 reports drift, not
        // redundancy. Guards against an impl that flags on keyword-repeat alone
        // without comparing the values.
        assert!(
            w07_diags(
                "Match User alice\n    X11Forwarding yes\n\
                 Match User alice\n    X11Forwarding yes\n",
            )
            .is_empty(),
            "identical values across co-satisfiable blocks are redundant, not a shadow"
        );
    }

    #[test]
    fn negated_cidr_carveout_makes_blocks_disjoint_is_clean() {
        // `ssh_config(5)` PATTERNS: a negated entry carves its range OUT of the
        // match set. `192.168.0.0/16,!192.168.5.0/24` matches all of 192.168/16
        // EXCEPT 192.168.5.0/24. The two blocks' positive intersection (the /16
        // vs the /24) is exactly 192.168.5.0/24, and the negation fully COVERS
        // that intersection, so under the negation-aware overlap rule (an
        // intersection fully covered by a negation is disjoint; a negation that
        // only partially covers it still overlaps) the two blocks are DISJOINT -
        // no source address satisfies both, so the second block is never
        // shadowed even though the values differ (no vs yes). An impl that drops
        // the negated entry entirely (reading the criterion as the wider,
        // un-carved /16) false-fires here.
        assert!(
            w07_diags(
                "Match Address 192.168.0.0/16,!192.168.5.0/24\n    X11Forwarding no\n\
                 Match Address 192.168.5.0/24\n    X11Forwarding yes\n",
            )
            .is_empty(),
            "a negated CIDR carve-out makes the two Address blocks disjoint"
        );
    }

    #[test]
    fn later_instance_compares_against_the_winning_value_not_any_earlier() {
        // sshd applies ONLY the first satisfied block's value, so the shadow hazard
        // is "a later instance whose value DIFFERS from the WINNER (block 0)". With
        // three co-satisfiable `User alice` blocks yes / no / yes: the winner is
        // line 2 (yes); line 4 (no) differs from the winner -> a real shadow; line 6
        // (yes) EQUALS the winner -> redundant, NOT a differing shadow. So exactly
        // ONE W07, on line 4. An impl that compares a later instance against ANY
        // earlier value (not the winner) wrongly fires on line 6 too, since line 6's
        // `yes` differs from line 4's `no`.
        let d = w07_diags(
            "Match User alice\n    X11Forwarding yes\n\
             Match User alice\n    X11Forwarding no\n\
             Match User alice\n    X11Forwarding yes\n",
        );
        assert_eq!(d.len(), 1, "only the winner-differing instance is a shadow");
        assert_eq!(
            d[0].line, 4,
            "line 4 (no) differs from the winning line 2 (yes); line 6 (yes) equals it"
        );
    }

    // ---- POSITIVE: negation-aware CIDR/LocalPort overlap (#403) ----

    #[test]
    fn irrelevant_negation_still_overlaps_flags_w07() {
        // The negated `!192.168.0.0/16` carves out a range that does not intersect
        // 10.0.0.0/8 at all, so it is IRRELEVANT to this pair's overlap: the shared
        // range (all of 10.0.0.0/8) is untouched, and the two blocks still
        // co-satisfy. An impl that treats ANY negated entry as blanket
        // non-overlapping would wrongly clear this pair.
        let d = w07_diags(
            "Match Address 10.0.0.0/8,!192.168.0.0/16\n    X11Forwarding yes\n\
             Match Address 10.0.0.0/8\n    X11Forwarding no\n",
        );
        assert_eq!(
            d.len(),
            1,
            "an irrelevant negation does not prevent overlap"
        );
        assert_eq!(d[0].line, 4);
    }

    #[test]
    fn three_block_shadow_compares_against_the_overlapping_winner_not_any_earlier() {
        // The #403 headline case: three co-satisfiable Address 10.0.0.0/8 blocks
        // (the first with an irrelevant `!192.168.0.0/16` carve-out) set no / yes /
        // no. Block 0 (no) is the winner for every 10.x connection. Block 1's line 4
        // (yes) differs from the winner -> a real shadow. Block 2's line 6 (no)
        // EQUALS block 0's value -> redundant against the winner, not a differing
        // shadow, even though it differs from block 1's (also-shadowed) yes. An
        // impl that only compares a later instance against the IMMEDIATELY prior
        // differing instance (rather than every earlier overlapping block) would
        // wrongly also flag line 6.
        let d = w07_diags(
            "Match Address 10.0.0.0/8,!192.168.0.0/16\n    X11Forwarding no\n\
             Match Address 10.0.0.0/8\n    X11Forwarding yes\n\
             Match Address 10.0.0.0/8\n    X11Forwarding no\n",
        );
        assert_eq!(d.len(), 1, "only the winner-differing instance is a shadow");
        assert_eq!(
            d[0].line, 4,
            "line 4 (yes) differs from the winning block 0 (no)"
        );
    }

    #[test]
    fn partial_negation_coverage_still_overlaps_flags_w07() {
        // The negated `!192.168.5.0/24` covers only ONE /24 out of the full /16 the
        // other block matches (e.g. 192.168.6.1 satisfies both blocks), so the
        // carve-out is PARTIAL, not full: the blocks still co-satisfy on the
        // uncovered remainder. Contrast with
        // `negated_cidr_carveout_makes_blocks_disjoint_is_clean`, where the
        // negation exactly equals the other block's entire positive range (full
        // coverage -> disjoint).
        let d = w07_diags(
            "Match Address 192.168.0.0/16,!192.168.5.0/24\n    X11Forwarding yes\n\
             Match Address 192.168.0.0/16\n    X11Forwarding no\n",
        );
        assert_eq!(
            d.len(),
            1,
            "a partial carve-out leaves an overlapping remainder"
        );
        assert_eq!(d[0].line, 4);
    }

    #[test]
    fn same_single_localport_flags_w07() {
        // A valid `Match LocalPort` value is a SINGLE port: sshd parses it with
        // `a2port`, which accepts exactly one port and REJECTS comma-lists
        // (`Match LocalPort 22,2222` -> "Invalid LocalPort '22,2222' on Match line",
        // rc 255, verified on OpenSSH 9.9p1 + 10.2p1). So on valid configs LocalPort
        // overlap is single-port equality: two `Match LocalPort 2222` blocks accept
        // the same port and co-satisfy, shadowing the later value.
        let d = w07_diags(
            "Match LocalPort 2222\n    X11Forwarding yes\n\
             Match LocalPort 2222\n    X11Forwarding no\n",
        );
        assert_eq!(
            d.len(),
            1,
            "identical single LocalPort co-satisfies -> one W07"
        );
        assert_eq!(d[0].line, 4);
    }

    #[test]
    fn ipv6_cidr_supernet_contains_host_address_flags_w07() {
        // `Address` CIDR handling is not IPv4-only: 2001:db8::1 is inside the
        // 2001:db8::/32 supernet, exactly as the IPv4
        // `cidr_supernet_contains_host_address_flags_w07` case above.
        let d = w07_diags(
            "Match Address 2001:db8::/32\n    X11Forwarding yes\n\
             Match Address 2001:db8::1\n    X11Forwarding no\n",
        );
        assert_eq!(
            d.len(),
            1,
            "IPv6 host address inside the supernet -> one W07"
        );
        assert_eq!(d[0].line, 4);
    }

    // ---- POSITIVE: glob wildcard vs a LITERAL value (wildcard-vs-wildcard is a
    // ---- documented deferred false negative for v0.3; see the module doc-comment) ----

    #[test]
    fn trailing_star_glob_matches_literal_flags_w07() {
        // `dev-*` (glob) against the LITERAL `dev-web` is exactly the kind of
        // wildcard-vs-literal overlap `match_pattern_list` decides: `*` matches any
        // (possibly empty) suffix, so `dev-*` matches `dev-web`.
        let d = w07_diags(
            "Match User dev-*\n    X11Forwarding yes\n\
             Match User dev-web\n    X11Forwarding no\n",
        );
        assert_eq!(
            d.len(),
            1,
            "trailing-star glob matches the literal -> one W07"
        );
        assert_eq!(d[0].line, 4);
    }

    #[test]
    fn mid_pattern_star_glob_matches_literal_flags_w07() {
        // `a*c` against the LITERAL `abac` forces the `*`'s backtracking loop (the
        // `*` must first try consuming zero chars, then one, ... until the
        // remaining literal `c` lines up), unlike a simple trailing-star case.
        let d = w07_diags(
            "Match User a*c\n    X11Forwarding yes\n\
             Match User abac\n    X11Forwarding no\n",
        );
        assert_eq!(
            d.len(),
            1,
            "mid-pattern glob matches the literal -> one W07"
        );
        assert_eq!(d[0].line, 4);
    }

    #[test]
    fn question_mark_glob_matches_literal_flags_w07() {
        // `al?ce` against the LITERAL `alice`: `?` matches exactly one character
        // (the `i`), distinct from `*`'s zero-or-more.
        let d = w07_diags(
            "Match User al?ce\n    X11Forwarding yes\n\
             Match User alice\n    X11Forwarding no\n",
        );
        assert_eq!(d.len(), 1, "`?` glob matches the literal -> one W07");
        assert_eq!(d[0].line, 4);
    }

    // ---- POSITIVE: additional criterion TYPES must each dispatch (Host, LocalAddress) ----

    #[test]
    fn identical_host_criteria_shadow_flags_w07() {
        // `Host` is a name-list criterion just like `User`/`Group`, and
        // `sshd_config(5)`'s "only the first instance of the keyword is applied"
        // rule spans ALL Match block types. Two identical `Host web1` blocks
        // co-satisfy (a connection whose client hostname is web1 matches both), so
        // the pass must handle Host as a first-class overlap type, not fall through
        // a `_ => no_overlap` arm that silently skips it.
        let d = w07_diags(
            "Match Host web1\n    X11Forwarding yes\n\
             Match Host web1\n    X11Forwarding no\n",
        );
        assert_eq!(d.len(), 1, "identical Host criteria co-satisfy -> one W07");
        assert_eq!(d[0].line, 4);
    }

    #[test]
    fn localaddress_cidr_supernet_contains_host_flags_w07() {
        // `LocalAddress` is a DISTINCT criterion string from `Address` (it is the
        // local address sshd accepted the connection on), and `sshd_config(5)` says
        // it too accepts CIDR. 10.1.2.3 is inside 10.0.0.0/8, so a connection
        // accepted on 10.1.2.3 satisfies both blocks. Guards against a dispatcher
        // that wires up `address` CIDR handling but leaves `localaddress` in a
        // fall-through no-overlap arm.
        let d = w07_diags(
            "Match LocalAddress 10.0.0.0/8\n    X11Forwarding yes\n\
             Match LocalAddress 10.1.2.3\n    X11Forwarding no\n",
        );
        assert_eq!(
            d.len(),
            1,
            "LocalAddress host inside the supernet -> one W07"
        );
        assert_eq!(d[0].line, 4);
    }

    // NOTE: LocalPort negation/comma-list tests were removed - sshd's `a2port`
    // rejects both `Match LocalPort 22,2222` and any negated port with rc 255
    // ("Invalid LocalPort ... on Match line", OpenSSH 9.9p1 + 10.2p1), so there is
    // no VALID sshd config that exercises port-list negation. Valid LocalPort
    // reasoning is single-port equality (see `same_single_localport_flags_w07` and
    // `disjoint_localports_do_not_flag_w07`); any port-negation branch in the impl
    // is defensive-only and unreachable on sshd-valid input.

    // ---- NEGATIVE: accepted v0.3 false negatives (documented, not implemented) ----

    #[test]
    fn wildcard_vs_wildcard_is_an_accepted_fn_is_clean() {
        // Two wildcard-only `User a*` criteria obviously co-satisfy (any user named
        // `aX` matches both), so ideally this would flag. But W07's overlap oracle
        // only witnesses a wildcard pattern against a LITERAL value (a listed
        // literal from the other block, or a fresh sentinel) - it never matches two
        // wildcard PATTERNS against each other, so nothing witnesses `a*` vs `a*`.
        // This is the documented v0.3 wildcard-vs-wildcard ACCEPTED false negative:
        // kept clean, not flagged. Locks the FN AND pins that the candidate witness
        // set admits only literals, not wildcard patterns (an impl that added `a*`
        // itself to the candidate literals would wrongly flag this).
        assert!(
            w07_diags(
                "Match User a*\n    X11Forwarding yes\n\
                 Match User a*\n    X11Forwarding no\n",
            )
            .is_empty(),
            "wildcard-vs-wildcard is a documented v0.3 accepted false negative (no literal witness)"
        );
    }

    // ---- POSITIVE + NEGATIVE: `Match all` is a shadowER, never a shadowEE (owner-locked) ----

    #[test]
    fn match_all_shadows_later_conditional_flags_w07() {
        // GROUND TRUTH (`sshd -T -C user=bob` on OpenSSH 9.9p1): `Match all
        // X11Forwarding yes` followed by `Match User bob X11Forwarding no` yields
        // `x11forwarding yes` for bob - sshd applies the `Match all` value and DROPS
        // the later `no`. An unconditional `Match all` is a Match block whose
        // criteria are ALWAYS satisfied, so it is the FIRST satisfied setter and
        // shadows any later conditional block that sets the same first-value-wins
        // keyword to a different value. NOTE `Match all K` is NOT the same as a bare
        // global `K`: a bare global is OVERRIDDEN by a later Match block, but a
        // `Match all` block is applied FIRST and wins (contrast
        // `global_then_single_match_override_is_clean`, which is a bare global). The
        // later `Match User bob no` on line 4 is the dropped instance.
        let d = w07_diags(
            "Match all\n    X11Forwarding yes\n\
             Match User bob\n    X11Forwarding no\n",
        );
        assert_eq!(
            d.len(),
            1,
            "Match all is the earliest always-satisfied setter -> the later block is shadowed"
        );
        assert_eq!(d[0].line, 4, "the later (shadowed) conditional is flagged");
    }

    #[test]
    fn match_all_same_value_as_later_conditional_is_clean() {
        // `Match all` shadows a later conditional only when the DROPPED value
        // differs from the winning one (same first-value-wins rule as everywhere
        // else). Here both set `yes`, so nothing behaviorally changes for bob - the
        // later instance is redundant, not a differing shadow.
        assert!(
            w07_diags(
                "Match all\n    X11Forwarding yes\n\
                 Match User bob\n    X11Forwarding yes\n",
            )
            .is_empty(),
            "identical values across Match all + a later conditional are redundant, not a shadow"
        );
    }

    #[test]
    fn match_all_after_a_conditional_is_not_a_shadowee() {
        // OWNER-DECIDED conservative scope: a `Match all` block that appears AFTER a
        // conditional is NEVER flagged (W07 treats `Match all` as a shadowER but
        // never a shadowEE). Its value stays the effective default for every
        // connection the earlier conditional does not cover - here every non-bob
        // user gets `no` - and being overridden for the one covered user (bob, who
        // takes the earlier `yes`) is the intended default-plus-exception idiom, not
        // a shadow hazard. This pins the decision so the implementer cannot
        // accidentally flag the trailing `Match all no` on line 4.
        assert!(
            w07_diags(
                "Match User bob\n    X11Forwarding yes\n\
                 Match all\n    X11Forwarding no\n",
            )
            .is_empty(),
            "a Match all after a conditional stays the effective default; it is not a shadowee"
        );
    }

    #[test]
    fn match_all_does_not_shadow_a_nobody_block_is_clean() {
        // `Match all` shadows a LATER real block, but the later block here -
        // `Match User alice User bob` - AND-s two disjoint single-value criteria and
        // so matches NOBODY (no user is both alice and bob). No connection ever
        // reaches that block, so there is nothing for `Match all` to drop. This pins
        // that the nobody-check runs BEFORE the Match-all overlap short-circuit: a
        // block that matches no one is never a shadowee, even under a leading
        // always-satisfied `Match all`.
        assert!(
            w07_diags(
                "Match all\n    X11Forwarding yes\n\
                 Match User alice User bob\n    X11Forwarding no\n",
            )
            .is_empty(),
            "Match all cannot shadow a later block that matches nobody"
        );
    }

    // ---- NEGATIVE: repeated same-type criteria in one header are AND-ed (match nobody) ----

    #[test]
    fn repeated_same_type_criteria_are_and_match_nobody_is_clean() {
        // GROUND TRUTH (`sshd -T -C user=alice` and `-C user=bob` both yield the
        // LATER block's value; the first block never wins for either): `sshd_config(5)`
        // says a Match line's criteria are "used only if ALL of the criteria on the
        // line are satisfied", so `Match User alice User bob` requires
        // user==alice AND user==bob simultaneously - impossible, so the block matches
        // NOBODY and can never shadow the later `Match User alice`. An impl that
        // UNIONS the two repeated `User` criteria (user in {alice, bob}) wrongly
        // treats the first block as overlapping and false-fires. (Currently RED: the
        // impl false-fires 1 diag; GREEN after the AND fix.)
        assert!(
            w07_diags(
                "Match User alice User bob\n    X11Forwarding yes\n\
                 Match User alice\n    X11Forwarding no\n",
            )
            .is_empty(),
            "two User criteria in one header are AND-ed (no user is both), so the block matches nobody"
        );
    }

    // ---- NEGATIVE: a satisfiable-but-NARROWED repeated-criteria block whose
    // ---- intersection is disjoint from the later block does not shadow (residual FP) ----

    #[test]
    fn narrowed_repeated_user_disjoint_from_later_is_clean() {
        // Repeated same-type criteria AND, so a block's effective match set is the
        // INTERSECTION of its instances. `User alice,carol User bob,carol` ANDs
        // {alice,carol} with {bob,carol} = just `carol`. The later block is `alice`;
        // carol != alice, so NO connection satisfies both -> no shadow. GROUND TRUTH
        // (`sshd -T` on OpenSSH 10.2p1 with the exact fixture): user=alice ->
        // x11forwarding no (later block applies; block-0 does NOT match alice),
        // user=carol -> yes (block-0 applies), so the two never both apply. An impl
        // that OR-unions the repeated criteria to {alice,carol,bob} wrongly overlaps
        // on alice and false-fires. (Currently RED until the intersection fix lands.)
        assert!(
            w07_diags(
                "Match User alice,carol User bob,carol\n    X11Forwarding yes\n\
                 Match User alice\n    X11Forwarding no\n",
            )
            .is_empty(),
            "block-0's AND-intersection is carol only, disjoint from the later `alice`; no shadow"
        );
    }

    #[test]
    fn narrowed_repeated_address_disjoint_from_later_is_clean() {
        // Address criteria AND the same way. `Address 10.0.0.0/8 Address 10.0.0.0/16`
        // ANDs to the tighter `10.0.0.0/16` (in /8 AND in /16). The later block is
        // 10.5.0.0/16, which is disjoint from 10.0.0.0/16, so no source address
        // satisfies both. GROUND TRUTH (`sshd -T` on 10.2p1): addr 10.0.5.5 -> yes
        // (block-0's /16 applies), addr 10.5.5.5 -> no (later applies); never both.
        // An OR-union impl treats block-0 as the wider /8, wrongly overlaps 10.5.x,
        // and false-fires. (Currently RED until the intersection fix lands.)
        assert!(
            w07_diags(
                "Match Address 10.0.0.0/8 Address 10.0.0.0/16\n    X11Forwarding yes\n\
                 Match Address 10.5.0.0/16\n    X11Forwarding no\n",
            )
            .is_empty(),
            "block-0's AND-intersection is 10.0.0.0/16, disjoint from the later 10.5.0.0/16"
        );
    }

    // ---- POSITIVE: a satisfiable narrowed repeated-criteria block that STILL
    // ---- overlaps the later block shadows it (intersection is non-empty + shared) ----

    #[test]
    fn narrowed_repeated_user_overlapping_later_flags_w07() {
        // `User alice,carol User carol` ANDs {alice,carol} with {carol} = `carol`
        // (a non-empty match set). The later block is `carol`, so a carol connection
        // satisfies BOTH -> the later value is shadowed. Confirms the intersection is
        // computed correctly (block matches somebody) AND that the somebody overlaps
        // the later block.
        let d = w07_diags(
            "Match User alice,carol User carol\n    X11Forwarding yes\n\
             Match User carol\n    X11Forwarding no\n",
        );
        assert_eq!(
            d.len(),
            1,
            "block-0 ANDs to carol, which co-satisfies the later carol block -> one W07"
        );
        assert_eq!(d[0].line, 4);
    }

    #[test]
    fn narrowed_repeated_address_overlapping_later_flags_w07() {
        // `Address 10.0.0.0/8 Address 10.1.0.0/16` ANDs to the tighter `10.1.0.0/16`.
        // 10.1.2.3 is inside 10.1.0.0/16 (block-0) AND is the later block, so a
        // connection from 10.1.2.3 satisfies both -> shadow.
        let d = w07_diags(
            "Match Address 10.0.0.0/8 Address 10.1.0.0/16\n    X11Forwarding yes\n\
             Match Address 10.1.2.3\n    X11Forwarding no\n",
        );
        assert_eq!(
            d.len(),
            1,
            "block-0 ANDs to 10.1.0.0/16, which contains the later 10.1.2.3 -> one W07"
        );
        assert_eq!(d[0].line, 4);
    }

    #[test]
    fn repeated_same_localport_criteria_overlapping_later_flags_w07() {
        // Two `LocalPort 2222` criteria in one header AND to port 2222 (each is a
        // single valid `a2port`; the intersection of {2222} with {2222} is {2222}).
        // The later block is 2222, so a connection on port 2222 satisfies both ->
        // shadow. Valid sshd form (space-separated repeated criteria, single ports).
        let d = w07_diags(
            "Match LocalPort 2222 LocalPort 2222\n    X11Forwarding yes\n\
             Match LocalPort 2222\n    X11Forwarding no\n",
        );
        assert_eq!(
            d.len(),
            1,
            "repeated LocalPort 2222 ANDs to 2222, co-satisfying the later block -> one W07"
        );
        assert_eq!(d[0].line, 4);
    }

    // ---- NEGATIVE: a repeated-criteria block whose instances are mutually
    // ---- exclusive matches NOBODY, so it can never shadow ----

    #[test]
    fn repeated_disjoint_address_criteria_match_nobody_is_clean() {
        // `Address 10.0.0.0/8 Address 192.168.0.0/16` ANDs two disjoint ranges, whose
        // intersection is EMPTY, so block-0 matches nobody and cannot shadow the
        // later 10.1.2.3 block. Exercises the "block matches nobody" path for Address.
        assert!(
            w07_diags(
                "Match Address 10.0.0.0/8 Address 192.168.0.0/16\n    X11Forwarding yes\n\
                 Match Address 10.1.2.3\n    X11Forwarding no\n",
            )
            .is_empty(),
            "10.0.0.0/8 AND 192.168.0.0/16 is empty -> block-0 matches nobody"
        );
    }

    #[test]
    fn repeated_disjoint_localport_criteria_match_nobody_is_clean() {
        // A connection arrives on exactly ONE local port, so `LocalPort 22 LocalPort
        // 2222` (AND-ed) is unsatisfiable: no port is both 22 and 2222. Block-0
        // matches nobody and cannot shadow the later 2222 block. Exercises the
        // "block matches nobody" path for LocalPort on a valid sshd form.
        assert!(
            w07_diags(
                "Match LocalPort 22 LocalPort 2222\n    X11Forwarding yes\n\
                 Match LocalPort 2222\n    X11Forwarding no\n",
            )
            .is_empty(),
            "LocalPort 22 AND LocalPort 2222 is impossible -> block-0 matches nobody"
        );
    }

    #[test]
    fn repeated_cidr_criteria_with_negation_conservative_no_shadow() {
        // Block-0 REPEATS the Address type where one occurrence carries a negation
        // (`10.0.0.0/8,!10.1.0.0/16 Address 10.0.0.0/8`). Computing the true
        // negation-aware intersection ACROSS repeated occurrences is beyond the
        // negation-blind cross-occurrence witness, so W07 conservatively treats a
        // repeated CIDR/LocalPort type that contains a negation as non-overlap - an
        // ACCEPTED v0.3 false negative that matches W07's FN-leaning posture (never
        // risk a false positive). Here it also happens to be a TRUE negative:
        // block-0's effective set is (10.0.0.0/8 minus 10.1.0.0/16), which EXCLUDES
        // the later block's 10.1.2.3, so no connection satisfies both. GROUND TRUTH
        // (`sshd -T` on OpenSSH 10.2p1 with this exact fixture): addr 10.1.2.3 ->
        // x11forwarding no (block-0 excluded, later applies), addr 10.2.2.2 -> yes
        // (block-0 applies); the two never both apply. Currently RED: the impl's
        // repeated-occurrence branch is negation-blind and false-fires; GREEN once
        // the conservative guard lands.
        assert!(
            w07_diags(
                "Match Address 10.0.0.0/8,!10.1.0.0/16 Address 10.0.0.0/8\n    X11Forwarding yes\n\
                 Match Address 10.1.2.3\n    X11Forwarding no\n",
            )
            .is_empty(),
            "a repeated CIDR type carrying a negation is conservatively non-overlapping (accepted FN)"
        );
    }

    // ---- POSITIVE: glob trailing-`*` consumed at end-of-value (mutation-coverage lock) ----

    #[test]
    fn trailing_star_matches_at_end_of_value_flags_w07() {
        // `dev-*` against the LITERAL `dev-`: the `*` matches an EMPTY suffix at the
        // very end of the value, which exercises `glob_match`'s trailing-`*`
        // consumption path (distinct from the earlier glob positives, where the `*`
        // is consumed mid-string against a non-empty tail). The two blocks co-satisfy
        // on a user literally named `dev-`.
        let d = w07_diags(
            "Match User dev-*\n    X11Forwarding yes\n\
             Match User dev-\n    X11Forwarding no\n",
        );
        assert_eq!(
            d.len(),
            1,
            "trailing `*` matches an empty end-of-value suffix -> one W07"
        );
        assert_eq!(d[0].line, 4);
    }

    // ---- POSITIVE: per-sub-population cross-Match shadow (#409, per-region) ----
    // Each fixture is GROUND-TRUTHED against live `sshd -T -C` on OpenSSH 10.2p1.
    // These are RED against the v0.3 block-level rule (which finds an agreeing earlier
    // block and stays clean); they pass once per-sub-population detection lands.

    #[test]
    fn partitioned_host_sets_flag_beta_subpopulation_w07() {
        // #409, per-sub-population detection (this is the FLIP of the former v0.3
        // accepted-FN test `partitioned_host_sets_are_an_accepted_fn_v0_3`):
        // `Host alpha` yes / `Host beta` no / `Host alpha,beta` yes. For a BETA
        // connection the middle block (line 4, no) wins and block 2's `yes` (line 6)
        // is silently dropped - a real per-connection shadow. GROUND TRUTH
        // (`sshd -T -C` on OpenSSH 10.2p1): host=beta -> `x11forwarding no` (middle
        // block wins over block 2); host=alpha -> yes (block 0 wins, block 2 agrees).
        // The v0.3 block-level rule MISSED this: block 0 (`Host alpha`, yes) overlaps
        // block 2 with the SAME value, so "some earlier overlapping block agrees" held
        // and line 6 stayed clean. The per-region rule sees block 0's agreement covers
        // only the alpha sub-population, NOT the beta one that collides with the middle
        // block, so the beta sub-population is an uncovered differing shadow.
        let d = w07_diags(
            "Match Host alpha\n    X11Forwarding yes\n\
             Match Host beta\n    X11Forwarding no\n\
             Match Host alpha,beta\n    X11Forwarding yes\n",
        );
        assert_eq!(d.len(), 1, "the beta sub-population shadow flags block 2");
        assert_eq!(
            d[0].line, 6,
            "line 6 (Host alpha,beta yes) is shadowed for the beta sub-population by line 4 (no)"
        );
    }

    #[test]
    fn partitioned_user_sets_flag_bob_subpopulation_w07() {
        // #409 on the `User` criterion: `User alice` yes / `User bob` no /
        // `User alice,bob` yes. For a BOB connection the middle block (line 4, no)
        // wins and block 2's `yes` (line 6) is dropped. GROUND TRUTH (`sshd -T -C
        // user=bob,host=h,addr=1.2.3.4` on OpenSSH 10.2p1): `x11forwarding no`;
        // user=alice -> yes (block 0 wins, block 2 agrees). Only the bob
        // sub-population is a differing shadow -> exactly one flag on line 6.
        let d = w07_diags(
            "Match User alice\n    X11Forwarding yes\n\
             Match User bob\n    X11Forwarding no\n\
             Match User alice,bob\n    X11Forwarding yes\n",
        );
        assert_eq!(d.len(), 1, "the bob sub-population shadow flags block 2");
        assert_eq!(d[0].line, 6);
    }

    #[test]
    fn partitioned_cidr_flags_middle_subnet_w07() {
        // #409 on CIDR: `Address 10.1.0.0/16` yes / `Address 10.2.0.0/16` no /
        // `Address 10.0.0.0/8` yes. Block 2's /8 supernet contains BOTH earlier /16
        // subnets. For a 10.2.x connection the middle block (line 4, no) wins and
        // block 2's `yes` (line 6) is dropped. GROUND TRUTH (`sshd -T -C` on OpenSSH
        // 10.2p1): addr=10.2.0.5 -> no (middle wins), addr=10.1.0.5 -> yes (block 0
        // wins, block 2 agrees), addr=10.3.0.5 -> yes (block 2 still wins the /8
        // remainder no earlier block covers). Only the 10.2.0.0/16 sub-population is a
        // differing shadow -> one flag on line 6.
        let d = w07_diags(
            "Match Address 10.1.0.0/16\n    X11Forwarding yes\n\
             Match Address 10.2.0.0/16\n    X11Forwarding no\n\
             Match Address 10.0.0.0/8\n    X11Forwarding yes\n",
        );
        assert_eq!(
            d.len(),
            1,
            "the 10.2.0.0/16 sub-population shadow flags block 2"
        );
        assert_eq!(d[0].line, 6);
    }

    #[test]
    fn partitioned_multiregion_only_part_shadowed_w07() {
        // #409 with a THREE-name later block: `Host alpha` yes / `Host beta` no /
        // `Host alpha,beta,gamma` yes. Block 2 covers alpha (block 0 agrees, yes),
        // beta (middle block wins, no -> shadow), and gamma (no earlier block, block 2
        // wins). GROUND TRUTH (`sshd -T -C` on OpenSSH 10.2p1): host=beta -> no
        // (shadow), host=gamma -> yes (block 2 wins), host=alpha -> yes (block 0
        // agrees). Only the beta sub-population differs -> EXACTLY one flag on line 6,
        // proving per-region detection isolates the shadowed sub-population without
        // over-flagging the clean gamma remainder.
        let d = w07_diags(
            "Match Host alpha\n    X11Forwarding yes\n\
             Match Host beta\n    X11Forwarding no\n\
             Match Host alpha,beta,gamma\n    X11Forwarding yes\n",
        );
        assert_eq!(
            d.len(),
            1,
            "only the beta sub-population shadows; the gamma remainder is clean"
        );
        assert_eq!(d[0].line, 6);
    }

    // ---- NEGATIVE (#409 over-flag guards): per-region detection must stay FP-free.
    // ---- These PASS today (block-level rule) and must STAY correct after #409. Two
    // ---- of them are NOT diagnostic-free: the covering block 0 genuinely shadows the
    // ---- MIDDLE block (line 4), so they pin the exact diag set {line 4} - the guard
    // ---- is that block 2 / line 6 is not OVER-flagged (see the barrier report). ----

    #[test]
    fn agreeing_earlier_block_covering_whole_population_suppresses_flag_w07() {
        // THE core #409 over-flag guard. `Host alpha,beta` yes / `Host beta` no /
        // `Host alpha,beta` yes. Block 0 covers block 2's ENTIRE population (alpha AND
        // beta) with the SAME value (yes) and, being earliest, wins every connection
        // block 2 could match BEFORE the middle `Host beta no` can apply. GROUND TRUTH
        // (`sshd -T -C` on OpenSSH 10.2p1): host=alpha -> yes AND host=beta -> yes
        // (block 0 wins both; the middle `no` NEVER applies). So block 2 (line 6) has
        // NO differing sub-population and must NOT be flagged - a naive per-region impl
        // that picked the middle block as beta's shadower would over-flag here.
        //
        // The fixture is NOT diagnostic-free: because block 0 (`alpha,beta` yes) wins
        // every beta connection, the middle `Host beta no` (line 4) is itself a genuine
        // cross-Match shadow of block 0 and IS flagged (the block-level rule TODAY and
        // the per-region rule after #409 agree on line 4). So this pins the EXACT diag
        // set {line 4}: block 2 / line 6 stays UN-flagged (the over-flag guard) while
        // block 1 / line 4 is the real shadow. `.is_empty()` would be WRONG here - line
        // 4 is a true shadow, confirmed by the oracle above.
        let d = w07_diags(
            "Match Host alpha,beta\n    X11Forwarding yes\n\
             Match Host beta\n    X11Forwarding no\n\
             Match Host alpha,beta\n    X11Forwarding yes\n",
        );
        assert_eq!(
            d.len(),
            1,
            "only the middle block (line 4) is shadowed by block 0; block 2 is not over-flagged"
        );
        assert_eq!(
            d[0].line, 4,
            "line 4 (Host beta no) is shadowed by block 0 (alpha,beta yes); block 2 / line 6 is NOT flagged"
        );
    }

    #[test]
    fn middle_block_winning_region_outside_block2_does_not_overflag_w07() {
        // #409 over-flag guard for PARTIAL coverage: the middle differing block wins a
        // non-empty region that lies OUTSIDE block 2's population, so it must not cause
        // block 2 to be flagged. `Host alpha,beta` yes / `Host beta,gamma` no /
        // `Host alpha,beta` yes. Block 0 covers block 2's WHOLE population (alpha AND
        // beta) with the same value (yes) and wins it first; the middle block only wins
        // gamma, which is NOT in block 2. GROUND TRUTH (`sshd -T -C` on OpenSSH 10.2p1):
        // host=alpha -> yes AND host=beta -> yes (block 0 wins ALL of block 2's
        // population), host=gamma -> no (middle block wins gamma, OUTSIDE block 2). So
        // block 2 / line 6 is NEVER shadowed and must stay clean; a wrong impl that
        // flags block 2 merely because a differing earlier block overlaps it and wins
        // SOME region (here just gamma) - rather than a region that INTERSECTS block 2's
        // population - would over-flag line 6.
        //
        // As with `agreeing_...`, the fixture is NOT diagnostic-free: block 0
        // (alpha,beta yes) wins the middle block's beta with a different value, so the
        // middle `Host beta,gamma no` (line 4) is itself a genuine shadow and IS
        // flagged. The assertion pins the EXACT diag set {line 4}: block 2 / line 6 is
        // not over-flagged.
        let d = w07_diags(
            "Match Host alpha,beta\n    X11Forwarding yes\n\
             Match Host beta,gamma\n    X11Forwarding no\n\
             Match Host alpha,beta\n    X11Forwarding yes\n",
        );
        assert_eq!(
            d.len(),
            1,
            "the middle block's winning region gamma lies outside block 2; block 2 not over-flagged"
        );
        assert_eq!(
            d[0].line, 4,
            "line 4 (Host beta,gamma no) is shadowed by block 0 for beta; block 2 / line 6 is NOT flagged"
        );
    }

    #[test]
    fn wildcard_agreeing_block0_covering_whole_population_does_not_overflag_block2_w07() {
        // sshd -T (OpenSSH 10.2p1): host=db.corp -> yes, host=web.corp -> yes.
        // block0 (`Host *.corp` yes) wins ALL of block2's *.corp population; block2's
        // yes equals the winner -> block2 (line 6) is NOT a differing shadow. Only
        // block1 (`Host db.corp` no, line 4) is genuinely shadowed by block0.
        let d = w07_diags(
            "Match Host *.corp\n    X11Forwarding yes\n\
             Match Host db.corp\n    X11Forwarding no\n\
             Match Host *.corp\n    X11Forwarding yes\n",
        );
        assert_eq!(
            d.len(),
            1,
            "block2/line6 must NOT be over-flagged (winner value == block2 value)"
        );
        assert_eq!(
            d[0].line, 4,
            "only block1 (Host db.corp no) is a differing shadow of block0"
        );
    }

    #[test]
    fn multi_type_earlier_cover_does_not_suppress_single_type_block2_w07() {
        // #409 locks the fix's structural filter (exact same-type membership): a
        // MULTI-TYPE earlier block does NOT count as a single-type earlier setter, so
        // it cannot suppress a single-type block's shadow. `Match User carol Host *`
        // yes / `Match User carol` no / `Match User carol` yes. block0 is 2-type
        // ({user,host}), so it is excluded from block2's single-type-user region
        // reasoning; block1 (`User carol` no) wins the witness -> block2 (line 6, yes)
        // IS a differing shadow and is flagged. GROUND TRUTH (`sshd -T -C` on OpenSSH
        // 10.2p1): user=carol with host ABSENT -> `x11forwarding no` (block0's `Host *`
        // fails with no host, so block1 `no` wins and block2 `yes` is shadowed there);
        // user=carol,host=bar -> yes (block0 wins). The linter conservatively treats
        // block0 (different type set) as not covering block2, so it correctly flags
        // block2. Exact W07 set confirmed via the CLI: only line 6.
        let d = w07_diags(
            "Match User carol Host *\n    X11Forwarding yes\n\
             Match User carol\n    X11Forwarding no\n\
             Match User carol\n    X11Forwarding yes\n",
        );
        assert_eq!(
            d.len(),
            1,
            "block2 (single-type) is a genuine shadow of block1"
        );
        assert_eq!(
            d[0].line, 6,
            "block2's X11Forwarding yes on line 6 is flagged"
        );
        assert_eq!(d[0].code, "sshd-W07");
    }

    #[test]
    fn multi_type_later_block_shadow_flags_via_block_level_fallback_w07() {
        // #409: a MULTI-TYPE (2-type) LATER block has no single region type, so
        // single_region_type returns None and it routes through the block-level
        // fallback, which still flags a genuine shadow. `Match User alice Host web.corp`
        // yes / `Match User alice Host web.corp` no: both blocks constrain the same
        // {user,host} type set and overlap (literal alice + literal web.corp), so
        // block0 (yes) shadows the later block's `no` (line 4). GROUND TRUTH (`sshd -T
        // -C user=alice,host=web.corp` on OpenSSH 10.2p1): `x11forwarding yes` (block0
        // wins), so the later `no` is a real dropped value; exact W07 line via the CLI:
        // line 4. NOTE the host MUST be literal here: a WILDCARD host (`Host *.corp`)
        // would be the accepted wildcard-vs-wildcard FN (no overlap witness) and emit
        // nothing, so it would not exercise this block-level-fallback path.
        let d = w07_diags(
            "Match User alice Host web.corp\n    X11Forwarding yes\n\
             Match User alice Host web.corp\n    X11Forwarding no\n",
        );
        assert_eq!(
            d.len(),
            1,
            "the multi-type later block routes through the block-level fallback and is flagged"
        );
        assert_eq!(
            d[0].line, 4,
            "block1's X11Forwarding no on line 4 is shadowed by block0"
        );
        assert_eq!(d[0].code, "sshd-W07");
    }

    #[test]
    fn partition_all_same_value_is_clean() {
        // #409 guard: three partition blocks that all set the SAME value shadow
        // nothing. `Host alpha` yes / `Host beta` yes / `Host alpha,beta` yes. Every
        // connection sees `yes` regardless of which block wins, so there is no
        // differing value to drop. GROUND TRUTH (`sshd -T -C` on 10.2p1): host=alpha
        // -> yes, host=beta -> yes. Guards against a per-region impl that flags on
        // partition STRUCTURE alone without comparing values.
        assert!(
            w07_diags(
                "Match Host alpha\n    X11Forwarding yes\n\
                 Match Host beta\n    X11Forwarding yes\n\
                 Match Host alpha,beta\n    X11Forwarding yes\n",
            )
            .is_empty(),
            "all-same-value partition blocks drop nothing"
        );
    }

    #[test]
    fn partition_cross_type_middle_block_is_invisible_clean() {
        // #409 guard that per-region reasoning never leaks across criterion TYPES
        // (preserving the #400 conservative contract). `User alice` yes /
        // `Group admins` no / `User alice` yes. The middle `Group admins` block is
        // CROSS-TYPE to the User blocks, so it is excluded from overlap entirely (a
        // static linter cannot resolve NSS membership; #400). Block 0 (User alice,
        // yes) covers block 2's whole population with the same value, and the
        // cross-type middle block partitions nothing, so nothing is flagged. An impl
        // whose region reasoning counted the cross-type block as shadowing part of
        // block 2 would violate #400 and false-fire. (Fully clean: block 0 does NOT
        // overlap the cross-type middle block either, so there is no line-4 shadow.)
        assert!(
            w07_diags(
                "Match User alice\n    X11Forwarding yes\n\
                 Match Group admins\n    X11Forwarding no\n\
                 Match User alice\n    X11Forwarding yes\n",
            )
            .is_empty(),
            "a cross-type middle block is invisible to region reasoning (#400 contract)"
        );
    }

    #[test]
    fn partitioned_cidr_carveout_region_empty_does_not_overflag_block2_w07() {
        // #409 guard requiring EXACT CIDR carve-out geometry. `Address 10.0.0.0/8`
        // yes / `Address 10.0.0.0/8,!10.5.0.0/16` no / `Address 10.5.0.0/16` yes. The
        // middle block's `!10.5.0.0/16` carve-out makes its positive region DISJOINT
        // from block 2 (10.5.0.0/16), so the middle block shadows NO part of block 2's
        // population; block 0 (/8) covers all of block 2's 10.5.x with the same value
        // (yes). GROUND TRUTH (`sshd -T -C` on 10.2p1): addr=10.5.1.1 -> yes (block 0
        // wins), addr=10.2.2.2 -> yes (block 0 wins; the middle `no` NEVER applies
        // anywhere). A naive per-region impl that ignored the `!` would think the
        // middle block covers block 2's 10.5.x with `no` and over-flag line 6.
        //
        // As with `agreeing_...`: block 0 (/8, yes) wins EVERY 10.x, so the middle
        // block (line 4, no) is itself a genuine shadow of block 0 and IS flagged. The
        // assertion pins the EXACT diag set {line 4}: block 2 / line 6 is NOT
        // over-flagged. `.is_empty()` would be WRONG (line 4 is a true shadow).
        let d = w07_diags(
            "Match Address 10.0.0.0/8\n    X11Forwarding yes\n\
             Match Address 10.0.0.0/8,!10.5.0.0/16\n    X11Forwarding no\n\
             Match Address 10.5.0.0/16\n    X11Forwarding yes\n",
        );
        assert_eq!(
            d.len(),
            1,
            "the carve-out empties the middle block's overlap with block 2; block 2 not over-flagged"
        );
        assert_eq!(
            d[0].line, 4,
            "line 4 (the /8-minus-/16 no block) is shadowed by block 0 (/8 yes); block 2 / line 6 is NOT flagged"
        );
    }

    #[test]
    fn single_localport_region_reduces_to_block_level_w07() {
        // #409 guard: region reasoning must not regress single-port equality.
        // `LocalPort 2201` yes / `LocalPort 2202` no / `LocalPort 2202` yes. On a VALID
        // sshd config `LocalPort` is a SINGLETON (a2port rejects comma-lists AND
        // negation with "Invalid LocalPort ... on Match line" / "Bad Match condition",
        // verified OpenSSH 10.2p1), so the "region" of a LocalPort block is a single
        // port and reduces to equality. Block 0 (2201) is disjoint from block 2 (2202);
        // block 1 (2202, no) overlaps block 2 (2202, yes) with a DIFFERING value ->
        // shadow on line 6. GROUND TRUTH (`sshd -T -C` on 10.2p1): lport=2202 ->
        // x11forwarding no (block 1 wins over block 2); lport=2201 -> yes.
        //
        // NOTE this is ALREADY a block-level flag TODAY (block 1 directly shadows block
        // 2; no partition is involved), NOT a #409-new case. It guards that the
        // per-region path preserves single-port equality rather than regressing it.
        let d = w07_diags(
            "Match LocalPort 2201\n    X11Forwarding yes\n\
             Match LocalPort 2202\n    X11Forwarding no\n\
             Match LocalPort 2202\n    X11Forwarding yes\n",
        );
        assert_eq!(d.len(), 1, "single-port equality still shadows -> one W07");
        assert_eq!(d[0].line, 6);
    }

    // ---- Direct unit test for the NAME-overlap oracle (white-box) ----
    // #409 routed the single-type NAME region path OFF `match_blocks_overlap` (its
    // pattern oracle cannot witness a wildcard-vs-wildcard overlap, so it would drop
    // an agreeing wildcard block and over-flag; see
    // `wildcard_agreeing_block0_covering_whole_population_does_not_overflag_block2_w07`).
    // That leaves the NAME branches of `match_blocks_overlap` /`criterion_overlap` /
    // `criterion_instances_have_common_witness` / `pattern_lists_overlap` /
    // `name_instances_have_common_witness` reachable end-to-end only through the
    // out-of-scope multi-type block-level fallback (an accepted-FN path with no
    // lint()-level fixture). They remain LIVE production code, so pin their contract
    // directly here. Grounded in OpenSSH `match_pattern_list` (a POSITIVE pattern must
    // match and NO negated pattern may match) and the AND-across-repeated-criteria rule.

    #[test]
    fn match_blocks_overlap_name_oracle_pinned_directly() {
        let mb = |src: &str| -> crate::ast::MatchBlock {
            crate::parser::parse_config_str_located(src, Path::new("/etc/ssh/sshd_config"))
                .expect("fixture parses")
                .into_iter()
                .find_map(|b| match b {
                    crate::ast::Block::Match(m) => Some(m),
                    crate::ast::Block::Global(_) => None,
                })
                .expect("fixture has a Match block")
        };
        let overlap = |a: &str, b: &str| super::match_blocks_overlap(&mb(a), &mb(b));
        // Single-instance name overlap (pattern_lists_overlap): a shared literal
        // `carol` co-satisfies both lists.
        assert!(overlap(
            "Match User alice,carol\n    X11Forwarding yes\n",
            "Match User carol\n    X11Forwarding yes\n",
        ));
        // Disjoint literals never co-satisfy.
        assert!(!overlap(
            "Match User alice\n    X11Forwarding yes\n",
            "Match User bob\n    X11Forwarding yes\n",
        ));
        // Wildcard vs literal: `*.corp` glob-matches the literal `db.corp`.
        assert!(overlap(
            "Match Host *.corp\n    X11Forwarding yes\n",
            "Match Host db.corp\n    X11Forwarding yes\n",
        ));
        // A negation excluding the peer's sole user is disjoint (`!bob,*` admits every
        // user EXCEPT bob, so it cannot co-satisfy `User bob`).
        assert!(!overlap(
            "Match User !bob,*\n    X11Forwarding yes\n",
            "Match User bob\n    X11Forwarding yes\n",
        ));
        // Repeated same-type criteria are AND-ed: `alice,carol` AND `carol` = `carol`,
        // which co-satisfies a later `carol` (name_instances_have_common_witness).
        assert!(overlap(
            "Match User alice,carol User carol\n    X11Forwarding yes\n",
            "Match User carol\n    X11Forwarding yes\n",
        ));
        // Repeated same-type with an EMPTY intersection matches nobody (User alice AND
        // User bob is impossible), so it overlaps nothing (block_matches_nobody).
        assert!(!overlap(
            "Match User alice User bob\n    X11Forwarding yes\n",
            "Match User carol\n    X11Forwarding yes\n",
        ));
        // A nobody-block co-satisfies nothing, even against an always-satisfied
        // `Match all` (the nobody-check must run BEFORE the Match-all short-circuit).
        assert!(!overlap(
            "Match Address 10.0.0.0/8 Address 192.168.0.0/16\n    X11Forwarding yes\n",
            "Match all\n    X11Forwarding yes\n",
        ));
        // `Match all` is always satisfied, so it overlaps any satisfiable block.
        assert!(overlap(
            "Match all\n    X11Forwarding yes\n",
            "Match User bob\n    X11Forwarding yes\n",
        ));
        // Repeated criteria are AND-ed across ALL occurrences, not just the first:
        // `alice,carol` AND `bob,carol` = `carol`, which is DISJOINT from a later
        // `alice`, so the blocks do NOT overlap (comparing only the first occurrence
        // `alice,carol` vs `alice` would wrongly report overlap).
        assert!(!overlap(
            "Match User alice,carol User bob,carol\n    X11Forwarding yes\n",
            "Match User alice\n    X11Forwarding yes\n",
        ));
        // The candidate filter admits ONLY literals + the FRESH sentinel; wildcards are
        // excluded (`!is_empty() && !contains(*/?)`). So two pure wildcards are the
        // accepted wildcard-vs-wildcard FN and do NOT overlap. If that filter's `&&`
        // weakened to `||`, a wildcard would leak in as a literal candidate and `a*`
        // vs `a*` would falsely overlap (the wildcard STRING `a*` glob-matches its own
        // pattern) -- this pins the filter conjunction that the region path bypasses.
        assert!(!overlap(
            "Match Host a*\n    X11Forwarding yes\n",
            "Match Host a*\n    X11Forwarding yes\n",
        ));
    }

    #[test]
    fn single_region_type_pinned_directly() {
        // Region reasoning is single-type only. A block with exactly one modeled
        // criterion type yields that type; 2+ types or an unmodeled type yields None
        // (routing to the block-level fallback).
        let mb = |src: &str| -> crate::ast::MatchBlock {
            crate::parser::parse_config_str_located(src, Path::new("/etc/ssh/sshd_config"))
                .expect("fixture parses")
                .into_iter()
                .find_map(|b| match b {
                    crate::ast::Block::Match(m) => Some(m),
                    crate::ast::Block::Global(_) => None,
                })
                .expect("fixture has a Match block")
        };
        let kind = |src: &str| super::single_region_type(&mb(src));
        assert_eq!(
            kind("Match User alice\n    X11Forwarding yes\n"),
            Some("user".to_string()),
        );
        assert_eq!(
            kind("Match Address 10.0.0.0/8\n    X11Forwarding yes\n"),
            Some("address".to_string()),
        );
        // Two criterion types -> None (block-level fallback).
        assert_eq!(
            kind("Match User alice Address 10.0.0.0/8\n    X11Forwarding yes\n"),
            None,
        );
        // A SINGLE Address instance carrying a negation is NOT the repeated-with-negation
        // guard (that needs >= 2 instances), so it stays a region type.
        assert_eq!(
            kind("Match Address 10.0.0.0/8,!10.5.0.0/16\n    X11Forwarding yes\n"),
            Some("address".to_string()),
        );
        // A REPEATED Address type carrying a negation trips the conservative guard -> None.
        assert_eq!(
            kind(
                "Match Address 10.0.0.0/8,!10.5.0.0/16 Address 10.0.0.0/8\n    X11Forwarding yes\n"
            ),
            None,
        );
    }

    #[test]
    fn block_matches_nobody_pinned_directly() {
        // A criterion TYPE repeated on one header is AND-ed, so a repeat with an empty
        // intersection matches nobody; a single (or satisfiable-repeated) criterion does
        // not. Pins the address / localport arms of the common-witness dispatch.
        let mb = |src: &str| -> crate::ast::MatchBlock {
            crate::parser::parse_config_str_located(src, Path::new("/etc/ssh/sshd_config"))
                .expect("fixture parses")
                .into_iter()
                .find_map(|b| match b {
                    crate::ast::Block::Match(m) => Some(m),
                    crate::ast::Block::Global(_) => None,
                })
                .expect("fixture has a Match block")
        };
        let nobody = |src: &str| super::block_matches_nobody(&mb(src));
        // Disjoint repeated Address / LocalPort -> nobody.
        assert!(nobody(
            "Match Address 10.0.0.0/8 Address 192.168.0.0/16\n    X11Forwarding yes\n"
        ));
        assert!(nobody(
            "Match Address 10.0.0.0/16 Address 10.5.0.0/16\n    X11Forwarding yes\n"
        ));
        assert!(nobody(
            "Match LocalPort 22 LocalPort 2222\n    X11Forwarding yes\n"
        ));
        // A single criterion, or a satisfiable repeated (nested) one, is somebody.
        assert!(!nobody("Match Address 10.0.0.0/8\n    X11Forwarding yes\n"));
        assert!(!nobody(
            "Match Address 10.0.0.0/8 Address 10.5.0.0/16\n    X11Forwarding yes\n"
        ));
        assert!(!nobody(
            "Match LocalPort 2222 LocalPort 2222\n    X11Forwarding yes\n"
        ));
    }

    #[test]
    fn port_region_set_pinned_directly() {
        // A LocalPort block's region set is its ports; repeated LocalPort criteria are
        // AND-ed (intersection). Pins port_region_set against a constant-set mutation.
        let mb = |src: &str| -> crate::ast::MatchBlock {
            crate::parser::parse_config_str_located(src, Path::new("/etc/ssh/sshd_config"))
                .expect("fixture parses")
                .into_iter()
                .find_map(|b| match b {
                    crate::ast::Block::Match(m) => Some(m),
                    crate::ast::Block::Global(_) => None,
                })
                .expect("fixture has a Match block")
        };
        assert_eq!(
            super::port_region_set(
                &mb("Match LocalPort 2202\n    X11Forwarding yes\n"),
                "localport"
            ),
            std::collections::BTreeSet::from([2202u32]),
        );
        // Repeated same port ANDs to itself.
        assert_eq!(
            super::port_region_set(
                &mb("Match LocalPort 2202 LocalPort 2202\n    X11Forwarding yes\n"),
                "localport",
            ),
            std::collections::BTreeSet::from([2202u32]),
        );
        // Disjoint repeated ports AND to the empty set.
        assert!(
            super::port_region_set(
                &mb("Match LocalPort 22 LocalPort 2222\n    X11Forwarding yes\n"),
                "localport",
            )
            .is_empty()
        );
    }

    #[test]
    fn same_value_localport_across_overlapping_blocks_is_clean() {
        // Two identical single-LocalPort blocks setting the SAME value have no
        // behavioral effect (the first wins, the second would apply the same value), so
        // there is no differing shadow. Pins the port region path's non-empty-region AND
        // differing-value conjunction (an OR would flag this redundant repeat).
        assert!(
            w07_diags(
                "Match LocalPort 2202\n    X11Forwarding yes\n\
                 Match LocalPort 2202\n    X11Forwarding yes\n",
            )
            .is_empty(),
            "identical value across two co-satisfiable LocalPort blocks is redundant, not a shadow"
        );
    }

    #[test]
    fn multi_type_block_level_fallback_flags_and_disjoint_is_clean() {
        // A block constraining 2+ criterion types routes through the block-level
        // fallback (region reasoning is single-type only). Two IDENTICAL multi-type
        // blocks co-satisfy, so a differing first-value-wins value shadows the later
        // line. Pins block_level_shadow's positive path.
        let d = w07_diags(
            "Match User alice Address 10.0.0.0/8\n    X11Forwarding yes\n\
             Match User alice Address 10.0.0.0/8\n    X11Forwarding no\n",
        );
        assert_eq!(
            d.len(),
            1,
            "identical multi-type blocks co-satisfy -> one W07"
        );
        assert_eq!(d[0].line, 4);
        // Two multi-type blocks that do NOT overlap (disjoint on the User type) never
        // co-satisfy, so nothing is shadowed. Pins the block-level filter's
        // overlap-AND-sets-keyword conjunction (an OR would treat the disjoint earlier
        // block as a spurious winner and false-fire).
        assert!(
            w07_diags(
                "Match User alice Address 10.0.0.0/8\n    X11Forwarding yes\n\
                 Match User bob Address 192.168.0.0/16\n    X11Forwarding no\n",
            )
            .is_empty(),
            "disjoint multi-type blocks never co-satisfy, so nothing is shadowed"
        );
    }

    // ---- Multi-type one-axis reduction (#452, #494) ----
    // Grounding: /home/runner/rulesteward-docs/research-notes/452-multitype-grounding.md
    // (session 7d, 2026-07-10). Oracle: live `sshd -T -C` in rockylinux containers,
    // OpenSSH 9.9p1 (rocky9) cross-checked against OpenSSH 8.0p1 (rocky8) - all 17
    // probed outcomes IDENTICAL across both versions.
    //
    // #494: today's multi-type reasoning goes through `block_level_shadow`, whose
    // candidate earlier setters are filtered by `match_blocks_overlap`, which requires
    // an EXACT same-criterion-type-set match. A bare `Match User alice` predecessor
    // (type-set {user}) is silently DROPPED as a candidate winner for a later
    // `Match User alice Address ...` block (type-set {user,address}), even though the
    // predecessor is unconditionally satisfied by every connection the later block
    // matches. This produces both a false positive (a later block that agrees with the
    // TRUE (predecessor) winner still gets flagged against the wrong, merely
    // type-set-identical, comparator) and a false negative (a later block that
    // genuinely differs from the dropped predecessor is never flagged at all).
    //
    // The fix (design LOCKED, not implemented by these tests): select earlier setters
    // STRUCTURALLY - `Match all` OR type_set(earlier) subset-or-equal type_set(later) -
    // rather than via `match_blocks_overlap`'s exact-set gate. When exactly one axis X
    // exists on which every selected setter differs from the later block (every other
    // axis is a setter no-op: either unconstrained by the setter, i.e. universe, or an
    // EXACT match of the later block's own restriction on that axis), the analysis
    // reduces to the shipped single-type region walk on X. Otherwise it DECLINES the
    // per-axis reduction and falls back to `block_level_shadow`, still using the
    // structurally-selected (not `match_blocks_overlap`-selected) earlier-setter set.
    //
    // CE1/CE2/CE3/CE4 below are RED against TODAY's code (verified via a scratch
    // `w07_diags` dump against this exact main-branch build before authoring these
    // tests): CE4 and CE3 are currently silent (false negatives); CE1 and CE2 currently
    // flag the WRONG (supernet) block while staying silent on the true shadow (both a
    // false positive and a false negative on the same fixture). CE6, the two-axis
    // DECLINE lock, and the type-outside-T (G3) lock are LOCKS: the scratch dump showed
    // today's block-level fallback already produces the CE-pinned correct answer on
    // those fixtures (via the pre-existing `Match all` short-circuit in
    // `match_blocks_overlap`, or via today's exact-type-set match happening to coincide
    // with the new structural selection, or via both today's and the new selection
    // excluding a type-outside-T predecessor identically) - these guard the fix against
    // REGRESSING an already-correct case, not against a currently-broken one.

    #[test]
    fn ce4_452_target_partition_flags_only_the_shadowed_subnet() {
        // #452's issue example. `User alice Address 10.1.0.0/16` yes / `User alice
        // Address 10.2.0.0/16` no / `User alice Address 10.0.0.0/8` yes: all three
        // blocks share the IDENTICAL {user,address} type-set (equal, not a proper
        // subset), so the reduction axis is `address` (every setter's `user`
        // restriction is the same literal `alice` as the later block's own, an exact
        // match = a no-op axis). Walking the address axis for the /8 block (line 6):
        // the /16-yes predecessor (line 1-2) consumes 10.1.0.0/16 of the /8 with an
        // AGREEING value; the /16-no predecessor (line 3-4) then wins the remaining
        // 10.2.0.0/16 sub-population with a DIFFERING value -> line 6 is a real
        // sub-population shadow. GROUND TRUTH (452-multitype-grounding.md CE4,
        // OpenSSH 9.9p1/8.0p1): addr=10.2.0.5 -> no (middle block wins); addr=10.1.0.5
        // -> yes; addr=10.3.0.5 -> yes. RED: TODAY's `match_blocks_overlap`-gated
        // block-level fallback finds no differing earlier winner here (verified: main
        // emits nothing on this fixture) since block-level compares only the FIRST
        // overlapping setter's value block-wide, not per sub-population, and this
        // shape needs a THIRD (partition) block to expose the gap the same way #409's
        // partition tests did for the single-type case.
        let d = w07_diags(
            "Match User alice Address 10.1.0.0/16\n    X11Forwarding yes\n\
             Match User alice Address 10.2.0.0/16\n    X11Forwarding no\n\
             Match User alice Address 10.0.0.0/8\n    X11Forwarding yes\n",
        );
        assert_eq!(
            d.len(),
            1,
            "only the /8 block's line is a genuine sub-population shadow"
        );
        assert_eq!(d[0].code, "sshd-W07");
        assert_eq!(d[0].severity, Severity::Warning);
        assert_eq!(
            d[0].line, 6,
            "the 10.2.0.0/16 sub-population of the /8 block really resolves to `no`"
        );
    }

    #[test]
    fn ce1_agreeing_subset_user_predecessor_flags_middle_not_supernet() {
        // #494's FP-guard shape. `User alice` yes (subset predecessor, type-set
        // {user} - a PROPER subset of the later blocks' {user,address}) / `User alice
        // Address 10.2.0.0/16` no / `User alice Address 10.0.0.0/8` yes. The bare-User
        // block is unconditionally satisfied by every alice connection (universe on
        // the address axis), so it is the FIRST winner for the entire /8 block's
        // population, agreeing with its `yes` - the /16 block's `no` is whole-population
        // DEAD, and the /8 block's `yes` is NOT a differing shadow (its value equals
        // the true winner). GROUND TRUTH (CE1, OpenSSH 9.9p1/8.0p1): user=alice,
        // addr=10.2.0.5 -> yes (bare-User block wins, NOT the /16 `no`); addr=10.5.0.5
        // and addr=10.1.0.5 -> yes; user=bob,addr=10.2.0.5 -> no (default, no block
        // applies). RED both ways: TODAY (confirmed via a scratch dump against this
        // exact fixture on main) flags line 6 - a LATENT FALSE POSITIVE, since
        // `match_blocks_overlap` drops the bare-User predecessor (type-set size 1 != 2)
        // and instead compares the /8 block against the /16 block, whose value happens
        // to differ - and stays silent on line 4, a FALSE NEGATIVE, since the /16
        // block's true (bare-User) shadower is invisible to the type-set-exact gate.
        let d = w07_diags(
            "Match User alice\n    X11Forwarding yes\n\
             Match User alice Address 10.2.0.0/16\n    X11Forwarding no\n\
             Match User alice Address 10.0.0.0/8\n    X11Forwarding yes\n",
        );
        assert_eq!(
            d.len(),
            1,
            "only the /16 block is a real shadow of the bare-User predecessor"
        );
        assert_eq!(d[0].code, "sshd-W07");
        assert_eq!(d[0].severity, Severity::Warning);
        assert_eq!(
            d[0].line, 4,
            "line 4 (/16 `no`) is shadowed; line 6 (/8 `yes`) is NOT (its value IS the true winner's)"
        );
    }

    #[test]
    fn ce2_subset_address_predecessor_constrains_the_differing_axis() {
        // The address-axis mirror of CE1: the subset predecessor restricts `address`
        // (not `user`), so the reduction axis is `user` this time. `Address
        // 10.2.0.0/16` yes (type-set {address}, subset) / `User alice Address
        // 10.2.0.0/16` no / `User alice Address 10.0.0.0/8` yes. The bare-Address
        // block is universe on `user` and its own address restriction EXACTLY equals
        // the /16 block's, so it wins the /16 block's entire population first with
        // `yes`; the /16 block's `no` (line 4) is dead. For the /8 block (line 6), the
        // bare-Address predecessor's 10.2.0.0/16 covers only PART of the /8's
        // population with the agreeing `yes`, and the /16 `no` block's own 10.2.0.0/16
        // region is already fully consumed by the earlier (source-order-first)
        // bare-Address block, so nothing differing remains uncovered - line 6 stays
        // clean. GROUND TRUTH (CE2, OpenSSH 9.9p1/8.0p1): user=alice,addr=10.2.0.5 ->
        // yes (bare-Address wins, block2's `no` is DEAD); addr=10.5.0.5 -> yes;
        // user=bob,addr=10.2.0.5 -> yes (bare-Address has no user restriction). RED:
        // TODAY (confirmed via scratch dump) flags line 6 instead (the same
        // supernet-vs-subnet FP as CE1) and stays silent on line 4.
        let d = w07_diags(
            "Match Address 10.2.0.0/16\n    X11Forwarding yes\n\
             Match User alice Address 10.2.0.0/16\n    X11Forwarding no\n\
             Match User alice Address 10.0.0.0/8\n    X11Forwarding yes\n",
        );
        assert_eq!(
            d.len(),
            1,
            "only the middle block is a real shadow of the bare-Address predecessor"
        );
        assert_eq!(d[0].code, "sshd-W07");
        assert_eq!(
            d[0].line, 4,
            "line 4 (`no`) is shadowed by the bare-Address block; line 6 (`yes`) is clean"
        );
    }

    #[test]
    fn ce3_differing_subset_user_predecessor_whole_population_shadow() {
        // The plain (non-partitioned) whole-population #494 miss: `Match User alice`
        // no / `Match User alice Address 10.0.0.0/8` yes. The bare-User predecessor is
        // universe on `address`, so it unconditionally wins EVERY alice connection the
        // later /8 block could also match, and its value (`no`) DIFFERS from the later
        // block's (`yes`) - a genuine, unqualified whole-population shadow: the later
        // `yes` never actually applies for any connection. GROUND TRUTH (CE3, OpenSSH
        // 9.9p1/8.0p1): user=alice,addr=10.2.0.5 -> no; user=alice,addr=192.168.1.1 ->
        // no (the /8 block's `yes` NEVER wins). RED: TODAY (confirmed via scratch
        // dump) is completely silent on this fixture - `match_blocks_overlap` excludes
        // the bare-User predecessor purely on type-set-size mismatch (1 vs 2), so no
        // candidate winner is ever considered for the later block.
        let d = w07_diags(
            "Match User alice\n    X11Forwarding no\n\
             Match User alice Address 10.0.0.0/8\n    X11Forwarding yes\n",
        );
        assert_eq!(
            d.len(),
            1,
            "the /8 block's `yes` is fully shadowed by the differing bare-User predecessor"
        );
        assert_eq!(d[0].line, 4);
    }

    #[test]
    fn ce6_match_all_agreeing_interleave_stays_correct_regression_lock() {
        // LOCK, not RED: `Match all` yes / `User alice Address 10.2.0.0/16` no /
        // `User alice Address 10.0.0.0/8` yes. `Match all` is ALWAYS satisfied, so it
        // is the unconditional first winner of BOTH later blocks' entire populations:
        // the /16 block's `no` (line 4) is a real dead shadow, and the /8 block's
        // `yes` (line 6) agrees with the `Match all` winner everywhere, so it is NOT a
        // differing shadow. GROUND TRUTH (CE6, OpenSSH 9.9p1/8.0p1): every probe ->
        // yes (`Match all` wins unconditionally). A scratch `w07_diags` dump against
        // this EXACT fixture on unmodified main (session 7d-p1, before any #494 fix)
        // already produces `{line 4}` and nothing else: `match_blocks_overlap`
        // special-cases `Match all` as an unconditional overlap regardless of
        // criterion-type-set size, so `Match all` already qualifies as a candidate
        // winner for the /8 block today (via the pre-existing `is_unconditional_match_all`
        // short-circuit, not the new structural subset selection), and it is the FIRST
        // (and therefore decisive) candidate in source order for both later blocks.
        // This test is a non-regression LOCK for the #494 fix: it must not disturb an
        // interleave that a `Match all` predecessor already gets right.
        let d = w07_diags(
            "Match all\n    X11Forwarding yes\n\
             Match User alice Address 10.2.0.0/16\n    X11Forwarding no\n\
             Match User alice Address 10.0.0.0/8\n    X11Forwarding yes\n",
        );
        assert_eq!(d.len(), 1, "only the /16 block is shadowed by `Match all`");
        assert_eq!(
            d[0].line, 4,
            "line 4 (/16 `no`) is shadowed; line 6 (/8 `yes`) agrees with the `Match all` winner"
        );
    }

    #[test]
    fn accepted_fn_two_differing_axes_declines_to_todays_block_level_result() {
        // LOCK: the accepted-FN DECLINE case. `User alice Address 10.1.0.0/16` yes /
        // `User alice,bob Address 10.0.0.0/8` no. The earlier block's type-set
        // {user,address} equals the later block's, so it is structurally selected
        // either way (old `match_blocks_overlap` or the new subset-or-equal rule).
        // But NEITHER axis is a setter no-op: on `user`, the earlier block's {alice}
        // does NOT cover the later block's {alice,bob} (bob is missing); on `address`,
        // the earlier block's 10.1.0.0/16 does NOT cover the later block's wider
        // 10.0.0.0/8. No single axis exists on which the earlier setter is neutral
        // everywhere else, so the design DECLINES the per-axis reduction and falls
        // back to `block_level_shadow` - which still uses the structurally-selected
        // earlier-setter set (here, the same single candidate either selection method
        // would pick), so the coarse whole-block comparison (`yes` != `no`) still
        // fires. This is an ACCEPTED simplification, not a precision loss vs today:
        // for user=alice,addr=10.1.0.5 (the only connection where BOTH blocks'
        // criteria are simultaneously satisfiable), the earlier block genuinely wins
        // and the later `no` really is dropped, so flagging line 4 is correct; the
        // decline only means finer PARTIAL-shadow reasoning across the mismatched
        // bob/10.0.0.0/8 remainder is not attempted (a documented v0.3-style accepted
        // FN, not a false positive). A scratch `w07_diags` dump against this exact
        // fixture on unmodified main already produces `{line 4}` (both blocks share an
        // identical 2-type set, so today's `match_blocks_overlap` already selects the
        // earlier block as a candidate and `block_level_shadow` finds the differing
        // value) - this locks that the #494 fix's DECLINE fallback must reproduce that
        // same answer, not silently drop it in the name of two-axis conservatism.
        // GROUNDING CLASS: inference from CE4 semantics + observed-vs-main (no
        // transcript-pinned CE entry for this exact fixture).
        let d = w07_diags(
            "Match User alice Address 10.1.0.0/16\n    X11Forwarding yes\n\
             Match User alice,bob Address 10.0.0.0/8\n    X11Forwarding no\n",
        );
        assert_eq!(
            d.len(),
            1,
            "the DECLINE fallback still reproduces today's whole-block comparison"
        );
        assert_eq!(d[0].line, 4);
    }

    #[test]
    fn g4_repeated_negated_address_does_not_block_a_whole_population_shadow() {
        // RED: G4's guard ("repeated CIDR/port criteria carrying `!` in L decline")
        // must decline only the PER-AXIS reduction attempt, not the coarse
        // `block_level_shadow` fallback. `Match User alice` yes (subset predecessor,
        // universe on `address`) / `Match User alice Address 10.0.0.0/8 Address
        // 10.0.0.0/8,!10.5.0.0/16` no - the later block repeats the `Address` type
        // with a negated occurrence (AND-folds to 10.0.0.0/8 minus 10.5.0.0/16), which
        // trips G4 and declines the fine-grained per-axis carve. But the bare-User
        // predecessor is universe on `address` regardless of what that AND-folded
        // region actually is, so it unconditionally wins the ENTIRE later block's
        // population (any alice connection, whatever its address) with a DIFFERING
        // value - a whole-population shadow the safe block-level DECLINE path must
        // still catch (structurally selecting the bare-User block as a subset
        // predecessor, exactly as CE3 does, independent of L's own repeated-negation
        // detail). Semantically identical to CE3 with an irrelevant repeated-negated
        // Address decoration on the later block. RED: TODAY (confirmed via scratch
        // dump against this exact fixture on main) is silent - `match_blocks_overlap`
        // excludes the bare-User predecessor on type-set-size mismatch (as in CE3) AND
        // its separate repeated-negation cross-occurrence guard would independently
        // suppress overlap even if the sizes matched.
        // GROUNDING CLASS: inference from CE3 semantics + observed-vs-main (no
        // transcript-pinned CE entry for this exact fixture).
        let d = w07_diags(
            "Match User alice\n    X11Forwarding yes\n\
             Match User alice Address 10.0.0.0/8 Address 10.0.0.0/8,!10.5.0.0/16\n    \
             X11Forwarding no\n",
        );
        assert_eq!(
            d.len(),
            1,
            "declining the per-axis carve must not suppress a real whole-population shadow"
        );
        assert_eq!(d[0].line, 4);
    }

    #[test]
    fn g4_repeated_negated_address_agreeing_value_stays_clean() {
        // LOCK, pairs with the RED case directly above: same repeated-negated later
        // block shape, but the subset predecessor's value AGREES (`no` both times).
        // Whichever earlier-setter set G4's DECLINE fallback uses, an agreeing value
        // can never produce a differing-value shadow, so this must stay clean both
        // before and after the #494 fix - it locks that G4's guard does not
        // accidentally FABRICATE a flag out of the newly-structurally-included subset
        // predecessor when there is nothing to shadow. TODAY (confirmed via scratch
        // dump) is already silent on this fixture (for the unrelated reason that the
        // predecessor is excluded entirely), so this also guards against a regression
        // where the #494 fix's broader earlier-setter inclusion starts comparing
        // against the wrong (block-level, non-region) value and false-fires on
        // agreement.
        // GROUNDING CLASS: inference from CE3 semantics (agreeing-value variant) +
        // observed-vs-main (no transcript-pinned CE entry for this exact fixture).
        assert!(
            w07_diags(
                "Match User alice\n    X11Forwarding no\n\
                 Match User alice Address 10.0.0.0/8 Address 10.0.0.0/8,!10.5.0.0/16\n    \
                 X11Forwarding no\n",
            )
            .is_empty(),
            "an agreeing subset predecessor never shadows, regardless of L's negated repeat"
        );
    }

    #[test]
    fn g3_earlier_type_outside_t_is_ignored_entirely() {
        // LOCK: design guard G3, "earlier setters with a type OUTSIDE T are ignored".
        // `Match User alice Host web.corp` yes (type-set {user,host}) / `Match User
        // alice Address 10.0.0.0/8` no (type-set {user,address}). `host` is present in
        // the earlier block but ABSENT from the later block's type-set T={user,address},
        // so {user,host} is NOT a subset-or-equal of T (host is outside T) - the
        // earlier block is excluded from structural selection entirely, exactly the
        // same conservative v0.3 CROSS-type posture `cross_type_user_and_group_do_not_flag_w07`
        // already locks for a fully-disjoint type pair (#400): a static linter cannot
        // resolve whether a connection's client hostname happens to equal `web.corp`
        // without live DNS/NSS-style resolution, so the pair is left conservatively
        // clean rather than guessed at. TODAY (confirmed via scratch dump) is already
        // silent here too - `match_blocks_overlap` also requires an identical type-set,
        // so a {user,host} vs {user,address} pair fails its size/key check the same
        // way. This locks that #494's structural subset-or-equal rule does not widen
        // to "any SHARED type overlaps", which would incorrectly let the outside-T
        // `host` criterion leak into the reduction.
        // GROUNDING CLASS: inference from CE5 field-absent semantics + the #400
        // cross-type contract + observed-vs-main (no transcript-pinned CE entry for
        // this exact fixture).
        assert!(
            w07_diags(
                "Match User alice Host web.corp\n    X11Forwarding yes\n\
                 Match User alice Address 10.0.0.0/8\n    X11Forwarding no\n",
            )
            .is_empty(),
            "a type OUTSIDE the later block's type-set is ignored, not treated as overlap"
        );
    }

    #[test]
    fn ce7_disjoint_one_axis_nested_other_axis_stays_clean() {
        // LOCK (barrier-review strengthening, NEEDS_REWORK round 1): the per-type
        // co-satisfiability gate. `User alice Address 10.1.0.0/16` yes / `User bob
        // Address 10.0.0.0/8` no: the two blocks share the identical {user,address}
        // type-set and are NESTED on the address axis (10.1.0.0/16 inside
        // 10.0.0.0/8) but DISJOINT on the user axis (alice vs bob), so NO single
        // connection can ever satisfy both blocks at once and the later `no` (line
        // 4) is never shadowed. Expected W07 diag set: EMPTY. GROUND TRUTH (CE7,
        // 452-multitype-grounding.md, `sshd -T -C` OpenSSH 9.9p1): user=bob,
        // addr=10.1.0.5 -> no and user=bob,addr=10.5.0.5 -> no (the later block wins
        // its own population; the alice block never applies to bob); user=alice,
        // addr=10.1.0.5 -> yes (block 1); user=alice,addr=10.5.0.5 -> no (default;
        // NEITHER block matches). This kills the wrong impl the impl-blind barrier
        // adversary constructed: a per-axis walk that folds subset/same-set earlier
        // setters into a single-axis region walk but DROPS the per-type
        // co-satisfiability gate (today enforced by `match_blocks_overlap`'s
        // per-shared-type `.all()` conjunction) would see only the nested address
        // axis, treat the alice block as a differing earlier winner for part of the
        // /8, and FP-flag line 4. The neighboring fixtures do not discriminate that
        // impl: `multi_type_block_level_fallback_flags_and_disjoint_is_clean`'s
        // disjoint pair is disjoint on BOTH axes, and the two-axis DECLINE fixture
        // above expects {line 4}, which a naive per-axis walk coincidentally also
        // produces. Main today is clean on this fixture (verified empirically: this
        // assertion passes against the UNMODIFIED production code in this worktree -
        // today's `match_blocks_overlap` returns no-overlap via its disjoint-user
        // conjunct); the #494 structural subset selection must PRESERVE a per-type
        // co-satisfiability check, not trade it away for the axis walk.
        assert!(
            w07_diags(
                "Match User alice Address 10.1.0.0/16\n    X11Forwarding yes\n\
                 Match User bob Address 10.0.0.0/8\n    X11Forwarding no\n",
            )
            .is_empty(),
            "disjoint on one axis (user) means NO co-satisfaction, however nested the other axis is"
        );
    }

    // ---- Mutation-survivor killers for the multi-type reduction (#452 ATL round) ----
    // The post-GREEN mutation gate on the multi-type reduction code left survivors
    // whose common cause was one-sided axis coverage: every CE1-CE7 fixture walks the
    // ADDRESS axis with USER as the neutral axis. The fixtures below rotate the walk
    // axis (CE8: user walk) and the neutral axis (CE10: address cover; CE9prime:
    // localport), and pin the guard seams (exact_name_set, G4) from both sides.
    // Oracle-pinned fixtures cite their CE label in
    // /home/runner/rulesteward-docs/research-notes/452-multitype-grounding.md
    // ("Mutation-survivor fixture shapes"); the rest carry an explicit GROUNDING
    // CLASS inference note, and EVERY fixture's current-impl output was observed via
    // a scratch `w07_diags` dump before being pinned here.

    #[test]
    fn ce8_user_axis_walk_flags_partition_and_all_agreeing_is_clean() {
        // CE8 (452-multitype-grounding.md, `sshd -T -C` OpenSSH 9.9p1): the USER-axis
        // walk. `User alice Address 10/8` yes / `User bob Address 10/8` no /
        // L=`User alice,bob,carol Address 10/8` yes. The neutral axis is ADDRESS
        // (every setter's /8 exactly equals L's /8), so the reduction walks USER:
        // alice is consumed by the agreeing block 1; bob is won by the DIFFERING
        // block 2 -> L (line 6) is a real sub-population shadow. Oracle: bob -> no,
        // alice -> yes, carol -> yes.
        // KILLS (multitype_names_axis_shadow): the `-> false` body replacement and
        // the `"user"|"group"|"host"` walk-arm deletion in multitype_axis_shadow
        // (either one degrades to the block-level fallback / never-flag, whose first
        // structurally-selected setter block 1 AGREES with L -> no flag, RED vs the
        // expected flag).
        let d = w07_diags(
            "Match User alice Address 10.0.0.0/8\n    X11Forwarding yes\n\
             Match User bob Address 10.0.0.0/8\n    X11Forwarding no\n\
             Match User alice,bob,carol Address 10.0.0.0/8\n    X11Forwarding yes\n",
        );
        assert_eq!(d.len(), 1, "the bob sub-population shadow flags L");
        assert_eq!(d[0].code, "sshd-W07");
        assert_eq!(d[0].severity, Severity::Warning);
        assert_eq!(d[0].line, 6, "line 6 is shadowed for bob by block 2's `no`");
        // ALL-AGREEING variant: identical partition structure, every value `yes`.
        // Nothing behaviorally differs anywhere, so the walk must stay silent.
        // GROUNDING CLASS: inference from CE8 (value-agreement corollary; mirrors
        // `partition_all_same_value_is_clean`) + observed-vs-main.
        // KILLS (multitype_names_axis_shadow): `-> true` (flags the clean fixture),
        // `&&` -> `||` at the member/winner conjunction (a later-member candidate
        // alone would satisfy the disjunction), and `!=` -> `==` at the winner-value
        // comparison (an AGREEING winner would flag).
        assert!(
            w07_diags(
                "Match User alice Address 10.0.0.0/8\n    X11Forwarding yes\n\
                 Match User bob Address 10.0.0.0/8\n    X11Forwarding yes\n\
                 Match User alice,bob,carol Address 10.0.0.0/8\n    X11Forwarding yes\n",
            )
            .is_empty(),
            "an all-agreeing user-axis partition drops nothing"
        );
    }

    #[test]
    fn ce10_address_cover_neutral_axis_flags_user_walk() {
        // CE10 (452-multitype-grounding.md, `sshd -T -C` OpenSSH 9.9p1): the neutral
        // axis proven by a PROPER CIDR COVER, not exact equality. `User alice
        // Address 10.0.0.0/8` yes / `User bob Address 10.0.0.0/8` no / L=`User
        // alice,bob Address 10.2.0.0/16` yes. Each setter's /8 strictly COVERS L's
        // /16 (cidr_set_difference(L, setter) empty), so ADDRESS is neutral and USER
        // is the walk axis; bob is won by the differing block 2 -> FLAG L (line 6).
        // Oracle: bob@10.2.0.5 -> no, alice@10.2.0.5 -> yes.
        // KILLS (axis_is_noop): the `"address"|"localaddress"` arm deletion - the
        // fallthrough `_ => false` would make ADDRESS never-neutral, so no unique
        // axis exists, the reduction declines, and the fallback's first setter
        // (block 1, agreeing `yes`) stays silent, RED vs the expected flag. The
        // proper-cover shape (unlike CE8's equal /8s) also pins the difference-
        // emptiness direction: covering must be judged setter-covers-L, not
        // set-equality.
        let d = w07_diags(
            "Match User alice Address 10.0.0.0/8\n    X11Forwarding yes\n\
             Match User bob Address 10.0.0.0/8\n    X11Forwarding no\n\
             Match User alice,bob Address 10.2.0.0/16\n    X11Forwarding yes\n",
        );
        assert_eq!(d.len(), 1, "the bob sub-population shadow flags L");
        assert_eq!(
            d[0].line, 6,
            "the /8-covers-/16 neutral address axis reduces to the user walk"
        );
    }

    #[test]
    fn ce9prime_localport_neutral_axis_flags_address_walk() {
        // CE9prime (452-multitype-grounding.md, `sshd -T -C` OpenSSH 9.9p1): the
        // LOCALPORT arm of axis_is_noop as the NEUTRAL axis. CE4's address partition
        // at a constant `LocalPort 22`: `Address 10.1.0.0/16 LocalPort 22` yes /
        // `Address 10.2.0.0/16 LocalPort 22` no / L=`Address 10.0.0.0/8 LocalPort
        // 22` yes. Every setter's port singleton {22} equals L's, so LOCALPORT is
        // neutral and the walk runs on ADDRESS: block 1 agrees and consumes
        // 10.1.0.0/16, block 2 differs and wins 10.2.0.0/16 -> FLAG L (line 6).
        // Oracle: 10.2.0.5@22 -> no, 10.1.0.5@22 -> yes, 10.3.0.5@22 -> yes,
        // 10.2.0.5@2222 -> no (default; no block applies).
        // KILLS (axis_is_noop): the `"localport"` arm deletion - `_ => false` makes
        // LOCALPORT never-neutral, no unique axis remains, and the fallback's
        // agreeing first setter goes silent, RED vs the expected flag.
        let d = w07_diags(
            "Match Address 10.1.0.0/16 LocalPort 22\n    X11Forwarding yes\n\
             Match Address 10.2.0.0/16 LocalPort 22\n    X11Forwarding no\n\
             Match Address 10.0.0.0/8 LocalPort 22\n    X11Forwarding yes\n",
        );
        assert_eq!(
            d.len(),
            1,
            "the 10.2.0.0/16 sub-population shadow flags L at constant LocalPort"
        );
        assert_eq!(d[0].line, 6);
    }

    #[test]
    fn ce11_user_proper_superset_neutral_axis_flags_address_walk() {
        // CE11 (452-multitype-grounding.md, `sshd -T -C` OpenSSH 9.9p1): the USER
        // neutral axis proven by PROPER literal-set superset, not equality. `User
        // alice,bob Address 10.1.0.0/16` yes / `User alice,bob Address 10.2.0.0/16`
        // no / L=`User alice Address 10.0.0.0/8` yes. Each setter's {alice,bob}
        // strictly contains L's {alice} (exact_name_set containment), so USER is
        // neutral and the ADDRESS walk finds the CE4 partition -> FLAG L (line 6).
        // Oracle: alice@10.2.0.5 -> no, @10.1.0.5 -> yes, @10.3.0.5 -> yes.
        // KILLS (exact_name_set): the `-> None` return replacement (None makes the
        // user axis unprovable -> not neutral -> no unique axis -> the agreeing
        // fallback goes silent, RED vs the expected flag). The Some(garbage)
        // replacements are killed by the PROPER-SUBSET decline fixture below (they
        // make containment hold trivially, so they pass here).
        let d = w07_diags(
            "Match User alice,bob Address 10.1.0.0/16\n    X11Forwarding yes\n\
             Match User alice,bob Address 10.2.0.0/16\n    X11Forwarding no\n\
             Match User alice Address 10.0.0.0/8\n    X11Forwarding yes\n",
        );
        assert_eq!(
            d.len(),
            1,
            "the proper-superset user axis is neutral; the address walk flags L"
        );
        assert_eq!(d[0].line, 6);
    }

    #[test]
    fn proper_subset_user_on_neutral_axis_is_not_a_cover_declines_clean() {
        // The reverse of CE11: the setters' user set {alice} is a PROPER SUBSET of
        // L's {alice,bob} - NOT a cover - so the user axis is NOT neutral, and the
        // address axis is not either (10.1.0.0/16 does not cover L's /8): a two-axis
        // shape that DECLINES to the block-level fallback, whose first structurally-
        // selected setter (block 1) AGREES with L -> entirely clean. sshd truth
        // (alice@10.2.0.5 -> block 2 `no` while L says yes) makes this a genuinely
        // shadowed sub-population, i.e. a documented ACCEPTED FN of the locked
        // one-axis design (the same class the two-axis DECLINE lock above pins).
        // GROUNDING CLASS: inference from the locked design's neutrality rule
        // (subset-or-equal cover required) + observed-vs-main; no transcript-pinned
        // CE entry for this exact fixture.
        // KILLS (exact_name_set): the `-> Some(garbage)` return replacements
        // (Some(BTreeSet::new()) / Some(junk-literal)): both make BOTH sides of the
        // containment check the same garbage set, so `l.is_subset(e)` holds
        // trivially, the user axis is wrongly declared neutral, the address walk
        // runs, and block 2's differing `no` FP-flags line 6 on a fixture the design
        // REQUIRES to stay clean.
        assert!(
            w07_diags(
                "Match User alice Address 10.1.0.0/16\n    X11Forwarding yes\n\
                 Match User alice Address 10.2.0.0/16\n    X11Forwarding no\n\
                 Match User alice,bob Address 10.0.0.0/8\n    X11Forwarding yes\n",
            )
            .is_empty(),
            "a proper-subset user set does not cover L; two-axis -> decline -> agreeing fallback"
        );
    }

    #[test]
    fn negation_in_neutral_axis_user_list_is_not_provably_neutral_declines_clean() {
        // The "unprovable is not neutral" rule for name lists: the setters carry a
        // NEGATED entry (`alice,!bob`) on the would-be neutral USER axis. The
        // negation is semantically redundant (the positive list is alice-only), but
        // exact containment is only computed for pure literal sets - a negation (or
        // glob) makes the axis unprovable, so the reduction declines and the
        // agreeing first setter keeps the fixture clean. sshd truth (alice@10.2.0.5
        // -> block 2 `no` vs L's yes) again makes this an ACCEPTED FN of the locked
        // conservative design, exactly like the proper-subset fixture above.
        // GROUNDING CLASS: inference from the locked design's no-glob/no-negation
        // neutrality guard + observed-vs-main; no transcript-pinned CE entry.
        // KILLS (exact_name_set): `||` -> `&&` in the reject condition
        // (`starts_with('!') || contains(*/?)`): under `&&` a negation-only value
        // like `!bob` is no longer rejected and is kept as a LITERAL, so
        // {alice,!bob} "contains" L's {alice}, the user axis is wrongly declared
        // neutral, the address walk runs, and block 2 FP-flags line 6.
        assert!(
            w07_diags(
                "Match User alice,!bob Address 10.1.0.0/16\n    X11Forwarding yes\n\
                 Match User alice,!bob Address 10.2.0.0/16\n    X11Forwarding no\n\
                 Match User alice Address 10.0.0.0/8\n    X11Forwarding yes\n",
            )
            .is_empty(),
            "a negated entry on the neutral axis is not provably neutral -> decline -> clean"
        );
    }

    #[test]
    fn g4_decline_beats_walk_when_l_repeats_negated_address_bare_user_setters() {
        // G4 from the walk's side: L repeats the Address type with a negated
        // occurrence (`10.0.0.0/8` AND `10.0.0.0/8,!10.2.0.0/16`), which DECLINES
        // the per-axis reduction entirely, while the earlier setters are bare
        // single-type User blocks ({user} is a proper subset of L's {user,address},
        // and they do not constrain the negated address axis at all - so they stay
        // structurally SELECTED, unlike CE12's setters). The DECLINE fallback's
        // first setter (`User alice` yes) agrees with L -> clean. sshd truth
        // (bob@10.1.0.5 -> block 2 `no` while L says yes) makes this an ACCEPTED FN
        // of G4's conservatism. GROUNDING CLASS: inference from CE12's
        // addr_match_list negation grounding + the locked G4 guard +
        // observed-vs-main; no transcript-pinned CE entry for this exact fixture.
        // KILLS (later_has_repeated_negated_region): `-> false` (G4 disabled, the
        // user-axis walk runs - the setters are universe on address, so USER is the
        // unique axis - and block 2's differing `no` wins the bob witness,
        // FP-flagging line 6 where the design requires the decline). CE12 itself
        // CANNOT kill this mutant: its setters constrain the negated address axis
        // and are already excluded by type_co_satisfiable's negation guard, so both
        // the real impl and the mutant see zero setters there.
        assert!(
            w07_diags(
                "Match User alice\n    X11Forwarding yes\n\
                 Match User bob\n    X11Forwarding no\n\
                 Match User alice,bob,carol Address 10.0.0.0/8 Address 10.0.0.0/8,!10.2.0.0/16\n    \
                 X11Forwarding yes\n",
            )
            .is_empty(),
            "a repeated negated Address in L declines the walk; the agreeing fallback stays clean"
        );
    }

    #[test]
    fn single_negated_address_occurrence_does_not_trip_g4_walk_still_flags() {
        // G4's boundary from the other side: L's Address type appears ONCE, carrying
        // a negation (`10.0.0.0/8,!10.5.0.0/16`). G4 requires a REPEATED (>= 2
        // occurrences) negated CIDR/port type - a single negated occurrence has an
        // exact region (cidr_list_set already carves the negation), so the walk
        // proceeds: user is neutral (equal {alice}), the address walk carves block
        // 1's agreeing 10.1.0.0/16 out of (10/8 minus 10.5/16), and block 2's
        // differing `no` wins 10.2.0.0/16 -> FLAG L (line 6). This mirrors the
        // single-type guard's boundary pinned by `single_region_type_pinned_directly`
        // (a SINGLE negated instance stays a region type; only a repeat trips it).
        // GROUNDING CLASS: inference from CE4 + the #403 negation-aware carve
        // semantics (both transcript-grounded classes) + observed-vs-main; no
        // transcript-pinned CE entry for this exact fixture.
        // KILLS (later_has_repeated_negated_region): `>=` -> `<` at the occurrence
        // count and `&&` -> `||` joining it (both make a SINGLE negated occurrence
        // trip G4 -> decline -> the agreeing fallback goes silent, RED vs the
        // expected flag).
        let d = w07_diags(
            "Match User alice Address 10.1.0.0/16\n    X11Forwarding yes\n\
             Match User alice Address 10.2.0.0/16\n    X11Forwarding no\n\
             Match User alice Address 10.0.0.0/8,!10.5.0.0/16\n    X11Forwarding yes\n",
        );
        assert_eq!(
            d.len(),
            1,
            "a single negated Address occurrence keeps the exact walk; the partition flags"
        );
        assert_eq!(d[0].line, 6);
    }

    #[test]
    fn ce12_negation_only_address_occurrence_matches_nothing_entirely_clean() {
        // CE12 (452-multitype-grounding.md, `sshd -T -C` OpenSSH 9.9p1): a
        // NEGATION-ONLY Address occurrence. sshd's addr_match_list lets a negated
        // entry only VETO - it never positively matches - so L's second occurrence
        // `Address !10.2.0.0/16` matches NO address, and the AND across occurrences
        // makes L match NOTHING. Oracle: alice@10.3.0.5 -> no (the DEFAULT: L does
        // not apply even though 10.3.0.5 is in 10/8 and not vetoed!), @10.2.0.5 ->
        // no (block 2), @10.1.0.5 -> yes (block 1). L is self-dead, not shadowed,
        // and blocks 1-2 are mutually disjoint -> the fixture is ENTIRELY CLEAN.
        // W07's guard stack composes to that verdict: G4 declines the walk (repeated
        // negated Address) and type_co_satisfiable's negation guard excludes both
        // earlier setters (each constrains the negated address axis), so the
        // fallback has no candidates. LOCKS the whole conservative composition; a
        // wrong impl that computes L's region negation-BLIND (as the full 10/8)
        // walks the partition and FP-flags line 6 via block 2.
        assert!(
            w07_diags(
                "Match User alice Address 10.1.0.0/16\n    X11Forwarding yes\n\
                 Match User alice Address 10.2.0.0/16\n    X11Forwarding no\n\
                 Match User alice Address 10.0.0.0/8 Address !10.2.0.0/16\n    X11Forwarding yes\n",
            )
            .is_empty(),
            "a negation-only Address occurrence makes L match nothing; nothing to flag anywhere"
        );
    }

    #[test]
    fn lenient_multiport_localport_walk_flags_partition_and_all_agreeing_is_clean() {
        // TOOL-BEHAVIOR LOCK on an sshd-INVALID config (NOT sshd semantics): sshd's
        // a2port REJECTS comma-list LocalPort ("Invalid LocalPort '22,2222' on Match
        // line", rc 255 - CE9, 452-multitype-grounding.md), so no sshd-loadable
        // config reaches the multi-type LOCALPORT WALK: on valid singleton ports
        // every structurally-selected setter is provably neutral on the port axis
        // (universe or equal singleton), so localport can never be the UNIQUE
        // reduction axis and the walk is sshd-domain-unreachable. RuleSteward's
        // parser, however, is LENIENT: parse_criteria comma-splits Match values
        // generically, so `LocalPort 22,2222` parses as the port set {22, 2222} and
        // W07 still runs. The locked tool behavior is CONSISTENCY with the CIDR
        // walk: treat the lenient-parsed port set exactly like an address set
        // (agreeing setter consumes its ports, differing setter wins the remainder).
        // GROUNDING CLASS: tool-determinism lock (lenient-parse domain) + CE9 for
        // the sshd-invalidity of the fixture itself + observed-vs-main; deliberately
        // NOT a claim about sshd behavior (sshd refuses to load this config).
        // KILLS (multitype_port_axis_shadow + the `"localport"` walk-arm in
        // multitype_axis_shadow): the walk-arm deletion and `-> false` body
        // replacement (fallback/never-flag: the agreeing first setter goes silent,
        // RED vs the expected flag) via the partition fixture; `-> true`, the
        // winner-value `!=` -> `==`, and the region/winner `&&` -> `||` via the
        // all-agreeing fixture (each would flag a fixture with nothing to drop).
        let d = w07_diags(
            "Match User alice,bob LocalPort 22\n    X11Forwarding yes\n\
             Match User alice,bob LocalPort 2222\n    X11Forwarding no\n\
             Match User alice LocalPort 22,2222\n    X11Forwarding yes\n",
        );
        assert_eq!(
            d.len(),
            1,
            "the lenient-parsed port partition walks like CIDR: block 2 wins port 2222"
        );
        assert_eq!(d[0].line, 6);
        // ALL-AGREEING variant: same lenient-parsed shape, every value `yes`.
        assert!(
            w07_diags(
                "Match User alice,bob LocalPort 22\n    X11Forwarding yes\n\
                 Match User alice,bob LocalPort 2222\n    X11Forwarding yes\n\
                 Match User alice LocalPort 22,2222\n    X11Forwarding yes\n",
            )
            .is_empty(),
            "an all-agreeing lenient-parsed port partition drops nothing"
        );
        // UNIVERSE-SETTER variant: block 2 is a bare `Match User alice,bob` block
        // (no LocalPort criterion at all), so on the walked port axis it is
        // UNIVERSE - it must win every port block 1's agreeing {22} did not consume
        // (here the lenient-parsed 2222) with its differing `no` -> FLAG L (line 6).
        // Same tool-determinism grounding class as the partition fixture above.
        // KILLS (multitype_port_axis_shadow): `||` -> `&&` in the universe-branch
        // condition (`is_unconditional_match_all(earlier) || !constrains_axis`):
        // under `&&` a non-`Match all` setter without a port criterion takes the
        // set-intersection branch with an EMPTY port set, wins NOTHING instead of
        // everything, and the flag is silently lost (the mutation gate's one
        // first-round survivor, w07.rs:676).
        let d = w07_diags(
            "Match User alice,bob LocalPort 22\n    X11Forwarding yes\n\
             Match User alice,bob\n    X11Forwarding no\n\
             Match User alice LocalPort 22,2222\n    X11Forwarding yes\n",
        );
        assert_eq!(
            d.len(),
            1,
            "a setter without a port criterion is UNIVERSE on the walked port axis"
        );
        assert_eq!(d[0].line, 6, "the universe setter wins port 2222 with `no`");
    }

    // ---- Multi-type NOBODY-block FP locks (#452 round 3, impl-aware adversary) ----
    // The #452 rewrite routed multi-type later blocks off `match_blocks_overlap`
    // (onto the structural `multitype_earlier_setters` selection) and thereby DROPPED
    // its `block_matches_nobody(later)` short-circuit: a multi-type later block whose
    // AND-ed criteria admit NO connection is now FP-flagged by both the reduction
    // walk and the DECLINE fallback, where pre-#452 main was clean. Adversary-
    // grounded (impl-aware review round 3): `sshd_config(5)` says a Match line's
    // criteria are "used only if ALL of the criteria on the line are satisfied" (a
    // repeated type is an intersection), and live `sshd -T -C` on OpenSSH 9.9p1 with
    // `Match all X11Forwarding yes` / `Match User alice User bob Address 10.0.0.0/8
    // X11Forwarding no` yields `x11forwarding yes` for BOTH user=alice and user=bob
    // probes - the nobody block's `no` never applies to anyone, so nothing is ever
    // shadowed. The existing single-type nobody locks
    // (`repeated_same_type_criteria_are_and_match_nobody_is_clean`,
    // `match_all_does_not_shadow_a_nobody_block_is_clean`,
    // `block_matches_nobody_pinned_directly`) cover only single-type later blocks;
    // the four tests below close the MULTI-TYPE gap. All four are RED against the
    // current impl (each emits a line-4 FP, verified via a scratch `w07_diags` dump
    // against this exact build before pinning); the implementer applies the
    // `block_matches_nobody(later)` guard to make them green.

    #[test]
    fn multi_type_nobody_block_repeated_user_is_not_a_shadowee_fallback_clean() {
        // Adversary-grounded (sshd -T -C 9.9p1, sshd_config(5) AND-of-criteria; the
        // exact oracle fixture quoted in the section comment above): the later block
        // AND-s `User alice` with `User bob` - no user is both - so it matches
        // NOBODY, and `Match all`'s differing `yes` has nothing to drop. This is the
        // DECLINE-fallback route: L's type-set {user,address} has TWO qualifying
        // axes for the always-neutral `Match all` setter (no unique axis), so the
        // coarse block-level comparison runs and currently FP-flags line 4 against
        // the `Match all` winner. The multi-type analogue of
        // `match_all_does_not_shadow_a_nobody_block_is_clean`.
        assert!(
            w07_diags(
                "Match all\n    X11Forwarding yes\n\
                 Match User alice User bob Address 10.0.0.0/8\n    X11Forwarding no\n",
            )
            .is_empty(),
            "a multi-type block whose repeated User criteria AND to nobody is never a shadowee"
        );
    }

    #[test]
    fn multi_type_nobody_block_repeated_user_is_not_a_shadowee_walk_clean() {
        // The same repeated-User nobody block, but with a bare-Address predecessor
        // so the reduction finds a UNIQUE axis and takes the WALK route instead of
        // the fallback: the setter is universe on `user` (it does not constrain it)
        // and non-covering on `address` (10.1.0.0/16 does not cover L's /8), so
        // `address` is the unique reduction axis and the CIDR walk currently hands
        // the setter's differing `no` the 10.1.0.0/16 sub-population - an FP on
        // line 4, because L matches NOBODY (User alice AND User bob is impossible)
        // and owns no population to be carved. Adversary-grounded (same
        // sshd_config(5) AND-of-criteria + sshd -T -C 9.9p1 grounding as above);
        // proves the nobody guard must sit ABOVE the axis walk, not only in the
        // fallback.
        assert!(
            w07_diags(
                "Match Address 10.1.0.0/16\n    X11Forwarding no\n\
                 Match User alice User bob Address 10.0.0.0/8\n    X11Forwarding yes\n",
            )
            .is_empty(),
            "the axis walk must not carve sub-populations out of a block that matches nobody"
        );
    }

    #[test]
    fn multi_type_nobody_block_disjoint_repeated_address_is_clean() {
        // Nobody via disjoint repeated CIDR on a MULTI-TYPE block: `Address
        // 10.0.0.0/8` AND `Address 192.168.0.0/16` intersect to the empty set, so
        // the block matches no connection and `Match all`'s differing `yes` drops
        // nothing. The multi-type analogue of the Address arm of
        // `block_matches_nobody_pinned_directly` /
        // `repeated_disjoint_address_criteria_match_nobody_is_clean` (which pin the
        // single-type path). Adversary-grounded (sshd_config(5) AND-of-criteria;
        // same round-3 finding); currently FP-flags line 4 via the fallback.
        assert!(
            w07_diags(
                "Match all\n    X11Forwarding yes\n\
                 Match User alice Address 10.0.0.0/8 Address 192.168.0.0/16\n    \
                 X11Forwarding no\n",
            )
            .is_empty(),
            "disjoint repeated Address criteria AND to nobody; the multi-type block cannot shadow"
        );
    }

    #[test]
    fn multi_type_nobody_block_disjoint_repeated_localport_is_clean() {
        // Nobody via disjoint repeated LocalPort on a MULTI-TYPE block: a connection
        // arrives on exactly ONE local port, so `LocalPort 22` AND `LocalPort 2222`
        // is unsatisfiable and the block matches nobody. The multi-type analogue of
        // `repeated_disjoint_localport_criteria_match_nobody_is_clean`.
        // Adversary-grounded (sshd_config(5) AND-of-criteria; same round-3
        // finding); currently FP-flags line 4 via the fallback.
        assert!(
            w07_diags(
                "Match all\n    X11Forwarding yes\n\
                 Match User alice LocalPort 22 LocalPort 2222\n    X11Forwarding no\n",
            )
            .is_empty(),
            "disjoint repeated LocalPort criteria AND to nobody; the multi-type block cannot shadow"
        );
    }

    // ---- SINGLE-INSTANCE nobody-criterion FP locks (#452 round 4, adversary round 2) ----
    // `block_matches_nobody` only inspects REPEATED criterion types
    // (`instances.len() >= 2`), so a block whose SINGLE-instance criterion admits no
    // witness slips the round-3 nobody guard entirely and is still FP-flagged.
    // OpenSSH `match_pattern_list` requires some POSITIVE pattern to match AND no
    // negated pattern to match, which yields two single-instance nobody shapes:
    // a PURE-NEGATION list (`!alice` positively matches NOBODY - the OpenSSH
    // footgun: it does NOT mean "everyone except alice") and a SELF-NEGATED list
    // (`!alice,alice`: alice is vetoed by the negation, everyone else fails the
    // positive). Adversary-grounded, sshd -T -C 9.9p1: both user=alice and user=bob
    // probes -> yes (the nobody block's `no` never applies); satisfiability CONTROL:
    // `User !alice,*` IS satisfiable (bob -> no), so flagging THAT one is correct
    // and stays locked below. Both fixtures' current-impl [line 4] FP was observed
    // via a scratch `w07_diags` dump before pinning.
    //
    // FIX CAUTION (for the implementer): the single-instance nobody predicate must
    // treat an UN-NEGATED positive glob (`a*`, `*`) as SATISFIABLE - only
    // pure-negation and fully-self-negated lists are nobody. The control assertion
    // in the second test enforces that boundary mechanically.

    #[test]
    fn single_instance_self_negated_user_list_matches_nobody_is_clean() {
        // RED (round 4): `User !alice,alice` is a SINGLE-instance list that matches
        // NOBODY - alice matches the positive `alice` but is vetoed by `!alice`
        // (match_pattern_list's negation short-circuit), and every other name fails
        // the sole positive pattern. The block's `no` therefore never applies and
        // the bare-Address predecessor's differing `yes` has nothing to drop ->
        // truth EMPTY. Adversary-grounded (sshd -T -C 9.9p1: user=alice and
        // user=bob probes both -> yes; the block never applies). NOTE this is a NEW
        // regression vs pre-#452 main, not just an uncovered case: main's
        // `match_blocks_overlap` identical-type-set gate rejected the bare-Address
        // predecessor ({address} vs {user,address}) before any value comparison, so
        // main was CLEAN here; the #494 structural subset-or-equal selection now
        // admits the predecessor, and the single-instance gap in
        // `block_matches_nobody` lets the value comparison FP-flag line 4.
        assert!(
            w07_diags(
                "Match Address 10.0.0.0/8\n    X11Forwarding yes\n\
                 Match User !alice,alice Address 10.0.0.0/8\n    X11Forwarding no\n",
            )
            .is_empty(),
            "a self-negated single-instance User list matches nobody; the block is never a shadowee"
        );
    }

    #[test]
    fn single_instance_pure_negation_user_list_matches_nobody_is_clean() {
        // CONTROL (green, must STAY green after the fix): `User !alice,*` IS
        // satisfiable - the positive `*` admits every user the negation does not
        // veto (adversary probe: bob -> no), so the later block genuinely loses its
        // `no` to the earlier `Match all yes` for every user it matches, and the
        // line-4 flag is CORRECT. This pins the fix-caution boundary: an un-negated
        // positive glob keeps the list satisfiable; the nobody predicate must not
        // over-reach to any list that merely CONTAINS a negation.
        let control = w07_diags(
            "Match all\n    X11Forwarding yes\n\
             Match User !alice,* Address 10.0.0.0/8\n    X11Forwarding no\n",
        );
        assert_eq!(
            control.len(),
            1,
            "the satisfiable !alice,* control must keep its correct flag"
        );
        assert_eq!(control[0].line, 4);
        // RED (round 4): `User !alice` is a PURE-NEGATION single-instance list.
        // OpenSSH match_pattern_list returns a match only when some POSITIVE
        // pattern matches, so a negation-only list positively matches NOBODY - it
        // does NOT mean "everyone except alice". The block never applies, so the
        // earlier `Match all yes` drops nothing -> truth EMPTY. Adversary-grounded
        // (sshd -T -C 9.9p1: user=alice and user=bob probes both -> yes). Unlike
        // the self-negated fixture above, this FP is PRE-EXISTING IN-FAMILY on
        // main: a `Match all` predecessor short-circuits match_blocks_overlap's
        // overlap check, and block_matches_nobody's repeated-types-only scan never
        // inspected the single-instance pure-negation list, so main FP-flagged this
        // shape too - the round-4 fix retires both the new and the inherited FP at
        // one root.
        assert!(
            w07_diags(
                "Match all\n    X11Forwarding yes\n\
                 Match User !alice Address 10.0.0.0/8\n    X11Forwarding no\n",
            )
            .is_empty(),
            "a pure-negation single-instance User list matches nobody; the block is never a shadowee"
        );
    }

    // ---- WIDER-NEGATED-GLOB nobody FP locks on the DECLINE path (#452 round 5) ----
    // Completion of the round-4 single-instance-nobody family (adversary round 2,
    // second finding): `name_list_matches_nobody` handles pure-negation and
    // EXACT self-negation only, deliberately treating a WIDER negated glob vetoing a
    // narrower positive (`!a*,ab`) as satisfiable on the assumption the
    // overlap/witness oracles reject such lists independently. That assumption
    // holds on the axis-WALK path (its member() search runs match_pattern_list and
    // finds no witness - verified clean by the adversary) but NOT on the DECLINE
    // path: `block_level_shadow` is MEMBERSHIP-BLIND (it compares first-setter
    // values without ever asking whether any connection satisfies the later block),
    // so with a `Match all` or subset predecessor the dead block still FP-flags.
    // Adversary-grounded, sshd -T -C 9.9p1 (all probes yes; the wider negated glob
    // vetoes the narrower positive): user=ab -> yes, user=xyz -> yes, user=b -> yes
    // (the block never applies). Each fixture's current-impl [line 4] FP was
    // observed via a scratch `w07_diags` dump before pinning.
    //
    // FIX NOTE (for the implementer): the fix is a later-block WITNESS check on the
    // decline path (reusing the walk's member()/match_pattern_list machinery to ask
    // "does ANY candidate name satisfy the later block?"), NOT glob-subsumption
    // math bolted onto name_list_matches_nobody - pattern-subsumption reasoning is
    // exactly what that predicate's doc comment declines, and the witness search
    // already decides these lists correctly on the walk path.

    #[test]
    fn wider_negated_glob_nobody_via_match_all_decline_is_clean() {
        // RED (round 5): `User !a*,ab` matches NOBODY - the positive `ab` only
        // admits the user "ab", and the negated glob `!a*` vetoes every name
        // starting with "a", including "ab" itself; every other name fails the sole
        // positive. Adversary-grounded (sshd -T -C 9.9p1: user=ab -> yes, user=xyz
        // -> yes, user=b -> yes; the block's `no` never applies). The `Match all`
        // predecessor is neutral on both of L's axes, so no unique reduction axis
        // exists and the DECLINE route runs `block_level_shadow`, which is
        // membership-blind and currently FP-flags line 4 against the `Match all`
        // winner.
        assert!(
            w07_diags(
                "Match all\n    X11Forwarding yes\n\
                 Match User !a*,ab Address 10.0.0.0/8\n    X11Forwarding no\n",
            )
            .is_empty(),
            "a wider negated glob vetoes the narrower positive; the dead block is never a shadowee"
        );
    }

    #[test]
    fn wider_negated_glob_nobody_via_subset_predecessor_decline_is_clean() {
        // RED (round 5): the same dead `User !a*,ab` block behind a bare-Address
        // SUBSET predecessor (the #494 selection shape) instead of `Match all`. The
        // predecessor's /8 exactly equals L's /8 (neutral on address) and it does
        // not constrain user (universe there), so BOTH axes qualify, no unique axis
        // exists, and the DECLINE route again compares values membership-blind ->
        // currently FP-flags line 4. Same adversary grounding as above (sshd -T -C
        // 9.9p1: all probes yes; the block never applies); proves the gap is the
        // decline route itself, not something about `Match all` predecessors.
        assert!(
            w07_diags(
                "Match Address 10.0.0.0/8\n    X11Forwarding yes\n\
                 Match User !a*,ab Address 10.0.0.0/8\n    X11Forwarding no\n",
            )
            .is_empty(),
            "the decline route must not flag a nobody block admitted by the subset selection"
        );
    }

    #[test]
    fn bang_star_negated_glob_nobody_decline_is_clean() {
        // RED (round 5): `User !*,alice` - the negated glob `!*` vetoes EVERY name,
        // so no candidate can survive it and the positive `alice` is unreachable:
        // the list matches nobody. Same wider-negated-glob shape at its extreme
        // (the widest possible veto), same DECLINE-route FP via the `Match all`
        // predecessor, currently flagging line 4. Adversary-grounded (sshd -T -C
        // 9.9p1: all probes yes; the wider negated glob vetoes the narrower
        // positive). Distinct from the SATISFIABLE `!alice,*` control pinned in
        // `single_instance_pure_negation_user_list_matches_nobody_is_clean`: there
        // the positive is the glob and the negation is narrow (bob survives); here
        // the NEGATION is the glob and nothing survives.
        assert!(
            w07_diags(
                "Match all\n    X11Forwarding yes\n\
                 Match User !*,alice Address 10.0.0.0/8\n    X11Forwarding no\n",
            )
            .is_empty(),
            "a !* veto admits no name at all; the dead block is never a shadowee"
        );
    }

    #[test]
    fn single_instance_nobody_walk_route_stays_clean() {
        // LOCK (round 6, green today): the WALK-route single-instance analogue of
        // `multi_type_nobody_block_repeated_user_is_not_a_shadowee_walk_clean`. The
        // bare-Address predecessor (10.1.0.0/16, universe on `user`, NON-covering on
        // `address` vs L's /8) gives the reduction a UNIQUE address axis, so this is
        // an axis-WALK case that bypasses the round-5 witness gate on the DECLINE
        // route entirely - the only thing keeping it clean is the nobody guard
        // itself, whose name-list branch (`name_list_matches_nobody`) recognizes the
        // self-negated `!alice,alice` list (round-4 oracle transcripts: sshd -T -C
        // 9.9p1, user=alice and user=bob probes both take the OTHER block's value;
        // the self-negated block never applies - same nobody list as the round-4
        // fixtures, different route). KILLS the mutation survivor
        // `name_list_matches_nobody -> bool with false` (w07.rs:909, surfaced after
        // the round-5 witness gate took over the round-4 fixtures' protection):
        // the implementer PROVED non-equivalence empirically by temp-applying the
        // mutant on this exact fixture - the real impl emits nothing, the mutant
        // misses the nobody guard, walks the unique address axis, hands the
        // differing `no` setter the 10.1.0.0/16 sub-population, and FP-flags
        // line 4. BACK-REFERENCE: the round-7 hoist (name_axes_admit_witness moved
        // above the walk) re-masked this LINT-LEVEL kill - the hoisted witness gate
        // now suppresses this fixture even under that mutant - so
        // `name_list_matches_nobody_direct_pin` (round 8) is the surviving DIRECT
        // kill for it; this test remains the walk-route behavioral lock.
        assert!(
            w07_diags(
                "Match Address 10.1.0.0/16\n    X11Forwarding no\n\
                 Match User !alice,alice Address 10.0.0.0/8\n    X11Forwarding yes\n",
            )
            .is_empty(),
            "the walk route must not carve sub-populations out of a self-negated nobody block"
        );
    }

    // ---- WALK-ROUTE wider-negated-glob nobody FP locks (#452 round 7) ----
    // The walk-route TWIN of the round-5 decline-route locks: the round-5 witness
    // gate (`name_axes_admit_witness`) sits on the DECLINE path only, and the axis
    // WALK never inspects a witness-less NON-walked axis - the round-1 #494
    // mechanism resurfaced through a nobody shape `block_matches_nobody` cannot see
    // (its `name_list_matches_nobody` handles pure-negation / exact self-negation,
    // not a wider negated glob vetoing a narrower positive). A bare-Address subset
    // predecessor makes ADDRESS the unique reduction axis, so the walk carves the
    // predecessor's /16 out of L's /8 and flags the differing value without ever
    // asking whether ANY user satisfies L's dead `!a*,ab` (or `!*,alice`) list.
    // Adversary-grounded, sshd -T -C 9.9p1 (global X11Forwarding no; probes ab,
    // xyz, b, abcd at addr=10.5.0.5 all -> no; the later block's `yes` never
    // applies to anyone). Both fixtures' current-impl [line 4] FP was observed via
    // a scratch `w07_diags` dump before pinning. After this round, walk and decline
    // - the only two multitype routes - are BOTH witness-gated, closing the family
    // exhaustively.
    //
    // FIX NOTE (for the implementer): hoist `name_axes_admit_witness` to the TOP of
    // `multitype_shadow` so it guards both routes. The check is SUPPRESS-ONLY (it
    // can only turn a flag into silence), so hoisting it cannot introduce new FPs.

    #[test]
    fn walk_route_wider_negated_glob_nobody_is_clean() {
        // RED (round 7): `User !a*,ab` matches NOBODY (the negated glob `!a*`
        // vetoes the only positive `ab`; every other name fails the positive - the
        // same dead list as the round-5 decline fixtures). The bare-Address
        // predecessor (10.1.0.0/16: universe on user, NON-covering on L's /8)
        // makes ADDRESS the unique reduction axis, so this takes the WALK route,
        // bypassing the round-5 decline-path witness gate; the walk hands the
        // differing `no` predecessor the 10.1.0.0/16 sub-population of a block no
        // connection can ever satisfy and currently FP-flags line 4.
        // Adversary-grounded (sshd -T -C 9.9p1: probes ab, xyz, b, abcd at
        // addr=10.5.0.5 all -> no under a global X11Forwarding no; L's `yes` never
        // applies).
        assert!(
            w07_diags(
                "Match Address 10.1.0.0/16\n    X11Forwarding no\n\
                 Match User !a*,ab Address 10.0.0.0/8\n    X11Forwarding yes\n",
            )
            .is_empty(),
            "the walk must not carve sub-populations out of a wider-glob-vetoed nobody block"
        );
    }

    #[test]
    fn walk_route_bang_star_negated_glob_nobody_is_clean() {
        // RED (round 7): the same walk-route shape at the veto's extreme -
        // `User !*,alice`, where the negated glob `!*` vetoes EVERY name and the
        // positive `alice` is unreachable (the round-5 `bang_star` fixture's list,
        // now reached via the WALK route instead of the decline route). The unique
        // address axis again lets the walk flag line 4 against the differing
        // bare-Address predecessor without a membership check on the dead user
        // list. Same adversary grounding (sshd -T -C 9.9p1: all probes -> no; the
        // block never applies); still distinct from the SATISFIABLE `!alice,*`
        // control (there the positive is the glob and bob survives).
        assert!(
            w07_diags(
                "Match Address 10.1.0.0/16\n    X11Forwarding no\n\
                 Match User !*,alice Address 10.0.0.0/8\n    X11Forwarding yes\n",
            )
            .is_empty(),
            "the walk must not carve sub-populations out of a !*-vetoed nobody block"
        );
    }

    #[test]
    fn name_list_matches_nobody_direct_pin() {
        // Direct unit pin on the private fast-path predicate (round 8). The round-7
        // hoist of `name_axes_admit_witness` to the top of `multitype_shadow`
        // SUBSUMES this predicate's domain through the lint() entry point: every
        // list it recognizes as nobody is also witness-less, so the mutation
        // survivor `name_list_matches_nobody -> bool with false` became GENUINELY
        // behavior-equivalent end-to-end (the implementer proved the whole suite
        // passes with the mutant applied; this supersedes the round-6 lint-level
        // kill, which the hoist re-masked). Rather than a documented-equivalence
        // exclusion, this test kills the mutant DIRECTLY and pins the fast-path
        // contract: TRUE only for pure-negation and EXACT self-negation (literal or
        // glob-string-identical); FALSE for anything with a surviving positive.
        // The ["!a*","ab"] FALSE case is INTENTIONAL - the wider-glob-veto shape is
        // deliberately NOT detected here (no glob-subsumption math in the fast
        // path); the hoisted witness gate catches it with real match_pattern_list
        // semantics (#452 rounds 5-7), and this pin keeps the predicate honest
        // about exactly where its cheap exact-match contract ends.
        let nobody = |vals: &[&str]| -> bool {
            let owned: Vec<String> = vals.iter().map(|v| (*v).to_string()).collect();
            super::name_list_matches_nobody(&owned)
        };
        // Pure negation: no positive entry at all -> nobody.
        assert!(nobody(&["!alice"]));
        // Exact self-negation: the only positive is negated verbatim -> nobody.
        assert!(nobody(&["!alice", "alice"]));
        // Exact GLOB self-negation: same rule, the entries compare as strings
        // (`a*` vs `a*`), no glob expansion involved -> nobody.
        assert!(nobody(&["!a*", "a*"]));
        // A positive glob not exactly negated keeps the list satisfiable
        // (`!alice,*` admits every user except alice - the round-4 control).
        assert!(!nobody(&["!alice", "*"]));
        // A plain literal with no negation at all is trivially satisfiable.
        assert!(!nobody(&["alice"]));
        // The wider-glob-veto shape (`!a*` vetoes `ab` under real
        // match_pattern_list semantics) is INTENTIONALLY not detected by the fast
        // path - exact string containment only, the witness gate owns this shape.
        assert!(!nobody(&["!a*", "ab"]));
    }

    #[test]
    fn unmodeled_criterion_rdomain_takes_fallback_arm_and_flags() {
        // GREEN pin (round 9, from the idiomatic review): the `_` arm of
        // `multitype_axis_shadow` is documented "unreachable" but IS live, and this
        // pins it. Reachability trace: `RDomain` is a VALID sshd Match criterion
        // (sshd_config(5); accepted by the parser's generic criterion split and
        // listed in e04's valid-criteria registry) but is NOT region-modeled, so a
        // `Match RDomain vrf0` block takes `single_region_type` -> None -> the
        // multitype path; `multitype_reduction_axis` returns Some("rdomain") (the
        // block's lone axis, with no OTHER axis to disqualify it); and
        // `multitype_axis_shadow` dispatches it to the `_` arm's conservative
        // `block_level_shadow` fallback. The behavior is CORRECT: first-value-wins
        // makes the always-satisfied `Match all yes` win every connection including
        // rdomain=vrf0, so the later `no` is dead - a REAL shadow the fallback
        // rightly flags. ORACLE (live probe, OpenSSH 9.9p1 sshd -T -C, this exact
        // fixture): rdomain=vrf0 -> x11forwarding yes AND rdomain=other -> yes
        // (`Match all` wins everywhere; the `no` never applies); CONTROL with the
        // RDomain block FIRST -> x11forwarding no (proving sshd honors the RDomain
        // criterion itself - the dead-ness above is purely Match-block ordering).
        // This arm must NEVER become `unreachable!()` (a linter must not panic on
        // valid input); the pin also kills the latent mutation gap on the arm
        // (deleting it or constant-replacing its body now changes an asserted
        // verdict).
        let d = w07_diags(
            "Match all\n    X11Forwarding yes\n\
             Match RDomain vrf0\n    X11Forwarding no\n",
        );
        assert_eq!(
            d.len(),
            1,
            "the unmodeled-criterion block routes through the live fallback arm and flags"
        );
        assert_eq!(d[0].code, "sshd-W07");
        assert_eq!(
            d[0].line, 4,
            "Match all wins every rdomain; the RDomain block's `no` on line 4 is dead"
        );
    }

    // ---- HOST axis case folding (#495): host folds, user/group do NOT ----
    //
    // # Grounding (PRIMARY SOURCE: openssh-portable, pinned tag `V_10_2_P1`)
    // The `Host` axis folds BOTH sides of the comparison, not just the incoming
    // hostname:
    // - `servconf.c:1134-1141` - the `host` attrib dispatches to
    //   `match_hostname(ci->host, arg)`.
    // - `match.c:196-203` - `match_hostname()` lowercases the incoming host
    //   (`lowercase(hostcopy)`) AND passes `dolower=1`:
    //   `r = match_pattern_list(hostcopy, pattern, 1);`
    // - `match.c:141-146` - with `dolower=1`, `match_pattern_list()` lowercases the
    //   CONFIG PATTERN too while extracting each subpattern:
    //   `sub[subi] = dolower && isupper((u_char)pattern[i]) ? tolower(...) : pattern[i];`
    // So `Match Host WEB.CORP` and `Match Host web.corp` denote the IDENTICAL host
    // set: both sides normalize to `web.corp`.
    //
    // The counter-axis is case-SENSITIVE, from the same source:
    // - `servconf.c:1108-1115` - `user` dispatches to
    //   `match_usergroup_pattern_list(ci->user, arg)`.
    // - `match.c:177-186` - that calls `match_pattern_list(string, pattern, 0)`
    //   (`dolower=0`) under the explicit comment `/* Case sensitive match */`.
    //
    // # Live oracle (local `sshd -T -C`, OpenSSH_10.2p1, 2026-07-15)
    // - `Match Host WEB.CORP` + `PermitTTY no`: host=web.corp -> `permittty no`,
    //   host=WEB.CORP -> `permittty no`, host=other.corp -> `permittty yes`. The
    //   uppercase PATTERN matches the lowercase host, proving the pattern folds.
    // - `Match Host !web.corp,WEB.CORP` + `PermitTTY no`: host=web.corp -> `yes`,
    //   host=WEB.CORP -> `yes`, host=other.corp -> `yes`. The block applies to NO
    //   host: `WEB.CORP` folds onto `web.corp`, which its own `!web.corp` vetoes.
    // - `Match User !alice,ALICE` + `PermitTTY no`: user=alice -> `yes`,
    //   user=ALICE -> `no`, user=bob -> `yes`. `ALICE` survives as a distinct
    //   positive, so the user list stays SATISFIABLE - the host fold must not
    //   reach the user axis.

    #[test]
    fn mixed_case_host_self_negation_matches_nobody_and_is_not_a_shadow_victim_w07() {
        // #495 FP direction. Under sshd's host fold, `!web.corp,WEB.CORP` positively
        // admits nothing: `WEB.CORP` normalizes to `web.corp` and is then vetoed by
        // its own `!web.corp` (oracle: every host probe falls through to the global
        // default). A block that matches nobody can never be shadowed, so W07 must
        // stay silent. A case-SENSITIVE reading sees `WEB.CORP` as a live positive
        // that `Host *` also admits, and wrongly reports line 4 as a shadow victim.
        assert!(
            w07_diags(
                "Match Host *\n    X11Forwarding yes\n\
                 Match Host !web.corp,WEB.CORP\n    X11Forwarding no\n",
            )
            .is_empty(),
            "`Host !web.corp,WEB.CORP` self-negates to nobody under sshd's host fold, \
             so it is not a shadow victim"
        );
    }

    #[test]
    fn mixed_case_host_patterns_co_satisfy_and_shadow_w07() {
        // #495 FN direction. `WEB.CORP` and `web.corp` fold to the SAME host set
        // (match.c dolower=1 lowercases the pattern as well as the host), so a
        // `web.corp` connection satisfies BOTH blocks and the later X11Forwarding is
        // silently dropped. A case-SENSITIVE reading treats the two as disjoint and
        // misses the shadow entirely.
        let d = w07_diags(
            "Match Host WEB.CORP\n    X11Forwarding yes\n\
             Match Host web.corp\n    X11Forwarding no\n",
        );
        assert_eq!(
            d.len(),
            1,
            "mixed-case host patterns denote one host set -> exactly one W07"
        );
        assert_eq!(d[0].code, "sshd-W07");
        assert_eq!(d[0].severity, Severity::Warning);
        assert_eq!(
            d[0].line, 4,
            "the LATER (shadowed) instance is flagged, not the winning first one"
        );
    }

    #[test]
    fn mixed_case_user_self_negation_stays_satisfiable_w07() {
        // #495 counter-axis guard: the fold is host-ONLY. `match_usergroup_pattern_list`
        // passes dolower=0, so `ALICE` stays a distinct positive from `alice` and the
        // list is SATISFIABLE (oracle: user=ALICE -> `permittty no`, i.e. the block
        // APPLIES). The block therefore co-satisfies `User *` and line 4 IS a shadow.
        // A blanket `to_ascii_lowercase()` applied to ALL name axes would fold `ALICE`
        // onto `alice`, declare the list nobody, and drop this finding - this test
        // fails such an impl. Expected to PASS before the fix (regression guard).
        let d = w07_diags(
            "Match User *\n    X11Forwarding yes\n\
             Match User !alice,ALICE\n    X11Forwarding no\n",
        );
        assert_eq!(
            d.len(),
            1,
            "user axis is case-SENSITIVE: `!alice,ALICE` still admits ALICE -> one W07"
        );
        assert_eq!(
            d[0].line, 4,
            "the satisfiable mixed-case user block is the shadow victim"
        );
    }

    #[test]
    fn mixed_case_user_patterns_stay_disjoint_w07() {
        // #495 counter-axis guard, FN direction: the mirror of
        // `mixed_case_host_patterns_co_satisfy_and_shadow_w07` on the case-SENSITIVE
        // axis. No single connection is both `ALICE` and `alice`, so the two blocks
        // are provably disjoint and nothing is shadowed. A blanket lowercase across
        // all name axes would make them overlap and manufacture a false W07 here.
        // Expected to PASS before the fix (regression guard).
        assert!(
            w07_diags(
                "Match User ALICE\n    X11Forwarding yes\n\
                 Match User alice\n    X11Forwarding no\n",
            )
            .is_empty(),
            "user axis does not fold: `ALICE` and `alice` are disjoint -> no W07"
        );
    }

    // ---- HOST fold: both SIDES, and at EVERY comparison site (#495) ----
    //
    // The tests above are carried by a lowercase TWIN present among the config
    // literals (`web.corp` appears in both fixtures), so they are also satisfied by
    // a HALF-fix that lowercases only the config PATTERN (match.c:145-146's
    // `dolower=1`) and skips `match_hostname`'s `lowercase(hostcopy)` on the
    // incoming VALUE (match.c:199). The witness search draws candidates from config
    // literals ([`collect_name_literals`]), so the twin alone satisfies both sides
    // and the value axis is never forced to fold. The fixtures below remove the twin
    // and cross the multi-type path, pinning the fold at every host-comparison site.

    #[test]
    fn uppercase_only_host_literal_folds_onto_lowercase_glob_w07() {
        // #495 FN direction with NO lowercase twin among the literals: `WEB.CORP` is
        // the ONLY host literal here (`*.corp` is a glob, so it contributes no
        // witness candidate). The sole witness is therefore uppercase, and it can
        // only satisfy the earlier `*.corp` if the incoming VALUE folds
        // (match.c:199 `lowercase(hostcopy)`) - lowercasing just the pattern leaves
        // `glob_match("*.corp", "WEB.CORP")` false and the shadow unfound. A
        // `web.corp` connection satisfies both blocks, so line 4's `no` is dead.
        let d = w07_diags(
            "Match Host *.corp\n    X11Forwarding yes\n\
             Match Host WEB.CORP\n    X11Forwarding no\n",
        );
        assert_eq!(
            d.len(),
            1,
            "the incoming host folds too: `WEB.CORP` is admitted by `*.corp` -> one W07"
        );
        assert_eq!(d[0].code, "sshd-W07");
        assert_eq!(d[0].severity, Severity::Warning);
        assert_eq!(
            d[0].line, 4,
            "the LATER (shadowed) instance is flagged, not the winning first one"
        );
    }

    #[test]
    fn identical_uppercase_host_blocks_stay_a_shadow_w07() {
        // #495 REGRESSION guard on the fold's value side. Two byte-identical
        // uppercase headers are a shadow under ANY consistent reading - the
        // case-SENSITIVE impl already flags this. It is here because a half-fix that
        // folds only the pattern BREAKS it: the pattern becomes `web.corp` while the
        // witness stays `WEB.CORP`, so the block stops matching ITSELF and the
        // finding silently disappears. Expected to PASS before the fix; it fails only
        // for an impl that folds one side.
        let d = w07_diags(
            "Match Host WEB.CORP\n    X11Forwarding yes\n\
             Match Host WEB.CORP\n    X11Forwarding no\n",
        );
        assert_eq!(
            d.len(),
            1,
            "identical uppercase host headers denote one host set -> exactly one W07"
        );
        assert_eq!(d[0].line, 4, "the later duplicate is the shadow victim");
    }

    #[test]
    fn mixed_case_host_shadows_across_the_multitype_path_w07() {
        // #495 FN direction on the MULTI-TYPE route. The tests above are all
        // single-criterion-type, so [`single_region_type`] routes them exclusively
        // through [`names_region_shadow`]; adding an `Address` sends the identical
        // host question through [`multitype_shadow`] instead, whose own host
        // comparisons ([`type_co_satisfiable`]'s selection gate,
        // [`multitype_names_axis_shadow`]'s `member`, [`exact_name_set`]) are
        // INDEPENDENT sites. Folding only the single-type site leaves this fixture
        // silent: the earlier block is never even selected as a setter, because
        // `WEB.CORP` and `web.corp` look disjoint to the gate.
        let d = w07_diags(
            "Match Host WEB.CORP Address 10.0.0.0/8\n    X11Forwarding yes\n\
             Match Host web.corp Address 10.0.0.0/8\n    X11Forwarding no\n",
        );
        assert_eq!(
            d.len(),
            1,
            "the host fold must reach the multi-type route: same host set, same net -> one W07"
        );
        assert_eq!(d[0].code, "sshd-W07");
        assert_eq!(
            d[0].line, 4,
            "the LATER (shadowed) instance is flagged, not the winning first one"
        );
    }

    #[test]
    fn repeated_mixed_case_host_is_satisfiable_not_nobody_w07() {
        // #495 FN direction at the nobody guard. `sshd_config(5)` AND-s repeated
        // criteria, so `Host WEB.CORP Host web.corp` needs ONE host satisfying both
        // occurrences: under the fold that host is `web.corp`, so the block is
        // SATISFIABLE and IS shadowed by the earlier `Host *`. A case-SENSITIVE
        // reading finds no common witness, declares the block NOBODY
        // ([`block_matches_nobody`] via [`name_instances_have_common_witness`]) and
        // returns early - a site no other fixture reaches, and one that suppresses
        // the finding no matter how many other sites are folded.
        let d = w07_diags(
            "Match Host *\n    X11Forwarding yes\n\
             Match Host WEB.CORP Host web.corp Address 10.0.0.0/8\n    X11Forwarding no\n",
        );
        assert_eq!(
            d.len(),
            1,
            "repeated mixed-case host instances share the witness `web.corp` -> satisfiable, \
             and shadowed by `Host *` -> one W07"
        );
        assert_eq!(d[0].line, 4, "the shadowed repeated-host block is flagged");
    }

    #[test]
    fn mixed_case_user_stays_disjoint_across_the_multitype_path_w07() {
        // #495 counter-axis guard on the MULTI-TYPE route: the mirror of
        // `mixed_case_host_shadows_across_the_multitype_path_w07` on the
        // case-SENSITIVE axis. The user guards above only cover the single-type
        // route, so a blanket `to_ascii_lowercase()` confined to the multi-type
        // sites would pass them; here it would make `ALICE` and `alice` co-satisfy
        // and manufacture a false W07. `match_usergroup_pattern_list` passes
        // dolower=0 (match.c:177-186), so no connection is both users and nothing is
        // shadowed. Expected to PASS before the fix (regression guard).
        assert!(
            w07_diags(
                "Match User ALICE Address 10.0.0.0/8\n    X11Forwarding yes\n\
                 Match User alice Address 10.0.0.0/8\n    X11Forwarding no\n",
            )
            .is_empty(),
            "user axis does not fold on the multi-type route either: `ALICE` vs `alice` \
             are disjoint -> no W07"
        );
    }

    // ---- GROUP axis stays case-sensitive too (#495 round 3) ----
    //
    // The round-2 barrier landed User-axis counter-guards but left the Group axis
    // UNGUARDED: a wrong impl that gates the fold on `kind == "host" || kind ==
    // "group"` (instead of host only) passes the whole pre-round-3 suite. The
    // three tests below are the Group mirrors of the User counter-axis guards
    // above, closing that hole.
    //
    // # Grounding (PRIMARY SOURCE: openssh-portable, pinned tag `V_10_2_P1`)
    // `Group` reaches the SAME case-sensitive comparison as `User`, through a
    // different dispatch path:
    // - `servconf.c:1127` - the `group` attrib dispatches to
    //   `match_cfg_line_group(ci->user, ci->groups, ci->ngroups, arg)`.
    // - `groupaccess.c:117-118` - `ga_match_pattern_list()` (called from
    //   `match_cfg_line_group` for each of the connection's groups) calls
    //   `match_usergroup_pattern_list(value, group)`.
    // - `match.c:177-186` - `match_usergroup_pattern_list()` calls
    //   `match_pattern_list(string, pattern, 0)` (`dolower=0`) under the explicit
    //   comment `/* Case sensitive match */` - the IDENTICAL call User goes
    //   through, just reached via group membership instead of `ci->user`.
    //
    // # Live oracle (local `sshd -T -C`, OpenSSH_10.2p1, 2026-07-15, this session)
    // `Match Group runner` + `PermitTTY no`, probed with `user=runner` (a real
    // member of the local `runner` group, gid 1000):
    // - Lowercase pattern `Match Group runner` -> `permittty no` (the block
    //   APPLIES: the group criterion matches).
    // - Uppercase pattern `Match Group RUNNER` -> `permittty yes` (the block does
    //   NOT apply: `Match all` wins instead) - proving `RUNNER` and `runner` are
    //   DIFFERENT group patterns to sshd, exactly mirroring the User-axis oracle
    //   already cited above.

    #[test]
    fn mixed_case_group_patterns_stay_disjoint_w07() {
        // #495 counter-axis guard (GROUP), FP direction. The Group mirror of
        // `mixed_case_user_patterns_stay_disjoint_w07`. No connection's groups can
        // be simultaneously named `DEVS` and `devs` (case-sensitive per the
        // grounding above), so the two blocks are provably disjoint and nothing is
        // shadowed. A wrong impl folding `kind == "host" || kind == "group"` would
        // make them co-satisfy and manufacture a false W07 here.
        assert!(
            w07_diags(
                "Match Group DEVS\n    X11Forwarding yes\n\
                 Match Group devs\n    X11Forwarding no\n",
            )
            .is_empty(),
            "group axis does not fold: `DEVS` and `devs` are disjoint -> no W07"
        );
    }

    #[test]
    fn mixed_case_group_self_negation_stays_satisfiable_w07() {
        // #495 counter-axis guard (GROUP), FN direction. The Group mirror of
        // `mixed_case_user_self_negation_stays_satisfiable_w07`. Group is
        // case-SENSITIVE (dolower=0, per the grounding above), so `DEVS` stays a
        // distinct positive from `devs` and `!devs,DEVS` is SATISFIABLE (a member
        // of group `DEVS` is not vetoed by `!devs`). The block therefore
        // co-satisfies `Group *` and line 4 IS a shadow. A wrong impl folding
        // `kind == "host" || kind == "group"` would fold `DEVS` onto `devs`,
        // declare the list self-negated (nobody), and MISS this finding.
        let d = w07_diags(
            "Match Group *\n    X11Forwarding yes\n\
             Match Group !devs,DEVS\n    X11Forwarding no\n",
        );
        assert_eq!(
            d.len(),
            1,
            "group axis is case-SENSITIVE: `!devs,DEVS` still admits DEVS -> one W07"
        );
        assert_eq!(
            d[0].line, 4,
            "the satisfiable mixed-case group block is the shadow victim"
        );
    }

    #[test]
    fn mixed_case_group_stays_disjoint_across_the_multitype_path_w07() {
        // #495 counter-axis guard (GROUP) on the MULTI-TYPE route. The mirror of
        // `mixed_case_user_stays_disjoint_across_the_multitype_path_w07`. The two
        // Group guards above only cover the single-type route
        // ([`names_region_shadow`]); a wrong impl that folds `kind == "host" ||
        // kind == "group"` only at the multi-type sites
        // ([`type_co_satisfiable`]'s selection gate, [`multitype_names_axis_shadow`]'s
        // `member`, [`exact_name_set`]) would pass the single-type guards above but
        // still fold `DEVS` onto `devs` here and manufacture a false W07. Group
        // stays case-sensitive on this route too (same `match_usergroup_pattern_list`
        // dolower=0 call, independent of which comparison SITE reaches it), so no
        // connection is a member of both `DEVS` and `devs` and nothing is shadowed.
        assert!(
            w07_diags(
                "Match Group DEVS Address 10.0.0.0/8\n    X11Forwarding yes\n\
                 Match Group devs Address 10.0.0.0/8\n    X11Forwarding no\n",
            )
            .is_empty(),
            "group axis does not fold on the multi-type route either: `DEVS` vs \
             `devs` are disjoint -> no W07"
        );
    }

    // ---- HOST fold fidelity: ASCII-only, not full Unicode (#495 round 4) ----
    //
    // The round-1..3 suite pins WHICH axis folds (host, not user/group) and THAT
    // both sides of the comparison fold, but never HOW FAR the fold reaches. A
    // wrong impl that uses Rust's full-Unicode `str::to_lowercase()` instead of
    // `to_ascii_lowercase()` passes the entire pre-round-4 suite (507/507):
    // every existing fixture's mixed-case pairs differ only in the ASCII a-z/A-Z
    // range, where the two functions agree.
    //
    // # Grounding (PRIMARY SOURCE: openssh-portable, pinned tag `V_10_2_P1`)
    // As already cited above (match.c:141-146), the fold is:
    //   `sub[subi] = dolower && isupper((u_char)pattern[i]) ? tolower((u_char)pattern[i]) : pattern[i];`
    // - BYTE-WISE C `isupper()`/`tolower()`, operating one `u_char` at a time.
    // UTF-8 continuation and lead bytes for any non-ASCII codepoint are all
    // `>= 0x80`, so C `isupper()` (locale "C") is false for every one of them and
    // they pass through completely unchanged. `match_hostname()` (match.c:196-203)
    // reaches the identical byte-wise loop for the incoming host value via
    // `lowercase(hostcopy)`.
    //
    // # Live oracle (local `sshd -T -C`, OpenSSH_10.2p1, 2026-07-15)
    // - `Match Host k` + `PermitTTY no`: host=`K` (ASCII 0x4B) -> `permittty no`
    //   (block APPLIES: the ASCII fold is real). host=U+212A KELVIN SIGN (UTF-8
    //   `e2 84 aa`) -> `permittty yes` (block does NOT apply: no Unicode fold).
    // - `Match Host cafe-acute` (lowercase e-acute, U+00E9) + `PermitTTY no`:
    //   host=`cafe-acute` -> `permittty no` (APPLIES). host=`CAFE-ACUTE` (uppercase
    //   E-acute, U+00C9) -> `permittty yes` (does NOT apply): the byte-wise
    //   `tolower` leaves `c3 89` (U+00C9) alone, so it never becomes `c3 a9`
    //   (U+00E9).
    //
    // Rust's `char::to_lowercase()` / `str::to_lowercase()` instead follow full
    // Unicode simple case mapping, where U+212A KELVIN SIGN has a documented
    // simple-lowercase mapping to U+006B (`k`) and U+00C9 maps to U+00E9 - both
    // WOULD fold under a `to_lowercase()` impl, collapsing patterns the daemon
    // treats as disjoint and manufacturing a false W07.

    #[test]
    fn kelvin_sign_host_pattern_does_not_fold_onto_ascii_k_w07() {
        // #495 round-4 FIDELITY guard, FP direction. `k` (U+006B) and U+212A
        // KELVIN SIGN are wholly distinct host patterns under sshd's byte-wise
        // ASCII fold (the oracle above), so the two blocks are disjoint and
        // nothing is shadowed. A wrong impl using `str::to_lowercase()` maps
        // KELVIN SIGN onto ASCII `k` (Unicode's documented simple-lowercase
        // mapping for U+212A), collapsing the two into one host set and
        // manufacturing a false W07 here.
        assert!(
            w07_diags(
                "Match Host k\n    X11Forwarding yes\n\
                 Match Host \u{212A}\n    X11Forwarding no\n",
            )
            .is_empty(),
            "the host fold is ASCII-only: `k` and U+212A KELVIN SIGN are disjoint \
             -> no W07"
        );
    }

    #[test]
    fn accented_e_host_pattern_does_not_fold_across_case_w07() {
        // #495 round-4 FIDELITY guard, FP direction, operator-facing mirror of the
        // KELVIN SIGN guard above. U+00C9 (LATIN CAPITAL LETTER E WITH ACUTE) and
        // U+00E9 (LATIN SMALL LETTER E WITH ACUTE) are both non-ASCII bytes in
        // UTF-8 (`c3 89` / `c3 a9`), so sshd's byte-wise fold never touches them
        // and `CAF\u{C9}` / `caf\u{E9}` stay disjoint host patterns (the oracle
        // above). A wrong impl using `str::to_lowercase()` performs full Unicode
        // case mapping and lowercases U+00C9 onto U+00E9, collapsing the two into
        // one host set and manufacturing a false W07 here.
        assert!(
            w07_diags(
                "Match Host CAF\u{C9}\n    X11Forwarding yes\n\
                 Match Host caf\u{E9}\n    X11Forwarding no\n",
            )
            .is_empty(),
            "the host fold is ASCII-only: accented E case is untouched -> \
             `CAF\u{C9}` and `caf\u{E9}` are disjoint -> no W07"
        );
    }

    // ---- HOST fold on a GLOB, and full multi-site Unicode fidelity (#495 round 5) ----
    //
    // DEFERRAL NOTE: #495 is being taken out of the v0.8 Wave-1 milestone for a
    // dedicated future session. These are the last two fixtures landed before the
    // hand-off; see the issue for the full implementation map (call-site surface,
    // signature-preserving fold routes, and the exact fold semantics) so the next
    // session does not have to re-derive it from the five review rounds' history.
    //
    // Every host GLOB in the suite above is already lowercase (`*.corp`, `a*`, `*`);
    // the only UPPERCASE host tokens are LITERALS (`WEB.CORP`, `CAF\u{C9}`, `K`). So
    // pattern-folding is never exercised on a glob, and an impl that folds the
    // incoming VALUE always but folds the PATTERN only when it contains no `*`/`?`
    // passes the whole pre-round-5 suite (509/509): it never meets an uppercase glob
    // to skip.
    //
    // Separately, the round-4 Unicode guards above
    // (`kelvin_sign_host_pattern_does_not_fold_onto_ascii_k_w07`,
    // `accented_e_host_pattern_does_not_fold_across_case_w07`) are both
    // SINGLE-criterion-type fixtures (no `Address`), so they route exclusively
    // through [`member_of_type`] / [`match_pattern_list`] on the single-type path. A
    // `to_lowercase()` (full Unicode) confined to any OTHER fold site therefore
    // passes them too - the same structural hole that let a User-axis-only fold
    // survive earlier rounds recurred here because the new guards were single-type.

    #[test]
    fn uppercase_host_glob_folds_onto_lowercase_literal_w07() {
        // #495 round-5 FIDELITY guard, FN direction. The earlier block's glob is
        // uppercase (`*.CORP`) and the later block is the lowercase literal
        // `web.corp`. An impl that folds the pattern only when it has no `*`/`?`
        // (`wrongGLOB`) leaves `*.CORP` un-folded (it contains `*`), so
        // `glob_match("*.CORP", "web.corp")` stays false and the shadow goes unfound
        // even though it correctly folds every literal-vs-literal and
        // literal-vs-lowercase-glob pair the rest of the suite exercises.
        //
        // # Live oracle (local `sshd -T -C`, OpenSSH_10.2p1, 2026-07-15, this session)
        // `Match Host *.CORP` + `PermitTTY no`, probed against the global default
        // `PermitTTY yes`:
        // - host=`web.corp` -> `permittty no` (the block APPLIES: the pattern folds).
        // - host=`web.example` -> `permittty yes` (control: does not match `*.corp`).
        //
        // # Grounding (PRIMARY SOURCE: openssh-portable, pinned tag `V_10_2_P1`)
        // match.c:141-146's fold loop is byte-wise over EVERY pattern character with
        // no wildcard special-casing - `*` and `?` are not exempted from `dolower`,
        // so an uppercase glob folds exactly like an uppercase literal.
        let d = w07_diags(
            "Match Host *.CORP\n    X11Forwarding yes\n\
             Match Host web.corp\n    X11Forwarding no\n",
        );
        assert_eq!(
            d.len(),
            1,
            "the uppercase glob `*.CORP` folds too: it admits `web.corp` -> one W07"
        );
        assert_eq!(d[0].code, "sshd-W07");
        assert_eq!(d[0].severity, Severity::Warning);
        assert_eq!(
            d[0].line, 4,
            "the LATER (shadowed) instance is flagged, not the winning first one"
        );
    }

    #[test]
    fn kelvin_sign_shadow_reaches_nobody_guard_and_multitype_member_w07() {
        // #495 round-5 FIDELITY guard, FN direction. Adding `Address` forces the
        // multi-type route: the LATER block's `Host !k,\u{212A}` list first passes
        // through [`block_matches_nobody`]'s self-negation check, then (once past
        // that guard) through [`multitype_names_axis_shadow`]'s `member` closure -
        // two independent host-comparison sites a single-type fixture never reaches.
        //
        // # Live oracle (local `sshd -T -C`, OpenSSH_10.2p1, 2026-07-15, this session)
        // `Match Host !k,\u{212A}` + `PermitTTY no`, probed against the global
        // default `PermitTTY yes`:
        // - host=`\u{212A}` (KELVIN SIGN) -> `permittty no` (the block APPLIES:
        //   KELVIN is a live positive the ASCII fold does not touch, so the
        //   self-negation `!k` never vetoes it).
        // - host=`k` -> `permittty yes` (vetoed by `!k`).
        // - host=`K` (ASCII) -> `permittty yes` (folds onto `k`, also vetoed).
        // So the block is SATISFIABLE (a real host, KELVIN SIGN, gets `no`) and is a
        // genuine shadow victim of the earlier unconditional `Match Host *`.
        //
        // A wrong impl using full-Unicode `to_lowercase()` at EITHER site instead of
        // the ASCII-only fold misses this: at `block_matches_nobody`, KELVIN folds
        // onto `k` (Unicode's documented simple-lowercase mapping for U+212A), making
        // `!k,\u{212A}` look self-negated (nobody) and suppressing the finding
        // entirely before the axis walk ever runs. At
        // `multitype_names_axis_shadow`'s `member` closure, the same Unicode fold
        // collapses the KELVIN witness candidate onto `k`, which the block's own
        // `!k` negation then excludes, so no candidate satisfies membership and the
        // walk finds no shadow either. Both are proven survivors of the round-4
        // guards; this fixture kills both.
        let d = w07_diags(
            "Match Host *\n    X11Forwarding yes\n\
             Match Host !k,\u{212A} Address 10.0.0.0/8\n    X11Forwarding no\n",
        );
        assert_eq!(
            d.len(),
            1,
            "KELVIN SIGN is a live positive under the ASCII-only fold: the block is \
             satisfiable and shadowed by `Host *` -> one W07"
        );
        assert_eq!(d[0].code, "sshd-W07");
        assert_eq!(d[0].severity, Severity::Warning);
        assert_eq!(
            d[0].line, 4,
            "the LATER (shadowed) instance is flagged, not the winning first one"
        );
    }
}
