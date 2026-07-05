//! sshd-W07: cross-`Match` first-value-wins shadow. See [`w07`]. The
//! CIDR/port/glob geometry primitives live in [`super::matching`].

use std::collections::{BTreeMap, HashSet};
use std::net::IpAddr;
use std::path::Path;

use rulesteward_core::{Diagnostic, Severity};

use crate::ast::{Block, MatchBlock};
use crate::lints::{SshdLintContext, anchored, is_unconditional_match_all};

use super::E02_ALLOW_REPEAT;
use super::matching::{
    cidr_intersects, cidr_lists_overlap, glob_match, parse_cidr_list, parse_port_list,
    port_lists_overlap,
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
            // sshd applies ONLY the first satisfied block's value, so the shadow
            // hazard is measured against the WINNER: the earliest earlier block that
            // both overlaps this one AND sets the keyword. A later value equal to the
            // winner's is redundant (the winner would have applied the same value),
            // not a differing shadow - so compare against the winner, not any earlier.
            let winning_value = match_blocks[..j]
                .iter()
                .filter(|earlier| match_blocks_overlap(earlier, later))
                .find_map(|earlier| first_value_for(earlier, &keyword));
            if winning_value.is_some_and(|value| value != directive.args.as_slice()) {
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
/// occurrence of it in `a` AND `b` combined. When each block states the type exactly
/// once, that reduces to the negation-aware pairwise oracle
/// ([`criterion_overlap`]); when either block repeats the type, the cross-block
/// intersection is decided by [`criterion_instances_have_common_witness`].
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
        b_types.get(kind).is_some_and(|b_insts| {
            if a_insts.len() == 1 && b_insts.len() == 1 {
                // One occurrence on each side: the negation-aware pairwise oracle.
                criterion_overlap(kind, a_insts[0], b_insts[0])
            } else {
                // A type repeated on either header is an AND across its occurrences,
                // so the blocks co-apply on it only if one witness satisfies every
                // occurrence in BOTH blocks (the cross-block intersection).
                let combined: Vec<&[String]> = a_insts.iter().chain(b_insts).copied().collect();
                // CONSERVATIVE GUARD: the cross-occurrence CIDR/port witness
                // ([`cidr_instances_have_common_address`] / [`port_instances_have_common_port`])
                // is negation-BLIND - it drops `!` carve-outs - so a repeated
                // CIDR/LocalPort type carrying a negation would be over-approximated
                // into a possible false positive. Computing the true negation-aware
                // intersection across repeated occurrences is out of v0.3 scope, so we
                // treat such a type as non-overlapping: an FN-leaning accepted gap that
                // never risks a false positive. Name lists stay negation-aware via
                // [`match_pattern_list`], so the guard is CIDR/port only.
                if matches!(kind.as_str(), "address" | "localaddress" | "localport")
                    && combined
                        .iter()
                        .any(|occ| occ.iter().any(|value| value.starts_with('!')))
                {
                    false
                } else {
                    criterion_instances_have_common_witness(kind, &combined)
                }
            }
        })
    })
}

/// Whether a `Match` block can be satisfied by NO connection. `sshd_config(5)`
/// AND-s all criteria on a header, so a criterion TYPE repeated on the same header
/// requires ONE connection to satisfy every occurrence of that type at once (e.g.
/// `Match User alice User bob` needs user == alice AND user == bob - impossible).
/// A block matches nobody iff some repeated type has no single common witness.
///
/// Types appearing only once are assumed satisfiable (a single criterion normally
/// admits someone). An unmodeled repeated type is also assumed satisfiable
/// (conservative: [`criterion_overlap`] returns no-overlap for it anyway, so
/// treating it as satisfiable never manufactures a finding). Reasoning per repeated
/// type from the block's OWN criteria only makes this independent of the other block.
fn block_matches_nobody(block: &MatchBlock) -> bool {
    criteria_by_type(block)
        .iter()
        .filter(|(_, instances)| instances.len() >= 2)
        .any(|(kind, instances)| !criterion_instances_have_common_witness(kind, instances))
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
    //! Besides the cross-type conservative reading above (#400), two further gaps
    //! are intentionally accepted for v0.3 rather than implemented:
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
}
