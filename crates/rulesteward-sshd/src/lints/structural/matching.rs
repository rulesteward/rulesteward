//! Geometry and glob-matching toolkit shared by sshd-W07's Match-overlap oracle:
//! OpenSSH `match_pattern` globbing plus the CIDR / port set-overlap primitives.
//! Every item here is used only by [`super::w07`].

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Advance a glob cursor by one position. Extracted so the three NON-TERMINATING
/// `+= 1` advances in [`glob_match`] (the `*`-open, backtrack, and trailing-`*`
/// sites, whose mutation to `*=` hangs the loop) live in one function-anchored
/// place `.cargo/mutants.toml` can exclude by name, instead of line-anchored
/// ranges that drift when the file shifts. `i + 1` is exactly `i += 1`, so this
/// is behavior-identical. `#[must_use]` avoids a `clippy::pedantic`
/// `must_use_candidate` error under `-D warnings`.
///
/// MUST stay a module-level `fn`: nesting it inside [`glob_match`] would change
/// its cargo-mutants name and break the `matching\.rs:.*in glob_advance`
/// exclusion anchors in `.cargo/mutants.toml`, silently re-admitting the three
/// non-terminating timeout mutants into the nightly gate.
#[must_use]
fn glob_advance(i: usize) -> usize {
    i + 1
}

/// OpenSSH `match_pattern` glob: `*` matches any run of characters and `?` matches
/// exactly one. Case-sensitive (sshd criterion values are case-sensitive). Iterative
/// with `*` backtracking, so it never recurses.
pub(super) fn glob_match(pattern: &str, value: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let value: Vec<char> = value.chars().collect();
    let (mut p, mut v) = (0usize, 0usize);
    let (mut star, mut star_v) = (None, 0usize);
    while v < value.len() {
        if p < pattern.len() && (pattern[p] == '?' || pattern[p] == value[v]) {
            p += 1;
            v += 1;
        } else if p < pattern.len() && pattern[p] == '*' {
            star = Some(p);
            star_v = v;
            p = glob_advance(p);
        } else if let Some(star_p) = star {
            p = star_p + 1;
            star_v = glob_advance(star_v);
            v = star_v;
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == '*' {
        p = glob_advance(p);
    }
    p == pattern.len()
}

/// Whether some address satisfies BOTH `Address`/`LocalAddress` CIDR lists. CIDR
/// blocks are power-of-two aligned, so any two are either disjoint or nested.
///
/// For each pair of POSITIVE networks (one from each list) that intersect, the
/// intersection is exactly the MORE SPECIFIC of the two (the longer-prefix net,
/// since it nests entirely inside the shorter one). That intersection survives -
/// and the pair overlaps - UNLESS some single negated entry (from either list)
/// fully COVERS it: a negation `N` covers an intersection `I` iff `N`'s prefix is
/// `<=` `I`'s (so `N` is a supernet of, or equal to, `I`) and `N` intersects `I`.
/// A negation with a LONGER prefix than `I` only carves out part of it, leaving
/// an overlapping remainder, so it does NOT disqualify the pair. This is the
/// negation-AWARE remainder model (#403): an irrelevant negation (does not
/// intersect the shared range) or a partial one (covers only part of it) both
/// leave a real overlap; only a negation that fully covers the intersection makes
/// the pair disjoint. Unparseable entries are ignored (conservative: they never
/// manufacture overlap).
///
/// APPROXIMATION: coverage is tested against ONE negation at a time. An intersection
/// left uncovered by every SINGLE negation but fully covered by the UNION of several
/// negations is treated as overlapping - a rare potential false positive scoped to
/// the single-negation model (multi-negation union coverage is out of v0.3 scope).
pub(super) fn cidr_lists_overlap(a: &[String], b: &[String]) -> bool {
    let a_pos = parse_cidr_list(a);
    let b_pos = parse_cidr_list(b);
    let negations: Vec<(IpAddr, u8)> = parse_negated_cidr_list(a)
        .into_iter()
        .chain(parse_negated_cidr_list(b))
        .collect();
    a_pos.iter().any(|&a_net| {
        b_pos.iter().any(|&b_net| {
            cidr_intersects(a_net, b_net) && {
                let intersection = if a_net.1 >= b_net.1 { a_net } else { b_net };
                !negations
                    .iter()
                    .any(|&n| n.1 <= intersection.1 && cidr_intersects(n, intersection))
            }
        })
    })
}

/// Parse the positive (non-negated) entries of an `Address` list into
/// `(network, prefix_len)` pairs, dropping any that do not parse.
pub(super) fn parse_cidr_list(values: &[String]) -> Vec<(IpAddr, u8)> {
    values
        .iter()
        .filter(|v| !v.starts_with('!'))
        .filter_map(|v| parse_cidr(v))
        .collect()
}

/// Parse the NEGATED (`!`-prefixed) entries of an `Address` list into
/// `(network, prefix_len)` pairs, dropping any that do not parse. Used by
/// [`cidr_lists_overlap`] to compute the negation-aware remainder (#403).
fn parse_negated_cidr_list(values: &[String]) -> Vec<(IpAddr, u8)> {
    values
        .iter()
        .filter_map(|v| v.strip_prefix('!'))
        .filter_map(parse_cidr)
        .collect()
}

/// Parse one `Address` value: `a.b.c.d[/n]` or an IPv6 form. A bare address is a
/// host route (`/32` for IPv4, `/128` for IPv6). Returns `None` for a malformed
/// address or an out-of-range prefix.
fn parse_cidr(value: &str) -> Option<(IpAddr, u8)> {
    if let Some((addr, prefix)) = value.split_once('/') {
        let addr: IpAddr = addr.parse().ok()?;
        let prefix: u8 = prefix.parse().ok()?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        (prefix <= max).then_some((addr, prefix))
    } else {
        let addr: IpAddr = value.parse().ok()?;
        Some((addr, if addr.is_ipv4() { 32 } else { 128 }))
    }
}

/// Whether two CIDR networks share any address. Same-family networks intersect iff
/// they agree on the first `min(prefix)` bits (CIDR blocks nest or are disjoint);
/// different-family networks never intersect.
pub(super) fn cidr_intersects(a: (IpAddr, u8), b: (IpAddr, u8)) -> bool {
    let prefix = a.1.min(b.1);
    match (a.0, b.0) {
        (IpAddr::V4(x), IpAddr::V4(y)) => leading_bits_equal(
            u128::from(u32::from(x)),
            u128::from(u32::from(y)),
            prefix,
            32,
        ),
        (IpAddr::V6(x), IpAddr::V6(y)) => {
            leading_bits_equal(u128::from(x), u128::from(y), prefix, 128)
        }
        _ => false,
    }
}

/// Whether `x` and `y` agree on their most-significant `prefix` bits within a
/// `width`-bit address. `prefix == 0` trivially agrees (the whole address space).
fn leading_bits_equal(x: u128, y: u128, prefix: u8, width: u8) -> bool {
    if prefix == 0 {
        return true;
    }
    let shift = width - prefix;
    (x >> shift) == (y >> shift)
}

/// Whether two `LocalPort` lists share a port. A connection arrives on exactly one
/// local port, so a shared port `p` between the two POSITIVE sets means the lists
/// co-satisfy on `p` - UNLESS `p` is carved out by a negated (`!`) entry in EITHER
/// list. This is the negation-AWARE remainder model (#403), the port analogue of
/// [`cidr_lists_overlap`]: a negation that names an irrelevant port (not in the
/// shared set) leaves the overlap untouched, and only a negation naming the
/// shared port itself disqualifies it. Non-numeric entries are ignored
/// (conservative).
pub(super) fn port_lists_overlap(a: &[String], b: &[String]) -> bool {
    let a_pos = parse_port_list(a);
    let b_pos = parse_port_list(b);
    let a_neg = parse_negated_port_list(a);
    let b_neg = parse_negated_port_list(b);
    a_pos
        .iter()
        .any(|port| b_pos.contains(port) && !a_neg.contains(port) && !b_neg.contains(port))
}

/// Parse the positive (non-negated) numeric entries of a `LocalPort` list.
pub(super) fn parse_port_list(values: &[String]) -> Vec<u32> {
    values
        .iter()
        .filter(|v| !v.starts_with('!'))
        .filter_map(|v| v.parse::<u32>().ok())
        .collect()
}

/// Parse the NEGATED (`!`-prefixed) numeric entries of a `LocalPort` list. Used
/// by [`port_lists_overlap`] to compute the negation-aware remainder (#403).
fn parse_negated_port_list(values: &[String]) -> Vec<u32> {
    values
        .iter()
        .filter_map(|v| v.strip_prefix('!'))
        .filter_map(|v| v.parse::<u32>().ok())
        .collect()
}

// ---- EXACT CIDR / port set algebra for the #409 per-sub-population region path ----
//
// The bool oracles above (`cidr_lists_overlap`, `port_lists_overlap`) decide only
// "do these two criteria share ANY address/port?". Per-sub-population shadow detection
// (#409) needs the actual SETS so an agreeing earlier block can CONSUME its covered
// sub-population (leaving only the genuinely-shadowed remainder to flag). These
// primitives compute those sets EXACTLY - `cidr_set_difference` splits multi-net
// carve-outs precisely rather than the single-negation approximation `cidr_lists_overlap`
// documents - so a region flag is always backed by a real remaining address/port.

/// A CIDR network as `(network address, prefix length)`. The network address's host
/// bits below `prefix` are assumed zero (as produced by [`parse_cidr_list`]).
pub(super) type Cidr = (IpAddr, u8);

/// The EXACT positive address set a single `Address`/`LocalAddress` value LIST denotes
/// under `match_pattern_list`: the union of its positive nets MINUS the union of its
/// negated (`!`) nets, normalized to pairwise-disjoint CIDR nets. Unlike the
/// single-negation approximation in [`cidr_lists_overlap`], multi-net carve-outs are
/// split precisely, so the #409 region path flags only against a real remaining
/// sub-population (FP-free). Unparseable entries are ignored (conservative).
#[must_use]
pub(super) fn cidr_list_set(values: &[String]) -> Vec<Cidr> {
    let positives = normalize_disjoint(parse_cidr_list(values));
    let negatives = parse_negated_cidr_list(values);
    cidr_set_difference(&positives, &negatives)
}

/// The intersection of two disjoint-normalized CIDR sets: every address in BOTH. CIDR
/// nets nest-or-are-disjoint, so two intersecting nets meet in the MORE specific
/// (longer-prefix) one. The result is disjoint-normalized.
#[must_use]
pub(super) fn cidr_set_intersection(a: &[Cidr], b: &[Cidr]) -> Vec<Cidr> {
    let mut out = Vec::new();
    for &x in a {
        for &y in b {
            if cidr_intersects(x, y) {
                out.push(if x.1 >= y.1 { x } else { y });
            }
        }
    }
    normalize_disjoint(out)
}

/// The set difference `a \ b`: every address in `a` but in no net of `b`. Each net of
/// `a` is split around every net of `b` via [`cidr_minus_one`], yielding a union of
/// disjoint CIDR nets. This EXACT carve-out is what the #409 region path consumes so an
/// agreeing earlier block removes its covered sub-population and cannot over-flag.
#[must_use]
pub(super) fn cidr_set_difference(a: &[Cidr], b: &[Cidr]) -> Vec<Cidr> {
    let mut current = a.to_vec();
    for &hole in b {
        let mut next = Vec::new();
        for net in current {
            next.extend(cidr_minus_one(net, hole));
        }
        current = next;
    }
    current
}

/// The positive port set a `LocalPort` value list denotes: its positive numeric entries
/// minus its negated (`!`) ones. On sshd-valid input a `LocalPort` block is a SINGLETON
/// (a2port rejects comma-lists and negation), so this is normally one element; the set
/// form keeps the #409 region path uniform with CIDR without ever over-claiming.
#[must_use]
pub(super) fn port_set(values: &[String]) -> BTreeSet<u32> {
    let positives: BTreeSet<u32> = parse_port_list(values).into_iter().collect();
    let negations: BTreeSet<u32> = parse_negated_port_list(values).into_iter().collect();
    positives.difference(&negations).copied().collect()
}

/// Whether `outer` fully contains `inner`: a shorter-or-equal prefix that intersects.
/// (CIDR nets nest-or-are-disjoint, so an intersecting net with a `<=` prefix is a
/// supernet-or-equal of the other.)
fn cidr_contains(outer: Cidr, inner: Cidr) -> bool {
    outer.1 <= inner.1 && cidr_intersects(outer, inner)
}

/// Drop any net contained in another so the result is pairwise disjoint (and
/// deduplicated). Order-independent: a wider net subsumes every narrower net it covers.
fn normalize_disjoint(nets: Vec<Cidr>) -> Vec<Cidr> {
    let mut out: Vec<Cidr> = Vec::new();
    for net in nets {
        if out.iter().any(|&kept| cidr_contains(kept, net)) {
            continue;
        }
        out.retain(|&kept| !cidr_contains(net, kept));
        out.push(net);
    }
    out
}

/// `outer` minus the single net `hole`, as a union of disjoint CIDR nets. If `hole` is
/// disjoint from `outer`, `outer` is returned unchanged; if `hole` covers `outer`, the
/// result is empty; otherwise `outer` is bisected repeatedly, keeping the half that does
/// not contain `hole` and recursing into the half that does (standard CIDR range
/// subtraction on power-of-two boundaries). Recursion depth is bounded by the address
/// width (<=32 / <=128 splits), so it always terminates.
fn cidr_minus_one(outer: Cidr, hole: Cidr) -> Vec<Cidr> {
    if !cidr_intersects(outer, hole) {
        return vec![outer];
    }
    if cidr_contains(hole, outer) {
        return Vec::new();
    }
    // `outer` strictly contains `hole` (shorter prefix, intersecting), so it can split.
    let Some((low, high)) = cidr_split(outer) else {
        return vec![outer];
    };
    let mut out = Vec::new();
    for half in [low, high] {
        if cidr_contains(half, hole) {
            out.extend(cidr_minus_one(half, hole));
        } else {
            out.push(half);
        }
    }
    out
}

/// Bisect a CIDR net into its two `prefix + 1` halves, or `None` for a host route
/// (`/32` v4, `/128` v6) that cannot split. The low half keeps the network address; the
/// high half sets the top host bit. Split per family so no truncating cast is needed.
fn cidr_split(net: Cidr) -> Option<(Cidr, Cidr)> {
    match net.0 {
        IpAddr::V4(addr) => {
            if net.1 >= 32 {
                return None;
            }
            let child = net.1 + 1;
            let high = u32::from(addr) | (1u32 << (32 - child));
            Some(((net.0, child), (IpAddr::V4(Ipv4Addr::from(high)), child)))
        }
        IpAddr::V6(addr) => {
            if net.1 >= 128 {
                return None;
            }
            let child = net.1 + 1;
            let high = u128::from(addr) | (1u128 << (128 - child));
            Some(((net.0, child), (IpAddr::V6(Ipv6Addr::from(high)), child)))
        }
    }
}
