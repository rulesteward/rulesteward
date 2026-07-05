//! Geometry and glob-matching toolkit shared by sshd-W07's Match-overlap oracle:
//! OpenSSH `match_pattern` globbing plus the CIDR / port set-overlap primitives.
//! Every item here is used only by [`super::w07`].

use std::net::IpAddr;

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
