//! Predicate comparison over `-F` values: `implies` (au-W02 subsumption, #219),
//! `disjoint` (au-W03 suppression, #219/#228), and the interval/bitmask/exact
//! helpers both rest on. Split out of `value.rs` (#438); see the parent
//! `value` module doc for the overall design.

use crate::ast::{CompareOp, FieldFilter};
use crate::lints::field_type::{FieldType, field_type};

use super::LintOptions;
use super::canonical::canonical_value;
use super::classify::{FieldValue, classify};
use super::msgtype::msgtype_resolved_number;

/// True when the later predicate `pl` IMPLIES the earlier predicate `pe`: every
/// value matching `pl` also matches `pe` (so `pl`'s matched set is a subset of
/// `pe`'s, i.e. `pe` is at least as broad). Both predicates must be on the same
/// field. Used by au-W02 subsumption (#219): the earlier rule subsumes the
/// later one when every earlier predicate is implied by a later predicate.
///
/// Conservative: returns true only for provable implication; any unsupported
/// operator pairing returns false (a false negative, never a false positive).
#[must_use]
pub fn implies(pe: &FieldFilter, pl: &FieldFilter, opts: LintOptions) -> bool {
    if pe.field != pl.field {
        return false;
    }
    let ft = field_type(&pe.field);
    // I0: identical operator and folded-equal value. Covers Eq, Ne, the bitmask
    // ops, and exact relational, and folds the uid/gid sentinel spellings, so
    // au-W02 agrees with au-W01 on value identity.
    if pe.op == pl.op
        && canonical_value(ft, &pe.value, opts) == canonical_value(ft, &pl.value, opts)
    {
        return true;
    }
    // Otherwise pl implies pe iff pl's matched interval is contained in pe's.
    // interval() yields None for Ne/bitmask/opaque/sentinel operands, so those
    // reach implication ONLY through the exact I0 case above (conservative).
    match (interval(ft, pe), interval(ft, pl)) {
        (Some((elo, ehi)), Some((llo, lhi))) => elo <= llo && lhi <= ehi,
        _ => false,
    }
}

/// True when two same-field predicates are PROVABLY non-co-matching: no single
/// event value can satisfy both. Used by au-W03 (#219, #228) to prove two rules
/// cannot overlap. Conservative: returns true only when provable; on any doubt
/// returns false (the rules are then treated as overlapping, keeping the
/// suppression warning).
///
/// Provable cases:
/// * Eq vs Eq: contradict iff [`eq_values_provably_differ`].
/// * Eq vs Ne (#228): `f=k` and `f!=k'` contradict iff k provably equals k'
///   ([`eq_values_provably_equal`]); the Eq value is exactly what Ne excludes.
/// * Eq vs bitmask (#228): the Eq value pins the field, so the mask test is
///   decidable - `=k` vs `&m` iff `k & m == 0`; `=k` vs `&=m` iff `k & m != m`
///   (both operands must be concrete unsigned numbers).
/// * Relational/Eq pairs: non-overlapping concrete intervals, OR (#475 class
///   3) a sentinel Eq (uid/gid/sessionid `unset`/`-1`/`4294967295`) whose
///   fixed numeric position (`u32::MAX`) falls outside the relational's
///   matched interval ([`eq_sentinel_relational_disjoint`]) - a promotion
///   scoped to `disjoint()` only, never touching [`FieldValue::position`]/
///   [`interval`], which `implies()` (au-W02) also shares.
///
/// Cases that are NEVER provably disjoint (theorems, kept conservative -> false):
/// two bitmask predicates (always co-satisfiable by `m1 | m2`), Ne vs Ne (each
/// excludes one point, so they always intersect), and Ne/bitmask vs a relational
/// (the Ne/bitmask set has no interval). These fall through to the interval arm,
/// where Ne/bitmask yield `None`.
///
/// NOTE: for `msgtype` (#475), [`canonical_decides_value_identity`] returns
/// `true` ONLY when BOTH compared values independently resolve to a concrete
/// record-type number via [`msgtype_resolved_number`] (name lookup, then the
/// base-0 numeric fallback -- the same resolution `canonical_value` uses, so
/// the two can never disagree). This mirrors the real system: userspace
/// resolves a msgtype NAME to its number at rule-load time
/// (`audit_rule_fieldpair_data`, libaudit.c @ 3bfa048) and the kernel compares
/// only the resolved `u32` numbers at match time (`audit_comparator`,
/// auditfilter.c @ v6.6) -- so two spellings that resolve to the SAME number
/// (`msgtype=SYSCALL` and `msgtype=1300`) denote the identical kernel value and
/// must NOT be claimed disjoint, while two that resolve to DIFFERENT numbers
/// genuinely are. If EITHER side fails to resolve (an unrecognized name, or an
/// `AppArmor` name with `opts.include_apparmor` off), this stays conservative
/// (`false`) -- a bare canonical-STRING inequality is unsound here, since an
/// unresolved spelling and a resolved one can denote the identical value (see
/// the `value` module's #475 test-comment block for the concrete
/// counter-example). For every other operator pairing on `msgtype` (relational,
/// bitmask), this function is still fully conservative, exactly as before.
#[must_use]
pub fn disjoint(pa: &FieldFilter, pb: &FieldFilter, opts: LintOptions) -> bool {
    if pa.field != pb.field {
        return false;
    }
    let ft = field_type(&pa.field);
    match (&pa.op, &pb.op) {
        // Eq vs Eq: one event carries one value per field, so two equalities
        // contradict iff their values are PROVABLY different kernel values.
        (CompareOp::Eq, CompareOp::Eq) => eq_values_provably_differ(ft, &pa.value, &pb.value, opts),
        // Eq vs Ne (either order, #228): contradict iff the Eq value provably
        // equals the value Ne excludes.
        (CompareOp::Eq, CompareOp::Ne) | (CompareOp::Ne, CompareOp::Eq) => {
            eq_values_provably_equal(ft, &pa.value, &pb.value, opts)
        }
        // Eq vs bitmask (either order, #228): `&` matches iff (value & mask) != 0,
        // `&=` matches iff (value & mask) == mask. With the value pinned by Eq the
        // test is decidable; helpers take (eq, mask) so the order is normalized.
        (CompareOp::Eq, CompareOp::BitAnd) => eq_bitand_disjoint(ft, &pa.value, &pb.value),
        (CompareOp::BitAnd, CompareOp::Eq) => eq_bitand_disjoint(ft, &pb.value, &pa.value),
        (CompareOp::Eq, CompareOp::BitAndEq) => eq_bitandeq_disjoint(ft, &pa.value, &pb.value),
        (CompareOp::BitAndEq, CompareOp::Eq) => eq_bitandeq_disjoint(ft, &pb.value, &pa.value),
        // Eq vs relational (either order, #475 class 3): a sentinel Eq
        // (uid/gid/sessionid unset/-1/4294967295) is provably disjoint from a
        // same-field relational predicate whenever the sentinel's fixed
        // numeric position falls outside the relational's matched interval
        // (see eq_sentinel_relational_disjoint's doc). This SHADOWS the
        // generic interval fallback below for this operator pairing, so both
        // arms OR in interval_disjoint to preserve the fallback's existing,
        // unrelated proof for a CONCRETE (non-sentinel) Eq value -- the
        // sentinel helper declines (returns false) for a concrete Eq, and the
        // `||` lets the fallback still decide those cases exactly as before.
        (CompareOp::Eq, CompareOp::Ge | CompareOp::Gt | CompareOp::Le | CompareOp::Lt) => {
            eq_sentinel_relational_disjoint(ft, &pa.value, &pb.op, &pb.value)
                || interval_disjoint(ft, pa, pb)
        }
        (CompareOp::Ge | CompareOp::Gt | CompareOp::Le | CompareOp::Lt, CompareOp::Eq) => {
            eq_sentinel_relational_disjoint(ft, &pb.value, &pa.op, &pa.value)
                || interval_disjoint(ft, pa, pb)
        }
        // Otherwise prove disjointness only via non-overlapping concrete
        // intervals. Ne/bitmask/opaque/sentinel yield None -> not provably
        // disjoint -> overlap (this is where the conservative theorems land).
        _ => interval_disjoint(ft, pa, pb),
    }
}

/// The generic interval-overlap fallback for `disjoint()`: PROVABLY disjoint
/// iff both predicates resolve to a concrete `i128` interval and those
/// intervals do not overlap. `Ne`/bitmask/opaque/sentinel operands yield
/// `None` from [`interval`] -> conservative `false` (not provably disjoint).
/// Factored out so the new sentinel-vs-relational arms above can fall back to
/// it (via `||`) for the concrete-Eq case they do not decide themselves.
fn interval_disjoint(ft: FieldType, pa: &FieldFilter, pb: &FieldFilter) -> bool {
    match (interval(ft, pa), interval(ft, pb)) {
        (Some((alo, ahi)), Some((blo, bhi))) => ahi < blo || bhi < alo,
        _ => false,
    }
}

/// The concrete unsigned value of `raw` under `ft`, or `None` if it is not a
/// concrete unsigned number (so the bitmask relations decline -> conservative).
fn as_u64(ft: FieldType, raw: &str) -> Option<u64> {
    match classify(ft, raw) {
        FieldValue::Unsigned(n) => Some(n),
        _ => None,
    }
}

/// True when `=k` and `&m` cannot co-match (#228): the single value `k` fails the
/// bit-mask test `(k & m) != 0`, i.e. `k & m == 0`. Both must be concrete
/// unsigned; otherwise conservative (false).
fn eq_bitand_disjoint(ft: FieldType, eq: &str, mask: &str) -> bool {
    match (as_u64(ft, eq), as_u64(ft, mask)) {
        (Some(k), Some(m)) => k & m == 0,
        _ => false,
    }
}

/// True when `=k` and `&=m` cannot co-match (#228): the single value `k` fails
/// the bit-test `(k & m) == m`, i.e. `k & m != m`. Both must be concrete
/// unsigned; otherwise conservative (false).
fn eq_bitandeq_disjoint(ft: FieldType, eq: &str, mask: &str) -> bool {
    match (as_u64(ft, eq), as_u64(ft, mask)) {
        (Some(k), Some(m)) => k & m != m,
        _ => false,
    }
}

/// The uid/gid/sessionid unset sentinel's fixed numeric position: `u32::MAX`,
/// i.e. `(uid_t)-1` (uapi audit.h `AUDIT_UID_UNSET`). Kept LOCAL to this
/// disjointness helper (never fed into [`FieldValue::position`]/[`interval`],
/// which `implies()` also shares) so the promotion cannot leak into au-W02
/// subsumption reasoning (#475 class 3 grounding, section 5a).
const SENTINEL_POSITION: i128 = 4_294_967_295; // u32::MAX

/// True when a sentinel `Eq` (uid/gid/sessionid `unset`/`-1`/`4294967295`) and
/// a same-field relational predicate cannot co-match (#475 class 3): the
/// kernel's `audit_uid_comparator`/`audit_gid_comparator`
/// (`uid_lt`/`uid_gte`/etc, `include/linux/uidgid.h` @ v6.6) and plain
/// `audit_comparator` (`auditsc.c:542-545`, `SessionId`) do RAW numeric
/// comparison with NO special-casing for the invalid/unset value, so the
/// sentinel occupies exactly position `u32::MAX` on the number line like any
/// other value. Both operands must resolve: `eq` to
/// [`FieldValue::UidGidUnset`], `rel_val` to a concrete orderable position (a
/// NAME, opaque value, or the sentinel spelling on the relational side stays
/// conservative -> declines, returning `false`).
fn eq_sentinel_relational_disjoint(
    ft: FieldType,
    eq: &str,
    rel_op: &CompareOp,
    rel_val: &str,
) -> bool {
    if classify(ft, eq) != FieldValue::UidGidUnset {
        return false;
    }
    let Some(p) = classify(ft, rel_val).position() else {
        return false; // symbolic/opaque/also-sentinel relational value: stay conservative
    };
    // Only an UPPER-bounded range can exclude the sentinel: a concrete
    // uid/gid/sessionid position `p` caps at 4294967294 (u32::MAX itself folds
    // to the sentinel, so it never reaches here as a concrete `p`), so the
    // sentinel at u32::MAX sits strictly ABOVE every `p`. A LOWER-bounded range
    // (Ge/Gt) therefore always contains the sentinel -> never disjoint; and the
    // symmetric "sentinel below the lower bound" case is impossible since
    // nothing exceeds u32::MAX. So only Le/Lt can prove disjointness, via their
    // upper bound `hi`.
    let hi: i128 = match rel_op {
        CompareOp::Le => p,
        CompareOp::Lt => p - 1,
        _ => return false,
    };
    hi < SENTINEL_POSITION
}

/// Whether two `=`/`!=` values on field `ft` can be decided same-vs-different
/// from their canonical spelling alone: both concrete-comparable (a numeric value
/// or the uid/gid sentinel), a free-form exact-match string field
/// ([`FieldType::String`]/[`FieldType::StringEqNe`]/[`FieldType::Key`]: path, dir,
/// exe, subj_*, obj_*, key), OR (#475) `msgtype` when BOTH values independently
/// resolve to a concrete record-type number ([`msgtype_resolved_number`]).
/// Alias-bearing fields where one spelling can denote the same value as another
/// (uid/gid NAMES like `uid=root` == `uid=0`; `arch=b64` == `arch=x86_64`;
/// filetype/fstype symbolic names) are otherwise NOT decidable from a spelling,
/// so this returns false and the caller stays conservative (never DROPS a real
/// au-W03 suppression warning). The `msgtype` exception is sound specifically
/// because it gates on RESOLUTION, not on raw spelling equality/inequality --
/// see [`disjoint`]'s doc NOTE for why a naive string-inequality shortcut would
/// be unsound here.
fn canonical_decides_value_identity(ft: FieldType, a: &str, b: &str, opts: LintOptions) -> bool {
    let comparable = |v: FieldValue| {
        matches!(
            v,
            FieldValue::Unsigned(_) | FieldValue::Signed(_) | FieldValue::UidGidUnset
        )
    };
    let both_concrete = comparable(classify(ft, a)) && comparable(classify(ft, b));
    let free_form = matches!(
        ft,
        FieldType::String | FieldType::StringEqNe | FieldType::Key
    );
    let msgtype_resolved = ft == FieldType::MsgType
        && msgtype_resolved_number(a, opts).is_some()
        && msgtype_resolved_number(b, opts).is_some();
    both_concrete || free_form || msgtype_resolved
}

/// True when two values on the same field are PROVABLY DIFFERENT kernel values
/// (e.g. `uid=0` vs `uid=1000`, `path=/a` vs `path=/b`). Decidable only when
/// [`canonical_decides_value_identity`] holds; otherwise false (conservative).
fn eq_values_provably_differ(ft: FieldType, a: &str, b: &str, opts: LintOptions) -> bool {
    canonical_decides_value_identity(ft, a, b, opts)
        && canonical_value(ft, a, opts) != canonical_value(ft, b, opts)
}

/// True when two values on the same field are PROVABLY the SAME kernel value (the
/// mirror of [`eq_values_provably_differ`]); used by au-W03 Eq-vs-Ne
/// disjointness (#228). Decidable only when [`canonical_decides_value_identity`]
/// holds; otherwise false (conservative).
///
/// `pub(super)`: only called internally by `disjoint` above, but also read
/// directly by `mod tests` in the parent `value::mod` via a `#[cfg(test)]`
/// import.
pub(super) fn eq_values_provably_equal(ft: FieldType, a: &str, b: &str, opts: LintOptions) -> bool {
    canonical_decides_value_identity(ft, a, b, opts)
        && canonical_value(ft, a, opts) == canonical_value(ft, b, opts)
}

/// The closed `i128` interval `[lo, hi]` of event values a predicate matches,
/// or `None` when the operand is not a concrete orderable number (`Ne`, the
/// bitmask ops, opaque values, and the uid/gid sentinel have no interval). The
/// half-line infinities use `i128::MIN`/`MAX`; real `u64`/`i64` values plus the
/// `+/-1` boundary adjustments stay well inside `i128`.
fn interval(ft: FieldType, p: &FieldFilter) -> Option<(i128, i128)> {
    let c = classify(ft, &p.value).position()?;
    match p.op {
        CompareOp::Eq => Some((c, c)),
        CompareOp::Ge => Some((c, i128::MAX)),
        CompareOp::Gt => Some((c + 1, i128::MAX)),
        CompareOp::Le => Some((i128::MIN, c)),
        CompareOp::Lt => Some((i128::MIN, c - 1)),
        CompareOp::Ne | CompareOp::BitAnd | CompareOp::BitAndEq => None,
    }
}
