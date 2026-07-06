//! `canonical_value`: the canonical spelling of a `-F` value, for content
//! identity (#220, #227, #230). Split out of `value.rs` (#438); see the
//! parent `value` module doc for the overall design.

use std::borrow::Cow;

use rulesteward_core::parse_base0_u64 as parse_u64_base0;

use crate::lints::field_type::FieldType;

use super::LintOptions;
use super::classify::{FieldValue, classify};
use super::msgtype::msgtype_number;

/// The canonical spelling of `raw` under `ft`, for content identity (#220, #227).
///
/// The uid/gid unset triple collapses to `"unset"`; concrete numerics
/// decimal-normalize (a value-preserving bijection); a `msgtype` symbolic name
/// folds to its record-type number (#227, so `SYSCALL` == `1300`); opaque values
/// keep their trimmed spelling. Equal canonical values mean the two predicates
/// match the same kernel value.
///
/// When `opts.include_apparmor` is true, `AppArmor` msgtype names
/// (`APPARMOR_DENIED`, etc.) are also folded to their numbers (1500-1507);
/// by default they are kept as-is (opaque) to preserve pre-#230 behaviour on
/// non-AppArmor audit daemons (#230).
#[must_use]
pub fn canonical_value(ft: FieldType, raw: &str, opts: LintOptions) -> Cow<'_, str> {
    // msgtype folds symbolic record-type names to their number (#227), so au-W01
    // (canonical_key) and au-W02 (implies I0) treat `msgtype=SYSCALL` and
    // `msgtype=1300` as one value. This is the ONLY place msgtype folds:
    // classify(MsgType) stays Opaque, so msgtype never enters interval reasoning
    // and au-W03 disjointness stays conservative for it.
    if ft == FieldType::MsgType {
        let t = raw.trim();
        if let Some(n) = msgtype_number(t, opts) {
            return Cow::Owned(n.to_string());
        }
        // A bare numeric spelling normalizes via base-0 (#229); an unknown name
        // or otherwise unparseable value keeps its trimmed spelling (opaque).
        return match parse_u64_base0(t) {
            Some(n) => Cow::Owned(n.to_string()),
            None => Cow::Borrowed(t),
        };
    }
    match classify(ft, raw) {
        FieldValue::UidGidUnset => Cow::Borrowed("unset"),
        // Decimal-normalize concrete numerics (a value-preserving bijection, so
        // it only ever merges spellings of the SAME number, never distinct ones).
        FieldValue::Unsigned(n) => Cow::Owned(n.to_string()),
        FieldValue::Signed(n) => Cow::Owned(n.to_string()),
        FieldValue::Opaque => Cow::Borrowed(raw.trim()),
    }
}
