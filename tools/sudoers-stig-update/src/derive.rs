//! The owned comparison shape ([`DerivedControl`]) plus the two sides fed to
//! the drift diff: the DISA-XCCDF-derived table (built in [`crate::xccdf`])
//! and the shipped `rulesteward-sudoers` projection ([`code_table`]).
//!
//! Unlike `tools/sshd-stig-update` (per-directive value assertions dispatched
//! by [`rulesteward_sudoers::TargetVersion`]-shaped arrays of MANY controls),
//! sudo-W04's DISA half is exactly THREE fixed control families
//! ([`Family::Authenticate`], [`Family::PwFamily`], [`Family::TimestampTimeout`])
//! and the crate's own module doc says the resulting findings are
//! "version-agnostic" (one finding cites all three RHEL ids at once, no
//! `--target` rail). The comparison here is per-family, per-RHEL-product STIG
//! Rule id ONLY -- there is no per-directive VALUE assertion to derive (unlike
//! sshd's `OwnedValueRule`), since a W04 DISA control is "does this id still
//! match", not "does this keyword still require this value".

use rulesteward_sudoers::TargetVersion;

/// The three sudo-W04 DISA STIG control families (#551). Fixed and closed --
/// unlike sshd's per-directive keyword set (which grows/shrinks as DISA STIG
/// revisions add/remove directives), these three are a structural property of
/// `crates/rulesteward-sudoers/src/lints/stig.rs`'s `w04` check and do not
/// vary by RHEL product.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Family {
    /// `!authenticate` -- bypasses per-invocation re-authentication.
    Authenticate,
    /// `targetpw` / `rootpw` / `runaspw` -- ONE DISA Rule per product covers
    /// all three settings together (verified against the real DISA XCCDF at
    /// authoring time: the check-content greps `(rootpw|targetpw|runaspw)`
    /// and the fixtext defines all three `Defaults !xxxpw` lines under a
    /// single Rule id).
    PwFamily,
    /// `timestamp_timeout` -- a negative value never expires the sudo
    /// credential cache.
    TimestampTimeout,
}

impl Family {
    /// All three families, in the SAME order `stig.rs`'s `PW_FAMILY_CONTROLS` /
    /// `AUTHENTICATE_CONTROLS` / `TIMESTAMP_TIMEOUT_CONTROLS` list their
    /// RHEL-08/09/10 ids (an implementation detail of comparison ordering, not
    /// semantic significance).
    pub const ALL: [Family; 3] = [
        Family::Authenticate,
        Family::PwFamily,
        Family::TimestampTimeout,
    ];

    /// Stable string form, used in diagnostics and diff output.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Family::Authenticate => "authenticate",
            Family::PwFamily => "pw_family",
            Family::TimestampTimeout => "timestamp_timeout",
        }
    }
}

/// One derived sudo-W04 control row, normalized for comparison against the
/// shipped projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivedControl {
    /// Which of the three fixed families this row belongs to.
    pub family: Family,
    /// DISA V-number (the XCCDF `<Group id="...">`), e.g. `V-281208`.
    /// Populated by the XCCDF-derived side ([`crate::xccdf::parse_controls`]);
    /// the shipped [`code_table`] side leaves this empty (`stig.rs`'s
    /// `PW_FAMILY_CONTROLS` etc. carry no V-number, only the STIG Rule id
    /// citation) -- so [`diff_controls`] never compares this field.
    pub v_number: String,
    /// The STIG Rule id (the crate's citation string), e.g. `RHEL-10-600530`.
    /// This is the ONLY field [`diff_controls`] compares.
    pub rule_id: String,
    /// The DISA Rule's human-readable title, verbatim (e.g. "RHEL 10 must
    /// require users to reauthenticate for privilege escalation."). Populated
    /// by the XCCDF-derived side for display/diagnostic use only; empty on
    /// the [`code_table`] side (the crate's consts carry no title).
    pub title: String,
}

/// The shipped `rulesteward-sudoers` sudo-W04 DISA control-id table,
/// projected into the comparison shape, for ONE RHEL product. This is the
/// "code" side of the drift diff -- exactly 3 rows (one per [`Family`]).
///
/// # STUBBED (9j lane 6, RED phase, #551)
///
/// `crates/rulesteward-sudoers/src/lints/stig.rs`'s `PW_FAMILY_CONTROLS` /
/// `AUTHENTICATE_CONTROLS` / `TIMESTAMP_TIMEOUT_CONTROLS` consts are today
/// PRIVATE to that module (no `pub` keyword) -- unlike
/// `rulesteward_sshd::lints::stig::stig_baseline`, which `tools/sshd-stig-update`
/// already depends on and which IS `pub`, sudo-W04 has no public accessor yet
/// (nothing else in the crate currently needs one; these consts are consumed
/// only by `stig.rs`'s own `check_file` / `negated_weakening`). A GREEN
/// implementation must ALSO widen visibility in `stig.rs` (either `pub` the
/// three consts, or add a `pub fn w04_disa_controls(target: TargetVersion) ->
/// [(Family, &'static str); 3]`-shaped accessor) before this function can
/// return real data instead of `todo!()`. This is a cross-crate change outside
/// this lane's permitted edit surface (`tools/sudoers-stig-update/` + the root
/// `Cargo.toml` exclude list only), so it is left for the implementer phase.
///
/// The three consts are ordered `[RHEL-08, RHEL-09, RHEL-10]`; a correct
/// implementation indexes by `target` (`Rhel8` -> `[0]`, `Rhel9` -> `[1]`,
/// `Rhel10` -> `[2]`) for each of the three families, producing exactly 3 rows
/// with empty `v_number` / `title` (see the field docs on [`DerivedControl`]).
#[must_use]
pub fn code_table(_target: TargetVersion) -> Vec<DerivedControl> {
    todo!(
        "GREEN (#551): project stig.rs's PW_FAMILY_CONTROLS/AUTHENTICATE_CONTROLS/\
         TIMESTAMP_TIMEOUT_CONTROLS for `_target` into 3 DerivedControl rows; \
         requires widening their visibility in crates/rulesteward-sudoers/src/lints/stig.rs \
         first (see this fn's doc comment)"
    )
}

/// Human-readable diff of an `upstream` (XCCDF-derived) table against the
/// shipped `code` table, both keyed by [`Family`]. Empty result == no drift.
///
/// Compares ONLY `rule_id` (per the [`DerivedControl::rule_id`] doc: the code
/// side carries no `v_number` / `title` to compare). `-` a family in `code`
/// but absent from `upstream` (should never happen -- all 3 families are
/// always DISA-mandated -- but handled for completeness); `+` a family new in
/// `upstream` (ditto); `~` a changed STIG Rule id for a shared family (the
/// actual drift signal this tool exists to catch, including the #355
/// regression class -- two ids swapped between families still shows as TWO
/// `~` lines, one per affected family).
///
/// # STUBBED (9j lane 6, RED phase, #551)
///
/// See [`code_table`]'s doc comment for why the comparison side is not yet
/// real. This function's OWN logic (the diff itself) has no DISA-specific
/// decision-making -- it is a pure `Family`-keyed comparison, structurally
/// identical to `tools/sshd-stig-update/src/derive.rs::diff_controls` keyed by
/// keyword instead of `Family` -- but is left stubbed rather than implemented,
/// per this lane's "tests only, no implementation" scope.
#[must_use]
pub fn diff_controls(_upstream: &[DerivedControl], _code: &[DerivedControl]) -> Vec<String> {
    todo!(
        "GREEN (#551): Family-keyed diff of _upstream vs _code, comparing rule_id only; \
         mirror tools/sshd-stig-update/src/derive.rs::diff_controls's shape, keyed by \
         Family instead of keyword"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctl(family: Family, v: &str, rule_id: &str, title: &str) -> DerivedControl {
        DerivedControl {
            family,
            v_number: v.to_string(),
            rule_id: rule_id.to_string(),
            title: title.to_string(),
        }
    }

    // -----------------------------------------------------------------------
    // `diff_controls` contract (pure unit tests, no fixture / no code_table
    // dependency -- these pin the SHAPE of the diff independent of the
    // cross-crate visibility gap `code_table` is blocked on).
    // -----------------------------------------------------------------------

    /// THE POSITIVE CONTROL (item 2 of the task): a changed STIG Rule id for a
    /// shared family MUST be reported as drift, naming BOTH the old (code) and
    /// new (upstream) id. A drift checker that only ever reports "0 drift" is
    /// worthless -- this proves the diff actually fires on a real mismatch.
    #[test]
    fn diff_controls_reports_a_changed_rule_id() {
        let code = vec![ctl(
            Family::Authenticate,
            "V-281208",
            "RHEL-10-600530",
            "RHEL 10 must require users to reauthenticate for privilege escalation.",
        )];
        let upstream = vec![ctl(
            Family::Authenticate,
            "V-281208",
            "RHEL-10-999999",
            "RHEL 10 must require users to reauthenticate for privilege escalation.",
        )];
        let diff = diff_controls(&upstream, &code);
        assert!(
            !diff.is_empty(),
            "a changed rule id for the SAME family must be reported as drift"
        );
        assert!(
            diff.iter()
                .any(|l| l.contains("RHEL-10-600530") && l.contains("RHEL-10-999999")),
            "the diff must name BOTH the stale (code) and new (upstream) ids; got {diff:?}"
        );
        assert!(
            diff.iter().any(|l| l.contains("authenticate")),
            "the diff must name the affected FAMILY, not just the ids; got {diff:?}"
        );
    }

    #[test]
    fn diff_controls_empty_when_identical() {
        let code = vec![
            ctl(Family::Authenticate, "V-1", "RHEL-10-600530", "t1"),
            ctl(Family::PwFamily, "V-2", "RHEL-10-600550", "t2"),
            ctl(Family::TimestampTimeout, "V-3", "RHEL-10-600540", "t3"),
        ];
        assert!(
            diff_controls(&code, &code).is_empty(),
            "an upstream table identical to the code table must report 0 drift"
        );
    }

    /// `diff_controls` ignores `v_number` / `title` differences -- only
    /// `rule_id` is compared (per `DerivedControl::rule_id`'s doc: the code
    /// side never carries a real `v_number` / `title` to compare against).
    #[test]
    fn diff_controls_ignores_v_number_and_title_differences() {
        let code = vec![ctl(
            Family::PwFamily,
            "V-OLD",
            "RHEL-10-600550",
            "old title",
        )];
        let upstream = vec![ctl(
            Family::PwFamily,
            "V-NEW",
            "RHEL-10-600550",
            "new title",
        )];
        assert!(
            diff_controls(&upstream, &code).is_empty(),
            "a v_number/title-only difference (same rule_id) must NOT be reported as drift"
        );
    }

    /// THE #355 REGRESSION CLASS (item 5 of the task): the historical incident
    /// this tool exists to prevent recurring was TWO controls' ids being
    /// SWAPPED with each other (the RHEL-08 `!authenticate` and pw-family ids
    /// were once accidentally exchanged). A permutation of the id SET across
    /// families must be caught as drift on BOTH affected families -- a diff
    /// that only checks "is the total set of ids unchanged" would miss this
    /// (the set IS unchanged, just relabeled), so this test simulates exactly
    /// that swap and requires TWO independent `~` lines, one per family.
    #[test]
    fn diff_controls_catches_two_ids_swapped_between_families() {
        let code = vec![
            ctl(Family::Authenticate, "V-1", "RHEL-08-010381", "auth title"),
            ctl(Family::PwFamily, "V-2", "RHEL-08-010383", "pw title"),
        ];
        // Simulate the #355 incident: authenticate and pw_family's ids traded
        // places (the SET {010381, 010383} is unchanged; only which family
        // owns which id changed).
        let swapped = vec![
            ctl(Family::Authenticate, "V-1", "RHEL-08-010383", "auth title"),
            ctl(Family::PwFamily, "V-2", "RHEL-08-010381", "pw title"),
        ];
        let diff = diff_controls(&swapped, &code);
        assert_eq!(
            diff.len(),
            2,
            "a two-way id swap between families must be reported as TWO drift lines \
             (one per affected family), not silently pass because the id SET is \
             unchanged; got {diff:?}"
        );
        assert!(
            diff.iter().any(|l| l.contains("authenticate")),
            "the authenticate family's drift must be reported; got {diff:?}"
        );
        assert!(
            diff.iter().any(|l| l.contains("pw_family")),
            "the pw_family family's drift must be reported; got {diff:?}"
        );
    }

    /// A family present in `upstream` but absent from `code` (or vice versa)
    /// is reported, not silently dropped -- mirrors sshd's `+`/`-` diff lines.
    #[test]
    fn diff_controls_reports_added_and_removed_families() {
        let code = vec![ctl(Family::Authenticate, "V-1", "RHEL-10-600530", "t")];
        let upstream = vec![ctl(Family::PwFamily, "V-2", "RHEL-10-600550", "t2")];
        let diff = diff_controls(&upstream, &code);
        assert!(
            diff.iter().any(|l| l.contains("authenticate")),
            "authenticate (in code, absent upstream) must be reported; got {diff:?}"
        );
        assert!(
            diff.iter().any(|l| l.contains("pw_family")),
            "pw_family (new in upstream, absent in code) must be reported; got {diff:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Family
    // -----------------------------------------------------------------------

    #[test]
    fn family_as_str_is_stable_and_distinct() {
        let strs: Vec<&str> = Family::ALL.iter().map(|f| f.as_str()).collect();
        assert_eq!(strs, ["authenticate", "pw_family", "timestamp_timeout"]);
    }
}
