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
//!
//! # What this tool provably CANNOT see (not drift)
//!
//! [`diff_controls`] compares `rule_id` ONLY. A changed Rule `<title>`, a
//! changed `<Group>` V-number, or a changed `severity` attribute are NOT
//! drift signals this tool detects -- unlike `tools/sshd-stig-update`, whose
//! own `diff_controls` DOES compare `v_number` (its shipped projection
//! carries a real V-number per directive; sudo-W04's shipped consts carry
//! none). Only a changed STIG Rule id is drift here.

use rulesteward_sudoers::TargetVersion;
use rulesteward_sudoers::lints::stig::{
    AUTHENTICATE_CONTROLS, PW_FAMILY_CONTROLS, TIMESTAMP_TIMEOUT_CONTROLS,
};

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
    /// All three families. This array's own order (`Authenticate`,
    /// `PwFamily`, `TimestampTimeout`) is an arbitrary enumeration order with
    /// NO semantic significance -- it is NOT the order any committed fixture
    /// presents the families in (see `xccdf.rs`'s per-fixture document-order
    /// notes), and it is NOT necessarily `stig.rs`'s own `AUTHENTICATE_CONTROLS`
    /// / `PW_FAMILY_CONTROLS` / `TIMESTAMP_TIMEOUT_CONTROLS` const-declaration
    /// order either (each of those is independently ordered `[RHEL-08, RHEL-09,
    /// RHEL-10]` internally, unrelated to this array's family ordering).
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
/// # Cross-crate accessor (#551)
///
/// `crates/rulesteward-sudoers/src/lints/stig.rs`'s `PW_FAMILY_CONTROLS` /
/// `AUTHENTICATE_CONTROLS` / `TIMESTAMP_TIMEOUT_CONTROLS` consts were widened
/// to `pub` (the minimal legal change: the frozen `code_table_matches_stig_rs_
/// source_for_all_targets` oracle below anchors on `const {NAME}:` as a
/// substring, which still matches `pub const {NAME}:`) so this function can
/// read them directly instead of carrying a frozen copy.
///
/// The three consts are ordered `[RHEL-08, RHEL-09, RHEL-10]`; this indexes by
/// `target` (`Rhel8` -> `[0]`, `Rhel9` -> `[1]`, `Rhel10` -> `[2]`) for each of
/// the three families, producing exactly 3 rows with empty `v_number` /
/// `title` (see the field docs on [`DerivedControl`]).
#[must_use]
pub fn code_table(target: TargetVersion) -> Vec<DerivedControl> {
    let idx = match target {
        TargetVersion::Rhel8 => 0,
        TargetVersion::Rhel9 => 1,
        TargetVersion::Rhel10 => 2,
    };
    vec![
        DerivedControl {
            family: Family::Authenticate,
            v_number: String::new(),
            rule_id: AUTHENTICATE_CONTROLS[idx].1.to_string(),
            title: String::new(),
        },
        DerivedControl {
            family: Family::PwFamily,
            v_number: String::new(),
            rule_id: PW_FAMILY_CONTROLS[idx].1.to_string(),
            title: String::new(),
        },
        DerivedControl {
            family: Family::TimestampTimeout,
            v_number: String::new(),
            rule_id: TIMESTAMP_TIMEOUT_CONTROLS[idx].1.to_string(),
            title: String::new(),
        },
    ]
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
/// This function's own logic has no DISA-specific decision-making -- it is a
/// pure `Family`-keyed comparison, structurally identical to
/// `tools/sshd-stig-update/src/derive.rs::diff_controls` keyed by keyword
/// instead of `Family`.
#[must_use]
pub fn diff_controls(upstream: &[DerivedControl], code: &[DerivedControl]) -> Vec<String> {
    let mut out = Vec::new();
    for family in Family::ALL {
        let c = code.iter().find(|d| d.family == family);
        let u = upstream.iter().find(|d| d.family == family);
        match (c, u) {
            (Some(c), None) => out.push(format!(
                "- {} (in code, absent in the DISA XCCDF): {}",
                family.as_str(),
                c.rule_id
            )),
            (None, Some(u)) => out.push(format!(
                "+ {} = {} (new in the DISA XCCDF)",
                family.as_str(),
                u.rule_id
            )),
            (Some(c), Some(u)) => {
                if c.rule_id != u.rule_id {
                    out.push(format!(
                        "~ {} rule id: code {} -> DISA {}",
                        family.as_str(),
                        c.rule_id,
                        u.rule_id
                    ));
                }
            }
            (None, None) => {}
        }
    }
    out
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

    // -----------------------------------------------------------------------
    // BLOCKER 3 (adversarial round): `code_table` must be a genuine LIVE read
    // of the crate, never a copy frozen in this tool at authoring time -- the
    // exact internal-self-consistency defect #551 exists to remove.
    //
    // `code_table_matches_stig_rs_source_for_all_targets` reads
    // `crates/rulesteward-sudoers/src/lints/stig.rs`'s RAW source text via
    // `include_str!` (the SAME cross-tool technique
    // `tags.rs::w06_stig_drift_tests` already uses to keep sudo-W06 pinned
    // against sshd/auditd's `stig-refs.toml`) as an INDEPENDENT oracle,
    // extracted at every test run -- NOT a literal copy of the 9 ids frozen
    // here. If a future PR bumps `stig.rs`'s consts (a real STIG revision, or
    // a mistake) without updating `code_table`'s live read, this test's
    // oracle moves and `code_table`'s stale hardcoded copy is caught
    // immediately; a hardcoded copy that merely matches TODAY's ids cannot
    // pass this by coincidence once the source changes.
    //
    // `code_table_differs_across_all_three_targets` guards the OTHER half of
    // the same defect class: a `code_table` that ignores its `target`
    // argument (e.g. always returning RHEL-10's rows) would still pass every
    // single-target test in this crate if only one target were ever checked
    // end-to-end -- this asserts all three targets are PAIRWISE distinct.
    // -----------------------------------------------------------------------

    const STIG_RS_SOURCE: &str =
        include_str!("../../../crates/rulesteward-sudoers/src/lints/stig.rs");

    /// Extract the 3 quoted ids following `const {const_name}: [(Framework, &str); 3] = [`
    /// in `stig.rs`'s raw source text, in declaration order (index 0 = RHEL-08,
    /// 1 = RHEL-09, 2 = RHEL-10, per that file's own `PW_FAMILY_CONTROLS` /
    /// `AUTHENTICATE_CONTROLS` / `TIMESTAMP_TIMEOUT_CONTROLS` doc comments).
    fn extract_ids_from_stig_rs(const_name: &str) -> [String; 3] {
        let marker = format!("const {const_name}:");
        let after_const = STIG_RS_SOURCE
            .split_once(&marker)
            .unwrap_or_else(|| panic!("stig.rs must define `const {const_name}`"))
            .1;
        let after_eq = after_const
            .split_once(" = [")
            .unwrap_or_else(|| panic!("no ` = [` array literal after `const {const_name}`"))
            .1;
        let body = after_eq
            .split_once("];")
            .unwrap_or_else(|| panic!("no closing `];` for `const {const_name}`"))
            .0;
        let quoted: Vec<&str> = body.split('"').skip(1).step_by(2).collect();
        assert_eq!(
            quoted.len(),
            3,
            "`const {const_name}` must have exactly 3 quoted ids in its raw stig.rs source; \
             got {quoted:?}"
        );
        [
            quoted[0].to_string(),
            quoted[1].to_string(),
            quoted[2].to_string(),
        ]
    }

    #[test]
    fn code_table_matches_stig_rs_source_for_all_targets() {
        let auth_ids = extract_ids_from_stig_rs("AUTHENTICATE_CONTROLS");
        let pw_ids = extract_ids_from_stig_rs("PW_FAMILY_CONTROLS");
        let ts_ids = extract_ids_from_stig_rs("TIMESTAMP_TIMEOUT_CONTROLS");

        for (idx, target) in [
            TargetVersion::Rhel8,
            TargetVersion::Rhel9,
            TargetVersion::Rhel10,
        ]
        .into_iter()
        .enumerate()
        {
            let code = code_table(target);
            let auth = code
                .iter()
                .find(|c| c.family == Family::Authenticate)
                .unwrap_or_else(|| panic!("{target:?}: Authenticate row present"));
            let pw = code
                .iter()
                .find(|c| c.family == Family::PwFamily)
                .unwrap_or_else(|| panic!("{target:?}: PwFamily row present"));
            let ts = code
                .iter()
                .find(|c| c.family == Family::TimestampTimeout)
                .unwrap_or_else(|| panic!("{target:?}: TimestampTimeout row present"));

            assert_eq!(
                auth.rule_id, auth_ids[idx],
                "{target:?}: code_table's Authenticate rule_id must match stig.rs's \
                 AUTHENTICATE_CONTROLS[{idx}] read live from source, not a frozen copy"
            );
            assert_eq!(
                pw.rule_id, pw_ids[idx],
                "{target:?}: code_table's PwFamily rule_id must match stig.rs's \
                 PW_FAMILY_CONTROLS[{idx}] read live from source, not a frozen copy"
            );
            assert_eq!(
                ts.rule_id, ts_ids[idx],
                "{target:?}: code_table's TimestampTimeout rule_id must match stig.rs's \
                 TIMESTAMP_TIMEOUT_CONTROLS[{idx}] read live from source, not a frozen copy"
            );
        }
    }

    #[test]
    fn code_table_differs_across_all_three_targets() {
        let r8 = code_table(TargetVersion::Rhel8);
        let r9 = code_table(TargetVersion::Rhel9);
        let r10 = code_table(TargetVersion::Rhel10);
        assert_ne!(
            r8, r9,
            "code_table must not ignore its `target` argument -- rhel8 and rhel9 must differ"
        );
        assert_ne!(
            r9, r10,
            "code_table must not ignore its `target` argument -- rhel9 and rhel10 must differ"
        );
        assert_ne!(
            r8, r10,
            "code_table must not ignore its `target` argument -- rhel8 and rhel10 must differ"
        );
    }

    #[test]
    fn code_table_returns_exactly_three_rows_per_target() {
        for target in [
            TargetVersion::Rhel8,
            TargetVersion::Rhel9,
            TargetVersion::Rhel10,
        ] {
            assert_eq!(
                code_table(target).len(),
                3,
                "{target:?}: code_table must return exactly 3 rows (one per Family)"
            );
        }
    }
}
