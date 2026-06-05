//! End-to-end RED tests for `rulesteward selinux triage --policy <path>` (#124).
//!
//! These tests pin the OPERATOR-FACING behaviour of wiring the authoritative
//! libsepol categorizer (`rulesteward_selinux::categorize`) into the CLI via a
//! new `--policy <path>` flag, and flipping the `authoritative-categorizer`
//! cargo feature default-ON so the plain `cargo test -p rulesteward-cli` build
//! links libsepol and runs the categorize path.
//!
//! # Why these are RED before the implementation
//!
//! No `--policy` flag exists on `TriageArgs` yet (see `cli.rs` `TriageArgs`), and
//! `commands/selinux.rs::triage` never calls `categorize`. So today:
//!   - `selinux triage --policy <x>` fails with a clap "unexpected argument"
//!     error (exit 2), so every `.success()` + authoritative-output assertion
//!     below FAILS = the watched-it-fail RED state.
//!
//! Post-impl they flip GREEN: the flag parses, the authoritative replay runs,
//! and the output reflects the authoritative `DenialKind`.
//!
//! # Grounding
//!
//! Every AVC line + its expected authoritative verdict is reused VERBATIM from
//! the selinux crate's barrier known-answer suite
//! (`crates/rulesteward-selinux/tests/known_answer_categorize.rs`), where each
//! `(scontext, tcontext, tclass, perm)` vector was confirmed by replaying it
//! through the real libsepol `sepol_compute_av_reason_buffer` (the f4b spike +
//! a throwaway musl `libsepol.a` probe). The binary policy fixtures
//! (`kat.policy`, `allow.policy`) are the same ones that suite loads.
//!
//! The human-renderer phrasings asserted below are grounded in
//! `crates/rulesteward-selinux/src/triage.rs` (the `triage_group` match arms):
//!   - `DenialKind::Constraint`   => "The authoritative policy analysis shows
//!     this is not a TE allow gap - a constrain or mlsconstrain statement
//!     blocked the access." (triage.rs ~line 247-256)
//!   - `DenialKind::RoleSuspected` (the record-only FLOOR verdict for the same
//!     record) => "an RBAC role constraint is likely responsible ..."
//!     (triage.rs ~line 233-242)
//!
//! The phrase "authoritative policy analysis" appears ONLY in the authoritative
//! `Constraint` and `Bounds` arms, never in any record-only floor arm (verified:
//! 2 occurrences total in triage.rs). That phrase is therefore the load-bearing
//! proof that the `--policy` replay actually ran.
//!
//! # Integration-gate note (NOT a cargo test)
//!
//! The orchestrator verifies at the integration gate that the default release
//! binary actually statically links libsepol, i.e.
//!   `nm -D <release-binary> | grep sepol_ | wc -l` > 0
//! That symbol-presence check cannot be expressed as an in-process cargo test
//! (we cannot `nm` the just-built release binary from inside the test harness),
//! so it is intentionally omitted here and left to the gate.

use std::path::PathBuf;

use assert_cmd::Command;
use predicates::prelude::*;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// Path to a binary `SELinux` policy fixture shared with the selinux crate's
/// known-answer suite. The fixtures live in the sibling `rulesteward-selinux`
/// crate (single source of truth - they are real binary policies built with
/// `secilc`, not hand-rolled), referenced relative to this crate's manifest dir.
fn selinux_fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("rulesteward-selinux")
        .join("tests")
        .join("fixtures")
        .join(name)
}

/// Write `contents` to a temp file and return the guard (keeps the file alive
/// for the duration of the test).
fn write_record(contents: &str) -> tempfile::NamedTempFile {
    use std::io::Write;
    let mut f = tempfile::NamedTempFile::new().expect("create temp AVC record file");
    f.write_all(contents.as_bytes())
        .expect("write AVC record contents");
    f.flush().expect("flush AVC record file");
    f
}

// ---------------------------------------------------------------------------
// AVC record fixtures (reused verbatim from known_answer_categorize.rs).
// ---------------------------------------------------------------------------

/// Role constraint: `r_a/src_t -> r_b/src_t : process { dyntransition }`.
///
/// The kat policy TE-ALLOWS this access but a `(constrain (process
/// (dyntransition)) (eq r1 r2))` blocks it (`r_a != r_b`). Authoritative replay
/// against `kat.policy` => reason bit 0x2 (`SEPOL_COMPUTEAV_CONS`) =>
/// `DenialKind::Constraint`.
///
/// The record-only FLOOR classifier, with NO policy, sees only the record:
/// equal levels (`s0:c0.c1` both), different roles (`r_a` vs `r_b`), target role
/// not `object_r` => `DenialKind::RoleSuspected`. So the floor and the
/// authoritative verdict DIVERGE on this exact record - that divergence is what
/// proves the `--policy` path ran.
const AVC_ROLE_CONSTRAINT: &str = r#"type=AVC msg=audit(1700000000.003:1003): avc:  denied  { dyntransition } for  pid=1003 comm="probe" scontext=u1:r_a:src_t:s0:c0.c1 tcontext=u1:r_b:src_t:s0:c0.c1 tclass=process permissive=0"#;

/// reason==0 (D8): `src_t -> tgt_t : file { read }` against `allow.policy`, which
/// EXPLICITLY ALLOWS the access. libsepol returns reason bitmask 0. Per locked
/// decision #122 this "the supplied policy already allows the host-denied access"
/// sub-case must produce a DISTINCT operator message from a true bad-context
/// (BADSCON) sub-case.
const AVC_REASON_ZERO: &str = r#"type=AVC msg=audit(1700000000.006:1006): avc:  denied  { read } for  pid=1006 comm="probe" scontext=u1:r_a:src_t:s0:c0.c1 tcontext=u1:r_a:tgt_t:s0:c0.c1 tclass=file permissive=0"#;

// ---------------------------------------------------------------------------
// Round-2 fixtures (heterogeneous group + permissive --policy).
// ---------------------------------------------------------------------------

/// MLS constraint record, reused VERBATIM from the selinux crate's barrier KAT
/// (`known_answer_categorize.rs` `AVC_MLS_CONSTRAINT`; grounded by
/// `kat_mls_constraint_is_constraint`): `src_t(s0) -> tgt_t(s1) : file { read }`.
/// The access is TE-allowed (`allow src_t tgt_t (file (read open getattr))`) but
/// the kat `(mlsconstrain (file (read)) (dom l1 l2))` blocks it (s0 does NOT
/// dominate s1) -> libsepol reason bit 0x2 (`SEPOL_COMPUTEAV_CONS`) ->
/// `DenialKind::Constraint`. Grounded in the f4b MLS probe
/// (`f4b-selinux-libsepol-categorization-grounding.md` §6.1 "mls probe" row,
/// bits=0x2 CONSTRAINT; the byte-identical reason buffer at ~line 358).
const AVC_MLS_CONSTRAINT: &str = r#"type=AVC msg=audit(1700000000.002:1002): avc:  denied  { read } for  pid=1002 comm="probe" scontext=u1:r_a:src_t:s0:c0.c1 tcontext=u1:r_a:tgt_t:s1:c0.c1 tclass=file permissive=0"#;

/// TE-allowed (reason==0 / "already allows") TWIN of [`AVC_MLS_CONSTRAINT`] that
/// shares the SAME grouping triple `(src_t, tgt_t, file)`: identical except the
/// TARGET MLS level is `s0` (not `s1`). With both contexts at level `s0`, the
/// `(mlsconstrain (file (read)) (dom l1 l2))` is satisfied (`dom s0 s0` holds)
/// and the `allow src_t tgt_t (file (read ...))` permits the access, so libsepol
/// returns reason bitmask 0 (the "already allows" sub-case).
///
/// Grounded: confirmed by a throwaway `categorize_with_outcome` probe against
/// `kat.policy` -> `ReplayOutcome::Reason(0)` / `DenialKind::ContextInvalid`,
/// and confirmed to share the exact `(src_t, tgt_t, file)` triple with
/// `AVC_MLS_CONSTRAINT` (so the two land in ONE denial group). This twin is what
/// makes the heterogeneous-group bug observable: when this Reason(0) record is
/// the FIRST representative, the impl's single-synthetic-replay-per-group emits
/// "already allows" for the whole group, masking the actionable Constraint member.
const AVC_ALLOWED_SAME_TRIPLE: &str = r#"type=AVC msg=audit(1700000000.007:1007): avc:  denied  { read } for  pid=1007 comm="probe" scontext=u1:r_a:src_t:s0:c0.c1 tcontext=u1:r_a:tgt_t:s0:c0.c1 tclass=file permissive=0"#;

/// Permissive TE-gap denial: `src_t -> tgt_t : file { write }` with
/// `permissive=1`. Reused from the barrier KAT `AVC_TE` (grounded
/// `kat_te_gap_is_te_allowable`, libsepol reason bit 0x1) but flipped to
/// permissive. The kat policy does NOT allow `src_t tgt_t:file write` and no
/// constraint covers it, so the authoritative verdict is `TeAllowable` - and the
/// floor marks `any_permissive=true`. Under the round-2 f4-inv-6 reversal a
/// permissive denial MUST still get a suggested allow plus the PERMISSIVE-MODE
/// banner on the `--policy` (authoritative) path.
const AVC_TE_PERMISSIVE: &str = r#"type=AVC msg=audit(1700000000.001:1001): avc:  denied  { write } for  pid=1001 comm="probe" scontext=u1:r_a:src_t:s0:c0.c1 tcontext=u1:r_a:tgt_t:s0:c0.c1 tclass=file permissive=1"#;

/// Stable PERMISSIVE-MODE banner marker the impl MUST emit on any permissive
/// denial block, shared verbatim with the selinux crate's floor-path h-test
/// (`triage_render_human.rs` `PERMISSIVE_BANNER_MARKER`). Round-2 reversal of
/// f4 §2.5 invariant 6.
const PERMISSIVE_BANNER_MARKER: &str = "PERMISSIVE MODE:";

/// BADSCON: the source context names a type (`zzz_undefined_t`) that
/// `allow.policy` does not define, so `sepol_context_to_sid` fails. This is the
/// TRUE bad-context sub-case: the supplied policy genuinely does not define a
/// context in the denial (cross-host / cross-version mismatch).
const AVC_BADSCON: &str = r#"type=AVC msg=audit(1700000000.005:1005): avc:  denied  { read } for  pid=1005 comm="probe" scontext=u1:r_a:zzz_undefined_t:s0:c0.c1 tcontext=u1:r_a:tgt_t:s0:c0.c1 tclass=file permissive=0"#;

// ---------------------------------------------------------------------------
// Test 1: authoritative-override e2e
// ---------------------------------------------------------------------------

/// `selinux triage --record <role-constraint> --policy kat.policy` must run the
/// AUTHORITATIVE categorizer, not just the record-only floor.
///
/// Why a wrong impl fails: the chosen record is one where the floor verdict
/// (`RoleSuspected`) and the authoritative verdict (`Constraint`) DIVERGE. An
/// implementation that ignores `--policy` and renders the floor result would
/// emit the `RoleSuspected` "an RBAC role constraint is likely responsible"
/// wording and NOT the authoritative "The authoritative policy analysis shows
/// ... a constrain or mlsconstrain statement blocked the access" wording, so:
///   - the `contains("authoritative policy analysis")` assertion fails, AND
///   - the `not(contains("likely responsible"))` assertion fails.
///
/// Only an impl that actually loads `--policy` and replays the denial passes.
#[test]
fn triage_policy_runs_authoritative_categorizer() {
    let record = write_record(AVC_ROLE_CONSTRAINT);
    let policy = selinux_fixture("kat.policy");

    Command::cargo_bin("rulesteward")
        .expect("binary built")
        .args(["selinux", "triage", "--record"])
        .arg(record.path())
        .arg("--policy")
        .arg(&policy)
        .assert()
        .success()
        // Load-bearing: this phrase is emitted ONLY by the authoritative
        // Constraint/Bounds arms, never by any record-only floor arm. Its
        // presence proves the `--policy` replay produced the verdict.
        .stdout(predicate::str::contains("authoritative policy analysis"))
        // The record-only floor would have classified this record as
        // RoleSuspected and emitted "likely responsible". Asserting that
        // phrasing is ABSENT proves the floor verdict did NOT win.
        .stdout(predicate::str::contains("likely responsible").not());
}

// ---------------------------------------------------------------------------
// Test 2: Reason(0) distinct operator message (locked decision #122)
// ---------------------------------------------------------------------------

/// A denial whose access the supplied policy ALREADY ALLOWS (reason==0) must
/// produce a DISTINCT operator message that says the policy already permits the
/// access (a policy/host mismatch) - and that message must DIFFER from the true
/// bad-context (BADSCON) message.
///
/// Locked decision #122: NO new `DenialKind` variant (the enum is frozen at 7);
/// the distinction is in the operator-facing TEXT. Today both the reason==0 case
/// and the BADSCON case map to `DenialKind::ContextInvalid` and render the SAME
/// "the supplied policy does not define one of the security contexts" message,
/// so the two outputs are byte-identical (modulo the differing context strings).
///
/// Why a wrong impl fails (the distinction must be driven by the underlying
/// `ReplayOutcome`/reason bitmask, NOT by `DenialKind`, which stays frozen with
/// BOTH sub-cases mapping to `ContextInvalid`):
///
///   1. An impl that leaves both sub-cases mapped to the SAME untouched
///      `ContextInvalid` template fails: the reason==0 output lacks the distinct
///      "already allow" phrase (positive assertion A), and (separately) the
///      BADSCON output keeps the bad-context "does not define" phrase the
///      reason==0 output must NOT carry. A vacuous `assert_ne!` would NOT catch
///      this - the existing `{src}` interpolation already makes the two strings
///      unequal (`src_t` vs `zzz_undefined_t`) - so the assertions below are
///      POSITIVE and type-INDEPENDENT instead.
///   2. An impl that makes BOTH say "already allow" fails the BADSCON
///      `not(contains("already allow"))` assertion.
///   3. A lazy `strings <policy> | grep <scontext-type>` impl (W4) that never
///      runs the libsepol replay - emitting "already allows" iff the scontext
///      type appears in the policy text - is killed by the POSITIVE CONTROL: a
///      defined-context-but-CONSTRAINED record (`src_t` IS present in
///      `kat.policy`, so `strings|grep src_t` wrongly says "already allows") whose
///      real libsepol verdict is `Constraint`, not reason==0. Only a real replay
///      emits the authoritative Constraint wording and withholds "already allow".
#[test]
fn triage_policy_reason_zero_has_distinct_already_allows_message() {
    let policy = selinux_fixture("allow.policy");

    // (a) reason==0: the access is explicitly allowed by allow.policy.
    let allowed_record = write_record(AVC_REASON_ZERO);
    let allowed_out = Command::cargo_bin("rulesteward")
        .expect("binary built")
        .args(["selinux", "triage", "--record"])
        .arg(allowed_record.path())
        .arg("--policy")
        .arg(&policy)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let allowed_msg = String::from_utf8(allowed_out).expect("UTF-8 stdout (reason==0)");

    // (b) true bad-context: zzz_undefined_t is not defined in allow.policy.
    let badscon_record = write_record(AVC_BADSCON);
    let badscon_out = Command::cargo_bin("rulesteward")
        .expect("binary built")
        .args(["selinux", "triage", "--record"])
        .arg(badscon_record.path())
        .arg("--policy")
        .arg(&policy)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let badscon_msg = String::from_utf8(badscon_out).expect("UTF-8 stdout (BADSCON)");

    // -- Positive, type-INDEPENDENT discrimination (replaces the vacuous
    //    `assert_ne!`, which the incidental `{src}` interpolation alone already
    //    satisfied). Each message is pinned to its OWN #122-specific phrasing. --

    // (A) reason==0 MUST carry its distinct "already allow" phrasing. Matched on
    //     "already allow" so it is robust to "already allows" / "already allowed".
    //     A same-template impl (both sub-cases -> untouched ContextInvalid) lacks
    //     this phrase and FAILS here even though its two strings differ by `{src}`.
    assert!(
        allowed_msg.contains("already allow"),
        "the reason==0 sub-case must tell the operator the supplied policy \
         ALREADY ALLOWS the denied access (#122); got:\n{allowed_msg}"
    );
    // (A') reason==0 MUST NOT carry the bad-context phrasing. The current
    //      `ContextInvalid` template (triage.rs:294-302) says \"does not define\"
    //      one of the security contexts + \"invalid or unknown context\"; the
    //      reason==0 message must use neither (the contexts ARE defined).
    assert!(
        !allowed_msg.contains("does not define"),
        "the reason==0 (already-allows) message must NOT use the bad-context \
         \"does not define\" wording; both contexts ARE defined here. got:\n{allowed_msg}"
    );

    // (B) BADSCON MUST carry its OWN distinct bad-context phrase (verbatim from
    //     the unchanged `ContextInvalid` template, triage.rs:294-302) that the
    //     already-allows message does not. This is what makes the discriminator
    //     survive the incidental `{src}` difference: it pins the bad-context
    //     message to bad-context-specific wording, not just "not equal".
    assert!(
        badscon_msg.contains("does not define"),
        "the true bad-context (BADSCON) message must use the bad-context \
         \"does not define one of the security contexts\" wording; got:\n{badscon_msg}"
    );
    // (B') BADSCON MUST NOT claim the policy already allows the access - that
    //      would be the wrong explanation for an undefined context.
    assert!(
        !badscon_msg.contains("already allow"),
        "the true bad-context (BADSCON) message must NOT say the policy already \
         allows the access; that wording is reserved for the reason==0 sub-case. \
         got:\n{badscon_msg}"
    );

    // -- (C) POSITIVE CONTROL that kills the W4 `strings|grep <type>` shortcut. --
    //
    // `AVC_ROLE_CONSTRAINT`'s scontext type is `src_t`, which IS defined in
    // `kat.policy` (verified: `strings kat.policy | grep src_t` -> 1 hit). A lazy
    // impl that emits "already allows" whenever the scontext type appears in the
    // policy text (never running the real replay) would therefore WRONGLY say
    // "already allow" for this record. But the record's AUTHORITATIVE libsepol
    // verdict is `Constraint` (reason bit 0x2), grounded byte-identical against
    // the barrier KAT `kat_role_constraint_is_constraint`
    // (known_answer_categorize.rs:172-182). So a real replay emits the
    // authoritative Constraint wording and does NOT say "already allow".
    let constrained_record = write_record(AVC_ROLE_CONSTRAINT);
    let constrained_msg = {
        let out = Command::cargo_bin("rulesteward")
            .expect("binary built")
            .args(["selinux", "triage", "--record"])
            .arg(constrained_record.path())
            .arg("--policy")
            .arg(selinux_fixture("kat.policy"))
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        String::from_utf8(out).expect("UTF-8 stdout (Constraint control)")
    };
    // A `strings|grep src_t` impl says "already allow" here (type present) and
    // FAILS; only a real replay withholds it for a constrained access.
    assert!(
        !constrained_msg.contains("already allow"),
        "W4 trap: a CONSTRAINED access whose scontext type IS in the policy must \
         NOT be reported as 'already allows' - that is the reason==0-only phrasing. \
         A lazy strings|grep impl would wrongly emit it. got:\n{constrained_msg}"
    );
    // And it MUST reflect the authoritative Constraint verdict (the phrase emitted
    // ONLY by the authoritative Constraint/Bounds arms; triage.rs:247-256), proving
    // the real replay - not the shortcut - produced the message.
    assert!(
        constrained_msg.contains("authoritative policy analysis"),
        "the W4 control record must render the AUTHORITATIVE Constraint verdict \
         (proving the libsepol replay ran), not the reason==0 already-allows \
         message; got:\n{constrained_msg}"
    );
}

// ---------------------------------------------------------------------------
// Test 3 + 4: heterogeneous group (the grounded MISS from the round-2 review)
// ---------------------------------------------------------------------------
//
// THE BUG (impl-aware adversarial finding): `apply_authoritative_categorizer`
// (commands/selinux.rs) builds ONE synthetic AvcDenial per group from the FIRST
// matching denial's raw contexts and replays it ONCE. But `group_denials` groups
// by the `(source_type, target_type, tclass)` triple ONLY - it does NOT split on
// the MLS level / role components of the raw context. So two AVCs that share the
// triple but carry DIFFERENT contexts (here: differing target MLS levels - one
// TE-allowed Reason(0), one MLS-constraint-blocked) collapse into ONE group, and
// whichever record happens to be FIRST decides the single replay's verdict.
//
// When the TE-allowed (Reason 0) record is first, the whole group is rendered as
// "already allows", telling the operator the policy permits an access that is in
// fact BLOCKED for the constrained member - a dangerous false reassurance.
//
// INVARIANT PINNED: the output MUST NEVER tell the operator "policy already
// allows this" for a group that contains a non-Reason(0) (Constraint here)
// member; the authoritative verdict shown must reflect the ACTIONABLE
// (non-allowed) member. Both record orderings are tested to guard against an
// "is the first one constrained?" half-fix.
//
// Grounding:
//   - `AVC_MLS_CONSTRAINT` -> Constraint (reason 0x2): barrier KAT
//     `kat_mls_constraint_is_constraint` + f4b §6.1 MLS-probe row (~line 358).
//   - `AVC_ALLOWED_SAME_TRIPLE` -> Reason(0): throwaway categorize_with_outcome
//     probe against kat.policy; shares the (src_t,tgt_t,file) triple verbatim.

/// Run `selinux triage --audit-log <log> --policy kat.policy` on a two-record log
/// and return stdout as a String.
fn triage_audit_log_with_kat_policy(log_contents: &str) -> String {
    let log = write_record(log_contents);
    let out = Command::cargo_bin("rulesteward")
        .expect("binary built")
        .args(["selinux", "triage", "--audit-log"])
        .arg(log.path())
        .arg("--policy")
        .arg(selinux_fixture("kat.policy"))
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    String::from_utf8(out).expect("UTF-8 stdout (heterogeneous group)")
}

/// Heterogeneous group, Reason(0)-FIRST ordering: the TE-allowed record precedes
/// the MLS-constrained one. A naive single-synthetic-replay-per-group impl picks
/// the FIRST record's contexts (the allowed s0->s0 one), gets Reason(0), and
/// emits "already allows" for the whole group - the exact MISS this pins.
#[test]
fn triage_heterogeneous_group_reason_zero_first_must_not_say_already_allows() {
    // Order: ALLOWED (Reason 0) first, then the MLS-constrained member.
    let log = format!("{AVC_ALLOWED_SAME_TRIPLE}\n{AVC_MLS_CONSTRAINT}\n");
    let msg = triage_audit_log_with_kat_policy(&log);

    // The actionable member is MLS-constrained: the group must NOT be reported as
    // "already allows" (that masks a real, enforced block).
    assert!(
        !msg.contains("already allow"),
        "heterogeneous group (Reason(0) first): must NOT tell the operator the \
         policy 'already allows' a group that contains an MLS-constraint-blocked \
         member; the actionable verdict must win. got:\n{msg}"
    );
    // The authoritative verdict shown MUST reflect the Constraint member (the
    // phrase emitted ONLY by the authoritative Constraint/Bounds arms).
    assert!(
        msg.contains("authoritative policy analysis"),
        "heterogeneous group (Reason(0) first): the authoritative Constraint \
         verdict for the blocked member must be surfaced. got:\n{msg}"
    );
}

/// Symmetric variant - MLS-constrained record FIRST. Guards against an impl that
/// "fixes" the bug only when the constrained record happens to be the
/// representative (e.g. by reordering rather than replaying per record). The
/// invariant must hold regardless of input order.
#[test]
fn triage_heterogeneous_group_constrained_first_must_not_say_already_allows() {
    // Order: MLS-constrained member first, then the ALLOWED (Reason 0) one.
    let log = format!("{AVC_MLS_CONSTRAINT}\n{AVC_ALLOWED_SAME_TRIPLE}\n");
    let msg = triage_audit_log_with_kat_policy(&log);

    assert!(
        !msg.contains("already allow"),
        "heterogeneous group (constrained first): must NOT report 'already allows' \
         for a group containing an MLS-constraint-blocked member. got:\n{msg}"
    );
    assert!(
        msg.contains("authoritative policy analysis"),
        "heterogeneous group (constrained first): the authoritative Constraint \
         verdict must be surfaced. got:\n{msg}"
    );
}

// ---------------------------------------------------------------------------
// Test 5: permissive denial under --policy (round-2 f4-inv-6 reversal)
// ---------------------------------------------------------------------------
//
// SANCTIONED SPEC CHANGE: the user reversed f4 §2.5 invariant 6
// (`f4-selinux-triage-grounding.md` line 294-296). A `permissive=1` denial MUST
// now get a suggested allow PLUS a PERMISSIVE-MODE caveat banner - on BOTH the
// always-on floor path (covered by the selinux crate's `h4_*` h-test) AND this
// `--policy` authoritative path.
//
// `AVC_TE_PERMISSIVE` is a TE-gap (`src_t -> tgt_t : file write`, not allowed by
// kat.policy, no constraint) flipped to `permissive=1`. The authoritative
// categorizer IGNORES permissive (frozen `permissive_flag_is_ignored_by_categorizer`
// invariant) and returns `TeAllowable`; the floor records `any_permissive=true`.
// The output MUST carry both the narrow allow and the banner.

#[test]
fn triage_policy_permissive_emits_allow_with_banner() {
    let record = write_record(AVC_TE_PERMISSIVE);
    let policy = selinux_fixture("kat.policy");

    let out = Command::cargo_bin("rulesteward")
        .expect("binary built")
        .args(["selinux", "triage", "--record"])
        .arg(record.path())
        .arg("--policy")
        .arg(&policy)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let msg = String::from_utf8(out).expect("UTF-8 stdout (permissive --policy)");

    // The PERMISSIVE-MODE caveat banner MUST be present (round-2 reversal).
    assert!(
        msg.contains(PERMISSIVE_BANNER_MARKER),
        "permissive denial under --policy MUST carry the '{PERMISSIVE_BANNER_MARKER}' \
         banner (f4-inv-6 reversal); got:\n{msg}"
    );
    // A suggested allow MUST be emitted (no longer withheld for permissive).
    assert!(
        msg.contains("allow src_t tgt_t:file write;")
            || msg.contains("allow src_t tgt_t:file { write };"),
        "permissive denial under --policy MUST now get a suggested allow \
         (f4-inv-6 reversal); got:\n{msg}"
    );
}

// ---------------------------------------------------------------------------
// Test 6: failed --policy load -> non-zero exit (round-2 decision)
// ---------------------------------------------------------------------------
//
// DECISION (round-2): a `--policy` that cannot be loaded must FAIL LOUD, not
// silently fall back to the floor. `selinux triage --record <valid> --policy
// /nonexistent` MUST exit with the project's error code EXIT_ERRORS (2; see
// crates/rulesteward-cli/src/exit_code.rs). The run must stay read-only and not
// panic (clean non-zero exit, not an abort).
//
// Why RED today: `apply_authoritative_categorizer` currently logs a warning on a
// load failure and returns an empty set, and `triage` returns EXIT_CLEAN (0). So
// the `.code(2)` assertion fails (observed code is 0) = the watched-it-fail RED
// state.

/// The project's error exit code (spec §9.4). Mirrors
/// `rulesteward_cli::exit_code::EXIT_ERRORS`, which is crate-private to the cli
/// binary and so cannot be imported into an integration test; the literal is
/// pinned here with a citation so a drift in the constant is caught by review.
const EXIT_ERRORS: i32 = 2;

#[test]
fn triage_policy_load_failure_exits_nonzero() {
    let record = write_record(AVC_REASON_ZERO);
    // A path that does not exist - Policy::load must fail.
    let missing = selinux_fixture("definitely-nonexistent-policy.bin");
    assert!(
        !missing.exists(),
        "precondition: the fixture path must not exist"
    );

    Command::cargo_bin("rulesteward")
        .expect("binary built")
        .args(["selinux", "triage", "--record"])
        .arg(record.path())
        .arg("--policy")
        .arg(&missing)
        .assert()
        // Non-zero, specifically EXIT_ERRORS (2). A clean non-zero exit (NOT a
        // panic/abort): assert_cmd's `.failure()` would also accept a SIGABRT, so
        // pin the exact code to prove a graceful error path.
        .code(EXIT_ERRORS);
}
