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
