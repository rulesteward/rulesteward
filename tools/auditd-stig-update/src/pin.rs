//! Upstream-pin staleness detection (#550): DISA publishes NO releases API, so
//! (unlike `tools/cis-update --latest`'s ComplianceAsCode github-releases query -
//! see `tools/stig-update/src/source.rs::latest_release`, which hits
//! `api.github.com/repos/.../releases/latest` and has nothing to do with DISA)
//! a stale pin cannot be discovered by asking for "latest". Every RHEL DISA
//! STIG is instead versioned by FILENAME in a `V<major>R<minor>` scheme (e.g.
//! the `V2R9` inside `U_RHEL_9_V2R9_STIG.zip`), so staleness is detected by
//! PROBING THE NEXT CANDIDATE filename: increment the minor; once a minor
//! probe 404s, roll the major over (reset minor to 1) and try once more; stop
//! the first time BOTH a minor-increment probe and a major-rollover probe
//! (from the last confirmed revision) come back 404.
//!
//! Rollover rule pinned by the tests below (grounded in the observed pin
//! history: `stig-refs.toml`'s rhel10 lineage began at `V1R1` and is now
//! `V1R2` - DISA starts a new major at minor 1): a major bump always resets
//! the minor to 1, and minor-incrementing resumes under the new major before
//! the next rollover is attempted (V2R9 -> V2R10? -> ... -> V3R1? -> V3R2? ->
//! ... -> V4R1?, stopping at the first pair of consecutive 404s).
//!
//! Byte-identical logic to `tools/sshd-stig-update/src/pin.rs` (the revision
//! scheme is generic, not sshd-specific - both tools draw their pins from the
//! same three DISA STIG documents, per this crate's `stig-refs.toml` comment);
//! kept as a separate copy so this tool has no dependency on the sshd
//! crate/tool, mirroring `config.rs`/`source.rs`'s existing duplication.
//!
//! CI must not depend on the network, so the "does this candidate zip exist"
//! check is abstracted behind [`Prober`]. The real implementation (a `curl`
//! HEAD-ish probe, mirroring `source.rs`'s `run`/`fetch_status` shape) belongs
//! beside the other live-network code and is exercised only by a live run, not
//! by unit tests (see `.cargo/mutants.toml`'s `source.rs` exclusion for the
//! established precedent this mirrors); [`find_latest`] and everything else in
//! this module is the offline-testable pure core, exercised below with a fake
//! `Prober` that never touches the network.
//!
//! Non-blocking by design (#550, Phase-0 justfile comment): a newer upstream
//! revision is NEWS, not a build failure - [`report`] exits `0` on every
//! branch, including [`PinStatus::Unavailable`] (e.g. `curl` missing), matching
//! the `sshd-stig-check-pin` / `auditd-stig-check-pin` recipes' existing
//! graceful-skip convention for a missing `curl` at the shell level.

/// Result of probing whether one candidate revision's zip exists at DISA's CDN.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Probe {
    /// HTTP 200 (or equivalent): the candidate zip exists.
    Found,
    /// HTTP 404 (or equivalent): the candidate zip does not exist.
    NotFound,
}

/// The prober itself could not run at all (e.g. `curl` is not installed) -
/// distinct from [`Probe::NotFound`], which means the prober DID run and got a
/// definitive 404.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeError(pub String);

/// Injected "does this candidate zip exist" check, so [`find_latest`] stays
/// offline-testable. The real implementation shells out to `curl`; tests
/// inject a fake that returns canned answers and records every URL asked
/// about, so the exact probe sequence is assertable.
pub trait Prober {
    /// Probe `url`. `Err` means the prober could not even attempt the check;
    /// `Ok(Probe::NotFound)` means it ran and got a definitive 404.
    fn probe(&mut self, url: &str) -> Result<Probe, ProbeError>;
}

/// A DISA STIG revision extracted from a pinned zip filename, e.g. `V2R9`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Revision {
    pub major: u32,
    pub minor: u32,
}

/// Outcome of a full staleness check against the pinned zip filename.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinStatus {
    /// No newer revision exists; the pin is current.
    Current,
    /// A newer revision exists (informational only - never a build failure).
    Newer { revision: Revision, zip: String },
    /// The prober could not run at all (e.g. `curl` missing); nothing checked.
    Unavailable(String),
}

/// Parse the `V<major>R<minor>` revision token out of a pinned zip filename
/// (e.g. `"U_RHEL_9_V2R9_STIG.zip"` -> `Revision { major: 2, minor: 9 }`).
/// `None` if no such token is present.
pub fn parse_revision(_zip: &str) -> Option<Revision> {
    todo!("lane 5 (#550) impl: extract V<major>R<minor> from the pinned zip filename")
}

/// Build the candidate zip filename for `rev`, substituting into `zip`'s own
/// `V<major>R<minor>` token and leaving every other character (the `U_RHEL_9_`
/// prefix, the `_STIG.zip` suffix) unchanged.
pub fn candidate_zip(_zip: &str, _rev: Revision) -> String {
    todo!("lane 5 (#550) impl: substitute a new V<major>R<minor> into the pinned filename")
}

/// Probe successive candidate revisions after the one pinned by `pinned_zip`,
/// incrementing the minor first; once a minor probe 404s, roll the major over
/// (reset minor to 1) and probe once more. Stops the first time BOTH a
/// minor-increment probe and a major-rollover probe (from the last confirmed
/// revision) come back 404. See the module doc for the full rollover rule.
pub fn find_latest(_base_url: &str, _pinned_zip: &str, _prober: &mut impl Prober) -> PinStatus {
    todo!("lane 5 (#550) impl: the next-candidate probe loop")
}

/// Render a staleness check to a human-readable message + process exit code.
/// Every branch exits `0` - a newer revision is news, not a build failure, and
/// an unavailable prober (e.g. missing `curl`) is a graceful skip, matching the
/// `*-stig-check-pin` justfile recipes' existing convention for a missing
/// `curl` at the shell level.
pub fn report(_product: &str, _status: &PinStatus) -> (String, u8) {
    todo!("lane 5 (#550) impl: format the check-pin message (exit code is always 0)")
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- parse_revision / candidate_zip: pure filename<->Revision plumbing ---

    #[test]
    fn parse_revision_extracts_major_and_minor() {
        assert_eq!(
            parse_revision("U_RHEL_9_V2R9_STIG.zip"),
            Some(Revision { major: 2, minor: 9 })
        );
        assert_eq!(
            parse_revision("U_RHEL_10_V1R2_STIG.zip"),
            Some(Revision { major: 1, minor: 2 })
        );
    }

    #[test]
    fn parse_revision_none_when_no_version_token_present() {
        assert_eq!(parse_revision("U_RHEL_9_STIG.zip"), None);
    }

    #[test]
    fn candidate_zip_bumps_minor_preserving_prefix_and_suffix() {
        assert_eq!(
            candidate_zip(
                "U_RHEL_9_V2R9_STIG.zip",
                Revision {
                    major: 2,
                    minor: 10
                }
            ),
            "U_RHEL_9_V2R10_STIG.zip"
        );
    }

    #[test]
    fn candidate_zip_bumps_major_and_resets_minor() {
        assert_eq!(
            candidate_zip("U_RHEL_9_V2R9_STIG.zip", Revision { major: 3, minor: 1 }),
            "U_RHEL_9_V3R1_STIG.zip"
        );
    }

    // --- find_latest: the injected-prober candidate-enumeration core ---------

    /// Records every URL probed, in order, and answers from a pre-programmed
    /// queue - a pure in-memory stand-in for the real `curl`-backed prober.
    /// Contains no `std::process::Command`/socket/file I/O of any kind, so a
    /// test built on it cannot touch the network: the ONLY way `find_latest`
    /// can learn "found" or "not found" is through the canned answers handed
    /// to this struct at construction time. This is the offline proof that
    /// #550's central constraint (CI must not depend on the network) holds -
    /// not merely asserted, but structurally guaranteed by what this type can
    /// and cannot do.
    struct FakeProber {
        answers: std::collections::VecDeque<Result<Probe, ProbeError>>,
        probed: Vec<String>,
    }

    impl FakeProber {
        fn new(answers: Vec<Result<Probe, ProbeError>>) -> Self {
            FakeProber {
                answers: answers.into(),
                probed: Vec::new(),
            }
        }
    }

    impl Prober for FakeProber {
        fn probe(&mut self, url: &str) -> Result<Probe, ProbeError> {
            self.probed.push(url.to_string());
            self.answers.pop_front().expect(
                "test bug: find_latest probed more URLs than the fake was programmed to answer",
            )
        }
    }

    const BASE_URL: &str = "https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip";
    const PINNED: &str = "U_RHEL_9_V2R9_STIG.zip";

    fn url_for(zip: &str) -> String {
        format!("{BASE_URL}/{zip}")
    }

    #[test]
    fn find_latest_reports_current_when_next_minor_and_major_rollover_both_404() {
        // V2R9 (pin) -> V2R10 404 -> V3R1 (rollover) 404 -> stop.
        let mut fake = FakeProber::new(vec![Ok(Probe::NotFound), Ok(Probe::NotFound)]);
        let status = find_latest(BASE_URL, PINNED, &mut fake);
        assert_eq!(status, PinStatus::Current, "no newer revision exists");
        assert_eq!(
            fake.probed,
            vec![
                url_for("U_RHEL_9_V2R10_STIG.zip"),
                url_for("U_RHEL_9_V3R1_STIG.zip"),
            ],
            "must probe the next minor, then the major rollover, and stop there \
             (exactly 2 probes - proves it does not probe unboundedly)"
        );
    }

    #[test]
    fn find_latest_several_successive_minors_then_stops_at_first_double_404() {
        // V2R9 (pin) -> V2R10 found -> V2R11 found -> V2R12 found -> V2R13
        // 404 -> V3R1 (rollover) 404 -> stop. Latest confirmed: V2R12.
        let mut fake = FakeProber::new(vec![
            Ok(Probe::Found),    // V2R10
            Ok(Probe::Found),    // V2R11
            Ok(Probe::Found),    // V2R12
            Ok(Probe::NotFound), // V2R13
            Ok(Probe::NotFound), // V3R1 rollover
        ]);
        let status = find_latest(BASE_URL, PINNED, &mut fake);
        assert_eq!(
            status,
            PinStatus::Newer {
                revision: Revision {
                    major: 2,
                    minor: 12
                },
                zip: "U_RHEL_9_V2R12_STIG.zip".to_string(),
            }
        );
        assert_eq!(
            fake.probed,
            vec![
                url_for("U_RHEL_9_V2R10_STIG.zip"),
                url_for("U_RHEL_9_V2R11_STIG.zip"),
                url_for("U_RHEL_9_V2R12_STIG.zip"),
                url_for("U_RHEL_9_V2R13_STIG.zip"),
                url_for("U_RHEL_9_V3R1_STIG.zip"),
            ],
            "must stop probing the instant BOTH the next minor and the major \
             rollover 404 - not keep incrementing minors under V2 forever, and \
             not keep trying further majors (V4R1, V5R1, ...) after V3R1 fails"
        );
    }

    #[test]
    fn find_latest_rolls_over_major_then_continues_probing_minors_under_new_major() {
        // V2R9 (pin) -> V2R10 404 (minor exhausted immediately) -> V3R1
        // (rollover) found -> V3R2 found -> V3R3 404 -> V4R1 (rollover) 404 ->
        // stop. Latest confirmed: V3R2. Pins the explicit rollover rule: a
        // major bump resets the minor to 1, and minor-incrementing resumes
        // under the new major before the next rollover is tried.
        let mut fake = FakeProber::new(vec![
            Ok(Probe::NotFound), // V2R10
            Ok(Probe::Found),    // V3R1 rollover
            Ok(Probe::Found),    // V3R2
            Ok(Probe::NotFound), // V3R3
            Ok(Probe::NotFound), // V4R1 rollover
        ]);
        let status = find_latest(BASE_URL, PINNED, &mut fake);
        assert_eq!(
            status,
            PinStatus::Newer {
                revision: Revision { major: 3, minor: 2 },
                zip: "U_RHEL_9_V3R2_STIG.zip".to_string(),
            }
        );
        assert_eq!(
            fake.probed,
            vec![
                url_for("U_RHEL_9_V2R10_STIG.zip"),
                url_for("U_RHEL_9_V3R1_STIG.zip"),
                url_for("U_RHEL_9_V3R2_STIG.zip"),
                url_for("U_RHEL_9_V3R3_STIG.zip"),
                url_for("U_RHEL_9_V4R1_STIG.zip"),
            ]
        );
    }

    #[test]
    fn find_latest_stops_after_one_probe_when_prober_is_unavailable() {
        // curl-absent case: the prober cannot even attempt the first probe.
        let mut fake = FakeProber::new(vec![Err(ProbeError("curl not found".to_string()))]);
        let status = find_latest(BASE_URL, PINNED, &mut fake);
        assert_eq!(status, PinStatus::Unavailable("curl not found".to_string()));
        assert_eq!(
            fake.probed,
            vec![url_for("U_RHEL_9_V2R10_STIG.zip")],
            "must stop at the FIRST unavailable probe, not retry or continue \
             to the major rollover"
        );
    }

    // --- report: the non-blocking exit-code contract -------------------------

    #[test]
    fn report_exits_0_when_pin_is_current() {
        let (msg, code) = report("rhel9", &PinStatus::Current);
        assert_eq!(code, 0);
        assert!(
            msg.to_lowercase().contains("current") || msg.to_lowercase().contains("no newer"),
            "message={msg:?}"
        );
    }

    #[test]
    fn report_exits_0_and_names_the_specific_revision_when_newer_exists() {
        let status = PinStatus::Newer {
            revision: Revision { major: 3, minor: 2 },
            zip: "U_RHEL_9_V3R2_STIG.zip".to_string(),
        };
        let (msg, code) = report("rhel9", &status);
        assert_eq!(
            code, 0,
            "a newer upstream revision is news, not a build failure - #550"
        );
        assert!(
            msg.contains("V3R2") || msg.contains("U_RHEL_9_V3R2_STIG.zip"),
            "message must name the specific newer revision; message={msg:?}"
        );
        assert!(
            msg.contains("rhel9"),
            "message must name the product; message={msg:?}"
        );
    }

    #[test]
    fn report_exits_0_with_clear_message_when_prober_unavailable() {
        let status = PinStatus::Unavailable("curl not found".to_string());
        let (msg, code) = report("rhel9", &status);
        assert_eq!(
            code, 0,
            "a missing curl must skip gracefully (exit 0), matching the \
             existing *-stig-check-pin recipes' shell-level convention"
        );
        assert!(
            msg.to_lowercase().contains("curl"),
            "message must explain why nothing was checked; message={msg:?}"
        );
    }
}
