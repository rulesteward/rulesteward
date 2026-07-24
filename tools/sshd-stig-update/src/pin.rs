//! Upstream-pin staleness detection (#550): DISA publishes NO releases API, so
//! (unlike `tools/cis-update --latest`'s ComplianceAsCode github-releases query -
//! see `tools/stig-update/src/source.rs::latest_release`, which hits
//! `api.github.com/repos/.../releases/latest` and has nothing to do with DISA)
//! a stale pin cannot be discovered by asking for "latest". Every RHEL DISA
//! STIG is instead versioned by FILENAME in a `V<major>R<minor>` scheme (e.g.
//! the `V2R9` inside `U_RHEL_9_V2R9_STIG.zip`).
//!
//! # Algorithm (adversarial-review rework, 2026-07-24)
//!
//! 1. Parse the pin's own `V<major>R<minor>` token. Unparseable ->
//!    [`PinStatus::Unparseable`], nothing probed (a config/typo problem, not
//!    a network one).
//! 2. Probe the PINNED zip's own URL FIRST, before enumerating any candidate
//!    (USER RULING). This is direct, convention-independent evidence: a live
//!    check (2026-07-24) found DISA's CDN retains only a WINDOW of revisions
//!    per product (`U_RHEL_8_V2R3..V2R8` returned 200; `V2R1`/`V2R2` already
//!    404). A pin that has aged past the low end of that window 404s on
//!    ITSELF - the OLD algorithm (probe next-minor first) could miss this
//!    entirely: if the next one or two minors are ALSO purged, "next-minor
//!    404, rollover 404" falsely reported `Current` while later revisions
//!    (e.g. V2R8) were live the whole time. A 404 on the pin itself needs no
//!    such inference, so it is checked first and reported as
//!    [`PinStatus::PinNotFound`] - explicitly NOT [`PinStatus::Current`].
//! 3. If the pin itself is live, enumerate forward: increment the minor;
//!    once a minor probe 404s, roll the major over (reset minor to 1) and
//!    probe once; if THAT is found, resume incrementing the minor under the
//!    new major before the next rollover is attempted. Stop the first time
//!    BOTH a minor-increment probe and the major-rollover probe (computed
//!    from the last CONFIRMED revision) come back 404 -> [`PinStatus::Current`]
//!    (if nothing beyond the pin was ever found) or [`PinStatus::Newer`]
//!    (naming the last confirmed revision).
//! 4. A hard ceiling ([`PROBE_CEILING`]) bounds the TOTAL number of probes
//!    per call, so a misbehaving prober (a captive portal / proxy answering
//!    HTTP 200 for every URL - DISA's own CDN returns clean hard 404s, per
//!    live verification) cannot loop forever; giving up reports
//!    [`PinStatus::Unavailable`].
//! 5. An `Err` from the prober at ANY probe position (not only the first)
//!    short-circuits immediately to [`PinStatus::Unavailable`] - a transient
//!    failure (DNS, TLS, timeout) partway through enumeration must never be
//!    folded into a 404-style "stop" and misreported as `Current`.
//!
//! ## The minor-then-major rollover rule is ASSUMED, not observed
//!
//! [`next_candidates`] pins the rule "a major bump resets the minor to 1,
//! then minor-incrementing resumes" - this is an ASSUMPTION about DISA's
//! versioning convention, not a fact verified against a live rollover. A live
//! check during this rework (2026-07-24) found DISA's CDN has already purged
//! every historical rollover boundary that could confirm or refute it:
//! `U_RHEL_8_V1R12`, `V1R13`, `U_RHEL_9_V1R1`, `U_RHEL_7_V3R1`, and the
//! non-RHEL benchmarks `U_Ubuntu_22-04_LTS_V2R1` / `U_MS_Windows_Server_2022_V2R1`
//! all 404 today - there is currently no way to observe an actual rollover on
//! the live CDN. If the assumption is wrong (e.g. DISA resets to R0, or does
//! not reset the minor at all), the consequence is bounded and ONE-SIDED:
//! `find_latest` reports `Current` one candidate later than it should (a
//! missed rollover probe) - it NEVER fabricates a false `Newer`/
//! `PinNotFound`, since those are only ever reported from a definitive 200 on
//! some concrete URL that was actually probed. If a real rollover is ever
//! observed, update `next_candidates`'s OWN tests (the one place this rule is
//! pinned - see that test's doc comment) rather than the loop tests that
//! consume it.
//!
//! Byte-identical logic (and tests, below) to the sister tool's `pin.rs` (the
//! revision scheme is generic, not tool-specific - both tools draw their pins
//! from the same three DISA STIG documents, per each crate's `stig-refs.toml`
//! comment); kept as a separate copy so neither tool depends on the other's
//! crate, mirroring `config.rs`/`source.rs`'s existing duplication. The
//! "cross-tool drift guard" test near the end of this file's `mod tests`
//! makes that byte-identical claim mechanical.
//!
//! CI must not depend on the network, so the "does this candidate zip exist"
//! check is abstracted behind [`Prober`]. The real implementation (a `curl`
//! HEAD-ish probe, mirroring `source.rs`'s `run`/`fetch_status` shape) belongs
//! beside the other live-network code and is exercised only by a live run, not
//! by unit tests (see `.cargo/mutants.toml`'s `source.rs` exclusion for the
//! established precedent this mirrors); everything in this module is the
//! offline-testable pure core, exercised below with a fake `Prober` that
//! never touches the network.
//!
//! Non-blocking by design (#550, Phase-0 justfile comment): a newer upstream
//! revision, and even a retired pin, are NEWS, not a build failure -
//! [`report`] exits `0` on every branch, matching the `sshd-stig-check-pin` /
//! `auditd-stig-check-pin` recipes' existing graceful-skip convention for a
//! missing `curl` at the shell level. The `check-pin` CLI subcommand (see
//! `tests/cli.rs`) must exit 0 for every `PinStatus`, including
//! `Unavailable` - `main.rs::run`'s `Result<ExitCode, String>` maps `Err` to
//! exit 2, so wiring `Unavailable` through that path would invert this
//! contract at the process boundary even if `report`'s own `u8` were correct.

/// Result of probing whether one candidate revision's zip exists at DISA's CDN.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Probe {
    /// HTTP 200 (or equivalent): the candidate zip exists.
    Found,
    /// HTTP 404 (or equivalent): the candidate zip does not exist.
    NotFound,
}

/// The prober itself could not run at all, or failed transiently (e.g. `curl`
/// missing, DNS/TLS/timeout) - distinct from [`Probe::NotFound`], which means
/// the prober DID run and got a definitive 404. An `Err` at ANY probe
/// position (not only the first) must short-circuit to
/// [`PinStatus::Unavailable`] - see the module doc, point 5.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeError(pub String);

/// Injected "does this candidate zip exist" check, so [`find_latest`] stays
/// offline-testable. The real implementation shells out to `curl`; tests
/// inject a fake that returns canned answers and records every URL asked
/// about, so the exact probe sequence is assertable.
pub trait Prober {
    /// Probe `url`. `Err` means the prober could not get a definitive answer;
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
    /// No newer revision exists; the pin (confirmed live) is current.
    Current,
    /// A newer revision exists (informational only - never a build failure).
    Newer { revision: Revision, zip: String },
    /// The PINNED zip itself 404d: direct, convention-independent evidence
    /// the pin has fallen out of DISA's CDN retention window. NOT `Current` -
    /// see the module doc, point 2, for why forward-guessing from here is
    /// deliberately NOT attempted.
    PinNotFound { pinned_zip: String },
    /// The pinned zip filename has no `V<major>R<minor>` token at all -
    /// nothing was probed (a config/typo problem, not a network one).
    Unparseable { pinned_zip: String },
    /// No definitive answer could be obtained: the prober errored (at any
    /// probe position) or [`PROBE_CEILING`] was hit without a 404.
    Unavailable(String),
}

/// Hard ceiling on the TOTAL number of probes (including the leading probe of
/// the pin itself) [`find_latest`] may issue in one call, so a misbehaving
/// prober (e.g. a captive portal or proxy that answers HTTP 200 for every
/// URL - DISA's own CDN returns clean hard 404s, per live verification)
/// cannot loop forever. Chosen generously above any plausible real STIG
/// revision drift (DISA STIGs move at most a handful of minors/majors between
/// this tool's monthly scheduled `check-pin` runs).
pub const PROBE_CEILING: usize = 64;

/// Parse the `V<major>R<minor>` revision token out of a pinned zip filename
/// (e.g. `"U_RHEL_9_V2R9_STIG.zip"` -> `Revision { major: 2, minor: 9 }`).
/// `None` if no such token is present.
pub fn parse_revision(_zip: &str) -> Option<Revision> {
    todo!("lane 5 (#550) impl: extract V<major>R<minor> from the pinned zip filename")
}

/// Build the candidate zip filename for `rev`, substituting into `zip`'s own
/// `V<major>R<minor>` token and leaving every other character (the
/// `U_RHEL_<n>_` prefix, the `_STIG.zip` suffix) unchanged.
pub fn candidate_zip(_zip: &str, _rev: Revision) -> String {
    todo!("lane 5 (#550) impl: substitute a new V<major>R<minor> into the pinned filename")
}

/// The two candidates tried immediately after `current` is confirmed to
/// exist: `.0` increments the minor; `.1` is the major-rollover fallback
/// (major + 1, minor reset to 1), tried only once `.0` 404s. Extracted so the
/// ASSUMED rollover rule (see the module doc) is pinned in exactly ONE place:
/// a future correction to the assumption touches this function's own tests,
/// not every `find_latest` loop test's literal `V3R1`/`V4R1` strings.
pub fn next_candidates(_current: Revision) -> (Revision, Revision) {
    todo!("lane 5 (#550) impl: (minor+1, same major) and (major+1, minor=1)")
}

/// Probe the pin itself, then successive candidates, per the module doc's
/// numbered algorithm.
pub fn find_latest(_base_url: &str, _pinned_zip: &str, _prober: &mut impl Prober) -> PinStatus {
    todo!("lane 5 (#550) impl: the pin-first, then next-candidate, probe loop")
}

/// Render a staleness check to a human-readable message + process exit code.
/// Every branch exits `0` - see the module doc's closing paragraph for why,
/// including why the CLI wiring (not just this function) must preserve it.
pub fn report(_product: &str, _status: &PinStatus) -> (String, u8) {
    todo!("lane 5 (#550) impl: format the check-pin message (exit code is always 0)")
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- parse_revision / candidate_zip / next_candidates: pure plumbing ---

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
        // #550 lane-5 round-2 rework, BLOCKER 1: every fixture above happens
        // to have a SINGLE-DIGIT minor, so a fixed-offset parse (e.g. byte
        // `i+1` for the major digit, `i+3` for the minor digit) passes both -
        // and, worse under the pin-first ruling, silently mis-parses any real
        // pin whose minor has rolled past 9 (e.g. the real rhel8 pin already
        // reads `V2R10`) into the WRONG revision, so `find_latest` probes a
        // URL it never intended to and can report an actionable false
        // `PinNotFound` against a pin that is actually current. A genuinely
        // multi-digit minor closes this.
        assert_eq!(
            parse_revision("U_RHEL_8_V2R10_STIG.zip"),
            Some(Revision {
                major: 2,
                minor: 10
            })
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

    #[test]
    fn candidate_zip_works_for_a_different_rhel_product_and_stig_major() {
        // #550 lane-5 rework, blocker 1: the two tests above only ever
        // exercise the RHEL_9 / STIG-major-2 lineage; an impl hardcoding
        // "U_RHEL_9_" or major==2 could still pass both. rhel10's real pin
        // (V1R2, a DIFFERENT STIG major and RHEL product) proves the
        // substitution is filename-driven, for both a minor bump and a
        // major rollover.
        assert_eq!(
            candidate_zip("U_RHEL_10_V1R2_STIG.zip", Revision { major: 1, minor: 3 }),
            "U_RHEL_10_V1R3_STIG.zip",
            "minor bump"
        );
        assert_eq!(
            candidate_zip("U_RHEL_10_V1R2_STIG.zip", Revision { major: 2, minor: 1 }),
            "U_RHEL_10_V2R1_STIG.zip",
            "major rollover"
        );
    }

    #[test]
    fn next_candidates_pins_the_assumed_rollover_rule() {
        // #550 lane-5 rework, concern raised in review: extracted so the
        // ASSUMED (not observed - see this file's module doc, "The
        // minor-then-major rollover rule is ASSUMED, not observed") rollover
        // rule is pinned in exactly ONE place. If the assumption is later
        // proven wrong, only THIS test + `next_candidates` change - not every
        // `find_latest` loop test's literal `V3R1`/`V4R1` strings.
        assert_eq!(
            next_candidates(Revision { major: 2, minor: 9 }),
            (
                Revision {
                    major: 2,
                    minor: 10
                }, // minor bump
                Revision { major: 3, minor: 1 }, // major rollover
            )
        );
        // A rollover from a DIFFERENT major/minor, to prove this isn't
        // hardcoded to the 2/9 pair used elsewhere in this file.
        assert_eq!(
            next_candidates(Revision { major: 1, minor: 2 }),
            (
                Revision { major: 1, minor: 3 },
                Revision { major: 2, minor: 1 },
            )
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

    /// A pathological prober that ALWAYS answers Found and never exhausts
    /// (unlike `FakeProber`'s queue, which panics when exhausted, so an
    /// always-Found scenario cannot even be expressed with it). The realistic
    /// trigger, per the reviewer's live measurement, is a captive portal or
    /// misconfigured proxy answering HTTP 200 for everything - NOT the DISA
    /// CDN itself, which returns clean hard 404s. Used ONLY to prove
    /// `find_latest` enforces its own [`PROBE_CEILING`].
    struct AlwaysFoundProber {
        probed: Vec<String>,
    }

    impl Prober for AlwaysFoundProber {
        fn probe(&mut self, url: &str) -> Result<Probe, ProbeError> {
            self.probed.push(url.to_string());
            // #550 lane-5 round-2 rework, CONCERN: a no-ceiling `find_latest`
            // would otherwise grow `probed` unboundedly and this test would
            // hang until CI kills it (or OOMs, which this repo's
            // cargo-mutants experience shows can present as a runner-kill
            // rather than a clean timeout - a fragile signal to gate a real
            // mutant on). Turn that hang into an immediate, diagnostic
            // failure well past any plausible correct stopping point.
            if self.probed.len() > PROBE_CEILING * 2 {
                panic!(
                    "find_latest issued {} probes, exceeding PROBE_CEILING ({PROBE_CEILING}) - \
                     it must stop at the ceiling, not loop unboundedly",
                    self.probed.len()
                );
            }
            Ok(Probe::Found)
        }
    }

    const BASE_URL: &str = "https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip";
    const PINNED: &str = "U_RHEL_9_V2R9_STIG.zip";

    fn url_for(zip: &str) -> String {
        format!("{BASE_URL}/{zip}")
    }

    #[test]
    fn find_latest_probes_the_pin_itself_first_then_reports_current() {
        // USER RULING: the pin's OWN zip is probed FIRST, before any
        // candidate enumeration - a direct, convention-independent staleness
        // signal (see module doc, point 2). V2R9 (pin) found -> V2R10 404 ->
        // V3R1 (rollover) 404 -> stop, 3 probes total.
        let pin_rev = Revision { major: 2, minor: 9 };
        let (minor1, rollover1) = next_candidates(pin_rev);
        let mut fake = FakeProber::new(vec![
            Ok(Probe::Found),    // the pin itself
            Ok(Probe::NotFound), // next minor
            Ok(Probe::NotFound), // major rollover
        ]);
        let status = find_latest(BASE_URL, PINNED, &mut fake);
        assert_eq!(status, PinStatus::Current, "no newer revision exists");
        assert_eq!(
            fake.probed,
            vec![
                url_for(PINNED),
                url_for(&candidate_zip(PINNED, minor1)),
                url_for(&candidate_zip(PINNED, rollover1)),
            ],
            "must probe the pin itself first, then the next minor, then the \
             major rollover, and stop there (exactly 3 probes)"
        );
    }

    #[test]
    fn find_latest_reports_pin_not_found_when_the_pinned_zip_itself_404s() {
        // USER RULING: a 404 on the PIN ITSELF is direct, convention-
        // independent evidence of staleness (DISA purges from the low end of
        // its retention window, so a pin that has aged past the window 404s
        // on itself even though newer revisions are live) - it must NOT be
        // reported as `Current`, and must stop immediately (1 probe) rather
        // than guess forward using a convention the pin has already fallen
        // outside of.
        let mut fake = FakeProber::new(vec![Ok(Probe::NotFound)]);
        let status = find_latest(BASE_URL, PINNED, &mut fake);
        assert_eq!(
            status,
            PinStatus::PinNotFound {
                pinned_zip: PINNED.to_string()
            }
        );
        assert_ne!(status, PinStatus::Current, "a missing pin is never current");
        assert_eq!(
            fake.probed,
            vec![url_for(PINNED)],
            "must stop at the very first probe - the pin itself - rather \
             than continue guessing forward with a convention the pin has \
             already fallen outside of"
        );
    }

    #[test]
    fn find_latest_several_successive_minors_then_stops_at_first_double_404() {
        // V2R9 (pin) found -> V2R10 found -> V2R11 found -> V2R12 found ->
        // V2R13 404 -> V3R1 (rollover) 404 -> stop. Latest confirmed: V2R12.
        let pin_rev = Revision { major: 2, minor: 9 };
        let (r10, _) = next_candidates(pin_rev);
        let (r11, _) = next_candidates(r10);
        let (r12, _) = next_candidates(r11);
        let (r13, rollover_from_12) = next_candidates(r12);

        let mut fake = FakeProber::new(vec![
            Ok(Probe::Found),    // pin
            Ok(Probe::Found),    // V2R10
            Ok(Probe::Found),    // V2R11
            Ok(Probe::Found),    // V2R12
            Ok(Probe::NotFound), // V2R13
            Ok(Probe::NotFound), // V3R1 rollover (from V2R12, the last confirmed)
        ]);
        let status = find_latest(BASE_URL, PINNED, &mut fake);
        assert_eq!(
            status,
            PinStatus::Newer {
                revision: r12,
                zip: candidate_zip(PINNED, r12),
            }
        );
        assert_eq!(
            fake.probed,
            vec![
                url_for(PINNED),
                url_for(&candidate_zip(PINNED, r10)),
                url_for(&candidate_zip(PINNED, r11)),
                url_for(&candidate_zip(PINNED, r12)),
                url_for(&candidate_zip(PINNED, r13)),
                url_for(&candidate_zip(PINNED, rollover_from_12)),
            ],
            "must stop probing the instant BOTH the next minor and the major \
             rollover 404 - not keep incrementing minors under V2 forever, and \
             not keep trying further majors (V4R1, V5R1, ...) after V3R1 fails"
        );
    }

    #[test]
    fn find_latest_rolls_over_major_then_continues_probing_minors_under_new_major() {
        // V2R9 (pin) found -> V2R10 404 (minor exhausted immediately) -> V3R1
        // (rollover) found -> V3R2 found -> V3R3 404 -> V4R1 (rollover) 404 ->
        // stop. Latest confirmed: V3R2. Pins the explicit rollover rule: a
        // major bump resets the minor to 1, and minor-incrementing resumes
        // under the new major before the next rollover is tried.
        let pin_rev = Revision { major: 2, minor: 9 };
        let (r10, rollover_from_pin) = next_candidates(pin_rev);
        let (v3r2, _) = next_candidates(rollover_from_pin);
        let (v3r3, rollover_from_v3r2) = next_candidates(v3r2);

        let mut fake = FakeProber::new(vec![
            Ok(Probe::Found),    // pin
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
                revision: v3r2,
                zip: candidate_zip(PINNED, v3r2),
            }
        );
        assert_eq!(
            fake.probed,
            vec![
                url_for(PINNED),
                url_for(&candidate_zip(PINNED, r10)),
                url_for(&candidate_zip(PINNED, rollover_from_pin)),
                url_for(&candidate_zip(PINNED, v3r2)),
                url_for(&candidate_zip(PINNED, v3r3)),
                url_for(&candidate_zip(PINNED, rollover_from_v3r2)),
            ]
        );
    }

    #[test]
    fn find_latest_uses_the_actual_base_url_and_pinned_filename_not_a_hardcoded_rhel9_lineage() {
        // #550 lane-5 rework, blocker 1: every OTHER `find_latest` test in
        // this file uses the SAME `PINNED`/`BASE_URL` constants (RHEL_9, STIG
        // major 2, the real DISA CDN host) - an impl hardcoding "U_RHEL_9_",
        // `major == 2`, or the dl.dod.cyber.mil host could pass all of them.
        // Use a DIFFERENT product (rhel10, STIG major 1) and a NON-DISA
        // base_url.
        let base = "https://mirror.example.test/stigs";
        let pinned = "U_RHEL_10_V1R2_STIG.zip";
        let pin_rev = Revision { major: 1, minor: 2 };
        let (r3, _) = next_candidates(pin_rev);
        let (r4, rollover) = next_candidates(r3);

        let mut fake = FakeProber::new(vec![
            Ok(Probe::Found),    // pin
            Ok(Probe::Found),    // V1R3
            Ok(Probe::NotFound), // V1R4
            Ok(Probe::NotFound), // V2R1 rollover
        ]);
        let status = find_latest(base, pinned, &mut fake);
        assert_eq!(
            status,
            PinStatus::Newer {
                revision: r3,
                zip: candidate_zip(pinned, r3),
            }
        );
        assert_eq!(
            fake.probed,
            vec![
                format!("{base}/{pinned}"),
                format!("{base}/{}", candidate_zip(pinned, r3)),
                format!("{base}/{}", candidate_zip(pinned, r4)),
                format!("{base}/{}", candidate_zip(pinned, rollover)),
            ]
        );
    }

    #[test]
    fn find_latest_enforces_a_hard_probe_ceiling_against_an_always_found_prober() {
        // #550 lane-5 rework, blocker 2: a misbehaving prober (captive portal
        // / proxy that answers 200 for every URL - the DISA CDN itself
        // returns clean hard 404s, per the reviewer's live measurement) must
        // not loop forever. `find_latest` must give up after EXACTLY
        // `PROBE_CEILING` probes and report a status the caller can act on,
        // never hang.
        let mut always_found = AlwaysFoundProber { probed: Vec::new() };
        let status = find_latest(BASE_URL, PINNED, &mut always_found);
        assert_eq!(
            always_found.probed.len(),
            PROBE_CEILING,
            "must stop at exactly the documented ceiling, not before or after"
        );
        assert_eq!(
            status,
            PinStatus::Unavailable(format!(
                "gave up after {PROBE_CEILING} probes without a definitive answer \
                 (a misbehaving prober? DISA's CDN itself returns clean 404s)"
            ))
        );
    }

    #[test]
    fn find_latest_stops_after_one_probe_when_the_pin_probe_itself_is_unavailable() {
        // curl-absent case: the prober cannot even attempt the FIRST probe,
        // which (per the pin-first ruling) is now the pin itself.
        let mut fake = FakeProber::new(vec![Err(ProbeError("curl not found".to_string()))]);
        let status = find_latest(BASE_URL, PINNED, &mut fake);
        assert_eq!(status, PinStatus::Unavailable("curl not found".to_string()));
        assert_eq!(
            fake.probed,
            vec![url_for(PINNED)],
            "must stop at the FIRST unavailable probe, not retry or continue \
             to the next candidate"
        );
    }

    #[test]
    fn find_latest_treats_an_error_at_any_later_probe_as_unavailable_not_a_404() {
        // #550 lane-5 rework, blocker 3: an impl that special-cases ONLY the
        // FIRST probe's `Err` (folding every LATER `Err` into "stop, as if
        // 404") would silently misreport staleness on a transient failure
        // (e.g. DNS) several probes in - exactly the false negative this seam
        // exists to prevent, just moved later. `Err` must short-circuit to
        // `Unavailable` at ANY probe position, immediately, without treating
        // it as evidence of a boundary.
        let pin_rev = Revision { major: 2, minor: 9 };
        let (r10, _) = next_candidates(pin_rev);
        let (r11, _) = next_candidates(r10);
        let mut fake = FakeProber::new(vec![
            Ok(Probe::Found),                                     // pin itself
            Ok(Probe::Found),                                     // V2R10
            Err(ProbeError("DNS resolution failed".to_string())), // V2R11
        ]);
        let status = find_latest(BASE_URL, PINNED, &mut fake);
        assert_eq!(
            status,
            PinStatus::Unavailable("DNS resolution failed".to_string())
        );
        assert_eq!(
            fake.probed,
            vec![
                url_for(PINNED),
                url_for(&candidate_zip(PINNED, r10)),
                url_for(&candidate_zip(PINNED, r11)),
            ],
            "must stop immediately at the Err (exactly 3 probes), not continue \
             probing further or fold the failure into a 404-style boundary"
        );
    }

    #[test]
    fn find_latest_reports_unparseable_when_the_pinned_filename_has_no_version_token_and_probes_nothing()
     {
        // CONCERN raised in review: an unparseable pin (a config/typo error,
        // e.g. someone hand-edits stig-refs.toml and drops the
        // V<major>R<minor> token) was previously unspecified - any behavior
        // an impl happened to pick would have been frozen in by omission.
        // This is a config problem, not a network one: nothing should be
        // probed (an empty answer queue means ANY probe attempt panics the
        // fake, so this also double-checks the "nothing probed" claim).
        let mut fake = FakeProber::new(vec![]);
        let status = find_latest(BASE_URL, "U_RHEL_9_STIG.zip", &mut fake);
        assert_eq!(
            status,
            PinStatus::Unparseable {
                pinned_zip: "U_RHEL_9_STIG.zip".to_string()
            }
        );
        assert!(
            fake.probed.is_empty(),
            "an unparseable pin must not trigger any network probe; probed={:?}",
            fake.probed
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
    fn report_exits_0_and_explains_pin_not_found_is_not_current() {
        // USER RULING: pin the report()-level contract for the new
        // PinNotFound status too - exit 0 (news, not a build failure), but
        // the message must not be mistakable for the Current-status message.
        let status = PinStatus::PinNotFound {
            pinned_zip: "U_RHEL_9_V2R9_STIG.zip".to_string(),
        };
        let (msg, code) = report("rhel9", &status);
        assert_eq!(
            code, 0,
            "a retired pin is news requiring a human re-pin, not a build failure"
        );
        assert!(
            msg.contains("U_RHEL_9_V2R9_STIG.zip"),
            "message must name the pinned zip that 404d; message={msg:?}"
        );
        assert!(
            msg.to_lowercase().contains("not found")
                || msg.to_lowercase().contains("missing")
                || msg.to_lowercase().contains("gone"),
            "message must convey the pin itself is gone; message={msg:?}"
        );
        assert!(
            !msg.to_lowercase().contains("no newer revision"),
            "must not reuse the Current-status phrasing; message={msg:?}"
        );
    }

    #[test]
    fn report_exits_0_and_flags_an_unparseable_pin_as_a_config_problem() {
        let status = PinStatus::Unparseable {
            pinned_zip: "U_RHEL_9_STIG.zip".to_string(),
        };
        let (msg, code) = report("rhel9", &status);
        assert_eq!(
            code, 0,
            "a config problem must still skip gracefully, not fail the build"
        );
        assert!(
            msg.contains("U_RHEL_9_STIG.zip"),
            "message must name the unparseable pin; message={msg:?}"
        );
    }

    #[test]
    fn report_exits_0_and_propagates_the_unavailable_reason_verbatim() {
        // #550 lane-5 rework, blocker 4: the ORIGINAL fixture payload
        // ("curl not found") shared a substring ("curl") with the test's own
        // assertion, so a hardcoded message ("curl is required...") could
        // pass without actually propagating `Unavailable`'s payload. Use a
        // payload with no plausible overlap with a hand-written message, and
        // require it verbatim.
        let status =
            PinStatus::Unavailable("TLS handshake failed: certificate expired".to_string());
        let (msg, code) = report("rhel9", &status);
        assert_eq!(
            code, 0,
            "an unavailable prober must skip gracefully (exit 0), matching the \
             existing *-stig-check-pin recipes' shell-level convention"
        );
        assert!(
            msg.contains("TLS handshake failed: certificate expired"),
            "message must propagate the prober's OWN reason verbatim, not a \
             hardcoded generic string; message={msg:?}"
        );
    }

    // --- cross-tool drift guard ----------------------------------------------

    // #550 lane-5 rework, CONCERN raised in review: this file and the SISTER
    // tool's `pin.rs` (whichever this crate does NOT belong to - see
    // `OTHER_TOOL_PIN_RS`'s `include_str!` path just below) are near-identical
    // by construction, but nothing enforces that a future edit to one is
    // mirrored in the other. Mirrors `rulesteward_sudoers::lints::tags`'s
    // `SSHD_STIG_REFS`/`AUDITD_STIG_REFS` `include_str!` cross-check (a
    // compile-time relative path read, NOT a cargo dependency, so this does
    // not violate the "no dependency on the sister crate/tool" intent
    // `config.rs`/`source.rs` already state). This prose is deliberately
    // crate-agnostic (never names "sshd" or "auditd" itself) so it reads
    // correctly verbatim in EITHER copy - a prior draft hardcoded the sister's
    // name here and one copy ended up self-referential (named itself as its
    // own sister) when pasted into the other file; see the round-2 review
    // note this fixes.
    const THIS_FILE: &str = include_str!("pin.rs");
    const OTHER_TOOL_PIN_RS: &str = include_str!("../../auditd-stig-update/src/pin.rs");

    /// Byte-for-byte comparison, from the doc-comment prefix through the end
    /// of file, of `this` (THIS_FILE) against `other` (the sister's own
    /// `pin.rs`) - EXCEPT the one line each copy's `include_str!` path
    /// necessarily differs on (it must name ITS OWN sister to compile at all,
    /// so that one line is asymmetric by construction, not drift). That line
    /// is neutralized by replacing either crate's sister-path string with a
    /// common placeholder BEFORE comparing, rather than by truncating the
    /// compared region - round 2 review flagged that the prior version
    /// stopped comparing right before this drift-guard section itself, so
    /// anything appended after it (or a one-sided edit inside it) would have
    /// gone unguarded. Comparing the doc-comment prefix too catches drift in
    /// the ASSUMED-rollover labeling and the live-404 grounding evidence,
    /// which round 2 flagged as otherwise invisible to any guard.
    fn normalize_and_compare(this: &str, other: &str) -> (String, String) {
        fn normalize(src: &str) -> String {
            src.replace("../../auditd-stig-update/src/pin.rs", "<SISTER_PIN_RS>")
                .replace("../../sshd-stig-update/src/pin.rs", "<SISTER_PIN_RS>")
        }
        (normalize(this), normalize(other))
    }

    #[test]
    fn pin_rs_matches_the_sister_tool_byte_for_byte_from_the_doc_comment_onward() {
        let (this_all, other_all) = normalize_and_compare(THIS_FILE, OTHER_TOOL_PIN_RS);
        assert_eq!(
            this_all, other_all,
            "tools/sshd-stig-update/src/pin.rs and tools/auditd-stig-update/src/pin.rs \
             must stay byte-identical (module doc-comment, every `pub` item, every \
             test - including this drift guard itself) except each copy's own \
             `include_str!` sister-path line, normalized away above - if this fails, \
             mirror whichever side changed into the other"
        );
    }
}
