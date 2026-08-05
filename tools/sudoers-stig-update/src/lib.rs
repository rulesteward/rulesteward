//! `sudoers-stig-update` - derive and drift-check the `rulesteward-sudoers`
//! sudo-W04 DISA STIG control-id families (`!authenticate`, the `targetpw` /
//! `rootpw` / `runaspw` pw-family, and `timestamp_timeout`) against the
//! official DISA XCCDF, per RHEL product (#551).
//!
//! # Scope (DISA only)
//!
//! This tool covers ONLY the DISA STIG half of sudo-W04. It deliberately does
//! NOT cover:
//! * The sudo-CIS baseline -- `tools/cis-update check --family sudoers`
//!   already drift-checks that half end-to-end (see
//!   `tools/cis-update/src/registry.rs`'s `sudoers` module, which calls
//!   `rulesteward_sudoers::lints::cis::cis_baseline`). Duplicating it here
//!   would be wrong.
//! * sudo-W06 (privilege-elevation restriction) -- that control family is
//!   pinned INLINE and hermetically inside
//!   `crates/rulesteward-sudoers/src/lints/tags.rs`'s `w06_stig_drift_tests`
//!   module: a single-control family does not justify a
//!   whole derive-tool crate (no-speculative-abstraction). W04 is different
//!   only because it spans THREE DISA control families across three RHEL
//!   products (nine ids total).
//!
//! Library half (the testable core): [`xccdf`] parses an XCCDF benchmark into
//! the normalized control table; [`derive`] holds the owned comparison shape,
//! the shipped-projection side ([`derive::code_table`]), and the drift diff;
//! [`config`] reads the pinned DISA zip refs. The `main` binary wires these
//! into the `derive` / `check` subcommands. The network fetch is isolated
//! behind the [`source`] seam so the core is tested offline with fixtures.

pub mod config;
pub mod derive;
pub mod source;
pub mod xccdf;

#[cfg(test)]
mod scope_tests {
    //! RULING: guard this tool's DISA-only scope BEHAVIORALLY; never with a
    //! bare substring-absence check on "CIS".
    //! Rationale + evidence: #551
    //!
    //! A substring ban cannot detect a maintainer adding actual CIS
    //! derivation LOGIC (it only catches a text mention), is brittle against
    //! words that merely CONTAIN "cis" (DECISION, PRECISE, EXCISE, ...), and
    //! forces this tool's own disclaimer text to go VAGUE to dodge itself (a
    //! correct disclaimer legitimately needs to say "CIS" to explain the
    //! exclusion). The behavioral form is:
    //!
    //! 1. [`no_source_file_references_cis_derivation_logic`]: a BEHAVIORAL
    //!    guard -- this crate's own sources must never reference
    //!    `cis_baseline` or construct a `Framework::Cis` `ControlRef` (the
    //!    actual surface `tools/cis-update` uses to derive CIS controls).
    //!    Catches real logic creeping in, not a word.
    //! 2. [`cargo_toml_description_points_at_the_real_cis_tool`]: a POSITIVE
    //!    assertion that the `Cargo.toml` description explicitly names
    //!    `tools/cis-update` (the ACTUAL tool that covers CIS), so the
    //!    disclaimer stays a real, checkable pointer instead of vague
    //!    hand-waving.
    //!
    //! Complements `tests/cli.rs`'s
    //! `help_points_at_the_real_cis_tool_and_the_real_w06_location` (the
    //! RUNTIME `--help` text) by pinning the STATIC package metadata too.

    const CARGO_TOML: &str = include_str!("../Cargo.toml");
    const LIB_RS: &str = include_str!("lib.rs");
    const MAIN_RS: &str = include_str!("main.rs");
    const CONFIG_RS: &str = include_str!("config.rs");
    const SOURCE_RS: &str = include_str!("source.rs");
    const DERIVE_RS: &str = include_str!("derive.rs");
    const XCCDF_RS: &str = include_str!("xccdf.rs");

    /// Strip `//`-comment lines (both doc comments `//!`/`///` and plain `//`)
    /// before scanning for CIS-derivation logic. Without this, the crate's OWN
    /// scope-rationale doc comments (which must legitimately EXPLAIN what
    /// `tools/cis-update` calls, in prose, to justify the exclusion) trip a
    /// naive whole-file substring scan. This filters PROSE, not CODE: an actual
    /// `use` statement or function call is never itself a comment line.
    fn non_comment_lines(src: &str) -> String {
        src.lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// The two literal identifiers a real CIS-derivation usage would need:
    /// `rulesteward_sudoers::lints::cis::cis_baseline`'s function name, and
    /// the `Framework::Cis` enum-variant path. Named as constants (rather
    /// than spelled out again in each assertion's failure message) so this
    /// test's OWN messages can explain the finding WITHOUT reproducing the
    /// exact banned substring inside a string literal -- which would
    /// self-contaminate the scan of `lib.rs` (this very file, via
    /// `include_str!`) with a false positive.
    const CIS_FN: &str = concat!("cis", "_baseline");
    const CIS_VARIANT: &str = concat!("Framework::", "Cis");

    /// The single source of truth for which source files the CIS-derivation
    /// scan covers. Shared by [`no_source_file_references_cis_derivation_logic`]
    /// (the actual scan) and [`scanned_file_list_covers_every_source_file`]
    /// (the completeness check), so the two can never silently drift apart --
    /// without that second test, a future `src/cis.rs` (or any new module)
    /// would escape this guard entirely, since neither its filename nor its
    /// content is in this list until someone remembers to add it by hand.
    const SCANNED_FILES: &[(&str, &str)] = &[
        ("lib.rs", LIB_RS),
        ("main.rs", MAIN_RS),
        ("config.rs", CONFIG_RS),
        ("source.rs", SOURCE_RS),
        ("derive.rs", DERIVE_RS),
        ("xccdf.rs", XCCDF_RS),
    ];

    #[test]
    fn no_source_file_references_cis_derivation_logic() {
        for &(name, src) in SCANNED_FILES {
            let code_only = non_comment_lines(src);
            assert!(
                !code_only.contains(CIS_FN),
                "{name} must never call the CIS baseline projection function in actual \
                 code -- this tool is DISA-only; the sudo-CIS baseline is \
                 `tools/cis-update`'s job, never this tool's"
            );
            assert!(
                !code_only.contains(CIS_VARIANT),
                "{name} must never construct a CIS-framework `ControlRef` in actual code \
                 -- this tool is DISA-only and must never derive or cite a CIS control"
            );
        }
    }

    /// Completeness check: [`SCANNED_FILES`] is
    /// a hand-maintained list, so a NEW top-level `src/*.rs` file (e.g. a
    /// future `cis.rs`) would silently escape
    /// [`no_source_file_references_cis_derivation_logic`] entirely -- neither
    /// its name nor its content appears anywhere in that scan until someone
    /// remembers to add it. This reads the REAL `src/` directory at test time
    /// and fails loudly if it ever disagrees with [`SCANNED_FILES`]'s file
    /// names, in either direction (a file added but not scanned, or a scanned
    /// name that no longer exists). Scoped to files DIRECTLY under `src/`
    /// (does not recurse into subdirectories); this crate has none today, and
    /// this is a cheap-hardening guard, not a build-system dependency tracker.
    #[test]
    fn scanned_file_list_covers_every_source_file() {
        let src_dir = std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/src"));
        let mut on_disk: Vec<String> = std::fs::read_dir(src_dir)
            .unwrap_or_else(|e| panic!("read_dir({}): {e}", src_dir.display()))
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .filter(|path| path.extension().and_then(|e| e.to_str()) == Some("rs"))
            .filter_map(|path| path.file_name().map(|n| n.to_string_lossy().into_owned()))
            .collect();
        on_disk.sort();

        let mut scanned: Vec<&str> = SCANNED_FILES.iter().map(|&(name, _)| name).collect();
        scanned.sort_unstable();

        assert_eq!(
            on_disk, scanned,
            "SCANNED_FILES must list EXACTLY the .rs files directly under src/ (found on \
             disk: {on_disk:?}; currently scanned: {scanned:?}) -- a mismatch means either \
             a new source file needs to be added to the CIS-derivation scan, or a stale \
             entry needs removing"
        );
    }

    #[test]
    fn cargo_toml_description_points_at_the_real_cis_tool() {
        let desc_line = CARGO_TOML
            .lines()
            .find(|l| l.trim_start().starts_with("description"))
            .expect("Cargo.toml must have a description field");
        assert!(
            desc_line.to_uppercase().contains("DISA"),
            "the crate description must name DISA explicitly; got {desc_line:?}"
        );
        assert!(
            desc_line.contains("tools/cis-update"),
            "the description must POINT AT the real tool that covers CIS \
             (tools/cis-update), not a vague disclaimer; got {desc_line:?}"
        );
    }
}
