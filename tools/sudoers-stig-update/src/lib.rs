//! `sudoers-stig-update` - derive and drift-check the `rulesteward-sudoers`
//! sudo-W04 DISA STIG control-id families (`!authenticate`, the `targetpw` /
//! `rootpw` / `runaspw` pw-family, and `timestamp_timeout`) against the
//! official DISA XCCDF, per RHEL product (#551).
//!
//! # Scope (DISA only, locked 2026-07-24)
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
//!   module (LOCKED 2026-07-15): a single-control family did not justify a
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
//!
//! # Test-authoring note (9j lane 6, RED phase)
//!
//! [`xccdf::parse_controls`] and [`derive::code_table`] / [`derive::diff_controls`]
//! are STUBBED (`todo!()`) as of this commit: this lane authors the RED test
//! contract only, per the parallel-orchestration test-author barrier. See each
//! stub's doc comment for what a GREEN implementation must satisfy, and
//! `derive::code_table`'s doc comment for the one cross-crate gap the
//! implementer must also close (the sudoers crate's `PW_FAMILY_CONTROLS` /
//! `AUTHENTICATE_CONTROLS` / `TIMESTAMP_TIMEOUT_CONTROLS` consts are private
//! today).

pub mod config;
pub mod derive;
pub mod source;
pub mod xccdf;

#[cfg(test)]
mod scope_tests {
    //! Item 6 of the RED test contract (#551): this crate's own `Cargo.toml`
    //! `description` must never claim CIS coverage (the sudo-CIS baseline is
    //! drift-checked by `tools/cis-update` instead; see the crate doc above).
    //! Complements `tests/cli.rs`'s `help_scopes_to_disa_w04_not_cis` (the
    //! RUNTIME `--help` text) by pinning the STATIC package metadata too.

    const CARGO_TOML: &str = include_str!("../Cargo.toml");

    #[test]
    fn cargo_toml_description_is_disa_only_never_claims_cis() {
        let desc_line = CARGO_TOML
            .lines()
            .find(|l| l.trim_start().starts_with("description"))
            .expect("Cargo.toml must have a description field");
        assert!(
            desc_line.to_uppercase().contains("DISA"),
            "the crate description must name DISA explicitly; got {desc_line:?}"
        );
        assert!(
            !desc_line.to_uppercase().contains("CIS"),
            "this tool is DISA-only; its Cargo.toml description must never claim \
             CIS coverage (tools/cis-update already drift-checks sudo-CIS); \
             got {desc_line:?}"
        );
    }
}
