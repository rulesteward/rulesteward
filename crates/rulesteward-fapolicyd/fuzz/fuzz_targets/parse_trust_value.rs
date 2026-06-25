//! Fuzz target: `rulesteward_fapolicyd::trustdb::parse_trust_value`
//!
//! INVARIANT: `parse_trust_value` must never panic or abort on arbitrary
//! byte input. It must always return either `Ok((TrustSource, u64, String))`
//! or `Err(_)` (a `MalformedValue` for a structural-grammar violation, or a
//! `TornRead` for a NUL/non-ASCII byte - see #291/#317).
//!
//! The function accepts `&[u8]` directly and internally applies
//! `String::from_utf8_lossy`, so we pass raw bytes without any pre-filtering.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // `parse_trust_value_fuzz` is a `#[doc(hidden)]` shim exposed via the
    // `fuzz-targets` Cargo feature. It delegates directly to the
    // crate-private `parse_trust_value` without any additional logic.
    let _ = rulesteward_fapolicyd::fuzz_hooks::parse_trust_value_fuzz(data);
});
