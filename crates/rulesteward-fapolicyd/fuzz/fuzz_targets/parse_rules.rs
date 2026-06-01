//! Fuzz target: `rulesteward_fapolicyd::parse_rules_file`
//!
//! INVARIANT: `parse_rules_file` must never panic or abort on arbitrary
//! byte input. It must always return either `Ok(Vec<Entry>)` or
//! `Err(Vec<Diagnostic>)`.
//!
//! The input bytes are interpreted as a UTF-8 string via
//! `String::from_utf8_lossy` so that the fuzzer can explore the full u8
//! input space without being restricted to valid UTF-8 sequences.

#![no_main]

use libfuzzer_sys::fuzz_target;
use std::path::Path;

fuzz_target!(|data: &[u8]| {
    // Convert arbitrary bytes to a string the parser can consume.
    // `from_utf8_lossy` replaces invalid UTF-8 sequences with U+FFFD so the
    // parser sees a valid Rust `str` regardless of what the fuzzer supplies.
    let source = String::from_utf8_lossy(data);

    // A fixed dummy path is sufficient: the parser uses the path only when
    // constructing `Diagnostic` spans and never reads the filesystem.
    let dummy_path = Path::new("fuzz-input.rules");

    // The only requirement is that this call must not panic/abort.
    // We discard the result; Ok and Err are both acceptable outcomes.
    let _ = rulesteward_fapolicyd::parse_rules_file(&source, dummy_path);
});
