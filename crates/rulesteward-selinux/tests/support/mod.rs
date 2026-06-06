//! Shared integration-test support modules for `rulesteward-selinux`.
//!
//! Included by a test binary via `mod support;`. Each submodule is feature-gated
//! to match the tests that consume it.

pub mod policy_corpus;
