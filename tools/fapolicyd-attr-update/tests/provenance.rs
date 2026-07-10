//! Fixture PROVENANCE gate (ATL round-1 adversary miss #1, library half): the
//! COMMITTED `tests/fixtures/<version>/{subject,object}-attr.c` bytes must
//! match the sha256 pins in the COMMITTED `attr-refs.toml`, for every pinned
//! version. GREEN today (the fixtures were copied + verified from the pinned
//! upstream sources at authoring time - see the crate's attr-refs.toml header);
//! turns RED the moment anyone edits/regenerates a fixture without re-pinning,
//! or edits a pin without re-copying - the corruption the offline `check
//! --fixtures` PR gate would otherwise never notice.

use fapolicyd_attr_update::config::Config;
use fapolicyd_attr_update::source::verify_sha256;

const ATTR_REFS: &str = include_str!("../attr-refs.toml");
const SUBJECT_1_3_2: &str = include_str!("fixtures/1.3.2/subject-attr.c");
const OBJECT_1_3_2: &str = include_str!("fixtures/1.3.2/object-attr.c");
const SUBJECT_1_4_5: &str = include_str!("fixtures/1.4.5/subject-attr.c");
const OBJECT_1_4_5: &str = include_str!("fixtures/1.4.5/object-attr.c");

/// Every committed fixture file's bytes hash to its committed attr-refs.toml
/// pin. Iterates the CONFIG's versions (not a hardcoded list) so a version
/// added to attr-refs.toml without a matching committed fixture pair fails
/// loudly here rather than being silently unverified.
#[test]
fn committed_fixtures_match_the_committed_sha256_pins() {
    let cfg = Config::parse(ATTR_REFS).expect("committed attr-refs.toml parses");
    assert!(
        !cfg.versions.is_empty(),
        "attr-refs.toml must pin at least one version"
    );

    let fixture = |version: &str, file: &str| -> &'static str {
        match (version, file) {
            ("1.3.2", "subject-attr.c") => SUBJECT_1_3_2,
            ("1.3.2", "object-attr.c") => OBJECT_1_3_2,
            ("1.4.5", "subject-attr.c") => SUBJECT_1_4_5,
            ("1.4.5", "object-attr.c") => OBJECT_1_4_5,
            _ => panic!(
                "attr-refs.toml pins version {version:?} but tests/fixtures/{version}/{file} \
                 is not committed (add the fixture pair and this test's include_str! rows)"
            ),
        }
    };

    for (version, reference) in &cfg.versions {
        verify_sha256(
            fixture(version, "subject-attr.c"),
            &reference.subject_sha256,
        )
        .unwrap_or_else(|e| {
            panic!(
                "committed tests/fixtures/{version}/subject-attr.c does not match its \
                     attr-refs.toml pin: {e}"
            )
        });
        verify_sha256(fixture(version, "object-attr.c"), &reference.object_sha256).unwrap_or_else(
            |e| {
                panic!(
                    "committed tests/fixtures/{version}/object-attr.c does not match its \
                     attr-refs.toml pin: {e}"
                )
            },
        );
    }
}

/// The pinned version SET tracks `rulesteward_fapolicyd::version::TargetVersion`
/// exactly: attr-refs.toml must pin precisely the distinct
/// `fapolicyd_version()` strings of every supported RHEL target (today:
/// rhel8 -> "1.3.2", rhel9/rhel10 -> "1.4.5", so two distinct pins). Guards the
/// drift where version.rs gains/rebases a fapolicyd version (as RHEL 9.8 once
/// rebased 1.4.3 -> 1.4.5) but attr-refs.toml keeps deriving the stale one.
#[test]
fn pinned_versions_track_target_version_map() {
    use rulesteward_fapolicyd::version::TargetVersion;
    use std::collections::BTreeSet;

    let cfg = Config::parse(ATTR_REFS).expect("committed attr-refs.toml parses");
    let pinned: BTreeSet<&str> = cfg.versions.keys().map(String::as_str).collect();
    let supported: BTreeSet<&str> = [
        TargetVersion::Rhel8,
        TargetVersion::Rhel9,
        TargetVersion::Rhel10,
    ]
    .iter()
    .map(|t| t.fapolicyd_version())
    .collect();
    assert_eq!(
        pinned, supported,
        "attr-refs.toml's pinned versions must equal the distinct fapolicyd \
         versions of the supported RHEL targets (version.rs)"
    );
}
