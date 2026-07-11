//! Fixture PROVENANCE gate: the COMMITTED
//! `tests/fixtures/3bfa048/{msg_typetab.h,audit-records.h}` +
//! `tests/fixtures/linux-v6.6/audit.h` bytes must match the sha256 pins in
//! the COMMITTED `msgtype-refs.toml`. GREEN from authoring time (the fixtures
//! were copied + verified from the pinned upstream sources - see
//! `msgtype-refs.toml`'s header); turns RED the moment anyone
//! edits/regenerates a fixture without re-pinning, or edits a pin without
//! re-copying - the corruption the offline `check --fixtures` PR gate would
//! otherwise never notice.
//!
//! Deliberately IMPL-INDEPENDENT (unlike the sibling
//! fapolicyd-attr-update/tests/provenance.rs, which routes through the
//! crate's own `Config::parse` + `verify_sha256`): hashes are computed
//! directly via the sha2 crate and pins are read directly via the toml crate,
//! so this gate holds even while the crate's bodies are `todo!()` stubs, and
//! a broken impl-side hex encoder can never make the pins self-consistently
//! wrong. The impl-routed equivalents live in `src/config.rs`'s and
//! `src/source.rs`'s frozen unit tests.

const MSGTYPE_REFS: &str = include_str!("../msgtype-refs.toml");
const MSG_TYPETAB: &str = include_str!("fixtures/3bfa048/msg_typetab.h");
const AUDIT_RECORDS: &str = include_str!("fixtures/3bfa048/audit-records.h");
const KERNEL_AUDIT_H: &str = include_str!("fixtures/linux-v6.6/audit.h");

/// Test-local sha256 hex - computed DIRECTLY via the sha2 crate, deliberately
/// NOT routed through the crate's own `source::verify_sha256`.
fn sha256_hex(content: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(content.as_bytes());
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Read `refs[table][key]` as a string, panicking with a named message when
/// absent - a missing pin is itself a provenance failure.
fn pin<'a>(refs: &'a toml::Table, table: &str, key: &str) -> &'a str {
    refs.get(table)
        .and_then(toml::Value::as_table)
        .unwrap_or_else(|| panic!("msgtype-refs.toml must carry a [{table}] table"))
        .get(key)
        .and_then(toml::Value::as_str)
        .unwrap_or_else(|| panic!("msgtype-refs.toml must pin {table}.{key} as a string"))
}

/// Every committed fixture file's bytes hash to its committed
/// msgtype-refs.toml pin.
#[test]
fn committed_fixtures_match_the_committed_sha256_pins() {
    let refs: toml::Table = MSGTYPE_REFS
        .parse()
        .expect("committed msgtype-refs.toml parses");

    let cases: [(&str, &str, &str, &str); 3] = [
        (
            "audit-userspace",
            "msg_typetab_sha256",
            "tests/fixtures/3bfa048/msg_typetab.h",
            MSG_TYPETAB,
        ),
        (
            "audit-userspace",
            "audit_records_sha256",
            "tests/fixtures/3bfa048/audit-records.h",
            AUDIT_RECORDS,
        ),
        (
            "kernel",
            "audit_h_sha256",
            "tests/fixtures/linux-v6.6/audit.h",
            KERNEL_AUDIT_H,
        ),
    ];
    for (table, key, path, content) in cases {
        let pinned = pin(&refs, table, key);
        let actual = sha256_hex(content);
        assert_eq!(
            actual, pinned,
            "committed {path} does not match its msgtype-refs.toml pin \
             ({table}.{key}); re-copy the fixture from the pinned upstream or \
             re-pin deliberately"
        );
    }
}

/// The refs file pins the expected upstream refs: the audit-userspace
/// citation commit `3bfa048` (the crate-wide pinned commit
/// rulesteward-auditd cites throughout) and the kernel LTS tag `v6.6` - and
/// the fixture directory names embed the same refs, so the `--fixtures`
/// layout contract (`<DIR>/<commit>/...`, `<DIR>/linux-<tag>/audit.h`)
/// resolves to the committed tree.
#[test]
fn refs_file_pins_the_expected_upstream_refs() {
    let refs: toml::Table = MSGTYPE_REFS
        .parse()
        .expect("committed msgtype-refs.toml parses");
    assert_eq!(
        pin(&refs, "audit-userspace", "commit"),
        "3bfa048",
        "the audit-userspace pin must be the crate-wide citation commit"
    );
    assert_eq!(
        pin(&refs, "kernel", "tag"),
        "v6.6",
        "the kernel pin must be the v6.6 LTS tag"
    );
}
