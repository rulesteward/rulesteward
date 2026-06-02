//! fapd-W06 - a `path=`/`exe=` literal value in neither the trust DB nor on disk.
//! Walks every rule's subject + object attrs; for each `path=`/`exe=` string
//! literal that is absent from both the supplied trust DB and the local
//! filesystem, emits a Warning. Only runs when a `TrustDb` context is provided
//! (the no-context lint path does not call `w06`).
use std::path::Path;

use rulesteward_core::{Diagnostic, Severity};

use super::anchored;
use crate::ast::{Attr, AttrValue, Entry};
use crate::trustdb::TrustDb;

pub(crate) fn w06(entries: &[Entry], file: &Path, db: &TrustDb) -> Vec<Diagnostic> {
    let mut diags = Vec::new();
    for e in entries {
        let Entry::Rule(r) = e else {
            continue;
        };
        for attr in r.subject.iter().chain(r.object.iter()) {
            let Attr::Kv { key, value, .. } = attr else {
                continue;
            };
            if key != "path" && key != "exe" {
                continue;
            }
            let AttrValue::Str(p) = value else {
                continue;
            };
            if !db.contains_path(p) && !Path::new(p).exists() {
                diags.push(anchored(
                    Severity::Warning,
                    "fapd-W06",
                    r.span.clone(),
                    format!("`{key}={p}` is in neither the trust DB nor present on disk"),
                    file,
                    r.line,
                ));
            }
        }
    }
    diags
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::{Attr, Decision};
    use crate::lints::testkit::{kv, kv_ref, modern_rule, p};
    use crate::trustdb::{open_trustdb_readonly, write_fixture};
    use rulesteward_core::Severity;
    use tempfile::tempdir;

    // Quadrant 1: path= absent from both trust DB and disk -> 1 Warning fapd-W06.
    // RED against the empty stub (stub returns [], expect 1 diagnostic).
    // Also RED against a naive "always flag" impl when combined with quadrants 2/4/5.
    #[test]
    fn path_absent_from_db_and_disk_fires() {
        let tmp = tempdir().expect("tempdir");
        write_fixture(tmp.path(), &["/usr/bin/ls"]);
        let db = open_trustdb_readonly(tmp.path()).expect("open_trustdb_readonly");

        let entries = vec![modern_rule(
            1,
            Decision::Allow,
            None,
            vec![Attr::All],
            // Guaranteed absent on disk AND not in the fixture DB.
            vec![kv("path", "/nonexistent/rs-trap/x")],
        )];
        let diags = w06(&entries, &p(), &db);

        assert_eq!(
            diags.len(),
            1,
            "expected exactly 1 fapd-W06 diagnostic for a path absent from DB and disk, got {}: {diags:?}",
            diags.len()
        );
        assert_eq!(
            diags[0].code, "fapd-W06",
            "diagnostic code must be \"fapd-W06\", got {:?}",
            diags[0].code
        );
        assert_eq!(
            diags[0].severity,
            Severity::Warning,
            "fapd-W06 must be Warning severity, got {:?}",
            diags[0].severity
        );
        assert!(
            diags[0].message.contains("/nonexistent/rs-trap/x"),
            "diagnostic message must contain the offending path \"/nonexistent/rs-trap/x\", got {:?}",
            diags[0].message
        );
    }

    // Quadrant 2: path= present in trust DB -> no diagnostic.
    // PASSES against the empty stub (stub returns [] == expect empty).
    // RED against a naive impl that flags every path regardless of trust DB.
    #[test]
    fn path_in_db_does_not_fire() {
        let tmp = tempdir().expect("tempdir");
        write_fixture(tmp.path(), &["/usr/bin/ls"]);
        let db = open_trustdb_readonly(tmp.path()).expect("open_trustdb_readonly");

        let entries = vec![modern_rule(
            1,
            Decision::Allow,
            None,
            vec![Attr::All],
            vec![kv("path", "/usr/bin/ls")],
        )];
        let diags = w06(&entries, &p(), &db);

        assert!(
            diags.is_empty(),
            "expected no diagnostics for a path= that is present in the trust DB, got: {diags:?}"
        );
    }

    // Quadrant 3: exe= (subject) absent from trust DB and disk -> 1 Warning fapd-W06.
    // RED against the empty stub (stub returns [], expect 1 diagnostic).
    // Also RED against a impl that only checks object path= and ignores subject exe=.
    #[test]
    fn exe_subject_path_is_checked() {
        let tmp = tempdir().expect("tempdir");
        write_fixture(tmp.path(), &[]); // empty fixture - nothing trusted
        let db = open_trustdb_readonly(tmp.path()).expect("open_trustdb_readonly");

        let entries = vec![modern_rule(
            1,
            Decision::Allow,
            None,
            // exe= is a SUBJECT attribute; it should also be checked.
            vec![kv("exe", "/nonexistent/rs-trap/sh")],
            vec![Attr::All],
        )];
        let diags = w06(&entries, &p(), &db);

        assert_eq!(
            diags.len(),
            1,
            "expected exactly 1 fapd-W06 diagnostic for an exe= subject path absent from DB and disk, got {}: {diags:?}",
            diags.len()
        );
        assert_eq!(
            diags[0].code, "fapd-W06",
            "diagnostic code must be \"fapd-W06\", got {:?}",
            diags[0].code
        );
        assert_eq!(
            diags[0].severity,
            Severity::Warning,
            "fapd-W06 must be Warning severity for exe= paths too, got {:?}",
            diags[0].severity
        );
        assert!(
            diags[0].message.contains("/nonexistent/rs-trap/sh"),
            "diagnostic message must contain the offending exe= path \"/nonexistent/rs-trap/sh\", got {:?}",
            diags[0].message
        );
    }

    // Quadrant 4: dir= values and %setref values are excluded from W06 checking.
    // PASSES against the empty stub (stub returns [] == expect empty).
    // RED against an impl that erroneously checks dir= or dereferences %setref.
    #[test]
    fn dir_and_setref_and_int_values_are_ignored() {
        let tmp = tempdir().expect("tempdir");
        write_fixture(tmp.path(), &[]); // empty - nothing trusted
        let db = open_trustdb_readonly(tmp.path()).expect("open_trustdb_readonly");

        let entries = vec![modern_rule(
            1,
            Decision::Allow,
            None,
            // %setref in subject - should be skipped (no static path).
            vec![kv_ref("exe", "MY_SET")],
            // dir= in object - excluded per Q4; integer AttrValue would also be skipped.
            vec![kv("dir", "/nonexistent/rs-trap/")],
        )];
        let diags = w06(&entries, &p(), &db);

        assert!(
            diags.is_empty(),
            "expected no diagnostics: dir= is excluded and %setref values have no static path, got: {diags:?}"
        );
    }

    // Quadrant 6 (DB-isolation): path= present in trust DB but GUARANTEED absent on disk
    // -> no diagnostic. This is the symmetric counterpart to Quadrant 5 (disk-isolation).
    // PASSES against the empty stub (stub returns [] == expect empty).
    // RED against a wrong impl that ONLY checks Path::exists() and ignores db.contains_path:
    //   - disk-only wrong impl: sees path not on disk -> FIRES -> this test FAILS.
    //   - correct impl: sees path in DB -> covered -> empty -> this test PASSES.
    // This makes db.contains_path load-bearing; without this test the DB check is
    // never exercised by a value that can distinguish it from a disk-only impl.
    #[test]
    fn path_in_db_but_absent_on_disk_does_not_fire() {
        let tmp = tempdir().expect("tempdir");
        // Write the key into the fixture DB. /nonexistent/rs-trap/trusted does not
        // exist on disk on any host, so Path::exists() returns false for it.
        write_fixture(tmp.path(), &["/nonexistent/rs-trap/trusted"]);
        let db = open_trustdb_readonly(tmp.path()).expect("open ro");

        let entries = vec![modern_rule(
            1,
            Decision::Allow,
            None,
            vec![Attr::All],
            vec![kv("path", "/nonexistent/rs-trap/trusted")],
        )];
        let diags = w06(&entries, &p(), &db);

        assert!(
            diags.is_empty(),
            "a path present in the trust DB must not fire even when absent on disk, got: {diags:?}"
        );
    }

    // Quadrant 5: path= whose value exists on disk (but not in trust DB) -> no diagnostic.
    // PASSES against the empty stub (stub returns [] == expect empty).
    // RED against an impl that only checks the trust DB and ignores disk presence.
    #[test]
    fn path_present_on_disk_only_does_not_fire() {
        let tmp_db = tempdir().expect("tempdir for db");
        write_fixture(tmp_db.path(), &[]); // empty - path is NOT in the trust DB
        let db = open_trustdb_readonly(tmp_db.path()).expect("open_trustdb_readonly");

        // Create a real temporary file so Path::exists() returns true.
        let tmp_file = tempdir().expect("tempdir for real file");
        let real_path = tmp_file.path().join("exists_on_disk_only");
        std::fs::write(&real_path, b"").expect("create real temp file");
        assert!(real_path.exists(), "sanity: temp file must exist on disk");

        let path_str = real_path
            .to_str()
            .expect("temp path is valid UTF-8")
            .to_string();
        let entries = vec![modern_rule(
            1,
            Decision::Allow,
            None,
            vec![Attr::All],
            vec![kv("path", &path_str)],
        )];
        let diags = w06(&entries, &p(), &db);

        assert!(
            diags.is_empty(),
            "expected no diagnostics for a path= that exists on disk (even if absent from trust DB), got: {diags:?}"
        );
    }
}
