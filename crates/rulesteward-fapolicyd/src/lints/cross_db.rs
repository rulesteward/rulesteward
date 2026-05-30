//! fapd-X01 - trust-DB entries not referenced by any rule (one capped summary).
//! Invoked from the CLI (not from `lint_with_context`).
use std::collections::HashSet;
use std::path::PathBuf;

use rulesteward_core::{Diagnostic, Severity};

use crate::ast::{Attr, AttrValue, Decision, Entry, Rule};
use crate::trustdb::TrustDb;

const SAMPLE_CAP: usize = 10;

fn is_allow(d: Decision) -> bool {
    matches!(
        d,
        Decision::Allow | Decision::AllowAudit | Decision::AllowSyslog | Decision::AllowLog
    )
}

fn is_all(attrs: &[Attr]) -> bool {
    matches!(attrs, [Attr::All])
}

fn is_allow_all(r: &Rule) -> bool {
    is_allow(r.decision) && is_all(&r.subject) && is_all(&r.object)
}

/// Emit at most one fapd-X01 summary diagnostic (Extra severity -> exit 0).
#[must_use]
pub fn lint_orphans(files: &[(PathBuf, Vec<Entry>)], db: &TrustDb) -> Vec<Diagnostic> {
    let rules = || {
        files
            .iter()
            .flat_map(|(_, es)| es)
            .filter_map(|e| match e {
                Entry::Rule(r) => Some(r),
                _ => None,
            })
    };
    // Suppress: an all:all allow reaches everything.
    if rules().any(is_allow_all) {
        return Vec::new();
    }

    let mut exact: HashSet<&str> = HashSet::new();
    let mut prefixes: Vec<&str> = Vec::new();
    for r in rules() {
        for attr in r.subject.iter().chain(r.object.iter()) {
            let Attr::Kv { key, value } = attr else {
                continue;
            };
            let AttrValue::Str(v) = value else {
                continue;
            };
            match key.as_str() {
                "path" | "exe" => {
                    exact.insert(v.as_str());
                }
                "dir" => prefixes.push(v.as_str()),
                _ => {}
            }
        }
    }

    let Ok(keys) = db.iter_paths() else {
        return Vec::new();
    };
    let mut orphans: Vec<&String> = keys
        .iter()
        .filter(|k| {
            !exact.contains(k.as_str()) && !prefixes.iter().any(|pre| k.starts_with(pre))
        })
        .collect();
    if orphans.is_empty() {
        return Vec::new();
    }

    orphans.sort();
    let n = orphans.len();
    let sample: Vec<&str> = orphans.iter().take(SAMPLE_CAP).map(|s| s.as_str()).collect();
    let plural = if n == 1 { "entry" } else { "entries" };
    vec![Diagnostic::new(
        Severity::Extra,
        "fapd-X01",
        0..0,
        format!(
            "trust DB has {n} {plural} not referenced by any rule (showing first {}: {})",
            sample.len(),
            sample.join(", ")
        ),
        db.path(),
        0,
        0,
    )]
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use rulesteward_core::Severity;
    use tempfile::tempdir;

    use super::lint_orphans;
    use crate::ast::{Attr, AttrValue, Decision, Rule, SyntaxFlavor};
    use crate::ast::Entry;
    use crate::trustdb::{open_trustdb_readonly, write_fixture};

    // -- local AST helpers (codebase convention: per-module, NOT promoted) --------

    fn rule(
        line: usize,
        decision: Decision,
        subj: Vec<Attr>,
        obj: Vec<Attr>,
    ) -> Entry {
        Entry::Rule(Rule {
            decision,
            perm: None,
            subject: subj,
            object: obj,
            syntax: SyntaxFlavor::Modern,
            line,
            span: rulesteward_core::span(0, 0),
        })
    }

    fn kv(key: &str, value: &str) -> Attr {
        Attr::Kv {
            key: key.to_string(),
            value: AttrValue::Str(value.to_string()),
        }
    }

    // -- tests -------------------------------------------------------------------

    /// fapd-X01 fires: 3 trust-DB keys, only 1 referenced by an exact `path=` rule.
    /// The 2 unreferenced keys are orphans. The lint must emit EXACTLY 1 summary
    /// diagnostic with code "fapd-X01", severity Extra, and a message containing
    /// the orphan count token `"2 entries"` (count + plural word).
    ///
    /// Adversarial coverage:
    /// - The empty stub returns [] -> this test FAILS (RED) against the stub.
    /// - An impl that always emits would pass count=1 but fail `"2 entries"`.
    /// - An impl that emits one diag without the count token fails the assertion.
    #[test]
    fn orphans_summarized_as_single_extra_diagnostic() {
        let tmp = tempdir().expect("tempdir");
        write_fixture(tmp.path(), &["/usr/bin/ls", "/usr/bin/cat", "/opt/x"]);
        let db = open_trustdb_readonly(tmp.path()).expect("open db");

        // One file; references only /usr/bin/ls via exact path= match.
        let files = vec![(
            PathBuf::from("rules.d/10-allow.rules"),
            vec![rule(
                1,
                Decision::Allow,
                vec![Attr::All],
                vec![kv("path", "/usr/bin/ls")],
            )],
        )];

        let diags = lint_orphans(&files, &db);

        // Exactly one summary diagnostic (not one per orphan).
        assert_eq!(
            diags.len(),
            1,
            "lint_orphans must emit exactly 1 summary diagnostic for orphan keys; \
             got {}: {diags:?}",
            diags.len(),
        );

        let d = &diags[0];
        assert_eq!(
            d.code.as_ref(),
            "fapd-X01",
            "diagnostic code must be \"fapd-X01\""
        );
        assert_eq!(
            d.severity,
            Severity::Extra,
            "fapd-X01 must have severity Extra (exit 0)"
        );
        assert!(
            d.message.contains("2 entries"),
            "diagnostic message must contain \"2 entries\" (count + plural word); got: {:?}",
            d.message,
        );
    }

    /// fapd-X01 silent: a `dir=` prefix that covers all DB keys means zero orphans.
    /// Referenced via `dir=/usr/bin/` which is a prefix of both `/usr/bin/ls`
    /// and `/usr/bin/cat`.
    ///
    /// Adversarial coverage:
    /// - An impl that ignores `dir=` prefix coverage will see 2 orphans and emit a
    ///   diagnostic -> this test FAILS for that impl.
    /// - The empty stub returns [] -> this test PASSES against the stub (fine;
    ///   the stub is wrong in test 1).
    #[test]
    fn dir_prefix_reference_covers_entries() {
        let tmp = tempdir().expect("tempdir");
        write_fixture(tmp.path(), &["/usr/bin/ls", "/usr/bin/cat"]);
        let db = open_trustdb_readonly(tmp.path()).expect("open db");

        let files = vec![(
            PathBuf::from("rules.d/10-allow.rules"),
            vec![rule(
                1,
                Decision::Allow,
                vec![Attr::All],
                vec![kv("dir", "/usr/bin/")],
            )],
        )];

        let diags = lint_orphans(&files, &db);

        assert!(
            diags.is_empty(),
            "dir= prefix /usr/bin/ covers both DB keys; expected 0 diagnostics, got {}: {diags:?}",
            diags.len(),
        );
    }

    /// fapd-X01 silent: a rule with `Decision::Allow` and subject/object `all:all`
    /// makes every DB entry reachable. The lint MUST be fully suppressed.
    ///
    /// Adversarial coverage:
    /// - An impl that emits regardless of `all:all` rules will emit diagnostics here
    ///   -> this test FAILS for that impl.
    /// - The empty stub returns [] -> this test PASSES against the stub (fine).
    #[test]
    fn all_all_allow_suppresses_x01() {
        let tmp = tempdir().expect("tempdir");
        write_fixture(tmp.path(), &["/a", "/b"]);
        let db = open_trustdb_readonly(tmp.path()).expect("open db");

        // allow all : all -- every DB key is reachable.
        let files = vec![(
            PathBuf::from("rules.d/10-allow.rules"),
            vec![rule(
                1,
                Decision::Allow,
                vec![Attr::All],
                vec![Attr::All],
            )],
        )];

        let diags = lint_orphans(&files, &db);

        assert!(
            diags.is_empty(),
            "an allow all:all rule makes every DB entry reachable; \
             expected 0 diagnostics (full suppression), got {}: {diags:?}",
            diags.len(),
        );
    }

    /// fapd-X01 silent: every trust-DB key IS referenced by an exact `path=` rule.
    /// With zero orphans the lint must return an empty vec.
    ///
    /// Adversarial coverage:
    /// - An impl that always emits will fail here.
    /// - The empty stub returns [] -> this test PASSES against the stub (fine).
    #[test]
    fn no_orphans_yields_nothing() {
        let tmp = tempdir().expect("tempdir");
        write_fixture(tmp.path(), &["/usr/bin/ls"]);
        let db = open_trustdb_readonly(tmp.path()).expect("open db");

        let files = vec![(
            PathBuf::from("rules.d/10-allow.rules"),
            vec![rule(
                1,
                Decision::Allow,
                vec![Attr::All],
                vec![kv("path", "/usr/bin/ls")],
            )],
        )];

        let diags = lint_orphans(&files, &db);

        assert!(
            diags.is_empty(),
            "all DB keys are referenced; expected 0 diagnostics, got {}: {diags:?}",
            diags.len(),
        );
    }

    /// `path=` is an EXACT-key reference, NOT a prefix (only `dir=` is a prefix).
    /// DB keys `/usr/bin/ls` and `/usr/bin/lsof`; a rule references `path=/usr/bin/ls`
    /// EXACTLY. A wrong impl that treats `path=` as a prefix would "cover" `/usr/bin/lsof`
    /// (since `"lsof".starts_with("ls")` when comparing paths naively) and report 0 orphans
    /// -> FAILS this test. The correct exact-match impl leaves `/usr/bin/lsof` as the 1 orphan.
    ///
    /// Adversarial coverage:
    /// - An impl that treats `path=` as a prefix (like `dir=`) passes 0 orphans -> FAILS.
    /// - The empty stub returns [] -> FAILS the `assert_eq!(len, 1)` assertion. RED.
    #[test]
    fn path_reference_is_exact_not_prefix() {
        let tmp = tempdir().expect("tempdir");
        write_fixture(tmp.path(), &["/usr/bin/ls", "/usr/bin/lsof"]);
        let db = open_trustdb_readonly(tmp.path()).unwrap();

        // Object path=/usr/bin/ls references /usr/bin/ls exactly.
        // /usr/bin/lsof shares the /usr/bin/ls prefix but is a DISTINCT key.
        let files = vec![(
            PathBuf::from("rules.d/10-a.rules"),
            vec![rule(
                1,
                Decision::Allow,
                vec![Attr::All],
                vec![kv("path", "/usr/bin/ls")],
            )],
        )];

        let d = lint_orphans(&files, &db);
        assert_eq!(
            d.len(),
            1,
            "exactly one X01 summary diagnostic for the single orphan /usr/bin/lsof; \
             got {}: {d:?}",
            d.len(),
        );
        assert!(
            d[0].message.contains("1 entry"),
            "message must contain \"1 entry\" (singular; `path=` must not prefix-cover `/usr/bin/lsof`); \
             got: {:?}",
            d[0].message,
        );
    }

    /// An `exe=` literal is an exact-key reference too (covers subject-side paths).
    /// A wrong impl that only inspects `path=`/`dir=` object attributes would orphan a
    /// key that a rule references via subject `exe=` -> FAILS (expects empty).
    ///
    /// Adversarial coverage:
    /// - An impl that ignores `exe=` references orphans the key and emits a diagnostic
    ///   -> FAILS the `assert!(diags.is_empty())` assertion.
    /// - The empty stub returns [] -> PASSES (fine; the stub is wrong in test 1).
    #[test]
    fn exe_reference_covers_key() {
        let tmp = tempdir().expect("tempdir");
        write_fixture(tmp.path(), &["/usr/bin/ls"]);
        let db = open_trustdb_readonly(tmp.path()).unwrap();

        // Subject exe=/usr/bin/ls references /usr/bin/ls as an exact key.
        let files = vec![(
            PathBuf::from("rules.d/10-a.rules"),
            vec![rule(
                1,
                Decision::Allow,
                vec![kv("exe", "/usr/bin/ls")],
                vec![Attr::All],
            )],
        )];

        let diags = lint_orphans(&files, &db);
        assert!(
            diags.is_empty(),
            "`exe=` reference to `/usr/bin/ls` must cover the key (0 orphans); \
             got {}: {diags:?}",
            diags.len(),
        );
    }

    /// Only an `allow all:all` rule suppresses X01. A `deny all:all` does NOT make
    /// every DB entry reachable, so orphans are still reported.
    ///
    /// Kills the `is_allow -> true` mutant: that mutant makes `is_allow_all` return
    /// true for ANY decision including Deny, so the deny rule would wrongly suppress
    /// X01 and return 0 diagnostics. The correct impl requires the decision to be an
    /// allow variant, so a `deny all:all` leaves 2 orphans.
    ///
    /// Adversarial coverage:
    /// - The `is_allow -> true` mutant suppresses X01 for any decision -> returns []
    ///   -> FAILS `assert_eq!(d.len(), 1)`. RED against mutant.
    /// - Correct impl: deny does not satisfy `is_allow` -> orphans reported -> PASSES.
    #[test]
    fn deny_all_all_does_not_suppress() {
        let tmp = tempdir().expect("tempdir");
        write_fixture(tmp.path(), &["/a", "/b"]);
        let db = open_trustdb_readonly(tmp.path()).unwrap();

        // deny all : all -- does NOT make every DB entry reachable.
        let files = vec![(
            PathBuf::from("rules.d/90-deny.rules"),
            vec![rule(
                1,
                Decision::Deny,
                vec![Attr::All],
                vec![Attr::All],
            )],
        )];

        let d = lint_orphans(&files, &db);
        assert_eq!(
            d.len(),
            1,
            "`deny all:all` must NOT suppress X01; both /a and /b are orphans; \
             got {}: {d:?}",
            d.len(),
        );
        assert!(
            d[0].message.contains("2 entries"),
            "message must contain \"2 entries\" (both keys are orphans); got: {:?}",
            d[0].message,
        );
    }
}
