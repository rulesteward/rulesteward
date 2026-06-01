//! fapd-W05: validate `uid=` / `gid=` literals against the host identity database
//! by shelling out to `getent passwd` / `getent group` (read-only, opt-in).
//!
//! Shelling out to `getent` resolves through the host NSS stack (SSSD/LDAP/AD
//! included) and works in the static musl binary, which cannot `dlopen` NSS
//! modules - the reason a direct `/etc/passwd` parse is insufficient.
//!
//! Phase-0 stub: the W05 impl pipeline fills the getent shell-out + per-attribute
//! checks. The signature is frozen here so the fan-out edits only this file's
//! body (plus its helper) and not the shared `lints/mod.rs` dispatcher. Gated by
//! `LintContext.check_identities`.

use std::path::Path;
use std::process::Command;

use rulesteward_core::{Diagnostic, Severity};

use super::anchored;
use crate::ast::{Attr, AttrValue, Entry};

/// The kind of identity being checked: user (passwd) or group.
///
/// Passed to the injected resolver so mock closures can distinguish the two
/// lookup databases without knowing getent command details.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IdKind {
    User,
    Group,
}

/// Result of a single identity lookup.
///
/// - `Found`: the value resolved in the relevant database (no diagnostic).
/// - `NotFound`: exit 2 from getent - the value is unknown (fire W05).
/// - `Error`: getent exited with a code other than 0 or 2 (NSS error, timeout,
///   etc.) - be conservative and do NOT fire W05.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Resolution {
    Found,
    NotFound,
    Error,
}

/// Inner implementation with an injectable resolver.
///
/// Implementer MUST provide this function signature exactly so the unit tests
/// (which supply a mock resolver closure) compile and link correctly. The public
/// `walk` function wraps this with a real getent resolver.
///
/// `resolve(kind, value) -> Resolution` is called once per `uid=` / `gid=`
/// literal attribute encountered. Non-literal values (`SetRef`) are skipped.
/// Integer (`Int`) values are coerced to their decimal string form and resolved.
/// Non-uid/gid keys are skipped. A `Resolution::Error` conservatively suppresses
/// the diagnostic.
pub(crate) fn w05_with_resolver(
    entries: &[Entry],
    file: &Path,
    resolve: impl Fn(IdKind, &str) -> Resolution,
) -> Vec<Diagnostic> {
    let mut diags = Vec::new();
    for entry in entries {
        let Entry::Rule(rule) = entry else {
            continue;
        };
        for attr in rule.subject.iter().chain(rule.object.iter()) {
            let Attr::Kv { key, value, .. } = attr else {
                continue;
            };
            // Only check uid= and gid= attributes.
            let kind = match key.as_str() {
                "uid" => IdKind::User,
                "gid" => IdKind::Group,
                _ => continue,
            };
            // Extract the string value to check: Str as-is, Int coerced to decimal,
            // SetRef (macro reference) skipped entirely.
            let val_str: String = match value {
                AttrValue::Str(s) => s.clone(),
                AttrValue::Int(n) => n.to_string(),
                AttrValue::SetRef(_) => continue,
            };
            match resolve(kind, &val_str) {
                Resolution::NotFound => {
                    let db_name = match kind {
                        IdKind::User => "passwd",
                        IdKind::Group => "group",
                    };
                    diags.push(anchored(
                        Severity::Warning,
                        "fapd-W05",
                        rule.span.clone(),
                        format!(
                            "`{key}={val_str}` does not resolve in the host `{db_name}` database \
                             (`getent {db_name} {val_str}` exited 2 - not found)"
                        ),
                        file,
                        rule.line,
                    ));
                }
                // Found: clean, no diagnostic.
                // Error: conservative no-fire.
                Resolution::Found | Resolution::Error => {}
            }
        }
    }
    diags
}

/// Real getent-backed resolver. Shells out to `getent passwd <value>` for
/// `IdKind::User` and `getent group <value>` for `IdKind::Group`.
///
/// Exit code mapping (POSIX / glibc getent convention):
///   0  -> Found (entry printed to stdout)
///   2  -> `NotFound` (key absent in the database)
///   other -> Error (NSS error, missing binary, timeout - conservative no-fire)
fn getent_resolve(kind: IdKind, value: &str) -> Resolution {
    let database = match kind {
        IdKind::User => "passwd",
        IdKind::Group => "group",
    };
    let result = Command::new("getent").arg(database).arg(value).status();
    match result {
        Ok(status) => match status.code() {
            Some(0) => Resolution::Found,
            Some(2) => Resolution::NotFound,
            _ => Resolution::Error,
        },
        // Spawn failure (getent not found, permission denied, etc.) - conservative.
        Err(_) => Resolution::Error,
    }
}

/// Validate `uid=` / `gid=` literals against the host identity database.
/// Uses `getent` to resolve through the host NSS stack (SSSD/LDAP/AD included).
/// Gated by `LintContext.check_identities` in the caller (`lints/mod.rs`).
#[must_use]
pub(crate) fn walk(entries: &[Entry], file: &Path) -> Vec<Diagnostic> {
    w05_with_resolver(entries, file, getent_resolve)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
//
// Getent ground truth confirmed on this host (GNU libc 2.43):
//
//   getent passwd 0          -> "root:x:0:0:Super User:/root:/bin/bash", exit 0
//   getent passwd root       -> "root:x:0:0:Super User:/root:/bin/bash", exit 0
//   getent passwd 4294967294 -> (no output), exit 2
//   getent passwd rs_no_such_user_trap_xyz -> (no output), exit 2
//   getent group  0          -> "root:x:0:", exit 0
//   getent group  root       -> "root:x:0:", exit 0
//   getent group  4294967294 -> (no output), exit 2
//   getent group  rs_no_such_group_trap_xyz -> (no output), exit 2
//
// exit 0  = found (entry printed to stdout).
// exit 2  = one or more keys not found (POSIX / glibc convention for getent).
// exit !={0,2} = NSS/tool error; be conservative, do not fire W05.
//
// passwd line format: name:passwd:uid:gid:gecos:dir:shell
// group  line format: name:passwd:gid:members
//
// `getent passwd <key>` accepts numeric uid OR username string.
// `getent group  <key>` accepts numeric gid OR group-name string.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::{Attr, Decision};
    use crate::lints::testkit::{kv, kv_int, kv_ref, modern_rule, p};
    use crate::lints::{LintContext, lint_with_context};
    use rulesteward_core::Severity;

    // Helper: build a mock resolver that returns `Found` for every value in
    // `found_vals` and `NotFound` for everything else. The kind parameter is
    // checked to ensure the right database is being queried.
    fn resolver_found(
        found_vals: &'static [(&'static str, IdKind)],
    ) -> impl Fn(IdKind, &str) -> Resolution {
        move |kind, val| {
            if found_vals.iter().any(|(v, k)| *k == kind && *v == val) {
                Resolution::Found
            } else {
                Resolution::NotFound
            }
        }
    }

    // Convenience: a resolver that always returns NotFound.
    fn resolver_not_found() -> impl Fn(IdKind, &str) -> Resolution {
        |_kind, _val| Resolution::NotFound
    }

    // Convenience: a resolver that always returns Error.
    fn resolver_error() -> impl Fn(IdKind, &str) -> Resolution {
        |_kind, _val| Resolution::Error
    }

    // ---------------------------------------------------------------------------
    // Q1: numeric uid value that resolves -> no W05.
    //
    // Adversarial: a trivial "always fire" impl fails this test because it
    // would emit a W05 for uid=0 even when the resolver says Found.
    // PASSES against the empty stub (stub returns [] == expect empty).
    // RED against a correct impl if it ignores the resolver result.
    // ---------------------------------------------------------------------------
    #[test]
    fn numeric_uid_resolves_no_w05() {
        let entries = vec![modern_rule(
            1,
            Decision::Allow,
            None,
            vec![kv("uid", "0")],
            vec![Attr::All],
        )];
        // Resolver: uid=0 is Found.
        let resolve = resolver_found(&[("0", IdKind::User)]);
        let diags = w05_with_resolver(&entries, &p(), resolve);
        assert!(
            diags.is_empty(),
            "uid=0 resolves via passwd -> no W05 expected, got: {diags:?}"
        );
    }

    // ---------------------------------------------------------------------------
    // Q2: numeric uid value that does NOT resolve -> exactly one fapd-W05.
    //
    // Adversarial: the empty stub returns [], so this test is RED against the stub.
    // A trivial "never fire" impl also fails this test.
    // ---------------------------------------------------------------------------
    #[test]
    fn numeric_uid_not_found_fires_w05() {
        let entries = vec![modern_rule(
            1,
            Decision::Allow,
            None,
            // uid=4294967294 is confirmed absent on this host (getent exit 2).
            vec![kv("uid", "4294967294")],
            vec![Attr::All],
        )];
        let diags = w05_with_resolver(&entries, &p(), resolver_not_found());
        assert_eq!(
            diags.len(),
            1,
            "uid=4294967294 not found in passwd -> exactly 1 fapd-W05, got {}: {diags:?}",
            diags.len()
        );
        assert_eq!(
            diags[0].code, "fapd-W05",
            "diagnostic code must be fapd-W05, got {:?}",
            diags[0].code
        );
        assert_eq!(
            diags[0].severity,
            Severity::Warning,
            "fapd-W05 must have Severity::Warning, got {:?}",
            diags[0].severity
        );
        assert!(
            diags[0].message.contains("4294967294"),
            "diagnostic message must contain the unresolved value '4294967294', got {:?}",
            diags[0].message
        );
        assert_eq!(
            diags[0].line, 1,
            "W05 must point at the line with the offending uid= attr, got line={}",
            diags[0].line
        );
    }

    // ---------------------------------------------------------------------------
    // Q2b: the W05 diagnostic LINE is derived from the offending rule's line, not
    // hardcoded. Every other unit-test rule sits on line 1, so a wrong impl that
    // hardcodes `line = 1` survives them; this rule sits on line 7. RED against
    // the empty stub (0 diagnostics) AND against any line=1 hardcode. Closes the
    // adversarial-review CONCERN that line correctness was pinned only by the
    // self-baked snapshot.
    // ---------------------------------------------------------------------------
    #[test]
    fn uid_not_found_diagnostic_line_matches_rule_line() {
        let entries = vec![modern_rule(
            7,
            Decision::Allow,
            None,
            vec![kv("uid", "4294967294")],
            vec![Attr::All],
        )];
        let diags = w05_with_resolver(&entries, &p(), resolver_not_found());
        assert_eq!(
            diags.len(),
            1,
            "expected exactly 1 fapd-W05 for the unresolved uid, got {}: {diags:?}",
            diags.len()
        );
        assert_eq!(
            diags[0].line, 7,
            "W05 line must be the offending rule's line (7), not a hardcoded 1, got {}",
            diags[0].line
        );
    }

    // ---------------------------------------------------------------------------
    // Q3: name-form uid resolves -> no W05.
    //
    // Adversarial: a numeric-only impl would fail to resolve "alice" and falsely fire.
    // PASSES against the empty stub (stub returns [] == expect empty).
    // ---------------------------------------------------------------------------
    #[test]
    fn name_uid_resolves_no_w05() {
        let entries = vec![modern_rule(
            1,
            Decision::Allow,
            None,
            // "root" is confirmed to resolve via `getent passwd root` (exit 0).
            vec![kv("uid", "root")],
            vec![Attr::All],
        )];
        let resolve = resolver_found(&[("root", IdKind::User)]);
        let diags = w05_with_resolver(&entries, &p(), resolve);
        assert!(
            diags.is_empty(),
            "uid=root resolves via passwd -> no W05 expected, got: {diags:?}"
        );
    }

    // ---------------------------------------------------------------------------
    // Q4: name-form uid that does NOT resolve -> exactly one fapd-W05.
    //
    // Adversarial: empty stub returns [], so RED against the stub.
    // ---------------------------------------------------------------------------
    #[test]
    fn name_uid_not_found_fires_w05() {
        let entries = vec![modern_rule(
            1,
            Decision::Allow,
            None,
            vec![kv("uid", "rs_no_such_user_trap_xyz")],
            vec![Attr::All],
        )];
        let diags = w05_with_resolver(&entries, &p(), resolver_not_found());
        assert_eq!(
            diags.len(),
            1,
            "uid=rs_no_such_user_trap_xyz not found -> exactly 1 fapd-W05, got {}: {diags:?}",
            diags.len()
        );
        assert_eq!(diags[0].code, "fapd-W05");
        assert_eq!(diags[0].severity, Severity::Warning);
        assert!(
            diags[0].message.contains("rs_no_such_user_trap_xyz"),
            "message must name the unresolved uid value, got {:?}",
            diags[0].message
        );
    }

    // ---------------------------------------------------------------------------
    // Q5: numeric gid that resolves via `getent group` -> no W05.
    //
    // Adversarial: an impl that queries passwd for gid= values would fail.
    // PASSES against the empty stub.
    // ---------------------------------------------------------------------------
    #[test]
    fn numeric_gid_resolves_no_w05() {
        let entries = vec![modern_rule(
            1,
            Decision::Allow,
            None,
            // gid=0 is confirmed to resolve via `getent group 0` (exit 0).
            vec![kv("gid", "0")],
            vec![Attr::All],
        )];
        let resolve = resolver_found(&[("0", IdKind::Group)]);
        let diags = w05_with_resolver(&entries, &p(), resolve);
        assert!(
            diags.is_empty(),
            "gid=0 resolves via group db -> no W05 expected, got: {diags:?}"
        );
    }

    // ---------------------------------------------------------------------------
    // Q6: numeric gid that does NOT resolve -> exactly one fapd-W05.
    //
    // Adversarial: empty stub is RED here. Also adversarial against an impl that
    // uses passwd instead of group for gid= lookups.
    // ---------------------------------------------------------------------------
    #[test]
    fn numeric_gid_not_found_fires_w05() {
        let entries = vec![modern_rule(
            1,
            Decision::Allow,
            None,
            // gid=4294967294 is confirmed absent (getent group exit 2).
            vec![kv("gid", "4294967294")],
            vec![Attr::All],
        )];
        let diags = w05_with_resolver(&entries, &p(), resolver_not_found());
        assert_eq!(
            diags.len(),
            1,
            "gid=4294967294 not found in group db -> exactly 1 fapd-W05, got {}: {diags:?}",
            diags.len()
        );
        assert_eq!(diags[0].code, "fapd-W05");
        assert_eq!(diags[0].severity, Severity::Warning);
        assert!(
            diags[0].message.contains("4294967294"),
            "message must name the unresolved gid value, got {:?}",
            diags[0].message
        );
    }

    // ---------------------------------------------------------------------------
    // Q7: %macroref uid value is SKIPPED - no W05 regardless of resolution.
    //
    // Adversarial: a naive impl that calls the resolver on all Attr::Kv values
    // without checking the AttrValue discriminant would attempt to resolve
    // "%MY_USERS" as a literal and fire W05.
    // PASSES against the empty stub.
    // RED against an impl that does not skip SetRef values.
    // ---------------------------------------------------------------------------
    #[test]
    fn macro_ref_uid_is_skipped_no_w05() {
        let entries = vec![modern_rule(
            1,
            Decision::Allow,
            None,
            // AttrValue::SetRef("MY_USERS") - a macro reference, not a literal.
            vec![kv_ref("uid", "MY_USERS")],
            vec![Attr::All],
        )];
        // Even with a resolver that always says NotFound, no W05 should fire.
        let diags = w05_with_resolver(&entries, &p(), resolver_not_found());
        assert!(
            diags.is_empty(),
            "uid=%MY_USERS is a macro reference - must be skipped, no W05, got: {diags:?}"
        );
    }

    // ---------------------------------------------------------------------------
    // Q8: integer AttrValue uid is SKIPPED - no W05.
    //
    // The AST represents e.g. `uid=1000` as AttrValue::Int(1000) when the parser
    // recognises it as numeric. (fapolicyd allows both forms; the parser may
    // produce Int for a decimal literal that fits i64.) W05 must handle this
    // gracefully: either resolve via Int->string coercion OR skip. The test
    // asserts no panic and no spurious W05 when the resolver for "1000" says Found.
    //
    // NOTE: if the parser always produces AttrValue::Str for uid= values, this
    // test degrades to a PASS-against-stub (trivially empty). That is acceptable;
    // the test documents the expected behavior regardless of the AST representation.
    // ---------------------------------------------------------------------------
    #[test]
    fn integer_uid_value_handled_gracefully() {
        let entries = vec![modern_rule(
            1,
            Decision::Allow,
            None,
            vec![kv_int("uid", 1000)],
            vec![Attr::All],
        )];
        // Resolver returns Found for "1000" if the impl coerces Int to string.
        let resolve = resolver_found(&[("1000", IdKind::User)]);
        let diags = w05_with_resolver(&entries, &p(), resolve);
        // If the impl skips Int values: empty (acceptable).
        // If the impl coerces Int -> str and resolver says Found: empty (acceptable).
        // If the impl coerces Int -> str and resolver says NotFound: 1 W05 (bad!).
        // We test with a Found resolver so either skip or coerce+Found both pass.
        assert!(
            diags.is_empty(),
            "uid=<int> should either be skipped or resolve Found - no W05 expected, got: {diags:?}"
        );
    }

    // ---------------------------------------------------------------------------
    // Q9: two bad uid= values -> TWO W05 diagnostics (not collapsed to one).
    //
    // Adversarial: an impl that deduplicates or caps at one diagnostic per file
    // would return only 1, failing this test.
    // RED against the empty stub.
    // ---------------------------------------------------------------------------
    #[test]
    fn two_bad_uid_values_produce_two_w05() {
        let entries = vec![
            modern_rule(
                1,
                Decision::Allow,
                None,
                vec![kv("uid", "rs_no_such_user_trap_a")],
                vec![Attr::All],
            ),
            modern_rule(
                2,
                Decision::Allow,
                None,
                vec![kv("uid", "rs_no_such_user_trap_b")],
                vec![Attr::All],
            ),
        ];
        let diags = w05_with_resolver(&entries, &p(), resolver_not_found());
        assert_eq!(
            diags.len(),
            2,
            "two rules with different unresolved uid= values must each produce one fapd-W05 \
             (not collapsed), got {}: {diags:?}",
            diags.len()
        );
        // Both must be W05.
        for d in &diags {
            assert_eq!(
                d.code, "fapd-W05",
                "each diagnostic must be fapd-W05, got {:?}",
                d.code
            );
        }
        // Diagnostics must name the respective uid values.
        let msgs: Vec<&str> = diags.iter().map(|d| d.message.as_str()).collect();
        assert!(
            msgs.iter().any(|m| m.contains("rs_no_such_user_trap_a")),
            "one W05 must name 'rs_no_such_user_trap_a', got: {msgs:?}"
        );
        assert!(
            msgs.iter().any(|m| m.contains("rs_no_such_user_trap_b")),
            "one W05 must name 'rs_no_such_user_trap_b', got: {msgs:?}"
        );
    }

    // ---------------------------------------------------------------------------
    // Q10: getent error conservatism - resolver returns Error -> no W05.
    //
    // Adversarial: an impl that treats Error as NotFound would fire W05 here.
    // PASSES against the empty stub.
    // RED against an impl that does not distinguish Error from NotFound.
    // ---------------------------------------------------------------------------
    #[test]
    fn resolver_error_does_not_fire_w05() {
        let entries = vec![modern_rule(
            1,
            Decision::Allow,
            None,
            vec![kv("uid", "some_uid")],
            vec![Attr::All],
        )];
        // Resolver always returns Error (e.g. NSS timeout, getent crash).
        let diags = w05_with_resolver(&entries, &p(), resolver_error());
        assert!(
            diags.is_empty(),
            "getent error must conservatively suppress W05 (not fire it), got: {diags:?}"
        );
    }

    // ---------------------------------------------------------------------------
    // Q11: non-uid/gid keys (e.g. exe=, path=, dir=) are NOT checked by W05.
    //
    // Adversarial: a naive impl that iterates ALL Attr::Kv pairs and queries
    // getent for every value would attempt to resolve "/usr/bin/bash" as a uid.
    // PASSES against the empty stub.
    // RED against an impl that does not filter on key name.
    // ---------------------------------------------------------------------------
    #[test]
    fn non_uid_gid_keys_are_not_checked() {
        let entries = vec![modern_rule(
            1,
            Decision::Allow,
            None,
            // exe= is a subject attr - not a uid/gid identity check.
            vec![kv("exe", "/usr/bin/bash")],
            // path= is an object attr - also not a uid/gid identity check.
            vec![kv("path", "rs_no_such_user_trap_xyz")],
        )];
        // Resolver says NotFound for everything - only fires if the impl incorrectly
        // checks non-uid/gid keys.
        let diags = w05_with_resolver(&entries, &p(), resolver_not_found());
        assert!(
            diags.is_empty(),
            "exe= and path= are not identity keys - no W05 expected, got: {diags:?}"
        );
    }

    // ---------------------------------------------------------------------------
    // Q12: gate test - with check_identities=false, no W05 fires even for a
    // confirmed-bad uid value. Drives via lint_with_context.
    //
    // Adversarial: an impl that ignores ctx.check_identities would fire W05
    // even with the gate off. Since W05 uses the REAL getent path via walk(),
    // we use a universally-absent uid to ensure the real getent would fire W05
    // when the gate IS on (see Q13 integration test). With gate off, must be empty.
    // PASSES against the empty stub (walk() returns empty = gate-off is trivially ok).
    // RED against an impl that wires W05 outside the ctx.check_identities guard.
    // ---------------------------------------------------------------------------
    #[test]
    fn gate_off_no_w05_even_for_bad_uid() {
        // uid=4294967294 is confirmed absent on this host (getent exit 2).
        let src = "allow uid=4294967294 : all\n";
        let path = std::path::Path::new("tests/corpus/traps/fapd-W05/uid-gate-off.rules");
        let entries = crate::parser::parse_rules_file(src, path)
            .unwrap_or_else(|diags| panic!("fixture must parse: {diags:?}"));
        // Default context has check_identities=false.
        let diags = lint_with_context(&entries, src, path, &LintContext::default());
        let w05_count = diags
            .iter()
            .filter(|d| d.code.as_ref() == "fapd-W05")
            .count();
        assert_eq!(
            w05_count, 0,
            "check_identities=false must suppress ALL W05 diagnostics, \
             got {w05_count} W05 in: {diags:?}"
        );
    }

    // ---------------------------------------------------------------------------
    // Integration test I1: real getent path - uid=0 (root) MUST NOT fire W05.
    //
    // uid=0 is universally stable: root exists on every POSIX host.
    // getent passwd 0 -> "root:x:0:0:Super User:/root:/bin/bash", exit 0
    // (confirmed on this host, GNU libc 2.43)
    //
    // Drives via walk() (the real getent path) with check_identities=true.
    // PASSES against the empty stub (walk() returns [] == expect empty).
    // RED against a correct impl if it incorrectly fires W05 for uid=0.
    // ---------------------------------------------------------------------------
    #[test]
    fn integration_uid_root_resolves_no_w05() {
        let src = "allow uid=0 : all\n";
        let path = std::path::Path::new("tests/corpus/traps/fapd-W05/uid-root-clean.rules");
        let entries = crate::parser::parse_rules_file(src, path)
            .unwrap_or_else(|diags| panic!("fixture must parse: {diags:?}"));
        let ctx = LintContext {
            check_identities: true,
            ..Default::default()
        };
        let diags = lint_with_context(&entries, src, path, &ctx);
        let w05_diags: Vec<_> = diags
            .iter()
            .filter(|d| d.code.as_ref() == "fapd-W05")
            .collect();
        assert!(
            w05_diags.is_empty(),
            "uid=0 (root) resolves on every POSIX host via getent passwd 0 -> no W05 \
             expected (got {}: {w05_diags:?})",
            w05_diags.len()
        );
    }

    // ---------------------------------------------------------------------------
    // Integration test I2: real getent path - uid=4294967294 MUST fire W05.
    //
    // uid=4294967294 is confirmed absent on this host:
    //   getent passwd 4294967294 -> (no output), exit 2
    // (confirmed on this host, GNU libc 2.43)
    //
    // Drives via walk() with check_identities=true via lint_with_context.
    // RED against the empty stub (walk() returns [] but we expect 1 W05).
    // ---------------------------------------------------------------------------
    #[test]
    fn integration_uid_absent_fires_w05() {
        // uid=4294967294 is below POSIX uid_t max (2^32-1 = 4294967295) but is
        // guaranteed absent on any real host by virtue of being a reserved/trap value.
        let src = "allow uid=4294967294 : all\n";
        let path = std::path::Path::new("tests/corpus/traps/fapd-W05/uid-absent-fires.rules");
        let entries = crate::parser::parse_rules_file(src, path)
            .unwrap_or_else(|diags| panic!("fixture must parse: {diags:?}"));
        let ctx = LintContext {
            check_identities: true,
            ..Default::default()
        };
        let diags = lint_with_context(&entries, src, path, &ctx);
        let w05_diags: Vec<_> = diags
            .iter()
            .filter(|d| d.code.as_ref() == "fapd-W05")
            .collect();
        assert_eq!(
            w05_diags.len(),
            1,
            "uid=4294967294 is absent from passwd (getent exit 2) -> exactly 1 W05 expected \
             via the real getent path, got {}: {diags:?}",
            w05_diags.len()
        );
        assert_eq!(
            w05_diags[0].code, "fapd-W05",
            "diagnostic code must be fapd-W05"
        );
        assert_eq!(
            w05_diags[0].severity,
            Severity::Warning,
            "fapd-W05 must be Warning severity"
        );
    }

    // Pins the real getent exit-code mapping DIRECTLY. The output-level tests
    // cannot distinguish Found from Error (both suppress W05), so the
    // `Some(0) => Found` arm in getent_resolve is unconstrained by them - a
    // mutation that deletes it survives. This asserts exit-0 -> Found (uid/gid 0
    // always resolve) and exit-2 -> NotFound (a reserved-high id is always
    // absent), killing the surviving mutant. Host-stable per the W05 grounding.
    #[test]
    fn getent_resolve_maps_real_exit_codes() {
        assert_eq!(getent_resolve(IdKind::User, "0"), Resolution::Found);
        assert_eq!(getent_resolve(IdKind::Group, "0"), Resolution::Found);
        assert_eq!(
            getent_resolve(IdKind::User, "4294967294"),
            Resolution::NotFound
        );
        assert_eq!(
            getent_resolve(IdKind::Group, "4294967294"),
            Resolution::NotFound
        );
    }
}
