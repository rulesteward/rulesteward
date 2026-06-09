//! Unit tests for `emit_te` - adversarial barrier tests for issue #103.
//!
//! Every load-bearing assertion in this file is grounded in a cited primary
//! source: the hand-validated `narrow.te` that compiled + loaded + was removed
//! on el9 (f4 grounding doc §3.1 + §3.3), the kernel AVC format
//! (`security/selinux/avc.c:659-722 (Linux v6.12)`), and the 8-invariant narrowness contract
//! (f4 §2.5). These tests are written BLIND to the implementation.
//!
//! Test naming convention: `test_<area>_<scenario>`.

use std::collections::BTreeSet;

use rulesteward_selinux::{DenialGroup, DenialKind, emit_te};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a `DenialGroup` with the `TeAllowable` kind (the common enforcing case).
fn group(source_type: &str, target_type: &str, tclass: &str, perms: &[&str]) -> DenialGroup {
    DenialGroup {
        source_type: source_type.to_string(),
        target_type: target_type.to_string(),
        tclass: tclass.to_string(),
        perms: perms
            .iter()
            .map(ToString::to_string)
            .collect::<BTreeSet<_>>(),
        any_permissive: false,
        kind: DenialKind::TeAllowable,
    }
}

/// Build a `DenialGroup` with an explicit kind.
fn group_with_kind(
    source_type: &str,
    target_type: &str,
    tclass: &str,
    perms: &[&str],
    kind: DenialKind,
) -> DenialGroup {
    DenialGroup {
        source_type: source_type.to_string(),
        target_type: target_type.to_string(),
        tclass: tclass.to_string(),
        perms: perms
            .iter()
            .map(ToString::to_string)
            .collect::<BTreeSet<_>>(),
        any_permissive: matches!(kind, DenialKind::Permissive),
        kind,
    }
}

// ---------------------------------------------------------------------------
// Anchor 1: The hand-validated el9 example (f4 §3.1 + §3.3)
//
// The hand-written narrow.te that compiled + loaded + was removed on el9:
//
//   module narrow 1.0;
//   require {
//       type logrotate_t;
//       type shadow_t;
//       class file { read getattr };
//       class dir read;
//   }
//   allow logrotate_t shadow_t:file { read getattr };
//   allow logrotate_t shadow_t:dir read;
//
// This is the PRIMARY grounding artifact (f4 §3.1). Every structural test below
// is derived from this exact shape.
// ---------------------------------------------------------------------------

/// The emitter must produce a `module NAME 1.0;` header as the very first line.
/// Source: f4 §3.1 "First line `module <name> <version>;`".
/// Grounded: the hand-validated narrow.te starts with `module narrow 1.0;`.
#[test]
fn test_header_module_line_first() {
    let groups = [group(
        "logrotate_t",
        "shadow_t",
        "file",
        &["read", "getattr"],
    )];
    let te = emit_te(&groups, Some("narrow"));
    let first_line = te.lines().next().expect("output must not be empty");
    assert_eq!(
        first_line, "module narrow 1.0;",
        "first line must be `module narrow 1.0;` (f4 §3.1 base-module form, not policy_module())"
    );
}

/// `policy_module(...)` is the m4 form that FAILED checkmodule (f4 §3.1 failure log).
/// A correct emitter must NEVER emit that string.
#[test]
fn test_header_no_policy_module_macro() {
    let groups = [group("logrotate_t", "shadow_t", "file", &["read"])];
    let te = emit_te(&groups, Some("narrow"));
    assert!(
        !te.contains("policy_module"),
        "output must not contain `policy_module` - that is the m4 form that fails checkmodule \
         (f4 §3.1: 'narrow.te:1:ERROR Building a policy module, but no module specification found.')"
    );
}

/// The output must contain a `require {` block (f4 §3.1: "forward-declare every
/// external type/class/perm used"). The block must be non-empty.
#[test]
fn test_require_block_present() {
    let groups = [group("logrotate_t", "shadow_t", "file", &["read"])];
    let te = emit_te(&groups, Some("narrow"));
    assert!(
        te.contains("require {"),
        "output must contain a `require {{` block (f4 §3.1 base-module forward-declaration)"
    );
    let require_start = te.find("require {").expect("require block must exist");
    let require_end = te[require_start..]
        .find('}')
        .expect("require block must be closed");
    let inner = &te[require_start + "require {".len()..require_start + require_end];
    assert!(
        !inner.trim().is_empty(),
        "require block must not be empty when there are denial groups"
    );
}

/// The require block must declare ALL distinct source and target types.
/// Source: f4 §3.1 "declaring EVERY type, class, and per-class permission set".
/// Grounded: `type logrotate_t;` and `type shadow_t;` in narrow.te.
#[test]
fn test_require_declares_source_and_target_types() {
    let groups = [group(
        "logrotate_t",
        "shadow_t",
        "file",
        &["read", "getattr"],
    )];
    let te = emit_te(&groups, Some("narrow"));
    assert!(
        te.contains("type logrotate_t;"),
        "require block must forward-declare source type `logrotate_t`"
    );
    assert!(
        te.contains("type shadow_t;"),
        "require block must forward-declare target type `shadow_t`"
    );
}

/// When two groups share a type the require block must declare that type ONCE.
/// No duplicate `type X;` lines (f4 §3.1 "Group classes ONCE with their union").
#[test]
fn test_require_no_duplicate_type_declarations() {
    let groups = [
        group("logrotate_t", "shadow_t", "file", &["read"]),
        group("logrotate_t", "shadow_t", "dir", &["search"]),
    ];
    let te = emit_te(&groups, Some("narrow"));
    let type_logrotate_count = te.matches("type logrotate_t;").count();
    let type_shadow_count = te.matches("type shadow_t;").count();
    assert_eq!(
        type_logrotate_count, 1,
        "source type `logrotate_t` must appear exactly once in require block"
    );
    assert_eq!(
        type_shadow_count, 1,
        "target type `shadow_t` must appear exactly once in require block"
    );
}

/// The require block must declare each class with the UNION of perms across all
/// groups that reference that class.
/// Source: f4 §3.1 "Group classes once with their union of perms: `class file { read getattr };`".
/// Grounded: narrow.te line `class file { read getattr };`.
/// Perm order: `BTreeSet<String>` iterates alphabetically, so `open` < `read` -> `class file { open read };`.
#[test]
fn test_require_class_perm_union_across_groups() {
    // Two groups with the SAME (source, target, tclass) triple but DIFFERENT perms.
    // The require block must declare `class file` EXACTLY ONCE with the unioned perm set.
    // A per-group-duplicate impl emitting two separate `class file { read };` and
    // `class file { open };` lines (no union) must fail this test.
    let groups = [
        group("httpd_t", "shadow_t", "file", &["read"]),
        group("httpd_t", "shadow_t", "file", &["open"]),
    ];
    let te = emit_te(&groups, Some("test_mod"));
    // BTreeSet ordering: "open" < "read" alphabetically -> unioned line is
    // `class file { open read };` (f4 §3.1 union form, BTreeSet-sorted).
    assert!(
        te.contains("class file { open read };"),
        "require block must union both perms into ONE `class file {{ open read }};` line \
         (f4 §3.1 union form, BTreeSet alphabetical order)\n\ngot:\n{te}"
    );
    // Exactly one `class file` declaration - a per-group-duplicate impl emitting two
    // separate lines passes the substring check above but fails this count assertion.
    assert_eq!(
        te.matches("class file").count(),
        1,
        "require block must declare `class file` EXACTLY once (no per-group duplicates)\n\ngot:\n{te}"
    );
}

/// The require block must declare classes as well as types.
/// Source: f4 §3.1 narrow.te: `class file {{ read getattr }};` and `class dir read;`.
#[test]
fn test_require_declares_classes() {
    let groups = [
        group("logrotate_t", "shadow_t", "file", &["read", "getattr"]),
        group("logrotate_t", "shadow_t", "dir", &["read"]),
    ];
    let te = emit_te(&groups, Some("narrow"));
    assert!(
        te.contains("class file"),
        "require block must declare `class file`"
    );
    assert!(
        te.contains("class dir"),
        "require block must declare `class dir`"
    );
}

// ---------------------------------------------------------------------------
// Anchor 2: allow rule shape (f4 §3.1 + §2.5 invariants 1-5)
// ---------------------------------------------------------------------------

/// Multi-perm allow rule: perms in braces, no padding.
/// Source: f4 §3.1 narrow.te: `allow logrotate_t shadow_t:file { read getattr };`
/// Invariant 3 (f4 §2.5): exact perm set only, no perm-set expansion.
#[test]
fn test_allow_multi_perm_in_braces() {
    let groups = [group(
        "logrotate_t",
        "shadow_t",
        "file",
        &["read", "getattr"],
    )];
    let te = emit_te(&groups, Some("narrow"));
    // The allow rule must exist in the exact grounded form.
    // BTreeSet ensures perm order is `getattr read` (alphabetical).
    assert!(
        te.contains("allow logrotate_t shadow_t:file { getattr read };"),
        "multi-perm allow rule must use brace form with sorted perms: \
         `allow logrotate_t shadow_t:file {{ getattr read }};`\n\ngot:\n{te}"
    );
}

/// Single-perm allow rule: NO braces (matches narrow.te hand-validated shape).
/// Source: f4 §3.1 narrow.te: `allow logrotate_t shadow_t:dir read;`
/// The hand-validated .te that passed checkmodule uses this bare form for single perms.
#[test]
fn test_allow_single_perm_no_braces() {
    let groups = [group("logrotate_t", "shadow_t", "dir", &["read"])];
    let te = emit_te(&groups, Some("narrow"));
    assert!(
        te.contains("allow logrotate_t shadow_t:dir read;"),
        "single-perm allow rule must NOT use braces (grounded in narrow.te hand-validated form)\n\ngot:\n{te}"
    );
}

/// No interface macros in output (f4 §2.5 invariant 1: "No interface macros").
/// Invariant 2: "No `typeattribute`".
/// Invariant 4: "No unrelated types" - no `etc_t` when not in any denial.
/// Source: f4 §2.3 demonstrates audit2allow `-R` emitting `auth_read_shadow()` etc.
#[test]
fn test_no_interface_macros_or_typeattribute() {
    let groups = [group(
        "logrotate_t",
        "shadow_t",
        "file",
        &["read", "getattr"],
    )];
    let te = emit_te(&groups, Some("narrow"));
    assert!(
        !te.contains("auth_read_shadow"),
        "output must not contain refpolicy interface macro `auth_read_shadow`"
    );
    assert!(
        !te.contains("typeattribute"),
        "output must not contain `typeattribute` (f4 §2.5 invariant 2)"
    );
    assert!(
        !te.contains("etc_t"),
        "output must not contain unrelated type `etc_t` (f4 §2.5 invariant 4)"
    );
    assert!(
        !te.contains("read_file_perms"),
        "output must not contain perm-set macro `read_file_perms` (f4 §2.5 invariant 3)"
    );
}

/// One allow rule per (source, target, class) triple (f4 §2.5 invariant 5).
/// Perms for the SAME triple are unioned into one rule; perms for different triples
/// go on separate lines.
#[test]
fn test_one_allow_per_triple() {
    let groups = [
        group("logrotate_t", "shadow_t", "file", &["read", "getattr"]),
        group("logrotate_t", "shadow_t", "dir", &["read"]),
    ];
    let te = emit_te(&groups, Some("narrow"));
    let allow_count = te
        .lines()
        .filter(|l| l.trim_start().starts_with("allow "))
        .count();
    assert_eq!(
        allow_count, 2,
        "two different triples must produce exactly 2 allow lines"
    );
    assert!(
        te.contains("allow logrotate_t shadow_t:file { getattr read };"),
        "file allow must contain both perms in brace form"
    );
    assert!(
        te.contains("allow logrotate_t shadow_t:dir read;"),
        "dir allow must use bare perm form (single perm)"
    );
}

/// Exact perm set - no `open`, `ioctl`, `lock` padding from the perm-set macros.
/// Source: f4 §2.3 + §2.5 invariant 3: the 2 denied perms must not become 5.
/// Grounded: audit2allow `-R` on `{ read getattr }` produced 5 perms; we must emit exactly 2.
#[test]
fn test_exact_perms_no_padding() {
    let groups = [group(
        "logrotate_t",
        "shadow_t",
        "file",
        &["read", "getattr"],
    )];
    let te = emit_te(&groups, Some("narrow"));
    // The allow line must have EXACTLY these two perms, no more.
    assert!(
        !te.contains("ioctl"),
        "output must not pad with `ioctl` (perm-set expansion, f4 §2.5 invariant 3)"
    );
    assert!(
        !te.contains(" lock"),
        "output must not pad with `lock` (perm-set expansion)"
    );
    assert!(
        !te.contains(" open"),
        "output must not pad with `open` (perm-set expansion)"
    );
}

// ---------------------------------------------------------------------------
// Anchor 3: Permissive groups - NO allow rule emitted (f4 §2.5 invariant 6)
//
// "permissive=1 denials are reported but NOT auto-suggested as allows"
// "a permissive denial did not block anything, so suggesting an allow for it
//  may grant access the operator only saw because the domain was permissive."
// ---------------------------------------------------------------------------

/// A permissive group (`any_permissive=true`, `kind=Permissive`) must NOT produce
/// an `allow` rule in the emitted .te.
/// Source: f4 §2.5 invariant 6.
#[test]
fn test_permissive_group_no_allow_emitted() {
    let groups = [group_with_kind(
        "httpd_t",
        "shadow_t",
        "file",
        &["read"],
        DenialKind::Permissive,
    )];
    let te = emit_te(&groups, Some("test_mod"));
    assert!(
        !te.contains("allow httpd_t"),
        "a Permissive denial group must not produce an `allow` rule (f4 §2.5 invariant 6)\n\ngot:\n{te}"
    );
}

/// Mixed: one enforcing group + one permissive group. Only the enforcing group
/// must produce an allow rule.
#[test]
fn test_mixed_enforcing_and_permissive_only_enforcing_has_allow() {
    let groups = [
        group("logrotate_t", "shadow_t", "file", &["read"]),
        group_with_kind(
            "httpd_t",
            "shadow_t",
            "file",
            &["write"],
            DenialKind::Permissive,
        ),
    ];
    let te = emit_te(&groups, Some("test_mod"));
    assert!(
        te.contains("allow logrotate_t"),
        "enforcing group must produce an allow rule"
    );
    assert!(
        !te.contains("allow httpd_t"),
        "permissive group must not produce an allow rule (f4 §2.5 invariant 6)"
    );
}

// ---------------------------------------------------------------------------
// Anchor 4: Module name validation (f4 §3.1, audit2allow:114 `is_valid_name`)
//
// Valid name regex: ^[A-Za-z][A-Za-z0-9._-]*$
// audit2allow validates this (f4 §3.1 cited from audit2allow source).
// ---------------------------------------------------------------------------

/// A supplied module name is used verbatim in the `module` line.
#[test]
fn test_module_name_supplied_used_verbatim() {
    let groups = [group("logrotate_t", "shadow_t", "file", &["read"])];
    let te = emit_te(&groups, Some("my_module_1"));
    let first_line = te.lines().next().unwrap();
    assert_eq!(
        first_line, "module my_module_1 1.0;",
        "supplied module name must appear verbatim in the header"
    );
}

/// `None` module name must produce some non-empty default name, not a panic.
/// The default name must satisfy the valid-name regex (start with a letter).
/// Source: f4 §3.1 "name = a valid identifier".
#[test]
fn test_module_name_default_when_none() {
    let groups = [group("logrotate_t", "shadow_t", "file", &["read"])];
    let te = emit_te(&groups, None);
    let first_line = te.lines().next().expect("output must not be empty");
    // Must start with `module ` and end with ` 1.0;`
    assert!(
        first_line.starts_with("module "),
        "module header must start with `module ` even when name=None"
    );
    assert!(
        first_line.ends_with(" 1.0;"),
        "module header must end with ` 1.0;` even when name=None"
    );
    // Extract the name portion and verify it starts with a letter.
    let rest = &first_line["module ".len()..first_line.len() - " 1.0;".len()];
    assert!(
        rest.chars().next().is_some_and(|c| c.is_ascii_alphabetic()),
        "default module name must start with an ASCII letter (valid SELinux identifier): got `{rest}`"
    );
    assert!(!rest.is_empty(), "default module name must not be empty");
}

// ---------------------------------------------------------------------------
// Anchor 5: Structural ordering - header before require before allow rules
// (f4 §3.1 describes the three sections in order)
// ---------------------------------------------------------------------------

/// The output sections must appear in the mandated order:
///   1. `module ...;`
///   2. `require { ... }`
///   3. `allow ...;` lines
#[test]
fn test_section_order_header_require_allow() {
    let groups = [group("logrotate_t", "shadow_t", "file", &["read"])];
    let te = emit_te(&groups, Some("narrow"));
    let header_pos = te
        .find("module narrow")
        .expect("module header must be present");
    let require_pos = te.find("require {").expect("require block must be present");
    let allow_pos = te.find("allow ").expect("allow rule must be present");
    assert!(
        header_pos < require_pos,
        "`module` header must come before `require` block"
    );
    assert!(
        require_pos < allow_pos,
        "`require` block must come before `allow` rules"
    );
}

// ---------------------------------------------------------------------------
// Anchor 6: Empty input - emit_te(&[], ...) must not panic and must not
// produce allow rules.
// ---------------------------------------------------------------------------

/// #165: an empty group slice must NOT produce a fake, uncompilable module. A
/// bare `module NAME 1.0;` and an empty `require {}` are BOTH rejected by
/// checkmodule, so zero denials emit an explanatory comment instead. No panic, no
/// `module` declaration, no `require` block, no `allow` rules.
#[test]
fn test_empty_groups_emit_comment_not_fake_module() {
    let te = emit_te(&[], Some("empty_mod"));
    // Must not panic (tested by getting here).
    assert!(
        te.starts_with('#'),
        "zero-denial output must be an explanatory comment, got:\n{te}"
    );
    assert!(
        !te.contains("module "),
        "zero-denial output must NOT declare a module (it would not compile):\n{te}"
    );
    assert!(
        !te.contains("require {"),
        "zero-denial output must omit the require block (an empty `require {{}}` is \
         uncompilable):\n{te}"
    );
    assert!(
        !te.contains("allow "),
        "zero-denial output must produce no allow rules:\n{te}"
    );
    assert!(
        te.ends_with('\n'),
        "output must end with a trailing newline (machine-output invariant):\n{te}"
    );
}

// ---------------------------------------------------------------------------
// Anchor 7: Output terminates with a trailing newline (project rule).
// ---------------------------------------------------------------------------

/// The emitted string must end with a newline character.
/// Source: project rule (trailing newline on machine-readable output).
#[test]
fn test_output_ends_with_newline() {
    let groups = [group("logrotate_t", "shadow_t", "file", &["read"])];
    let te = emit_te(&groups, Some("narrow"));
    assert!(
        te.ends_with('\n'),
        "emit_te output must end with a trailing newline (project rule)"
    );
}

// ---------------------------------------------------------------------------
// Anchor 8: Multi-group require block unions types globally (not per-group).
//
// The narrow.te hand-validated example has TWO groups (file + dir) sharing the
// same types. The require block declares each type ONCE with the union.
// Source: f4 §3.1 "declaring EVERY type ... the rules reference".
// ---------------------------------------------------------------------------

/// Two groups sharing the same source+target types but different classes must
/// produce a require block that declares each type exactly once, with BOTH
/// classes declared.
#[test]
fn test_require_unions_types_across_groups() {
    let groups = [
        group("logrotate_t", "shadow_t", "file", &["read", "getattr"]),
        group("logrotate_t", "shadow_t", "dir", &["read"]),
    ];
    let te = emit_te(&groups, Some("narrow"));
    // Types must appear exactly once each in the require block.
    assert_eq!(te.matches("type logrotate_t;").count(), 1);
    assert_eq!(te.matches("type shadow_t;").count(), 1);
    // Both classes must be declared.
    assert!(te.contains("class file"), "require must declare class file");
    assert!(te.contains("class dir"), "require must declare class dir");
}

/// Three groups involving THREE distinct types must declare all three in require.
#[test]
fn test_require_three_distinct_types() {
    let groups = [
        group("httpd_t", "shadow_t", "file", &["read"]),
        group("httpd_t", "httpd_config_t", "file", &["open"]),
    ];
    let te = emit_te(&groups, Some("test_mod"));
    assert!(
        te.contains("type httpd_t;"),
        "require must declare source type `httpd_t`"
    );
    assert!(
        te.contains("type shadow_t;"),
        "require must declare target type `shadow_t`"
    );
    assert!(
        te.contains("type httpd_config_t;"),
        "require must declare target type `httpd_config_t`"
    );
}
