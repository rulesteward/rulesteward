//! Crate-level lint tests for `rulesteward-sysctld` v1 (issue #150), authored at
//! the test-author barrier BEFORE the F01/W01 impl. These call the frozen public
//! entry `parser::lint_str(source, path)` directly and are RED against the Phase-0
//! stub (which returns an empty `Vec`): only a correct tokenizer + W01 pass turns
//! them green. Mirrors how `rulesteward-sshd` / `rulesteward-auditd` structure
//! their lint integration tests.
//!
//! # Ground truth (sysctl.d(5) / sysctl.conf(5), re-verified 2026-06-27)
//! * "Empty lines and lines whose first non-whitespace character is '#' or ';' are
//!   ignored." -> whole-line `#`/`;` comments only; a `#` mid-value is part of the
//!   value (no inline comments).
//! * "If a variable assignment is prefixed with a single '-' character, failure to
//!   set the variable [...] will not cause the service to fail." -> a leading `-`
//!   on an assignment is a VALID line.
//! * "A key may be explicitly excluded from being set by any matching glob patterns
//!   by specifying the key name prefixed with a '-' character and not followed by
//!   '='." -> a BARE `-key` (no `=`) is a VALID glob-exclusion line, NOT malformed.
//! * Separator normalization: "If the first separator is a slash, remaining slashes
//!   and dots are left intact. If the first separator is a dot, dots and slashes are
//!   interchanged." The man page's own example: "'kernel.domainname=foo' and
//!   'kernel/domainname=foo' are equivalent". v1 canonicalizes a key to its
//!   `/proc/sys` path form (slash-first left as-is; dot-first swaps every `.`<->`/`),
//!   so `net/ipv4/ip_forward` and `net.ipv4.ip_forward` are the SAME key, while a
//!   slash-first and a dot-first VLAN form (`enp3s0.200`) are DISTINCT keys.
//!
//! # F01 = parse failure; W01 = last-wins conflict
//! A non-comment, non-blank line that is NOT a bare `-key` glob-exclusion and has
//! NO `=` is malformed -> `sysctld-F01` (Fatal). The LAST assignment of a key wins;
//! an earlier assignment of the SAME key to a DIFFERENT value is dead -> `sysctld-W01`
//! (Warning), anchored at the OVERRIDDEN earlier line (the dead line is the
//! actionable surprise).

use std::path::Path;

use rulesteward_core::{Diagnostic, Severity};
use tempfile::tempdir;

const PATH: &str = "/etc/sysctl.d/99-test.conf";

fn lint(source: &str) -> Vec<Diagnostic> {
    rulesteward_sysctld::parser::lint_str(source, Path::new(PATH))
}

/// All `sysctld-F01` (Fatal parse-failure) diagnostics in emission order.
fn f01s(diags: &[Diagnostic]) -> Vec<&Diagnostic> {
    diags
        .iter()
        .filter(|d| d.code == "sysctld-F01")
        .inspect(|d| {
            assert_eq!(
                d.severity,
                Severity::Fatal,
                "sysctld-F01 must be Fatal, got {:?}",
                d.severity
            );
        })
        .collect()
}

/// All `sysctld-W01` (Warning last-wins) diagnostics in emission order.
fn w01s(diags: &[Diagnostic]) -> Vec<&Diagnostic> {
    diags
        .iter()
        .filter(|d| d.code == "sysctld-W01")
        .inspect(|d| {
            assert_eq!(
                d.severity,
                Severity::Warning,
                "sysctld-W01 must be Warning, got {:?}",
                d.severity
            );
        })
        .collect()
}

// ---------------------------------------------------------------------------
// F01 SHOULD fire (malformed lines)
// ---------------------------------------------------------------------------

#[test]
fn f01_fires_on_bare_key_without_equals() {
    // `kernel.dmesg_restrict` - a bare key, no leading `-`, no `=`: not a comment,
    // not blank, not a glob-exclusion -> malformed.
    let diags = lint("kernel.dmesg_restrict\n");
    let f = f01s(&diags);
    assert_eq!(f.len(), 1, "exactly one F01 for the bare key: {diags:?}");
    assert_eq!(f[0].line, 1, "F01 anchors at the malformed line");
}

#[test]
fn f01_fires_on_space_separated_assignment() {
    // `net.ipv4.ip_forward 1` - a space is not an assignment separator; without an
    // `=` this line carries no assignment -> malformed.
    let diags = lint("net.ipv4.ip_forward 1\n");
    let f = f01s(&diags);
    assert_eq!(f.len(), 1, "exactly one F01 for the space form: {diags:?}");
    assert_eq!(f[0].line, 1);
}

#[test]
fn f01_fires_on_empty_key() {
    // `= 1` - an assignment with an empty key (nothing before `=`) is malformed.
    let diags = lint("= 1\n");
    let f = f01s(&diags);
    assert_eq!(f.len(), 1, "exactly one F01 for the empty key: {diags:?}");
    assert_eq!(f[0].line, 1);
}

#[test]
fn f01_anchors_at_the_offending_line_number() {
    // F01 reports the 1-based line of the malformed line, not line 1 blindly: a
    // valid assignment precedes a malformed bare key.
    let diags = lint("kernel.sysrq = 0\nkernel.dmesg_restrict\n");
    let f = f01s(&diags);
    assert_eq!(f.len(), 1, "one malformed line on line 2: {diags:?}");
    assert_eq!(f[0].line, 2, "F01 anchors at line 2, the malformed line");
}

// ---------------------------------------------------------------------------
// F01 SHOULD NOT fire (valid lines)
// ---------------------------------------------------------------------------

#[test]
fn f01_does_not_fire_on_semicolon_comment() {
    assert!(
        f01s(&lint("; this is a comment\n")).is_empty(),
        "a `;` whole-line comment is valid, not malformed"
    );
}

#[test]
fn f01_does_not_fire_on_hash_comment() {
    assert!(
        f01s(&lint("# this is a comment\n")).is_empty(),
        "a `#` whole-line comment is valid, not malformed"
    );
}

#[test]
fn f01_does_not_fire_on_blank_line() {
    assert!(
        f01s(&lint("\n   \n\t\n")).is_empty(),
        "blank / whitespace-only lines are ignored, not malformed"
    );
}

#[test]
fn f01_does_not_fire_on_ignore_error_prefixed_assignment() {
    // `-kernel.dmesg_restrict = 1` - a leading `-` on an ASSIGNMENT means "ignore
    // set errors"; it is a valid assignment line.
    assert!(
        f01s(&lint("-kernel.dmesg_restrict = 1\n")).is_empty(),
        "a leading `-` on an assignment is valid (ignore-error prefix)"
    );
}

#[test]
fn f01_does_not_fire_on_bare_glob_exclusion() {
    // `-net.ipv4.conf.eth0.rp_filter` - a `-key` with NO `=` is a valid
    // glob-EXCLUSION line (man page: "prefixed with a '-' character and not
    // followed by '='"), NOT a malformed bare key.
    assert!(
        f01s(&lint("-net.ipv4.conf.eth0.rp_filter\n")).is_empty(),
        "a bare `-key` (no `=`) is a valid glob-exclusion, not malformed"
    );
}

#[test]
fn f01_does_not_fire_on_slash_separated_key() {
    // `net/ipv4/ip_forward = 1` - slash separators are valid (interchangeable with
    // dots per sysctl.d(5)).
    assert!(
        f01s(&lint("net/ipv4/ip_forward = 1\n")).is_empty(),
        "slash-separated keys are a valid assignment"
    );
}

#[test]
fn f01_does_not_fire_on_surrounding_whitespace() {
    // `   kernel.sysrq   =   16   ` - arbitrary surrounding whitespace is tolerated.
    assert!(
        f01s(&lint("   kernel.sysrq   =   16   \n")).is_empty(),
        "surrounding whitespace around key/=/value is valid"
    );
}

#[test]
fn f01_does_not_fire_on_glob_key_assignment() {
    // `net.ipv4.conf.*.rp_filter = 1` - a systemd glob key is a valid assignment.
    assert!(
        f01s(&lint("net.ipv4.conf.*.rp_filter = 1\n")).is_empty(),
        "a glob-key assignment is valid"
    );
}

// ---------------------------------------------------------------------------
// W01 SHOULD fire (last-wins conflict)
// ---------------------------------------------------------------------------

#[test]
fn w01_fires_on_within_file_last_wins_conflict() {
    // The same key assigned two DIFFERENT values: the first (=2) is dead, the
    // last (=1) wins -> one W01.
    let source = "kernel.kptr_restrict=2\nkernel.kptr_restrict=1\n";
    let diags = lint(source);
    let w = w01s(&diags);
    assert_eq!(w.len(), 1, "exactly one W01 for the conflict: {diags:?}");

    // PINNED ANCHOR: W01 points at the DEAD/overridden EARLIER assignment (line 1),
    // the actionable surprise - the dead line is what the operator must remove.
    assert_eq!(
        w[0].line, 1,
        "W01 anchors at the overridden earlier line (the dead assignment)"
    );

    // The message names the conflicting key so the operator can identify it.
    assert!(
        w[0].message.contains("kernel.kptr_restrict"),
        "W01 message names the conflicting key; was: {:?}",
        w[0].message
    );
}

#[test]
fn w01_does_not_fire_without_a_conflict_clean_file() {
    // A single assignment of a key has no conflict.
    assert!(
        w01s(&lint("kernel.kptr_restrict = 2\n")).is_empty(),
        "a single assignment is not a conflict"
    );
}

// ---------------------------------------------------------------------------
// W01 SHOULD NOT fire (no real conflict)
// ---------------------------------------------------------------------------

#[test]
fn w01_does_not_fire_on_same_key_same_value() {
    // Same key, SAME value twice: redundant, not a conflict.
    assert!(
        w01s(&lint("net.ipv4.ip_forward=1\nnet.ipv4.ip_forward=1\n")).is_empty(),
        "same key with the same value is redundant, not a W01 conflict"
    );
}

#[test]
fn w01_does_not_fire_on_separator_normalized_same_value() {
    // `net.ipv4.ip_forward` and `net/ipv4/ip_forward` are the SAME key (normalize
    // `/` to `.`); same value -> NO conflict.
    assert!(
        w01s(&lint("net.ipv4.ip_forward=1\nnet/ipv4/ip_forward=1\n")).is_empty(),
        "separator-normalized same key with the same value is not a conflict"
    );
}

#[test]
fn w01_does_not_fire_on_two_different_keys() {
    // Two different keys never conflict, even with different values.
    assert!(
        w01s(&lint("kernel.kptr_restrict=2\nkernel.dmesg_restrict=1\n")).is_empty(),
        "different keys never conflict"
    );
}

#[test]
fn w01_fires_across_separator_normalized_different_values() {
    // The mirror of the same-value case: `net.ipv4.ip_forward` and
    // `net/ipv4/ip_forward` are the SAME key, so DIFFERENT values DO conflict.
    // Pins that normalization is applied for conflict detection, not just for the
    // no-fire path (guards a mutant that skips normalization on the fire side).
    let diags = lint("net.ipv4.ip_forward=1\nnet/ipv4/ip_forward=0\n");
    let w = w01s(&diags);
    assert_eq!(
        w.len(),
        1,
        "separator-normalized same key with DIFFERENT values is one conflict: {diags:?}"
    );
    assert_eq!(w[0].line, 1, "anchors at the overridden earlier line");
}

// ===========================================================================
// FINDING 1 (real bug): asymmetric key-separator normalization.
//
// sysctl.d(5) (man7.org/linux/man-pages/man5/sysctl.d.5.html, verified
// 2026-06-27): "Note that either "/" or "." may be used as separators within
// sysctl variable names. If the first separator is a slash, remaining slashes
// and dots are left intact. If the first separator is a dot, dots and slashes
// are interchanged." Worked example from the man page: BOTH
// "net.ipv4.conf.enp3s0/200.forwarding" AND "net/ipv4/conf/enp3s0.200/forwarding"
// refer to "/proc/sys/net/ipv4/conf/enp3s0.200/forwarding".
//
// The consequence the impl gets wrong: the rule is ASYMMETRIC, so a DOT-first
// key cannot carry a literal dot inside a path component. Canonicalizing each
// form to its /proc/sys path:
//   * SLASH-first `net/ipv4/conf/enp3s0.200/forwarding`: slashes are the
//     separators, the dot is left intact -> path .../conf/enp3s0.200/forwarding
//     (component "enp3s0.200", a VLAN interface name).
//   * DOT-first `net.ipv4.conf.enp3s0.200.forwarding`: dots and slashes are
//     interchanged, so EVERY dot becomes a path separator ->
//     path .../conf/enp3s0/200/forwarding (components "enp3s0" then "200").
// These are DIFFERENT /proc/sys keys. The impl's blanket `/`->`.` collapses
// both to `net.ipv4.conf.enp3s0.200.forwarding`, so it treats them as the same
// key and (with different values) raises a FALSE sysctld-W01.
// ===========================================================================

#[test]
fn w01_does_not_fire_on_asymmetric_distinct_keys() {
    // FINDING 1a (RED today, the bug): the slash-first VLAN form and the dot-first
    // form are DISTINCT /proc/sys keys (see the canonicalization above), so even
    // with different values there is NO conflict. The impl's symmetric `/`->`.`
    // normalization wrongly collapses them and fires one W01.
    let source =
        "net/ipv4/conf/enp3s0.200/forwarding = 1\nnet.ipv4.conf.enp3s0.200.forwarding = 0\n";
    let diags = lint(source);
    let w = w01s(&diags);
    assert!(
        w.is_empty(),
        "the slash-first `enp3s0.200/forwarding` (path .../enp3s0.200/forwarding) and \
         dot-first `enp3s0.200.forwarding` (path .../enp3s0/200/forwarding) are DISTINCT \
         /proc/sys keys per sysctl.d(5)'s asymmetric rule; no conflict expected, got: {w:?}"
    );
}

#[test]
fn w01_fires_on_two_slash_first_vlan_forms_same_key() {
    // FINDING 1b (control, should be green): two SLASH-first forms of the SAME VLAN
    // key with DIFFERENT values ARE a real conflict. The dot inside `enp3s0.200`
    // stays a literal interface-name dot for both forms, so both canonicalize to
    // the identical key `net/ipv4/conf/enp3s0.200/rp_filter` -> exactly one W01.
    let source = "net/ipv4/conf/enp3s0.200/rp_filter = 1\nnet/ipv4/conf/enp3s0.200/rp_filter = 0\n";
    let diags = lint(source);
    let w = w01s(&diags);
    assert_eq!(
        w.len(),
        1,
        "two slash-first forms of the same VLAN key with different values is one real \
         conflict: {w:?}"
    );
    assert_eq!(w[0].line, 1, "anchors at the overridden earlier line");
}

#[test]
fn w01_easy_separator_case_still_holds_after_fix() {
    // FINDING 1c (regression guard): the EASY equivalence must survive the fix.
    // `net.ipv4.ip_forward` (dot-first, no path-component dots) and
    // `net/ipv4/ip_forward` (slash-first) BOTH canonicalize to the same key
    // (.../net/ipv4/ip_forward), matching the man page's
    // `kernel.domainname == kernel/domainname` equivalence. So:
    //   * same value  -> no W01,
    //   * diff value  -> exactly one W01.
    // This pins that the FINDING-1 fix does not over-correct into treating these
    // simple equivalent forms as distinct keys.
    assert!(
        w01s(&lint("net.ipv4.ip_forward=1\nnet/ipv4/ip_forward=1\n")).is_empty(),
        "easy equivalent forms with the same value must not conflict"
    );
    let diags = lint("net.ipv4.ip_forward=1\nnet/ipv4/ip_forward=0\n");
    let w = w01s(&diags);
    assert_eq!(
        w.len(),
        1,
        "easy equivalent forms with different values must still conflict: {w:?}"
    );
}

// ===========================================================================
// FINDING 2 (degenerate output): an empty key with the ignore-error dash.
//
// `= 1` (a bare empty key) is correctly sysctld-F01. But `- = 1` and `-=1`
// (the ignore-error `-` prefix followed by an EMPTY key) currently slip past
// the empty-key check (the `-` is stripped only during key normalization, so
// the raw key is non-empty `-` at the malformed gate) and produce a degenerate
// sysctld-W01 with an EMPTY key name. Decided behavior: an empty key is
// malformed REGARDLESS of a leading `-`, so `- = 1` and `-=1` are sysctld-F01
// (consistent with `= 1`) and must NEVER produce a W01 with an empty key.
// ===========================================================================

#[test]
fn f01_fires_on_dash_then_empty_key_spaced() {
    // FINDING 2a (RED today): `- = 1` is an empty key after the ignore-error dash ->
    // exactly one F01, and NOT a W01.
    let diags = lint("- = 1\n");
    let f = f01s(&diags);
    assert_eq!(
        f.len(),
        1,
        "`- = 1` is an empty key (after the ignore-error dash) -> one F01: {diags:?}"
    );
    assert_eq!(f[0].line, 1);
    assert!(
        w01s(&diags).is_empty(),
        "`- = 1` must not produce a W01 (no degenerate empty-key conflict): {diags:?}"
    );
}

#[test]
fn f01_fires_on_dash_then_empty_key_unspaced() {
    // FINDING 2b (RED today): `-=1` (no spaces) is likewise an empty key -> one F01.
    let diags = lint("-=1\n");
    let f = f01s(&diags);
    assert_eq!(
        f.len(),
        1,
        "`-=1` is an empty key after the ignore-error dash -> one F01: {diags:?}"
    );
    assert_eq!(f[0].line, 1);
    assert!(
        w01s(&diags).is_empty(),
        "`-=1` must not produce a W01: {diags:?}"
    );
}

#[test]
fn dash_empty_key_never_produces_empty_key_w01() {
    // FINDING 2c (RED today): two `- = ...` lines must each be F01 and must NOT
    // form a degenerate empty-key W01 conflict. Also assert no diagnostic carries
    // an empty key in its message: the W01 message wraps the key in backticks as
    // `last-wins conflict: `<key>` here...`, so an empty key would surface the
    // adjacent-backtick marker "`` here" (two backticks with nothing between).
    let diags = lint("- = 1\n- = 0\n");
    let f = f01s(&diags);
    assert_eq!(
        f.len(),
        2,
        "each `- = ...` line is an empty-key F01 (one per line): {diags:?}"
    );
    assert!(
        w01s(&diags).is_empty(),
        "two empty-key lines must NOT form a degenerate W01 conflict: {diags:?}"
    );
    // No diagnostic may name an empty key. The W01 conflict message would render
    // an empty key as the adjacent-backtick sequence "`` here" - assert it never
    // appears in ANY diagnostic message.
    for d in &diags {
        assert!(
            !d.message.contains("`` here"),
            "no diagnostic may name an empty key (saw the empty-backtick marker): {:?}",
            d.message
        );
    }
}

#[test]
fn valid_ignore_error_assignment_stays_valid_with_empty_key_rule() {
    // FINDING 2 regression guard: a VALID `-key = value` (non-empty key after the
    // dash) must remain a valid assignment - NO F01 - even though `- = value` is
    // now F01. Pins that the empty-key rule keys off the post-dash key being
    // empty, not off the presence of the dash.
    let diags = lint("-kernel.dmesg_restrict = 1\n");
    assert!(
        f01s(&diags).is_empty(),
        "a `-key = value` with a non-empty key is a valid ignore-error assignment: {diags:?}"
    );
}

// ===========================================================================
// FINDING 3 (mutation survivors in lint_dir): dir-mode under-covered at the
// unit level. The e2e test exercises `lint_dir` but mutation does not reliably
// kill: (a) `lint_dir -> vec![]` (whole-body replacement) and (b) the `*.conf`
// file-filter `&&` / `==` at parser.rs's `is_file() && ext == "conf"`. These
// crate-level tests build a real temp dir and assert the W01 outcome so a
// stubbed body or a broadened filter changes the observable result.
// ===========================================================================

#[test]
fn lint_dir_detects_cross_file_conflict() {
    // FINDING 3a: two `.conf` drop-ins assign the SAME key different values; the
    // lexicographically-later file (90-b.conf) wins, the earlier (10-a.conf) is
    // dead -> exactly one sysctld-W01. A `lint_dir -> vec![]` mutant returns no
    // diagnostics and fails this assertion (kills the whole-body survivor).
    let dir = tempdir().expect("temp dir");
    std::fs::write(dir.path().join("10-a.conf"), "net.ipv4.ip_forward=1\n").expect("write a");
    std::fs::write(dir.path().join("90-b.conf"), "net.ipv4.ip_forward=0\n").expect("write b");

    let (diags, _sources) = rulesteward_sysctld::parser::lint_dir(dir.path());
    let w = w01s(&diags);
    assert_eq!(
        w.len(),
        1,
        "the cross-file last-wins conflict on net.ipv4.ip_forward fires exactly one W01: \
         {diags:?}"
    );
    assert!(
        w[0].message.contains("net.ipv4.ip_forward"),
        "the W01 names the conflicting key; was: {:?}",
        w[0].message
    );
}

#[test]
fn lint_dir_ignores_non_conf_extension_files() {
    // FINDING 3b: the conflicting override lives in `99-z.txt` (NOT a `.conf`
    // file), so it must NOT participate in the drop-in set. Only `10-a.conf`
    // assigns the key -> a single clean assignment, NO conflict.
    //
    // This kills the `is_file() && extension == "conf"` mutants: a filter that
    // dropped the `&&` short-circuit's `== "conf"` clause (or flipped `==`)
    // would INCLUDE the `.txt` override, see two different values for the key,
    // and wrongly fire one W01. The W01 count is the observable that separates
    // a correct `.conf`-only filter from a broadened one.
    let dir = tempdir().expect("temp dir");
    std::fs::write(dir.path().join("10-a.conf"), "net.ipv4.ip_forward=1\n").expect("write conf");
    std::fs::write(dir.path().join("99-z.txt"), "net.ipv4.ip_forward=0\n").expect("write txt");

    let (diags, _sources) = rulesteward_sysctld::parser::lint_dir(dir.path());
    let w = w01s(&diags);
    assert!(
        w.is_empty(),
        "the `.txt` override must be ignored (only `.conf` drop-ins count), so the single \
         `.conf` assignment is conflict-free; got: {diags:?}"
    );
    // And no F01 either: the one `.conf` file is well-formed; the `.txt` is not a
    // drop-in so its contents are never parsed.
    assert!(
        f01s(&diags).is_empty(),
        "a non-`.conf` file is skipped entirely, not parsed for F01: {diags:?}"
    );
}

#[test]
fn lint_dir_only_conf_files_in_a_mixed_dir_conflict() {
    // FINDING 3b (sharper variant): a directory holding BOTH a `.conf` conflict
    // pair AND an unrelated `.txt` that would, if wrongly included, add a THIRD
    // value. A correct `.conf`-only filter sees exactly one conflict (the two
    // `.conf` files); a broadened filter that swept in the `.txt` would still
    // report one conflict but anchored/valued differently - so we pin the precise
    // values to make the `.conf`-only distinction observable.
    let dir = tempdir().expect("temp dir");
    std::fs::write(dir.path().join("10-low.conf"), "kernel.kptr_restrict=1\n").expect("write low");
    std::fs::write(dir.path().join("20-high.conf"), "kernel.kptr_restrict=2\n")
        .expect("write high");
    // A `.txt` that, if wrongly included as the lexicographically-latest file,
    // would change the WINNING value from 2 to 9 and the W01 message text.
    std::fs::write(dir.path().join("99-z.txt"), "kernel.kptr_restrict=9\n").expect("write txt");

    let (diags, _sources) = rulesteward_sysctld::parser::lint_dir(dir.path());
    let w = w01s(&diags);
    assert_eq!(
        w.len(),
        1,
        "only the two `.conf` files conflict (the `.txt` is ignored): {diags:?}"
    );
    // The winner is `20-high.conf`'s value 2 (not the `.txt`'s 9). The dead line
    // (10-low.conf, =1) is overridden BY value 2. Pin both the dead value and the
    // winning value so a filter that swept in the `.txt` (winner would be 9)
    // fails here even if it still reports one W01.
    assert!(
        w[0].message.contains("(= 1)") && w[0].message.contains("(= 2)"),
        "the conflict is between the `.conf` values 1 (dead) and 2 (winner), not the \
         ignored `.txt` value 9; was: {:?}",
        w[0].message
    );
    assert!(
        !w[0].message.contains("(= 9)"),
        "the ignored `.txt` value 9 must never appear as the winner: {:?}",
        w[0].message
    );
}

#[test]
fn lint_dir_clean_dir_has_no_findings() {
    // FINDING 3c: a directory with a single clean `.conf` file (and an empty dir)
    // produces no findings and does not panic.
    let dir = tempdir().expect("temp dir");
    std::fs::write(dir.path().join("10-ok.conf"), "kernel.dmesg_restrict=1\n").expect("write ok");
    let (diags, _sources) = rulesteward_sysctld::parser::lint_dir(dir.path());
    assert!(
        diags.is_empty(),
        "a single clean `.conf` file yields no diagnostics: {diags:?}"
    );

    let empty = tempdir().expect("temp dir");
    assert!(
        rulesteward_sysctld::parser::lint_dir(empty.path())
            .0
            .is_empty(),
        "an empty directory yields no diagnostics and does not panic"
    );
}

#[test]
fn lint_dir_on_an_unreadable_directory_path_returns_one_file_level_f01() {
    // `lint_dir` must not panic when `dir` cannot be enumerated (e.g. it names a
    // regular file, not a directory - `std::fs::read_dir` returns `Err(ENOTDIR)`
    // on Linux for that case): it degrades to a single file-level F01 anchored at
    // `dir` (line 0, span 0..0, no source_id -- there is no source to stage) and an
    // EMPTY sources map, per the doc comment on `lint_dir_with_target`.
    let outer = tempdir().expect("temp dir");
    let not_a_dir = outer.path().join("this-is-a-file.conf");
    std::fs::write(&not_a_dir, "kernel.dmesg_restrict = 1\n").expect("write plain file");

    let (diags, sources) = rulesteward_sysctld::parser::lint_dir(&not_a_dir);

    assert_eq!(
        diags.len(),
        1,
        "an unreadable directory path yields exactly one file-level F01: {diags:?}"
    );
    assert_eq!(diags[0].code, "sysctld-F01");
    assert_eq!(diags[0].severity, Severity::Fatal);
    assert_eq!(diags[0].line, 0, "no source line to anchor at");
    assert_eq!(diags[0].span, 0..0, "no byte span to anchor at");
    assert!(
        diags[0].source_id.is_none(),
        "a directory-enumeration failure has no staged source"
    );
    assert_eq!(
        diags[0].file, not_a_dir,
        "the F01 names the unreadable path itself"
    );
    assert!(
        diags[0].message.contains("cannot read sysctl.d directory"),
        "the message explains the directory could not be read: {:?}",
        diags[0].message
    );
    assert!(
        sources.is_empty(),
        "no file was ever successfully read, so nothing is staged: {sources:?}"
    );
}

#[test]
fn lint_dir_a_non_utf8_dropin_yields_a_file_level_f01_but_the_rest_of_the_dir_still_lints() {
    // A `.conf` drop-in that is present and a regular file (so it passes the
    // `is_file() && extension == "conf"` filter) but is NOT valid UTF-8 fails at
    // `read_to_string`, not at `read_dir`: it becomes its own file-level F01 (no
    // panic, no source staged for IT), while a SIBLING well-formed drop-in in the
    // same directory is still parsed and lints normally - the directory-wide scan
    // does not abort on one bad file.
    let dir = tempdir().expect("temp dir");
    let good = dir.path().join("10-a.conf");
    std::fs::write(&good, "kernel.dmesg_restrict = 1\n").expect("write good drop-in");
    let bad = dir.path().join("20-bad.conf");
    // 0xFF is never a valid UTF-8 lead byte, so `read_to_string` fails with
    // `InvalidData` regardless of platform.
    std::fs::write(&bad, [0xFFu8, 0xFE, 0x00, 0x01]).expect("write non-UTF8 drop-in");

    let (diags, sources) = rulesteward_sysctld::parser::lint_dir(dir.path());

    let f = f01s(&diags);
    assert_eq!(
        f.len(),
        1,
        "exactly one F01 for the unreadable non-UTF8 drop-in: {diags:?}"
    );
    assert_eq!(
        f[0].file, bad,
        "the F01 names the bad file, not the good one"
    );
    assert!(
        f[0].message.contains("cannot read"),
        "the message explains the read failure: {:?}",
        f[0].message
    );
    assert!(
        f[0].source_id.is_none(),
        "an unreadable drop-in has no staged source"
    );

    // The good drop-in was still read and staged; the bad one was not.
    let good_key = good.display().to_string();
    let bad_key = bad.display().to_string();
    assert!(
        sources.contains_key(&good_key),
        "the good drop-in's source is staged: {sources:?}"
    );
    assert!(
        !sources.contains_key(&bad_key),
        "the unreadable drop-in's source is never staged: {sources:?}"
    );
    // The good drop-in's single clean assignment produces no W01 (nothing to
    // conflict with) - confirms the rest of the directory really did lint.
    assert!(
        w01s(&diags).is_empty(),
        "the well-formed sibling drop-in has no conflicts: {diags:?}"
    );
}

// ===========================================================================
// issue #337: F01/W01 carry the REAL byte span of the offending line (not the
// degenerate 0..0 that mis-anchored the ariadne snippet at line 1). These pin
// the exact byte range for a known fixture, killing mutants that revert the span
// to 0..0 or swap its endpoints. Per-package (in-crate) so the parser mutation
// gate kills them without the CLI e2e tests.
// ===========================================================================

#[test]
fn f01_carries_the_real_byte_span_of_the_malformed_line() {
    // Byte layout of the source (offsets are 0-based, half-open):
    //   "# c\n"                   bytes 0..3   then '\n' at 3
    //   "kernel.dmesg_restrict\n" bytes 4..25  then '\n' at 25  (malformed: bare key)
    // The F01 must span the malformed line's real bytes (4..25), NOT 0..0.
    let source = "# c\nkernel.dmesg_restrict\n";
    let diags = lint(source);
    let f = f01s(&diags);
    assert_eq!(f.len(), 1, "one malformed line -> one F01: {diags:?}");
    assert_eq!(
        f[0].span,
        4..25,
        "F01 span must cover the malformed line's real bytes (line 2 = 4..25), not 0..0"
    );
}

#[test]
fn f01_byte_span_counts_bytes_not_chars_with_multibyte_before_the_line() {
    // issue #337 (strengthening, per the spec + idiomatic reviewers): the running
    // offset accumulates BYTE lengths (`raw_line.len()`), not char counts, so a
    // multibyte UTF-8 char on an EARLIER line shifts the offending line's span by the
    // extra byte(s). ariadne's renderer converts the byte span to a char span, so the
    // parser MUST emit byte offsets. A wrong char-counting impl would put the span at
    // 7..28; the byte-correct impl puts it at 8..29.
    //
    //   "# caf\u{e9}\n"             bytes 0..7   ('\u{e9}' is 2 bytes) then '\n' at 7
    //   "kernel.dmesg_restrict\n"   bytes 8..29  then '\n' at 29   (malformed: bare key)
    let source = "# caf\u{e9}\nkernel.dmesg_restrict\n";
    let diags = lint(source);
    let f = f01s(&diags);
    assert_eq!(f.len(), 1, "one malformed line -> one F01: {diags:?}");
    assert_eq!(
        f[0].span,
        8..29,
        "F01 span must count the 2-byte `\u{e9}` as 2 bytes (line 2 = 8..29), not as 1 char"
    );
}

#[test]
fn w01_carries_the_real_byte_span_of_the_dead_line() {
    // Byte layout (the dead line is line 2 so BOTH endpoints differ from 0..0):
    //   "# c\n"                      bytes 0..3   then '\n' at 3
    //   "kernel.kptr_restrict = 2\n" bytes 4..28  then '\n' at 28  (dead: overridden)
    //   "kernel.kptr_restrict = 1\n" bytes 29..53 then '\n' at 53  (winner)
    // The W01 anchors at the OVERRIDDEN earlier line; its span is that line (4..28).
    let source = "# c\nkernel.kptr_restrict = 2\nkernel.kptr_restrict = 1\n";
    let diags = lint(source);
    let w = w01s(&diags);
    assert_eq!(w.len(), 1, "one last-wins conflict -> one W01: {diags:?}");
    assert_eq!(
        w[0].span,
        4..28,
        "W01 span must cover the dead earlier line's real bytes (line 2 = 4..28), not 0..0"
    );
}
