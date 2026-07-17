//! fapd-W14: `fapolicyd.conf` sets `permissive=1` (fail-open instead of
//! enforcing). Operates on an explicitly-supplied conf file (CLI `--conf`
//! path, `commands/fapolicyd/lint.rs`); NOT wired into the default per-file
//! `lint_with_context` pass list (a conf file is not a `rules.d/*.rules`
//! file and has no `--file`/directory relationship to one).
//!
//! Version-INDEPENDENT: `permissive=1` fail-open is wrong on every supported
//! fapolicyd release, so this fires even with `target: None` - unlike
//! fapd-W13 (`Condition::RequiresTarget`), fapd-W14 is gated on
//! `Condition::RequiresConf` (fires whenever `--conf` is given at all; see
//! `lints::catalog`). The STIG `ControlRef` (`DenyAll` family - a permissive
//! daemon defeats the deny-all/permit-by-exception policy regardless of what
//! the rules themselves say) is attached only when a benchmark `target` IS
//! resolved, mirroring every other doctor/lint control-attachment site.
//!
//! Duplicate-key resolution is LAST-WINS, mirroring
//! `crates/rulesteward-cli/src/commands/conf.rs::conf_value` (fapolicyd's own
//! `daemon-config.c` keyword handlers overwrite with no early-exit) - this is
//! an IN-CRATE scanner, not a call into that CLI helper: `rulesteward-fapolicyd`
//! must not depend on `rulesteward-cli` (the dependency runs the other way).
//! Only WHOLE-LINE `#` comments are skipped (a line whose first non-whitespace
//! token starts with `#`); a trailing `#` is not stripped.

use std::path::Path;

use rulesteward_core::{Diagnostic, Severity};

use crate::lints::stig::ControlFamily;
use crate::version::TargetVersion;

/// fapd-W14: `permissive=1` set in the `fapolicyd.conf` text at `path`.
///
/// Fires whenever the LAST-WINS resolved value of the `permissive` key is
/// exactly `"1"`, regardless of `target` (version-independent). Anchored at
/// the WINNING line (the last non-whole-line-comment occurrence of the key,
/// last-wins per fapolicyd's own config-loader semantics - see the module
/// doc). Absent key, or resolved to anything other than `"1"` (e.g. `"0"`),
/// is clean.
#[must_use]
pub fn lint_conf(text: &str, path: &Path, target: Option<TargetVersion>) -> Vec<Diagnostic> {
    // Last-wins scan, mirroring `commands/conf.rs::conf_value` exactly (whole-line
    // `#` comments only; whitespace-tolerant around `=`; a trailing `#` is part of
    // the literal value, never stripped). Tracked separately here (rather than
    // calling into that CLI helper) because this crate must not depend on
    // `rulesteward-cli` - the dependency runs the other way.
    let mut winner: Option<(usize, std::ops::Range<usize>, &str)> = None;
    let mut offset = 0usize;
    for (idx, line) in text.split('\n').enumerate() {
        let start = offset;
        let end = start + line.len();
        offset = end + 1; // account for the consumed '\n' separator.
        if line.trim_start().starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=')
            && k.trim() == "permissive"
        {
            winner = Some((idx + 1, start..end, v.trim()));
        }
    }

    let Some((line, span, value)) = winner else {
        return Vec::new();
    };
    if value != "1" {
        return Vec::new();
    }

    let controls = target
        .map(|t| crate::lints::stig::control_refs(ControlFamily::DenyAll, t))
        .unwrap_or_default();

    vec![
        super::anchored(
            Severity::Warning,
            "fapd-W14",
            span,
            "fapolicyd.conf sets `permissive = 1` (fail-open instead of enforcing)",
            path,
            line,
        )
        .with_controls(controls),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn p() -> PathBuf {
        PathBuf::from("/etc/fapolicyd/fapolicyd.conf")
    }

    fn codes(diags: &[Diagnostic]) -> Vec<&str> {
        diags.iter().map(|d| d.code.as_ref()).collect()
    }

    // ---------------------------------------------------------------------
    // Version-independence: fires under target=None too.
    // ---------------------------------------------------------------------

    #[test]
    fn permissive_one_fires_even_without_a_target() {
        let diags = lint_conf("permissive = 1\n", &p(), None);
        assert_eq!(
            diags.len(),
            1,
            "permissive=1 is version-independent and must fire under target=None: {diags:?}"
        );
        assert_eq!(diags[0].code, "fapd-W14");
        assert!(
            diags[0].controls.is_empty(),
            "no target resolved -> no STIG control attached: {:?}",
            diags[0].controls
        );
    }

    // ---------------------------------------------------------------------
    // Last-wins anchoring (kills a first-wins wrong impl in BOTH directions).
    // ---------------------------------------------------------------------

    #[test]
    fn zero_then_one_fires_anchored_at_the_second_winning_line() {
        // Last-wins: line 2's `permissive=1` overrides line 1's `permissive=0`,
        // so the daemon is actually permissive -> fires, anchored at line 2 (the
        // WINNING occurrence), not line 1.
        let diags = lint_conf("permissive=0\npermissive=1\n", &p(), None);
        assert_eq!(diags.len(), 1, "{diags:?}");
        assert_eq!(diags[0].code, "fapd-W14");
        assert_eq!(
            diags[0].line, 2,
            "must anchor at the WINNING (second, last) line, not the first"
        );
    }

    #[test]
    fn one_then_zero_is_clean() {
        // Reversed order: the LAST occurrence resolves to 0, so the daemon is
        // enforcing, not permissive -> clean. This is the direct kill of a
        // first-wins wrong impl (which would wrongly fire here, having seen
        // `permissive=1` first).
        let diags = lint_conf("permissive=1\npermissive=0\n", &p(), None);
        assert!(
            codes(&diags).is_empty(),
            "last-wins resolves to 0 (enforcing); a first-wins impl would \
             wrongly fire here: {diags:?}"
        );
    }

    // ---------------------------------------------------------------------
    // Absent / zero -> clean.
    // ---------------------------------------------------------------------

    #[test]
    fn absent_key_is_clean() {
        let diags = lint_conf("integrity=sha256\nrpm_integrity_check=1\n", &p(), None);
        assert!(codes(&diags).is_empty(), "{diags:?}");
    }

    #[test]
    fn permissive_zero_alone_is_clean() {
        let diags = lint_conf("permissive=0\n", &p(), None);
        assert!(codes(&diags).is_empty(), "{diags:?}");
    }

    #[test]
    fn whole_line_commented_permissive_is_ignored() {
        // Mirrors `commands/conf.rs::conf_value_skips_whole_line_comments`: a
        // whole-line `#`-prefixed occurrence never counts, so the REAL
        // (uncommented) `permissive=0` below is the only vote and resolves
        // clean.
        let diags = lint_conf("# permissive=1\npermissive=0\n", &p(), None);
        assert!(
            codes(&diags).is_empty(),
            "a commented-out permissive=1 must not count: {diags:?}"
        );
    }

    #[test]
    fn inline_hash_is_part_of_the_value_not_a_comment() {
        // Adversarial round 1 (Finding 3): pins the module doc's "a trailing
        // `#` is not stripped". Mirrors
        // `commands/conf.rs::conf_value_does_not_strip_inline_comment`:
        // fapolicyd's own `nv_split` (daemon-config.c) honors ONLY whole-line
        // `#` comments, so the raw resolved value here is `"1 # note"`, which
        // is NOT exactly `"1"` -> clean. An impl that strips inline comments
        // (reading the value as `"1"`) would wrongly fire.
        let diags = lint_conf("permissive = 1 # note\n", &p(), None);
        assert!(
            codes(&diags).is_empty(),
            "raw value \"1 # note\" is not \"1\"; the inline `#` must not be \
             stripped: {diags:?}"
        );

        // And the inline-`#` line must not shadow a LATER bare occurrence:
        // last-wins resolves line 2's `permissive = 1` to exactly "1" ->
        // fires, anchored at that later WINNING line.
        let diags = lint_conf("permissive = 1 # note\npermissive = 1\n", &p(), None);
        assert_eq!(diags.len(), 1, "{diags:?}");
        assert_eq!(diags[0].code, "fapd-W14");
        assert_eq!(
            diags[0].line, 2,
            "must anchor at the later uncommented winning line, not the \
             inline-comment line"
        );
    }

    // ---------------------------------------------------------------------
    // ControlRefs: DenyAll family, ONLY when target resolves.
    // ---------------------------------------------------------------------

    #[test]
    fn control_attached_only_when_target_resolves() {
        // With a resolved target: exactly one DenyAll STIG control (G7/G8
        // rhel9 row: RHEL-09-433016 / V-270180), hardcoded here rather than
        // sourced from `lints::stig::control_refs` so this test's RED status
        // does not depend on T1's (also not-yet-implemented) table.
        let with_target = lint_conf("permissive=1\n", &p(), Some(TargetVersion::Rhel9));
        assert_eq!(with_target.len(), 1, "{with_target:?}");
        assert_eq!(
            with_target[0].controls.len(),
            1,
            "a resolved target must attach the DenyAll STIG control: {:?}",
            with_target[0].controls
        );
        assert_eq!(with_target[0].controls[0].id, "RHEL-09-433016");
        assert_eq!(
            with_target[0].controls[0].alias.as_deref(),
            Some("V-270180")
        );

        // Without a target: same finding, but NO control (nothing to map to a
        // benchmark baseline without one).
        let without_target = lint_conf("permissive=1\n", &p(), None);
        assert_eq!(without_target.len(), 1, "{without_target:?}");
        assert!(
            without_target[0].controls.is_empty(),
            "target=None must attach no controls: {:?}",
            without_target[0].controls
        );
    }
}
