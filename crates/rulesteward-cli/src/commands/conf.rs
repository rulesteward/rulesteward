//! Shared `fapolicyd.conf` key reader.
//!
//! `fapolicyd.conf` is a flat `key = value` file (full-line `#` comments). Before
//! this helper existed, three hand-rolled scanners parsed it with three different
//! acceptance sets, and two of them (in `doctor/probe.rs`) DISAGREED on whitespace
//! variants like `permissive =1` -- so doctor's mode probe and its misconfiguration
//! check could report different modes for the same line (issue #192, D2). This is
//! the single, comment-aware, whitespace-tolerant reader they all use.

/// Look up `key` in `fapolicyd.conf`-style text and return the trimmed value of
/// the LAST matching `key = value` line, mirroring how the fapolicyd daemon itself
/// resolves its config (`daemon-config.c`: each keyword handler overwrites with no
/// early-exit, so duplicate keys are last-wins). Resolving duplicates differently
/// from the daemon would make `doctor`/`container-check` misreport the effective
/// config.
///
/// Tolerant of any whitespace around `=` (`permissive=1`, `permissive = 1`,
/// `permissive =1`, `permissive= 1` all read as value `"1"`). The key is matched
/// EXACTLY (so `permissive_debug=1` is NOT read as the `permissive` key). Only
/// WHOLE-LINE `#` comments are skipped; a trailing `#` is part of the literal value
/// (fapolicyd's `nv_split` rejects only a line whose first token starts with `#`).
/// Returns `None` when the key is absent.
#[must_use]
pub(crate) fn conf_value<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    let mut value = None;
    for line in text.lines() {
        // Whole-line comments only: fapolicyd skips a line whose first token starts
        // with `#` but does NOT strip a trailing inline comment (the value is
        // literal). See daemon-config.c `nv_split`.
        if line.trim_start().starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=')
            && k.trim() == key
        {
            // Last occurrence wins (fapolicyd parity): keep overwriting.
            value = Some(v.trim());
        }
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conf_value_tolerates_all_whitespace_variants_around_equals() {
        // The D2 fix: every spacing variant of `permissive=1` yields the same
        // value, so the mode probe and the misconfig check cannot disagree.
        for line in [
            "permissive=1",
            "permissive = 1",
            "permissive =1",
            "permissive= 1",
        ] {
            assert_eq!(
                conf_value(line, "permissive"),
                Some("1"),
                "variant {line:?} must read as 1"
            );
        }
    }

    #[test]
    fn conf_value_requires_exact_key_match() {
        // A key that merely starts with the search key must NOT match.
        assert_eq!(conf_value("permissive_debug=1", "permissive"), None);
    }

    #[test]
    fn conf_value_last_occurrence_wins() {
        // fapolicyd's config loader overwrites on each duplicate key, so the LAST
        // occurrence determines the effective value (daemon-config.c per-keyword
        // parsers `free(); strdup()` with no early-exit). The reader must resolve
        // duplicates the same way or doctor/container-check would misreport the
        // effective config (issue #192 adversarial finding).
        assert_eq!(
            conf_value("permissive=0\npermissive=1\n", "permissive"),
            Some("1")
        );
    }

    #[test]
    fn conf_value_skips_whole_line_comments() {
        assert_eq!(
            conf_value("# permissive=1\npermissive=0\n", "permissive"),
            Some("0")
        );
    }

    #[test]
    fn conf_value_does_not_strip_inline_comment() {
        // fapolicyd honors ONLY whole-line `#` comments; a trailing `#` is part of
        // the literal value (nv_split in daemon-config.c rejects only a line whose
        // first token starts with `#`). Match that exactly so we never accept a
        // value fapolicyd would read differently (issue #192 adversarial finding).
        assert_eq!(
            conf_value("permissive=1 # default off\n", "permissive"),
            Some("1 # default off")
        );
    }

    #[test]
    fn conf_value_absent_key_is_none() {
        assert_eq!(
            conf_value("integrity=sha256\nrpm_integrity_check=1\n", "permissive"),
            None
        );
    }

    #[test]
    fn conf_value_reads_a_list_value_verbatim() {
        // watch_fs is a comma list the caller splits; conf_value returns the
        // trimmed raw value.
        assert_eq!(
            conf_value("watch_fs = ext4,tmpfs,xfs\n", "watch_fs"),
            Some("ext4,tmpfs,xfs")
        );
    }
}
