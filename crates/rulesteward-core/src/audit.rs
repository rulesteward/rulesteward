//! Shared parsing helpers for Linux audit-record (`key=value`) lines.
//!
//! Both the fapolicyd FANOTIFY parser (`rulesteward_fapolicyd::fanotify`) and the
//! `SELinux` AVC parser (`rulesteward_selinux::avc`), as well as the `doctor`
//! denial summariser, read fields out of `ausearch`/kernel audit lines. This is
//! the single, word-boundary-guarded extractor they share, so a search for `pid`
//! never matches inside `ppid=`.

/// Extract the value of `key` from an audit-record line, accepting both unquoted
/// (`key=value`) and quoted (`key="value"`) forms.
///
/// `key` is passed WITHOUT the trailing `=` (e.g. `"pid"`, not `"pid="`). The key
/// must sit at a word boundary -- the start of the line or immediately after ASCII
/// whitespace -- so a search for `pid=` does NOT match inside `ppid=`. The
/// unquoted form ends at the next whitespace (or end of line); the quoted form is
/// delimited by the next `"`. Returns `None` when the key is absent.
#[must_use]
pub fn extract_audit_field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let search = format!("{key}=");
    // Take the first `key=` occurrence at a word boundary (start-of-line or
    // preceded by whitespace), so `pid=` does not match inside `ppid=`. Scanning
    // with `match_indices(..).find(..)` (rather than a hand-rolled
    // `start = abs_pos + 1` cursor) means there is no loop-advance arithmetic a
    // mutation could reverse into a non-terminating loop. No `key=` needle here
    // can self-overlap (no key passed in contains `=`), so `match_indices`
    // (non-overlapping) selects the same occurrence a `+1` walk would.
    let (abs_pos, _) = line.match_indices(search.as_str()).find(|&(abs_pos, _)| {
        abs_pos == 0
            || line
                .as_bytes()
                .get(abs_pos - 1)
                .is_some_and(u8::is_ascii_whitespace)
    })?;
    let after = &line[abs_pos + search.len()..];
    // Quoted value: key="...", delimited by the next quote.
    if let Some(inner) = after.strip_prefix('"') {
        let end = inner.find('"')?;
        return Some(&inner[..end]);
    }
    // Unquoted value: ends at the next whitespace (or end of line).
    let end = after.find(char::is_whitespace).unwrap_or(after.len());
    Some(&after[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_audit_field_key_at_position_zero() {
        // The key sits at byte 0 (no preceding whitespace): exercises the
        // `abs_pos == 0` arm of the word-boundary guard.
        assert_eq!(extract_audit_field("resp=2 fan_type=0", "resp"), Some("2"));
    }

    #[test]
    fn extract_audit_field_unquoted_value_stops_at_whitespace() {
        assert_eq!(extract_audit_field("a=1 pid=51 auid=0", "pid"), Some("51"));
    }

    #[test]
    fn extract_audit_field_handles_quoted_value() {
        // Quoted values may contain spaces; delimited by the closing quote.
        assert_eq!(
            extract_audit_field("exe=\"/usr/bin/cat\" pid=1", "exe"),
            Some("/usr/bin/cat")
        );
    }

    #[test]
    fn extract_audit_field_value_at_end_of_line() {
        // No trailing whitespace after the value: must take to end-of-line.
        assert_eq!(extract_audit_field("tclass=file", "tclass"), Some("file"));
    }

    #[test]
    fn extract_audit_field_absent_key_is_none() {
        assert_eq!(extract_audit_field("resp=2 fan_type=0", "exe"), None);
    }

    // -- The word-boundary guard: this is the D1 latent bug avc.rs lacked. --

    #[test]
    fn extract_audit_field_does_not_match_pid_inside_ppid() {
        // The classic bug: searching `pid` must return pid's value (51), NOT
        // ppid's value (1) found inside the substring `ppid=`.
        assert_eq!(extract_audit_field("ppid=1 pid=51", "pid"), Some("51"));
    }

    #[test]
    fn extract_audit_field_suffix_only_collision_is_none() {
        // When ONLY `ppid=` is present, a search for `pid` finds no real `pid=`
        // at a word boundary and returns None (the unguarded `find` would have
        // wrongly returned "1").
        assert_eq!(extract_audit_field("ppid=1 auid=0", "pid"), None);
    }

    #[test]
    fn extract_audit_field_word_boundary_requires_whitespace_or_start() {
        // `subj_trust=2` must NOT satisfy a search for `trust` (preceded by `_`,
        // not whitespace); a real whitespace-preceded `trust=` does match.
        assert_eq!(extract_audit_field("resp=2 subj_trust=2", "trust"), None);
        assert_eq!(extract_audit_field("resp=2 trust=1", "trust"), Some("1"));
    }
}
