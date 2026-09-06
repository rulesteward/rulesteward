//! The decision table. DESIGN.md §7.

use super::model::{Record, Suggestion, Trust};

pub enum Decision {
    /// A suggestion, and anything the user has to know about how it was reached.
    Emit {
        suggestion: Suggestion,
        note: Option<String>,
    },
    /// Nothing safe to emit, and the reason why.
    Explain(String),
}

/// Why the record landed in the rule arms, which is also the difference between them.
enum Arm {
    /// `trust=1`. The file is trusted and a rule denied it, so widening trust would be
    /// wrong and a rule is the only answer.
    Trusted,
    /// No `trust=` at all. A trust entry is still a legal answer here (§8.1), which is
    /// what the unrepresentable-path fallback uses.
    TrustAbsent,
}

const ABSENT_NOTE: &str = "no trust= in this record, so the trust-vs-rule decision has \
                           no input; a scoped rule never widens global trust, so a rule \
                           is the safe default";

/// Four arms, not two. `trust=0` means untrusted and `trust=9` means the attribute
/// was unavailable; collapsing them into "non-zero, so emit a rule" produces an allow
/// rule for a file whose trust state is simply unknown.
///
/// Subject trust never reaches here. It takes a different path, `subj ? subj->uval : 0`,
/// and has no sentinel — an unavailable subject trust prints as `0`, indistinguishable
/// from genuinely untrusted. No branch may depend on telling those apart.
pub fn decide(record: &Record) -> Decision {
    let Some(path) = record.object_get(b"path") else {
        return Decision::Explain(
            "record carries no path=; nothing to act on (this is a syslog_format \
             configuration, not a malformed record)"
                .into(),
        );
    };

    // `escape_shell` returns NULL past MAX_SIZE 8192 and `format_value` substitutes
    // "??" for the WHOLE value, which a long non-ASCII path reaches at ~2048 bytes.
    // A "??" path is not a path.
    if path == b"??" {
        return Decision::Explain(
            "path= is ?? — the daemon could not encode the real path, so there is \
             nothing to add to the trust database"
                .into(),
        );
    }

    let trust = record.object_get(b"trust");
    match Trust::from_object(trust.as_deref()) {
        Trust::Untrusted => {
            // fapolicyd.trust is one `path size sha256` record per line, parsed
            // right to left — which is why a path containing a SPACE is fine and
            // needs no special handling here. A control byte is not: a newline
            // splits the record in two and right-to-left parsing cannot recover it.
            // It would also break §9's promise that stdout is bare, pipe-safe lines.
            if let Some(b) = control_byte(&path) {
                return Decision::Explain(format!(
                    "path contains a control byte (0x{b:02x}), which cannot be written \
                     as a fapolicyd.trust record; emitting nothing"
                ));
            }
            Decision::Emit {
                suggestion: Suggestion::TrustFile { path },
                note: None,
            }
        }
        Trust::Trusted => rule(record, path, Arm::Trusted),
        // The value is displayed, not compared: `from_object` maps every non-0/1 value
        // here, so hard-coding `9` would misreport a `trust=?` record.
        Trust::Unavailable => Decision::Explain(format!(
            "trust attribute unavailable (trust={}); emitting nothing, because the \
             file's trust state is unknown rather than untrusted",
            String::from_utf8_lossy(trust.as_deref().unwrap_or_default())
        )),
        Trust::Absent => rule(record, path, Arm::TrustAbsent),
    }
}

/// The two rule arms. DESIGN.md §7 "The rule v1 emits".
///
/// Refusals live here and not in `emit` because they change the decision, not the
/// rendering: on an unrepresentable path the `trust`-absent arm still has a legal
/// answer, and the trusted arm has none.
fn rule(record: &Record, path: Vec<u8>, arm: Arm) -> Decision {
    let note = match arm {
        Arm::Trusted => None,
        Arm::TrustAbsent => Some(ABSENT_NOTE.to_string()),
    };

    // A control byte splits the emitted line in two. Neither a rule nor a trust
    // record survives that, so both arms refuse.
    if let Some(b) = control_byte(&path) {
        return Decision::Explain(format!(
            "path contains a control byte (0x{b:02x}), which would split the emitted \
             line; emitting nothing"
        ));
    }

    if path.iter().any(|b| *b == b' ' || *b == b':') {
        return match arm {
            Arm::Trusted => Decision::Explain(
                "path is unrepresentable in a rule (space or colon; the rule parser \
                 has no quoting and a colon flips the format), and the file is already \
                 trusted, so there is nothing safe to emit"
                    .into(),
            ),
            // §8.1 offers the trust entry as the alternative, and the trust file is
            // parsed right to left, so a space in the path is fine there.
            Arm::TrustAbsent => Decision::Emit {
                suggestion: Suggestion::TrustFile { path },
                note: Some(
                    "no trust= in this record and the path cannot be written in a rule \
                     (space or colon), so a trust entry is the only representable \
                     suggestion"
                        .into(),
                ),
            },
        };
    }

    // §8.1's fail-open rule: an attribute the event could not supply makes the rule
    // broader, not narrower. `perm` is the whole scope of the rule, so a record
    // without a real one has nothing to scope.
    let Some(perm) = record
        .subject_get(b"perm")
        .filter(|p| matches!(p.as_slice(), b"open" | b"execute"))
    else {
        return Decision::Explain(
            "cannot scope a rule without a real perm=; the record carries no perm=open \
             or perm=execute, and a rule without it would allow every access to the path"
                .into(),
        );
    };

    // Absent, `?` or unrepresentable means no subject constraint at all, which renders
    // as `all`. A wrong `exe=` would be worse: the evaluator skips a constraint it
    // cannot match, so a broken one silently widens the rule.
    let exe = record.subject_get(b"exe").filter(|e| {
        !e.is_empty()
            && !matches!(e.as_slice(), b"?" | b"??")
            && !e.iter().any(|b| *b == b' ' || *b == b':' || *b < 0x20)
    });

    Decision::Emit {
        suggestion: Suggestion::Rule { perm, exe, path },
        note,
    }
}

fn control_byte(value: &[u8]) -> Option<u8> {
    value.iter().copied().find(|b| *b < 0x20)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fapolicyd::parse;

    fn decide_line(line: &[u8]) -> Decision {
        decide(&parse::parse(line))
    }

    fn emitted(d: &Decision) -> (&Suggestion, Option<&str>) {
        match d {
            Decision::Emit { suggestion, note } => (suggestion, note.as_deref()),
            Decision::Explain(msg) => panic!("expected an emission, got: {msg}"),
        }
    }

    fn explained(d: &Decision) -> &str {
        match d {
            Decision::Emit { suggestion, .. } => panic!("expected a refusal, got: {suggestion:?}"),
            Decision::Explain(msg) => msg,
        }
    }

    #[test]
    fn untrusted_object_gets_a_trust_entry() {
        let d = decide_line(b"dec=deny_audit perm=open exe=/usr/bin/bash : path=/tmp/x trust=0");
        assert_eq!(
            emitted(&d),
            (
                &Suggestion::TrustFile {
                    path: b"/tmp/x".to_vec()
                },
                None
            )
        );
    }

    #[test]
    fn trusted_object_gets_a_scoped_rule() {
        let d = decide_line(b"dec=deny_audit perm=execute exe=/usr/bin/bash : path=/tmp/x trust=1");
        assert_eq!(
            emitted(&d),
            (
                &Suggestion::Rule {
                    perm: b"execute".to_vec(),
                    exe: Some(b"/usr/bin/bash".to_vec()),
                    path: b"/tmp/x".to_vec(),
                },
                None
            )
        );
    }

    #[test]
    fn subject_trust_never_overrides_object_trust() {
        // `trust=1` on the subject side is the process, and subject trust has no
        // sentinel, so it may not move the decision. The object is untrusted.
        let d = decide_line(
            b"dec=deny_audit perm=open trust=1 exe=/usr/bin/bash : path=/tmp/x trust=0",
        );
        assert!(matches!(
            emitted(&d).0,
            Suggestion::TrustFile { .. } //
        ));
    }

    #[test]
    fn an_unavailable_trust_quotes_the_value_it_actually_saw() {
        let d = decide_line(b"dec=deny_audit perm=open : path=/tmp/x trust=?");
        let msg = explained(&d);
        assert!(msg.contains("trust=?"), "{msg}");
    }

    #[test]
    fn a_trusted_object_on_a_spaced_path_gets_nothing() {
        let d = decide_line(b"dec=deny_audit perm=open : path=/tmp/spaced\\ bash trust=1");
        assert!(explained(&d).contains("unrepresentable in a rule"));

        let d = decide_line(b"dec=deny_audit perm=open : path=/tmp/a:b trust=1");
        assert!(explained(&d).contains("unrepresentable in a rule"));
    }

    #[test]
    fn an_absent_trust_on_a_spaced_path_falls_back_to_a_trust_entry() {
        let d = decide_line(b"dec=deny_audit perm=open : path=/tmp/spaced\\ bash");
        let (suggestion, note) = emitted(&d);
        assert_eq!(
            suggestion,
            &Suggestion::TrustFile {
                path: b"/tmp/spaced bash".to_vec()
            }
        );
        assert!(note.is_some_and(|n| n.contains("no trust=")), "{note:?}");
    }

    #[test]
    fn an_absent_trust_with_no_usable_exe_scopes_the_rule_to_the_path_alone() {
        let d = decide_line(b"dec=deny_audit perm=open exe=? : path=/tmp/x");
        let (suggestion, note) = emitted(&d);
        assert_eq!(
            suggestion,
            &Suggestion::Rule {
                perm: b"open".to_vec(),
                exe: None,
                path: b"/tmp/x".to_vec(),
            }
        );
        assert!(note.is_some());
    }

    #[test]
    fn a_control_byte_in_the_path_refuses_in_every_arm() {
        for tail in [b"trust=0".as_slice(), b"trust=1", b""] {
            let mut line = b"dec=deny_audit perm=open : path=/tmp/a\\012b ".to_vec();
            line.extend_from_slice(tail);
            assert!(explained(&decide_line(&line)).contains("control byte"));
        }
    }

    #[test]
    fn a_record_without_a_real_perm_cannot_be_scoped() {
        let d = decide_line(b"dec=deny_audit exe=/usr/bin/bash : path=/tmp/x trust=1");
        assert!(explained(&d).contains("without a real perm="));

        // `perm=any` is not one of the two the daemon emits.
        let d = decide_line(b"dec=deny_audit perm=any : path=/tmp/x trust=1");
        assert!(explained(&d).contains("without a real perm="));
    }

    #[test]
    fn a_record_with_no_path_is_a_configuration_report_not_a_failure() {
        let d = decide_line(b"dec=deny_audit perm=open exe=/usr/bin/bash");
        assert!(explained(&d).contains("no path="));
    }

    #[test]
    fn an_unencodable_path_is_refused_before_the_trust_arms() {
        let d = decide_line(b"dec=deny_audit perm=open : path=?? trust=1");
        assert!(explained(&d).contains("path= is ??"));
    }
}
