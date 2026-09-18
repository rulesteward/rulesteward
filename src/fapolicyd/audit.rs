//! The `ausearch` reader: audit records in, the same `Record`s the daemon route
//! produces out. DESIGN.md §5 "Audit route". Pure, like every sibling here.

use super::model::{Artifact, Diagnostic, Record, Side, Source};
use super::rules;
use std::collections::HashMap;

/// Fields of one audit record, as they were written: keys and values borrowed from the
/// input, decoded only where a caller asks for a string.
type Fields<'a> = Vec<(&'a [u8], &'a [u8])>;

/// The records of one event, keyed by `msg=audit(ts:serial)`. FANOTIFY is a list
/// because an exec through the loader carries two of them, one per rule decision.
#[derive(Default)]
struct Event<'a> {
    fanotify: Vec<(usize, Fields<'a>)>,
    syscall: Option<Fields<'a>>,
    paths: Vec<Fields<'a>>,
}

/// `ausearch` framing that carries no record: the default mode's event separator and
/// its `time->` header, plus the blank and `#` lines every route skips.
fn framing(line: &[u8]) -> bool {
    line.is_empty()
        || line.starts_with(b"#")
        || line.starts_with(b"----")
        || line.starts_with(b"time->")
}

/// Which reader the input belongs to, decided on its first real line.
///
/// `--raw` and default mode both write `type=NAME msg=audit(...)` records and differ
/// only in framing, so one test covers both (research `log-format.md`, "auditd", Q3).
/// The framing skip is what makes default mode reach this test at all: `----` and
/// `time->` sit ahead of the first record. `-i` also starts its lines with `type=` and
/// is NOT a supported dialect -- it rewrites `fan_info` to decimal, `resp` to a word and
/// the timestamp to a date -- so it lands here and produces nonsense rather than an
/// error. Section 5 says to pipe `--raw`.
pub fn is_audit(input: &[u8]) -> bool {
    input
        .split(|&b| b == b'\n')
        .map(|l| l.trim_ascii_start())
        .find(|l| !framing(l))
        .is_some_and(|l| l.starts_with(b"type="))
}

/// One `Record` per FANOTIFY record, grouped into events by `msg=audit(ts:serial)`.
///
/// Not one per event: a single exec through the loader carries two FANOTIFY records,
/// one per rule decision (#87 Q2), and each is a denial in its own right. Grouping and
/// not adjacency, because the order of the records inside an event is `--raw`'s in one
/// mode and its reverse in the other, and neither is promised.
///
/// `rules` is the compiled rules file when there is one. It decides nothing about the
/// object and everything about `dec=`: see `decision`.
pub fn records(input: &[u8], rules: Option<&[rules::Rule]>) -> Source {
    let mut source = Source::default();
    let mut events: Vec<Event> = Vec::new();
    // First-seen order is the report's order, so the index is kept beside the map
    // rather than iterating the map itself.
    let mut at: HashMap<&[u8], usize> = HashMap::new();

    for (i, raw) in input.split(|&b| b == b'\n').enumerate() {
        let line = raw.trim_ascii_start();
        if framing(line) || !line.starts_with(b"type=") {
            continue;
        }
        source.content += 1;
        let fields = fields(enriched(line));
        // The `type=` that made the line content is itself a field, so everything
        // counted above is parsed and §9's exit 2 cannot fire on audit input.
        source.parsed += 1;
        // A `msg=audit(...)` key is what makes the record usable: without one there is
        // no event to put it in.
        let (Some(kind), Some(key)) = (value(&fields, b"type"), key(&fields)) else {
            continue;
        };
        let e = *at.entry(key).or_insert_with(|| {
            events.push(Event::default());
            events.len() - 1
        });
        match kind {
            b"FANOTIFY" => events[e].fanotify.push((i + 1, fields)),
            b"SYSCALL" => events[e].syscall = Some(fields),
            b"PATH" => events[e].paths.push(fields),
            // EXECVE, CWD, PROCTITLE and everything else carry nothing the record model
            // has a place for. Never `proctitle=` or `cwd=`: a path is the file the
            // kernel named, not one reconstructed from a command line.
            _ => {}
        }
    }

    let mut no_rule = 0usize;
    let mut no_path = 0usize;
    for event in &events {
        // A property of the event and not of the FANOTIFY record, so it is resolved
        // once and counted once however many decisions the event carried.
        let path = object_path(event);
        if path.is_none() && !event.fanotify.is_empty() {
            no_path += 1;
        }
        for (line, fan) in &event.fanotify {
            let rule = value(fan, b"fan_info")
                .and_then(|v| usize::from_str_radix(std::str::from_utf8(v).ok()?, 16).ok())
                .unwrap_or(0);
            if rule == 0 {
                no_rule += 1;
            }
            let mut subject: Side = vec![
                (b"rule".to_vec(), rule.to_string().into_bytes()),
                (
                    b"dec".to_vec(),
                    decision(value(fan, b"resp"), rule, rules).into_bytes(),
                ),
                (b"perm".to_vec(), perm(event).to_vec()),
            ];
            if let Some(sys) = &event.syscall {
                if let Some(exe) = value(sys, b"exe") {
                    subject.push((b"exe".to_vec(), decode(exe)));
                }
                // Numeric by definition and never hex-encoded, so they are copied as
                // written: `uid=1001` is even-length hex too, and decoding it would
                // turn a uid into two raw bytes.
                for name in [&b"pid"[..], b"auid", b"uid"] {
                    if let Some(v) = value(sys, name) {
                        subject.push((name.to_vec(), v.to_vec()));
                    }
                }
            }
            let object = path.clone().map(|p| {
                let mut side: Side = vec![(b"path".to_vec(), p)];
                // Object trust is the FANOTIFY record's, not the PATH record's: it is
                // fapolicyd's own view of the file and the same value the daemon writes
                // as `trust=`. Rocky 8's `2` reaches `Trust::Unavailable` untouched.
                if let Some(t) = value(fan, b"obj_trust") {
                    side.push((b"trust".to_vec(), t.to_vec()));
                }
                side
            });
            // The payload length is the 511-byte truncation test's input and there is
            // no daemon payload here, so it is 0 and that test never fires.
            source
                .records
                .push((Some(*line), Record { subject, object }, 0));
        }
    }

    if no_rule > 0 {
        source.diagnostics.push(Diagnostic {
            line: None,
            artifact: Artifact::Both,
            msg: format!(
                "{no_rule} FANOTIFY record(s) carry no rule number (fan_info=0): fapolicyd \
                 1.3.2 on Rocky 8 does not write one; why has nothing to count"
            ),
        });
    }
    if no_path > 0 {
        source.diagnostics.push(Diagnostic {
            line: None,
            artifact: Artifact::Both,
            msg: format!(
                "{no_path} audit event(s) carry no PATH record for the object, so nothing to act on: load \
                 an exit rule with `auditctl -a always,exit -F arch=b64 -S \
                 creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EPERM` or use \
                 the journal route"
            ),
        });
    }
    source
}

/// The decision, which the record does not carry.
///
/// `resp=2` is an enforcing deny and says so itself. `resp=1` is what a permissive
/// daemon answers for BOTH a `deny_audit` and an `allow_audit` (#87 Q1), so the rules
/// file is the only thing that tells them apart: with one in hand the rule's own word
/// is used, and an `allow_audit` then fails `is_denial` and is never counted as a
/// denial the file does not match. Without one, the permissive default is assumed.
fn decision(resp: Option<&[u8]>, rule: usize, rules: Option<&[rules::Rule]>) -> String {
    if resp == Some(b"2") {
        return "deny_audit".into();
    }
    rules
        .and_then(|r| rule.checked_sub(1).and_then(|i| r.get(i)))
        .map_or_else(|| "deny_audit".into(), |r| r.decision.clone())
}

/// `execute` for the two exec syscalls, `open` for everything else.
///
/// `arch=c000003e` (x86-64) is the only architecture measured, where 59 is `execve` and
/// 322 is `execveat`. A record with no SYSCALL has no syscall number and falls to
/// `open`, which is §8.1's fail-open direction: the wrong perm on a rule is a narrower
/// mistake than none at all, and `policy::decide` refuses a record with neither.
fn perm(event: &Event) -> &'static [u8] {
    match event.syscall.as_ref().and_then(|s| value(s, b"syscall")) {
        Some(b"59") | Some(b"322") => b"execute",
        _ => b"open",
    }
}

/// The file the denial was about, from the event's PATH records.
///
/// `item=0` is the object when the syscall named one file (`items=1`). An exec names
/// two, the binary and the loader, and `item=0` is the binary only when both are there:
/// with no exit-filter rule loaded the kernel collects one name on the exec and it is
/// the LOADER (#87 Q4), so taking `item=0` unconditionally would emit a rule for
/// /lib64/ld-linux-x86-64.so.2 in place of the file that was actually denied.
fn object_path(event: &Event) -> Option<Vec<u8>> {
    let syscall = event.syscall.as_ref()?;
    let items = if perm(event) == b"execute" {
        b"2"
    } else {
        b"1"
    };
    if value(syscall, b"items") != Some(items) {
        return None;
    }
    let path = event
        .paths
        .iter()
        .find(|p| value(p, b"item") == Some(b"0"))?;
    let name = decode(value(path, b"name")?);
    (name != b"(null)").then_some(name)
}

/// `msg=audit(<epoch>.<ms>:<serial>)`, the one token identical on every record of one
/// event on every release (#87 Q5). The parentheses are kept out of the key so the
/// trailing `):` of the wire form cannot end up in it.
fn key<'a>(fields: &Fields<'a>) -> Option<&'a [u8]> {
    let msg = value(fields, b"msg")?;
    let open = msg.iter().position(|&b| b == b'(')? + 1;
    let close = open + msg[open..].iter().position(|&b| b == b')')?;
    Some(&msg[open..close])
}

/// First match wins, like `model::get`, and the value comes back as written: decoding
/// is the caller's, because only the caller knows whether the field is a string.
fn value<'a>(fields: &Fields<'a>, name: &[u8]) -> Option<&'a [u8]> {
    fields.iter().find(|(k, _)| *k == name).map(|(_, v)| *v)
}

/// The record without its ENRICHED suffix.
///
/// A capture from a host with `log_format = ENRICHED` carries the decoded uid, gid and
/// syscall names after the raw fields, separated from them by an 0x1d and NOT by a
/// space: a text dump reads `key=(null)\x1dARCH=x86_64` as one token and `obj_trust=0` as
/// the last field when it is really `obj_trust=0\x1d`. Cutting at the separator is what
/// keeps the last raw field of every record readable. Rocky 8's audit writes no suffix
/// and no separator, and the cut is then a no-op.
fn enriched(line: &[u8]) -> &[u8] {
    match line.iter().position(|&b| b == 0x1d) {
        Some(i) => &line[..i],
        None => line,
    }
}

/// `name=value` pairs joined by single spaces, split on the FIRST `=` only.
///
/// A space is unambiguous here in a way it is not in a daemon record: audit writes a
/// value that holds a space, a quote or a control byte as unquoted hex, so a quoted
/// value never contains one and there is nothing to escape.
fn fields(line: &[u8]) -> Fields<'_> {
    line.split(|&b| b == b' ')
        .filter_map(|tok| {
            let i = tok.iter().position(|&b| b == b'=')?;
            (i > 0).then(|| (&tok[..i], &tok[i + 1..]))
        })
        .collect()
}

/// A string-valued audit field, as bytes.
///
/// The trust boundary of this module: every shape is decoded or passed through, and
/// nothing here can panic or allocate unboundedly. Quoted is the ordinary case; the hex
/// form is what audit writes instead of quoting when the value holds a space, a quote
/// or a control byte. Anything else -- odd length, a non-hex digit, `(null)` -- is
/// passed through as the raw bytes, because a value this cannot read is still closer to
/// the truth than a guess at it.
fn decode(value: &[u8]) -> Vec<u8> {
    if value.len() >= 2 && value[0] == b'"' && value[value.len() - 1] == b'"' {
        return value[1..value.len() - 1].to_vec();
    }
    let hex = |b: u8| (b as char).to_digit(16).map(|d| d as u8);
    if value.is_empty()
        || !value.len().is_multiple_of(2)
        || !value.iter().all(|&b| hex(b).is_some())
    {
        return value.to_vec();
    }
    value
        .chunks(2)
        .filter_map(|p| Some(hex(p[0])? * 16 + hex(p[1])?))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// The three records of one denied `execve`, `--raw`, trimmed of the fields no
    /// reader here looks at. Lifted from
    /// `research/docs/fixtures/live/rocky9-audit-live-vm/…syscall.fanotify.raw`.
    const EXEC_EVENT: &[u8] = b"\
type=FANOTIFY msg=audit(1789678619.719:7454): resp=1 fan_type=1 fan_info=D subj_trust=2 obj_trust=0\x1d
type=SYSCALL msg=audit(1789678619.719:7454): arch=c000003e syscall=59 success=yes items=2 ppid=91725 pid=91726 auid=1000 uid=1001 comm=\"probe-grep\" exe=\"/tmp/live/probe-grep\" key=\"rulesteward-live\"\x1dARCH=x86_64
type=PATH msg=audit(1789678619.719:7454): item=0 name=\"/tmp/live/probe-grep\" inode=33555299 nametype=NORMAL cap_frootid=0\x1dOUID=\"root\"
type=PATH msg=audit(1789678619.719:7454): item=1 name=\"/lib64/ld-linux-x86-64.so.2\" inode=193036 nametype=NORMAL cap_frootid=0\x1dOUID=\"root\"
type=PROCTITLE msg=audit(1789678619.719:7454): proctitle=2F746D702F6C6976652F70726F62652D67726570
";

    /// The same denial as `ausearch` writes it without `--raw`: `----` and `time->`
    /// ahead of the event, and the record order reversed (#87 Q3).
    const EXEC_EVENT_DEFAULT: &[u8] = b"\
----
time->Thu Sep 17 20:56:59 2026
type=PROCTITLE msg=audit(1789678619.719:7454): proctitle=2F746D702F6C6976652F70726F62652D67726570
type=PATH msg=audit(1789678619.719:7454): item=1 name=\"/lib64/ld-linux-x86-64.so.2\" inode=193036 nametype=NORMAL cap_frootid=0\x1dOUID=\"root\"
type=PATH msg=audit(1789678619.719:7454): item=0 name=\"/tmp/live/probe-grep\" inode=33555299 nametype=NORMAL cap_frootid=0\x1dOUID=\"root\"
type=SYSCALL msg=audit(1789678619.719:7454): arch=c000003e syscall=59 success=yes items=2 ppid=91725 pid=91726 auid=1000 uid=1001 comm=\"probe-grep\" exe=\"/tmp/live/probe-grep\" key=\"rulesteward-live\"\x1dARCH=x86_64
type=FANOTIFY msg=audit(1789678619.719:7454): resp=1 fan_type=1 fan_info=D subj_trust=2 obj_trust=0\x1d
";

    /// One denied `openat`: `items=1`, one PATH, and the object is `item=0`.
    const OPEN_EVENT: &[u8] = b"\
type=FANOTIFY msg=audit(1789678619.794:7470): resp=1 fan_type=1 fan_info=8 subj_trust=2 obj_trust=1\x1d
type=SYSCALL msg=audit(1789678619.794:7470): arch=c000003e syscall=257 success=yes items=1 ppid=91731 pid=91732 auid=1000 uid=1001 comm=\"cat\" exe=\"/usr/bin/cat\" key=(null)\x1dARCH=x86_64
type=PATH msg=audit(1789678619.794:7470): item=0 name=\"/tmp/live/probe-lib.so\" inode=33555301 nametype=NORMAL cap_frootid=0\x1dOUID=\"root\"
";

    fn one(input: &[u8]) -> Record {
        let source = records(input, None);
        assert_eq!(source.records.len(), 1, "expected exactly one record");
        source.records[0].1.clone()
    }

    fn notes(source: &Source) -> String {
        source
            .diagnostics
            .iter()
            .map(|d| format!("{}\n", d.msg))
            .collect()
    }

    #[test]
    fn a_daemon_log_is_not_audit_input_and_ausearch_framing_does_not_hide_the_first_record() {
        assert!(!is_audit(
            b"rule=13 dec=deny_audit perm=execute : path=/tmp/x trust=1\n"
        ));
        assert!(!is_audit(b""));
        assert!(is_audit(EXEC_EVENT));
        // The `----`/`time->` pair sits ahead of the first record in default mode, so
        // testing the literal first line would route this input to the daemon reader.
        assert!(is_audit(EXEC_EVENT_DEFAULT));
    }

    #[test]
    fn a_contiguous_raw_event_maps_to_one_record() {
        let r = one(EXEC_EVENT);
        assert_eq!(r.subject_get(b"dec"), Some(b"deny_audit".to_vec()));
        assert_eq!(r.subject_get(b"perm"), Some(b"execute".to_vec()));
        assert_eq!(
            r.subject_get(b"exe"),
            Some(b"/tmp/live/probe-grep".to_vec())
        );
        assert_eq!(r.subject_get(b"pid"), Some(b"91726".to_vec()));
        assert_eq!(r.subject_get(b"auid"), Some(b"1000".to_vec()));
        assert_eq!(r.subject_get(b"uid"), Some(b"1001".to_vec()));
        assert_eq!(
            r.object_get(b"path"),
            Some(b"/tmp/live/probe-grep".to_vec())
        );
        assert_eq!(r.object_get(b"trust"), Some(b"0".to_vec()));
    }

    #[test]
    fn default_framing_and_reversed_records_map_to_the_same_record() {
        // Grouping is on the `msg=audit(...)` key, so the order the records arrive in
        // may not change the answer.
        assert_eq!(one(EXEC_EVENT_DEFAULT), one(EXEC_EVENT));
    }

    #[test]
    fn interleaved_events_group_by_their_audit_key() {
        // auditd writes one event at a time, but nothing in the format promises it, and
        // a concatenation of two captures interleaves by construction.
        let mut input = Vec::new();
        for (a, b) in EXEC_EVENT.split(|&c| c == b'\n').zip(
            OPEN_EVENT
                .split(|&c| c == b'\n')
                .chain(std::iter::repeat(&b""[..])),
        ) {
            input.extend_from_slice(a);
            input.push(b'\n');
            input.extend_from_slice(b);
            input.push(b'\n');
        }
        let source = records(&input, None);
        let paths: Vec<Vec<u8>> = source
            .records
            .iter()
            .filter_map(|(_, r, _)| r.object_get(b"path"))
            .collect();
        assert_eq!(
            paths,
            [
                b"/tmp/live/probe-grep".to_vec(),
                b"/tmp/live/probe-lib.so".to_vec()
            ],
            "{}",
            notes(&source)
        );
    }

    #[test]
    fn fan_info_is_the_rule_number_in_hex() {
        // `D` is 13, the shipped `deny_audit perm=execute all : all` (#87 Q1).
        assert_eq!(one(EXEC_EVENT).subject_get(b"rule"), Some(b"13".to_vec()));
    }

    #[test]
    fn a_record_with_no_rule_number_is_rule_zero_and_one_diagnostic() {
        // Rocky 8: kernel 4.18 with fapolicyd 1.3.2 writes `fan_type=0 fan_info=0`.
        let input = replace(EXEC_EVENT, b"fan_info=D", b"fan_info=0");
        let source = records(&input, None);
        assert_eq!(
            source.records[0].1.subject_get(b"rule"),
            Some(b"0".to_vec())
        );
        assert_eq!(source.diagnostics.len(), 1, "{}", notes(&source));
        assert!(
            source.diagnostics[0].msg.contains("fan_info=0"),
            "{}",
            notes(&source)
        );
        assert_eq!(source.diagnostics[0].line, None);
        assert_eq!(source.diagnostics[0].artifact, Artifact::Both);
    }

    #[test]
    fn an_open_takes_its_object_from_item_zero_of_one_path() {
        let r = one(OPEN_EVENT);
        assert_eq!(r.subject_get(b"perm"), Some(b"open".to_vec()));
        assert_eq!(
            r.object_get(b"path"),
            Some(b"/tmp/live/probe-lib.so".to_vec())
        );
        assert_eq!(r.object_get(b"trust"), Some(b"1".to_vec()));
    }

    #[test]
    fn an_exec_takes_item_zero_only_when_there_are_two_paths() {
        // With two items, `item=0` is the binary and `item=1` the loader.
        assert_eq!(
            one(EXEC_EVENT).object_get(b"path"),
            Some(b"/tmp/live/probe-grep".to_vec())
        );
    }

    #[test]
    fn an_exec_with_one_path_has_no_object_and_says_so_once() {
        // No exit rule loaded: the lone PATH names the loader, not the file that was
        // executed, so taking `item=0` here would emit a rule for /lib64/ld-linux (#87
        // Q4). Two FANOTIFY records in the event, one diagnostic for the run.
        let input = replace(
            &replace(EXEC_EVENT, b" items=2 ", b" items=1 "),
            b"type=PATH msg=audit(1789678619.719:7454): item=0 name=\"/tmp/live/probe-grep\" inode=33555299 nametype=NORMAL cap_frootid=0\x1dOUID=\"root\"\n",
            b"",
        );
        let source = records(&input, None);
        assert_eq!(source.records.len(), 1);
        assert!(source.records[0].1.object.is_none());
        assert_eq!(source.diagnostics.len(), 1, "{}", notes(&source));
        assert!(
            source.diagnostics[0].msg.contains("no PATH record"),
            "{}",
            notes(&source)
        );
        assert!(
            source.diagnostics[0].msg.contains("auditctl"),
            "the fix has to be in the message: {}",
            notes(&source)
        );
    }

    #[test]
    fn the_enriched_suffix_is_cut_at_its_separator() {
        // `obj_trust=0` is the last raw field of a FANOTIFY record and the 0x1d that
        // follows it is invisible in a text dump. Reading `0\x1d` as the trust value
        // turns every trusted and untrusted object into an unavailable one.
        let r = one(EXEC_EVENT);
        assert_eq!(r.object_get(b"trust"), Some(b"0".to_vec()));
        // The suffix's own fields are never read, so cutting the record at the
        // separator loses nothing (#87: the reader needs none of them).
        assert_eq!(r.subject_get(b"ARCH"), None);
    }

    #[test]
    fn a_hex_value_decodes_and_a_numeric_one_is_left_alone() {
        // audit writes a value unquoted and hex whenever it holds a space, a quote or a
        // control byte. `uid=1001` is even-length hex too and is NOT a string.
        let input = replace(
            EXEC_EVENT,
            b"exe=\"/tmp/live/probe-grep\"",
            b"exe=2F746D702F6C6976652F61206220",
        );
        let r = one(&input);
        assert_eq!(r.subject_get(b"exe"), Some(b"/tmp/live/a b ".to_vec()));
        assert_eq!(r.subject_get(b"uid"), Some(b"1001".to_vec()));
    }

    #[test]
    fn resp_one_against_an_allow_rule_is_not_a_denial() {
        // `resp=1` is both a permissive `deny_audit` and an `allow_audit` (#87 Q1);
        // only the rule text tells them apart, and `is_denial` reads `dec=`.
        let rules: Vec<rules::Rule> = rules::parse(
            b"allow perm=open all : all\nallow_audit perm=execute all : all\n\
              allow perm=any all : all\nallow perm=any all : all\n\
              allow perm=any all : all\nallow perm=any all : all\n\
              allow perm=any all : all\nallow perm=any all : all\n\
              allow perm=any all : all\nallow perm=any all : all\n\
              allow perm=any all : all\nallow perm=any all : all\n\
              allow_audit perm=execute all : all\n",
        );
        let source = records(EXEC_EVENT, Some(&rules));
        let r = &source.records[0].1;
        assert_eq!(r.subject_get(b"dec"), Some(b"allow_audit".to_vec()));
        assert!(!crate::fapolicyd::parse::is_denial(r));
    }

    #[test]
    fn resp_two_is_a_denial_whatever_the_rules_file_says() {
        // An enforcing daemon answers deny to the kernel, so the record says so itself.
        let input = replace(EXEC_EVENT, b"resp=1", b"resp=2");
        let rules = rules::parse(b"allow perm=any all : all\n");
        let source = records(&input, Some(&rules));
        assert_eq!(
            source.records[0].1.subject_get(b"dec"),
            Some(b"deny_audit".to_vec())
        );
    }

    #[test]
    fn the_line_of_a_record_is_the_fanotify_line_it_came_from() {
        // The FANOTIFY record is the denial; a per-line note has to send the reader to
        // it and not to the SYSCALL record that supplied the subject.
        assert_eq!(records(EXEC_EVENT, None).records[0].0, Some(1));
        assert_eq!(records(EXEC_EVENT_DEFAULT, None).records[0].0, Some(7));
    }

    /// Byte-substitution, so a test can state one field's change instead of restating
    /// a whole event around it.
    fn replace(input: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
        let at = input
            .windows(from.len())
            .position(|w| w == from)
            .unwrap_or_else(|| panic!("{} is not in the input", String::from_utf8_lossy(from)));
        let mut out = input[..at].to_vec();
        out.extend_from_slice(to);
        out.extend_from_slice(&input[at + from.len()..]);
        out
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(2048))]

        /// No input, however malformed, may panic the reader. Hex decoding, the
        /// `msg=audit(...)` key and the field split all run on attacker-shaped bytes
        /// here; the property is the absence of a panic, not the value.
        #[test]
        fn records_never_panics(v in proptest::collection::vec(any::<u8>(), 0..4096)) {
            let _ = is_audit(&v);
            let _ = records(&v, None);
        }
    }
}
