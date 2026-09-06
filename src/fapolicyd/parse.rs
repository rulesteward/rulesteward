//! Input pipeline and record parsing. DESIGN.md §4 and §5.

use super::model::{Record, Side};

/// `working_buffer[WB_SIZE - 1] = 0`, so the payload caps at 511 bytes.
pub const MAX_PAYLOAD: usize = 511;

/// Strip the framing prefix by anchoring on `]: `, never on a byte count.
///
/// The `--debug-deny` prefix is `MM/DD/YY HH:MM:SS [ <colour>LEVEL<reset> ]: ` whose
/// visible width tracks the log level (DEBUG 29, INFO 28, NOTICE 30, WARNING 31) and
/// whose `%x` is LC_TIME-dependent. Under syslog it is a timestamp, a hostname and
/// `fapolicyd[<PID>]: ` — which ends in the same anchor, so one rule covers both.
/// Rocky 8 emits no prefix at all and falls through untouched.
///
/// A literal `]: ` inside a value cannot be confused for the anchor: a literal space is
/// always escaped, so such a path emits as `]:\ `.
pub fn strip_prefix(line: &[u8]) -> &[u8] {
    match find(line, b"]: ") {
        Some(i) => &line[i + 3..],
        None => line,
    }
}

/// Remove ANSI SGR sequences. The daemon colourises the log level, not the payload,
/// but the escapes sit inside the region we measure for truncation.
pub fn strip_ansi(line: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(line.len());
    let mut i = 0;
    while i < line.len() {
        if line[i] == 0x1b && line.get(i + 1) == Some(&b'[') {
            i += 2;
            while i < line.len() && !(0x40..=0x7e).contains(&line[i]) {
                i += 1;
            }
            i += 1; // the final byte
        } else {
            out.push(line[i]);
            i += 1;
        }
    }
    out
}

/// `dec=` is the only reliable denial test; "it appeared in the stream" is not one.
/// A default install emits only `deny_audit`, but a corpus with plain `deny`,
/// `deny_syslog` and `deny_log` rules produces all four, and full `--debug` carries
/// `dec=no-opinion` records that are not denials.
pub fn is_denial(record: &Record) -> bool {
    // Subject side only, and from the already-parsed record: `dec` is a subject-side
    // field, and re-splitting the payload here would parse every line twice.
    record
        .subject_get(b"dec")
        .is_some_and(|v| v.starts_with(b"deny"))
}

/// Rocky 9/10 emit one `SHA256HASH ... deprecated` NOTICE per daemon start,
/// unconditionally and regardless of the user's rules. Not a denial, not a problem.
///
/// Both words are required. Matching `deprecated` alone silently discards a real
/// denial for `path=/opt/deprecated/x`, before it is ever counted. Comments are not
/// tested here: `#` is a property of the RAW line, and `analyze` checks it before the
/// framing prefix is stripped.
pub fn is_noise(payload: &[u8]) -> bool {
    payload.is_empty()
        || (find(payload, b"SHA256HASH").is_some() && find(payload, b"deprecated").is_some())
}

/// Split a payload into subject and object sides on the bare ` : ` separator.
///
/// Splitting on ` : ` is sound because a literal space is always escaped, so an
/// unescaped space is always a delimiter: a path containing ` : ` emits as `\ :\ `.
/// This is a derived consequence of the escaping table, verified byte-identical on
/// Rocky 8, 9 and 10 — it is not a documented guarantee, so do not "simplify" it into
/// a plain `split(':')`.
pub fn parse(payload: &[u8]) -> Record {
    let (subj, obj) = match find_unescaped(payload, b" : ") {
        Some(i) => (&payload[..i], Some(&payload[i + 3..])),
        None => (payload, None),
    };
    Record {
        subject: fields(subj),
        object: obj.map(fields),
    }
}

/// `name=value` pairs joined by single unescaped spaces. Key and value split on the
/// FIRST `=` only: `:`, `=`, `#`, `%`, `,` and raw UTF-8 all appear literally inside
/// values.
///
/// A token with no `=` is not a field and is dropped. The daemon interleaves ordinary
/// prose log lines with records, and turning `cannot open /etc/foo` into three
/// nameless fields makes every such line look like a corrupted record.
fn fields(side: &[u8]) -> Side {
    split_unescaped(side, b' ')
        .into_iter()
        .filter_map(|tok| {
            let i = tok.iter().position(|&b| b == b'=')?;
            (i > 0).then(|| (tok[..i].to_vec(), tok[i + 1..].to_vec()))
        })
        .collect()
}

/// Inverse of the daemon's `escape_shell`. The escaping table is
/// `static const char sh_set[] = "\"'`$\\!()| ";` plus every byte below 32 rendered as
/// a backslash and three OCTAL digits.
///
/// The octal form is the one that matters: `spec/fapolicyd-grammar.json` claims
/// newline and tab escape as `\n` and `\t`, but the captures disagree —
/// `nl\012line`, `tab\011here`. The captures win.
///
/// Only `\000`..`\037` decode. The escaper emits the octal form for bytes below 32 and
/// nothing else, so `\040` is a literal backslash followed by `040` — a real backslash
/// arrives as `\\`. Decoding the wider range would rewrite `/tmp/a\\040b` into a path
/// that never existed.
pub fn unescape(value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(value.len());
    let mut i = 0;
    while i < value.len() {
        if value[i] == b'\\'
            && i + 3 < value.len()
            && matches!(value[i + 1..i + 4], [b'0', b'0'..=b'3', b'0'..=b'7'])
        {
            let n = value[i + 1..i + 4]
                .iter()
                .fold(0u8, |acc, d| acc * 8 + (d - b'0'));
            out.push(n);
            i += 4;
        } else if value[i] == b'\\' && i + 1 < value.len() {
            out.push(value[i + 1]);
            i += 2;
        } else {
            out.push(value[i]);
            i += 1;
        }
    }
    out
}

/// After a failed rules reload `destroy_rules` frees every field NAME while leaving
/// `num_fields` non-zero, so `log_it` reads each name out of freed memory. Values
/// survive and names do not, producing records like `<garbage>=no-opinion`. The
/// garbage differs per release and per run, so it cannot be matched on — but a real
/// field name is always lowercase ASCII, which the garbage reliably is not.
///
/// This matters more than it looks. A daemon in this state is fully operational and
/// ALLOWING EVERYTHING, so the correct report is "restart the daemon", never "no
/// denials found".
pub fn is_corrupt_field_name(name: &[u8]) -> bool {
    // The test is "cannot be text", not "is not a name I know". Freed pointer bytes
    // are arbitrary binary and reliably carry control or high bytes; anything
    // printable is some other tool's output, not corruption. Being wrong in the
    // permissive direction matters here — crying "your daemon is allowing
    // everything" over an unfamiliar field name would be worse than staying quiet.
    //
    // ponytail: byte-class heuristic. Garbage that happens to be entirely printable
    // ASCII reads as an ordinary unknown field. Tighten to a known-name whitelist
    // only if a capture ever slips through.
    name.iter().any(|b| *b < 0x20 || *b >= 0x7f)
}

/// True when the byte at `i` is escaped, i.e. preceded by an odd run of backslashes.
fn escaped(buf: &[u8], i: usize) -> bool {
    let mut n = 0;
    let mut j = i;
    while j > 0 && buf[j - 1] == b'\\' {
        n += 1;
        j -= 1;
    }
    n % 2 == 1
}

fn split_unescaped(buf: &[u8], sep: u8) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut start = 0;
    for i in 0..buf.len() {
        if buf[i] == sep && !escaped(buf, i) {
            out.push(&buf[start..i]);
            start = i + 1;
        }
    }
    out.push(&buf[start..]);
    out
}

fn find_unescaped(buf: &[u8], needle: &[u8]) -> Option<usize> {
    // `windows` yields nothing when the needle is longer than the buffer, which is
    // why there is no length guard here.
    buf.windows(needle.len())
        .enumerate()
        .find(|&(i, w)| w == needle && !escaped(buf, i))
        .map(|(i, _)| i)
}

fn find(buf: &[u8], needle: &[u8]) -> Option<usize> {
    buf.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fapolicyd::model::get;
    use proptest::prelude::*;

    #[test]
    fn strips_debug_prefix_by_anchor_not_width() {
        let debug = b"08/26/26 23:50:59 [ DEBUG ]: rule=1 dec=deny_audit";
        let warning = b"08/26/26 23:50:59 [ WARNING ]: rule=1 dec=deny_audit";
        assert_eq!(strip_prefix(debug), b"rule=1 dec=deny_audit");
        assert_eq!(strip_prefix(warning), b"rule=1 dec=deny_audit");
    }

    #[test]
    fn rocky8_has_no_prefix() {
        let bare = b"rule=13 dec=deny_audit perm=execute";
        assert_eq!(strip_prefix(bare), bare);
    }

    #[test]
    fn strips_syslog_prefix_via_the_same_anchor() {
        let syslog = b"fapolicyd[292]: rule=1 dec=deny_audit";
        assert_eq!(strip_prefix(syslog), b"rule=1 dec=deny_audit");
    }

    #[test]
    fn strips_ansi() {
        let coloured = b"[ \x1b[34mDEBUG\x1b[0m ]: rule=1";
        assert_eq!(strip_ansi(coloured), b"[ DEBUG ]: rule=1");
    }

    #[test]
    fn splits_subject_from_object() {
        let r = parse(b"rule=1 dec=deny_audit exe=/usr/bin/bash : path=/tmp/x trust=0");
        assert_eq!(get(&r.subject, b"exe"), Some(b"/usr/bin/bash".to_vec()));
        assert_eq!(r.object_get(b"path"), Some(b"/tmp/x".to_vec()));
        assert_eq!(r.object_get(b"trust"), Some(b"0".to_vec()));
    }

    #[test]
    fn an_escaped_colon_in_a_path_is_not_the_separator() {
        // /tmp/edge/a : b emits as a\ :\ b — the delimiter is the UNESCAPED one.
        let r = parse(b"exe=/usr/sbin/runuser : path=/tmp/edge/a\\ :\\ b ftype=text/plain");
        // `get` unescapes, so the caller sees the true bytes and never the wire form.
        assert_eq!(r.object_get(b"path"), Some(b"/tmp/edge/a : b".to_vec()));
    }

    #[test]
    fn a_record_with_no_separator_is_not_a_failure() {
        let r = parse(b"rule=2 dec=deny_audit perm=open comm=runuser");
        assert!(r.object.is_none());
        assert_eq!(get(&r.subject, b"comm"), Some(b"runuser".to_vec()));
    }

    #[test]
    fn prose_log_lines_yield_no_fields() {
        // Not a record. If these became nameless fields, every daemon message would
        // read as a corrupted record.
        assert!(
            parse(b"cannot open /etc/fapolicyd/fapolicyd.rules")
                .subject
                .is_empty()
        );
        assert!(parse(b"Loaded 13 rules").subject.is_empty());
    }

    #[test]
    fn duplicate_field_names_survive_and_first_wins() {
        // The 21-field syslog_format case: names repeat inside one side.
        let r = parse(b"rule=2 dec=deny_audit rule=2 dec=deny_audit rule=2");
        assert_eq!(r.subject.len(), 5);
        assert_eq!(get(&r.subject, b"rule"), Some(b"2".to_vec()));
    }

    #[test]
    fn value_splits_on_the_first_equals_only() {
        let r = parse(b"exe=/usr/bin/bash : path=/tmp/edge/eq=sign");
        assert_eq!(r.object_get(b"path"), Some(b"/tmp/edge/eq=sign".to_vec()));
    }

    #[test]
    fn unescape_round_trips_the_sh_set() {
        assert_eq!(
            unescape(b"/tmp/gaps/spaced\\ bash"),
            b"/tmp/gaps/spaced bash"
        );
        assert_eq!(unescape(b"back\\\\slash"), b"back\\slash");
        assert_eq!(unescape(b"quote\\'single"), b"quote'single");
        assert_eq!(unescape(b"quote\\\"double"), b"quote\"double");
        // Octal, not \n and \t, whatever the grammar spec says.
        assert_eq!(unescape(b"nl\\012line"), b"nl\nline");
        assert_eq!(unescape(b"tab\\011here"), b"tab\there");
    }

    #[test]
    fn unescaped_bytes_above_127_pass_through_raw() {
        let utf8 = "path=/tmp/edge/caf\u{e9}".as_bytes();
        assert_eq!(unescape(utf8), utf8);
    }

    #[test]
    fn recognises_freed_memory_as_a_field_name() {
        assert!(!is_corrupt_field_name(b"dec"));
        assert!(!is_corrupt_field_name(b"sha256hash"));
        // Other tools write to the same stream. Unfamiliar is not corrupt.
        assert!(!is_corrupt_field_name(b"DISAGREEMENT"));
        assert!(!is_corrupt_field_name(b"check-config"));
        // A real capture from rocky8-base-reload-probe-empty-ruleset-daemon.log.
        assert!(is_corrupt_field_name(&[0x52, 0x3f, 0xfa, 0x62, 0x0f, 0x56]));
    }

    #[test]
    fn denial_filter_rejects_no_opinion() {
        assert!(is_denial(&parse(b"rule=1 dec=deny_audit perm=open")));
        assert!(is_denial(&parse(b"rule=4 dec=deny_syslog perm=open")));
        assert!(!is_denial(&parse(b"rule=0 dec=no-opinion perm=open")));
        assert!(!is_denial(&parse(b"rule=1 dec=allow perm=open")));
    }

    #[test]
    fn the_denial_test_reads_dec_from_the_subject_side_only() {
        // `dec` is subject-side. An object-side `dec=` is not a decision.
        let r = parse(b"rule=0 dec=no-opinion : path=/tmp/x dec=deny_audit");
        assert!(!is_denial(&r));
    }

    #[test]
    fn the_deprecation_notice_is_noise_and_a_deprecated_path_is_not() {
        assert!(is_noise(
            b"SHA256HASH is deprecated, please use filehash instead"
        ));
        assert!(is_noise(b""));
        // The word alone is not the notice. Dropping this line loses a real denial.
        assert!(!is_noise(
            b"rule=1 dec=deny_audit perm=open : path=/opt/deprecated/x trust=0"
        ));
    }

    #[test]
    fn octal_decoding_stops_at_037() {
        // The escaper only emits the octal form for bytes below 32; \040 is a literal
        // backslash and three digits, because a real backslash arrives as \\.
        assert_eq!(unescape(b"a\\037b"), b"a\x1fb");
        assert_eq!(unescape(b"a\\040b"), b"a040b");
        assert_eq!(unescape(b"a\\101b"), b"a101b");
    }

    #[test]
    fn get_unescapes_the_subject_side_too() {
        // §8.2: `exe=` is escaped identically to `path=`, so the accessor unescapes
        // both and no caller has to remember to.
        let r = parse(b"exe=/tmp/gaps/spaced\\ bash : path=/tmp/x");
        assert_eq!(
            r.subject_get(b"exe"),
            Some(b"/tmp/gaps/spaced bash".to_vec())
        );
    }

    /// The forward direction of `unescape`, written independently from the daemon's
    /// escaper as `unescape`'s doc comment describes it: the ten `sh_set` bytes take a
    /// backslash, every byte below 32 becomes a backslash and three octal digits, and
    /// everything else is raw. Writing the rule twice is what makes the round trip
    /// evidence — a shared helper would only prove the code agrees with itself. The
    /// reverse property (`escape(unescape(v)) == v`) is not valid, because `unescape`
    /// is not injective: `\x` and `x` both yield `x`.
    fn escape(value: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        for &b in value {
            if br#""'`$\!()| "#.contains(&b) {
                out.push(b'\\');
                out.push(b);
            } else if b < 0x20 {
                out.push(b'\\');
                out.push(b'0' + (b >> 6));
                out.push(b'0' + ((b >> 3) & 7));
                out.push(b'0' + (b & 7));
            } else {
                out.push(b);
            }
        }
        out
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(2048))]

        /// No input, however malformed, may panic the pipeline. Every result is
        /// discarded: the property is the absence of a panic, not the value.
        #[test]
        fn parse_never_panics(v in proptest::collection::vec(any::<u8>(), 0..4096)) {
            let _ = strip_prefix(&v);
            let _ = strip_ansi(&v);
            let _ = is_noise(&v);
            let _ = is_corrupt_field_name(&v);
            let _ = is_denial(&parse(&v));
        }

        /// Every branch of `unescape` consumes at least as many bytes as it emits.
        #[test]
        fn unescape_never_grows(v in proptest::collection::vec(any::<u8>(), 0..4096)) {
            prop_assert!(unescape(&v).len() <= v.len());
        }

        // D5: the survey read `\400`..`\777` aliasing through `n as u8` on 4b06bb8. On
        // this tree only `\000`..`\037` decode and the fold is `u8`, so the aliasing is
        // unreachable; this property and `octal_decoding_stops_at_037` pin that.
        #[test]
        fn unescape_inverts_escape(v in proptest::collection::vec(any::<u8>(), 0..512)) {
            prop_assert_eq!(unescape(&escape(&v)), v);
        }
    }
}
