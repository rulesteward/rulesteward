//! Rendering suggestions. DESIGN.md §8.

use super::model::Suggestion;

/// The rule shape is fixed by DESIGN.md §8.1, one constraint per line here:
///
/// - Colon format always: without the `:` the parser retries an unknown subject name
///   against the object table, so `trust=`, `dir=` and `ftype=` silently change side.
/// - No `mode=`: never evaluated, so it always matches, and it dereferences
///   uninitialised heap on Rocky 8.
/// - No `filehash`: 9/10-only spelling, and the only attribute that fails closed.
/// - A trailing newline always: on Rocky 8 a `rules.d/` file that lacks one glues its
///   last line to the next file's first.
/// - No quoting of rule values: rules have no quoting mechanism at all, so `policy`
///   has already refused every path and `exe` that could not be written literally.
pub fn render(s: &Suggestion) -> Vec<u8> {
    match s {
        // `--file add` alone writes a text file and contacts no daemon; taking effect
        // on a running daemon requires the following `--update`. Always emit both.
        Suggestion::TrustFile { path } => {
            let q = shell_quote(path);
            let mut out = b"fapolicyd-cli --file add ".to_vec();
            out.extend_from_slice(&q);
            out.extend_from_slice(b"\nfapolicyd-cli --update\n");
            out
        }
        // `all` is "add no constraint", which is what an `exe` the record could not
        // supply has to become: a guessed one would be skipped at match time and make
        // the rule broader than written.
        Suggestion::Rule { perm, exe, path } => {
            let subj = exe
                .as_ref()
                .map_or(b" all".to_vec(), |e| [b" exe=", e.as_slice()].concat());
            [
                b"allow perm=",
                perm.as_slice(),
                &subj,
                b" : path=",
                path,
                b"\n",
            ]
            .concat()
        }
    }
}

/// Values arrive already escaped for the daemon's own `sh_set`, which omits `;`, `&`,
/// `<`, `>`, `*`, `?`, `[` and `]`. Passing that straight into a shell command is
/// wrong, so callers unescape to the true byte path and this applies our own quoting.
///
/// Single quotes, unconditionally: inside them every byte is literal except `'`, and
/// `'\''` closes, escapes and reopens. Correct for non-UTF-8 paths too.
pub fn shell_quote(bytes: &[u8]) -> Vec<u8> {
    let mut out = vec![b'\''];
    for &b in bytes {
        if b == b'\'' {
            out.extend_from_slice(b"'\\''");
        } else {
            out.push(b);
        }
    }
    out.push(b'\'');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trust_file_always_emits_the_update_too() {
        let out = render(&Suggestion::TrustFile {
            path: b"/tmp/untrusted-ls".to_vec(),
        });
        let text = String::from_utf8(out).unwrap();
        assert_eq!(
            text,
            "fapolicyd-cli --file add '/tmp/untrusted-ls'\nfapolicyd-cli --update\n"
        );
    }

    #[test]
    fn quotes_spaces_and_shell_metacharacters_the_daemon_does_not_escape() {
        assert_eq!(
            shell_quote(b"/tmp/gaps/spaced bash"),
            b"'/tmp/gaps/spaced bash'"
        );
        assert_eq!(shell_quote(b"/tmp/a;rm -rf /"), b"'/tmp/a;rm -rf /'");
        assert_eq!(shell_quote(b"/tmp/a$(id)"), b"'/tmp/a$(id)'");
    }

    #[test]
    fn quotes_a_single_quote() {
        assert_eq!(
            shell_quote(b"/tmp/quote'single"),
            b"'/tmp/quote'\\''single'"
        );
    }

    #[test]
    fn quotes_non_utf8_bytes_without_losing_them() {
        assert_eq!(
            shell_quote(&[b'/', 0xff, 0xfe]),
            &[b'\'', b'/', 0xff, 0xfe, b'\'']
        );
    }

    fn rule(exe: Option<&[u8]>) -> String {
        let out = render(&Suggestion::Rule {
            perm: b"execute".to_vec(),
            exe: exe.map(<[u8]>::to_vec),
            path: b"/tmp/gaps/trusted-ls".to_vec(),
        });
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn a_rule_names_the_exe_when_the_record_supplied_one() {
        assert_eq!(
            rule(Some(b"/usr/bin/bash")),
            "allow perm=execute exe=/usr/bin/bash : path=/tmp/gaps/trusted-ls\n"
        );
    }

    #[test]
    fn a_rule_without_an_exe_constrains_only_the_object() {
        assert_eq!(
            rule(None),
            "allow perm=execute all : path=/tmp/gaps/trusted-ls\n"
        );
    }

    #[test]
    fn rule_values_are_never_quoted_or_escaped() {
        // A rule has no quoting mechanism, so there is nothing to apply. `policy`
        // already refused the bytes that would break the line.
        let out = render(&Suggestion::Rule {
            perm: b"open".to_vec(),
            exe: Some(br"/tmp/quote'back\slash".to_vec()),
            path: b"/tmp/x".to_vec(),
        });
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "allow perm=open exe=/tmp/quote'back\\slash : path=/tmp/x\n"
        );
    }

    #[test]
    fn every_rendered_rule_ends_in_exactly_one_newline() {
        for text in [rule(Some(b"/usr/bin/bash")), rule(None)] {
            assert!(text.ends_with('\n'));
            assert!(!text.trim_end_matches('\n').contains('\n'));
            assert_eq!(text.matches('\n').count(), 1);
        }
    }

    #[test]
    fn neither_side_of_a_rule_reaches_the_eight_attribute_cap() {
        // Past 8 attributes a side is silently truncated and the rule loads broader
        // than written (§8.1). The shape guarantees 1 or 2 per side; assert it.
        for text in [rule(Some(b"/usr/bin/bash")), rule(None)] {
            let line = text.trim_end_matches('\n');
            let (subject, object) = line.split_once(" : ").unwrap();
            let attrs = |side: &str| side.split(' ').filter(|t| t.contains('=')).count();
            assert!(attrs(subject) <= 8, "{subject}");
            assert!(attrs(object) <= 8, "{object}");
        }
    }
}
