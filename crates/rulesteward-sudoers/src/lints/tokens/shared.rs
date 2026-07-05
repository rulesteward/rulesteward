//! Helpers shared by 2+ of the `tokens` per-position lint passes (#433 split
//! from a single `tokens.rs` file into this directory module; see `super`
//! for the module overview).

/// The five printable-ASCII chars a sudoers group/runas name may not contain,
/// grounded via the exhaustive `visudo -cf` probe documented above in the
/// Case-4 doc comment: `! ( ) > "`. Shared by the subject-position sub-case
/// (b) check in `check_user_spec` and the #375 runas-position check
/// (`check_runas`) below.
pub(super) fn is_denylist_char(c: char) -> bool {
    matches!(c, '!' | '(' | ')' | '>' | '"')
}

/// #375 Rule 3 predicate: `true` when `name` (the part after a `%` prefix) is a
/// `#`-prefixed group name that is NOT a pure-digit GID run and is therefore
/// visudo-rejected -- i.e. a digit run followed by non-digit char(s)
/// (`#1000abc`) or no digits at all after the `#` (`#abc`). The valid pure-GID
/// form (`#1000`) and the empty `#` (`""` after strip -- `all` is vacuously
/// true) both return `false`, preserving the pure-GID exemption. A name that
/// does NOT start with `#` (`1000abc`, `wheel`) returns `false` (it is an
/// ordinary group name). Shared by `check_group_subject`, both `check_runas`
/// token loops (runas-user and runas-group), and the `check_defaults` scope
/// targets (User/Runas/Host) so all `#`-GID validations stay consistent.
pub(super) fn is_malformed_gid_tail(name: &str) -> bool {
    name.strip_prefix('#')
        .is_some_and(|rest| !rest.bytes().all(|b| b.is_ascii_digit()))
}

/// Return `true` when `s` contains a `#<digits>` token that the
/// `strip_inline_comment` stage preserved as a UID/GID reference and that is
/// invalid in a command or Defaults-value context.
///
/// By the time a string reaches this function, `strip_inline_comment` has already
/// removed any `#` that is a genuine inline comment. The only surviving `#` followed
/// by digits are ones preceded by start-of-string or whitespace -- the positions
/// that produce invalid UID-like tokens in command / Defaults-value context.
///
/// # Which preceding chars are (and are NOT) checked here
///
/// A surviving `#<digits>` is only a UID/GID token -- and thus visudo-invalid in a
/// command / Defaults-value context -- when it is preceded by start-of-string,
/// whitespace, or `%`. Those three are checked:
///
/// - **start-of-string / whitespace**: `/bin/ls #2`, a bare `#2` command.
/// - **`%`**: `%#<digits>` glued in a command arg or a Defaults value, e.g.
///   `/bin/prog %#2` or `Defaults passprompt=x%#2`. The byte immediately before the
///   `#` is `%` (NOT whitespace), so the whitespace arm cannot reach it -- the `%`
///   arm is required. Grounded: both forms are visudo-rejected (rc=1, rockylinux:9,
///   sudo 1.9.17p2, 2026-06-30). (Round-2 wrongly dropped this arm on the claim the
///   whitespace arm covered it; it does not -- restored in round-3.)
///
/// The `,` preceding char is deliberately NOT checked, but -- unlike the other
/// three arms -- this is no longer because it is unreachable. Before #405,
/// `parse_default_settings` split on a naive `s.split(',')`, so no literal `,`
/// could ever survive into a produced setting name/value (every `,`, escaped or
/// not, was consumed as a separator); the claim held for `split_cmnd_specs`
/// (#370) too, for the same reason at the time it was written.
///
/// #405 made `parse_default_settings` escape/quote-aware (grounded via
/// visudo/cvtsudoers 1.9.17p2, 2026-07-03), so a literal `,` CAN now survive
/// into a value in two ways, and they are NOT distinguishable from the final
/// string alone:
///
/// - **Quoted** (`Defaults badpass_message="Wrong\,#5"`): visudo ACCEPTS this
///   (rc=0). `has_hash_digits` is itself quote-BLIND, so a `#<digits>` preceded
///   by whitespace/start/`%` INSIDE a quoted value WOULD fire here -- e.g.
///   `Defaults passprompt="Enter #5 now"` is visudo rc=0 (VALID) yet the stored
///   value `Enter #5 now` is byte-identical to the rejected unquoted form. #423
///   fixed that false positive at the CALLER, not here: `parse_one_default_setting`
///   now records `DefaultSetting::value_double_quoted` when the value is ONE
///   clean double-quoted region (an opening `"` whose first UNESCAPED closing
///   `"` is the final byte -- so `"a" #5 "b"`, an unquoted `#5` between two
///   regions, is NOT clean and still fires), and `check_defaults` skips the
///   value scan for such fully-quoted values before ever calling
///   `has_hash_digits`. So a clean double-quoted Defaults value never reaches
///   this function; this predicate stays a pure byte scanner (it is also used on
///   command tokens and setting names, which are never quote-stripped).
/// - **Unquoted, escaped** (`Defaults badpass_message=Wrong\,#5`, no quotes):
///   visudo REJECTS this (rc=1, "Success" quirk position, matching Case 2's
///   note above). SHOULD be flagged, but currently is not -- again because the
///   `,` predecessor is the unchecked arm, not because of any quoting logic.
///
/// Per the #370 precedent, `parse_default_settings` keeps a value VERBATIM (no
/// unescaping), so both cases above store the IDENTICAL value string
/// `"Wrong\,#5"` (backslash retained either way). The #423 `value_double_quoted`
/// flag distinguishes the quoted case at the CALLER (`check_defaults` skips the
/// value scan for the clean-quoted form), but it does NOT help THIS `,`-glued
/// escaped-comma pair: the flag is caller-side, whereas a `,`-preceding check
/// inside this byte scanner still cannot tell the accept case from the reject
/// case (both land on the same VERBATIM string). So the `,` arm stays a known,
/// narrow gap: a bare `,` immediately -- no whitespace -- before `#<digits>` in
/// an UNQUOTED, backslash-escaped Defaults value is visudo-rejected but not
/// flagged. Left unchecked here rather than guessing. Two regression tests in
/// the module below pin the current no-flag for the `,`-glued `#<digits>` case:
/// `f02_does_not_flag_hash_after_comma_in_a_quoted_defaults_value` (quoted --
/// now double-protected: the caller gate AND the dead `,` arm) and
/// `f02_known_gap_does_not_flag_hash_after_escaped_comma_in_unquoted_defaults_value`
/// (unquoted -- the dead `,` arm only); a future fix of the `,` gap trips the
/// unquoted one if it regresses.
pub(super) fn has_hash_digits(s: &str) -> bool {
    let bytes = s.as_bytes();
    for i in 0..bytes.len() {
        if bytes[i] == b'#' && bytes.get(i + 1).is_some_and(u8::is_ascii_digit) {
            let prev_ok = match i.checked_sub(1) {
                None => true, // `#` at position 0
                Some(j) => {
                    let p = bytes[j];
                    // whitespace-preceded (`/bin/ls #2`) OR `%`-preceded (`%#2`);
                    // `,` is not checked (dead -- see the doc comment).
                    // `char::is_whitespace` (NOT `is_ascii_whitespace`) is
                    // deliberate, mirroring `parser.rs`'s `prev_allows_uid`: a
                    // `#<digits>` after a whitespace byte that ASCII checks miss
                    // (0x0B / 0x85 / 0xA0) is still a visudo-rejected token, so
                    // narrowing to ASCII here would be a false-negative regression
                    // (#426 review).
                    p == b'%' || (p as char).is_whitespace()
                }
            };
            if prev_ok {
                return true;
            }
        }
    }
    false
}
