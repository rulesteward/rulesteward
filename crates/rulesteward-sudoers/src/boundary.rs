//! Boundary location: where a structural separator, a quoted span, or a token
//! boundary actually IS in one line of `sudoers(5)` text.
//!
//! # Why this module exists
//!
//! Every function here was previously a private helper in `parser.rs`, sitting
//! among ~20 other hand-rolled scanners that each re-derived their own
//! quote/escape/paren state. That arrangement is the direct cause of a defect
//! class this project has fixed one call site at a time since 2026-07-03
//! (#406, #405, #407, #423, then #622, #629, #630, #631, #643, then #651), and
//! `parser.rs` says so in its own voice: "Recognizers of one concept
//! disagreeing is the recurring shape on this surface."
//!
//! Giving them ONE home is the point. Nothing here is new logic - each function
//! is the grounded version that already existed, moved verbatim - so a
//! behaviour change in this module is a bug, not a feature.
//!
//! # THE TWO ESCAPE RULES
//!
//! This is the single most important thing to know before touching anything
//! here, and getting it wrong is a shipped fail-open rather than a style
//! problem. `sudoers` has TWO backslash rules, they apply in DIFFERENT places,
//! and BOTH are correct:
//!
//! - **Separator-finding**, the rule OUTSIDE a quoted span: a `\` consumes
//!   exactly the next character, so an escaped separator is a literal token
//!   byte and PARITY matters. Grounded on
//!   `a\=b ALL = NOPASSWD: /bin/ls` -> rc 0 with `User_List ["a=b"]`.
//!   Implemented by the `escaped` state machines in [`structural_eq`] and
//!   [`unquoted_whitespace_runs`].
//! - **Quote-finding**, the rule INSIDE a quoted span: a `\` escapes ONLY a
//!   `"`, regardless of its own parity, and a `\` before anything else
//!   (including another `\`) is a literal byte that consumes nothing.
//!   Grounded on `alice "h\\1" = ALL` -> rc 0 with hostname `h\\1`, BOTH
//!   backslashes kept, and `alice "h\\" = ALL` -> rc 1 because that `"` does
//!   not close. Implemented by [`quote_is_escaped`] and [`find_closing_quote`].
//!
//! Applying one rule in the other's context is not hypothetical: it is #676,
//! where [`quote_is_escaped`] (the inside-a-span rule) is used at an OPENER,
//! where the separator rule belongs. "Wrong rule, right function, wrong
//! context" is the failure mode this module's shape has to make hard to spell,
//! which is why the two are named separately here rather than collapsed into a
//! single `is_escaped`.
//!
//! A third rule exists next door and is NOT here: `rulesteward_core::comment`'s
//! `EscapeRule`, which decides whether a `#` starts a comment (#649). It
//! carries both of the rules above, in their proper contexts, for the
//! comment-marker question specifically.

/// The trimmed text of `s` between `tok_start` and the boundary char at `i` - the
/// token candidate [`split_top_level_segments`] tests against the `Tag_Spec` and
/// `Option_Spec` keyword sets.
///
/// `tok_start` is CLAMPED to `i`. It can legitimately overshoot: an `Option_Spec`
/// whose value runs to the end of the string (`TIMEOUT=30:x`, no whitespace after
/// the `=`) pushes `tok_start` to `s.len()`, and a boundary char INSIDE that value
/// is then at a lower index. The clamp yields `""`, which is the right reading -
/// the boundary sits inside a token, not after a complete one - and `""` matches
/// neither keyword set.
pub(crate) fn preceding_token(s: &str, tok_start: usize, i: usize) -> &str {
    s[tok_start.min(i)..i].trim()
}

/// Byte positions of every UNESCAPED `"` in `s`, per [`quote_is_escaped`]: a
/// `"` is escaped exactly when a backslash immediately precedes it.
///
/// # This file has TWO escape rules, and both are correct
///
/// They apply to different contexts, so a comment naming one must say which
/// (several used to say "the" escape model and were wrong by omission):
///
/// - **Quote-finding** ([`quote_is_escaped`], used here and by
///   [`find_closing_quote`]): a `\` escapes ONLY a `"`. A `\` before anything
///   else, including another `\`, is a literal byte that consumes nothing.
///   Grounded on `alice "h\\1" = ALL` -> rc 0 with hostname `h\\1`, BOTH
///   backslashes kept, and `alice "h\\" = ALL` -> rc 1 because that `"` does
///   not close. This is the rule INSIDE a quoted string.
/// - **Separator-finding** (the `escaped` state machines in
///   [`split_top_level_segments`], [`split_cmnd_specs`], [`structural_eq`],
///   [`unquoted_whitespace_runs`]): a `\` consumes exactly the next char, so an
///   escaped separator is a literal token byte. Grounded on
///   `a\=b ALL = NOPASSWD: /bin/ls` -> rc 0 with `User_List ['a=b']` (frozen as
///   the third case of `principal_containing_eq_still_reports_its_nopasswd_grant`).
///   This is the rule OUTSIDE a quoted string, where sudoers lets any special
///   character be backslash-escaped.
///
/// Changing [`quote_is_escaped`] therefore propagates to quote-finding only; it
/// does NOT reach those state machines, and it should not.
///
/// # Call graph
///
/// The single quote-SCANNING primitive: its ONLY direct caller is
/// [`simple_quote_pairs`], which feeds [`unquoted_whitespace_runs`] and
/// [`split_user_list`]. The splitters' `:` and `,` guards do NOT reach this
/// function at all, directly or indirectly - they consume spans from
/// [`quoted_value_span`] / [`find_closing_quote`], which locate quotes by their
/// own scan and share only the RULE above. (Two earlier revisions of this
/// comment claimed a call path that has never existed.)
pub(crate) fn unescaped_quote_positions(s: &str) -> Vec<usize> {
    s.char_indices()
        .filter(|&(i, c)| c == '"' && !quote_is_escaped(s, i))
        .map(|(i, _)| i)
        .collect()
}

/// Whether byte index `i` sits strictly inside one of `spans` -- a set of
/// pre-computed `(open, close)` quote-pair byte ranges. THREE DIFFERENT
/// producers feed this, per caller (#538 gap A/B/C - "quote handling
/// must be TOKEN-SCOPED, and a quote only quotes when it ENCLOSES the token it
/// starts"):
///   * `Option_Spec` VALUE spans, recorded by [`split_top_level_segments`]'s
///     and [`split_cmnd_specs`]'s own `'='` arms -- each records a span ONLY
///     when ITS OWN `preceding_token`/`tok_start` check (the same one that
///     decides whether the current `=` is a genuine `Option_Spec` anchor at
///     all - #538/9m; see [`quoted_value_span`]) recognizes that `=` as the
///     option's own, not just any `=` and not necessarily glued to it. Consumed
///     by the `:` and `,` arms, where a bare COMMAND quote must never mask a
///     real separator.
///   * PRINCIPAL spans, recorded by [`split_top_level_segments`]'s `'"'` arm
///     and independently by [`structural_eq`], both via [`opens_principal`].
///     These DO deliberately mask a separator: a `User_List`/`Host_List`
///     principal may be quoted precisely to carry an `=` or a `:` of its own
///     (`alice "h:1" = NOPASSWD: ALL` is rc 0 with `Host_List ["h:1"]`), so
///     [`split_top_level_segments`]'s `':'` arm consults both this and the
///     option-value one above. The distinction from a command quote is WHERE it
///     may open, not what it does once open.
///   * RUNAS spans, recorded by [`split_top_level_segments`]'s and
///     [`split_cmnd_specs`]'s `'"' if depth > 0` arms, also via
///     [`opens_principal`]. A quoted RUNAS principal is legal
///     (`alice ALL = (root,"a)b") ...` is rc 0 with `runasusers ["root", "a)b"]`),
///     so its bytes are literal too -- including a `)`, which no `depth` test can
///     distinguish from the group's real closer. `split_top_level_segments`'s
///     `'='` arm consults this AND the principal registry above; its `','` and
///     `')'` arms consult this one.
///   * [`simple_quote_pairs`] -- ANY unescaped quote may open, with no
///     token-scoping at all (used by [`unquoted_whitespace_runs`] and
///     [`split_user_list`], which are already operating inside a region known
///     to hold nothing but principals).
///
/// Either way, an UNMATCHED trailing `"` opens no span at all: the frozen
/// `unterminated_quote_does_not_swallow_comma_separator` (on [`split_cmnd_specs`])
/// and `unterminated_quote_does_not_swallow_the_segment_colon` (on
/// [`split_top_level_segments`]) regressions already pin that a lone,
/// never-closed quote must not suppress a real separator, so only a
/// properly-CLOSED pair may mask one.
pub(crate) fn inside_a_clean_quoted_region(spans: &[(usize, usize)], i: usize) -> bool {
    spans.iter().any(|&(open, close)| open < i && i < close)
}

/// Adjacent PAIRS of [`unescaped_quote_positions`], with NO notion of which
/// token each quote belongs to: quote 1 pairs with quote 2, quote 3 with quote
/// 4, and so on (`chunks_exact(2)`, silently dropping a trailing unmatched
/// quote). Correct only where ANY quote may legitimately open a span
/// regardless of what precedes it -- a `User_List`/`Host_List` principal may be
/// quoted anywhere (`man 5 sudoers`, rendered page lines 399-402), so
/// [`unquoted_whitespace_runs`] and [`split_user_list`]'s glued-quote boundary
/// check both use this. Contrast [`quoted_value_span`], whose callers restrict
/// an opener to immediately after an `Option_Spec`'s OWN `=` -- a bare
/// command or host-group's own quote has NO such unrestricted pairing power
/// (#538 gap A/C).
pub(crate) fn simple_quote_pairs(s: &str) -> Vec<(usize, usize)> {
    unescaped_quote_positions(s)
        .chunks_exact(2)
        .map(|pair| (pair[0], pair[1]))
        .collect()
}

/// Byte index of the first STRUCTURAL `=` in `s` -- the first one that is
/// neither backslash-escaped nor inside a quoted principal -- or `None`.
///
/// This is the `User_List Host_List = Cmnd_Spec_List` boundary in a user-spec
/// segment and the `NAME = members` boundary in an alias segment. A bare
/// `s.find('=')` finds the first `=` BYTE, which is a different thing whenever
/// a principal contains one, and every such disagreement is a misparse of a
/// line real sudo accepts. Probes on sudo 1.9.17p2 (2026-08-02), all rc 0:
///
/// - `"a=b" h1 = ALL` -> `User_List ["a=b"]`, `Host_List ["h1"]`
/// - `alice "h=1" = NOPASSWD: /bin/ls` -> `Host_List ["h=1"]`
/// - `a\=b ALL = NOPASSWD: /bin/ls` -> `User_List ["a=b"]` (escape, not quote)
///
/// Splitting those at the byte `=` puts the boundary inside the principal, so
/// the LHS loses its host list (a false `sudo-F01` FATAL on a valid line, #622)
/// or the RHS swallows it and the `NOPASSWD` grant stops being reported at all
/// (#630) -- one call site failing loud and the other silent, from one bug.
///
/// Spans are opened by [`opens_principal`] (alternate pairing) and an unmatched
/// quote opens nothing. [`split_top_level_segments`] applies the same predicate
/// during its own scan, so the two agree by construction; it additionally gates
/// on `!in_cmnd_list`, which this function does not need because it returns at
/// the FIRST unmasked `=` and so never scans past the principal region.
/// Escaping here uses BOTH of the file's two rules, in their proper places (see
/// [`unescaped_quote_positions`]): the scan below consumes a `\`-escaped char
/// whole, so `a\=b` keeps its `=` as a token byte and `\"` never reaches the
/// `'"'` arm as an opener; once a span opens, its CLOSING quote is located by
/// [`find_closing_quote`], where a `\` escapes only a `"`.
///
/// NOT needed at the other two `=` scans in this file, both re-probed
/// 2026-08-02 and left on `find('=')` deliberately:
/// [`parse_one_default_setting`], because a `Defaults` NAME cannot contain an
/// `=` in any form (`Defaults "a=b"` and `Defaults a\=b` are both rc 1), and
/// [`split_leading_option`], because an `Option_Spec` keyword cannot be quoted
/// (`alice ALL = "CWD"=/a /bin/ls` is rc 1) and a command's own `=` fails that
/// function's exact keyword match anyway.
pub(crate) fn structural_eq(s: &str) -> Option<usize> {
    let mut principal_quotes: Vec<(usize, usize)> = Vec::new();
    let mut escaped = false;
    for (i, c) in s.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match c {
            '\\' => escaped = true,
            '"' if opens_principal(&principal_quotes, i) => {
                if let Some(close) = find_closing_quote(s, i + 1) {
                    principal_quotes.push((i, close));
                }
            }
            '=' if !inside_a_clean_quoted_region(&principal_quotes, i) => return Some(i),
            _ => {}
        }
    }
    None
}

/// Whether the `"` at byte index `i` OPENS a principal span, given the spans
/// already opened before it: it does unless it lies within one, where `within`
/// INCLUDES that span's own closing quote (`i <= close`).
///
/// This is real sudo's ALTERNATE PAIRING: quotes pair first-with-second,
/// third-with-fourth, and whitespace has nothing to do with it. Probes on sudo
/// 1.9.17p2 (2026-08-02), all rc 0. The first two carry a GLUED opener, which
/// is what refutes the positional rule this replaced; the third is a
/// comma-preceded opener that rule already accepted, kept only as a second
/// pairing case:
///
/// - `alice" h=1" = NOPASSWD: /bin/ls` -> `Host_List [" h=1"]`, `authenticate:
///   false`
/// - `alice"h=1" = NOPASSWD: ALL` -> `Host_List ["h=1"]`
/// - `alice,"b=c" ALL = NOPASSWD: /bin/ls` -> `User_List ["alice", "b=c"]`
///
/// The `i <= close` half is what makes this a PAIRING rule rather than a
/// blanket one, and it is load-bearing rather than defensive: treating every
/// `"` as an opener lets a span's own CLOSING quote start a second span that
/// then runs on and swallows the structural `=`. The compact witness is
/// `"a b" ALL=(ALL:ALL)CHROOT="/a)CWD=" NOPASSWD: /bin/ls`, frozen as
/// `quoted_user_with_a_space_plus_a_chroot_value_holding_a_paren_and_a_keyword`;
/// run that test against a `-> true` mutant of this function to see it fail.
/// An UNMATCHED quote still opens nothing that closes, so it protects nothing
/// and `%bad"group ALL = ALL` stays rejected, matching every other quote rule
/// in this file.
///
/// This REPLACES a positional predicate that asked whether the `"` followed
/// whitespace / `,` / `:`. That rule was refuted twice over: by live probe
/// above, and by this crate's own frozen
/// `a_quote_right_after_a_bare_word_starts_a_new_principal_token_with_no_whitespace_needed`,
/// whose recorded ground truth reads "a `\"` always opens a NEW token, whether
/// or not whitespace precedes it". It shipped green because no test combined a
/// GLUED opener with an `=` INSIDE the quotes -- each half was covered, the
/// intersection was not.
///
/// The escape case never reaches here: ALL FOUR call sites consume a
/// `\`-escaped char before matching, so a `\"` is never offered as an opener.
/// They are `split_top_level_segments`'s two `'"'` arms (principal and runas),
/// `structural_eq`'s, and `split_cmnd_specs`'s.
pub(crate) fn opens_principal(spans: &[(usize, usize)], i: usize) -> bool {
    // All FOUR call sites scan forward and push a span only AFTER deciding to
    // open it,
    // so every recorded span starts strictly before the cursor. Stated as an
    // assertion rather than a comment because it is what makes the `open < i`
    // -> `open <= i` mutant EQUIVALENT (the two differ only at `open == i`,
    // which this forbids). A refactor that batches spans, rescans, or reuses
    // this predicate outside a forward scan breaks that equivalence, and should
    // fail here rather than silently make the mutation gate's ruling stale.
    debug_assert!(
        spans.iter().all(|&(open, _)| open < i),
        "opens_principal: span starting at or after the cursor {i}; spans={spans:?}"
    );
    !spans.iter().any(|&(open, close)| open < i && i <= close)
}

/// If `s`'s byte at `value_start` is an unescaped `"`, and a later unescaped
/// `"` closes it, the `(open, close)` byte-index pair of that `Option_Spec`
/// value-ENCLOSING span -- otherwise `None`. `value_start` must already be
/// the value's TRUE first byte (any whitespace between an `Option_Spec`'s `=`
/// and its value already skipped by the caller, via
/// [`skip_value_leading_whitespace`]); see [`option_value_end`]'s doc comment
/// for the fuller grounding this mirrors (there is no `man 5 sudoers`
/// passage documenting `Option_Spec` value quoting at all - this behavior is
/// grounded ONLY by live `visudo -c -f -` / `cvtsudoers -f json` probes,
/// sudo 1.9.17p2, 2026-07-31): a `"` opens a span ONLY at `value_start`
/// itself, and only the FIRST unescaped `"` after that closes it.
///
/// Shared by [`split_top_level_segments`]'s and [`split_cmnd_specs`]'s own
/// `'='` arms (#538 gaps A/C): each already knows, from
/// its own `tok_start`-anchored `preceding_token` check, exactly when the
/// CURRENT `=` is a genuine `Option_Spec`'s own -- never a command
/// argument's merely keyword-spelled `=` (`/bin/echo CWD="..."`, where the
/// preceding token since the last boundary is `"/bin/echo CWD"`, not `CWD`)
/// -- so calling this at that SAME position-anchored point is what keeps the
/// opener itself position-aware. The predecessor of this function,
/// `is_option_value_quote_opener`, instead re-derived "the word before the
/// `=`" from scratch over the WHOLE prefix `s[..open]` with no token-boundary
/// context at all, so it disagreed with the `'='` arm's own check and let a
/// command argument merely SPELLED like a keyword gain the same
/// quote-pairing power as a genuine leading `Option_Spec`, masking a `,` or
/// `:` inside that argument's own quotes and silently hiding a `NOPASSWD`
/// grant or a `Cmnd_Alias` definition.
pub(crate) fn quoted_value_span(s: &str, value_start: usize) -> Option<(usize, usize)> {
    if s.as_bytes().get(value_start) == Some(&b'"') {
        find_closing_quote(s, value_start + 1).map(|close| (value_start, close))
    } else {
        None
    }
}

/// The end (exclusive byte index, absolute within `s`) of an `Option_Spec`
/// value starting at `start`: the byte just PAST the closing quote when the
/// value is enclosed in double quotes, or (otherwise) the first
/// backslash-escape-aware unquoted whitespace -- or `s.len()` if neither is
/// found.
///
/// A quoted value ends AT its closing quote, with the next token starting
/// immediately, whitespace or not. That is not an inference from the grammar;
/// it is what the real parser does (probes on sudo 1.9.17p2, 2026-08-02):
/// `alice ALL = CWD="/a"NOPASSWD: /usr/bin/env FOO=/bin/ls` is rc 0 and yields
/// BOTH `runcwd=/a` and `authenticate=false`, so the glued `NOPASSWD` is a
/// real tag; `alice ALL = CWD="/a"/bin/su` is rc 0 with command `/bin/su`; and
/// `alice ALL = CWD="/a:b"c NOPASSWD: /bin/su` is rc 1 precisely BECAUSE the
/// glued `c` starts a fresh token that is neither a tag nor a command.
///
/// This function once scanned ON from the closing quote to the next unquoted
/// whitespace, which made a glued tag part of the VALUE and silently dropped
/// the `NOPASSWD` above with no diagnostic -- a fail-open on the exact
/// construct this parser exists to report (#631). It also put this function in
/// direct disagreement with [`quoted_value_span`], which computes the SAME
/// value's span and always stopped at the closing quote; the two are now
/// consistent by construction, which is what lets the `quotes` registry both
/// splitters build be trusted as the single boundary substrate.
///
/// `start` MUST already be the value's true first byte - i.e. any whitespace
/// separating the `Option_Spec`'s `=` from its value has already been skipped
/// by the caller ([`skip_value_leading_whitespace`]; #538). A `start` still
/// pointing at that whitespace makes the quoted-value check below fail (a
/// space is never `"`) and `unquoted_value_end` return `start` itself
/// unchanged (its very first char IS the boundary) - an EMPTY value that
/// desyncs every caller.
///
/// There is NO passage in `man 5 sudoers` documenting `Option_Spec` value
/// quoting (same grounding gap [`quoted_value_span`]'s doc comment covers). A
/// quote once cited here for it - "may be enclosed in
/// double quotes ... \[or\] specified in escaped hex mode" - is verbatim the
/// Aliases section's PRINCIPAL-quoting sentence (a user/group/netgroup name,
/// not an `Option_Spec` value); it does not apply here. The behavior below is
/// grounded ONLY by live `visudo -c -f -` / `cvtsudoers -f json` probes: the
/// shipping parser treats a value's special characters as EITHER enclosed in
/// a matching double-quote pair OR individually backslash-escaped
/// (`CWD=/tmp/a\ b`) for the purpose of finding the value's end; the raw text
/// (quotes and backslashes included) is kept verbatim, never decoded - see
/// [`CmndOption`]. "Enclosed" means at BOTH ends: a `"` only opens a quoted
/// span when it is `start`'s own first byte, and only the FIRST unescaped
/// `"` after that closes it (#538 gap A/C). A `"` anywhere else in the value
/// is a literal byte with NO toggling power -- the value `/a"b` never
/// re-enters a quoted state, so a following tag or command is never
/// swallowed
/// (`interior_quote_in_an_option_value_does_not_swallow_a_following_tag_and_command`).
/// An OPENING quote with no matching close is likewise not an enclosing pair
/// (mirrors [`inside_a_clean_quoted_region`]'s "unmatched quote protects
/// nothing" rule) and falls through to the same literal-byte scan. Escaping
/// follows whichever of the file's two rules the context calls for (see
/// [`unescaped_quote_positions`]): the UNQUOTED scan below has a `\` consume
/// exactly the next byte, whitespace or not; locating the CLOSING quote of a
/// quoted value goes through [`find_closing_quote`], where a `\` escapes only a
/// `"`. So `alice ALL = CWD="/a\\" NOPASSWD: /bin/ls` is visudo rc 1 - that
/// quote does not close the value - and this function does not close it either.
/// Shared by
/// [`split_leading_option`] (the value's own scan) and
/// [`split_top_level_segments`]'s `=` arm, which needs the SAME end point so
/// its preceding-token marker lands past the whole value rather than inside it
/// (#538 gap A/C).
pub(crate) fn option_value_end(s: &str, start: usize) -> usize {
    if s.as_bytes().get(start) == Some(&b'"')
        && let Some(close) = find_closing_quote(s, start + 1)
    {
        return close + 1;
    }
    unquoted_value_end(s, start)
}

/// The byte index of the first UNESCAPED `"` at or after `start` (the single
/// sudoers backslash-escape model, matching [`unescaped_quote_positions`]), or
/// `None` if `s[start..]` contains no such quote.
pub(crate) fn find_closing_quote(s: &str, start: usize) -> Option<usize> {
    s[start..]
        .char_indices()
        .map(|(i, c)| (start + i, c))
        .find(|&(abs, c)| c == '"' && !quote_is_escaped(s, abs))
        .map(|(abs, _)| abs)
}

/// sudo's separator class, and the ONLY one: `toke.l` discards `[[:blank:]]+`
/// and nothing else.
///
/// Every other whitespace character - U+00A0 NBSP, but also the pure-ASCII
/// U+000B VT and U+000C FF - is an ordinary `WORD` byte to sudo and can appear
/// inside, or BE, a principal name. Grounded on `rs-oracle9` (sudo 1.9.17p2),
/// 2026-08-19: `alice<NBSP>h1 = ...` is rc **1** (one token, no host list)
/// while `"a"<NBSP> = NOPASSWD: ALL` is rc **0** with `Host_List` `[{"hostname":
/// "\u00a0"}]`, and `al<NBSP>ice h1 = ...` is rc 0 with the NBSP inside the
/// username.
///
/// This exists because the concept had SIX recognizers asking
/// `char::is_whitespace`, which is far wider, and #702 is what that cost: a
/// line real sudo ACCEPTS lost its `Host_List`, folded to `Malformed`, and per
/// #668 every W/E lint on it was suppressed - a passwordless-`ALL` grant
/// evaluated by nothing, reported by nothing.
///
/// The lane's four adversarial rounds each found one defect and all four were
/// this same shape: two recognizers of one lexical concept disagreeing.
/// #701 narrowed [`holds_a_principal`] to `' ' | '\t'` while
/// `split_user_list`'s entry trim stayed wide, and THAT disagreement was round
/// 4's regression - the trim ate the character that made a half a principal and
/// the postcondition then correctly rejected the half. Narrowing one recognizer
/// creates the next defect; this is the fix that does not.
///
/// Deliberately NOT applied to `unquoted_value_end`, which scans a `Defaults`
/// VALUE rather than a principal list, or to the `.trim()` calls in
/// `Defaults`/alias parsing. Those are a different grammar position and are
/// unprobed on this axis; widening the blame beyond what is grounded is how
/// #647's "indistinguishable readings" claim became false.
pub(crate) fn is_sudoers_blank(c: char) -> bool {
    matches!(c, ' ' | '\t')
}

/// `true` when a principal-list half contains something that could BE a
/// principal name: some character outside `{! , " blank}`, or a quoted span
/// with a non-empty interior.
///
/// [`split_user_list`](crate::parser) chooses a boundary and returns the two
/// halves; until #701 it never asked whether either half IS a principal list.
/// A half of nothing but negation sigils was accepted, so `alice!` parsed as
/// user `alice` / host `!`, the line became a well-formed `UserSpec`, and a
/// passwordless-`ALL` grant was reported off a file `visudo` REFUSES to load.
/// That is the worst outcome this tool has, and it is the postcondition the
/// three producer-level sigil fixes (#670, #672, #699) each left in place.
///
/// The discriminator is grounded and is NOT what the producers ask about: a
/// principal must FOLLOW the sigil. Escape parity and sigil count are both
/// irrelevant here. rs-oracle9, sudo 1.9.17p2, 2026-08-19: `alice!`, `alice!!`,
/// `alice !`, `a\!!` and `! h1` are all rc **1**, while `alice!h1`,
/// `alice!!h1`, `a\!!h1`, `!!alice ALL` and `alice,!bob h1` are all rc 0.
///
/// Blank is [`is_sudoers_blank`], which is sudo's `[[:blank:]]` and nothing
/// else. This predicate spelled `matches!(c, ' ' | '\t')` inline when #701
/// added it, while five other sites still asked `char::is_whitespace` or
/// `str::trim` - and THAT disagreement was the next round's regression, because
/// the wide trim ate the very character that made a half a principal and this
/// predicate then correctly rejected the remainder. #702 gave the concept one
/// recognizer and routed all six sites through it.
///
/// Widening it back is no longer an equivalent mutant, which is worth stating
/// because it WAS one for exactly one commit: swapping [`is_sudoers_blank`] for
/// `char::is_whitespace` now turns five tests RED, including both re-pinned
/// NBSP rows in `boundary_substrate.rs`.
///
/// It deliberately does NOT reject an empty QUOTED principal: `alice!"" = ...`
/// is rc 1 and `RuleSteward` is wrong on it too, but `""` holds a non-sigil
/// character so this predicate passes it through. That is #677, and folding it
/// in here risks the #669/#677 masking interaction this lane records as its
/// sharpest hazard.
pub(crate) fn holds_a_principal(s: &str) -> bool {
    // Any character that is not a sigil, a separator or a blank is a principal
    // byte on its own.
    if s.chars()
        .any(|c| !matches!(c, '!' | ',' | '"') && !is_sudoers_blank(c))
    {
        return true;
    }
    // Otherwise the half can still be a principal, and #704's own fix sketch got
    // this wrong: a quoted span with a NON-EMPTY interior is a legal name
    // whatever the interior contains. `alice " "` and `alice "!"` are `visudo`
    // rc 0; `alice ""` is rc 1. So the discriminator is the interior, not the
    // quote character - excluding `"` outright turns two accepted files into a
    // false `sudo-F01`, which is what the grounding probe caught before this was
    // written.
    simple_quote_pairs(s)
        .iter()
        .any(|&(open, close)| close > open + 1)
}

/// Whether the byte at `i` is consumed by a SEPARATOR-rule backslash escape:
/// the run of backslashes immediately before `i` has ODD length.
///
/// This is the counterpart to [`quote_is_escaped`], and the two are NOT
/// interchangeable - see this module's header. Use THIS one outside a quoted
/// span, where a `\` consumes exactly the next character and parity therefore
/// decides; use [`quote_is_escaped`] inside one, where a `\` escapes only a
/// `"` regardless of its own parity.
///
/// Grounded on sudo 1.9.17p2, 2026-08-19: `alice\!h1 = NOPASSWD: ALL` is
/// `visudo` **rc 1**, so an escaped `!` is not a principal boundary and the
/// existing `sudo-F01` on that line is CORRECT. A boundary scan that ignored
/// this would parse the line as `alice\` / `!h1` and silently drop a true
/// positive - the mirror image of the fail-opens this module exists to close,
/// and the reason this predicate was added rather than the `!` scan
/// hand-rolling its own.
///
/// # The COMMA call sites (#675), where parity is the whole point
///
/// Added 2026-08-19, and they are why the ODD-run wording above is load-bearing
/// rather than pedantic. A `\,` is a LITERAL comma inside ONE principal and does
/// not continue a `User_List`; an EVEN backslash run leaves the comma unescaped
/// and the list really does continue. All six rows re-derived on `rs-oracle9`
/// (sudo 1.9.17p2, 2026-08-19), stdin only:
///
/// | input | `visudo -c -f -` |
/// |---|---|
/// | `alice\, h1 = NOPASSWD: /bin/ls` | rc 0, `User_List ["alice,"]` / `Host_List ["h1"]` |
/// | `a\,"b" = NOPASSWD: ALL` | rc 0, `["a,"]` / `["b"]` |
/// | `a\,!h1 = NOPASSWD: ALL` | rc 0, `["a,"]` / `["h1"]` NEGATED |
/// | `a\\, b = NOPASSWD: ALL` | **rc 1** - even run, the comma separates |
/// | `a\\,"b" = NOPASSWD: ALL` | **rc 1** |
/// | `a\\,!h1 = NOPASSWD: ALL` | **rc 1** |
///
/// [`quote_is_escaped`] is a CATEGORY ERROR on a comma: it is
/// `s[..i].ends_with('\\')`, so it calls the comma in `a\\,` escaped, admits a
/// boundary on a line `visudo` rejects and converts a correct `sudo-F01` into
/// silence. That is the wrong-rule-in-the-wrong-context shape this module's
/// header names. The three rc-1 rows above are what pin the difference; each of
/// the rc-0 rows on its own is satisfied by a non-parity check.
pub(crate) fn separator_escaped(s: &str, i: usize) -> bool {
    s[..i].bytes().rev().take_while(|&b| b == b'\\').count() % 2 == 1
}

/// Whether the `"` at byte index `i` in `s` is escaped: it is exactly when the
/// byte immediately before it is a backslash.
///
/// Inside a sudoers double-quoted string a backslash escapes ONLY a `"`. A
/// backslash followed by anything else - INCLUDING another backslash - is a
/// literal byte that consumes nothing, so a `\` before a `"` always escapes it
/// no matter how many backslashes precede THAT one. Probes on sudo 1.9.17p2
/// (2026-08-02), stdin only:
///
/// - `alice "h\"1" = ALL`    -> rc 0, `Host_List ['h"1']`
/// - `alice "h\\1" = ALL`    -> rc 0, `Host_List ['h\\1']` (both kept, neither consumed)
/// - `alice "h\\" = ALL`     -> **rc 1** - that `"` does not close the string
/// - `alice "a\\"b" = ALL`   -> rc 0, `Host_List ['a\"b']` - the span runs past it
/// - `alice "a\\\\" = ALL`   -> **rc 1** - four backslashes, still escaped
///
/// This REPLACES a consume-the-next-char model ("a `\` consumes exactly the
/// next char, so `\\` is one literal backslash that leaves a following `"`
/// un-escaped"). The two agree on `\"` and disagree on every EVEN run of two or
/// more backslashes, where the old model closed the span a quote too early. It
/// was harmless while nothing grant-bearing depended on it and became a
/// fail-open the moment [`opens_principal`] did: an early close leaves the next
/// quote looking like a fresh opener, and the bogus span it opens covers the
/// structural `=`, so a line real sudo accepts is thrown away `Malformed` and
/// its `NOPASSWD` grant is never linted. Frozen as
/// `doubled_backslash_before_a_quote_does_not_close_the_principal_span`.
pub(crate) fn quote_is_escaped(s: &str, i: usize) -> bool {
    s[..i].ends_with('\\')
}

/// The end (exclusive byte index, absolute within `s`) of a run of value bytes
/// starting at `start` in which a `"` is ALWAYS a literal byte (never toggles
/// anything): the first backslash-escape-aware unquoted whitespace, or
/// `s.len()` if none. The escape-only half of [`option_value_end`]'s scan,
/// reached when `start` is not a `"` at all, AND when it is one whose closing
/// quote is missing -- [`option_value_end`]'s let-chain fails on the unmatched
/// case and falls through to here, matching the "an unmatched quote encloses
/// nothing" rule the rest of this file follows.
///
/// It once also scanned the literal tail after an enclosing pair's closing
/// quote. That second use is gone: a quoted value ends AT its closing quote and
/// the next token starts immediately, so [`option_value_end`] returns
/// `close + 1` directly (#631). Scanning on past the quote is what swallowed a
/// glued `NOPASSWD:` into the value.
pub(crate) fn unquoted_value_end(s: &str, start: usize) -> usize {
    let mut escaped = false;
    for (i, c) in s[start..].char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if c == '\\' {
            escaped = true;
            continue;
        }
        if c.is_whitespace() {
            return start + i;
        }
    }
    s.len()
}

/// Byte ranges `(start, end)` of whitespace RUNS in `s` that sit OUTSIDE a
/// genuinely CLOSED double-quoted span (see [`inside_a_clean_quoted_region`])
/// and are not themselves consumed by a backslash escape.
///
/// A whitespace byte inside a CLOSED quote pair is part of the token, not a
/// boundary; a `\` consumes exactly the next byte literally, whitespace or not
/// -- the SEPARATOR-finding rule of the two in [`unescaped_quote_positions`],
/// which is the right one here because this scan runs outside quoted spans
/// (the spans themselves come from [`simple_quote_pairs`], which uses the
/// quote-finding rule). Matches [`option_value_end`]'s unquoted half and the two
/// top-level splitters). Deliberately uses [`simple_quote_pairs`]'s PAIRED quote
/// detection rather than a live open/close toggle: an unrelated, unpaired `"` elsewhere in the same
/// pre-`=` text (e.g. a malformed `%bad"group` principal, `f02_group_name_with_dquote_fires`)
/// must not swallow every later whitespace boundary as "still inside quotes" -
/// the same "unterminated quote must not suppress a real boundary" rule the
/// two top-level splitters already enforce for `:` / `,`. Used by
/// [`split_user_list`] (#538 gap B) to find the real
/// `User_List`/`Host_List` boundary without splitting inside a quoted or
/// escaped principal.
pub(crate) fn unquoted_whitespace_runs(s: &str) -> Vec<(usize, usize)> {
    let quotes = simple_quote_pairs(s);
    let mut runs = Vec::new();
    let mut escaped = false;
    let mut run_start: Option<usize> = None;
    for (i, c) in s.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if c == '\\' {
            escaped = true;
            if let Some(start) = run_start.take() {
                runs.push((start, i));
            }
            continue;
        }
        if is_sudoers_blank(c) && !inside_a_clean_quoted_region(&quotes, i) {
            if run_start.is_none() {
                run_start = Some(i);
            }
        } else if let Some(start) = run_start.take() {
            runs.push((start, i));
        }
    }
    if let Some(start) = run_start.take() {
        runs.push((start, s.len()));
    }
    runs
}

/// If `value` is exactly ONE clean double-quoted string -- an opening `"`, an
/// interior with no UNESCAPED `"`, and a closing `"` as the final byte -- return
/// the interior with the surrounding quotes stripped. Otherwise return `None`
/// (the value is left verbatim by the caller).
///
/// "Unescaped" uses the sudoers single-backslash escape model (the same one
/// [`split_default_settings`] uses): a `\` escapes the next char, and `\\` is one
/// literal backslash that does NOT escape a following `"`. So the FIRST unescaped
/// `"` after the opening quote must be the LAST byte of the value; an unescaped
/// `"` before the end means a second quoted region or unquoted trailing content
/// follows -- e.g. `"a" #5 "b"` (the `#5` sits in an unquoted gap between two
/// regions) -- which is NOT one clean region.
///
/// Grounded via `visudo -c -f` 1.9.17p2 (2026-07-04): `"a" #5 "b"` rc=1 (two
/// regions), `"a\" #5 b"` rc=0 (escaped inner quote -> one region),
/// `"a\\" #5 "b"` rc=1, `"a\\\" #5 b"` rc=0.
///
/// CAVEAT on the third, re-checked 2026-08-02: the rc is right but the reason
/// once given here ("`\\` is a literal backslash, so the `"` closes the first
/// region") is not what visudo reports. Its caret lands on the `b`, i.e. the
/// string ran ON past that `"` and the bare `b` is the syntax error - the
/// QUOTE-FINDING rule of the two in [`unescaped_quote_positions`], not the
/// separator one this function implements. Both readings give rc 1 here, so no
/// probe in this set distinguishes them and this function's model is unpinned
/// on the `Defaults` surface. Left as-is deliberately rather than changed on an
/// unproven hunch; tracked separately.
pub(crate) fn clean_double_quoted_interior(value: &str) -> Option<&str> {
    let inner = value.strip_prefix('"')?;
    let mut escaped = false;
    for (i, c) in inner.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match c {
            '\\' => escaped = true,
            // First unescaped `"` in the interior: a clean single region only
            // when it is the closing quote at the very end (nothing follows).
            '"' => return (i + 1 == inner.len()).then_some(&inner[..i]),
            _ => {}
        }
    }
    // No unescaped closing `"` (unterminated) -> not a clean region.
    None
}

/// Byte index of the first `needle` in `s` that is neither SEPARATOR-escaped
/// nor inside a closed quoted span, or `None`.
///
/// The generalisation of what `split_top_level_segments` and `split_cmnd_specs`
/// already do inline for their `')'` arms, extracted so a THIRD `)`-locating
/// primitive does not have to re-derive it. `parse_cmnd_spec` used a bare
/// `after_open.find(')')` and was the odd one out (#650): it stopped at a
/// quoted `)` and truncated `"a)b"` to `"a`, or at an escaped one, dropping the
/// `NOPASSWD` grant that followed.
///
/// Uses the SEPARATOR-finding rule via [`separator_escaped`], because the
/// question is where a structural byte is OUTSIDE a quoted span. See this
/// module's header for why that is not [`quote_is_escaped`].
pub(crate) fn unquoted_unescaped(s: &str, needle: char) -> Option<usize> {
    let spans = simple_quote_pairs(s);
    s.char_indices()
        .find(|&(i, c)| {
            c == needle && !separator_escaped(s, i) && !inside_a_clean_quoted_region(&spans, i)
        })
        .map(|(i, _)| i)
}
