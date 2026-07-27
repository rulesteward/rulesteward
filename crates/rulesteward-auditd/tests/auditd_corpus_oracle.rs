//! Lane A (auditd) differential-oracle replay test (session 9k-1, #584/#601/#489/#491).
//!
//! Tier 1 of the two-tier contract in `CONTRIBUTING.md` "Differential oracle
//! contract": pure Rust, reads a COMMITTED corpus of RAW captured facts
//! (`rc`, `stdout`, `stderr`) for each `(target, rule-line)` pair and asserts
//! [`rulesteward_auditd::oracle::product_verdict`] agrees with
//! [`rulesteward_auditd::oracle::classify_capture`]'s recovered verdict for
//! the real daemon. No docker, no root, no network, no tool on PATH - so there
//! is no skip path at all. `just diff-auditd` (Tier 2, `scripts/rs-oracle-diff.sh`
//! -> `tests/corpus/auditd-oracle/capture_auditd.sh`) re-points this SAME
//! binary at a freshly captured corpus via `RS_ORACLE_CORPUS_AUDITD` to check
//! for drift.
//!
//! # AMENDMENT (session 9k-1, post-barrier): raw facts, not a precomputed verdict
//!
//! The first draft of this corpus stored a PRECOMPUTED "accept"/"reject"
//! column, written by a `grep -qF "Error sending add rule data request"` in
//! the capture script. That string only ever fires on the ADD-RULE path
//! (`-w`/`-a`), so every control-only line (`-D`, `-b`, ...) was silently
//! recorded as REJECT - including bare `-D`, the first line of essentially
//! every real `audit.rules` file. An adversarial review caught this at the
//! barrier before any implementation landed. The fix (owner-approved, full
//! remediation): **the capture script records raw facts; Rust classifies.**
//! [`classify_capture`] is the one place that decides "did the daemon accept
//! this?", and it lives under `cargo test`, `clippy`, the coverage floor and
//! the mutation gate - unlike the untested `grep -qF` it replaces.
//!
//! # Required product API (frozen by the test-author barrier)
//!
//! ```ignore
//! pub enum Verdict { Accept, Reject }
//! pub fn product_verdict(line: &str) -> Verdict; // delegates to parser::parse_rules_str
//!
//! pub enum CaptureVerdict { Accept, Reject { complaint: &'static str }, Unusable(Unusable) }
//! pub enum Unusable { NoCapability, Loaded, SilentNonAddLine, SandboxLimited,
//!                      UnrecognisedDiagnostic, UnexpectedRc }
//! pub fn classify_capture(line: &str, rc: i32, stdout: &str, stderr: &str) -> CaptureVerdict;
//! pub fn silence_is_conclusive(line: &str) -> bool;
//! ```
//!
//! `product_verdict` MUST delegate to [`rulesteward_auditd::parser::parse_rules_str`],
//! the exact entry point the CLI takes, and must NEVER `use rulesteward_auditd::ast`.
//! A differential whose product side reimplements the grammar is
//! self-referential: it proves the reimplementation agrees with the corpus
//! and says nothing about the parser an administrator actually runs. This is
//! the OPPOSITE requirement from the first draft of this file, which forbade
//! delegating to the "lenient" parser; that framing is exactly backwards and
//! was corrected at the barrier - see `rulesteward_auditd::oracle`'s module
//! doc.
//!
//! # Corpus format
//!
//! Flat TSV, one file per target (`el8.tsv` / `el9.tsv` / `el10.tsv`) under the
//! resolved corpus root. Each data row is EXACTLY 10 tab-separated fields
//! (`str::split('\t')`, arity asserted - never `splitn`, since every field is
//! escaped so no raw tab survives inside one):
//!
//! ```text
//! target  id  class  rc  rule_len  out_len  err_len  rule  stdout  stderr
//! ```
//!
//! `rule_len`/`out_len`/`err_len` are BYTE lengths measured inside the capture
//! container, before the value ever crosses the host's bash boundary (bash
//! cannot hold a NUL byte). [`unescape_field`] asserts `decoded.len() ==
//! recorded_len` for each of `rule`/`stdout`/`stderr`, which is what catches a
//! truncation, a dropped NUL, or an escaping bug with no external tool
//! needed. Escapes: `\\` -> `\`, `\t` -> TAB, `\n` -> LF, `\r` -> CR, `\xHH`
//! -> that byte, and the two-character sentinel `\0` meaning "this field is
//! the empty string" (never a bare empty string, so no column is silently
//! absent) - paired with `\x20` escaping a leading/trailing space, together
//! guaranteeing no field is empty-looking or starts/ends in whitespace (the
//! `.editorconfig` `trim_trailing_whitespace` hazard the first draft's
//! `mktemp` nondeterminism circled around). A `#`-prefixed header (5 lines)
//! precedes the data rows in every file; line 2 carries `target=... image=...
//! audit_version=<rpm -q audit output>` and line 3 carries `captured=<UTC
//! timestamp>` on ITS OWN line (moved off the `audit_version=` line in this
//! amendment: the timestamp is the ONLY thing that changes on every
//! recapture, and keeping it on a separate line means "every line except
//! `# captured=`" is the exact byte-identity check for "did this recapture
//! actually change anything").
//!
//! # Provenance
//!
//! See `tests/corpus/auditd-oracle/PROVENANCE.md` for image versions, capture
//! date, the safety invariant, the `UNOBSERVABLE`/`XFAIL` findings, and the
//! `MSG_SYSLOG`-under-`-R` finding that this amendment's regrounding surfaced.

use std::path::{Path, PathBuf};

use rulesteward_auditd::oracle::{
    CaptureVerdict, Unusable, Verdict, classify_capture, product_verdict,
};
use rulesteward_core::oracle_corpus::{resolve_corpus_root, sentinel_banner, sentinel_count};

/// Named floor: 76 scenario ids (74 after round-2 + 2 post-implementation
/// adversarial-review additions: `w-delete-watch`, `d-delete-syscall` - the
/// id count below is the ACTUAL captured count, verified against the corpus
/// this commit ships), each captured against el8/el9/el10 = 228 rows. Raise
/// this deliberately, in the same commit, when the corpus grows.
const FLOOR_ROWS: usize = 228;

/// Floor on the number of DISTINCT scenario ids (one per corpus target file).
const FLOOR_SCENARIO_IDS: usize = 76;

/// Floor on rows that actually reach the product-vs-oracle comparison, i.e.
/// every row EXCEPT the `Unusable` ones on the [`UNOBSERVABLE`] table (10
/// ids: 8 `SilentNonAddLine` + 2 `SandboxLimited`, x3 targets = 30 rows;
/// 76 - 10 = 66 comparable ids x3 = 198). This is the fourth member of the
/// "assert the count" family the first draft was missing: the
/// `all_rows.len()` floor alone would be satisfied by a corpus that is
/// entirely `Unusable` and compares nothing at all.
const FLOOR_COMPARED: usize = 198;

/// The three target files every capture (committed or fresh) must produce.
const EXPECTED_TARGETS: &[&str] = &["el8", "el9", "el10"];

/// The two-sided positive control ids (CONTRIBUTING.md rule 2): a rule the
/// real oracle must ACCEPT and one it must REJECT, each with non-silent
/// evidence. `control-reject`'s RULE changed in this amendment (see
/// `capture_auditd.sh`): the old `-F perm=zz` doubled as a product-divergence
/// row (`RuleSteward`'s parser does not validate `-F perm=` letter sets
/// either), which means a broken harness and a real XFAIL would have been
/// indistinguishable. `-F nosuchfield=1` is loud on the real oracle AND
/// rejected by `RuleSteward`'s own field-name table, so product and oracle
/// AGREE - this can never become an XFAIL.
const CONTROL_ACCEPT_ID: &str = "control-accept";
const CONTROL_REJECT_ID: &str = "control-reject";

/// Product/oracle divergences, named with their issue number and WHY the
/// divergence exists, keyed by scenario id alone (not `(target, id)`): every
/// id here is expected to diverge identically on el8/el9/el10 (no version
/// split has ever been observed in this corpus), so the per-id hit count is
/// asserted to be exactly 3 - one per EL major - by
/// [`assert_hit_exactly_three`]. A divergence that stops reproducing on some
/// target must fail the suite, not go quiet.
///
/// Every entry states whether it is a genuine blind spot (nothing downstream
/// catches it) or covered elsewhere; none of these 18 are caught by an
/// existing `au-E02`/`E04`/`E05` lint, because all three validate OPERATOR
/// legality (is `>=` allowed for this field's TYPE / this field on this
/// LIST), never VALUE content - none of today's divergences are an
/// operator-legality question.
const XFAIL: &[(&str, &str)] = &[
    // --- Quote stripping (deliberate leniency, parser.rs:277-287): the
    // parser strips a token's balanced leading+trailing SINGLE quote for
    // admin-UX reasons; real auditctl's `audit_strsplit` treats quotes as
    // literal bytes, so a quoted field spec glues the quote onto the field
    // name and is rejected. Genuine blind spot: once stripped, the field/op
    // pair is fully legal, so no lint downstream of a successful parse would
    // ever see the original quoted bytes.
    (
        "rocky9-arch-paired",
        "#584 quote-stripping: 'auid>=1000' parses after strip; real auditctl \
         rejects on the glued 'auid field name. Genuine blind spot (not an \
         operator-legality question au-E02 could see).",
    ),
    (
        "rocky9-execve-auid",
        "#584 quote-stripping, same mechanism as rocky9-arch-paired. Genuine \
         blind spot.",
    ),
    (
        "rocky9-field-compare",
        "#584 quote-stripping via -C 'uid!=euid' (the -C field-comparison \
         form, not -F). Genuine blind spot.",
    ),
    (
        "rocky9-never-suppress",
        "#584 quote-stripping via -F 'uid=0'. Genuine blind spot.",
    ),
    (
        "rocky9-priv-commands",
        "#584 quote-stripping via -F 'auid>=1000' -F 'auid!=unset'. Genuine \
         blind spot.",
    ),
    (
        "rocky9-task-list",
        "#584 quote-stripping on the 'filesystem'-adjacent 'task' list. \
         Genuine blind spot.",
    ),
    (
        "iss584-quoted-field-expr",
        "#584 quote-stripping, synthesized directly rather than found in an \
         existing scenario. Genuine blind spot.",
    ),
    // --- TAB tokenization (#584): `str::split_whitespace` treats a TAB the
    // same as a space; real `audit_strsplit` splits ONLY on the literal space
    // byte, so a TAB glues onto the adjacent token. The resulting line is a
    // fully ordinary, valid rule once collapsed - genuine blind spot, no
    // lint could see the original bytes.
    (
        "iss584-embedded-tab-glues-flag",
        "#584 TAB tokenization: a single embedded TAB collapses to a valid \
         rule under split_whitespace; real auditctl glues it onto the \
         adjacent token and rejects silently. Genuine blind spot.",
    ),
    (
        "iss584-all-tabs-separators",
        "#584 TAB tokenization, every separator on the line is a TAB. \
         Genuine blind spot.",
    ),
    // --- -k cap (#489): real auditctl caps the -k key value at
    // AUDIT_MAX_KEY_LEN (256 bytes, measured empirically in this corpus at
    // the 256/257-byte boundary); the parser enforces no length cap at all.
    // Genuine blind spot: no lint validates key length today.
    (
        "iss489-key-over-cap-257",
        "#489 no -k length cap enforced; the real 256-byte AUDIT_MAX_KEY_LEN \
         cap is exceeded by 1 byte. Genuine blind spot.",
    ),
    (
        "k-cap-invalid-shorter-line",
        "#489 same cap-enforcement gap as iss489-key-over-cap-257, paired \
         with k-cap-valid-longer-line as the anti-monotone-length \
         counterexample (this REJECT row's overall LINE is shorter than the \
         ACCEPT row's). Genuine blind spot.",
    ),
    // --- -F value typing (#491): the parser stores every -F value as an
    // unvalidated string; real auditctl requires pers/devminor (unlike
    // a0-a3) to be non-negative. Genuine blind spot: au-E02 validates
    // OPERATOR legality for a field's type, never the value's own numeric
    // range.
    (
        "iss491-neg-pers",
        "#491 -F pers=-1: real auditctl requires a non-negative value for \
         pers (unlike a0-a3's signed strtoll parse); the parser stores any \
         string. Genuine blind spot.",
    ),
    (
        "iss491-neg-devminor",
        "#491 -F devminor=-1, same non-negative requirement as pers. \
         Genuine blind spot.",
    ),
    // --- -F perm= letter validation (#601's other half): real auditctl
    // validates -F perm='s value against the letter set 'rwxa'; the parser
    // stores any string. This is the row the control-reject id used to
    // carry - moved off the control because a positive control must never
    // double as a divergence (see CONTROL_REJECT_ID's doc above).
    (
        "f-perm-invalid-letter",
        "#601 -F perm=zz: real auditctl rejects an invalid permission \
         letter set ('Permission can only contain 'rwxa''); the parser \
         performs no letter-set validation on -F perm= values (distinct \
         from the -p watch-flag validation in parse_perms, which DOES \
         reject invalid letters - see p-invalid-lower/p-invalid-upper \
         below, which are NOT XFAILs). Genuine blind spot.",
    ),
    // --- Unknown syscall name (new finding, beyond this lane's original
    // 16-id estimate): the parser accepts ANY string as a -S syscall name
    // with no table lookup; real auditctl validates the name via
    // audit_name_to_syscall and rejects an unknown one (silently, under -R -
    // see PROVENANCE.md "MSG_SYSLOG under -R"). Genuine blind spot: no lint
    // validates syscall names today.
    (
        "s-unknown-syscall",
        "-S totallynotasyscall: the parser accepts any string as a syscall \
         name with no table validation; real auditctl rejects an unknown \
         name. Genuine blind spot, discovered by this corpus's expanded \
         grounding rather than predicted in advance.",
    ),
    // --- Product too STRICT (the other direction: real auditctl accepts,
    // the parser rejects). These are open parser gaps (#584/#601), not
    // "coverage" in the lint sense at all - there is no AST to lint because
    // the parser refuses the line outright.
    (
        "iss584-backslash-escaped-space",
        "#584, product too STRICT: real auditctl's preprocess() rewrites a \
         backslash-escaped space before tokenizing, accepting the line; the \
         parser's naive split_whitespace has no such preprocessing and \
         rejects on the stray trailing token. Open parser gap, tracked by \
         #584.",
    ),
    (
        "iss601-uppercase-perm-all",
        "#601, product too STRICT: real auditctl accepts uppercase \
         permission letters (WA); parse_perms only matches lowercase rwxa. \
         Open parser gap, tracked by #601.",
    ),
    (
        "iss601-uppercase-perm-mixed",
        "#601, product too STRICT: same gap as iss601-uppercase-perm-all, \
         mixed-case 'Wa'. Open parser gap, tracked by #601.",
    ),
    (
        "w-delete-watch",
        "#584, product too STRICT (post-implementation adversarial review, \
         MISS 1): -W (delete-form watch) reaches handle_request()'s \
         `del != AUDIT_FILTER_UNSET` branch, the IDENTICAL MSG_QUIET->send-> \
         MSG_STDERR sequence as the add path, printing 'Error sending \
         delete rule data request' on refusal - proof the line parsed. \
         RuleSteward's parser has no '-W' arm at all (parser.rs's parse_line \
         dispatch); it falls to the unknown-flag arm and rejects. Open \
         parser gap: the parser only ever models the ADD-shaped subset of \
         auditctl's grammar, never delete-form rules.",
    ),
    (
        "d-delete-syscall",
        "#584, product too STRICT: same gap as w-delete-watch, the \
         syscall-rule delete form (-d list,action, mirrors -a/-A). Open \
         parser gap.",
    ),
];

/// Rows whose real-oracle verdict is [`Unusable`] rather than Accept/Reject -
/// the capture cannot support any comparison for this id, and that is
/// recorded rather than hidden. Permitted ONLY for an id listed here, WITH
/// the declared [`Unusable`] KIND matching exactly (round-2 adversarial
/// review, blocker 4: a two-part guard of "id is listed" AND "kind is one of
/// the two allowed variants" - checked independently rather than as a pair -
/// would let `rocky9-filesystem-list` classify `SilentNonAddLine` instead of
/// its actual `SandboxLimited` mechanism and still pass, which defeats the
/// entire point of naming the mechanism per entry). Each entry is hit
/// EXACTLY 3 times (once per EL major, verified PER TARGET - see
/// `assert_hit_exactly_three`); any [`Unusable`] outside this table, any kind
/// mismatch, or an id here hit any other number of times, is an
/// `ORACLE-BROKEN` hard failure with no allowlist. Refusing to emit these
/// rows at all would destroy the artifact that proves each blind spot exists
/// and would hide a future `auditctl` change that starts diagnosing one of
/// them.
const UNOBSERVABLE: &[(&str, Unusable, &str)] = &[
    (
        "rocky9-huge-ruleset",
        Unusable::SilentNonAddLine,
        "bare -D. Its SUCCESS path (delete_all_rules) fails silently under \
         EPERM, so silence proves nothing.",
    ),
    (
        "rocky9-stock-control",
        Unusable::SilentNonAddLine,
        "bare -D, same as rocky9-huge-ruleset.",
    ),
    (
        "rocky10-rulesd-multifile",
        Unusable::SilentNonAddLine,
        "bare -D, same as rocky9-huge-ruleset.",
    ),
    (
        "rocky9-exclude-msgtype",
        Unusable::SilentNonAddLine,
        "bare -b 8192, same silent-success-path ambiguity as -D \
         (audit_set_backlog_limit's failure path in setopt() prints nothing).",
    ),
    (
        "lead-e-enable",
        Unusable::SilentNonAddLine,
        "-e 1 (round-2 addition): empirical confirmation of a second denylisted \
         flag beyond -D/-b, same silent-success-path shape \
         (audit_set_enabled's failure path in setopt() prints nothing).",
    ),
    (
        "d-extra-silent",
        Unusable::SilentNonAddLine,
        "-D extra. Originally planned as a LOUD confirmation of #541's \
         field-count reject (auditctl.c's case 'D' does call audit_msg() \
         unconditionally on a count mismatch) - but empirically SILENT under \
         `auditctl -R`: for a ONE-LINE -R invocation, case 'D's audit_msg() \
         fires inside setopt(), which runs BEFORE handle_request ever executes \
         and restores MSG_STDERR (auditctl.c:1552-1554) - so at that point in \
         the invocation the mode is still the MSG_SYSLOG main() set for -R \
         (argc==3 && argv[1]==\"-R\"). See PROVENANCE.md 'MSG_SYSLOG under -R' \
         for the corrected (non-generalized) statement of this mechanism.",
    ),
    (
        "d-k-only-silent",
        Unusable::SilentNonAddLine,
        "-D -k (no key value), same MSG_SYSLOG-before-handle_request timing as \
         d-extra-silent.",
    ),
    (
        "d-k-extra-silent",
        Unusable::SilentNonAddLine,
        "-D -k mykey extra, same MSG_SYSLOG-before-handle_request timing as \
         d-extra-silent.",
    ),
    (
        "rocky9-filesystem-list",
        Unusable::SandboxLimited,
        "real auditctl prints 'fstype filter is not supported by the kernel' \
         (EAU_FILTERNOSUPPORT, libaudit.c ~1624-1630 gating on \
         audit_get_features() & AUDIT_FEATURE_BITMAP_FILTER_FS, errormsg.h:113 \
         for the message text), identical byte-for-byte across all three EL \
         majors (3.1.2/3.1.5/4.0.3) despite them being different compiled \
         binaries - consistent with the RUNTIME kernel-feature query (Docker \
         containers share the host kernel) this sandbox cannot complete. \
         Confirmed a sandbox artifact, not a property of the rule; see \
         PROVENANCE.md 'The fstype finding'.",
    ),
    (
        "reset-lost-probe",
        Unusable::SandboxLimited,
        "--reset-lost (round-2 addition, resolves blocker 5 empirically): \
         real auditctl prints 'Field option not supported by kernel: \
         reset-lost' (EAU_FIELDNOSUPPORT, libaudit.c's audit_reset_lost() \
         gating on audit_get_features() & AUDIT_FEATURE_BITMAP_LOST_RESET \
         BEFORE any netlink send, errormsg.h:108 for the message text) - the \
         SAME feature-bitmap mechanism as rocky9-filesystem-list, not the \
         silent-success-path ambiguity SILENT_SUCCESS_LEADING_FLAGS exists \
         for. This is why --reset-lost was removed from that denylist in \
         oracle.rs: it is never actually silent here.",
    ),
];

// ---------------------------------------------------------------------------
// Corpus model
// ---------------------------------------------------------------------------

/// One captured corpus row.
///
/// `stdout` is dead across all 213-then-222 rows this corpus has ever
/// captured (`auditctl -R` never writes to stdout in any scenario this lane
/// exercises - every row's `out_len` is 0): kept in the schema because a
/// future scenario COULD populate it and the raw-facts design promises not to
/// silently drop a column, but no test in this file, and no classification
/// rule in `oracle.rs`'s truth table, currently depends on its value.
/// `class` is used only inside panic/diagnostic strings (grouping label for a
/// human reading a failure), never in any comparison or assertion. Noted here
/// (round-2 adversarial review, also-fix 7) so a later session does not
/// mistake either field for load-bearing.
#[derive(Debug, Clone)]
struct Row {
    target: String,
    id: String,
    class: String,
    rc: i32,
    rule: String,
    stdout: String,
    stderr: String,
}

/// Reverse [`capture_auditd.sh`'s] `esc_field`: `\\` -> `\`, `\t` -> TAB,
/// `\n` -> LF, `\r` -> CR, `\xHH` -> that byte, and the whole-field sentinel
/// `\0` -> the empty string. Panics on an unrecognized escape or a trailing
/// lone backslash (fail-closed: a corpus row we cannot faithfully decode must
/// not be silently misread).
fn unescape_field(s: &str) -> String {
    if s == r"\0" {
        return String::new();
    }
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            match bytes.get(i + 1) {
                Some(b'\\') => {
                    out.push('\\');
                    i += 2;
                }
                Some(b't') => {
                    out.push('\t');
                    i += 2;
                }
                Some(b'n') => {
                    out.push('\n');
                    i += 2;
                }
                Some(b'r') => {
                    out.push('\r');
                    i += 2;
                }
                Some(b'x') => {
                    let hex = s.get(i + 2..i + 4).unwrap_or_else(|| {
                        panic!("unescape_field: truncated \\x escape at byte {i} in {s:?}")
                    });
                    let byte = u8::from_str_radix(hex, 16).unwrap_or_else(|e| {
                        panic!("unescape_field: invalid \\x hex {hex:?} at byte {i} in {s:?}: {e}")
                    });
                    out.push(char::from(byte));
                    i += 4;
                }
                other => panic!(
                    "unescape_field: unrecognized escape after backslash at byte {i} \
                     (next={other:?}) in {s:?}"
                ),
            }
        } else {
            // Safe: every special byte we handle above is ASCII, so stepping
            // one byte at a time never splits a multi-byte UTF-8 sequence -
            // none of this corpus's fields carry non-ASCII content (the one
            // non-printable byte, 0x01, is always escaped as `\x01`).
            out.push(char::from(bytes[i]));
            i += 1;
        }
    }
    out
}

fn corpus_root() -> PathBuf {
    let default = PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/corpus/auditd-oracle"
    ));
    let (root, mode) = resolve_corpus_root("RS_ORACLE_CORPUS_AUDITD", &default);
    eprintln!("{}", sentinel_banner("RS-DIFF-AUDITD", mode, &root));
    root
}

/// Discover target files: every `*.tsv` in the corpus root whose name does not
/// start with `_`, sorted for determinism. Enumeration is filesystem-driven (not
/// a hardcoded scenario count) even though the SET of expected target names
/// ([`EXPECTED_TARGETS`]) is asserted below.
fn target_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let entries = std::fs::read_dir(root)
        .unwrap_or_else(|e| panic!("read corpus dir {}: {e}", root.display()));
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        let is_tsv = path
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("tsv"));
        if name.starts_with('_') || !is_tsv {
            continue;
        }
        out.push(path);
    }
    out.sort();
    out
}

/// Parse one 10-field data row (already known non-`#`, non-blank). Fails
/// closed on a wrong field count, an unparseable `rc`/`*_len`, or a decoded
/// field whose length disagrees with its recorded `*_len` column - never a
/// silently wrong `Row`.
fn parse_data_row(path: &Path, lineno: usize, line: &str) -> Row {
    let fields: Vec<&str> = line.split('\t').collect();
    let [
        target,
        id,
        class,
        rc_str,
        rule_len_str,
        out_len_str,
        err_len_str,
        rule_raw,
        stdout_raw,
        stderr_raw,
    ] = fields.as_slice()
    else {
        panic!(
            "{}:{lineno}: expected exactly 10 tab-separated fields (target, id, class, rc, \
             rule_len, out_len, err_len, rule, stdout, stderr), got {}",
            path.display(),
            fields.len()
        );
    };

    let parse_usize = |label: &str, s: &str| -> usize {
        s.parse().unwrap_or_else(|e| {
            panic!(
                "{}:{lineno}: unparseable {label} {s:?}: {e}",
                path.display()
            )
        })
    };
    let rc: i32 = rc_str.parse().unwrap_or_else(|e| {
        panic!(
            "{}:{lineno}: unparseable rc {rc_str:?}: {e}",
            path.display()
        )
    });
    let rule_len = parse_usize("rule_len", rule_len_str);
    let out_len = parse_usize("out_len", out_len_str);
    let err_len = parse_usize("err_len", err_len_str);

    let rule = unescape_field(rule_raw);
    let stdout = unescape_field(stdout_raw);
    let stderr = unescape_field(stderr_raw);

    assert_eq!(
        rule.len(),
        rule_len,
        "{}:{lineno}: decoded rule length {} disagrees with recorded rule_len {rule_len} \
         (rule={rule:?}) - truncation, a dropped byte, or an escaping bug",
        path.display(),
        rule.len()
    );
    assert_eq!(
        stdout.len(),
        out_len,
        "{}:{lineno}: decoded stdout length {} disagrees with recorded out_len {out_len}",
        path.display(),
        stdout.len()
    );
    assert_eq!(
        stderr.len(),
        err_len,
        "{}:{lineno}: decoded stderr length {} disagrees with recorded err_len {err_len} \
         (stderr={stderr:?})",
        path.display(),
        stderr.len()
    );

    Row {
        target: (*target).to_string(),
        id: (*id).to_string(),
        class: (*class).to_string(),
        rc,
        rule,
        stdout,
        stderr,
    }
}

/// Parse one target TSV. Fails closed: empty/whitespace-only body, no
/// `#`-header anywhere, or a header with zero data rows are all errors,
/// never a silently empty `Vec`. Per-row validation is [`parse_data_row`].
fn parse_target_tsv(path: &Path) -> (String, Vec<Row>) {
    let body =
        std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    assert!(
        !body.trim().is_empty(),
        "{}: empty corpus file",
        path.display()
    );

    let mut audit_version: Option<String> = None;
    let mut saw_header = false;
    let mut rows = Vec::new();

    for (idx, line) in body.lines().enumerate() {
        let lineno = idx + 1;
        let trimmed = line.trim_start();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with('#') {
            saw_header = true;
            if let Some(pos) = trimmed.find("audit_version=") {
                let rest = &trimmed[pos + "audit_version=".len()..];
                let version = rest.split_whitespace().next().unwrap_or("");
                audit_version = Some(version.to_string());
            }
            continue;
        }

        rows.push(parse_data_row(path, lineno, line));
    }

    assert!(
        saw_header,
        "{}: missing documentation header (no '#'-prefixed line; file may be truncated \
         from the top)",
        path.display()
    );
    assert!(
        !rows.is_empty(),
        "{}: no data rows found (file may be truncated from the bottom, or is \
         comments-only)",
        path.display()
    );

    let version = audit_version.unwrap_or_else(|| {
        panic!(
            "{}: header carries no 'audit_version=' token; the per-version positive control \
             cannot be evaluated",
            path.display()
        )
    });
    (version, rows)
}

// ---------------------------------------------------------------------------
// The oracle test
// ---------------------------------------------------------------------------

#[test]
fn auditd_oracle_corpus_matches_real_auditctl() {
    let root = corpus_root();

    let files = target_files(&root);
    let file_names: Vec<String> = files
        .iter()
        .map(|p| p.file_stem().unwrap().to_string_lossy().to_string())
        .collect();
    let mut sorted_names = file_names.clone();
    sorted_names.sort_unstable();
    let mut expected_sorted = EXPECTED_TARGETS.to_vec();
    expected_sorted.sort_unstable();
    assert_eq!(
        sorted_names,
        expected_sorted,
        "expected exactly the target files {EXPECTED_TARGETS:?} under {}, found {file_names:?}",
        root.display()
    );

    let mut all_rows: Vec<Row> = Vec::new();
    let mut versions: Vec<(String, String)> = Vec::new(); // (target-file-stem, audit_version)
    for path in &files {
        let stem = path.file_stem().unwrap().to_string_lossy().to_string();
        let (version, rows) = parse_target_tsv(path);
        versions.push((stem, version));
        all_rows.extend(rows);
    }

    // Rule 1 (CONTRIBUTING "Assert the count, do not merely print it"): print
    // BEFORE asserting, but the assertion is what carries the guarantee.
    eprintln!("{}", sentinel_count("RS-DIFF-AUDITD", all_rows.len()));
    assert!(
        all_rows.len() >= FLOOR_ROWS,
        "expected >= {FLOOR_ROWS} corpus rows across {EXPECTED_TARGETS:?}, got {}",
        all_rows.len()
    );

    let mut unique_ids: Vec<&str> = all_rows.iter().map(|r| r.id.as_str()).collect();
    unique_ids.sort_unstable();
    unique_ids.dedup();
    assert!(
        unique_ids.len() >= FLOOR_SCENARIO_IDS,
        "expected >= {FLOOR_SCENARIO_IDS} distinct scenario ids, got {}",
        unique_ids.len()
    );

    // ------------------------------------------------------------------
    // Version-divergence positive control (CONTRIBUTING: "Where an oracle is
    // captured per-version, add a control pinning a known version divergence:
    // it is the only thing that detects 'all three transcripts are secretly
    // the same file'"). Measured (tools/oracle-images/README.md): no corpus
    // scenario's verdict differs across el8/el9/el10 audit-userspace
    // 3.1.2/3.1.5/4.0.3 (re-confirmed on the expanded 71-id corpus - every
    // data field byte-identical across all three targets), so the divergence
    // this control pins is the audit_version= STRING itself, captured live at
    // capture time (not hardcoded from the README).
    // ------------------------------------------------------------------
    assert_version_divergence_control(&versions);

    // Two-sided positive control (CONTRIBUTING rule 2), now evaluated via
    // classify_capture (the raw facts alone carry no verdict): if the capture
    // harness were broken (e.g. misclassifying every rule as the same
    // verdict), the ORACLE is broken, not the product, and the run must fail
    // rather than report clean or drift.
    for (stem, _version) in &versions {
        assert_two_sided_positive_control(&all_rows, stem);
    }

    // Product vs oracle: the actual comparison this whole file exists for.
    let (compared, xfail_hits, unobservable_hits) = compare_product_to_oracle(&all_rows);

    assert!(
        compared >= FLOOR_COMPARED,
        "expected >= {FLOOR_COMPARED} rows to reach the product-vs-oracle comparison (i.e. NOT \
         Unusable), got {compared}; a corpus that is entirely Unusable would satisfy the row-count \
         floor while comparing nothing"
    );

    assert_hit_exactly_three(&xfail_hits, XFAIL.iter().map(|(id, _)| *id), "XFAIL");
    assert_hit_exactly_three(
        &unobservable_hits,
        UNOBSERVABLE.iter().map(|(id, _, _)| *id),
        "UNOBSERVABLE",
    );
}

/// One target's two-sided positive control (CONTRIBUTING rule 2): a rule the
/// real oracle must ACCEPT and one it must REJECT with non-silent evidence,
/// classified to different [`CaptureVerdict`] variants. A broken harness that
/// cannot distinguish accept from reject is an ORACLE fault, not product
/// drift, and must fail the run outright.
fn assert_two_sided_positive_control(all_rows: &[Row], stem: &str) {
    let accept_row = all_rows
        .iter()
        .find(|r| r.target_file_stem_matches(stem) && r.id == CONTROL_ACCEPT_ID);
    let reject_row = all_rows
        .iter()
        .find(|r| r.target_file_stem_matches(stem) && r.id == CONTROL_REJECT_ID);
    let (Some(accept_row), Some(reject_row)) = (accept_row, reject_row) else {
        eprintln!(
            "RS-DIFF-AUDITD: ORACLE-BROKEN missing positive-control row(s) for target \
             file '{stem}': accept={:?} reject={:?}",
            accept_row.map(|r| &r.id),
            reject_row.map(|r| &r.id)
        );
        panic!("positive control rows missing for target file '{stem}'");
    };

    let accept_verdict = classify_capture(
        &accept_row.rule,
        accept_row.rc,
        &accept_row.stdout,
        &accept_row.stderr,
    );
    let reject_verdict = classify_capture(
        &reject_row.rule,
        reject_row.rc,
        &reject_row.stdout,
        &reject_row.stderr,
    );

    assert!(
        matches!(accept_verdict, CaptureVerdict::Accept),
        "control-accept row for '{stem}' must classify Accept, got {accept_verdict:?} \
         (rule={:?})",
        accept_row.rule
    );
    match reject_verdict {
        CaptureVerdict::Reject { complaint } => {
            assert!(
                !complaint.is_empty(),
                "control-reject row for '{stem}' must carry NON-SILENT evidence (this is the \
                 control that proves the harness truly parsed and rejected, not just went \
                 silent); rule={:?}",
                reject_row.rule
            );
            // Round-2 adversarial review: `!complaint.is_empty()` alone is
            // satisfied by ANY non-empty `&'static str`, including one that
            // was never grounded in the row's actual stderr (e.g. a
            // hardcoded placeholder). Cross-check the complaint is actually
            // PRESENT in the row's own captured evidence.
            assert!(
                reject_row.stderr.contains(complaint),
                "control-reject row for '{stem}': classify_capture's reported complaint \
                 {complaint:?} does not appear in the row's own captured stderr {:?}",
                reject_row.stderr
            );
        }
        other => panic!(
            "control-reject row for '{stem}' must classify Reject with a complaint, got \
             {other:?} (rule={:?})",
            reject_row.rule
        ),
    }
    assert_ne!(
        std::mem::discriminant(&accept_verdict),
        std::mem::discriminant(&reject_verdict),
        "target='{stem}': control-accept and control-reject classified to the SAME variant; \
         the capture harness cannot distinguish accept from reject, so neither a clean nor a \
         drift verdict would be truthful"
    );
}

/// `(target, id)` pairs, one per hit - see [`compare_product_to_oracle`]'s
/// doc for why the target must be tracked alongside the id.
type TargetIdHits = Vec<(String, String)>;

/// The core comparison this whole file exists for. Every row is first
/// classified by `classify_capture`; an `Unusable` row is permitted ONLY for
/// an id on [`UNOBSERVABLE`] whose declared KIND matches exactly (round-2
/// review, blocker 4) and is excluded from the product comparison entirely -
/// never "matched", never "xfailed", simply not comparable. An Accept/Reject
/// row is compared against `product_verdict`, matched directly or via
/// [`XFAIL`].
///
/// Returns `(compared, xfail_hits, unobservable_hits)`, each hit list keyed
/// by `(target, id)` - NOT just `id` - so [`assert_hit_exactly_three`] can
/// verify the 3 hits for an entry land one PER TARGET rather than merely
/// three times somewhere in the pooled rows (round-2 review, also-fix 5).
fn compare_product_to_oracle(all_rows: &[Row]) -> (usize, TargetIdHits, TargetIdHits) {
    let mut xfail_hits: TargetIdHits = Vec::new();
    let mut unobservable_hits: TargetIdHits = Vec::new();
    let mut compared = 0usize;

    for row in all_rows {
        let oracle = classify_capture(&row.rule, row.rc, &row.stdout, &row.stderr);
        let expected = match oracle {
            CaptureVerdict::Unusable(kind) => {
                record_unusable_hit(row, kind, &mut unobservable_hits);
                continue;
            }
            CaptureVerdict::Accept => Verdict::Accept,
            CaptureVerdict::Reject { .. } => Verdict::Reject,
        };

        let got = product_verdict(&row.rule);
        if got == expected {
            compared += 1;
            continue;
        }
        if XFAIL.iter().any(|(id, _)| *id == row.id) {
            xfail_hits.push((row.target.clone(), row.id.clone()));
            compared += 1;
            continue;
        }
        panic!(
            "auditd oracle divergence: target={} id={} class={} rule={:?} oracle={oracle:?} \
             product_verdict={got:?}",
            row.target, row.id, row.class, row.rule
        );
    }

    (compared, xfail_hits, unobservable_hits)
}

/// Validate one `Unusable` row against [`UNOBSERVABLE`] and record the hit.
/// Panics (`ORACLE-BROKEN`) on an unlisted id, OR an id that IS listed but
/// whose declared kind does not match this row's actual kind (round-2
/// review, blocker 4: checking "id is listed" and "kind is one of the two
/// allowed variants" independently would let `rocky9-filesystem-list`
/// classify `SilentNonAddLine` instead of its true `SandboxLimited`
/// mechanism and still pass). No allowlist, ever, for
/// `NoCapability`/`Loaded`/`UnexpectedRc`/`UnrecognisedDiagnostic`.
fn record_unusable_hit(row: &Row, kind: Unusable, unobservable_hits: &mut TargetIdHits) {
    let declared = UNOBSERVABLE.iter().find(|(id, _, _)| *id == row.id);
    let allowed = declared.is_some_and(|(_, declared_kind, _)| *declared_kind == kind);
    if !allowed {
        eprintln!(
            "RS-DIFF-AUDITD: ORACLE-BROKEN target={} id={} class={} rule={:?} unusable={kind:?} \
             declared={declared:?} - either not on the UNOBSERVABLE table, or the declared kind \
             does not match this row's actual kind",
            row.target, row.id, row.class, row.rule
        );
        panic!(
            "unexpected Unusable({kind:?}) for id={} (target={}); every Unusable row must be \
             pre-declared on UNOBSERVABLE with THIS EXACT kind",
            row.id, row.target
        );
    }
    unobservable_hits.push((row.target.clone(), row.id.clone()));
}

/// Every id on `table` must have been hit EXACTLY 3 times, ONE PER TARGET
/// (`rs-oracle8`/`rs-oracle9`/`rs-oracle10` - round-2 review, also-fix 5: a
/// version of this check that merely counts occurrences in the POOLED hit
/// list would pass a corpus where all 3 hits came from a single file and the
/// other two files dropped the row entirely, which is harmless today only
/// because the three files are `cmp`-identical modulo the target column, but
/// does not itself carry the "once per EL major" guarantee the docstring
/// claims). An id that stops reproducing on some target, or hits the SAME
/// target more than once, must fail the suite.
fn assert_hit_exactly_three<'a>(
    hits: &TargetIdHits,
    table_ids: impl Iterator<Item = &'a str>,
    label: &str,
) {
    const EXPECTED_TARGET_IMAGES: &[&str] = &["rs-oracle10", "rs-oracle8", "rs-oracle9"];
    for id in table_ids {
        let mut hit_targets: Vec<&str> = hits
            .iter()
            .filter(|(_, hit_id)| hit_id == id)
            .map(|(target, _)| target.as_str())
            .collect();
        hit_targets.sort_unstable();
        assert_eq!(
            hit_targets, EXPECTED_TARGET_IMAGES,
            "{label} entry '{id}' was hit on targets {hit_targets:?}, expected exactly one hit \
             on each of {EXPECTED_TARGET_IMAGES:?}; an entry that stops reproducing on some \
             target (or hits one target more than once) must fail the suite rather than go quiet"
        );
    }
}

impl Row {
    /// `true` if this row's `target` column (the docker image tag, e.g.
    /// `rs-oracle8`) corresponds to the target FILE stem (`el8`) it was read
    /// from. Encoded as a small match rather than a shared table because the
    /// mapping is frozen (exactly 3 pairs) and a wrong pairing here would be
    /// silently self-consistent (never observed) rather than caught.
    fn target_file_stem_matches(&self, stem: &str) -> bool {
        matches!(
            (stem, self.target.as_str()),
            ("el8", "rs-oracle8") | ("el9", "rs-oracle9") | ("el10", "rs-oracle10")
        )
    }
}

/// Assert the 3 captured `audit_version=` strings are pairwise distinct. If a
/// base-image refresh ever collapses two of them, THIS is what detects "all
/// three transcripts are secretly the same file" per CONTRIBUTING.md.
fn assert_version_divergence_control(versions: &[(String, String)]) {
    assert_eq!(
        versions.len(),
        3,
        "expected exactly 3 (target, audit_version) pairs, got {versions:?}"
    );
    for i in 0..versions.len() {
        for j in (i + 1)..versions.len() {
            let (ti, vi) = &versions[i];
            let (tj, vj) = &versions[j];
            if vi == vj {
                eprintln!(
                    "RS-DIFF-AUDITD: ORACLE-BROKEN target='{ti}' and target='{tj}' both report \
                     audit_version={vi:?}; the per-version divergence control cannot confirm \
                     these are genuinely distinct captures"
                );
                panic!("version-divergence control collapsed between '{ti}' and '{tj}'");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Test-side (NOT product) grounding for "loud reject" stderr text (round-2
// adversarial review, also-fix 4): `classify_capture`'s own complaint table
// is the implementer's to write inside `oracle.rs`, but nothing in this file
// independently verified that every loud-reject row in the corpus carries a
// RECOGNISED, cited diagnostic rather than an accidental catch-all - which is
// exactly the gap the reviewer's constant-catch-all counterexample
// (`_ => Reject { complaint: "some diagnostic" }`) exploited. This check runs
// TODAY, independent of `classify_capture` (still `todo!()`), by reading the
// corpus directly.
// ---------------------------------------------------------------------------

/// Substrings that must appear in a KNOWN loud-reject row's stderr, each cited
/// to the emitting `audit-userspace` function (`errormsg.h`'s `err_msgtab`,
/// printed via the direct-`fprintf` `audit_number_to_errmsg`, so visible even
/// under `-R`'s `MSG_SYSLOG` mode - see `PROVENANCE.md` "`MSG_SYSLOG` under
/// -R"). Distinct from the two `Unusable::SandboxLimited` substrings
/// (`"filter is not supported by the kernel"`, `"Field option not supported
/// by kernel:"`), which are feature-bitmap artifacts of THIS sandbox rather
/// than a genuine parse complaint about the rule's content - see
/// `is_sandbox_limited_stderr`.
const KNOWN_PARSE_COMPLAINTS: &[(&str, &str)] = &[
    ("-F unknown field:", "EAU_FIELDUNKNOWN, errormsg.h ~86"),
    ("-C unknown field:", "EAU_COMPFIELDUNKNOWN, errormsg.h ~103"),
    (
        "-F value should be number for",
        "EAU_FIELDVALNUM, errormsg.h ~98",
    ),
    (
        "Permission can only contain",
        "EAU_PERMRWXA, errormsg.h ~91",
    ),
];

/// A stderr matching either of these is a feature-bitmap query this sandbox's
/// blocked `AUDIT_GET` cannot complete (`Unusable::SandboxLimited`), NOT a
/// genuine parse complaint about the rule's own content - see
/// `rocky9-filesystem-list` / `reset-lost-probe` on [`UNOBSERVABLE`].
fn is_sandbox_limited_stderr(stderr: &str) -> bool {
    stderr.contains("filter is not supported by the kernel")
        || stderr.contains("Field option not supported by kernel:")
}

/// Independent of `classify_capture`'s own implementation: reads the corpus
/// directly and asserts every row whose raw facts have the SHAPE of a loud
/// reject (`rc == 1`, non-empty stderr, not an add-shaped OR delete-shaped
/// accept string, not a sandbox-limited feature-bitmap message) carries a
/// stderr matching at least one [`KNOWN_PARSE_COMPLAINTS`] entry, and that
/// every entry in that table is actually hit by at least one row (no orphan
/// entries). This is the test's own cross-check that the corpus does not
/// contain an unrecognised loud-reject diagnostic that `classify_capture`
/// could silently mis-map - complementary to (not a replacement for)
/// `oracle.rs`'s `rc_one_unrecognised_nonempty_stderr_is_unusable` synthetic
/// pin.
///
/// The delete-shaped exclusion (`w-delete-watch`/`d-delete-syscall`,
/// post-implementation adversarial review MISS 1) matters here too: without
/// it, those two rows' "Error sending delete rule data request" stderr looks
/// exactly like an unrecognised loud reject to THIS test's own heuristic,
/// which would make it fail forever (even once `classify_capture` is fixed
/// to accept them) rather than only while the bug is unfixed.
#[test]
fn known_parse_complaints_cover_every_loud_reject_row() {
    let root = corpus_root();
    let files = target_files(&root);
    let mut all_rows: Vec<Row> = Vec::new();
    for path in &files {
        let (_version, rows) = parse_target_tsv(path);
        all_rows.extend(rows);
    }
    assert!(!all_rows.is_empty(), "corpus must not be empty");

    let mut entry_hits = vec![0usize; KNOWN_PARSE_COMPLAINTS.len()];
    let mut loud_reject_rows_seen = 0usize;

    for row in &all_rows {
        let is_loud_reject_shape = row.rc == 1
            && !row.stderr.is_empty()
            && !row.stderr.contains("Error sending add rule data request")
            && !row
                .stderr
                .contains("Error sending delete rule data request")
            && !is_sandbox_limited_stderr(&row.stderr);
        if !is_loud_reject_shape {
            continue;
        }
        loud_reject_rows_seen += 1;

        let matched = KNOWN_PARSE_COMPLAINTS
            .iter()
            .position(|(substr, _)| row.stderr.contains(substr));
        match matched {
            Some(idx) => entry_hits[idx] += 1,
            None => panic!(
                "target={} id={} rule={:?} has a loud-reject-shaped stderr {:?} that matches \
                 NO entry in KNOWN_PARSE_COMPLAINTS; either this is a genuinely new diagnostic \
                 that needs its own cited entry, or it should be reclassified (e.g. as \
                 sandbox-limited)",
                row.target, row.id, row.rule, row.stderr
            ),
        }
    }

    assert!(
        loud_reject_rows_seen > 0,
        "expected at least one loud-reject-shaped row in the corpus; an instrument that \
         checked nothing must not report clean"
    );

    for (idx, (substr, citation)) in KNOWN_PARSE_COMPLAINTS.iter().enumerate() {
        assert!(
            entry_hits[idx] > 0,
            "KNOWN_PARSE_COMPLAINTS entry {substr:?} ({citation}) was never hit by any corpus \
             row; an orphan entry in a cited table is itself a grounding defect"
        );
    }
}

// ---------------------------------------------------------------------------
// Codec positive control (round-2 adversarial review, also-fix 6): the three
// `assert_eq!(decoded.len(), recorded_len)` checks in `parse_data_row` have
// only ever run against a corpus where they pass. This project's own rule is
// that any instrument gets ONE run against known-bad input before a green
// result from it is trusted (a summarizer that never reports bad must not be
// trusted to report clean). These tests feed `parse_data_row` a deliberately
// corrupted row directly (it is a private fn in this same file) and assert it
// panics, rather than silently accepting the corruption.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod parse_data_row_codec_positive_control {
    use super::parse_data_row;
    use std::path::Path;

    #[test]
    #[should_panic(expected = "disagrees with recorded rule_len")]
    fn a_truncated_rule_field_is_rejected_fail_closed() {
        // rule_len claims 20 bytes but the rule field itself is only 5.
        let line = "rs-oracle8\tfake-id\texisting\t1\t20\t0\t0\thello\t\\0\t\\0";
        parse_data_row(Path::new("synthetic.tsv"), 1, line);
    }

    #[test]
    #[should_panic(expected = "disagrees with recorded err_len")]
    fn a_dropped_byte_in_stderr_is_rejected_fail_closed() {
        // err_len claims 30 bytes; the decoded stderr is shorter (a dropped
        // byte, simulating truncation across the bash/container boundary).
        let line = "rs-oracle8\tfake-id\texisting\t1\t5\t0\t30\thello\t\\0\tError sending add rule";
        parse_data_row(Path::new("synthetic.tsv"), 1, line);
    }

    #[test]
    #[should_panic(expected = "expected exactly 10 tab-separated fields")]
    fn a_wrong_field_count_is_rejected_fail_closed() {
        let line = "rs-oracle8\tfake-id\texisting\t1\t0\t0\t0\t\\0"; // only 8 fields
        parse_data_row(Path::new("synthetic.tsv"), 1, line);
    }
}

// ---------------------------------------------------------------------------
// Unit tests for this file's own escaping logic (test infrastructure, not the
// product under test - but a bug here would silently corrupt every comparison
// above, so it gets its own adversarial coverage).
// ---------------------------------------------------------------------------
#[cfg(test)]
mod unescape_tests {
    use super::unescape_field;

    #[test]
    fn plain_text_round_trips_unchanged() {
        assert_eq!(
            unescape_field("-w /etc/passwd -p wa -k q1"),
            "-w /etc/passwd -p wa -k q1"
        );
    }

    #[test]
    fn whole_field_empty_sentinel_becomes_empty_string() {
        assert_eq!(unescape_field(r"\0"), "");
    }

    #[test]
    fn escaped_tab_becomes_a_real_tab() {
        assert_eq!(
            unescape_field(r"-w /etc/passwd\t-p wa -k q3"),
            "-w /etc/passwd\t-p wa -k q3"
        );
    }

    #[test]
    fn escaped_newline_becomes_a_real_newline() {
        assert_eq!(unescape_field(r"line1\nline2"), "line1\nline2");
    }

    #[test]
    fn escaped_cr_becomes_a_real_cr() {
        assert_eq!(unescape_field(r"a\rb"), "a\rb");
    }

    #[test]
    fn escaped_backslash_becomes_one_literal_backslash() {
        // Encoded form (as capture_auditd.sh's esc_field would write it) for
        // the real rule `-w /etc/my\ dir/file -p wa -k q2` (one literal
        // backslash before the space).
        assert_eq!(
            unescape_field(r"-w /etc/my\\ dir/file -p wa -k q2"),
            "-w /etc/my\\ dir/file -p wa -k q2"
        );
    }

    #[test]
    fn escaped_x01_becomes_the_soh_byte() {
        assert_eq!(
            unescape_field(r"-a always,exit -F arch=b64 -S execve -k key\x01withsep"),
            "-a always,exit -F arch=b64 -S execve -k key\u{0001}withsep"
        );
    }

    #[test]
    fn escaped_leading_and_trailing_space_round_trip() {
        assert_eq!(unescape_field(r"\x20leading"), " leading");
        assert_eq!(unescape_field(r"trailing\x20"), "trailing ");
    }

    #[test]
    #[should_panic(expected = "unrecognized escape")]
    fn an_unknown_escape_is_rejected_fail_closed() {
        unescape_field(r"-w /etc/passwd\z-p wa");
    }

    #[test]
    #[should_panic(expected = "truncated")]
    fn a_trailing_lone_backslash_x_is_rejected_fail_closed() {
        unescape_field(r"abc\x2");
    }
}
