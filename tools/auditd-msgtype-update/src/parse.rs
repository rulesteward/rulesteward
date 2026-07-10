//! Extract the auditd record-type tables from the pinned upstream headers:
//!
//! * [`parse_typetab`]: the `_S(AUDIT_<NAME>, "<NAME>")` rows of
//!   audit-userspace `lib/msg_typetab.h`, split into the BASE table and the
//!   `#ifdef WITH_APPARMOR` table (the split the shipped
//!   `MSGTYPE_NAMES` / `APPARMOR_MSGTYPE_NAMES` consts mirror - AppArmor
//!   folding is opt-in in the linter, so the derive tool must keep the two
//!   tables separate, never merged).
//! * [`parse_defines`]: the `#define AUDIT_<NAME> <number>` constants of a
//!   number source (`lib/audit-records.h` or the kernel
//!   `include/uapi/linux/audit.h`).
//! * [`resolve`]: names -> numbers, audit-records.h first, kernel header for
//!   names it lacks, hard error on a cross-source conflict or an unresolvable
//!   name.
//!
//! Source citations: upstream `linux-audit/audit-userspace` @ commit 3bfa048
//! (`lib/msg_typetab.h`, `lib/audit-records.h`) and `torvalds/linux` @ tag
//! v6.6 (`include/uapi/linux/audit.h`) - see `../msgtype-refs.toml` for the
//! pinned refs + sha256 of the sources `tests/fixtures/` were copied and
//! verified from (2026-07-10 grounding, session 7c pipeline P1, #476).

use std::collections::BTreeMap;

/// One uncommented `_S(AUDIT_<NAME>, "<NAME>")` row: the C constant identifier
/// and the record-type name string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypetabEntry {
    /// The `AUDIT_<NAME>` constant identifier (e.g. `"AUDIT_SYSCALL"`).
    pub audit_const: String,
    /// The quoted record-type name (e.g. `"SYSCALL"`).
    pub name: String,
}

/// The two tables of `msg_typetab.h`, in source order.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Typetab {
    /// Rows OUTSIDE any `#ifdef WITH_APPARMOR` block (189 at the pinned
    /// commit). Note the block sits mid-file: rows AFTER its `#endif` (e.g.
    /// `KERNEL`) are still base rows.
    pub base: Vec<TypetabEntry>,
    /// Rows INSIDE a `#ifdef WITH_APPARMOR` .. `#endif` block (8 at the
    /// pinned commit).
    pub apparmor: Vec<TypetabEntry>,
}

/// The fully-resolved name -> number tables, comparable against the shipped
/// consts. Maps (not vecs) because `msg_typetab.h` is NOT strictly
/// number-sorted (`MAC_CHECK` 1134 precedes `SYSTEM_BOOT` 1127 in file order)
/// while the shipped consts are number-grouped - the drift contract is
/// name/number CONTENT equality, not sequence order. Names are unique by
/// construction ([`parse_typetab`] hard-errors on a duplicate).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DerivedTables {
    pub base: BTreeMap<String, u32>,
    pub apparmor: BTreeMap<String, u32>,
}

/// Extract the `_S(AUDIT_<NAME>, "<NAME>")` rows of a `msg_typetab.h` source.
///
/// Contract (all frozen by the tests below):
/// * A row is a line whose first non-whitespace is `_S(`, carrying an
///   `AUDIT_<NAME>` identifier and one double-quoted name, closed by `)`.
/// * A line whose first non-whitespace is `//` is a COMMENT and is never
///   extracted - the deprecated/daemon-filtered `//_S(...)` rows (`GET`,
///   `SET`, `LIST`, `ADD`, `DEL`, `DAEMON_RECONFIG`, `SIGNAL_INFO`,
///   `FS_WATCH`, ... - 18 at the pinned commit) must NOT appear in either
///   table.
/// * Rows between `#ifdef WITH_APPARMOR` and its `#endif` go to `apparmor`;
///   all other rows (including rows AFTER the `#endif`) go to `base`.
///
/// Fails CLOSED (`Err`) - never returns a partial or empty table silently -
/// when:
/// * an `_S(` row has no closing `)` (a source truncated mid-line);
/// * a `#ifdef WITH_APPARMOR` has no matching `#endif` (truncated inside the
///   block);
/// * the same NAME appears twice anywhere (base + apparmor combined) - a
///   duplicate makes name->number folding ambiguous;
/// * zero rows were extracted (an empty table is not a real typetab).
///
/// A caller that silently accepted a truncated result would make the `check`
/// subcommand's drift gate report a false "no drift" on a corrupted source -
/// the worst failure shape for a drift gate.
pub fn parse_typetab(src: &str) -> Result<Typetab, String> {
    let mut base = Vec::new();
    let mut apparmor = Vec::new();
    let mut in_apparmor = false;
    let mut seen_names: std::collections::HashSet<String> = std::collections::HashSet::new();

    for (idx, line) in src.lines().enumerate() {
        let lineno = idx + 1;
        let trimmed = line.trim_start();

        if trimmed.starts_with("#ifdef WITH_APPARMOR") {
            in_apparmor = true;
            continue;
        }
        if trimmed.starts_with("#endif") {
            in_apparmor = false;
            continue;
        }
        if trimmed.starts_with("//") {
            // A commented-out row (deprecated/daemon-filtered) - never extracted.
            continue;
        }
        if !trimmed.starts_with("_S(") {
            continue;
        }

        let entry = parse_s_row(trimmed).ok_or_else(|| {
            format!("line {lineno}: malformed _S(...) row (no closing ')'): {trimmed:?}")
        })?;
        if !seen_names.insert(entry.name.clone()) {
            return Err(format!(
                "line {lineno}: duplicate record-type name {:?} (already seen earlier in the file)",
                entry.name
            ));
        }
        if in_apparmor {
            apparmor.push(entry);
        } else {
            base.push(entry);
        }
    }

    if in_apparmor {
        return Err(
            "unterminated #ifdef WITH_APPARMOR block: reached end of file with no matching #endif"
                .to_string(),
        );
    }

    if base.is_empty() && apparmor.is_empty() {
        return Err("no _S(AUDIT_<NAME>, \"<NAME>\") rows found in the source".to_string());
    }

    Ok(Typetab { base, apparmor })
}

/// Parse one `_S(AUDIT_<NAME>, "<NAME>")` row (already known to start with
/// `_S(`). Returns `None` on a truncated row (no closing `)`, no comma, or no
/// closing quote) - the caller turns that into a named, line-numbered error.
fn parse_s_row(trimmed: &str) -> Option<TypetabEntry> {
    let rest = trimmed.strip_prefix("_S(")?;
    let close_paren = rest.find(')')?;
    let inner = &rest[..close_paren];

    let comma = inner.find(',')?;
    let audit_const = inner[..comma].trim().to_string();

    let after_comma = &inner[comma + 1..];
    let open_quote = after_comma.find('"')?;
    let after_open_quote = &after_comma[open_quote + 1..];
    let close_quote = after_open_quote.find('"')?;
    let name = after_open_quote[..close_quote].to_string();

    if audit_const.is_empty() || name.is_empty() {
        return None;
    }
    Some(TypetabEntry { audit_const, name })
}

/// Extract the `#define AUDIT_<NAME> <number>` constants of a number source.
///
/// Contract: a define counts only when its value token (the
/// whitespace-delimited token after the name) parses fully as a PLAIN DECIMAL
/// `u32`. Expression-valued defines (`(EM_X86_64|...)`), hex-valued defines
/// (`0x0001`), and non-`AUDIT_`-prefixed defines are SKIPPED (not errors) -
/// they are real, legitimate lines of both pinned sources, and every actual
/// record-type constant in both files is plain decimal. This keeps the scan
/// minimal and the known-answer counts stable (166 in `audit-records.h`, 199
/// in the kernel header, both pinned by the tests below).
pub fn parse_defines(src: &str) -> Result<BTreeMap<String, u32>, String> {
    let mut out = BTreeMap::new();
    for line in src.lines() {
        let trimmed = line.trim_start();
        let Some(rest) = trimmed.strip_prefix("#define") else {
            continue;
        };
        let mut tokens = rest.split_whitespace();
        let Some(name) = tokens.next() else {
            continue;
        };
        if !name.starts_with("AUDIT_") {
            continue;
        }
        let Some(value_tok) = tokens.next() else {
            continue;
        };
        if let Ok(value) = value_tok.parse::<u32>() {
            out.insert(name.to_string(), value);
        }
        // Expression-valued (`(EM_X86_64|...)`) and hex-valued (`0x0001`)
        // defines fail the plain-decimal u32 parse above and are silently
        // skipped, per the documented contract.
    }
    Ok(out)
}

/// Resolve every [`Typetab`] row's `AUDIT_<NAME>` constant to its number.
///
/// Contract (the coordinator-fixed number-resolution design for #476):
/// * `records` (audit-records.h's defines) is consulted FIRST; `kernel` (the
///   kernel uapi header's defines) resolves names `records` lacks (60 of the
///   197 referenced constants at the pinned refs).
/// * A referenced constant defined in BOTH sources with DIFFERENT numbers is
///   a hard error naming the constant - the tool must NEVER silently prefer
///   one source on a conflict. (Defined in both with the SAME number is
///   fine.)
/// * A referenced constant defined in NEITHER source is a hard error naming
///   the constant - never a silent skip (a silent skip would shrink the
///   derived table and masquerade as name-level drift, or worse, as no drift
///   at all).
/// * The conflict check is scoped to constants REFERENCED by the typetab: the
///   two sources also share dozens of range markers
///   (`AUDIT_FIRST_*`/`AUDIT_LAST_*`) that no `_S` row references, and a
///   future legitimate divergence there must not fail the msgtype drift gate.
pub fn resolve(
    typetab: &Typetab,
    records: &BTreeMap<String, u32>,
    kernel: &BTreeMap<String, u32>,
) -> Result<DerivedTables, String> {
    Ok(DerivedTables {
        base: resolve_entries(&typetab.base, records, kernel)?,
        apparmor: resolve_entries(&typetab.apparmor, records, kernel)?,
    })
}

/// Resolve one table's entries (base or apparmor) name -> number, per
/// [`resolve`]'s records-first / kernel-fallback / conflict-hard-error /
/// missing-hard-error contract.
fn resolve_entries(
    entries: &[TypetabEntry],
    records: &BTreeMap<String, u32>,
    kernel: &BTreeMap<String, u32>,
) -> Result<BTreeMap<String, u32>, String> {
    let mut out = BTreeMap::new();
    for e in entries {
        let in_records = records.get(&e.audit_const);
        let in_kernel = kernel.get(&e.audit_const);
        let number = match (in_records, in_kernel) {
            (Some(&r), Some(&k)) if r != k => {
                return Err(format!(
                    "{}: conflicting definition (audit-records.h has {r}, kernel header has {k})",
                    e.audit_const
                ));
            }
            (Some(&r), _) => r,
            (None, Some(&k)) => k,
            (None, None) => {
                return Err(format!(
                    "{}: not defined in audit-records.h or the kernel header",
                    e.audit_const
                ));
            }
        };
        out.insert(e.name.clone(), number);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MSG_TYPETAB: &str = include_str!("../tests/fixtures/3bfa048/msg_typetab.h");
    const AUDIT_RECORDS: &str = include_str!("../tests/fixtures/3bfa048/audit-records.h");
    const KERNEL_AUDIT_H: &str = include_str!("../tests/fixtures/linux-v6.6/audit.h");

    fn entry(audit_const: &str, name: &str) -> TypetabEntry {
        TypetabEntry {
            audit_const: audit_const.to_string(),
            name: name.to_string(),
        }
    }

    /// KNOWN-ANSWER on the real pinned fixture: 189 base rows + 8 AppArmor
    /// rows (= 197 uncommented `_S` lines; the file also carries 18
    /// commented-out `//_S` lines that must NOT be extracted). First/last
    /// rows of each table are pinned exactly so an off-by-one scan (dropping
    /// the first row, eating one row past the `#endif`, ...) cannot pass on
    /// counts alone.
    #[test]
    fn parse_typetab_real_fixture_yields_189_base_and_8_apparmor() {
        let tab = parse_typetab(MSG_TYPETAB).expect("the real msg_typetab.h parses");
        assert_eq!(tab.base.len(), 189, "base table must have exactly 189 rows");
        assert_eq!(
            tab.apparmor.len(),
            8,
            "WITH_APPARMOR table must have exactly 8 rows"
        );

        assert_eq!(tab.base[0], entry("AUDIT_USER", "USER"));
        assert_eq!(tab.base[1], entry("AUDIT_LOGIN", "LOGIN"));
        assert_eq!(
            tab.base[188],
            entry("AUDIT_VIRT_MIGRATE_OUT", "VIRT_MIGRATE_OUT")
        );
        assert_eq!(tab.apparmor[0], entry("AUDIT_AA", "APPARMOR"));
        assert_eq!(
            tab.apparmor[7],
            entry("AUDIT_APPARMOR_KILL", "APPARMOR_KILL")
        );

        // KERNEL is the first row AFTER the #endif: it must land in BASE, not
        // in the AppArmor table (a scanner that treats #endif as
        // end-of-apparmor-and-file, or never flips back, fails here).
        assert!(
            tab.base
                .iter()
                .any(|e| e.audit_const == "AUDIT_KERNEL" && e.name == "KERNEL"),
            "KERNEL (post-#endif row) must be a BASE row"
        );
        assert!(
            !tab.apparmor.iter().any(|e| e.name == "KERNEL"),
            "KERNEL must not land in the AppArmor table"
        );

        // Commented-out deprecated/daemon-filtered rows must not be extracted
        // into EITHER table (verified against the real fixture: all of these
        // appear only as `//_S(...)` lines).
        for dead in [
            "GET",
            "SET",
            "LIST",
            "ADD",
            "DEL",
            "DAEMON_RECONFIG",
            "SIGNAL_INFO",
            "FS_WATCH",
            "FS_INODE",
            "TRIM",
        ] {
            assert!(
                !tab.base.iter().any(|e| e.name == dead)
                    && !tab.apparmor.iter().any(|e| e.name == dead),
                "commented-out row {dead:?} must not be extracted"
            );
        }
    }

    /// A commented `//_S(...)` line must not be extracted even in a synthetic
    /// minimal input (isolates the comment rule from the big fixture).
    #[test]
    fn parse_typetab_ignores_commented_rows() {
        let src = "\
_S(AUDIT_USER,                       \"USER\"                          )
//_S(AUDIT_GET,                      \"GET\"                           )
_S(AUDIT_LOGIN,                      \"LOGIN\"                         )
";
        let tab = parse_typetab(src).expect("synthetic tab parses");
        assert_eq!(
            tab.base,
            vec![entry("AUDIT_USER", "USER"), entry("AUDIT_LOGIN", "LOGIN")],
            "the commented GET row must not be extracted"
        );
        assert!(tab.apparmor.is_empty());
    }

    /// Rows inside `#ifdef WITH_APPARMOR` land ONLY in the AppArmor table;
    /// rows after the `#endif` are base rows again.
    #[test]
    fn parse_typetab_apparmor_block_lands_only_in_apparmor() {
        let src = "\
_S(AUDIT_USER,                       \"USER\"                          )
#ifdef WITH_APPARMOR
_S(AUDIT_AA,                         \"APPARMOR\"                      )
_S(AUDIT_APPARMOR_AUDIT,             \"APPARMOR_AUDIT\"                )
#endif
_S(AUDIT_KERNEL,                     \"KERNEL\"                        )
";
        let tab = parse_typetab(src).expect("synthetic tab parses");
        assert_eq!(
            tab.base,
            vec![entry("AUDIT_USER", "USER"), entry("AUDIT_KERNEL", "KERNEL")],
            "rows outside the block (incl. post-#endif) are base rows"
        );
        assert_eq!(
            tab.apparmor,
            vec![
                entry("AUDIT_AA", "APPARMOR"),
                entry("AUDIT_APPARMOR_AUDIT", "APPARMOR_AUDIT"),
            ],
            "rows inside the block are AppArmor rows"
        );
    }

    /// A source truncated MID-ROW (an `_S(` line with no closing `)`) must
    /// fail closed, not return the rows before the cut. A line scanner that
    /// regex-matches complete rows and silently skips non-matching lines
    /// returns a short table here - the exact fail-open shape a drift gate
    /// cannot afford.
    #[test]
    fn parse_typetab_fails_closed_on_midline_truncation() {
        let src = "\
_S(AUDIT_USER,                       \"USER\"                          )
_S(AUDIT_LOGIN,                      \"LOGIN\"";
        let err =
            parse_typetab(src).expect_err("a mid-row truncation must be rejected, not skipped");
        assert!(!err.is_empty(), "error message must not be empty");
    }

    /// A source truncated INSIDE the `#ifdef WITH_APPARMOR` block (no
    /// `#endif` before EOF) must fail closed - the block's remaining rows
    /// (and every base row after the `#endif`, e.g. `KERNEL`) are missing,
    /// and a parser that shrugs returns a short table with exit 0.
    #[test]
    fn parse_typetab_fails_closed_on_unterminated_apparmor_block() {
        let src = "\
_S(AUDIT_USER,                       \"USER\"                          )
#ifdef WITH_APPARMOR
_S(AUDIT_AA,                         \"APPARMOR\"                      )
";
        let err =
            parse_typetab(src).expect_err("an unterminated WITH_APPARMOR block must be rejected");
        assert!(!err.is_empty(), "error message must not be empty");
    }

    /// A duplicate NAME (whether within one table or across base/apparmor)
    /// makes name->number folding ambiguous and must be a hard error naming
    /// the duplicate.
    #[test]
    fn parse_typetab_fails_closed_on_duplicate_name() {
        let within = "\
_S(AUDIT_USER,                       \"USER\"                          )
_S(AUDIT_USER_AUTH,                  \"USER\"                          )
";
        let err = parse_typetab(within).expect_err("duplicate name within base must error");
        assert!(
            err.contains("USER"),
            "the error must name the duplicated name: {err:?}"
        );

        let across = "\
_S(AUDIT_USER,                       \"USER\"                          )
#ifdef WITH_APPARMOR
_S(AUDIT_AA,                         \"USER\"                          )
#endif
";
        let err = parse_typetab(across).expect_err("duplicate name across tables must error");
        assert!(
            err.contains("USER"),
            "the error must name the duplicated name: {err:?}"
        );
    }

    /// Zero extracted rows (an empty or rows-free source) is not a real
    /// typetab - fail closed rather than deriving a vacuous empty table.
    #[test]
    fn parse_typetab_fails_closed_on_zero_rows() {
        let err = parse_typetab("/* just a header comment, no rows */\n")
            .expect_err("a rows-free source must be rejected");
        assert!(!err.is_empty(), "error message must not be empty");
    }

    /// The line-number formatting in a malformed-row error must be the
    /// 1-based `idx + 1`, not the raw 0-based `enumerate` index. Reuses the
    /// mid-row-truncation fixture from
    /// `parse_typetab_fails_closed_on_midline_truncation` (malformed row is
    /// the SECOND source line) and additionally pins the reported line
    /// number - that test only asserts the error is non-empty, so it cannot
    /// distinguish `idx + 1` from a mutated `idx * 1` (which would report
    /// line 1, not line 2, for this fixture). Kills `parse.rs:90:26`
    /// (`idx + 1` -> `idx * 1` in `parse_typetab`).
    #[test]
    fn parse_typetab_malformed_row_error_reports_the_correct_one_based_line_number() {
        let src = "\
_S(AUDIT_USER,                       \"USER\"                          )
_S(AUDIT_LOGIN,                      \"LOGIN\"";
        let err = parse_typetab(src).expect_err("a mid-row truncation must be rejected");
        assert!(
            err.starts_with("line 2:"),
            "the malformed row is the second (1-based) source line: {err:?}"
        );
    }

    /// A row whose `AUDIT_<NAME>` half is empty (a bare `,` immediately after
    /// `_S(`) must be rejected as malformed via `parse_s_row` returning
    /// `None`, never silently accepted as a name-only entry and never a
    /// panic. Kills three survivors in one input:
    /// * `parse.rs:150:36` `comma + 1` -> `comma - 1`: with `comma == 0`
    ///   (the row starts with the comma), `0usize - 1` underflows and panics
    ///   in a debug build instead of returning `None`.
    /// * `parse.rs:150:36` `comma + 1` -> `comma * 1` is a separate mutant
    ///   NOT killed here (see `.cargo/mutants.toml`: `inner[comma]` is
    ///   provably always the comma character itself, never `"`, so shifting
    ///   the search start by exactly that one non-quote character cannot
    ///   change which `"` is found - a genuine equivalent mutant, proved in
    ///   the exclude_re rationale, not chased with a test here).
    /// * `parse.rs:156:31` `||` -> `&&` in
    ///   `audit_const.is_empty() || name.is_empty()`: the mutated guard only
    ///   rejects a row when BOTH halves are empty, so this one-sided-empty
    ///   row would fall through and be accepted as
    ///   `Some(TypetabEntry { audit_const: "", name: "NAME" })` instead of
    ///   `None`, turning the expected `Err` into an `Ok` here.
    #[test]
    fn parse_typetab_rejects_a_row_with_an_empty_audit_const_before_the_comma() {
        let src = "_S(,\"NAME\"                                                    )\n";
        let err = parse_typetab(src).expect_err(
            "an empty audit_const before the comma must be rejected, not silently accepted",
        );
        assert!(!err.is_empty(), "error message must not be empty");
    }

    /// KNOWN-ANSWER on the real audit-records.h fixture: exactly 166
    /// decimal-valued `#define AUDIT_*` constants, with pinned spot values
    /// spanning the file (first block, daemon block, integrity `#ifndef`
    /// block, LSPP + virt tails). Constants that live ONLY in the kernel
    /// header (SYSCALL / KERNEL / USER / LOGIN...) must be ABSENT here - a
    /// scan that hallucinated them (e.g. by reading the block comment's range
    /// prose) would break the resolve precedence contract.
    #[test]
    fn parse_defines_real_audit_records_known_answers() {
        let d = parse_defines(AUDIT_RECORDS).expect("audit-records.h parses");
        assert_eq!(d.len(), 166, "audit-records.h decimal define count");
        assert_eq!(d["AUDIT_USER_AUTH"], 1100);
        assert_eq!(d["AUDIT_DAEMON_RECONFIG"], 1204);
        assert_eq!(d["AUDIT_AA"], 1500);
        assert_eq!(d["AUDIT_INTEGRITY_DATA"], 1800);
        assert_eq!(d["AUDIT_ANOM_CREAT"], 1703);
        assert_eq!(d["AUDIT_VIRT_MIGRATE_OUT"], 2507);
        for kernel_only in ["AUDIT_SYSCALL", "AUDIT_KERNEL", "AUDIT_USER", "AUDIT_LOGIN"] {
            assert!(
                !d.contains_key(kernel_only),
                "{kernel_only} is kernel-header-only and must be absent from \
                 the audit-records.h map"
            );
        }
    }

    /// KNOWN-ANSWER on the real kernel uapi fixture: exactly 199
    /// decimal-valued `#define AUDIT_*` constants. Expression-valued defines
    /// (`AUDIT_ARCH_X86_64 (EM_X86_64|...)`) and hex-valued defines
    /// (`AUDIT_STATUS_ENABLED 0x0001`) are SKIPPED, not errors - both exist
    /// in the real file, so a scan that errored on them could never parse the
    /// pinned source at all, and a scan that included hex would inflate the
    /// count past 199.
    #[test]
    fn parse_defines_real_kernel_header_known_answers() {
        let d = parse_defines(KERNEL_AUDIT_H).expect("kernel audit.h parses");
        assert_eq!(d.len(), 199, "kernel audit.h decimal define count");
        assert_eq!(d["AUDIT_USER"], 1005);
        assert_eq!(d["AUDIT_LOGIN"], 1006);
        assert_eq!(d["AUDIT_SYSCALL"], 1300);
        assert_eq!(d["AUDIT_KERNEL"], 2000);
        assert_eq!(d["AUDIT_BPF"], 1334);
        assert!(
            !d.contains_key("AUDIT_ARCH_X86_64"),
            "expression-valued defines must be skipped, not parsed"
        );
        assert!(
            !d.contains_key("AUDIT_STATUS_ENABLED"),
            "hex-valued defines must be skipped (decimal-token contract)"
        );
    }

    fn tab(base: &[(&str, &str)], apparmor: &[(&str, &str)]) -> Typetab {
        Typetab {
            base: base.iter().map(|(c, n)| entry(c, n)).collect(),
            apparmor: apparmor.iter().map(|(c, n)| entry(c, n)).collect(),
        }
    }

    fn defines(pairs: &[(&str, u32)]) -> BTreeMap<String, u32> {
        pairs.iter().map(|(k, v)| (k.to_string(), *v)).collect()
    }

    /// Precedence: audit-records.h resolves what it defines; the kernel
    /// header resolves the rest. Both tables resolve through the same rules.
    #[test]
    fn resolve_prefers_audit_records_then_falls_back_to_kernel() {
        let t = tab(
            &[("AUDIT_X", "X"), ("AUDIT_Y", "Y")],
            &[("AUDIT_AA", "APPARMOR")],
        );
        let records = defines(&[("AUDIT_X", 5), ("AUDIT_AA", 1500)]);
        let kernel = defines(&[("AUDIT_Y", 7)]);
        let derived = resolve(&t, &records, &kernel).expect("resolves");
        assert_eq!(derived.base, defines(&[("X", 5), ("Y", 7)]));
        assert_eq!(derived.apparmor, defines(&[("APPARMOR", 1500)]));
    }

    /// A referenced constant defined in BOTH sources with DIFFERENT numbers
    /// is a hard error naming the constant - the tool must never silently
    /// prefer one source.
    #[test]
    fn resolve_conflicting_definition_is_a_hard_error() {
        let t = tab(&[("AUDIT_X", "X")], &[]);
        let records = defines(&[("AUDIT_X", 5)]);
        let kernel = defines(&[("AUDIT_X", 6)]);
        let err = resolve(&t, &records, &kernel)
            .expect_err("a cross-source number conflict must be a hard error");
        assert!(
            err.contains("AUDIT_X"),
            "the error must name the conflicting constant: {err:?}"
        );
    }

    /// Defined in both sources with the SAME number is fine (the common case:
    /// audit-records.h re-states many kernel constants verbatim).
    #[test]
    fn resolve_same_number_in_both_sources_is_ok() {
        let t = tab(&[("AUDIT_X", "X")], &[]);
        let records = defines(&[("AUDIT_X", 5)]);
        let kernel = defines(&[("AUDIT_X", 5)]);
        let derived = resolve(&t, &records, &kernel).expect("agreeing sources resolve");
        assert_eq!(derived.base, defines(&[("X", 5)]));
    }

    /// A referenced constant defined in NEITHER source is a hard error naming
    /// the constant, never a silent skip.
    #[test]
    fn resolve_missing_constant_is_a_hard_error() {
        let t = tab(&[("AUDIT_X", "X"), ("AUDIT_NOSUCH", "NOSUCH")], &[]);
        let records = defines(&[("AUDIT_X", 5)]);
        let kernel = defines(&[]);
        let err = resolve(&t, &records, &kernel)
            .expect_err("an unresolvable constant must be a hard error, not a skip");
        assert!(
            err.contains("AUDIT_NOSUCH"),
            "the error must name the unresolvable constant: {err:?}"
        );
    }

    /// The conflict check is scoped to REFERENCED constants: a number
    /// disagreement on a constant no `_S` row references (range markers such
    /// as `AUDIT_LAST_USER_MSG2`) must NOT fail resolution.
    #[test]
    fn resolve_ignores_conflicts_on_unreferenced_constants() {
        let t = tab(&[("AUDIT_X", "X")], &[]);
        let records = defines(&[("AUDIT_X", 5), ("AUDIT_LAST_MARKER", 2999)]);
        let kernel = defines(&[("AUDIT_LAST_MARKER", 3000)]);
        let derived = resolve(&t, &records, &kernel)
            .expect("an unreferenced-constant conflict must not fail the gate");
        assert_eq!(derived.base, defines(&[("X", 5)]));
    }

    /// FULL-PIPELINE KNOWN-ANSWER on the real fixtures: parse both number
    /// sources, parse the typetab, resolve - the derived tables must carry
    /// EXACTLY 189 + 8 entries, every AppArmor name stays out of the base
    /// table, and the 60 kernel-only constants resolve (spot-pinned:
    /// SYSCALL/KERNEL/USER/DAEMON_START from the kernel header;
    /// USER_AUTH/DAEMON_ROTATE from audit-records.h). Source attributions
    /// verified mechanically against the fixtures (adversarial-test review
    /// round 1: DAEMON_START was mislabeled records-resolved; it is defined
    /// ONLY in linux-v6.6/audit.h:82 - AUDIT_FIRST_DAEMON is the sole 1200
    /// in audit-records.h and is a range marker, not DAEMON_START.
    /// DAEMON_ROTATE 1205 is the swapped-in second records-only witness:
    /// defined in audit-records.h, absent from the kernel header, referenced
    /// by the typetab).
    #[test]
    fn resolve_real_fixtures_yields_189_base_and_8_apparmor_numbers() {
        let t = parse_typetab(MSG_TYPETAB).expect("typetab parses");
        let records = parse_defines(AUDIT_RECORDS).expect("records parse");
        let kernel = parse_defines(KERNEL_AUDIT_H).expect("kernel parses");
        let derived = resolve(&t, &records, &kernel).expect("all 197 names resolve");

        assert_eq!(derived.base.len(), 189);
        assert_eq!(derived.apparmor.len(), 8);
        assert_eq!(derived.base["USER"], 1005, "kernel-header-resolved");
        assert_eq!(derived.base["SYSCALL"], 1300, "kernel-header-resolved");
        assert_eq!(derived.base["KERNEL"], 2000, "kernel-header-resolved");
        assert_eq!(derived.base["DAEMON_START"], 1200, "kernel-header-resolved");
        assert_eq!(derived.base["USER_AUTH"], 1100, "audit-records-resolved");
        assert_eq!(
            derived.base["DAEMON_ROTATE"], 1205,
            "audit-records-resolved"
        );
        assert_eq!(derived.apparmor["APPARMOR"], 1500);
        assert_eq!(derived.apparmor["APPARMOR_KILL"], 1507);
        assert!(
            !derived.base.keys().any(|n| n.starts_with("APPARMOR")),
            "no AppArmor name may leak into the base table"
        );
    }
}
