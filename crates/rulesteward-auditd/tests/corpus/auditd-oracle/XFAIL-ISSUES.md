# Draft issue bodies for the 18 XFAIL product/oracle divergences

DRAFT ONLY. Nothing here has been filed. No GitHub issue, comment, or PR was
created or touched while producing this file. If these are approved, file the
"existing issue" ones as COMMENTS on the named issue (they extend an
already-open, already-scoped issue) and the "new issue" one as a fresh GitHub
issue.

Every finding below is grounded in `crates/rulesteward-auditd/tests/corpus/
auditd-oracle/{el8,el9,el10}.tsv` (identical on all three EL majors) and
exercised by a named `XFAIL` entry in `crates/rulesteward-auditd/tests/
auditd_corpus_oracle.rs`, so each is a live, mutation-gated regression pin, not
just a written note.

---

## Comment to add to #584 (auditd rules-file tokenization)

**Additional #584 divergences found by the Lane A (session 9k-1) differential
corpus, beyond the original quote-stripping report:**

1. **`-C` field-comparison quoting** (`rocky9-field-compare`,
   `-a always,exit -S execve -C 'uid!=euid' -k priv_escalation`): the same
   balanced-single-quote stripping that affects `-F` (parser.rs:277-287) also
   applies to `-C`'s operand tokens. Real `auditctl -R` rejects with
   `-C unknown field: 'uid` (the leading quote glues onto the field name,
   exactly as with `-F`); RuleSteward's parser strips the quotes and accepts.

2. **TAB tokenization** (`iss584-embedded-tab-glues-flag`,
   `iss584-all-tabs-separators`): `rulesteward_auditd::parser`'s tokenizer uses
   `str::split_whitespace()`, which treats a TAB byte identically to a space.
   Real `auditctl`'s `audit_strsplit` splits ONLY on the literal space byte
   (0x20); a TAB glues onto the adjacent token, and the resulting garbled token
   is silently rejected (rc 1, empty stdout/stderr, confirmed - see the
   "silent-rc1 blind spot" note below on why this is a REAL reject and not
   ambiguous: the line is `-w`/`-a`-shaped, so silence here is conclusive).
   RuleSteward accepts the collapsed, valid-looking rule instead. Suggested
   fix direction: the tokenizer needs to split ONLY on the literal space byte
   to match `audit_strsplit` exactly, not on any Unicode whitespace class.

3. **Backslash-escaped-space acceptance (the other direction: product is too
   STRICT)** (`iss584-backslash-escaped-space`,
   `-w /etc/my\ dir/file -p wa -k q2`): real `auditctl`'s `preprocess()`
   (`auditctl.c`) rewrites a backslash-escaped space to a sentinel byte pair
   BEFORE `audit_strsplit` runs, then restores it afterward in
   `postprocess()` - so this line parses and is accepted by the real daemon.
   RuleSteward's naive `split_whitespace()` tokenizer has no such
   preprocessing step and rejects the line on a stray trailing token. This is
   the mirror-image gap to (2): here the product needs to become MORE lenient
   (recognize the backslash-space escape), not less.

Corpus rows: `rocky9-field-compare` (existing scenario, re-grounded),
`iss584-embedded-tab-glues-flag`, `iss584-all-tabs-separators`,
`iss584-backslash-escaped-space`, `iss584-quoted-field-expr`.

---

## Comment to add to #601 (auditd permission-letter handling)

**Additional #601 divergence found by the Lane A (session 9k-1) differential
corpus:**

The original #601 finding was that real `auditctl` accepts UPPERCASE
permission letters (`-w /path -p WA`) where RuleSteward's `parse_perms` only
matches lowercase `rwxa` - a product-too-STRICT gap (tracked, still open;
corpus ids `iss601-uppercase-perm-all` / `iss601-uppercase-perm-mixed`).

This session's regrounding found the OTHER half of the same validation
surface, this time product-too-LENIENT: **`-F perm=` field-filter values are
not validated against the `rwxa` letter set at all.** `-a always,exit -F
perm=zz -S execve -k fpermbad` is rejected by the real daemon
(`Permission can only contain  'rwxa'`, loud and non-silent) but accepted by
RuleSteward (the `-F perm=` value is stored as an unvalidated string in
`parse_field_filter`). This is a DIFFERENT code path from the watch-flag `-p`
case (which correctly rejects an invalid letter today, see
`p-invalid-lower`/`p-invalid-upper` in the corpus, both non-divergent) - the
`-F` field-filter path has no equivalent validation.

Corpus row: `f-perm-invalid-letter`.

---

## Comment to add to #489 (auditd `-k` key handling)

**Additional #489 divergence found by the Lane A (session 9k-1) differential
corpus:**

The real daemon enforces a 256-byte cap on the `-k` key value
(`AUDIT_MAX_KEY_LEN`), measured empirically at the exact 256/257-byte boundary
(`iss489-key-at-cap-256` accepts, `iss489-key-over-cap-257` rejects silently).
RuleSteward's parser stores the `-k` value with no length check at all -
`key = Some(rest.next()...)` in `parse_watch_rule`/`parse_syscall_rule` never
validates length.

This session added a second, anti-monotone-length pair
(`k-cap-valid-longer-line` / `k-cap-invalid-shorter-line`) specifically to
close off a "reject on overall line length" workaround: the ACCEPT row's whole
LINE is longer (padded with extra, semantically inert `-F` filters) than the
REJECT row's whole line, so only the actual `-k` VALUE length can distinguish
them - a fix must check the key value itself, not the line.

Corpus rows: `iss489-key-over-cap-257`, `k-cap-invalid-shorter-line` (both
XFAIL); `iss489-key-at-cap-256`, `k-cap-valid-longer-line` (both already
correctly ACCEPT on both sides, confirming the boundary).

---

## Comment to add to #491 (auditd `-F` numeric field typing)

**No new finding beyond the original report** - this session's regrounding
simply re-confirmed the original `pers`/`devminor` non-negative-value
requirement empirically (`iss491-neg-pers`, `iss491-neg-devminor`, both still
XFAIL) and re-confirmed that `a0`-`a3` correctly accept a negative decimal
representation on both sides (`iss491-neg-a0`..`a3`, all four non-divergent).
Included here only for completeness of the corpus-to-issue mapping.

---

## New issue: `-S` syscall names are not validated against a known table

**Found by:** Lane A (session 9k-1) differential-corpus regrounding, corpus id
`s-unknown-syscall`. Not predicted in this lane's original divergence
estimate (13 lenient + 3 strict = 16); discovered empirically once the corpus
added a `-S` coverage row.

**Rule:** `-a always,exit -F arch=b64 -S totallynotasyscall -k sunknown`

**Real `auditctl -R` behavior:** rejects the line, silently (rc 1, empty
stdout AND stderr - confirmed on el8/el9/el10 alike). This is consistent with
`audit_name_to_syscall`'s lookup failing and the daemon's syscall-name
resolution path being one of the `audit_msg()`-routed diagnostics silenced
under `-R`'s `MSG_SYSLOG` mode (see `PROVENANCE.md`'s "MSG_SYSLOG-under--R
finding" for the general mechanism) - or possibly a path with no diagnostic at
all; the corpus does not by itself distinguish those two, only that the
result is REJECT.

**RuleSteward's behavior:** `parse_syscall_rule` in `parser.rs` pushes ANY
string as a syscall name with no validation against a known table:

```rust
for name in sc.split(',').filter(|s| !s.is_empty()) {
    syscalls.push(name.to_string());
}
```

So RuleSteward accepts a rule referencing a syscall name that does not exist
on any real kernel. Suggested fix direction: a per-architecture syscall-name
table (mirroring the existing per-field `FieldType` taxonomy's approach of
citing a specific `audit-userspace` source commit) that `parse_syscall_rule`
consults; this is architecture-dependent (`arch=b32` vs `arch=b64` changes
which names are valid), which is likely why RuleSteward's parser did not
attempt it initially - flagging that scope question for whoever picks this up
rather than prejudging it.

Corpus row: `s-unknown-syscall`.
