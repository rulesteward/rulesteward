# rulesteward — v1 design

`rulesteward` is an `audit2why`/`audit2allow` equivalent for host policy
systems. fapolicyd is its first domain.

This document is the hand-off from research to implementation. It is written to
be sufficient on its own: every constraint below is stated in full, with a
citation to the research document it came from, so nothing here requires opening
another repository to act on. Citations of the form `log-format.md:313` refer to
`docs/grammar/` in the companion research repository, which holds the measured
behavioural spec of fapolicyd on Rocky 8, 9 and 10.

Nothing in this document was assumed. The research it summarises ran six
read-only verification gates over three container releases and three VMs, and
landed 762 rule-grammar verdicts with zero disagreements between predicted and
observed behaviour.

---

## 1. What v1 is

`rulesteward` is a family tool, not a fapolicyd tool that might one day grow.
Every use of it is spelled `rulesteward <domain> <action>`, and the top level
stays open for `selinux`, `apparmor` and whatever follows. v1 ships exactly one
domain and one action:

```
rulesteward fapolicyd analyze
```

It reads fapolicyd denial records on stdin and writes fapolicyd rules or
`fapolicyd-cli` commands on stdout. It is the audit2allow half only.

**Non-goals for v1**, named so re-entry is cheap:

- no `rules.d` or `compiled.rules` reading, and therefore no audit2why (§2, D3)
- no journald or auditd input
- no `--apply`; the tool never mutates anything
- no RPM awareness
- no generalisation beyond the exact path in the record
- no JSON output
- no filter-subsystem support

The one thing v1 *does* touch on the filesystem is `fapolicyd.conf`, and only to
read `syslog_format`. That is decision D1, and §2 explains why it is worth the
scope it costs.

---

## 2. The three decisions

These were the open questions the research handed to design. They are settled.

### D1 — truncation detection reads `fapolicyd.conf` by default

v1 is therefore **not** a pure text transform, which is a deliberate reversal of
the original scope.

The reason is that truncation is the tool's most dangerous failure mode and the
alternative detection is weak. A record is capped at 511 payload bytes with no
marker, no ellipsis and no error (`log-format.md:313`). The captured long-path
denial lost both `ftype=` and `trust=` *and* had its `path=` value cut
mid-string, while still looking like a well-formed record. A tool that turns
`path=` into `fapolicyd-cli --file add` without detecting that will trust a
prefix of a real path — a file that either does not exist, or, worse, does.

The daemon's `syslog_format` names the fields and their order
(`log-format.md:18`). Comparing that list against the record is the only strong
truncation test available. The length heuristic alone has a known false
negative: `log_it()` stops the moment a field does not fit, so a record can lose
its trailing field and still end below the cap, indistinguishable from a
legitimately short record. That gap is exactly what reading the conf closes.

The cost is bounded — one file, one key, read in the binary crate only (§3), with
a documented degradation path when the read fails (§6).

### D2 — one framing-tolerant stdin reader

v1 accepts denial records on stdin regardless of framing. It strips an optional
leading prefix, strips ANSI escapes, and filters on `dec=` beginning with
`deny`. This covers `--debug-deny` on all three releases, full `--debug`, and
syslog text, at the cost of one prefix-stripping stage that has to exist anyway
because Rocky 8 and Rocky 9/10 do not frame the same way (`differences.md:91`).

Journald is out. It is a second input path with its own framing and its own
process access, and it buys nothing that a pipe does not.

### D3 — the audit2why half is out of v1

Explaining *which rule* denied means reading the loaded rules, and the daemon
never reads `rules.d/` — it reads `/etc/fapolicyd/fapolicyd.rules` first and
only falls back to `compiled.rules` (`matching-semantics.md:167`). Reproducing
what actually loaded therefore means reproducing `fagenrules`: its `ls -1v`
natural sort, its rule that an unprefixed file sorts last, and its fatal
`%set` redefinition. That is a subsystem, not a feature.

What survives into v1 is the warning. A rule written into `rules.d/` on a host
that still has a legacy monolithic `fapolicyd.rules` has **zero effect and
produces no diagnostic at all** — the daemon starts cleanly and enforces the
other file. v1 emits that warning as text alongside any rule it suggests,
because it costs nothing and prevents a silent no-op.

---

## 3. Architecture

A Cargo workspace, built for `x86_64-unknown-linux-musl` so the result is a
static binary with no runtime dependencies.

```
crates/rulesteward/        bin — the ONLY crate permitted fs/io/env/clock
crates/fapolicyd-model/    pure data types, zero dependencies
crates/fapolicyd-parse/    &[u8] -> Record
crates/fapolicyd-policy/   Record -> Suggestion
crates/fapolicyd-emit/     Suggestion -> Vec<u8>
crates/fapolicyd-analyze/  pure pipeline over the above
```

The dependency graph is strictly one-directional and acyclic.
`fapolicyd-model` has no external dependencies at all.

Every crate except the binary is a pure function of its input. They carry
`#![forbid(unsafe_code)]` and `#![deny(clippy::print_stdout,
clippy::print_stderr)]`, and diagnostics are **returned as data, never printed**.
The lints are the enforcement; purity that is only a convention does not hold.

D1's config read happens in the binary and is handed to the libraries as an
already-parsed value, so reading the conf does not move the purity boundary.

The crate names are domain-namespaced, which is what leaves room for a
`selinux-*` family beside them. Inside the binary, keep the same seam cheaply:
`src/main.rs` parses the domain and dispatches, and `src/fapolicyd/` holds
everything fapolicyd-specific. **No trait, no registry, no plugin loader.** One
domain does not justify an abstraction. Adding a second domain should mean
adding a module and one match arm, and that is all the future-proofing worth
buying now.

### Amended at implementation time: one crate, six modules

v1 ships **one** crate whose module tree is exactly the crate tree above:

```
src/main.rs            bin - the ONLY fs/io/env/clock
src/fapolicyd/mod.rs   the seam that becomes crates/fapolicyd/
src/fapolicyd/{model,parse,conf,policy,emit,analyze}.rs
```

Six manifests to enforce a boundary that one crate can state as a lint is a cost
without a matching benefit while there is one domain. `Cargo.toml` carries
`unsafe_code = "forbid"` and `clippy::print_stdout`/`print_stderr = "deny"`
crate-wide, which is *stricter* than the per-crate scheme above because it also
covers `main.rs`; the binary writes through `io::stdout().lock()` at one site
rather than holding an escape hatch. `[workspace]` is declared from the first
commit so members can be added without restructuring.

The intended end state is a top-level `fapolicyd/` crate holding the domain
subcrates. Splitting then is a move, not a redesign, because the module names and
the dependency direction already match.

---

## 4. The record model

A denial record is `name=value` pairs joined by single spaces, with the subject
side and the object side separated by a bare ` : ` — space, colon, space, with
no field name (`log-format.md:52`).

Nine constraints, each of which breaks a naive parser.

**Values are bytes, not `String`.** The escaper passes every byte >= 128 through
raw (`log-format.md:96`), so a non-UTF-8 path reaches the parser verbatim. Values
must be `Vec<u8>`/`&[u8]` end to end, with lossy conversion at display time only.
This propagates through model, parse, policy and emit, which is why it is much
cheaper to get right before any code exists. (Honest caveat: the research stages
only valid UTF-8, so this is derived from the `sh_set` rules rather than captured
directly — but the rules are unambiguous.)

**Subject and object are two separate maps, never one merged map.** `trust`
appears on **both sides of the same record** and the two routinely disagree — a
trusted `runuser` executing an untrusted file is the common case
(`log-format.md:189`). A parser that scans for `trust=` without tracking which
side of the colon it found does not merely lose precision, it inverts the
answer: it reads the subject's `trust=1`, concludes the object is trusted, and
emits an allow rule where a trust entry was correct.

**No field is required.** `syslog_format = dec,:,path` is a valid configuration
the daemon starts on, and it emits `dec=deny_audit : path=/tmp/untrusted-ls` —
no `perm`, no `exe`, no `trust`, no `rule`. A parser that rejects that is
rejecting well-formed input. Parse whatever is present and let the decision layer
report what it could not do for want of a field. `path` is the only field the
tool genuinely cannot act without, and even then the right response is a
diagnostic, not a parse failure.

**Split key from value on the first `=` only.** `:`, `=`, `#`, `%`, `,` and raw
UTF-8 are not escaped and appear literally inside values (`log-format.md:96`).

**Splitting the record on ` : ` is sound, and the reason matters.** A literal
space is always escaped, so an unescaped space is always a delimiter — a path
containing ` : ` emits as `\ :\ ` (`log-format.md:126`). This is a derived
consequence of the escaping table, verified byte-identical on 8/9/10, not a
documented guarantee. It deserves a comment at the split site so nobody
"simplifies" it later.

**Absence of ` : ` is a reachable configuration, not a parse failure.**
`MAX_SYSLOG_FIELDS` is 21, and `parse_syslog_format` stops at the limit while
still returning success — silently, with nothing logged and `--check-config`
passing. Twenty-one subject-side names push the colon to field 22, which is
never parsed, so `parsing_obj` is never set and **every record the daemon emits
is subject-side only, with no object fields at all** (`syslog-format.md:131`).

**`uid=` and `gid=` are comma-separated lists on Rocky 9/10** — the whole
credential set, capped at 32 — and scalar on Rocky 8 (`log-format.md:177`).
`int(record["uid"])` throws on 9/10. Parse as a list on every release.

**Sentinels differ by release** (`differences.md:121`):

| | Rocky 8 | Rocky 9 / 10 |
|---|---|---|
| unavailable `auid`/`sessionid`/`pid`/`ppid` | `-2` | `0`, ambiguous with a real zero |
| unavailable `uid` / `gid` | `-2` / `?` | `?` / `?` |
| object attribute with no value | `?` | `?` |
| value the escaper could not handle | `??` (replaces the whole value) | `??` |

`uid=0` means root on every release — UID is excluded from the zero-sentinel
branch. An unset `auid` renders `4294967295`, not `-1`
(`matching-semantics.md:226`).

**Field inventory** (`syslog-format.md:10`). Always available: `rule`, `dec`,
`perm`, `:`. Subject side only: `auid`, `uid`, `sessionid`, `pid`, `ppid`,
`gid`, `comm`, `exe`. Object side only: `path`, `dir`, `device`, `ftype`,
`mode`, `sha256hash` (all releases) or `filehash` (9/10 only). Both sides:
`trust`. Note that object-side `dir=` holds the **full file path**, not a
directory. `perm=` is only ever `open` or `execute`.

---

## 5. Input pipeline

One reader on stdin, tolerant of framing (D2).

**Strip the prefix by anchoring on `]: `, never on a fixed byte count.** The
`--debug-deny` prefix is `MM/DD/YY HH:MM:SS [ \033[34mDEBUG\033[0m ]: `, and its
visible width varies with the log level — DEBUG 29 columns, INFO 28, NOTICE 30,
WARNING 31 — while `%x` is `LC_TIME`-dependent (`log-format.md:62`). **Rocky 8
emits no prefix at all** (`differences.md:91`). Under syslog the prefix is an
rsyslog timestamp, a hostname, and `fapolicyd[<PID>]: ` — and that PID is the
*daemon's*, not the denied process's, which is `pid=` inside the record
(`log-format.md:231`).

**Strip ANSI escapes** before parsing.

**Drop the deprecation notice.** Rocky 9/10 emit one `SHA256HASH ... deprecated`
NOTICE per daemon start, unconditionally, regardless of the user's rules
(`log-format.md:265`). It is not a denial and not a problem to report.

**Filter on `dec=` beginning with `deny`.** "It appeared in the stream" is not a
denial test. A default install emits only `deny_audit`, but a corpus with plain
`deny`, `deny_syslog` and `deny_log` rules produces all four, and full `--debug`
additionally carries `dec=no-opinion` records that are **not** denials
(`denial-shapes.md:23`). `rule=0` pairs with `no-opinion` and means *no rule
matched* — it is not rule index 0, and must never be parsed as a valid index.
It cannot appear in `--debug-deny` at all: `process_event()` only logs once the
result carries the DENY bit, which `NO_OPINION` lacks. It becomes reachable the
moment full `--debug` or journald input is added, which is why the filter is
written now rather than when it is needed.

**Records are one per line.** Newlines inside values become `\012`
(`log-format.md:96`). There is exactly one exception, and it is §6's corrupted
record.

**Do not add a syslog input mode expecting it to be useful.** Only decisions
carrying the syslog bit reach `/var/log/messages`: `deny_audit` and bare `deny`
produce **nothing** there (`log-format.md:231`) — and `deny_audit` is the
default. Recorded here so the discovery is not made twice.

---

## 6. Truncation and confidence

D1's ladder. It degrades; it never fails the run.

1. **Read `/etc/fapolicyd/fapolicyd.conf` and take `syslog_format`.**
   `--conf <path>` overrides the location. `--no-conf` disables the read — which
   is necessary when analysing a log captured on a different host, because
   validating against the wrong host's format is worse than validating against
   none. `--no-conf` also disables step 3, so step 4 is then the only test.

2. **Expect the default read to fail for an ordinary user.** The packaged
   `/etc/fapolicyd` is mode `750 root:fapolicyd` (`daemon-config.md:60`), so any
   user outside that group gets `Permission denied`. Fall back to step 4 with a
   diagnostic. Never exit on this.

3. **With a format in hand:** a field named in `syslog_format` but absent from
   the record is truncation. Only the first 21 names count — `MAX_SYSLOG_FIELDS`
   — because the daemon never emits the rest (§4), and a `:` that falls past the
   cap means every record is subject-side only, which is not truncation.

4. **Without one:** a record whose payload sits at the 511-byte boundary is
   truncation. `WB_SIZE` is 512 with `working_buffer[WB_SIZE-1] = 0`, and the cap
   applies to the record, not the line — the prefix sits outside it
   (`log-format.md:313`). This test has the false negative described in §2 and is
   the fallback for that reason.

5. **A record judged truncated produces a diagnostic and no emission.** Not a
   guess, not a partial suggestion. The failure being prevented is emitting
   `--file add` for a prefix of a real path.

Three further input hazards belong in the same layer.

**`--check-config` is not a validity oracle.** It validates `fapolicyd.conf`
only — not rules, not `syslog_format`, not trust backend names — and can return
0 on a config the daemon will not start on (`emitter-constraints.md:290`). Never
present it to the user as proof of anything.

**`permissive` does not suppress denial records.** Rules are still evaluated and
still logged; only the kernel response changes. A denial record on a permissive
host means *"would have been denied"*, which is a materially different statement
from *"was blocked"* — and the record itself cannot tell you which
(`daemon-config.md:56`).

**A permissive capture reports the pre-exec image after a denied exec.** Every
record a process emits after a *denied* execute still carries the old image as
`exe=`: the daemon's subject cache holds it until the exec is permitted, and
permissive mode never permits it. Measured 2026-09-06 on Rocky 8 (1.3.2), 9 and
10 (1.4.5), in containers and on VMs: running the loader as `tester` through
`runuser` logged `exe=/usr/sbin/runuser` on the loader's execute denial and on
the 9 to 23 opens that followed; once the execute was allowed, the same opens
logged `exe=/usr/lib64/ld-linux-x86-64.so.2`, and every
`allow perm=open exe=/usr/sbin/runuser : path=...` rule v1 had emitted stopped
matching. A `Rule` derived from such a record is scoped to the wrong `exe`:
applying it clears the execute denial and a fresh set of denials appears under
the new one. v1 emits the record's own `exe` and does not rewrite it (§7: every
emitted attribute carried that value in the record), so the answer is to re-run
on the next capture. Parked as #12.

**`uid` or `gid` in `syslog_format` is a host hazard, reported from the conf
read.** `format_value`'s uid/gid list branch dereferences `subj` with no NULL
check, which a unit test shows dying on SIGSEGV on Rocky 9/10; Rocky 8 cannot
reach that branch and instead leaves the buffer unterminated, so the field
carries heap bytes (`syslog-format.md:66`). A live daemon with `gid` in the
format stayed up under probe, so this is a warning, not a refusal. The tool
reports it once per run and continues.

**Unrecognisable field names mean the daemon needs a restart.** After a failed
rules reload, `destroy_rules` frees every field name while leaving `num_fields`
non-zero, so `log_it` reads each field *name* from freed memory. Values survive
and names do not, producing `<garbage>=deny_audit`. The garbage differs per
release and per run, so it cannot be matched on. The daemon in this state is
fully operational and **allowing everything**, so the right report is "restart
the daemon", never "the stream went quiet". An earlier claim that the Rocky 8
record split across several lines is retracted at `log-format.md:301`: every one
of the 416 post-reload records is on its own line, so one record per line holds
here too (`emitter-constraints.md:67` still carries the stale text). The garbage
reliably contains control or high bytes, which is what the tool tests for; it
runs that test **before** the `dec=` filter, because a record whose names are
gone reads as `no-opinion` and would otherwise be dropped in silence.

---

## 7. Policy — the decision table

Three arms, not two. The parked design's "`trust=0` → trust the file, non-zero →
emit a rule" treats `trust=9` as trusted and produces an allow rule for a file
whose trust state is simply unknown.

| object `trust` | meaning | v1 output |
|---|---|---|
| `0` | untrusted | `fapolicyd-cli --file add <path>` **and** `fapolicyd-cli --update` |
| `1` | trusted, so a rule denied it | scoped allow rule |
| `9` | trust attribute unavailable | diagnostic only, emit nothing |
| absent | `trust` not in `syslog_format` | rule, with a warning |
| any, `path=??` | the daemon could not encode the path (§4) | diagnostic only, emit nothing |
| any, control byte in a value to be emitted | newline or tab in the true path | diagnostic only, emit nothing |
| `1`, path contains a space or `:` | unrepresentable in a rule (§8.1) | diagnostic only, emit nothing |
| absent, path contains a space or `:` | unrepresentable in a rule (§8.1) | trust entry instead |

The last four rows were added at implementation time. `path=??` and the control
byte are refusals: a control byte splits the emitted line, breaking §9's promise
of bare pipe-safe stdout, and cannot be a `fapolicyd.trust` record. A space in a
path is fine for a trust entry, because the trust file is parsed right to left
(`trust-db.md:78`), and only rules refuse it.

**The rule v1 emits** is `allow perm=<perm> exe=<exe> : path=<path>`, with `all`
on the subject side when `exe=` is absent or `?`. Every attribute emitted must
have carried a real value in that record, because an attribute the event cannot
supply makes the rule broader, not narrower (§8.1). Rules are keyed on
`(perm, exe, path)`; trust entries on `path` alone.

Object trust is `obj ? (obj->val ? 1 : 0) : 9` (`log-format.md:189`). The
`absent` row matters more than it looks: the *compiled* default `syslog_format`
has no `trust` field at all, and only the shipped conf adds it — so a host with a
deleted or minimal conf emits records with no `trust`, which is exactly the case
where the trust-vs-rule decision has no input (`emitter-constraints.md:302`). A
scoped rule never widens global trust, so it is the safe default there.

**Subject trust is advisory only.** It takes a different path,
`subj ? subj->uval : 0`, and has **no sentinel** — an unavailable subject trust
prints as `0`, indistinguishable from genuinely untrusted (`log-format.md:189`).
No branch may depend on telling those apart.

**One inconsistency in the research, flagged rather than resolved here.**
`edge-cases.md:64` marks `trust=9` *unreachable by design* — every failure path
in `get_obj_attr` collapses to `trust=0`, and the only route to a NULL return is
`object_add()` failing a 24-byte `malloc`, which signals memory exhaustion rather
than an access shape. `log-format.md:189` presents it as a live sentinel.
Implement the arm; do not expect to see it. If it ever appears, the host is out
of memory and that is the finding.

**The aggregation key includes `perm`.** One user action produces two records:
executing a file emits both a `perm=execute` and a `perm=open` event, which can
match different rules and carry different `dec=` values for the same path
(`denial-shapes.md:90`). Aggregating on path alone collapses two genuinely
distinct denials into one and loses the `perm` the emitted rule depends on. A
path-only key is correct for the *trust* output — one trust entry covers both
perms — but the occurrence count will read low unless that merge is deliberate.

---

## 8. Emitter constraints

Everything `rulesteward` emits is a shell command or a rule that a human will
paste into a policy file. The consequences of getting it wrong are not cosmetic:
a malformed rule abandons the **entire** rule file and calls `exit(1)`, with no
skip-and-continue and no partial load, so appending one bad rule means fapolicyd
fails to start on next boot (`emitter-constraints.md:14`).

### 8.1 Rules

- **Always emit colon format. Never emit original format.** In original format a
  name the subject table does not hold is retried against the **object** table
  and assigned there, with the return discarded and nothing logged. `trust`,
  `dir` and `ftype` are subject attributes in colon format and object attributes
  in original format, so `allow uid=0 trust=1` loads as a rule constraining the
  trust of the *file*, not the process (`emitter-constraints.md:165`). The only
  signal is the absence of a colon on the line.
- **Refuse to emit a rule for any path containing a space.** Space is the token
  delimiter and there is no quoting mechanism (`emitter-constraints.md:194`).
  Emit a trust entry instead, or report the path as unrepresentable. Object
  values are also never trimmed, so a stray space survives into the stored value
  and that value can never match — emit no leading or trailing whitespace,
  anywhere.
- **Refuse to emit a rule for any path containing `:`.** Format selection is
  `strchr(buf, ':')` on the raw line, before tokenizing, so a colon inside a path
  flips the whole rule into the other format.
- **Never emit `mode=`.** It is never evaluated and always matches, so
  `: mode=0755` is exactly `: all` — confirmed by probe, where adding it took
  Rocky 9 from 1 denial to 144. On **Rocky 8 it crashes the daemon**: the `FMODE`
  slot is uninitialised heap and evaluation dereferences it
  (`emitter-constraints.md:219`).
- **Hard-cap emitted attributes at 8 per side.** `MAX_FIELDS` is 8 on Rocky 8 and
  11 on Rocky 9/10, and there is no bounds check on the write path — the guard
  lives in `sanity_check_node`, inside `#ifdef DEBUG`, compiled out of every
  shipped build. Excess attributes are silently **dropped and the rule loads
  broader than written**; past a certain depth it segfaults the daemon at match
  time. There is no diagnostic and no CLI readback that would show it
  (`emitter-constraints.md:120`).
- **A rule can load broader than written, silently, and nothing fails.** A bad
  `%set` reference, an unknown username, an invalid `pattern` value or `trust=7`
  logs an error, **drops that one attribute**, and lets the rule load with fewer
  constraints — `assign_subject` and `assign_object` return 0 or 1, never 3, yet
  every call site tests `== 3` or discards the return. The only backstop fires
  at startup, when the damage empties a side entirely; on the reload path there
  is no backstop at all (`emitter-constraints.md:22`).
- **Tell the user to validate before reloading, and to check the daemon
  afterwards.** `fapolicyd-cli --reload-rules` reports `Fapolicyd was notified`
  and exit 0 both when the reload segfaults the daemon and when it leaves a
  daemon up that answers ALLOW to everything. Exit 0 means the FIFO write
  succeeded and nothing more (`emitter-constraints.md:22`).
- **Every attribute is advisory, so never rely on one to narrow a rule** unless
  it has been seen carrying a value in a real denial record for that event class.
  The evaluator is fail-open by construction: `check_subject` and `check_object`
  both skip a constraint whose value the event could not supply, so an
  unavailable attribute makes the rule *broader*, never narrower
  (`emitter-constraints.md:104`). `filehash` is the only attribute that fails
  closed.
- **Portable spellings only** (`emitter-constraints.md:211`): `sha256hash`, not
  `filehash` (which is 9/10-only). There is no portable subject `device`. There
  is no portable `pattern=normal` — it is rejected on Rocky 8.
- **Values that parse but can never match** (`emitter-constraints.md:219`,
  `matching-semantics.md:62`): `comm=` longer than 15 characters (kernel
  `TASK_COMM_LEN`); uppercase hex in a hash; `auid=-1` on 9/10, where the unset
  value is `4294967295`; `trust=yes`, which silently becomes `trust=0` on both
  sides — only `0` and `1` are valid, and `trust=2` is a parse error, not a
  wildcard.
- **Two attribute names mean something other than they look**
  (`emitter-constraints.md:219`): `dir=` holds a full file path, not a directory,
  and is a prefix test; `device=` is a `/dev` node path that only resolves for
  block devices, and everything on tmpfs, overlay or proc yields the literal `?`.
- **`*` is a literal.** There is no globbing and no operators — only `=`, no
  `!=`, no comparison, no regex. For prefix semantics use `dir=`, which is
  exactly `path=` compared with `strncmp`, and nothing else
  (`emitter-constraints.md:203`).
- **Do not emit these when targeting Rocky 8** (`emitter-constraints.md:236`):
  `dir=execdirs`, `dir=systemdirs`, `dir=untrusted`, `exe=untrusted`,
  `pattern=normal`, and any `gid=%set`.
- **`ftype=` values are not portable across releases** and must be taken from a
  capture on the target release (`matching-semantics.md:148`).
- **`all` means "add no constraint"**, not "match anything"
  (`matching-semantics.md:211`), and on Rocky 9/10 subject attribute **order
  changes evaluation** (`matching-semantics.md:92`).
- **Emit a trailing newline.** On Rocky 8 a `rules.d/` component file that does
  not end with a newline has its last line glued to the next file's first
  (`emitter-constraints.md:241`). The rest of §10 there — `ls -1v` natural sort
  so `2-x` precedes `10-x`, unprefixed files sorting last, and a `%set`
  redefinition being fatal, so never emit a `%languages` definition — matters
  only once something installs rather than suggests, and is parked with D3 (§11).
- **Warn about `rules.d/`.** Emit the D3 warning with any rule: on a host with a
  legacy `/etc/fapolicyd/fapolicyd.rules`, a rule dropped into `rules.d/` is
  inert with no diagnostic, even after `fagenrules` runs
  (`emitter-constraints.md:79`). And there is no CLI way to check what loaded —
  `fapolicyd-cli --list` does not parse rules at all, it echoes lines with a
  counter and will happily print an attribute the parser dropped
  (`edge-cases.md:121`). The same note also says the file must sort before the
  file holding the rule that denied, because `rules.d/` merges in filename order
  and the first match wins: measured 2026-09-06 on Rocky 8, 9 and 10, a rule at
  `50-` was inert against a `30-patterns.rules` denial and the identical file at
  `00-` took effect.

### 8.2 Quoting

Values arrive already escaped, and passing them straight into an emitted shell
command is wrong. The escaping table is (`log-format.md:96`):

```c
static const char sh_set[] = "\"'`$\\!()| ";
```

plus every byte below 32 rendered as backslash and three octal digits. That set
**omits** `;`, `&`, `<`, `>`, `*`, `?`, `[`, `]`, and it encodes newline as
`\012` rather than quoting it.

The emitter must therefore **unescape to the true byte path and then apply its
own quoting**. That requires an `unescape` step in the parse layer, and it is the
inverse of a specific, version-checked `sh_set` — worth a dedicated test against
the captured fixtures.

The same unescaping applies to the subject side. `exe=` is escaped exactly like
`path=` — confirmed by capture as `exe=/tmp/gaps/spaced\ bash`
(`denial-shapes.md:48`) — so unescaping belongs in the shared attribute accessor,
not on an object-specific path.

### 8.3 Trust commands

- **`--file add` alone is not enough.** It writes a text file and contacts no
  daemon; taking effect on a running daemon requires a following
  `fapolicyd-cli --update`. Emit both (`emitter-constraints.md:257`).
- **`--file add` rewrites the destination file** with `"w"`, destroying any
  hand-written comments in `fapolicyd.trust` or a `trust.d/` fragment. Never
  advise a user to annotate those files (`emitter-constraints.md:265`).
- **Exit codes are not comparable across releases.** Rocky 9/10 return ten
  structured codes; Rocky 8 returns only 0/1, and code `9` ("nothing to do",
  e.g. already trusted) is reported as `1` — indistinguishable from a real
  failure (`emitter-constraints.md:271`). Any future `--apply` must not treat a
  Rocky 8 exit `1` as proof of error.
- **`--trust-file` is unsafe on Rocky 8.** Rocky 9/10 reject `/`, `.` and `..` in
  the fragment name; Rocky 8 does not, so an unsanitised name is a path
  traversal. Never pass a derived name through on Rocky 8
  (`emitter-constraints.md:280`).

---

## 9. CLI and output contract

The command surface is `rulesteward <domain> <action> [flags]`. v1 exposes
exactly `rulesteward fapolicyd analyze`. These are commitments, cheap now and
expensive to retrofit:

- **No bare-action forms and no default domain.** `rulesteward analyze` is not
  valid and must never become an alias, or the domain slot is spent.
- **No aliases or shortenings of `fapolicyd`**, so a future domain cannot collide
  with a prefix people got used to typing.
- **Domain-specific flags hang off the domain, not the root.** `--conf` and
  `--no-conf` (§6) belong to `fapolicyd`, declared there and accepted before or
  after the action, so a second action inherits them. v1 defines **no global
  flags** — it has no genuinely cross-domain option yet. Reserve the root for
  `--help` and `--version`.
- `rulesteward` with no arguments lists the domains it knows and exits 1.

What the **root** promises, and must keep promising for every domain added
later:

- results on stdout as bare lines, pipe-safe, no commentary
- diagnostics on stderr
- exit `0` success, `1` usage or I/O error, `2` input consumed but unparseable.
  "Unparseable" means non-comment input arrived and no line yielded a single
  `name=value` field. A log full of allow records parses fine and exits `0`
  with nothing to suggest; usage errors are `1`, and `--help`/`--version` are
  `0`, so clap's own exit-2-on-usage default is remapped.

What the root does **not** promise is the shape of those lines. That is each
domain's business; for `fapolicyd` it is rules and `fapolicyd-cli` commands.

---

## 10. Test strategy

Golden tests against captured fixtures, run without root and without containers.
The research repository holds all of the following as git-tracked, stable
artifacts:

- `docs/grammar/spec/fapolicyd-grammar.json` (257K) — rule language, 23
  attributes, 37 errors, evaluation semantics, log record, trust db.
  `fapolicyd-conf.json` (75K) — 18 conf keys, startup phases, 40 conf errors.
  `fapolicyd-filter.json` (53K). Each has a draft-07 JSON Schema beside it.
- `docs/fixtures/raw/*.log` — 121 files, 3.8M of raw daemon stdout with ANSI
  intact and a `#` header block naming the distro, the fapolicyd NEVRA, the
  kernel and the active `syslog_format`. Roughly 7,840 `dec=deny*` records.
  `rocky8-base-edge-paths.log` is the escaping torture set: pathological
  filenames and the 511-byte cap.
- `docs/harvest/corpus/generated/manifest.jsonl` — 127 rule cases with
  per-release expected verdicts. `docs/fixtures/validation/results.json` — the
  762 measured rows.

Ignore `docs/harvest/cases/*.sh` and `docs/harvest/apply-*.py`; those are
spec-authoring tools, not consumables.

Per-crate unit tests cover the adversarial parse cases directly: the truncated
record, the subject/object `trust` disagreement, the `dec=,:,path` minimal
format, the no-colon record from §4, a `uid=` list, and the `sh_set` round trip
from §8.2.

**The coupling problem, settled.** The fixtures live in a private repository
behind a gitignored symlink, so public CI cannot see them. Both options are
taken, because they answer different questions:

- **Vendored subset**, `tests/fixtures/`, one capture per parser hazard, kept in
  sync by `xtask/sync-fixtures.sh` (`--check` fails on drift), plus hand-written
  cases for shapes no capture has as a clean record: the `dec,:,path` minimal
  format, the not-a-denial set, the 21-field no-colon record with duplicate
  names, and a `trust=1` / `trust`-absent pair. Golden tests over these run in
  public CI on every PR, including from forks. A sweep of all 121 logs found
  nothing sensitive to redact: no IPs, no home paths, no usernames, identity
  numeric only. The `# kernel=` and `# nevra=` headers are kept verbatim — the
  Rocky 8 log records the *host* kernel because the guest ran nested, which is
  itself a finding.
- **Full corpus**, behind `--features full-corpus`, reached through the symlink,
  local only. It has no expected output; it asserts that no capture panics, none
  exits outside 0/1/2, no denial record is dropped without a diagnostic, and
  every stdout line is something a user can paste.

Choosing the vendored slice is not cosmetic. The corrupted-record log's garbage
field names are in its **last** 416 records, so a fixture capped from the front
vendors only the clean prefix and tests nothing; the sync script takes that one
from the tail for exactly this reason. Lines starting with `#` are comments to
the tool, so a research capture whose interesting record only appears inside a
`# record:` annotation is not a fixture; the record is copied out by hand.

---

## 11. Parked for v2

- audit2why, in two parts:
  - mapping `rule=N` to the `rules.d/` file it came from and recommending a
    filename for the emitted rule (#11, the v2 half of it)
  - refusing to suggest at all for a `pattern=` or subject-only rule, such as the
    shipped `pattern=ld_so` deny (#10)
- rewriting `exe=` for records that follow a denied exec of the same `pid`
  (#12); needs #10 first, because under the shipped `pattern=ld_so` deny no
  `exe` would resolve anything
- journald input
- `--apply`
- JSON output
- generalisation beyond exact paths (`dir=` prefix suggestions)
- the fapolicyd filter subsystem
- the trust database beyond `--file add`
