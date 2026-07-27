# `rs-oracle{8,9,10}` - the shared differential-oracle images

One image set carrying all three session-9k-1 oracles, built from
`dockerfiles/{8,9,10}/Dockerfile`:

| package | binary | lane |
|---|---|---|
| `audit` | `/usr/sbin/auditctl` | A (auditd rule-line parse oracle) |
| `systemd-udev` | `/usr/lib/systemd/systemd-sysctl` | B (sysctl.d merge oracle) |
| `sudo` | `/usr/sbin/visudo`, `/usr/bin/cvtsudoers` | C (sudoers parse + AST oracles) |

`systemd-sysctl` ships in **`systemd-udev`, not `systemd`**, and is **not on
PATH**. `sysctl-oracle` attempts that assume either are why an earlier probe
reported the binary missing.

One set rather than three: the lanes are crate-disjoint but their oracles are not
mutually exclusive, the packages are small, and a single set means one
`docker build` loop per drift workflow instead of three.

Unlike the `fapolicyd8/9/10` images (prebuilt, dev-machine-only, no committed
Dockerfile), these are built from this directory so CI can rebuild them. That is
what lets each lane have a scheduled drift workflow at all.

## Build

```bash
for v in 8 9 10; do
    docker build -t "rs-oracle${v}" "tools/oracle-images/dockerfiles/${v}"
done
```

## Measured oracle versions (2026-07-25)

The per-version control in each lane's Tier-1 test asserts these three are
distinct. If a base-image refresh collapses two of them, that control is what
detects "all three transcripts are secretly the same file".

| image | `audit` | `systemd-udev` | `sudo` |
|---|---|---|---|
| `rs-oracle8` | 3.1.2 | 239 | 1.9.5p2 |
| `rs-oracle9` | 3.1.5 | 252 | 1.9.17p2 |
| `rs-oracle10` | 4.0.3 | 257 | 1.9.17 |

Note `sudo` on el9 (`1.9.17p2`) and el10 (`1.9.17`) differ only by patch level,
so Lane C's per-version control cannot rest on the version string alone; it needs
a captured behavioural divergence as well.

## Lane A: audit netlink safety (read this before changing the invocation)

**Audit netlink is not namespaced.** A container that can actually reach it
mutates the *host* kernel's audit ruleset. The rules below are not stylistic.

- **Never** `--privileged`, **never** `--network host`, **never** `-v /:/host`.
- The invocation is
  `docker run --rm --network=none --cap-add=AUDIT_CONTROL rs-oracle<N>`.
- **The `auditctl -s` canary runs first, every time.** It is a status *read* with
  zero blast radius. If it SUCCEEDS, netlink is live and the host ruleset is
  reachable: refuse to capture and exit rc 3. Only a failing canary permits a
  capture run.

`--cap-add=AUDIT_CONTROL` is required, and this was measured rather than assumed
(2026-07-25, all three images):

- **Without** the capability, `auditctl` bails at its permission check *before
  parsing*. The canary, a valid rule and an invalid rule all produce identical
  output: `rc 4`, `You must be root to run this program.` There is no
  discriminator to preserve, because there is no parsing at all.
- **With** the capability, the canary still gets
  `Error sending status request (Operation not permitted)`, and a valid rule's
  add is *refused* with
  `Error sending add rule data request (Operation not permitted)`. Nothing
  reaches the host kernel; the capability only gets `auditctl` far enough to
  parse.

### Classification: rc gates, stderr discriminates

`rc` is not useless here, but it is not sufficient either:

| rc | meaning |
|---|---|
| 4 | `auditctl` never ran (no capability). The capture is UNUSABLE. |
| 0 | the rule LOADED, so netlink is live. ABORT: the host was modified. |
| 1 | `auditctl` ran and could not load. Classify by stderr. |

Within `rc 1`:

- stderr contains `Error sending add rule data request` -> the rule PARSED and
  the add was attempted -> **ACCEPT**.
- stderr contains a parse complaint (`-F unknown field:`,
  `Permission can only contain`, ...) -> **REJECT**.
- stderr and stdout both empty -> **AMBIGUOUS, not automatically REJECT.**
  AMENDMENT (session 9k-1 Lane A, post-barrier): this line originally read
  "REJECT, but silently", and that wording is what seeded a real bug - the
  first draft's capture script treated every silent line, including a bare
  `-D`, as a parse reject. `-D`/`-b`/`-e`/`-f`/`-r`/`--backlog_wait_time`/
  `--loginuid-immutable`/`--reset-lost` each send their OWN netlink message
  from inside `setopt()`'s own `case` arm and print nothing when THAT fails
  under this sandbox's EPERM - so silence for one of these flags is produced
  identically by a successful parse and by a genuine refusal. Silence is
  conclusive REJECT evidence only for an add-shaped line (`-w`/`-a`), because
  a successful parse of one of those is always LOUD (`Error sending add rule
  data request`) under this sandbox. See
  `crates/rulesteward-auditd/src/oracle.rs`'s `silence_is_conclusive` and
  `crates/rulesteward-auditd/tests/corpus/auditd-oracle/PROVENANCE.md`'s "The
  silent-rc1 blind spot" for the full reasoning and the `-D`-under-`-R`
  finding this correction is grounded in.

### `auditctl -R` swallows many parse diagnostics

Measured on el8, el9 and el10 alike:

| rule, fed via `-R <file>` | rc | stdout | stderr |
|---|---|---|---|
| `-w /etc/passwd -p zz -k c` | 1 | empty | **empty** |
| `garbage-not-a-flag` | 1 | empty | **empty** |
| `-a always,exit -F perm=zz -S execve` | 1 | empty | `Permission can only contain  'rwxa'` |
| `-a always,exit -F nosuchfield=1 -S execve` | 1 | empty | `-F unknown field: nosuchfield` |

The same `-p zz` rule passed **directly** on the command line does print
`Permission z isn't supported`. Issue #601's truth table was recorded that way.

`-R` is nonetheless the correct oracle for Lane A and must not be swapped for the
direct form: a rules FILE reaches the kernel via
`augenrules` -> `auditctl -R` -> `audit_strsplit`, which splits only on the
literal space byte and treats quotes as literal bytes. That raw reader IS the
subject of #584. Direct argv invocation would exercise shell tokenization, which
is the wrong tokenizer for the flagship issue this lane exists to ground.

So a silent `rc 1` on an add-shaped line (`-w`/`-a`) is a real REJECT (see the
qualified bullet above for why this does NOT generalize to control-shaped
lines like `-D`/`-b`). The risk that even an add-shaped silent line is instead
a broken harness is closed at BATCH level, per the CONTRIBUTING positive-control
rule:

- every capture batch includes a known-ACCEPT rule that MUST produce
  `Error sending add rule data request`;
- and a known-REJECT rule with positive (non-silent) evidence. AMENDMENT:
  this used to be `-F perm=zz` -> `Permission can only contain  'rwxa'`, but
  that rule is ALSO a RuleSteward parser divergence (no letter-set validation
  on `-F perm=` values), so a positive control would double as a product XFAIL.
  The control is now `-F nosuchfield=1` -> `-F unknown field: nosuchfield`,
  which both sides agree is a reject. `-p zz` (not `-F perm=zz`) is still the
  one to avoid entirely for this purpose: it is silent under `-R` (see the
  measured table above), so it cannot serve as a non-silent reject control at
  all;
- if the accept control does not fire, the entire capture is a tool error
  (rc 2), never 0 and never 1.

Per-line silence is then safe, because the instrument has proven it ran.
