# Changelog

All notable changes to RuleSteward are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **SARIF output for every lint verb** (#511): `--format sarif` (findings-only,
  SARIF 2.1.0) now works on `sshd lint`, `sysctl lint`, `sudoers lint`,
  `auditd lint`, and `selinux lint` in addition to `fapolicyd lint`, closing the
  "SARIF from all six lint verbs" v0.8 milestone item. `--sarif-include-pass`
  remains `fapolicyd lint` only (locked scope decision). The versioned JSON
  envelopes of the five verbs are byte-identical to before.
- **sysctld STIG derivation ported to DISA XCCDF** (#512): `tools/stig-update`
  now derives the sysctld baseline from the pinned official DISA STIG zips
  (RHEL 8 V2R8 / RHEL 9 V2R9 / RHEL 10 V1R2), like the sshd and auditd tools,
  with committed trimmed fixtures and golden tests; the PR-time drift gate runs
  offline against the fixtures and the weekly ComplianceAsCode `--latest` probe
  is retired (staleness detection tracked in #550). Reconciling against DISA
  narrowed four accepted values (`kernel.kptr_restrict` to `1` on rhel9/rhel10,
  `net.ipv4.conf.all.rp_filter` to `1` on rhel8/rhel10) and added three
  RHEL 8 V2R8 keys (`net.ipv4.conf.default.rp_filter`,
  `net.ipv4.conf.all.log_martians`, `net.ipv4.conf.default.log_martians`);
  RHEL 8 table grows 28 -> 31 keys.

### Fixed

- **fapolicyd SARIF schema validity for file-level findings**: diagnostics not
  anchored to a source line (e.g. `fapd-F02`/`fapd-C01`/`fapd-X01`) previously
  rendered `region.startLine: 0`, which violates the SARIF 2.1.0 minimum of 1.
  The renderer now omits the `region` (keeping `artifactLocation`) for
  unanchored findings, the standard SARIF shape for file-level results.
  Anchored findings are unchanged.

- **CIS Benchmark control tables for all four RHEL-target backends** (sshd
  #525, sudoers #526, sysctld #527, auditd #528): per-product (rhel8 v4.0.0 /
  rhel9 v2.0.0 / rhel10 v1.0.1) tables transcribed verbatim from
  ComplianceAsCode/content at the ref pinned in `tools/cis-update/cis-refs.toml`,
  each behind a `pub cis_baseline` accessor and drift-tethered by the
  `cis-check` gate (all 12 family-by-product slots now report `OK`, none
  `SKIPPED`). Control ids and CaC titles only - never benchmark prose.
- **`sysctld-W04`** (one new lint code, bringing the total to 61: fapolicyd 25,
  sshd 13, auditd 10, sudoers 8, sysctld 5): version-aware CIS-Benchmark
  kernel-hardening baseline check under `--target` - one Warning per
  CIS-required key that is unset or set outside the benchmark-accepted set,
  each carrying exactly one titled `Cis` control ref. (#527)
- **`Framework::Cis` control refs with CaC titles across backends**: sshd
  `W01`/`W02` findings on the STIG/CIS overlap keywords now carry BOTH their
  existing `Stig` ref and one `Cis` ref (never a dropped Stig ref, never a
  duplicate); auditd `au-W06` findings carry the mapped CIS control ref(s) via
  the CaC-rule join (`RHEL-10-500810` maps two CIS controls and carries both).
  `--profile cis` now surfaces findings from all four RHEL-target backends.
  (#525, #528)

### Changed

- **sudoers `sudo-W04` CIS citations renumbered** from the stale
  `1.3.2`/`1.3.3` (an older benchmark generation) to `5.2.2` (`use_pty`) /
  `5.2.3` (I/O logging), now table-driven from the backend's first
  `cis_baseline` accessor and carrying CaC titles; the CLI long-help was
  updated to match the emitted output. (#526)
- **`cis-check` drift filter is asymmetric over non-automated upstream
  status**: a shipped control id is forgiven when upstream maps it at any
  status (first hit: rhel9 auditd `6.3.3.5`, `partial` at the pin); upstream
  additions still count only when `automated`, and renumber/removal detection
  is unchanged. (#524)

## [0.7.0] - 2026-07-13

A cross-cutting STIG compliance-profile release. No new backends and no new
lint codes (unchanged from v0.6's 60): v0.7 instead promotes control
provenance to a typed, first-class property of every finding and adds a
`--profile` selector that turns the six independent linters into one
framework-scoped compliance scanner. Control IDs previously reached the user
only as inconsistent free text inside messages; they are now a structured
`controls` field, surfaced identically across human, JSON, and SARIF
output and machine-followable from a finding to its control. A dev-tooling
gap is also closed: `tools/sshd-stig-update` now drift-guards the
hand-authored sshd DISA Rule IDs against the upstream XCCDF.

### Added

- **`--profile <framework>`** (global flag; `stig`, `cis`, `pci`, or `nist`):
  retains only findings that enforce a control in the named framework, so a
  single scan answers "show me only the STIG-relevant findings." An
  empty-after-filter result from a non-empty finding set returns the reserved
  exit code `9` (`EXIT_NO_OP`), so CI can distinguish "profile matched
  nothing" from "checked and clean" (exit `0`). Parse errors and unreadable
  inputs are exempt from the filter and still exit `5` / `3` - a file that
  was never checked is not reported as a compliance no-op. `--profile` absent
  is byte-identical to prior behavior. (#506)
- **Typed control references** on findings: a structured `controls` array
  carrying each control's framework, ID, title, and (for DISA STIG) its
  V-number alias, surfaced consistently in human, JSON, and SARIF
  output. (#500, #504)
- **SARIF control taxonomies**: the SARIF renderer emits `runs[0].taxonomies`
  (one taxonomy component per framework) plus per-result `taxa` references -
  the purpose-built SARIF slot that compliance consumers (e.g. GitHub
  code-scanning) group findings by. Additive; a finding with no controls
  renders byte-identically to before. (#505)

### Changed

- **`sshd`, `auditd`, and `sudoers` findings** now populate the typed
  `controls` field instead of interpolating control IDs into free-text
  messages (`sshd-W01` / `sshd-W02` previously dropped them entirely), so
  control provenance is consistent and machine-readable across every output
  format. (#501, #502, #503)
- **Corrected CIS-vs-DISA control attribution**: sudoers findings that
  enforce CIS / PCI controls are labeled `Cis` / `Pci` rather than mislabeled
  as STIG, so `--profile stig` correctly excludes them while `--profile cis`
  / `pci` include them. (#503)

## [0.6.0] - 2026-07-12

A backend-deepening release. No new backends; one new lint code (`au-W06`,
bringing the total to 60: fapolicyd 25, sshd 13, auditd 10, sudoers 8,
sysctld 4). v0.6 deepens the auditd, fapolicyd, sshd, and sudoers lanes where
curated gaps were tracked - every change grounded against the real subsystem
(fapolicyd 1.3.2 / 1.4.5 containers, `sshd -T` on OpenSSH 8.0p1 / 9.9p1,
`visudo -c` 1.9.17p2, DISA XCCDF benchmarks) - and extends the v0.5
provenance-tooling pattern with four new dev-only derive/drift tools
(fapolicyd version/pattern probe, fapolicyd attribute registry, auditd
message-type tables, auditd STIG required-rules tables), so every remaining
hand-pinned table is now drift-tethered to its upstream source. The
repository also gains `LICENSES/GPL-2.0.txt` and a NOTICE entry covering the
GPL-2.0-or-later fapolicyd C test fixtures vendored for the attribute drift
tool (dev-only test data; no obligation attaches to released binaries), plus
two test/CI hygiene fixes (a preventive gate for unguarded permission-denial
tests and hermetic fixtures for two host-reading CLI tests).

### Added

- **`au-W06`** (Warning, fires only under an explicit `--target
  rhel8|rhel9|rhel10`): the audit ruleset is missing rules the applicable
  DISA STIG requires. Key-sensitive matching, with a distinct "present but
  under a different key" finding. The required-rules tables (61 / 67 / 75
  `rules.d` lines for RHEL 8 / 9 / 10) are derived from the DISA XCCDF
  benchmarks (RHEL8 V2R4 / RHEL9 V2R7 / RHEL10 V1R1) and kept drift-tethered
  by a new dev tool. The portable default (no `--target`) stays silent, so
  existing output is unchanged. `auditd` is now **10 codes**. (#474)

### Changed

- **`sshd-W07`** now detects per-sub-population shadows behind a later
  `Match` block that constrains two or more criterion types, when a unique
  differing axis exists and every other axis is provably neutral by exact
  algebra (CIDR / port-set / literal-name containment); the reduction reuses
  the shipped single-type region walks. The grounded example - a `/16`
  sub-population of a `/8` block silently resolving to an earlier block's
  value - is detected. Genuine two-axis partitions remain a documented
  accepted false negative. (#452)
- **`fapd-E05`** is now version-aware under `--target`: at `rhel9`/`rhel10`
  an integer-overflow set member is flagged only when the set is referenced
  by a non-STRING-category attribute (fapolicyd 1.4.5 loads unused or
  STRING-only-referenced overflow sets cleanly, so those are now silent);
  portable and `--target rhel8` keep the unconditional flag (1.3.2 aborts
  the whole rules file on any overflow member, even unused). The detector is
  also `strtol`-faithful now, fixing two daemon-verified false negatives
  (first-character set typing; sign-aware out-of-range at the asymmetric
  `i64` boundary). (#477)
- **`sudo-F02`** now flags non-path members of a `Defaults!` (Cmnd) list -
  `#`-prefixed non-numerics, `%`-group names, bare `/`, relative paths,
  lowercase barewords - matching `visudo -c` (1.9.17p2) verdicts; the
  reserved pseudo-commands `sudoedit` / `list` (including quoted `"list"`)
  stay accepted. (#451)
- **`au-W02`/`au-W03`** overlap analysis uses a tighter disjointness prover:
  two `msgtype` equality predicates naming different record numbers,
  complementary `-C` comparisons on the process-vs-process constants, and an
  `unset` uid/gid/sessionid sentinel versus a relational range excluding it
  are now all proven disjoint (fewer false-overlap findings; promotions are
  sound-direction only, so no real suppression warning is dropped). (#475)

### Fixed

- **`sshd-W07`**: a latent false-positive / false-negative pair in
  multi-type earlier-setter selection - the identical-type-set filter
  dropped subset-typed predecessors, misattributing first-match wins
  (flagging a block that is not shadowed while missing one that is dead).
  Selection is now structural subset-or-equal plus per-shared-type
  co-satisfiability. The "matches-nobody" family is also suppressed on both
  the reduction and fallback routes: repeated-type contradictions and
  pure-negation / self-negation / wider-negated-glob criteria lists (which
  positively match no principal) no longer count as shadowing setters.
  (#494, #452)
- **`fapd-E07`**: an all-digit set member exceeding `i64::MAX` is no longer
  typed numeric at `--target rhel9`+ (the 1.4.5 daemon types it STRING),
  removing an `fapd-E05`+`fapd-E07` double false positive on
  STRING-referenced overflow sets; the rhel8 typing path is deliberately
  unchanged. (#477)

## [0.5.0] - 2026-07-08

A resiliency and code-quality release. No new backends and no new lint codes
(59 total, unchanged): v0.5 continues v0.4's correctness-hardening theme one layer
up - the grounded tables the lints depend on - plus readability and coverage. It
deepens two existing lints, fixes several `sshd` false-positives and missed
deprecations surfaced by new daemon-grounded provenance tooling, refactors eight
modules for readability (behavior-preserving), and raises the per-crate coverage
floor to 90% everywhere (the CLI is now in the CI coverage gate).

### Changed

- **`sshd-W07`** now detects per-sub-population (partitioned-criteria) `Match`-block
  shadows, not only whole-block shadows. (#409)
- **`sudoers-F01`/`sudoers-F02`** empty comma-member detection now covers the fourth
  scope arm, `Defaults!` (Cmnd) scope. (#429)

### Fixed

- **`sshd-E04`**: removed four false-positive errors on keywords the daemon actually
  honors inside `Match` blocks - `authorizedkeysfile2`, `rsaauthentication`,
  `rhostsrsaauthentication`, and `gssapiindicators` (on RHEL 9 / 10). Grounded
  against the real `sshd` binary on Rocky Linux 8 / 9 / 10 by a new daemon-probe
  drift tool. (#372)
- **`sshd-W04`**: now flags three previously-missed deprecated keywords -
  `checkmail`, `authorizedkeysfile2`, and `pamauthenticationviakbdint`. (#372)
- **`sshd-W07`**: fixed a false-positive where a wildcard region incorrectly covered
  a same-type `Match` block. (#409)

## [0.4.0] - 2026-07-04

Correctness and fidelity hardening of the three backends first shipped in v0.3.0
(`sshd`, `sudoers`, `sysctl`). One new lint code (`sysctld-W03`) and a new opt-in
system-wide sysctl scan; every other change is a false-positive or false-negative
fix grounded against the real oracle (`visudo`/`cvtsudoers` 1.9.17p2, `sshd -T`
OpenSSH 10.2p1, procps-ng 3.3.17 + systemd-sysctl 259 + `sysctl.d(5)`).

### Added

- **`rulesteward sysctl lint --system [--root <PREFIX>]`**: new opt-in scan of the
  full `sysctl.d` search-path precedence chain (`/etc/sysctl.d` > `/run/sysctl.d` >
  `/usr/local/lib/sysctl.d` > `/usr/lib/sysctl.d` (= `/lib/sysctl.d`), plus
  `/etc/sysctl.conf`) instead of a single file. `--root <PREFIX>` reroots the scan
  under a prefix for offline / container inspection. Read-only. (#420)
- **`sysctld-W03`** (Warning, `--system` only): cross-directory precedence surprises
  a single-file lint cannot see. Three grounded sub-cases: a live assignment that
  wins from a lower-precedence directory over a dead one (W03-a); a
  `/etc/sysctl.conf` key whose winner differs between the procps and systemd
  appliers (W03-b); and a same-basename drop-in masked by a higher-precedence file
  that silently drops a key no surviving file re-asserts (W03-c). Masking is
  type-agnostic by basename, matching procps-ng 3.3.17 + systemd-sysctl 259.
  `sysctld` is now **4 codes**. (#420)

### Fixed

- **sudoers `sudo-F02` no longer false-positives on a `#<digits>` inside a quoted
  `Defaults` value** (e.g. `Defaults passprompt="Enter #5"`, which `visudo` accepts):
  the `Defaults` value now records whether it was cleanly double-quoted, and the F02
  glued-hash scan skips a quoted value. (#423)
- **sudoers: several `visudo`-invalid configs that previously emitted no diagnostic
  now do** - a letter-first runas `#`-GID (`(root:#abc)`), a glued `#<digits>`
  immediately after a closing quote (`Defaults passprompt="a"#5`), and a `NOPASSWD:`
  with an empty command no longer firing a spurious `sudo-W05`. (#424)
- **sudoers: a mid-command `(` or an unbalanced quote no longer hides a later
  passwordless grant** on the same line (the top-level `:` host-group splitter no
  longer mis-tracks runas parens). (#416)
- **sudoers: runas-position `#`-GID validation is now uniform** across the `:`, `>`,
  and `@` `Defaults` scopes and is applied per comma-list element rather than to the
  whole binding, fixing false negatives on malformed GIDs. (#407)
- **sudoers: the `Defaults` settings-list comma split is now escape- and
  quote-aware**, so a comma inside a quoted or escaped setting value no longer
  mis-splits. (#405)
- **sshd `sshd-W03` / `sshd-W06`: an operator-prefixed algorithm list no longer
  double-reports.** A `-`-prefixed list (removal, hardening) is deferred entirely and
  a `+` / `^` list is left to `sshd-W06`; a mid-list operator (which sshd rejects,
  rc 255) is handled distinctly. Grounded via `sshd -T` (OpenSSH 10.2p1). (#402)
- **`rulesteward sudoers lint`: a broken `@include` marker no longer blanks the
  ariadne source snippet** for real diagnostics sharing that path (an empty marker
  source could clobber the real staged source regardless of segment order). (#401)

### Changed

- Internal: a shared forward-`NOPASSWD` walker now backs `sudo-W01` / `W02` / `W05`;
  a non-ASCII character was removed from a sudoers source comment (ASCII-only source
  is a project invariant). (#404, #425)

### Known issues

- An empty comma-list member in a `Defaults:` user scope (`Defaults:root,,alice`,
  which `visudo` rejects) is not yet flagged; detection requires a parser
  scope-boundary rework and is tracked for a later release. (#426)

## [0.3.0] - 2026-07-02

### Added

- **`rulesteward sudoers lint`**: new `sudoers(5)` backend (8 `sudo-` codes). Parses
  a policy file or a `sudoers.d/` drop-in directory (line-continuation joins, `#`
  comment disambiguation, alias definitions, `@include`/`@includedir`, user
  specifications). Detects: parse errors (`sudo-F01`), undefined / dead aliases
  (`sudo-E01`, `sudo-W03`), passwordless run-anything grants (`sudo-W01`, `sudo-W02`),
  and `Defaults` settings that weaken or omit the sudo security baseline (`sudo-W04`):
  covers `!authenticate`, `targetpw`/`rootpw`/`runaspw`, `visiblepw`, `!use_pty`,
  negative `timestamp_timeout` (DISA STIG RHEL-08-010384/RHEL-09-432015); and
  merged-config absence of `use_pty`, I/O logging, and `timestamp_timeout`
  (CIS Benchmark 1.3.2/1.3.3 and DISA STIG RHEL-08-010384/RHEL-09-432015); and
  per-position tokens that `visudo` rejects but the classifier keeps as a clean
  spec (`sudo-F02`, Fatal: a `#<digits>` token glued in a command or `Defaults`
  value, a relative-path command, or an invalid `%group` name grounded against
  `visudo -c`). (#329, #330, #331, #332, #333, #346, #347, #363)
- **`rulesteward sysctl lint`**: new `sysctl.d`/`sysctl.conf` backend (3 `sysctld-`
  codes). Parses kernel-parameter assignment files (`key = value` format, whole-line
  `#`/`;` comments). Detects: parse errors (`sysctld-F01`), last-wins conflicts across
  the drop-in precedence order (`sysctld-W01`), and - when `--target rhel8|rhel9|rhel10`
  is set - STIG-required kernel-hardening keys that are unset or insecure
  (`sysctld-W02`, version-aware, grounded in ComplianceAsCode). (#150, #335)
- `auditd lint --apparmor`: opt-in folding of the `WITH_APPARMOR` msgtype record
  names (`APPARMOR_DENIED` == `1503`, etc.) in the `au-W01`/`au-W02` lints. Off by
  default, since a RHEL/fapolicyd-target audit daemon does not recognize these
  names; enable it when linting rules for an AppArmor build (Debian/Ubuntu). (#230)
- **`rulesteward sshd lint`**: new `sshd_config(5)` backend (13 `sshd-` codes). Lints a main
  `sshd_config` file or an `/etc/ssh` directory layout (main config plus a `sshd_config.d/*.conf`
  drop-in tree), honoring `Match` blocks, `Include` resolution, and sshd's first-value-wins
  keyword semantics; version-aware passes select the OpenSSH keyword set from
  `--target auto|rhel8|rhel9|rhel10` (rhel8 = 8.0p1, rhel9 / rhel10 = 9.9p1). Detects: parse
  failure (`sshd-F01`); directive defects (`sshd-E01` unknown keyword, `sshd-E02` duplicate
  directive silently overridden in the same scope, `sshd-E03` `Include` resolving to nothing,
  `sshd-E04` directive ignored inside a `Match` block); STIG-baseline gaps (`sshd-W01` required
  directive missing, `sshd-W02` value weaker than the baseline, `sshd-W04` deprecated or removed
  directive); weak cryptography (`sshd-W03` CBC / MD5 / SHA1 / group1 / ssh-rsa in
  `Ciphers` / `MACs` / `KexAlgorithms` / `HostKeyAlgorithms`, `sshd-W06` a `+` / `^`
  algorithm-list prefix reintroducing a weak default); and cross-scope shadowing (`sshd-F02` a
  drop-in overriding a required global, `sshd-W05` a `Match` block relaxing a required global,
  `sshd-W07` a first-value-wins keyword set differently in two simultaneously-satisfiable `Match`
  blocks). (#149 and children)
- `sshd lint` sshd-W05: flags a `Match` block that sets a STIG-controlled directive
  to a baseline-failing value (a STIG escape hatch). Reuses the sshd-W01/W02
  required-set + baseline; does not fire for a directive sshd ignores inside a Match
  block (that is sshd-E04's finding). (#244)
- `sshd lint` sshd-W06: flags an algorithm-list directive whose value begins with
  `+` or `^` and names a weak (sshd-W03 denylisted) algorithm, reintroducing it into
  the OpenSSH built-in default set. Conservative and target-independent; `-`
  (removal) is hardening and is never flagged. (#244)
- `sshd lint` sshd-W07: flags a first-value-wins directive set to DIFFERENT values in
  two simultaneously-satisfiable `Match` blocks - sshd applies only the first block's
  value and silently drops the later (shadowed) one. Overlap is decided conservatively
  from the criteria pattern text (no NSS/DNS): negation-aware for name and CIDR lists,
  AND-aware (intersection) for a criterion type repeated in one header, and an
  unconditional `Match all` participates as a shadower (never a shadowEE). Accepted
  conservative false negatives (cross-type `User`/`Group`, wildcard-vs-wildcard,
  sub-population partitions, and repeated CIDR/port criteria carrying a negation) are
  documented in-code. (#302)
- `sshd lint <dir>`: a directory target lints the standard `/etc/ssh` layout (main
  `sshd_config` plus a `sshd_config.d/*.conf` drop-in directory) and runs the new
  cross-file sshd-F02 (Fatal) check: a drop-in whose baseline-failing value wins by
  sshd precedence (Include position, lexical drop-in order, and unconditional
  `Match all` override, including an Include nested in a `Match all`) over the
  hardened main config. Conditional `Match` blocks are out of scope. (#245)
- `rulesteward sudoers lint` sudo-W05: a broad any-NOPASSWD STIG check that flags a
  passwordless grant on any specific command (complementing sudo-W01's
  NOPASSWD-on-ALL), deduped so a NOPASSWD-on-ALL line still raises only W01. Grounded
  in ComplianceAsCode `sudo_remove_nopasswd` (DISA STIG RHEL-08-010380 /
  RHEL-09-611085). (#370)
- `rulesteward sudoers lint` sudo-F02: extended to three more `visudo`-rejected shapes
  the total parser keeps as clean specs: runas-position group defects (including a
  bare `%`-prefixed group in the post-colon runas list), a lone `!` command with no
  path, and a `%#<digits><non-digit>` malformed numeric-gid (in both the subject and
  runas-user positions). (#375)

### Changed

- `rulesteward migrate` JSON envelope: the post-apply verification field is renamed
  `fagenrulesCheck` -> `checkRules` to match the `fapolicyd-cli --check-rules` verb,
  and the migrate envelope `schemaVersion` bumps 1 -> 2. This is a breaking change: the
  field name was the frozen schemaVersion-1 contract. (#221)

### Fixed

- fapolicyd trustdb: `trustdb check` and the simulate trust lookup now correctly
  find a trusted file whose path exceeds LMDB's 511-byte max key size (the daemon
  stores it under a hashed key); previously such long paths were falsely reported
  as untrusted/absent. (#318)
- `sshd lint` sshd-W03/W06 + tokenizer: the sshd_config `read_arg` tokenizer now
  strips and concatenates quoted runs within a token the way OpenSSH does, so a
  quoted weak algorithm is flagged whatever the quoting (`Ciphers ""aes128-cbc`
  and `Ciphers "aes128""-cbc"` no longer miss W03 - false negatives), while a
  quoted value glued to a trailing `#x` (which sshd rejects as an invalid cipher
  spec) no longer false-fires W03. The tokenizer also honors backslash-escaped
  quotes (`\"`, `\\`), so a valid line such as `Banner /etc/motd\"` no longer
  raises a spurious `sshd-F01` parse error (regression avoided). Grounded against
  `sshd -T` (OpenSSH 10.2p1); full single-quote / escaped-space `argv_split`
  fidelity is tracked in #374. (#348)
- `sshd lint` sshd-W03/W06: an algorithm-list directive whose value is not a single
  well-formed token is now handled the way sshd does. Internal whitespace (e.g.
  `Ciphers + aes128-cbc` or `Ciphers aes128-cbc foo`) is a fatal sshd parse error
  (rc 255) the daemon never loads, so W03/W06 no longer over-flag those non-loading
  lines (false positive). A whitespace-delimited inline `#` comment (e.g.
  `Ciphers aes128-cbc # legacy`) is a valid line sshd loads, so the weak algorithm
  is now correctly flagged (previously a false negative); a `#` glued inside the
  value token is a non-loading reject and stays unflagged. (#325)
- `sshd lint` sshd-F02: `Include` directives are now resolved recursively (with an
  ancestry cycle guard and a depth cap matching OpenSSH's `SERVCONF_MAX_DEPTH`), so
  a drop-in baseline override reached through a second-level include is no longer
  silently missed. Previously only one level of `Include` was followed. (#323)
- `rulesteward sshd lint` sshd-W03/W06: no longer false-fire on a quoted algorithm-list
  value that carries residual internal ASCII whitespace (e.g. `Ciphers "aes128-cbc "`),
  which sshd itself rejects as a fatal parse error (rc 255) and never loads. (#392)
- `rulesteward sudoers lint` sudo-F01: line-level parse errors are now anchored with an
  ariadne source snippet (matching auditd/sshd/sysctld) instead of unanchored;
  file-level errors (an unreadable file) stay unanchored. (#382)
- `rulesteward sudoers lint`: the `Cmnd_Spec_List` comma split is now escape-, paren-,
  and quote-aware, fixing a sudo-W01 false positive (an escaped comma such as
  `NOPASSWD: /bin/echo a\,ALL` was mis-split so the `ALL` tail was misclassified as the
  reserved run-anything command) and a sudo-W05 false negative (a comma inside a runas
  group `(root, operator)` swallowed the NOPASSWD tag). (#370)

## [0.2.1] - 2026-06-11

Maintenance and supply-chain release. Its reason to exist: v0.2.0 was tagged a few
hours before the liblmdb / OpenLDAP (OLDAP-2.8) binary attribution landed on `main`
(#200), so the public v0.2.0 release assets shipped without the OLDAP-2.8 license
text that binary redistribution requires. This release ships that attribution in
signed assets and folds in the deferred supply-chain hardening.

### Added

- **THIRD-PARTY-LICENSES** aggregate generated by cargo-about and shipped with the
  binary and RPM: consolidated attribution for the permissive (MIT/Apache/BSD) Rust
  crates plus musl libc statically linked into the release binary. (#185)
- **SLSA build-provenance attestation** for the binary and RPM, recorded in the
  GitHub attestation log and verifiable with `gh attestation verify`. (#188)
- **Nightly `security-audit` workflow** re-running cargo-audit and cargo-deny on a
  schedule, so a new advisory against an unchanged `main` surfaces within a day
  instead of waiting for the next PR. (#186)

### Changed

- **Release assets now carry the liblmdb OLDAP-2.8 attribution** (license text in
  the signed SHA256SUMS, in the RPM, and in the NOTICE) that v0.2.0 shipped without.
  (#200, first shipped in this release)
- **RPM `License:` tag** now names the default binary's effective
  `Apache-2.0 AND LGPL-2.1-or-later` instead of bare `Apache-2.0`. (#189)

### Fixed

- `--sarif-include-pass` `--help` text no longer describes the flag as "reserved";
  it has been functional since #137. (#197)

## [0.2.0] - 2026-06-10

Second release. fapolicyd remains the most complete backend; SELinux and auditd
gain real analysis paths this cycle. Read-only-by-default, no-telemetry, and
CI-grade exit codes are unchanged.

### Added

- **fapolicyd `explain` and `simulate`.** `explain` annotates why a rule fires;
  `simulate` evaluates a workload against the ruleset without touching the running
  daemon. (#118, #130)
- **fapolicyd `container-check`.** Flags rules that behave differently inside
  containers. (#134, #176)
- **`doctor` composite health check.** One command that probes the local fapolicyd
  install and surfaces actionable findings. (#76, #77, #78, #133)
- **SELinux `triage`.** Classifies AVC denials, with authoritative category
  resolution backed by libsepol and an optional `--policy <file>` for full-MLS
  scope. (#94, #105, #118, #122, #124, #135)
- **SELinux `te-emit`.** Emits compilable Type Enforcement stanzas from denials.
  (#102, #118)
- **auditd cost analysis / `report`.** Estimates per-rule audit volume and emits an
  exception register. (#118, #130, #139)
- **SARIF output** with `--sarif-include-pass` per-check coverage attestation, for
  code-scanning ingestion. (#137, #138, #172)
- **`--format csv`** for `trustdb list` and auditd cost output. (#64, #138)
- **auditd `-C` field-comparison parsing** and `arch=b32` demotion handling. (#161, #169)
- **`SECURITY.md`** vulnerability-disclosure policy. (#160)

### Changed

- **libsepol 3.10 is now vendored and built from source, statically linked into the
  default binary.** This makes SELinux category resolution authoritative out of the
  box. The default build is LGPL-2.1 (libsepol) over Apache-2.0 (engine); the
  release ships the LGPL-2.1 text, a NOTICE, and a written source offer. A pure
  Apache-2.0, libsepol-free build remains available via `--no-default-features`.
  (#110, #125, #135)
- **Minimum Supported Rust Version raised to 1.88** (let-chains in the engine).
- Output-format policy locked and documented across `--help`/man pages, with an
  OSCAL design note. (#65, #138)
- Internal refactor: `doctor`, `simulate`, and `fapolicyd` command modules split
  into focused submodules (no behavior or CLI change). (#145, #146, #148)

### Fixed

- fapolicyd `fapd-E07` type model corrected to be version-divergent; auditd `a0`-`a3`
  argument parsing; `te-emit` and `triage --policy` hint accuracy. (#168)
- auditd cost-model Finding-2 subset and SELinux MCS floor dominance. (#162)
- fapolicyd `dir=` handling and untrusted-macro absent-path behavior. (#139, #142)
- Nightly mutation-testing gate made complete and hang-free; closed outstanding
  cargo-mutants survivors. (#128, #132)

## [0.1.0] - 2026-06-02

Initial release. Cargo workspace (`-core`, `-fapolicyd`, `-sink`, `-cli`) with the
fapolicyd lint backend, the `rulesteward` CLI, and a signed static
`x86_64-unknown-linux-musl` binary plus RPM, SBOM, and cosign keyless signatures.

[Unreleased]: https://github.com/rulesteward/rulesteward/compare/v0.7.0...HEAD
[0.7.0]: https://github.com/rulesteward/rulesteward/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/rulesteward/rulesteward/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/rulesteward/rulesteward/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/rulesteward/rulesteward/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/rulesteward/rulesteward/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/rulesteward/rulesteward/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/rulesteward/rulesteward/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/rulesteward/rulesteward/releases/tag/v0.1.0
