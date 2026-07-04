# Changelog

All notable changes to RuleSteward are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/rulesteward/rulesteward/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/rulesteward/rulesteward/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/rulesteward/rulesteward/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/rulesteward/rulesteward/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/rulesteward/rulesteward/releases/tag/v0.1.0
