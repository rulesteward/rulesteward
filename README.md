# RuleSteward

**Modular RHEL hardening toolkit** - read-only, CI-friendly static analysis and live triage for `fapolicyd`, `sshd_config`, `sudoers`, `sysctl.d`, `SELinux`, and `auditd`.

> Compatible with **DISA STIG RHEL 8/9/10** and **ACSC Essential Eight** application control objectives.

## Design principles

- **Read-only by default.** Every mutation flag is opt-in (`migrate --apply` is the only writer, and it dry-runs without it).
- **Unprivileged-friendly.** Static analysis paths never require root; live probes degrade gracefully when run unprivileged.
- **No telemetry, ever.** No phone-home, no anonymous metrics.
- **Exit-code-driven.** CI-grade exit codes (`0` clean / `1` warnings / `2` errors / `3` tool failure / `5` rule-parse-error).
- **Multiple output formats.** Human (default), JSON, SARIF, and CSV (for tabular output).

## Modules

| Crate | Purpose |
| --- | --- |
| `rulesteward-core` | Shared types: diagnostics, severity, AST |
| `rulesteward-fapolicyd` | fapolicyd rule parser + lint engine, trust-DB reader, simulate / report / migrate |
| `rulesteward-sshd` | `sshd_config` parser + structural lint passes |
| `rulesteward-auditd` | auditd rules parser, semantic linter, cost calculator |
| `rulesteward-sudoers` | `sudoers(5)` parser + security-baseline lint passes |
| `rulesteward-sysctld` | `sysctl.d`/`sysctl.conf` parser + STIG-baseline lint passes |
| `rulesteward-selinux` | AVC parser, denial triage, TE-module emission |
| `rulesteward-selinux-sys` | FFI bridge to vendored libsepol (authoritative AVC categorizer) |
| `rulesteward-sink` | `EventSink` trait + implementations |
| `rulesteward-license` | Offline license verification (planned; stub today) |
| `rulesteward-cli` | `rulesteward` binary |

## Install

Pre-built static `x86_64-unknown-linux-musl` binaries ship via GitHub Releases. Three install paths:

### 1. Download the signed static binary (recommended)

Each release attaches the `rulesteward` binary, a `SHA256SUMS` file, and a cosign keyless signature (`SHA256SUMS.sig` + `SHA256SUMS.pem`). Verify integrity and authenticity before running:

```bash
# Download rulesteward, SHA256SUMS, SHA256SUMS.sig, SHA256SUMS.pem from the release.
sha256sum -c SHA256SUMS                       # integrity
# authenticity (Sigstore keyless, no key to manage):
cosign verify-blob \
  --certificate SHA256SUMS.pem \
  --signature SHA256SUMS.sig \
  --certificate-identity-regexp '^https://github.com/rulesteward/rulesteward' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  SHA256SUMS
chmod +x rulesteward && ./rulesteward --version
```

> **cosign version:** the `verify-blob` command above uses detached-signature flags and
> requires cosign **v2.x**. cosign v3 removed `--certificate` / `--signature` from
> `verify-blob` (it verifies bundles only), so if you have cosign v3 installed, use a
> v2.x cosign to verify these detached `.sig` / `.pem` assets.

### 2. RPM (RHEL / Rocky / AlmaLinux 8, 9, 10)

```bash
sudo dnf install ./rulesteward-<version>.x86_64.rpm
```

### 3. Build from source (Rust developers)

```bash
cargo install --git https://github.com/rulesteward/rulesteward rulesteward-cli
```

## Commands

Every command is read-only unless noted. `--help` works on the binary and every
subcommand; `--format json` returns a versioned envelope (`{ "schemaVersion": 1,
"kind": ..., ... }`) for pipeline use.

### fapolicyd

```bash
rulesteward fapolicyd lint /etc/fapolicyd/rules.d/      # lint a rules.d/ directory (or --file one.rules)
rulesteward fapolicyd lint --format sarif /etc/fapolicyd/rules.d/   # SARIF 2.1.0 findings for CI
rulesteward fapolicyd simulate --rules /etc/fapolicyd/rules.d/ --workload access.json
rulesteward fapolicyd explain --record denial.log --ruleset /etc/fapolicyd/rules.d/
rulesteward fapolicyd report /etc/fapolicyd/rules.d/ --format csv   # exception register of every allow grant
rulesteward fapolicyd doctor                           # 14-check health scorecard on a live deployment
rulesteward fapolicyd doctor --target rhel9            # same scorecard with DISA STIG control ids attached
rulesteward fapolicyd container-check                  # detect container runtimes + namespace-limit risk
rulesteward fapolicyd migrate --from rhel8 --to rhel9 --rules-dir /etc/fapolicyd   # legacy -> rules.d/ (dry-run; --apply to write)
rulesteward fapolicyd trustdb list /var/lib/fapolicyd  # read the trust DB (also: check, diff, stale)
```

- **lint** - static-analyze rule files (28 `fapd-` codes; see Lint coverage). Optional
  cross-checks: `--against-trustdb`, `--check-identities`, `--target rhel8|rhel9|rhel10`,
  `--conf /etc/fapolicyd/fapolicyd.conf` (fail-open `permissive` detection, `fapd-W14`).
- **simulate** - statically replay a workload of access attempts and report which rule
  decides each (verdicts: `DECISIVE` / `POSSIBLE` / `NO MATCH`).
- **explain** - replay a FANOTIFY denial (bare record or `ausearch` block) against a
  ruleset and name the rule that caused it.
- **report** - build the exception register; `--diff-against` a prior snapshot and
  `--fail-on-drift` for CI gating.
- **doctor** - read-only deployment health check (service state, package presence, kernel
  FANOTIFY support, config, rule lint, trust-DB consistency, denial rate, and more). With
  `--target` (or on an auto-detected RHEL host) each check carries its DISA STIG control ids.
- **container-check** - detect podman / Docker / containerd / CRI-O / Kubernetes / RHCOS
  and flag the fapolicyd namespace-awareness limitation.
- **migrate** - move a legacy single-file `fapolicyd.rules` into `rules.d/` and rewrite
  `sha256hash=` to `filehash=`. Read-only until `--apply`.
- **trustdb** - inspect the fapolicyd trust DB: `list`, `check <paths...>`, `diff`
  (DB vs disk or two DBs), `stale` (entries whose paths are gone).

### sshd_config

```bash
rulesteward sshd lint /etc/ssh/sshd_config             # parse + structural lints
rulesteward sshd lint --format json /etc/ssh/sshd_config
```

- **lint** - parse an `sshd_config` (whole-line `#` comments, case-insensitive keywords,
  `Match` blocks, `Include` directives) and run the lint passes. All 13 `sshd-` codes
  are active: structural errors (`sshd-E01`..`sshd-E04`), the parse fatal (`sshd-F01`),
  the drop-in override fatal (`sshd-F02`), and the STIG / crypto / deprecation / Match-shadow
  warnings (`sshd-W01`..`sshd-W07`).

### auditd

```bash
rulesteward auditd cost --rules /etc/audit/rules.d/    # estimate SIEM ingest volume + cost
rulesteward auditd cost --rules /etc/audit/rules.d/ --from-log /var/log/audit/audit.log
rulesteward auditd lint /etc/audit/rules.d/            # semantic ruleset lint (9 au- codes)
```

- **cost** - estimate ingest volume and USD/month from the ruleset (a low / typical / high
  band, not a guarantee). `--from-log` grounds the estimate in measured event rates;
  `--price-per-gb` sets the rate.
- **lint** - static semantic analysis: duplicates, shadowing, `-e 2` lock unreachability,
  exclude/never suppression conflicts, and invalid field operators.

### sudoers

```bash
rulesteward sudoers lint /etc/sudoers                  # lint the sudoers policy (8 sudo- codes)
rulesteward sudoers lint /etc/sudoers.d                # lint a sudoers.d/ drop-in directory
rulesteward sudoers lint --format json /etc/sudoers
```

- **lint** - parse a `sudoers(5)` policy file (line-continuation joins, `#` comment
  disambiguation, `Defaults` entries, alias definitions, `@include` / `@includedir`
  directives, and user specifications) and run all lint passes. A directory target
  lints each eligible drop-in (sorted; names ending in `~` or containing `.` are
  skipped). Read-only.

### sysctl.d

```bash
rulesteward sysctl lint /etc/sysctl.conf               # lint kernel parameter assignments (5 sysctld- codes)
rulesteward sysctl lint /etc/sysctl.d/99-hardening.conf
rulesteward sysctl lint --target rhel9 /etc/sysctl.conf   # STIG + CIS baseline checks (sysctld-W02/W04)
rulesteward sysctl lint --system                       # scan the whole sysctl.d precedence chain (sysctld-W03)
rulesteward sysctl lint --system --root ./rootfs        # reroot the system scan (offline / container)
```

- **lint** - parse a kernel-parameter assignment file (`/etc/sysctl.conf`,
  `/etc/sysctl.d/*.conf`, etc.) and run the lint passes: `sysctld-F01` (parse
  error), `sysctld-W01` (last-wins conflict across the drop-in precedence order),
  and - when `--target rhel8|rhel9|rhel10` is set - the version-aware `sysctld-W02`
  STIG and `sysctld-W04` CIS-Benchmark kernel-hardening baseline checks. With
  `--system` (optionally rerooted by
  `--root <PREFIX>`) it instead scans the whole `sysctl.d` search-path precedence
  chain and adds `sysctld-W03` (cross-directory override / applier-divergence /
  masked-drop-in surprises). Read-only.

### SELinux

```bash
rulesteward selinux triage --record denial.log         # classify an AVC denial + suggest a fix
rulesteward selinux triage --audit-log /var/log/audit/audit.log
rulesteward selinux triage --record denial.log --emit-te --module-name mymod   # emit a .te policy module
rulesteward selinux triage --record denial.log --policy /etc/selinux/targeted/policy/policy.33   # authoritative
rulesteward selinux lint --target rhel9 /etc/selinux/config   # boot-config STIG lint (se-W01/se-W02)
rulesteward selinux doctor --target rhel9                     # 5-check live scorecard with DISA STIG ids
```

- **triage** - parse AVC denials, classify each by kind, and suggest the narrowest fix.
  A record-only floor classifier always runs; `--policy <binary-policy>` adds an
  authoritative verdict by replaying the denial against the compiled policy via libsepol.
  `--emit-te` writes a self-contained `.te` module instead of a report. Read-only: a
  suggested `allow` is never auto-applied. (Only plain type-enforcement denials are
  `allow`-fixable; MLS/MCS constraint, RBAC, and typebounds denials are reported but not
  auto-fixable.)
- **lint** - static-analyze `/etc/selinux/config` (2 `se-` codes; version-aware via
  `--target`, defaults to `/etc/selinux/config` when the path is omitted).
- **doctor** - read-only host health check (enforce status, loaded policy name,
  policycoreutils packages, faillock tally-directory context). With `--target` (or on an
  auto-detected RHEL host) each check carries its DISA STIG control ids.

### Shell completions

```bash
rulesteward completions bash    # also: zsh, fish, elvish, powershell, tcsh
```

## Lint coverage

Lint codes follow a SELint-style scheme: the letter after the backend prefix is the
severity tier (`F` fatal, `E` error, `W` warning, `S` style, `C` convention, `X` extra).

### fapolicyd (`fapd-`, 28 codes)

| Code | Severity | Checks | Gate |
| --- | --- | --- | --- |
| `fapd-C01` | Convention | rules.d/ filename does not follow the `NN-` numeric-prefix convention | directory mode |
| `fapd-C02` | Convention | cross-file duplicate: an identical rule appears in two rules.d/ files | directory mode |
| `fapd-E01` | Error | unknown attribute key, or a known attribute on the wrong (subject/object) side | always |
| `fapd-E02` | Error | invalid attribute value (e.g. a malformed digest) | always |
| `fapd-E03` | Error | reference to an undefined `%setname` macro | always |
| `fapd-E04` | Error | macro reference in a `trust=`/`pattern=` field, where it is not allowed | always |
| `fapd-E05` | Error | integer-typed set value overflows its type | always |
| `fapd-E06` | Error | construct diverges across the targeted fapolicyd/RHEL version | `--target` |
| `fapd-E07` | Error | set or attribute value-type incompatibility | always |
| `fapd-F01` | Fatal | rules file failed to parse | always |
| `fapd-F02` | Fatal | compiled and source rules coexist (ambiguous active-policy layout) | always |
| `fapd-F03` | Fatal | mixed modern and legacy rule syntax in one file | always |
| `fapd-S02` | Style | `%name=` set definition appears after the first rule | always |
| `fapd-W01` | Warning | rule unreachable: an earlier same-file rule subsumes it | always |
| `fapd-W02` | Warning | broad allow on execute (overly permissive) | always |
| `fapd-W03` | Warning | inline trailing `# comment` after a rule (fapolicyd silently drops the rule) | always |
| `fapd-W04` | Warning | unreachable: a deny in an earlier-loading rules.d/ file shadows it | directory mode |
| `fapd-W05` | Warning | `uid=`/`gid=` identity does not resolve via `getent` | `--check-identities` |
| `fapd-W06` | Warning | `path=`/`exe=` literal is neither in the trust DB nor present on disk | `--against-trustdb` |
| `fapd-W07` | Warning | deprecated `sha256hash=` (use `filehash=`; fapolicyd 1.4.2+) | all targets except rhel8 |
| `fapd-W08` | Warning | `dir=` value is missing its trailing slash | always |
| `fapd-W09` | Warning | macro may be defined in an unseen sibling file | `--file` mode |
| `fapd-W10` | Warning | cross-file decision shadow: an earlier-loading allow shadows a later rule | directory mode |
| `fapd-W11` | Warning | weak hash digest (MD5/SHA1); prefer SHA-256 | always |
| `fapd-W12` | Warning | deprecated `dir=untrusted` member (use object trust with execute permission instead; fapolicyd 1.6+) | fapolicyd 1.6+ target: dormant, no current target qualifies |
| `fapd-W13` | Warning | the merged ruleset's final rule is not a catch-all deny (`deny perm=any all : all` family; DISA STIG) | `--target` |
| `fapd-W14` | Warning | `fapolicyd.conf` sets a permissive (fail-open) value | `--conf` |
| `fapd-X01` | Extra | trust-DB orphan: a trusted path absent from the loaded rules | `--report-orphans` + `--against-trustdb` |

### auditd (`au-`, 11 codes)

| Code | Severity | Checks |
| --- | --- | --- |
| `au-E01` | Error | unreachable rule after the `-e 2` lock line |
| `au-E02` | Error | comparison operator invalid for the field's type (auditctl rejects the rule at load) |
| `au-E03` | Error | load-aborting duplicate: an identical earlier rule makes `auditctl -R` abort |
| `au-E04` | Error | field used on a filter list the kernel rejects for that field (`auditctl -R` aborts the load) |
| `au-E05` | Error | bitmask operator (`&`/`&=`) on a field the kernel rejects it for (`auditctl -R` aborts the load); the version-stable field set fires always, version-divergent fields only under `--target` |
| `au-F01` | Fatal | rules file does not parse |
| `au-W01` | Warning | duplicate rule (normalized-equal to an earlier rule in load order) |
| `au-W02` | Warning | shadowed rule: an earlier, broader rule subsumes it |
| `au-W03` | Warning | suppression conflict: an exclude/never rule suppresses an always rule's events |
| `au-W04` | Warning | missing-ABI coverage: a syscall rule pins one ABI (`arch=b32`/`b64`) with no companion on the other ABI |
| `au-W06` | Warning | missing STIG-required audit rule: the applicable RHEL STIG requires a rule this ruleset does not contain (fires only under `--target`) |

### sshd_config (`sshd-`, 13 codes)

| Code | Severity | Checks |
| --- | --- | --- |
| `sshd-E01` | Error | unknown directive for the target OpenSSH version |
| `sshd-E02` | Error | duplicate directive in the global block or within a `Match` block (sshd uses the first value; the later line is silently ignored) |
| `sshd-E03` | Error | `Include` references a path or glob that resolves to nothing |
| `sshd-E04` | Error | directive is not permitted inside a `Match` block (silently ignored at runtime) |
| `sshd-F01` | Fatal | `sshd_config` file does not parse |
| `sshd-F02` | Fatal | drop-in fragment overrides a required global directive |
| `sshd-W01` | Warning | STIG-required directive is missing |
| `sshd-W02` | Warning | directive value is weaker than the STIG baseline |
| `sshd-W03` | Warning | weak algorithm in Ciphers/MACs/KexAlgorithms/GSSAPIKexAlgorithms/HostKeyAlgorithms |
| `sshd-W04` | Warning | directive deprecated or removed in the target OpenSSH version |
| `sshd-W05` | Warning | `Match` block overrides a required global in a more permissive direction |
| `sshd-W06` | Warning | algorithm-list prefix operator (`+`/`-`/`^`) may reintroduce a weak default |
| `sshd-W07` | Warning | cross-`Match` shadow: a first-value-wins directive set to different values in two simultaneously-satisfiable `Match` blocks (sshd applies only the first; the later value is silently dropped) |

### sudoers (`sudo-`, 9 codes)

| Code | Severity | Checks |
| --- | --- | --- |
| `sudo-E01` | Error | reference to an undefined alias |
| `sudo-F01` | Fatal | sudoers file does not parse |
| `sudo-F02` | Fatal | contains a per-position token that `visudo` rejects but the classifier keeps as a clean spec (`#<digits>` in a command or `Defaults` value, a relative-path command, or an invalid `%group` name) |
| `sudo-W01` | Warning | `NOPASSWD` applies to an `ALL` command (passwordless run-anything) |
| `sudo-W02` | Warning | a `Cmnd_Alias` transitively expands to `ALL` under `NOPASSWD` |
| `sudo-W03` | Warning | alias defined but never referenced (dead alias) |
| `sudo-W04` | Warning | `Defaults` setting weaker than, or required hardening absent from, the sudo security baseline (covers weakening settings such as `!authenticate`, `targetpw`, `rootpw`, `visiblepw`, `!use_pty`, and negative `timestamp_timeout`; and missing-required checks for `use_pty`, I/O logging, and `timestamp_timeout` over the merged config - DISA STIG RHEL-08-010384/RHEL-09-432015 and CIS Benchmark 5.2.2/5.2.3) |
| `sudo-W05` | Warning | `NOPASSWD` grants passwordless sudo on a specific (non-ALL) command; STIG requires removing `NOPASSWD` entirely (DISA STIG RHEL-08-010380/RHEL-09-611085) |
| `sudo-W06` | Warning | a user specification grants the literal `ALL` user unrestricted privilege elevation (`ALL ALL=(ALL) ALL` / `ALL ALL=(ALL:ALL) ALL`, including `ALL` appearing among other list members and run-as specs inherited by later commands on the line) - DISA STIG RHEL-08-010382/RHEL-09-432030/RHEL-10-600520 |

### sysctl.d (`sysctld-`, 4 codes)

| Code | Severity | Checks | Gate |
| --- | --- | --- | --- |
| `sysctld-F01` | Fatal | `sysctl.d`/`sysctl.conf` file does not parse | always |
| `sysctld-W01` | Warning | last-wins conflict: the same key is assigned different effective values across the drop-in precedence order | always |
| `sysctld-W02` | Warning | STIG-required kernel-hardening key is unset or set to an insecure value (version-aware) | `--target` |
| `sysctld-W03` | Warning | cross-directory precedence surprise: a lower-precedence directory wins (W03-a), the procps and systemd appliers disagree on `/etc/sysctl.conf` (W03-b), or a masked same-basename drop-in silently drops a key (W03-c) | `--system` |
| `sysctld-W04` | Warning | CIS-Benchmark-required kernel-hardening key is unset or set to a value outside the benchmark-accepted set (version-aware) | `--target` |

### SELinux (`se-`, 2 codes)

| Code | Severity | Checks | Gate |
| --- | --- | --- | --- |
| `se-W01` | Warning | `SELINUX=` in `/etc/selinux/config` does not resolve to `enforcing` at boot (missing, commented out, or another value) | `--target rhel9`/`rhel10` |
| `se-W02` | Warning | `SELINUXTYPE=` is not `targeted` (missing or another policy type) | `--target rhel8` |

SELinux `triage` is denial analysis rather than file linting and has no lint codes of
its own: it categorizes each AVC denial by kind (floor classifier always; authoritative
libsepol categorizer with `--policy`) and can emit a `.te` module.

## Exit codes

The lint and analysis verbs share one contract:

| Code | Meaning |
| --- | --- |
| `0` | clean (no findings) |
| `1` | warnings present |
| `2` | errors present |
| `3` | tool failure (I/O, bad arguments) |
| `5` | input could not be parsed |

Three commands report their scorecard through the exit code instead:

- `fapolicyd doctor`: `0` all checks pass, `1` warnings, `2` one or more failures.
- `selinux doctor`: same contract (`0` pass, `1` warnings, `2` failures).
- `fapolicyd container-check`: `0` no risk, `1` WARN, `2` HIGH, `3` RHCOS (unsupported).

## Output formats

`--format` selects the surface. Availability follows a locked policy:

| Format | Available on |
| --- | --- |
| `human` | every command (default) |
| `json` | every structured command (versioned envelope) |
| `sarif` | `fapolicyd lint` only (findings-only, SARIF 2.1.0; `--sarif-include-pass` adds per-check pass results) |
| `csv` | flat-row verbs only: `fapolicyd report`, `fapolicyd trustdb list`, `auditd cost` |

OSCAL / HDF compliance exports are deferred; the register payload is pre-designed to map
to OSCAL, but no exporter ships in this release.

## How RuleSteward compares

`fapolicyd` ships a first-party checker: `fapolicyd-cli --check-rules` validates
rule syntax without loading the policy (exit `0` when valid), and
`--check-rules --lint` adds a small fixed set of hardcoded "default-allow"
policy-shape warnings. That is the right first stop for "is this rule file
syntactically valid, and does it have an obvious open-by-default gap?"

RuleSteward is the CI-grade semantic layer above that:

| Capability | `fapolicyd-cli --check-rules --lint` | RuleSteward |
| --- | --- | --- |
| Syntax validation | yes | yes |
| Policy-shape warnings | a small fixed set (default-allow reachability) | a documented lint-code taxonomy (25 fapolicyd codes today) |
| Whole-ruleset analysis (shadowing, ordering, subsumption) | no | yes |
| Machine-readable output | no (human text + exit code) | SARIF 2.1, JSON, CSV |
| Exit-code taxonomy | binary (zero / non-zero) | documented `0`/`1`/`2`/`3`/`5` contract |
| Version-aware linting | no | yes (`--target <fapolicyd-version>`) |
| Trust-database analysis | no | yes (`trustdb` + simulate/report/explain/doctor) |
| Other policy backends | fapolicyd only | + `sshd_config` lint, auditd semantic lint + cost, SELinux denial triage / TE emission |

Use `fapolicyd-cli --check-rules` as your local syntax gate; reach for
RuleSteward when you want CI-grade semantic analysis, machine-readable findings
for a pipeline, version-targeted rules, and coverage beyond fapolicyd. The two
are complementary, not mutually exclusive.

## License

Engine: **Apache-2.0**. The default build statically links vendored **libsepol**
(**LGPL-2.1-or-later**) for the authoritative SELinux categorizer; build with
`--no-default-features` for an Apache-2.0-only binary. Rule templates (separate repo):
**BSD-3-Clause**.
