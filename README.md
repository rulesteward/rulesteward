# RuleSteward

**Modular RHEL hardening toolkit** - read-only, CI-friendly static analysis and live triage for `fapolicyd`, `SELinux`, and `auditd`.

> Compatible with **DISA STIG RHEL 8/9/10** and **ACSC Essential Eight** application control objectives.

## Design principles

- **Read-only by default.** Every mutation flag is opt-in.
- **Unprivileged-friendly.** Static analysis paths never require root.
- **No telemetry, ever.** No phone-home, no anonymous metrics.
- **Exit-code-driven.** CI-grade exit codes (`0` clean / `1` warnings / `2` errors / `3` tool failure / `5` rule-parse-error).
- **Multiple output formats.** Human (default), JSON, SARIF, and CSV (for tabular output).

## Modules

| Crate | Purpose |
| --- | --- |
| `rulesteward-core` | Shared types: diagnostics, severity, AST |
| `rulesteward-fapolicyd` | fapolicyd rule parser, trust-DB reader, audit-log reader |
| `rulesteward-selinux` | AVC parser, triage |
| `rulesteward-auditd` | auditd rules parser, cost calculator |
| `rulesteward-license` | Offline JWT verification (post-v0.1) |
| `rulesteward-sink` | `EventSink` trait + implementations |
| `rulesteward-cli` | `rulesteward` binary |

## Install

Pre-built static `x86_64-unknown-linux-musl` binaries ship via GitHub Releases. Three install paths:

### 1. Download the signed static binary (recommended)

Each release attaches the `rulesteward` binary, a `SHA256SUMS` file, and a cosign keyless signature (`SHA256SUMS.sig` + `SHA256SUMS.pem`). Verify integrity and authenticity before running:

```bash
# Download rulesteward, SHA256SUMS, SHA256SUMS.sig, SHA256SUMS.pem from the release.
sha256sum -c SHA256SUMS                       # integrity
cosign verify-blob \                          # authenticity (Sigstore keyless, no key to manage)
  --certificate SHA256SUMS.pem \
  --signature SHA256SUMS.sig \
  --certificate-identity-regexp '^https://github.com/rulesteward/rulesteward' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  SHA256SUMS
chmod +x rulesteward && ./rulesteward --version
```

### 2. RPM (RHEL / Rocky / AlmaLinux 8, 9, 10)

```bash
sudo dnf install ./rulesteward-<version>.x86_64.rpm
```

### 3. Build from source (Rust developers)

```bash
cargo install --git https://github.com/rulesteward/rulesteward rulesteward-cli
```

## Usage

```bash
rulesteward --help                    # umbrella help
rulesteward fapolicyd lint            # static-analyze /etc/fapolicyd/rules.d/
rulesteward fapolicyd lint --help     # per-command help
```

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
| Trust-database analysis | no | yes |
| Other policy backends | fapolicyd only | + SELinux denial triage / TE emission, auditd cost analysis |

Use `fapolicyd-cli --check-rules` as your local syntax gate; reach for
RuleSteward when you want CI-grade semantic analysis, machine-readable findings
for a pipeline, version-targeted rules, and coverage beyond fapolicyd. The two
are complementary, not mutually exclusive.

## License

Engine: **Apache-2.0**. Rule templates (separate repo): **BSD-3-Clause**.
