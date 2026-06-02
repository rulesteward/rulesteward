# RuleSteward

**Modular RHEL hardening toolkit** - read-only, CI-friendly static analysis and live triage for `fapolicyd`, `SELinux`, and `auditd`.

> Compatible with **DISA STIG RHEL 8/9/10** and **ACSC Essential Eight** application control objectives.

## Design principles

- **Read-only by default.** Every mutation flag is opt-in.
- **Unprivileged-friendly.** Static analysis paths never require root.
- **No telemetry, ever.** No phone-home, no anonymous metrics.
- **Exit-code-driven.** CI-grade exit codes (`0` clean / `1` warnings / `2` errors / `3` tool failure / `5` rule-parse-error).
- **Multiple output formats.** Human (default), JSON, SARIF (roadmap).

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

## License

Engine: **Apache-2.0**. Rule templates (separate repo): **BSD-3-Clause**.
