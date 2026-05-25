# RuleSteward

**Modular RHEL hardening toolkit** - read-only, CI-friendly static analysis and live triage for `fapolicyd`, SELinux, and `auditd`.

> Compatible with **DISA STIG RHEL 8/9/10** and **ACSC Essential Eight** application control objectives.

## Status

`0.1.0-dev` - workspace scaffold. No domain code yet. See [`.private-docs/handoff-session-2.md`](.private-docs/handoff-session-2.md) for the next implementation milestone (fapolicyd parser + `rulesteward fapolicyd lint`).

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

Pre-built static binaries for `x86_64-unknown-linux-musl` will ship via GitHub Releases. Until then:

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
