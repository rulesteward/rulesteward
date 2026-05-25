# Security Policy

## Reporting a vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report privately via either channel:

1. **GitHub Security Advisories** - preferred. Use the "Report a vulnerability" button on the [Security tab](https://github.com/rulesteward/rulesteward/security/advisories/new).
2. **Email** - `rulesteward+security@rulesteward.com` (PGP key fingerprint to be published before v0.1.0 GA).

Please include:
- Affected version (`rulesteward --version`)
- Reproduction steps or proof-of-concept
- Impact assessment from your perspective
- Whether you intend to publicly disclose, and a proposed timeline

## Response targets

- Acknowledgement: within **3 business days**
- Initial triage + severity rating: within **7 business days**
- Coordinated disclosure window: **90 days** by default, negotiable for high-impact issues

## Supported versions

During the `0.x` series, only the **latest released minor** receives security fixes. Post-1.0, the latest two minors are supported.

## Scope

In-scope:
- The `rulesteward` binary and all crates under `crates/`
- The CI pipeline and release artifacts (signed binaries, RPMs)

Out-of-scope:
- Upstream `fapolicyd`, `selinux`, `auditd` - report to the respective project
- Rule-template repository (separate `SECURITY.md` lives there)
- Issues that require a malicious local administrator with root access

## Safe harbor

Good-faith research conducted within this policy will not result in legal action. We will work with you on coordinated disclosure.
