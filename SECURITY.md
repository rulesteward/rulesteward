# Security Policy

RuleSteward is a security-focused policy linter. We take vulnerabilities in the
tool itself seriously and appreciate reports from the community.

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, use GitHub's private vulnerability reporting:

1. Go to the repository's **Security** tab.
2. Click **Report a vulnerability**.
3. Fill in the advisory form.

This opens a private GitHub Security Advisory visible only to the maintainers and
to you.

When reporting, please include:

- The affected version, tag, or commit SHA.
- Steps to reproduce, or a proof-of-concept.
- The impact you believe the issue has.

## What to Expect

This is a small, maintainer-driven project, so responses are best-effort rather
than bound by a fixed SLA:

- We aim to acknowledge a report within a few days.
- We will work with you on a coordinated disclosure timeline before any public
  details are published.
- We will credit reporters in the advisory unless you ask us not to.

## Supported Versions

| Version           | Supported          |
| ----------------- | ------------------ |
| Latest release    | :white_check_mark: |
| `main` branch     | :white_check_mark: |
| Older releases    | :x:                |

Security fixes are applied to the latest release line and `main`.

## Scope Notes

- The engine is licensed under Apache-2.0.
- RuleSteward is read-only by default and performs no telemetry; every write or
  mutation is behind an explicit opt-in flag.
