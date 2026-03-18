# Security Policy

## Supported Versions

InnerWarden is currently a `0.x` project. Security fixes are handled on a best-effort basis for the latest development line.

| Version | Supported |
| --- | --- |
| latest `main` | Yes |
| older snapshots | Best effort only |

## Reporting a Vulnerability

Please do not open public issues for suspected vulnerabilities that could put users or hosts at risk.

Preferred process:

1. Use GitHub private vulnerability reporting if it is enabled for the repository.
2. If private reporting is unavailable, contact the maintainer privately through the repository profile.
3. Include reproduction steps, impact, affected configuration, and any suggested mitigation.

Helpful details:

- InnerWarden version or commit SHA
- deployment mode (`local`, `trial`, `dashboard`, `honeypot`, etc.)
- whether responder actions were enabled
- whether the issue affects confidentiality, integrity, or availability

## Response Expectations

The project will try to:

- acknowledge receipt quickly
- validate the issue
- coordinate a fix or mitigation
- avoid publishing sensitive details before a fix is available

Because this is a small actively developed project, timelines are best-effort rather than guaranteed.
