# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| v1.x    | :white_check_mark: |
| < v1.0  | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please report it responsibly.

**Do not open a public issue.**

Instead, please email **basel5001** or use [GitHub's private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability) on this repository.

Please include:

- A description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We will acknowledge receipt within 48 hours and aim to release a patch within 7 days for confirmed issues.

## Security Scanning

This repository uses:

- **Gitleaks** for secret scanning
- **CodeQL** for static analysis
- **Dependency Review** for pull request dependency checks
- **Renovate** for automated dependency updates
