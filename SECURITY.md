# Security Policy

Tremelay is released security software (v1). Its limits are stated as facts in the README: no independent security audit yet, releases are checksummed but not signed, and brokered response content is not screened for prompt injection (H1).

## Reporting vulnerabilities

Until a dedicated private reporting channel is configured, do not publish exploitable vulnerability details in a public issue. Maintainers should configure GitHub Private Vulnerability Reporting before the first credential-handling release.

## Security posture

The project treats secret non-disclosure, authorization boundaries, audit integrity, and destination controls as core product requirements. See `SECURITY_INVARIANTS.md` and `THREAT_MODEL.md`.
