# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

---

## Reporting a Vulnerability

We prioritize the security and stability of SentinelScan. If you discover a vulnerability or security defect within SentinelScan itself (such as command injection, path traversal, untrusted deserialization, or credential leakage):

1. **Do not create a public GitHub issue.**
2. Send an email to the project maintainers or open a confidential security advisory via GitHub Security Advisories.
3. Include detailed reproduction steps, proof-of-concept payloads, and affected versions.

### What to Expect:
- **Initial Response:** Within 48 hours acknowledging receipt of your report.
- **Triage & Assessment:** Regular status updates while the issue is being investigated and patched.
- **Public Disclosure:** Coordinated release and disclosure timeline following the publication of a remediation patch.

---

## Safe Testing of SentinelScan
When conducting research or developing tests against SentinelScan:
- Test using mock local HTTP servers or local loopback instances (`localhost` / `127.0.0.1`).
- Avoid scanning production third-party web properties without explicit authorization.
- Never include sensitive API keys, production tokens, or customer credentials in automated test fixtures.
