# Veylance Terms of Service

**Terms Version:** 1.0  
**Effective Date:** October 2026

By installing, copying, executing, or otherwise using Veylance (including command-line interfaces `veyl`, interactive terminal menus, and programmatic APIs), you agree to be bound by these Terms of Service.

---

### 1. Scope and Eligibility
Veylance is intended solely for defensive cybersecurity practitioners, website administrators, developers, and security researchers conducting authorized audits. You represent and warrant that you possess the full legal power and authority to enter into these Terms and perform all testing actions requested.

---

### 2. Authorization Covenant
Before scanning any domain, hostname, IP address, or URL, you explicitly covenant that:
1. You are the registered domain owner or administrative controller of the target infrastructure, OR
2. You hold explicit, active, and demonstrable written authorization from the system owner permitting automated security assessment.

Using command-line flags such as `--yes`, `-y`, or `--i-own-this <domain>`, or confirming interactive consent prompts, constitutes your formal and legally binding declaration of authorization.

---

### 3. Prohibited Conduct
You agree not to use Veylance for:
- Scanning, probing, crawling, or fingerprinting systems, APIs, or networks without documented permission.
- Conducting denial-of-service (DoS) or distributed denial-of-service (DDoS) attacks.
- Exploiting discovered vulnerabilities, extracting unauthorized databases, modifying remote assets, or planting backdoors.
- Defeating, bypassing, or tampering with technological protection measures of third parties.
- Any unlawful purpose under municipal, state, federal, or international cybercrime statutes.

---

### 4. Audit Logging & Compliance Records
To support security hygiene and compliance auditing, Veylance records operational logs (including target hostnames, timestamps, and declared authorization methods) to local user storage (`~/.veylance/audit.log`). You acknowledge and agree that these local records reflect your usage history.

---

### 5. Indemnification
You agree to indemnify, defend, and hold harmless Veylance's authors, maintainers, contributors, and distributors from and against any claims, liabilities, damages, losses, costs, expenses, or fees (including reasonable legal fees) arising from:
- Your use or misuse of the software.
- Any unauthorized scanning activities initiated by your environment.
- Your violation of these Terms or the legal rights of any third party.

---

### 6. Modifications to Terms
The maintainers may update these Terms from time to time. When terms are modified, the terms version will bump (e.g. from `1.0` to `1.1`), prompting users to review and re-confirm consent upon subsequent CLI or interactive execution.
