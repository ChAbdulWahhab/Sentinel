"""Deep Content-Security-Policy (CSP) directive-level analysis."""
from __future__ import annotations

from veylance.core.findings import Severity
from veylance.modules.base import BaseModule

DANGEROUS_CSP_TOKENS = {
    "'unsafe-inline'": (
        Severity.HIGH,
        "Inline script execution permitted — enables execution of injected XSS payloads.",
        "Remove 'unsafe-inline' and implement cryptographic nonces or hash sources.",
    ),
    "'unsafe-eval'": (
        Severity.MEDIUM,
        "eval() and dynamic string execution allowed — undermines script execution boundaries.",
        "Refactor JavaScript code to avoid eval(), new Function(), or setTimeout with string arguments.",
    ),
    "data:": (
        Severity.MEDIUM,
        "data: scheme allowed for scripts/resources — can be abused to bypass origin restrictions.",
        "Disallow data: in script-src, object-src, and default-src directives.",
    ),
    "*": (
        Severity.MEDIUM,
        "Wildcard source '*' allows resources from arbitrary domains.",
        "Specify explicit domain origins (e.g. 'self' https://api.example.com) instead of wildcard '*'.",
    ),
    "http:": (
        Severity.MEDIUM,
        "Insecure http: protocol explicitly allowed — susceptible to Man-In-The-Middle (MITM) tampering.",
        "Require secure https: schemes or use 'self' with upgrade-insecure-requests.",
    ),
}


class CspAnalyzerModule(BaseModule):
    name = "csp_analyzer"
    description = "CSP directive-level analysis, wildcard and unsafe execution detection"

    async def run(self):
        r = await self.session.get(self.target.root)
        if r is None:
            return self.findings
        csp = r.headers.get("content-security-policy", "")
        if not csp:
            return self.findings  # headers module already flags missing CSP

        info = self.ctx.setdefault("info", {})
        info["CSP"] = csp[:500]

        directives: dict[str, list[str]] = {}
        for part in csp.split(";"):
            part = part.strip()
            if not part:
                continue
            bits = part.split()
            directives[bits[0].lower()] = [b.lower() for b in bits[1:]]

        # 1. Missing Core Directives
        critical_directives = {
            "default-src": (Severity.HIGH, "Fallback directive 'default-src' missing."),
            "script-src": (Severity.HIGH, "Dedicated 'script-src' directive missing — script execution defaults to broad rules."),
            "object-src": (Severity.MEDIUM, "Directives for plugins 'object-src' missing."),
            "base-uri": (Severity.LOW, "Missing 'base-uri' directive allows malicious <base href> tags to hijack relative URLs."),
            "frame-ancestors": (Severity.MEDIUM, "Missing 'frame-ancestors' directive leaves site vulnerable to clickjacking."),
        }

        for d, (sev, desc) in critical_directives.items():
            if d not in directives:
                # If default-src is present, some directives fall back to it
                if d in ("script-src", "object-src") and "default-src" in directives:
                    continue
                self.add(
                    severity=sev,
                    title=f"CSP directive missing: {d}",
                    detail=desc,
                    fix=f"Add '{d}' to your Content-Security-Policy header.",
                    url=self.target.base,
                    evidence=f"Active directives: {', '.join(directives.keys())}",
                    cwe="CWE-1021",
                )

        # 2. Check for Dangerous Tokens in script-sensitive directives
        for token, (sev, msg, fix) in DANGEROUS_CSP_TOKENS.items():
            if token in csp.lower():
                self.add(
                    severity=sev,
                    title=f"Weak CSP directive: contains {token}",
                    detail=msg,
                    fix=fix,
                    url=self.target.base,
                    evidence=f"Found '{token}' in: {csp[:300]}",
                    cwe="CWE-79" if "inline" in token else "CWE-1021",
                )

        # 3. object-src 'none' verification
        if "object-src" in directives:
            if "'none'" not in directives["object-src"]:
                self.add(
                    severity=Severity.LOW,
                    title="CSP object-src is not set to 'none'",
                    detail="Plugin execution (Flash, Java applets) is not completely prohibited.",
                    fix="Set 'object-src 'none';' in Content-Security-Policy.",
                    url=self.target.base,
                    evidence=f"object-src: {' '.join(directives['object-src'])}",
                )

        # 4. base-uri verification
        if "base-uri" in directives:
            sources = directives["base-uri"]
            if "'none'" not in sources and "'self'" not in sources and "*" in sources:
                self.add(
                    severity=Severity.LOW,
                    title="CSP base-uri allows wildcard (*)",
                    detail="Allows attackers to inject arbitrary <base> tags.",
                    fix="Restrict 'base-uri' to 'self' or 'none'.",
                    url=self.target.base,
                    evidence=f"base-uri: {' '.join(sources)}",
                )

        return self.findings