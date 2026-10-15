"""Security headers check with conflict detection and evidence reporting."""
from __future__ import annotations

from veylance.core.findings import Severity
from veylance.modules.base import BaseModule

SECURITY_HEADERS = {
    "Strict-Transport-Security": (
        Severity.HIGH,
        "HSTS missing — browser is not forced to use HTTPS.",
        "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        "CWE-319", "A02:2021",
    ),
    "Content-Security-Policy": (
        Severity.HIGH, "CSP missing — higher XSS and code injection impact.",
        "Content-Security-Policy: default-src 'self'; object-src 'none'; base-uri 'self'",
        "CWE-1021", "A05:2021",
    ),
    "X-Frame-Options": (
        Severity.MEDIUM, "Clickjacking protection missing (neither X-Frame-Options nor frame-ancestors found).",
        "X-Frame-Options: DENY (or CSP frame-ancestors 'none')",
        "CWE-1021", "A05:2021",
    ),
    "X-Content-Type-Options": (
        Severity.MEDIUM, "MIME sniffing protection missing.",
        "X-Content-Type-Options: nosniff", "CWE-430", "A05:2021",
    ),
    "Referrer-Policy": (
        Severity.LOW, "Referrer-Policy missing — potential referrer leakage of sensitive URLs.",
        "Referrer-Policy: strict-origin-when-cross-origin", None, None,
    ),
    "Permissions-Policy": (
        Severity.LOW, "Permissions-Policy missing — browser features (camera, mic, geolocation) unrestricted.",
        "Permissions-Policy: camera=(), microphone=(), geolocation=()", None, None,
    ),
    "Cross-Origin-Opener-Policy": (
        Severity.LOW, "COOP missing — cross-origin window isolation not enforced.",
        "Cross-Origin-Opener-Policy: same-origin", None, None,
    ),
    "Cross-Origin-Resource-Policy": (
        Severity.LOW, "CORP missing — resource not isolated from cross-origin embedding.",
        "Cross-Origin-Resource-Policy: same-origin", None, None,
    ),
}


class HeadersModule(BaseModule):
    name = "headers"
    description = "Security headers, XFO/CSP conflicts, and info-leak headers"

    async def run(self):
        r = await self.session.get(self.target.base + "/")
        if r is None:
            return self.findings

        h = {k.lower(): v for k, v in r.headers.items()}
        csp = h.get("content-security-policy", "")
        xfo = h.get("x-frame-options", "")

        # 1. Missing Security Headers
        for name, (sev, msg, fix, cwe, owasp) in SECURITY_HEADERS.items():
            lname = name.lower()
            if lname == "x-frame-options" and "frame-ancestors" in csp:
                continue
            if lname == "strict-transport-security" and self.target.scheme != "https":
                continue
            if lname not in h:
                code_name = "CSP_MISSING" if lname == "content-security-policy" else f"HEADER_MISSING_{name.upper().replace('-', '_')}"
                self.add(
                    code=code_name,
                    severity=sev,
                    title=f"Missing security header: {name}",
                    detail=msg,
                    fix=f"Add response header: `{fix}`",
                    url=self.target.base,
                    evidence=f"Header '{name}' was not returned in HTTP response headers.",
                    cwe=cwe, owasp=owasp,
                )

        # 2. X-Frame-Options vs. CSP frame-ancestors Conflict Detection
        if xfo and "frame-ancestors" in csp:
            xfo_clean = xfo.strip().upper()
            # Extract frame-ancestors directive
            fa_part = ""
            for part in csp.split(";"):
                if "frame-ancestors" in part.lower():
                    fa_part = part.strip()
                    break

            if xfo_clean == "DENY" and ("'self'" in fa_part or "http" in fa_part):
                self.add(
                    severity=Severity.MEDIUM,
                    title="Conflict between X-Frame-Options and CSP frame-ancestors",
                    detail="X-Frame-Options is set to DENY while CSP frame-ancestors permits framing. "
                           "Modern browsers prioritize CSP frame-ancestors, but older browsers may block framing entirely.",
                    fix="Align frame-ancestors and X-Frame-Options, or deprecate X-Frame-Options if modern browser support suffices.",
                    url=self.target.base,
                    evidence=f"X-Frame-Options: '{xfo}' vs CSP: '{fa_part}'",
                    cwe="CWE-1021",
                )
            elif "ALLOW-FROM" in xfo_clean:
                self.add(
                    severity=Severity.LOW,
                    title="Obsolete X-Frame-Options ALLOW-FROM directive",
                    detail="X-Frame-Options ALLOW-FROM is deprecated and ignored by most modern browsers.",
                    fix="Use CSP frame-ancestors <source> instead.",
                    url=self.target.base,
                    evidence=f"X-Frame-Options: '{xfo}'",
                )

        # 3. Information Leak Headers
        for leak in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
                     "x-generator", "x-drupal-cache", "x-debug-token"):
            if leak in h:
                self.add(
                    severity=Severity.LOW,
                    title=f"Information disclosure header: {leak}",
                    detail=f"Server reveals internal software or framework version: `{h[leak]}`",
                    fix=f"Configure server/application to strip or mask the '{leak}' response header.",
                    url=self.target.base,
                    evidence=f"{leak}: {h[leak]}",
                    cwe="CWE-200",
                )

        # 4. Deep CSP analysis in headers
        if csp:
            if "'unsafe-inline'" in csp:
                self.add(
                    severity=Severity.MEDIUM,
                    title="CSP contains 'unsafe-inline'",
                    detail="Inline script execution is allowed, significantly reducing defense against Cross-Site Scripting (XSS).",
                    fix="Remove 'unsafe-inline' and use cryptographic nonces (nonce-...) or SHA hashes.",
                    url=self.target.base,
                    evidence=f"Content-Security-Policy: {csp[:250]}...",
                    cwe="CWE-79",
                    owasp="A03:2021",
                )
            if "'unsafe-eval'" in csp:
                self.add(
                    severity=Severity.LOW,
                    title="CSP contains 'unsafe-eval'",
                    detail="eval() and dynamic code generation are permitted.",
                    fix="Refactor code to avoid eval(), setTimeout(string), or Function() constructors.",
                    url=self.target.base,
                    evidence=f"Content-Security-Policy: {csp[:250]}...",
                    cwe="CWE-95",
                )
            if "*" in csp and ("default-src" in csp or "script-src" in csp):
                self.add(
                    severity=Severity.MEDIUM,
                    title="CSP allows wildcard (*) resource sources",
                    detail="Wildcard '*' allows loading resources or scripts from any domain on the internet.",
                    fix="Replace '*' with an explicit allowlist of trusted origins or 'self'.",
                    url=self.target.base,
                    evidence=f"Content-Security-Policy: {csp[:250]}...",
                )
            if "report-uri" not in csp and "report-to" not in csp:
                self.add(
                    severity=Severity.INFO,
                    title="CSP violation reporting endpoint missing",
                    detail="No 'report-uri' or 'report-to' directive configured to capture policy violations.",
                    fix="Add 'report-to <group>' or 'report-uri <url>' to monitor blocked scripts and attacks in production.",
                    url=self.target.base,
                    evidence=f"Content-Security-Policy: {csp[:150]}...",
                )

        return self.findings