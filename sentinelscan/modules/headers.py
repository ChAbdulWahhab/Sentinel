"""Security headers check."""
from __future__ import annotations

from sentinelscan.core.findings import Severity
from sentinelscan.modules.base import BaseModule

SECURITY_HEADERS = {
    "Strict-Transport-Security": (
        Severity.HIGH,
        "HSTS missing — browser is not forced to use HTTPS.",
        "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        "CWE-319", "A02:2021",
    ),
    "Content-Security-Policy": (
        Severity.HIGH, "CSP missing — higher XSS impact.",
        "Content-Security-Policy: default-src 'self'; object-src 'none'; base-uri 'self'",
        "CWE-1021", "A05:2021",
    ),
    "X-Frame-Options": (
        Severity.MEDIUM, "Clickjacking protection missing.",
        "X-Frame-Options: DENY (or CSP frame-ancestors 'none')",
        "CWE-1021", "A05:2021",
    ),
    "X-Content-Type-Options": (
        Severity.MEDIUM, "MIME sniffing protection missing.",
        "X-Content-Type-Options: nosniff", "CWE-430", "A05:2021",
    ),
    "Referrer-Policy": (
        Severity.LOW, "Referrer-Policy missing.",
        "Referrer-Policy: strict-origin-when-cross-origin", None, None,
    ),
    "Permissions-Policy": (
        Severity.LOW, "Permissions-Policy missing.",
        "Permissions-Policy: camera=(), microphone=(), geolocation=()", None, None,
    ),
    "Cross-Origin-Opener-Policy": (
        Severity.LOW, "COOP missing.",
        "Cross-Origin-Opener-Policy: same-origin", None, None,
    ),
    "Cross-Origin-Resource-Policy": (
        Severity.LOW, "CORP missing.",
        "Cross-Origin-Resource-Policy: same-origin", None, None,
    ),
}


class HeadersModule(BaseModule):
    name = "headers"
    description = "Security headers + info-leak headers"

    async def run(self):
        r = await self.session.get(self.target.base + "/")
        if r is None:
            return self.findings

        h = {k.lower(): v for k, v in r.headers.items()}
        csp = h.get("content-security-policy", "")

        for name, (sev, msg, fix, cwe, owasp) in SECURITY_HEADERS.items():
            lname = name.lower()
            if lname == "x-frame-options" and "frame-ancestors" in csp:
                continue
            if lname == "strict-transport-security" and self.target.scheme != "https":
                continue
            if lname not in h:
                self.add(
                    severity=sev,
                    title=f"Missing header: {name}",
                    detail=msg, fix=f"`{fix}`",
                    url=self.target.base,
                    cwe=cwe, owasp=owasp,
                )

        # Info leak headers
        for leak in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
                     "x-generator", "x-drupal-cache", "x-debug-token"):
            if leak in h:
                self.add(
                    severity=Severity.LOW,
                    title=f"Info leak header: {leak}",
                    detail=f"`{leak}: {h[leak]}`",
                    fix="Remove version information or keep it generic.",
                    url=self.target.base,
                )

        # Deep CSP analysis
        if csp:
            if "'unsafe-inline'" in csp or "'unsafe-eval'" in csp:
                self.add(
                    severity=Severity.LOW,
                    title="CSP contains unsafe-inline / unsafe-eval",
                    detail=csp[:200],
                    fix="Use nonce- or hash-based CSP.",
                    url=self.target.base, owasp="A05:2021",
                )
            if "*" in csp and "default-src" in csp:
                self.add(
                    severity=Severity.MEDIUM,
                    title="CSP allows wildcard (*)",
                    detail=csp[:200],
                    fix="Use an explicit allowlist.",
                    url=self.target.base,
                )
            if "report-uri" not in csp and "report-to" not in csp:
                self.add(
                    severity=Severity.INFO,
                    title="CSP reporting endpoint missing",
                    detail="CSP violations are not being reported.",
                    fix="Add report-to / report-uri.",
                    url=self.target.base,
                )
        return self.findings