"""Deep CSP analysis."""
from __future__ import annotations

from veylance.core.findings import Severity
from veylance.modules.base import BaseModule

DANGEROUS = {
    "'unsafe-inline'": ("HIGH", "Inline scripts allowed — XSS easy."),
    "'unsafe-eval'": ("MEDIUM", "eval() allowed."),
    "data:": ("MEDIUM", "data: URIs allowed — XSS possible."),
    "*": ("MEDIUM", "Wildcard source."),
    "http:": ("MEDIUM", "Insecure http: sources allowed."),
    "https://*": ("LOW", "Wildcard HTTPS."),
}


class CspAnalyzerModule(BaseModule):
    name = "csp_analyzer"
    description = "CSP directive-level analysis"

    async def run(self):
        r = await self.session.get(self.target.root)
        if r is None:
            return self.findings
        csp = r.headers.get("content-security-policy", "")
        if not csp:
            return self.findings  # headers module already flagged missing

        info = self.ctx.setdefault("info", {})
        info["CSP"] = csp[:500]

        directives = {}
        for part in csp.split(";"):
            part = part.strip()
            if not part:
                continue
            bits = part.split()
            directives[bits[0]] = bits[1:]

        # missing important directives
        for d in ("default-src", "script-src", "object-src", "base-uri", "frame-ancestors"):
            if d not in directives:
                self.add(severity=Severity.MEDIUM if d in ("script-src", "object-src") else Severity.LOW,
                         title=f"CSP directive missing: {d}",
                         detail=csp[:200],
                         fix=f"Define the '{d}' directive in Content-Security-Policy.",
                         url=self.target.base)

        for token, (sev, msg) in DANGEROUS.items():
            if token in csp:
                self.add(
                    severity=getattr(Severity, sev),
                    title=f"Dangerous CSP token: {token}",
                    detail=msg,
                    fix="Implement a strict nonce- or hash-based Content-Security-Policy.",
                    url=self.target.base, cwe="CWE-1021",
                )

        if "object-src" in directives and "'none'" not in directives["object-src"]:
            self.add(severity=Severity.LOW, title="CSP object-src is not set to 'none'",
                     detail=str(directives["object-src"]),
                     fix="Set the 'object-src' directive to 'none' to block plugin execution.",
                     url=self.target.base)
        return self.findings