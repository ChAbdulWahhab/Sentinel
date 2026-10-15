"""CORS misconfiguration checks: reflected origin, credentials wildcard, and null origin handling."""
from __future__ import annotations

from veylance.core.findings import Severity
from veylance.modules.base import BaseModule


class CorsModule(BaseModule):
    name = "cors"
    description = "CORS misconfiguration: arbitrary origin reflection, credentials+wildcard, and null origin"
    requires_crawl = True

    async def run(self):
        evil = "https://evil.example.com"
        targets = [self.target.root]
        for e in list(self.ctx.get("js_endpoints", []))[:3]:
            if e.startswith("/"):
                targets.append(self.target.base + e)

        for t in targets:
            # 1. Test Reflected Origin & Wildcard
            r = await self.session.get(t, headers={"Origin": evil})
            if r is not None:
                acao = r.headers.get("access-control-allow-origin")
                acac = r.headers.get("access-control-allow-credentials", "").lower() == "true"

                if acao == evil and acac:
                    self.add(
                        severity=Severity.HIGH,
                        title="Critical CORS misconfiguration: arbitrary Origin reflection with credentials",
                        detail=f"The server reflected untrusted origin '{evil}' and allowed credentials (cookies/tokens). "
                               "Any malicious site can make authenticated cross-origin requests and read private user data.",
                        fix="Do not reflect arbitrary Origin headers. Maintain an explicit allowlist of trusted origins, and never allow credentials with unvalidated origins.",
                        url=t,
                        evidence=f"Request: Origin: {evil} -> Response: ACAO: {acao}, ACAC: true",
                        cwe="CWE-942",
                        owasp="A01:2021",
                    )
                elif acao == evil:
                    self.add(
                        severity=Severity.MEDIUM,
                        title="CORS arbitrary Origin reflection",
                        detail=f"The server reflects arbitrary origins ('{evil}') in Access-Control-Allow-Origin.",
                        fix="Validate the Origin header against a strict allowlist of trusted domain names.",
                        url=t,
                        evidence=f"Request: Origin: {evil} -> Response: ACAO: {acao}",
                        cwe="CWE-942",
                    )
                elif acao == "*" and acac:
                    self.add(
                        severity=Severity.HIGH,
                        title="CORS: wildcard (*) with credentials enabled",
                        detail="Access-Control-Allow-Origin is set to '*' while Access-Control-Allow-Credentials is true. "
                               "While modern browsers block this combination, it indicates server-side configuration error.",
                        fix="Specify explicit trusted origins when credentials support is required.",
                        url=t,
                        evidence="Access-Control-Allow-Origin: *, Access-Control-Allow-Credentials: true",
                    )
                elif acao == "*":
                    self.add(
                        severity=Severity.LOW,
                        title="CORS wildcard (*) allowed",
                        detail="Endpoint allows public cross-origin reads from any website.",
                        fix="Ensure this endpoint only exposes public, non-sensitive resources.",
                        url=t,
                        evidence="Access-Control-Allow-Origin: *",
                    )

            # 2. Test Null Origin Handling (Origin: null)
            r_null = await self.session.get(t, headers={"Origin": "null"})
            if r_null is not None:
                acao_null = r_null.headers.get("access-control-allow-origin")
                acac_null = r_null.headers.get("access-control-allow-credentials", "").lower() == "true"

                if acao_null == "null":
                    sev = Severity.HIGH if acac_null else Severity.MEDIUM
                    self.add(
                        severity=sev,
                        title="CORS accepts 'null' origin",
                        detail="The server allows 'null' in Access-Control-Allow-Origin. Attackers can trigger requests with Origin: null "
                               "via sandboxed iframes (<iframe sandbox='allow-scripts'>) or local file schemes to bypass origin checks.",
                        fix="Disallow 'null' as a valid CORS origin. Validate only explicitly authorized HTTP/HTTPS origins.",
                        url=t,
                        evidence=f"Request: Origin: null -> Response: ACAO: null, ACAC: {acac_null}",
                        cwe="CWE-942",
                        owasp="A01:2021",
                    )

        return self.findings