"""CORS misconfiguration check."""
from __future__ import annotations

from veylance.core.findings import Severity
from veylance.modules.base import BaseModule


class CorsModule(BaseModule):
    name = "cors"
    description = "CORS misconfiguration (Origin reflect, wildcard + credentials)"
    requires_crawl = True

    async def run(self):
        evil = "https://evil.example"
        targets = [self.target.root]
        for e in list(self.ctx.get("js_endpoints", []))[:3]:
            if e.startswith("/"):
                targets.append(self.target.base + e)

        for t in targets:
            r = await self.session.get(t, headers={"Origin": evil})
            if r is None:
                continue
            acao = r.headers.get("access-control-allow-origin")
            acac = r.headers.get("access-control-allow-credentials", "").lower() == "true"

            if acao == evil and acac:
                self.add(severity=Severity.HIGH,
                         title=f"CORS: arbitrary Origin reflect + credentials ({t})",
                         detail=f"ACAO={acao}, ACAC=true",
                         fix="Use an explicit origin allowlist; never reflect arbitrary origins with credentials enabled.",
                         url=t, cwe="CWE-942", owasp="A05:2021")
            elif acao == evil:
                self.add(severity=Severity.MEDIUM,
                         title=f"CORS: arbitrary Origin reflect ({t})",
                         detail=f"ACAO={acao}",
                         fix="Strict origin allowlist.",
                         url=t, cwe="CWE-942")
            elif acao == "*" and acac:
                self.add(severity=Severity.HIGH,
                         title=f"CORS: wildcard + credentials ({t})",
                         detail="ACAO=*, ACAC=true — browsers usually block but misconfig.",
                         fix="Replace the wildcard with an explicit list of trusted origins.",
                         url=t)
            elif acao == "*":
                self.add(severity=Severity.LOW,
                         title=f"CORS wildcard (*) ({t})",
                         detail="Acceptable only for public APIs that serve non-sensitive data.",
                         fix="Restrict allowed origins to specific trusted domains on sensitive endpoints.",
                         url=t)
        return self.findings