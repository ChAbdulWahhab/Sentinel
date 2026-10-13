"""DNS / email security recon."""
from __future__ import annotations

import asyncio
import dns.resolver
import dns.exception

from sentinelscan.core.findings import Severity
from sentinelscan.modules.base import BaseModule


class DnsReconModule(BaseModule):
    name = "dns_recon"
    description = "DNS records, SPF/DMARC/DKIM email security"

    async def run(self):
        host = self.target.host
        loop = asyncio.get_event_loop()

        async def safe(qname, rtype):
            try:
                return await loop.run_in_executor(None, lambda: dns.resolver.resolve(qname, rtype, lifetime=5))
            except Exception:
                return None

        # SPF
        txt = await safe(host, "TXT")
        spf = None
        if txt:
            for r in txt:
                s = r.to_text().strip('"')
                if s.startswith("v=spf1"):
                    spf = s
        if not spf:
            self.add(
                severity=Severity.MEDIUM,
                title="SPF record missing",
                detail=f"{host} ke liye koi SPF TXT record nahi mila.",
                fix='DNS mein add karein: v=spf1 include:_spf.google.com ~all (apne provider ke hisaab se)',
            )

        # DMARC
        dmarc = await safe(f"_dmarc.{host}", "TXT")
        dmarc_val = dmarc[0].to_text().strip('"') if dmarc else None
        if not dmarc_val:
            self.add(
                severity=Severity.MEDIUM,
                title="DMARC record missing",
                detail=f"_dmarc.{host} par koi record nahi.",
                fix="v=DMARC1; p=quarantine; rua=mailto:dmarc@" + host,
            )
        elif "p=none" in dmarc_val:
            self.add(
                severity=Severity.LOW,
                title="DMARC policy weak (p=none)",
                detail=dmarc_val,
                fix="p=quarantine ya p=reject par move karein.",
            )

        # MX
        mx = await safe(host, "MX")
        if mx:
            self.ctx.setdefault("info", {})["MX records"] = [str(r.exchange) for r in mx]

        # A / AAAA / CNAME
        for rtype in ("A", "AAAA", "CNAME", "NS"):
            ans = await safe(host, rtype)
            if ans:
                self.ctx.setdefault("info", {})[f"{rtype} records"] = [r.to_text() for r in ans]

        # Zone transfer attempt (safe, fail-fast)
        ns = await safe(host, "NS")
        if ns:
            self.ctx.setdefault("info", {})["Zone transfer attempt"] = "NS mila — manually test karein"

        return self.findings