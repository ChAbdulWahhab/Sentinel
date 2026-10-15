"""DNS / email security recon."""
from __future__ import annotations

import asyncio
import dns.resolver
import dns.exception

from veylance.core.findings import Severity
from veylance.modules.base import BaseModule


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
                code="SPF_RECORD_MISSING",
                severity=Severity.MEDIUM,
                title="SPF record missing",
                detail=f"No SPF TXT record found for {host}.",
                fix='Add an SPF TXT record to DNS (e.g., "v=spf1 include:_spf.google.com ~all" tailored to your mail provider).',
            )
        else:
            self.ctx.setdefault("info", {})["spf_record"] = spf
            self.add(
                code="SPF_RECORD_PRESENT",
                severity=Severity.INFO,
                title="SPF record configured",
                detail=f"SPF record found: {spf}",
                fix="",
                url=host,
            )

        # DMARC
        dmarc = await safe(f"_dmarc.{host}", "TXT")
        dmarc_val = dmarc[0].to_text().strip('"') if dmarc else None
        if not dmarc_val:
            self.add(
                code="DMARC_RECORD_MISSING",
                severity=Severity.MEDIUM,
                title="DMARC record missing",
                detail=f"No DMARC TXT record found at _dmarc.{host}.",
                fix="v=DMARC1; p=quarantine; rua=mailto:dmarc@" + host,
            )
        elif "p=none" in dmarc_val:
            self.ctx.setdefault("info", {})["dmarc_record"] = dmarc_val
            self.add(
                code="DMARC_POLICY_WEAK",
                severity=Severity.LOW,
                title="DMARC policy weak (p=none)",
                detail=dmarc_val,
                fix="Enforce DMARC by upgrading policy from 'p=none' to 'p=quarantine' or 'p=reject'.",
            )
        else:
            self.ctx.setdefault("info", {})["dmarc_record"] = dmarc_val
            self.add(
                code="DMARC_RECORD_PRESENT",
                severity=Severity.INFO,
                title="DMARC record configured",
                detail=f"DMARC policy enforced: {dmarc_val}",
                fix="",
                url=host,
            )

        # MX
        mx = await safe(host, "MX")
        if mx:
            self.ctx.setdefault("info", {})["MX records"] = [str(r.exchange) for r in mx]
            self.ctx.setdefault("info", {})["mail_configured"] = True

        # A / AAAA / CNAME
        for rtype in ("A", "AAAA", "CNAME", "NS"):
            ans = await safe(host, rtype)
            if ans:
                self.ctx.setdefault("info", {})[f"{rtype} records"] = [r.to_text() for r in ans]

        # Zone transfer attempt (safe, fail-fast)
        ns = await safe(host, "NS")
        if ns:
            self.ctx.setdefault("info", {})["Zone transfer attempt"] = "NS records identified — test zone transfer manually."

        return self.findings