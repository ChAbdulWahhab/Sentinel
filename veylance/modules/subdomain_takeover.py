"""Subdomain takeover detection for dangling CNAME DNS pointers."""
from __future__ import annotations

import asyncio
from typing import Any
import dns.resolver

from veylance.core.findings import Severity
from veylance.modules.base import BaseModule

TAKEOVER_FINGERPRINTS = [
    {
        "service": "GitHub Pages",
        "cname": ["github.io"],
        "patterns": ["There isn't a GitHub Pages site here", "For root URLs (like http://example.com/)"],
    },
    {
        "service": "Heroku",
        "cname": ["herokuapp.com", "herokudns.com"],
        "patterns": ["No such app", "herokucdn.com/error-pages/no-such-app.html"],
    },
    {
        "service": "AWS S3",
        "cname": ["s3.amazonaws.com", "s3-website"],
        "patterns": ["<Code>NoSuchBucket</Code>", "The specified bucket does not exist"],
    },
    {
        "service": "Azure App Service",
        "cname": ["azurewebsites.net", "cloudapp.net", "trafficmanager.net"],
        "patterns": ["404 Web Site not found", "The specified account does not exist"],
    },
    {
        "service": "Vercel",
        "cname": ["vercel.app", "now.sh", "cname.vercel-dns.com"],
        "patterns": ["The deployment could not be found on Vercel", "DEPLOYMENT_NOT_FOUND"],
    },
    {
        "service": "Netlify",
        "cname": ["netlify.app", "netlify.com"],
        "patterns": ["Not Found - Request ID", "page-not-found"],
    },
    {
        "service": "Shopify",
        "cname": ["myshopify.com"],
        "patterns": ["Sorry, this shop is currently unavailable"],
    },
    {
        "service": "Readme.io",
        "cname": ["readme.io"],
        "patterns": ["Project doesnt exist... yet!"],
    },
    {
        "service": "Fastly",
        "cname": ["fastly.net"],
        "patterns": ["Fastly error: unknown domain"],
    },
    {
        "service": "Surge.sh",
        "cname": ["surge.sh"],
        "patterns": ["project not found"],
    },
]

TARGET_SUBS = [
    "blog", "help", "docs", "status", "app", "dev", "staging", "shop", "store",
    "portal", "support", "community", "careers", "cdn", "demo", "api"
]


class SubdomainTakeoverModule(BaseModule):
    name = "subdomain_takeover"
    description = "Detect dangling CNAME records pointing to unclaimed third-party services"

    async def run(self):
        domain = self.target.hostname
        if not domain or domain.count(".") < 1:
            return self.findings

        # Gather subdomains from context or seed list
        subs: set[str] = set()
        subs.add(domain)

        # Pull any subdomains discovered in previous modules
        for sub_str in self.ctx.get("discovered_subdomains", set()):
            subs.add(sub_str)

        # Extract from info['Subdomains (A record)'] if present
        for entry in self.ctx.get("info", {}).get("Subdomains (A record)", []):
            host = entry.split(" -> ")[0].strip()
            if host:
                subs.add(host)

        # Add common candidates
        for prefix in TARGET_SUBS:
            subs.add(f"{prefix}.{domain}")

        loop = asyncio.get_event_loop()
        sem = asyncio.Semaphore(6)

        async def check_subdomain(sub: str):
            async with sem:
                cname = await self._resolve_cname(sub, loop)
                if not cname:
                    return

                matched_fp = None
                for fp in TAKEOVER_FINGERPRINTS:
                    if any(c.lower() in cname.lower() for c in fp["cname"]):
                        matched_fp = fp
                        break

                if not matched_fp:
                    return

                # Probe HTTP/HTTPS to check if the target responds with the unclaimed error string
                is_vulnerable, matched_sig = await self._verify_dangling_http(sub, matched_fp["patterns"])
                if is_vulnerable:
                    self.add(
                        severity=Severity.CRITICAL,
                        title=f"Subdomain takeover risk: {sub} -> {matched_fp['service']}",
                        detail=(
                            f"The DNS CNAME for '{sub}' points to an unclaimed {matched_fp['service']} instance ({cname}).\n"
                            f"An external adversary can register the missing application/bucket and take over this subdomain completely."
                        ),
                        fix=(
                            f"Immediately remove the dangling CNAME record '{sub} -> {cname}' in your DNS provider, "
                            f"or claim the corresponding resource in {matched_fp['service']}."
                        ),
                        url=f"http://{sub}",
                        evidence=f"CNAME: {cname} | Provider Signature: '{matched_sig}'",
                        cwe="CWE-284",
                        owasp="A01:2021",
                    )

        await asyncio.gather(*(check_subdomain(s) for s in list(subs)[:35]))
        return self.findings

    async def _resolve_cname(self, host: str, loop: Any) -> str | None:
        try:
            ans = await loop.run_in_executor(
                None,
                lambda: dns.resolver.resolve(host, "CNAME", lifetime=3),
            )
            for r in ans:
                return r.target.to_text().rstrip(".")
        except Exception:
            pass
        return None

    async def _verify_dangling_http(self, host: str, patterns: list[str]) -> tuple[bool, str]:
        for scheme in ("https", "http"):
            url = f"{scheme}://{host}"
            try:
                r = await self.session.get(url, follow_redirects=True)
                if r is not None and r.text:
                    body = r.text
                    for pat in patterns:
                        if pat.lower() in body.lower():
                            return True, pat
            except Exception:
                continue
        return False, ""
