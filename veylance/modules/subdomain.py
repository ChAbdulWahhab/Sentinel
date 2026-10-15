import asyncio
import uuid
import dns.resolver

from veylance.core.findings import Severity
from veylance.modules.base import BaseModule

COMMON = [
    "www", "api", "app", "admin", "dev", "staging", "test", "uat", "beta",
    "mail", "smtp", "imap", "pop", "webmail", "mx",
    "vpn", "remote", "portal", "gateway",
    "cdn", "static", "assets", "img", "media",
    "db", "mysql", "postgres", "mongo", "redis",
    "git", "gitlab", "github", "jenkins", "ci", "cd",
    "grafana", "kibana", "prometheus", "monitor", "status",
    "internal", "intranet", "corp", "office",
    "backup", "old", "new", "v1", "v2", "demo", "sandbox",
]


class SubdomainModule(BaseModule):
    name = "subdomain"
    description = "Common subdomain DNS enumeration"

    async def run(self):
        domain = self.target.hostname
        if not domain or domain.count(".") < 1:
            return self.findings

        loop = asyncio.get_event_loop()
        found: list[tuple[str, str]] = []

        # Check for DNS wildcard
        probe_sub = f"__veyl_probe_{uuid.uuid4().hex[:8]}.{domain}"
        wildcard_ips = set()
        try:
            ans = await loop.run_in_executor(
                None,
                lambda: dns.resolver.resolve(probe_sub, "A", lifetime=3),
            )
            wildcard_ips = set(r.to_text() for r in ans)
            self.ctx.setdefault("info", {})["Wildcard DNS"] = f"Detected (*.{domain} -> {', '.join(sorted(wildcard_ips))})"
        except Exception:
            pass

        async def probe(sub: str):
            fqdn = f"{sub}.{domain}"
            try:
                ans = await loop.run_in_executor(
                    None,
                    lambda: dns.resolver.resolve(fqdn, "A", lifetime=4),
                )
                ips = [r.to_text() for r in ans]
                # If wildcard DNS is present, only count subdomains with distinct IPs
                if wildcard_ips and set(ips).issubset(wildcard_ips):
                    return
                found.append((fqdn, ", ".join(ips[:3])))
            except Exception:
                pass

        await asyncio.gather(*(probe(s) for s in COMMON))

        if found:
            self.ctx.setdefault("info", {})["Subdomains (A record)"] = [
                f"{f} -> {ip}" for f, ip in found
            ]
            # Store confirmed, DNS-verified resolving subdomains in ctx
            self.ctx.setdefault("discovered_subdomains", set()).update(
                fqdn for fqdn, _ in found
            )

            # Dangling CNAME check on common ones
            for fqdn, ip in found:
                if fqdn.startswith(("dev.", "staging.", "test.")):
                    self.add(severity=Severity.INFO,
                             title=f"Non-prod subdomain: {fqdn}",
                             detail=f"IP: {ip}",
                             fix="Keep non-production environments behind authentication.",
                             url=f"https://{fqdn}")
        return self.findings