"""Passive reconnaissance using public Certificate Transparency (CT) logs."""
from __future__ import annotations

import asyncio
import json

from veylance.core.findings import Severity
from veylance.modules.base import BaseModule


MULTI_LEVEL_HOSTING_DOMAINS = (
    "pages.dev",
    "vercel.app",
    "github.io",
    "herokuapp.com",
    "netlify.app",
    "fly.dev",
    "firebaseapp.com",
    "web.app",
    "azurewebsites.net",
    "cloudfront.net",
    "amplifyapp.com",
    "gitlab.io",
)


def get_ct_query_target(hostname: str) -> str:
    """Build the scope for CT log queries without truncating multi-level hosting domains.

    For multi-level hosting platforms (e.g. dealsafe.pages.dev, app.vercel.app),
    the query must use the full tenant domain rather than a truncated platform apex.
    """
    clean_host = hostname.strip().lower().rstrip(".")
    if not clean_host:
        return ""

    parts = clean_host.split(".")

    # Check multi-level hosting platforms
    for mld in MULTI_LEVEL_HOSTING_DOMAINS:
        if clean_host.endswith(f".{mld}"):
            mld_labels = len(mld.split("."))
            # Include tenant label (e.g. dealsafe + pages.dev)
            if len(parts) >= mld_labels + 1:
                return ".".join(parts[-(mld_labels + 1):])
            return clean_host
        elif clean_host == mld:
            return clean_host

    # Check for common two-part TLDs (e.g. co.uk, com.au)
    two_part_tlds = (".co.uk", ".com.au", ".org.uk", ".gov.uk", ".ac.uk", ".co.nz", ".co.jp")
    for tld in two_part_tlds:
        if clean_host.endswith(tld) and len(parts) >= 3:
            return ".".join(parts[-3:])

    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return clean_host


class CertTransparencyReconModule(BaseModule):
    name = "cert_transparency_recon"
    description = "Passive Certificate Transparency log reconnaissance via crt.sh"

    async def run(self):
        hostname = self.target.hostname
        if not hostname or hostname.count(".") < 1:
            return self.findings

        query_target = get_ct_query_target(hostname)
        if not query_target:
            return self.findings

        url = f"https://crt.sh/?q=%.{query_target}&output=json"
        discovered_subs: set[str] = set()

        try:
            # Short timeout to avoid blocking scan if crt.sh is slow
            r = await asyncio.wait_for(
                self.session.get(url, timeout=6.0),
                timeout=7.0,
            )
            if r is not None and r.status_code == 200 and r.text:
                entries = json.loads(r.text)
                if isinstance(entries, list):
                    for entry in entries:
                        if not isinstance(entry, dict):
                            continue
                        name_val = entry.get("name_value") or entry.get("common_name") or ""
                        for host in name_val.split("\n"):
                            h = host.strip().lower()
                            if h.startswith("*."):
                                h = h[2:]
                            if h.endswith(f".{query_target}") or h == query_target:
                                discovered_subs.add(h)
        except Exception:
            # CT log lookup is best-effort reconnaissance; ignore network timeouts gracefully
            return self.findings

        # Save to shared context for other modules (e.g. subdomain_takeover)
        self.ctx.setdefault("discovered_subdomains", set()).update(discovered_subs)

        if discovered_subs:
            self.ctx.setdefault("info", {})["Certificate Transparency Hostnames"] = sorted(discovered_subs)

            # Check if any staging, dev, admin, internal hostnames are surfaced
            sensitive_keywords = ("dev", "staging", "test", "internal", "vpn", "admin", "corp", "jenkins", "gitlab", "jira", "db")
            sensitive_hosts = [h for h in discovered_subs if any(kw in h for kw in sensitive_keywords)]

            sev = Severity.LOW if sensitive_hosts else Severity.INFO
            sample_list = sorted(sensitive_hosts if sensitive_hosts else discovered_subs)[:10]

            self.add(
                severity=sev,
                title=f"Certificate Transparency discovered {len(discovered_subs)} hostnames",
                detail=(
                    f"Queried public Certificate Transparency logs for '{query_target}'.\n"
                    f"CT logs record all TLS certificates publicly issued by Certificate Authorities. "
                    f"Found {len(discovered_subs)} hostnames ({len(sensitive_hosts)} potentially non-production or internal)."
                ),
                fix="Review active DNS records for historical certificates. Ensure decommissioned hostnames are pruned from DNS and internal environments are protected with Zero-Trust / VPN controls.",
                url=f"https://crt.sh/?q=%.{query_target}",
                evidence="Discovered Hostnames: " + ", ".join(sample_list),
                cwe="CWE-200",
                owasp="A01:2021",
            )

        return self.findings
