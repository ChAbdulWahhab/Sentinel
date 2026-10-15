"""Open redirect probe (safe) with WAF awareness."""
from __future__ import annotations

from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from veylance.core.findings import Severity
from veylance.modules.base import BaseModule

COMMON_PARAMS = ["next", "url", "redirect", "return", "returnUrl", "return_url",
                 "continue", "dest", "destination", "redir", "redirect_uri", "callback"]

EVIL = "https://evil.example.com"


class OpenRedirectModule(BaseModule):
    name = "open_redirect"
    description = "Open redirect parameter probe with WAF/CDN interception filtering"
    requires_crawl = True

    async def run(self):
        pages = [self.target.root] + list(self.ctx.get("pages", {}).keys())[:15]
        for page in pages:
            for param in COMMON_PARAMS:
                u = urlparse(page)
                q = parse_qs(u.query)
                q[param] = [EVIL]
                new_url = urlunparse(u._replace(query=urlencode(q, doseq=True)))

                r = await self.session.get(new_url, follow_redirects=False)
                if r is None:
                    continue

                # Ignore WAF blocks (403, 406, 429)
                if r.status_code in (403, 406, 429):
                    continue

                if r.status_code in (301, 302, 303, 307, 308):
                    loc = r.headers.get("location", "")
                    # WAF filter: If Cloudflare or a CDN blocked/challenged with an internal redirect
                    if "cf-browser-verification" in loc or "challenge" in loc.lower():
                        continue

                    if loc.startswith(EVIL) or loc.startswith("//evil.example.com"):
                        self.add(
                            severity=Severity.HIGH,
                            title=f"Open redirect via parameter: '{param}'",
                            detail=f"The server redirected directly to an untrusted external origin without validation: {loc}",
                            fix="Validate redirect parameters against a strict internal route allowlist or relative path regex (e.g. ^/[^/\\\\]).",
                            url=page,
                            evidence=f"Request URL: {new_url} -> Status: {r.status_code}, Location: {loc}",
                            cwe="CWE-601",
                            owasp="A01:2021",
                        )
                        return self.findings
        return self.findings