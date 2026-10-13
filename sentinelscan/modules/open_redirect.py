"""Open redirect probe (safe)."""
from __future__ import annotations

from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from sentinelscan.core.findings import Severity
from sentinelscan.modules.base import BaseModule

COMMON_PARAMS = ["next", "url", "redirect", "return", "returnUrl", "return_url",
                 "continue", "dest", "destination", "redir", "redirect_uri", "callback"]

EVIL = "https://evil.example"


class OpenRedirectModule(BaseModule):
    name = "open_redirect"
    description = "Open redirect parameter probe"
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
                if r.status_code in (301, 302, 303, 307, 308):
                    loc = r.headers.get("location", "")
                    if EVIL in loc:
                        self.add(severity=Severity.MEDIUM,
                                 title=f"Open redirect: `{param}` param",
                                 detail=f"{new_url}\n-> {loc}",
                                 fix="Redirect target ko allowlist karein.",
                                 url=page, cwe="CWE-601", owasp="A01:2021")
                        return self.findings
        return self.findings