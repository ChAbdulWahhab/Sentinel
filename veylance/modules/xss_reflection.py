"""XSS reflection probe (non-exploit, safe)."""
from __future__ import annotations

import uuid
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from veylance.core.findings import Severity
from veylance.modules.base import BaseModule

PAYLOAD = "ssp" + uuid.uuid4().hex[:8] + "<svg/onload=alert(1)>"


class XssReflectionModule(BaseModule):
    name = "xss_reflection"
    description = "XSS reflection probe (harmless unique marker)"
    requires_crawl = True

    async def run(self):
        pages = [self.target.root] + list(self.ctx.get("pages", {}).keys())[:10]
        for page in pages:
            u = urlparse(page)
            q = parse_qs(u.query) or {}
            if not q:
                q = {"q": [""], "search": [""], "s": [""], "id": [""]}
            for param in list(q.keys())[:5]:
                test = dict(q)
                test[param] = [PAYLOAD]
                new_url = urlunparse(u._replace(query=urlencode(test, doseq=True)))
                r = await self.session.get(new_url)
                if r is None:
                    continue
                body = r.text
                if PAYLOAD in body:
                    # check unescaped
                    idx = body.find(PAYLOAD)
                    ctx = body[max(0, idx-30):idx+len(PAYLOAD)+30]
                    unescaped = "<svg/onload=alert(1)>" in ctx
                    self.add(
                        code="XSS_REFLECTION",
                        severity=Severity.HIGH if unescaped else Severity.LOW,
                        title=f"XSS reflection in `{param}` param",
                        detail=f"URL: {new_url}\nContext: {ctx[:120]}",
                        fix="Output encoding (context-aware), CSP, input validation.",
                        url=page, cwe="CWE-79", owasp="A03:2021",
                        evidence=ctx[:300],
                    )
        return self.findings