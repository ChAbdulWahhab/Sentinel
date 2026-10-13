"""robots.txt + sitemap.xml."""
from __future__ import annotations

import re

from sentinelscan.core.findings import Severity
from sentinelscan.modules.base import BaseModule


class RobotsSitemapModule(BaseModule):
    name = "robots_sitemap"
    description = "robots.txt / sitemap.xml analysis"

    async def run(self):
        info = self.ctx.setdefault("info", {})

        r = await self.session.get(self.target.base + "/robots.txt")
        if r is not None and r.status_code == 200 and "html" not in r.headers.get("content-type", ""):
            dis = []
            for line in r.text.splitlines():
                if line.lower().startswith("disallow:"):
                    val = line.split(":", 1)[1].strip()
                    if val:
                        dis.append(val)
            info["robots.txt Disallow"] = dis[:40]
            sensitive = [d for d in dis if re.search(r"admin|backup|private|internal|secret|config|\.env|\.git", d, re.I)]
            if sensitive:
                self.add(severity=Severity.LOW,
                         title="robots.txt sensitive paths reveal kar raha",
                         detail=", ".join(sensitive[:10]),
                         fix="Sensitive paths robots.txt me na likhein; access control se protect karein.",
                         url=self.target.base + "/robots.txt")

        r = await self.session.get(self.target.base + "/sitemap.xml")
        if r is not None and r.status_code == 200:
            urls = re.findall(r"<loc>(.*?)</loc>", r.text)
            info["sitemap.xml URLs"] = len(urls)
        return self.findings