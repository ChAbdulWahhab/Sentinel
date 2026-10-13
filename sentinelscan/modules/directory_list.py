"""Directory listing detection."""
from __future__ import annotations

import asyncio
import re

from sentinelscan.core.findings import Severity
from sentinelscan.modules.base import BaseModule

DIRS = ["/uploads/", "/images/", "/files/", "/static/", "/assets/", "/backup/",
        "/logs/", "/tmp/", "/data/", "/private/", "/media/", "/download/"]

LISTING_RX = re.compile(r"<title>Index of /|<h1>Index of /|\[To Parent Directory\]|Directory listing for", re.I)


class DirectoryListModule(BaseModule):
    name = "directory_list"
    description = "Directory listing exposure"

    async def run(self):
        sem = asyncio.Semaphore(8)

        async def probe(d):
            async with sem:
                url = self.target.base + d
                r = await self.session.get(url)
                if r is not None and r.status_code == 200 and LISTING_RX.search(r.text):
                    self.add(severity=Severity.MEDIUM,
                             title=f"Directory listing enabled: {d}",
                             detail=f"{url} par autoindex ON hai.",
                             fix="Autoindex off karein (nginx: autoindex off; Apache: Options -Indexes).",
                             url=url, cwe="CWE-548", owasp="A05:2021")

        await asyncio.gather(*(probe(d) for d in DIRS))
        return self.findings