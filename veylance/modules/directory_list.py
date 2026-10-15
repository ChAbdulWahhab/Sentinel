"""Directory listing detection with baseline diffing."""
from __future__ import annotations

import asyncio
import hashlib
import re

from veylance.core.findings import Severity
from veylance.modules.base import BaseModule
from veylance.utils.baseline import get_or_create_baseline

DIRS = ["/uploads/", "/images/", "/files/", "/static/", "/assets/", "/backup/",
        "/logs/", "/tmp/", "/data/", "/private/", "/media/", "/download/"]

LISTING_RX = re.compile(r"<title>Index of /|<h1>Index of /|\[To Parent Directory\]|Directory listing for", re.I)


class DirectoryListModule(BaseModule):
    name = "directory_list"
    description = "Directory listing exposure"

    async def run(self):
        baseline = await get_or_create_baseline(self.session, self.target.base, self.ctx)
        sem = asyncio.Semaphore(8)

        async def probe(d):
            async with sem:
                url = self.target.base + d
                r = await self.session.get(url)
                if r is None or r.status_code != 200:
                    return

                content = getattr(r, "content", None)
                if content is None:
                    content = r.text.encode("utf-8") if getattr(r, "text", None) else b""
                b_hash = hashlib.sha256(content).hexdigest()
                if baseline.matches(r.status_code, len(content), b_hash):
                    return

                if LISTING_RX.search(r.text):
                    self.add(
                        severity=Severity.MEDIUM,
                        title=f"Directory listing enabled: {d}",
                        detail=f"Directory listing is enabled at {url}.",
                        fix="Disable directory listing (Nginx: 'autoindex off;', Apache: 'Options -Indexes').",
                        url=url,
                        cwe="CWE-548",
                        owasp="A05:2021",
                    )

        await asyncio.gather(*(probe(d) for d in DIRS))
        return self.findings