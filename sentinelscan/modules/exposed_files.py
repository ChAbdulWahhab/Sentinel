"""Extra backup/config file probing."""
from __future__ import annotations

import asyncio

from sentinelscan.core.findings import Severity
from sentinelscan.modules.base import BaseModule

FILES = [
    "/backup.tar.gz", "/backup.rar", "/www.zip", "/site.zip", "/web.zip",
    "/db_backup.sql", "/data.sql", "/prod.sql", "/dump.sql.gz",
    "/.env.bak", "/config.php.bak", "/config.yml.bak", "/config.yaml",
    "/settings.py", "/local_settings.py", "/wp-config.php.bak",
    "/id_rsa", "/id_dsa", "/.ssh/id_rsa",
    "/credentials.json", "/secrets.json", "/.aws/credentials",
    "/.npmrc", "/.docker/config.json",
    "/Dockerfile", "/docker-compose.yml", "/.dockerenv",
    "/.travis.yml", "/.github/workflows/main.yml",
    "/phpunit.xml", "/.php_cs", "/.eslintrc",
]

CRITICAL = ("/.env.bak", "/id_rsa", "/credentials.json", "/secrets.json",
            "/.aws/credentials", "/.ssh/id_rsa", "/db_backup.sql",
            "/backup.tar.gz", "/backup.rar", "/www.zip", "/wp-config.php.bak")


class ExposedFilesModule(BaseModule):
    name = "exposed_files"
    description = "Backup / config / credential files"

    async def run(self):
        sem = asyncio.Semaphore(10)

        async def probe(p):
            async with sem:
                url = self.target.base + p
                r = await self.session.get(url, follow_redirects=False)
                if r is not None and r.status_code == 200:
                    ctype = r.headers.get("content-type", "")
                    if "html" in ctype and p not in CRITICAL:
                        return
                    sev = Severity.CRITICAL if p in CRITICAL else Severity.HIGH
                    self.add(severity=sev,
                             title=f"Exposed file: {p}",
                             detail=f"HTTP 200 — {len(r.content)} bytes",
                             fix="File ko web root se hatao / server config me deny karo.",
                             url=url, owasp="A05:2021")

        await asyncio.gather(*(probe(p) for p in FILES))
        return self.findings