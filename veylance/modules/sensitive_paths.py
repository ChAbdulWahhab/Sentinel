"""Sensitive path exposure check."""
from __future__ import annotations

import asyncio
import re

from veylance.core.findings import Severity
from veylance.modules.base import BaseModule

SENSITIVE_PATHS = [
    "/.env", "/.env.local", "/.env.production", "/.git/HEAD", "/.git/config",
    "/.svn/entries", "/.DS_Store", "/.htaccess", "/.htpasswd",
    "/phpinfo.php", "/info.php", "/server-status", "/server-info",
    "/admin", "/admin/", "/administrator", "/login", "/wp-login.php", "/wp-admin/",
    "/phpmyadmin/", "/adminer.php", "/pma/",
    "/swagger", "/swagger.json", "/swagger-ui/", "/openapi.json", "/api-docs", "/v2/api-docs", "/v3/api-docs",
    "/docs", "/redoc", "/graphql", "/graphiql",
    "/actuator", "/actuator/env", "/actuator/health", "/actuator/heapdump",
    "/metrics", "/debug", "/_debug", "/_profiler",
    "/telescope", "/horizon", "/storage/logs/laravel.log",
    "/composer.json", "/composer.lock", "/package.json", "/yarn.lock", "/Gemfile",
    "/config.json", "/config.php.bak", "/wp-config.php.bak",
    "/backup.zip", "/backup.sql", "/db.sql", "/dump.sql", "/database.sql",
    "/.well-known/security.txt", "/robots.txt", "/sitemap.xml",
    "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/elmah.axd", "/trace.axd",
]

CRITICAL_IF_200 = {
    "/.env", "/.env.local", "/.env.production",
    "/.git/HEAD", "/.git/config", "/phpinfo.php", "/info.php",
    "/storage/logs/laravel.log", "/backup.zip", "/backup.sql", "/db.sql",
    "/dump.sql", "/database.sql", "/actuator/env", "/actuator/heapdump",
    "/adminer.php", "/server-status", "/.htpasswd", "/wp-config.php.bak",
}

# Soft 404 detection keywords (must be present in response)
CRITICAL_KEYWORDS = (
    "db_password", "app_key", "db_host", "aws_secret", "secret_key",
    "[core]", "repositoryformatversion", "phpinfo()", "ref:", "refs/heads",
)


class SensitivePathsModule(BaseModule):
    name = "sensitive_paths"
    description = "Sensitive paths (.env, .git, swagger, actuator, backups)"

    async def run(self):
        sem = asyncio.Semaphore(15)

        async def probe(path: str):
            async with sem:
                url = self.target.base + path
                r = await self.session.get(url, follow_redirects=False)
                return path, url, r

        results = await asyncio.gather(*(probe(p) for p in SENSITIVE_PATHS))

        interesting_200 = []
        protected = []
        redirects = []

        for path, url, r in results:
            if r is None:
                continue
            code = r.status_code
            ctype = r.headers.get("content-type", "")
            body = r.text[:2000] if "text" in ctype or "json" in ctype or "html" in ctype else ""

            if code == 200:
                if path in CRITICAL_IF_200:
                    real = (
                        "html" not in ctype
                        or any(k.lower() in body.lower() for k in CRITICAL_KEYWORDS)
                        or path in ("/phpinfo.php", "/info.php", "/server-status", "/actuator/heapdump")
                    )
                    if real:
                        self.add(
                            severity=Severity.CRITICAL,
                            title=f"Sensitive path accessible: {path}",
                            detail=f"HTTP 200 — {len(r.content)} bytes",
                            fix="Remove from the web root or block access in the server configuration.",
                            url=url,
                            evidence=body[:300] if body else None,
                            owasp="A05:2021",
                        )
                        continue
                interesting_200.append(path)
            elif code in (401, 403):
                protected.append(f"{path} [{code}]")
            elif code in (301, 302) and path in ("/admin", "/login", "/wp-login.php"):
                redirects.append(f"{path} -> {r.headers.get('location','')}")

        if interesting_200:
            self.ctx.setdefault("info", {})["Interesting paths (200)"] = interesting_200
        if protected:
            self.ctx.setdefault("info", {})["Protected paths (401/403)"] = protected
        if redirects:
            self.ctx.setdefault("info", {})["Interesting redirects"] = redirects

        # API docs public
        docs = [p for p in interesting_200 if any(p.startswith(x) for x in
                ("/swagger", "/openapi", "/api-docs", "/v2/api-docs", "/v3/api-docs", "/graphiql", "/redoc"))]
        if docs:
            self.add(severity=Severity.MEDIUM,
                     title="API documentation public",
                     detail=", ".join(docs),
                     fix="Require authentication for documentation in production.",
                     url=self.target.base)

        if any(p in interesting_200 for p in ("/admin", "/admin/", "/phpmyadmin/", "/administrator")):
            self.add(severity=Severity.MEDIUM,
                     title="Admin panel publicly reachable",
                     detail="Admin/phpMyAdmin returns HTTP 200.",
                     fix="IP allowlist / VPN / 2FA.",
                     url=self.target.base)
        return self.findings