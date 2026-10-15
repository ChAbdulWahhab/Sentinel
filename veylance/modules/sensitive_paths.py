"""Sensitive path exposure check with SPA catch-all baseline filtering."""
from __future__ import annotations

import asyncio
import hashlib

from veylance.core.findings import Severity
from veylance.modules.base import BaseModule
from veylance.utils.baseline import get_or_create_baseline, has_content_signature

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

CRITICAL_PATHS = {
    "/.env": "env_file",
    "/.env.local": "env_file",
    "/.env.production": "env_file",
    "/.git/HEAD": "git_head",
    "/.git/config": "git_head",
    "/phpinfo.php": "phpinfo",
    "/info.php": "phpinfo",
    "/server-status": "mod_status",
    "/backup.sql": "sql_dump",
    "/db.sql": "sql_dump",
    "/dump.sql": "sql_dump",
    "/database.sql": "sql_dump",
}


class SensitivePathsModule(BaseModule):
    name = "sensitive_paths"
    description = "Sensitive paths (.env, .git, swagger, actuator, backups) with baseline verification"

    async def run(self):
        # 1. Establish baseline response for random nonexistent route
        baseline = await get_or_create_baseline(self.session, self.target.base, self.ctx)

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
        suppressed_paths: list[str] = []

        for path, url, r in results:
            if r is None:
                continue

            code = r.status_code
            content = getattr(r, "content", None)
            if content is None:
                content = r.text.encode("utf-8") if getattr(r, "text", None) else b""
            body_text = r.text or ""
            body_hash = hashlib.sha256(content).hexdigest()
            ctype = r.headers.get("content-type", "").lower()

            # Baseline Diff Check
            matches_baseline = baseline.matches(code, len(content), body_hash)

            if code == 200:
                if matches_baseline:
                    # Catch-all SPA route returned index.html for unmatched path
                    # Only escalate if genuine content-specific signature is present
                    sig_type = CRITICAL_PATHS.get(path)
                    if sig_type and has_content_signature(body_text, sig_type):
                        self.add(
                            severity=Severity.CRITICAL,
                            title=f"Sensitive path accessible: {path}",
                            detail=f"Verified exposure with authentic signature. HTTP 200 — {len(content)} bytes",
                            fix="Remove the file from the web root or deny access in server configuration.",
                            url=url,
                            evidence=body_text[:200],
                            owasp="A05:2021",
                        )
                    else:
                        suppressed_paths.append(path)
                    continue

                # Differs from baseline:
                sig_type = CRITICAL_PATHS.get(path)
                if path in CRITICAL_PATHS:
                    # Require signature verification or binary/text confirmation
                    if has_content_signature(body_text, sig_type) or ("html" not in ctype and len(content) > 10):
                        self.add(
                            severity=Severity.CRITICAL,
                            title=f"Sensitive path accessible: {path}",
                            detail=f"HTTP 200 — {len(content)} bytes (verified difference from baseline).",
                            fix="Remove from web root or block access in web server configuration.",
                            url=url,
                            evidence=body_text[:250] if body_text else f"{len(content)} binary bytes",
                            owasp="A05:2021",
                        )
                        continue

                interesting_200.append((path, url, body_text))

            elif code in (401, 403):
                protected.append(f"{path} [{code}]")
            elif code in (301, 302) and path in ("/admin", "/login", "/wp-login.php"):
                redirects.append(f"{path} -> {r.headers.get('location', '')}")

        if suppressed_paths:
            self.ctx.setdefault("info", {}).setdefault("spa_catchall_suppressed", []).extend(suppressed_paths)
            sample_preview = ", ".join(suppressed_paths[:8]) + ("..." if len(suppressed_paths) > 8 else "")
            self.add(
                severity=Severity.INFO,
                title=f"SPA catch-all suppressed: {len(suppressed_paths)} sensitive paths matched baseline",
                detail=(
                    f"{len(suppressed_paths)} sensitive paths returned the SPA catch-all response — "
                    "not flagged as real exposures. Full list available with --verbose or in JSON report (spa_catchall_suppressed)."
                ),
                fix="Configure your server (Vercel/Netlify/Cloudflare Pages) to return 404 for missing static and administrative paths.",
                url=self.target.base,
                evidence=f"Suppressed {len(suppressed_paths)} paths: {sample_preview}",
            )

        if interesting_200:
            self.ctx.setdefault("info", {})["Interesting paths (200)"] = [p for p, _, _ in interesting_200]
        if protected:
            self.ctx.setdefault("info", {})["Protected paths (401/403)"] = protected
        if redirects:
            self.ctx.setdefault("info", {})["Interesting redirects"] = redirects

        # API docs check: verify response contains actual Swagger / OpenAPI structure
        for path, url, body in interesting_200:
            if any(path.startswith(x) for x in ("/swagger", "/openapi", "/api-docs", "/v2/api-docs", "/v3/api-docs", "/graphiql", "/redoc")):
                if has_content_signature(body, "swagger_doc") or "swagger" in body.lower() or "openapi" in body.lower():
                    self.add(
                        severity=Severity.MEDIUM,
                        title=f"API documentation publicly exposed: {path}",
                        detail=f"Interactive API documentation accessible at {url}.",
                        fix="Require authentication or restrict IP access for API documentation in production.",
                        url=url,
                        evidence=f"API Documentation endpoint: {path}",
                    )
                    break

        # Admin panel check: must have differed from baseline
        for path, url, body in interesting_200:
            if path in ("/admin", "/admin/", "/phpmyadmin/", "/administrator"):
                self.add(
                    severity=Severity.MEDIUM,
                    title=f"Admin panel publicly reachable: {path}",
                    detail=f"Administrative interface accessible at {url} (HTTP 200).",
                    fix="Enforce IP allowlisting, VPN access, or multi-factor authentication (2FA).",
                    url=url,
                    evidence=f"Admin route returned HTTP 200 differing from baseline",
                )
                break

        return self.findings