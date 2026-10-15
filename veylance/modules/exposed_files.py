"""Extra backup/config file probing with SPA baseline diffing."""
from __future__ import annotations

import asyncio
import hashlib
import json
import re

from veylance.core.findings import Severity
from veylance.modules.base import BaseModule
from veylance.utils.baseline import (
    get_or_create_baseline,
    has_content_signature,
    is_valid_archive,
)

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

CRITICAL = (
    "/.env.bak", "/id_rsa", "/id_dsa", "/.ssh/id_rsa",
    "/credentials.json", "/secrets.json", "/.aws/credentials",
    "/db_backup.sql", "/prod.sql", "/dump.sql.gz",
    "/backup.tar.gz", "/backup.rar", "/www.zip", "/wp-config.php.bak",
)

SIG_MAP = {
    "/id_rsa": "pem_key",
    "/id_dsa": "pem_key",
    "/.ssh/id_rsa": "pem_key",
    "/db_backup.sql": "sql_dump",
    "/data.sql": "sql_dump",
    "/prod.sql": "sql_dump",
    "/.env.bak": "env_file",
    "/credentials.json": "json_creds",
    "/secrets.json": "json_creds",
    "/.aws/credentials": "json_creds",
    "/.docker/config.json": "json_creds",
}


def _verify_authentic_content(path: str, content: bytes, text: str, ctype: str) -> bool:
    """Return True if content matches expected signatures for sensitive files."""
    if path.endswith((".zip", ".tar.gz", ".rar", ".7z", ".sql.gz")):
        return is_valid_archive(content) or ("octet-stream" in ctype or "zip" in ctype or "compressed" in ctype)

    if path in SIG_MAP:
        sig_name = SIG_MAP[path]
        if has_content_signature(text, sig_name):
            return True
        if sig_name == "json_creds":
            try:
                data = json.loads(text)
                if isinstance(data, dict) and any("key" in k.lower() or "secret" in k.lower() or "token" in k.lower() for k in data.keys()):
                    return True
            except Exception:
                pass
        return False

    # Dockerfile / docker-compose
    if path in ("/Dockerfile", "/docker-compose.yml"):
        if re.search(r"^(?:FROM\s+\w+|version:\s*['\"]?\d|services:)", text, re.I | re.M):
            return True
        return False

    # Config / settings / npmrc
    if path in ("/.npmrc", "/config.php.bak", "/wp-config.php.bak", "/settings.py", "/local_settings.py", "/config.yaml", "/config.yml.bak"):
        if "html" not in ctype and re.search(r"(?:_auth|_authToken|define\s*\(\s*['\"]DB_|SECRET_KEY|DATABASE_URL)", text, re.I):
            return True
        return False

    # General fallback: if not HTML and has sensible length
    is_html = "html" in ctype or bool(re.search(r"<!doctype\s+html|<html|<body", text[:500], re.I))
    return not is_html and len(content) > 10


class ExposedFilesModule(BaseModule):
    name = "exposed_files"
    description = "Backup / config / credential files with baseline verification"

    async def run(self):
        baseline = await get_or_create_baseline(self.session, self.target.base, self.ctx)
        sem = asyncio.Semaphore(10)

        suppressed_files: list[str] = []

        async def probe(p: str):
            async with sem:
                url = self.target.base + p
                r = await self.session.get(url, follow_redirects=False)
                if r is None or r.status_code != 200:
                    return

                content = getattr(r, "content", None)
                if content is None:
                    content = r.text.encode("utf-8") if getattr(r, "text", None) else b""
                text = r.text or ""
                ctype = r.headers.get("content-type", "").lower()
                body_hash = hashlib.sha256(content).hexdigest()

                matches_baseline = baseline.matches(r.status_code, len(content), body_hash)
                has_signature = _verify_authentic_content(p, content, text, ctype)

                if matches_baseline:
                    if has_signature:
                        # Genuine exposure despite baseline match
                        sev = Severity.CRITICAL if p in CRITICAL else Severity.HIGH
                        self.add(
                            severity=sev,
                            title=f"Exposed file: {p}",
                            detail=f"Verified exposure with authentic signature. HTTP 200 — {len(content)} bytes",
                            fix="Remove the file from the web root or deny access to it in the server configuration.",
                            url=url,
                            evidence=text[:200] if text else f"{len(content)} binary bytes",
                            owasp="A05:2021",
                        )
                    else:
                        suppressed_files.append(p)
                    return

                # Differs from baseline:
                # If server returns HTML for non-HTML files without signatures, ignore or downgrade
                is_html = "html" in ctype or bool(re.search(r"<!doctype\s+html|<html|<body", text[:500], re.I))
                if is_html and not has_signature:
                    return

                sev = Severity.CRITICAL if p in CRITICAL else Severity.HIGH
                self.add(
                    severity=sev,
                    title=f"Exposed file: {p}",
                    detail=f"HTTP 200 — {len(content)} bytes (verified difference from baseline)",
                    fix="Remove the file from the web root or deny access to it in the server configuration.",
                    url=url,
                    evidence=text[:200] if text else f"{len(content)} binary bytes",
                    owasp="A05:2021",
                )

        await asyncio.gather(*(probe(p) for p in FILES))

        if suppressed_files:
            self.ctx.setdefault("info", {}).setdefault("spa_catchall_suppressed", []).extend(suppressed_files)
            sample_preview = ", ".join(suppressed_files[:8]) + ("..." if len(suppressed_files) > 8 else "")
            self.add(
                severity=Severity.INFO,
                title=f"SPA catch-all suppressed: {len(suppressed_files)} exposed-file paths matched baseline",
                detail=(
                    f"{len(suppressed_files)} exposed-file paths returned the SPA catch-all response — "
                    "not flagged as real exposures. Full list available with --verbose or in JSON report (spa_catchall_suppressed)."
                ),
                fix="Ensure web server returns HTTP 404 for nonexistent backup and configuration files.",
                url=self.target.base,
                evidence=f"Suppressed {len(suppressed_files)} paths: {sample_preview}",
            )

        return self.findings