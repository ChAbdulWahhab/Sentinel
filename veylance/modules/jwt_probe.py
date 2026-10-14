"""JWT token detection and 'none' algorithm test."""
from __future__ import annotations

import base64
import json
import re

from veylance.core.findings import Severity
from veylance.modules.base import BaseModule


JWT_RX = re.compile(r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*")


class JwtProbeModule(BaseModule):
    name = "jwt_probe"
    description = "JWT token detection and 'none' algorithm test"
    requires_crawl = True

    async def run(self):
        # --- Guard: scripts in ctx should be a set ---
        scripts = self.ctx.get("scripts") or set()
        if not isinstance(scripts, (set, list, tuple)):
            scripts = set()
        scripts = list(scripts)[:20]

        # --- Guard: pages should be a dict ---
        pages = self.ctx.get("pages") or {}
        if not isinstance(pages, dict):
            pages = {}

        # --- Find tokens in JS files ---
        for js in scripts:
            if not isinstance(js, str) or not js:
                continue
            try:
                r = await self.session.get(js)
            except Exception:
                continue
            if r is None or r.status_code != 200:
                continue
            try:
                body = r.text or ""
            except Exception:
                continue
            for tok in set(JWT_RX.findall(body)):
                self._analyze(tok, js)

        # --- Check response bodies as well ---
        for url in list(pages.keys())[:20]:
            if not isinstance(url, str) or not url:
                continue
            try:
                r = await self.session.get(url)
            except Exception:
                continue
            if r is None:
                continue
            try:
                body = r.text or ""
            except Exception:
                continue
            for tok in list(set(JWT_RX.findall(body)))[:3]:
                self._analyze(tok, url)

        return self.findings

    def _analyze(self, tok: str, source: str):
        try:
            parts = tok.split(".")
            if len(parts) < 2:
                return
            header_b64 = parts[0]
            header_b64 += "=" * (-len(header_b64) % 4)
            header = json.loads(base64.urlsafe_b64decode(header_b64))
        except Exception:
            return

        if not isinstance(header, dict):
            return

        alg = str(header.get("alg", "")).lower()

        if alg == "none":
            self.add(
                severity=Severity.HIGH,
                title="JWT 'alg: none' found",
                detail=f"Source: {source}\nHeader: {header}",
                fix="Verify JWTs on the server and keep an algorithm allowlist (RS256/HS256).",
                url=source, cwe="CWE-347", owasp="A02:2021",
            )
        elif alg == "hs256":
            self.add(
                severity=Severity.INFO,
                title="HS256 JWT detected",
                detail=f"Source: {source}",
                fix="Do not use weak secrets; run brute-force tests in staging.",
                url=source,
            )