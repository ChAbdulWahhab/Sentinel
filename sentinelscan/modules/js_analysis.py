"""JS files analysis — secrets, endpoints, source maps."""
from __future__ import annotations

import asyncio
import re

from sentinelscan.core.findings import Severity
from sentinelscan.modules.base import BaseModule

SECRET_PATTERNS = [
    (r"(?:api[_-]?key|apikey)\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]", "API key"),
    (r"(?:secret|client_secret)\s*[:=]\s*['\"][A-Za-z0-9_\-]{12,}['\"]", "Secret"),
    (r"(?:access[_-]?token|auth[_-]?token)\s*[:=]\s*['\"][A-Za-z0-9_\-\.]{20,}['\"]", "Token"),
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key"),
    (r"AIza[0-9A-Za-z_\-]{35}", "Google API Key"),
    (r"sk_live_[0-9a-zA-Z]{24,}", "Stripe Live Key"),
    (r"ghp_[A-Za-z0-9]{36}", "GitHub PAT"),
    (r"xox[baprs]-[A-Za-z0-9\-]{10,}", "Slack Token"),
    (r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----", "Private Key"),
    (r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}", "JWT"),
    (r"(?:firebase|firebaseio)\.com", "Firebase URL"),
    (r"mongodb(?:\+srv)?://[^\s'\"<>]+", "MongoDB URI"),
    (r"postgres://[^\s'\"<>]+", "Postgres URI"),
    (r"mysql://[^\s'\"<>]+", "MySQL URI"),
]

ENDPOINT_RX = re.compile(
    r"""["'`]((?:/|https?://[^"'`\s]+/)(?:api|v\d|graphql|rest|auth|oauth|admin|user|users|login|logout|register|upload|webhook|payment|order)[A-Za-z0-9_\-/{}.:?=&]*)["'`]"""
)


class JsAnalysisModule(BaseModule):
    name = "js_analysis"
    description = "JS secrets, endpoints, source maps"
    requires_crawl = True

    async def run(self):
        scripts = list(self.ctx.get("scripts", []))[:30]
        sem = asyncio.Semaphore(8)

        async def analyze(js: str):
            async with sem:
                r = await self.session.get(js)
                if r is None or r.status_code != 200:
                    return
                text = r.text

                for pat, kind in SECRET_PATTERNS:
                    for m in re.finditer(pat, text):
                        val = m.group(0)
                        # false positive filter: placeholder
                        if any(x in val.lower() for x in ("xxxx", "your_", "example", "placeholder", "redacted")):
                            continue
                        self.add(
                            severity=Severity.HIGH if kind in ("AWS Access Key", "Private Key", "Stripe Live Key", "GitHub PAT") else Severity.MEDIUM,
                            title=f"Possible hardcoded {kind} in JS",
                            detail=f"File: {js}\nMatch: {val[:80]}...",
                            fix="Secrets frontend me na rakhein; server-side env use karein.",
                            url=js, cwe="CWE-798", owasp="A05:2021",
                            evidence=val[:200],
                        )

                for m in ENDPOINT_RX.findall(text):
                    self.ctx.setdefault("js_endpoints", set()).add(m)

                if "//# sourceMappingURL=" in text:
                    self.ctx.setdefault("info", {}).setdefault("Source maps", []).append(js)

        await asyncio.gather(*(analyze(s) for s in scripts))
        return self.findings