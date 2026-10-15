"""Passive static scanner for hardcoded secrets in JS bundles and source maps."""
from __future__ import annotations

import asyncio
import re
from urllib.parse import urljoin

from veylance.core.findings import Severity
from veylance.modules.base import BaseModule

SECRET_PATTERNS = [
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}"), Severity.CRITICAL),
    ("Stripe Live Key", re.compile(r"sk_live_[0-9a-zA-Z]{24,}"), Severity.CRITICAL),
    ("Private Key Header", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"), Severity.CRITICAL),
    ("Database URI", re.compile(r"(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql)://[^\s'\"<>]+", re.I), Severity.CRITICAL),
    ("Google API Key", re.compile(r"AIza[0-9A-Za-z_\-]{35}"), Severity.HIGH),
    ("Generic API Key", re.compile(r"""(?:api[_-]?key|apiKey)\s*[:=]\s*['"]([A-Za-z0-9_\-\.]{16,})['"]""", re.I), Severity.HIGH),
    ("Embedded JWT", re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"), Severity.HIGH),
]

IGNORE_SNIPPETS = (
    "example", "placeholder", "your_", "your-", "xxxx", "test_", "dummy",
    "replace_me", "fake", "00000000", "123456789"
)


def mask_secret(raw: str) -> str:
    """Mask secret retaining only the first and last 4 characters."""
    s = raw.strip("\"' \t\r\n")
    if s.startswith("-----BEGIN"):
        return "-----BEGIN [REDACTED PRIVATE KEY]-----"
    if "://" in s and "@" in s:
        # Mask password in connection URI: proto://user:pass@host
        prefix, rest = s.split("://", 1)
        if "@" in rest:
            creds, host = rest.split("@", 1)
            return f"{prefix}://****:****@{host}"
    if len(s) <= 8:
        return s[:2] + "****" + s[-2:] if len(s) >= 4 else "****"
    return f"{s[:4]}{'*' * (len(s) - 8)}{s[-4:]}"


class SecretsInJsModule(BaseModule):
    name = "secrets_in_js"
    description = "Statically scan JS bundles and source maps for hardcoded secrets"
    requires_crawl = True

    async def run(self):
        scripts: set[str] = set(self.ctx.get("scripts", []))

        # If crawler didn't find scripts or crawl was skipped, try root page
        if not scripts:
            try:
                r = await self.session.get(self.target.base)
                if r is not None and r.text:
                    for src in re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', r.text, re.I):
                        full_url = urljoin(self.target.base, src)
                        scripts.add(full_url)
            except Exception:
                pass

        sem = asyncio.Semaphore(6)
        scanned_urls: set[str] = set()

        async def scan_script(script_url: str):
            if script_url in scanned_urls:
                return
            scanned_urls.add(script_url)

            async with sem:
                r = await self.session.get(script_url)
                if r is None or r.status_code != 200:
                    return

                content_text = r.text or ""
                self._inspect_text(content_text, script_url, is_sourcemap=False)

                # Check for source map URL inside the bundle
                map_match = re.search(r"//#\s*sourceMappingURL=([^\s]+)", content_text)
                if map_match:
                    map_url = urljoin(script_url, map_match.group(1))
                    if map_url not in scanned_urls:
                        scanned_urls.add(map_url)
                        mr = await self.session.get(map_url)
                        if mr is not None and mr.status_code == 200:
                            self._inspect_text(mr.text or "", map_url, is_sourcemap=True)

        await asyncio.gather(*(scan_script(s) for s in list(scripts)[:25]))
        return self.findings

    def _inspect_text(self, text: str, source_url: str, is_sourcemap: bool) -> None:
        if not text:
            return

        seen_keys: set[str] = set()

        for kind, pattern, sev in SECRET_PATTERNS:
            for match in pattern.finditer(text):
                # If pattern has capturing group, use it; otherwise full match
                val = match.group(1) if match.groups() else match.group(0)
                val_clean = val.strip("\"' ")

                if any(x in val_clean.lower() for x in IGNORE_SNIPPETS):
                    continue

                masked = mask_secret(val_clean)
                dedup_key = f"{kind}:{masked}"
                if dedup_key in seen_keys:
                    continue
                seen_keys.add(dedup_key)

                location_type = "source map" if is_sourcemap else "JS bundle"
                self.add(
                    severity=sev,
                    title=f"Hardcoded {kind} in {location_type}",
                    detail=(
                        f"Discovered hardcoded {kind} in {source_url}.\n"
                        f"Pattern: {kind} | Masked Secret: {masked}"
                    ),
                    fix="Revoke this credential immediately, remove it from client bundles, and access APIs via backend proxies.",
                    url=source_url,
                    evidence=f"Matched: {kind} -> {masked}",
                    cwe="CWE-798",
                    owasp="A05:2021",
                )
