"""Subresource Integrity (SRI) verification on external CDN scripts and stylesheets."""
from __future__ import annotations

import re
from urllib.parse import urlparse

from veylance.core.findings import Severity
from veylance.modules.base import BaseModule

CDN_PATTERNS = [
    "cdnjs.cloudflare.com", "unpkg.com", "cdn.jsdelivr.net", "stackpath.bootstrapcdn.com",
    "code.jquery.com", "ajax.googleapis.com", "cdn.tailwindcss.com", "cdn.segment.com",
    "use.fontawesome.com", "maxcdn.bootstrapcdn.com", "cdn.jsdelivr.net",
]


class SriCheckModule(BaseModule):
    name = "sri_check"
    description = "Subresource Integrity (SRI) validation for third-party scripts and stylesheets"
    requires_crawl = True

    async def run(self):
        target_host = self.target.hostname or ""
        pages_to_check = list(self.ctx.get("pages", {}).keys())[:10]
        if not pages_to_check:
            pages_to_check = [self.target.base]

        checked_assets: set[str] = set()

        for page_url in pages_to_check:
            r = await self.session.get(page_url)
            if r is None or not r.text:
                continue

            html_text = r.text

            # 1. Check <script> tags
            for tag in re.finditer(r'<script\b([^>]*)>', html_text, re.I):
                attrs = tag.group(1)
                src_match = re.search(r'src=["\']([^"\']+)["\']', attrs, re.I)
                if not src_match:
                    continue

                src = src_match.group(1).strip()
                if not self._is_external_asset(src, target_host):
                    continue

                if src in checked_assets:
                    continue
                checked_assets.add(src)

                has_integrity = bool(re.search(r'\bintegrity=["\']sha(?:256|384|512)-', attrs, re.I))
                if not has_integrity:
                    self.add(
                        severity=Severity.MEDIUM,
                        title=f"Missing Subresource Integrity (SRI) on external script: {urlparse(src).netloc}",
                        detail=(
                            f"Third-party script '{src}' is loaded on {page_url} without an 'integrity' attribute.\n"
                            "If the external CDN or hosting provider is compromised, arbitrary malicious JavaScript "
                            "can be executed in the context of your users' sessions without detection."
                        ),
                        fix=(
                            f"Add cryptographic integrity and crossorigin attributes to the tag:\n"
                            f"<script src=\"{src}\" integrity=\"sha384-...\" crossorigin=\"anonymous\"></script>"
                        ),
                        url=src,
                        evidence=f"Tag: <script {attrs[:100]}>",
                        cwe="CWE-353",
                        owasp="A08:2021",
                    )

            # 2. Check external <link rel="stylesheet">
            for tag in re.finditer(r'<link\b([^>]*)>', html_text, re.I):
                attrs = tag.group(1)
                if not re.search(r'rel=["\']stylesheet["\']', attrs, re.I):
                    continue

                href_match = re.search(r'href=["\']([^"\']+)["\']', attrs, re.I)
                if not href_match:
                    continue

                href = href_match.group(1).strip()
                if not self._is_external_asset(href, target_host):
                    continue

                if href in checked_assets:
                    continue
                checked_assets.add(href)

                has_integrity = bool(re.search(r'\bintegrity=["\']sha(?:256|384|512)-', attrs, re.I))
                if not has_integrity:
                    self.add(
                        severity=Severity.LOW,
                        title=f"Missing Subresource Integrity (SRI) on external stylesheet: {urlparse(href).netloc}",
                        detail=(
                            f"External stylesheet '{href}' is loaded without an 'integrity' hash attribute. "
                            "A compromised third-party style host could alter page layout or conduct CSS injection."
                        ),
                        fix=(
                            f"Add SRI verification to stylesheet:\n"
                            f"<link rel=\"stylesheet\" href=\"{href}\" integrity=\"sha384-...\" crossorigin=\"anonymous\">"
                        ),
                        url=href,
                        evidence=f"Tag: <link {attrs[:100]}>",
                        cwe="CWE-353",
                        owasp="A08:2021",
                    )

        return self.findings

    def _is_external_asset(self, url: str, base_host: str) -> bool:
        if url.startswith("//"):
            url = "https:" + url
        parsed = urlparse(url)
        if not parsed.netloc:
            return False
        # If it's a known CDN or different domain
        netloc = parsed.netloc.lower()
        if any(cdn in netloc for cdn in CDN_PATTERNS):
            return True
        return netloc != base_host.lower() and not netloc.endswith("." + base_host.lower())
