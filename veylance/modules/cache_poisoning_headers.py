"""Detection of unkeyed cache header reflections for web cache poisoning risk."""
from __future__ import annotations

import re

from veylance.core.findings import Severity
from veylance.modules.base import BaseModule

CANARY_HOST = "veylance-cache-canary.internal"

CACHE_HEADER_NAMES = (
    "cache-control", "x-cache", "cf-cache-status", "age",
    "x-cache-hits", "x-varnish", "x-fastly-request-id", "x-served-by"
)


class CachePoisoningHeadersModule(BaseModule):
    name = "cache_poisoning_headers"
    description = "Check for unkeyed cache header reflection (X-Forwarded-Host, X-Forwarded-Scheme)"

    async def run(self):
        url = self.target.base

        # Benign non-destructive probe testing header reflection
        probe_headers = {
            "X-Forwarded-Host": CANARY_HOST,
            "X-Forwarded-Scheme": "http",
        }

        try:
            r = await self.session.get(url, headers=probe_headers, follow_redirects=False)
        except Exception:
            return self.findings

        if r is None:
            return self.findings

        body = r.text or ""
        headers = r.headers

        # Collect caching indicators
        cache_indicators = [
            f"{h}: {headers[h]}" for h in CACHE_HEADER_NAMES if h in headers
        ]
        cache_ctx = ", ".join(cache_indicators) if cache_indicators else "no cache headers detected"

        # Check for reflection in Location header (redirect-based cache poisoning)
        location = headers.get("location", "")
        if CANARY_HOST in location:
            self.add(
                severity=Severity.HIGH,
                title="Unkeyed header reflected in redirect Location header (Cache Poisoning Risk)",
                detail=(
                    f"The canary value '{CANARY_HOST}' passed via 'X-Forwarded-Host' was directly reflected "
                    f"in the HTTP Location header ('{location}').\n"
                    "If an edge cache or reverse proxy caches this redirect without including 'X-Forwarded-Host' "
                    "in the cache key, legitimate users visiting this endpoint will be redirected to the attacker's host."
                ),
                fix="Configure your web server and reverse proxy to reject unverified 'X-Forwarded-Host' headers or strip them at the edge.",
                url=url,
                evidence=f"Reflected Location: {location} | Cache Context: [{cache_ctx}]",
                cwe="CWE-444",
                owasp="A05:2021",
            )
            return self.findings

        # Check for reflection in response body
        if CANARY_HOST in body:
            # Check if reflected inside script tag, link tag, or general markup
            is_script_ref = bool(re.search(rf'<script[^>]+(?:src=[\'"]|[\'"])[^\'"]*{re.escape(CANARY_HOST)}', body, re.I))
            sev = Severity.HIGH if is_script_ref else Severity.MEDIUM

            # Extract small reflection snippet
            idx = body.find(CANARY_HOST)
            start = max(0, idx - 40)
            end = min(len(body), idx + len(CANARY_HOST) + 40)
            snippet = body[start:end].replace("\n", " ").strip()

            self.add(
                severity=sev,
                title="Unkeyed header reflected in response body (Web Cache Poisoning Risk)",
                detail=(
                    f"The canary header 'X-Forwarded-Host: {CANARY_HOST}' is reflected in the server response body.\n"
                    "Observed behavior: header reflection without cache verification. "
                    "If intermediate CDN layers cache this response unkeyed, an attacker could poison cached responses "
                    "to hijack resource URLs or conduct client-side attacks."
                ),
                fix="Strip untrusted 'X-Forwarded-Host' / 'X-Forwarded-Scheme' headers at the CDN edge or configure the cache to include these headers in the cache key.",
                url=url,
                evidence=f"Reflected snippet: ...{snippet}... | Cache Context: [{cache_ctx}]",
                cwe="CWE-444",
                owasp="A05:2021",
            )

        return self.findings
