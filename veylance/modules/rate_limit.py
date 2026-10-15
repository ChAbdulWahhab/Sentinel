"""Rate limit detection, threshold discovery, and algorithm classification."""
from __future__ import annotations

import asyncio
import time
from collections import Counter

from veylance.core.findings import Severity
from veylance.modules.base import BaseModule


class RateLimitModule(BaseModule):
    name = "rate_limit"
    description = "Rate limiting detection, threshold analysis, and window classification"

    async def run(self):
        n = self.ctx.get("rate_requests", 20)
        url = self.target.root
        codes = []
        rl_headers_map: list[dict[str, str]] = []
        first_block = None
        first_block_headers = {}

        start = time.time()
        sem = asyncio.Semaphore(5)

        async def hit(i: int):
            nonlocal first_block, first_block_headers
            async with sem:
                r = await self.session.get(url, follow_redirects=False)
                if r is None:
                    return 0, {}
                hdrs = {k.lower(): v for k, v in r.headers.items()}
                if r.status_code in (429, 503) and first_block is None:
                    first_block = i
                    first_block_headers = hdrs
                return r.status_code, hdrs

        results = await asyncio.gather(*(hit(i) for i in range(1, n + 1)))
        for code, hdrs in results:
            codes.append(code)
            rl_headers = {k: v for k, v in hdrs.items() if k.startswith(("x-ratelimit", "ratelimit", "retry-after", "x-rate-limit"))}
            if rl_headers:
                rl_headers_map.append(rl_headers)

        dur = time.time() - start
        info = self.ctx.setdefault("info", {})
        code_counts = dict(Counter(codes))
        info["Rate limit burst"] = f"{n} requests in {dur:.2f}s -> {code_counts}"

        # 1. Distinguish Rate Limiting State & Thresholds
        if first_block is not None:
            retry_after = first_block_headers.get("retry-after", "N/A")
            limit_val = first_block_headers.get("x-ratelimit-limit") or first_block_headers.get("ratelimit-limit", "N/A")
            evidence_str = (
                f"Rate limit triggered at request #{first_block} of {n}. "
                f"Status: 429, Limit: {limit_val}, Retry-After: {retry_after}"
            )
            info["Rate limiter threshold"] = f"Triggered at request #{first_block}"
            self.add(
                severity=Severity.INFO,
                title="Rate limiter active (threshold identified)",
                detail=f"Target actively throttled burst traffic at request #{first_block}. Responses: {code_counts}.",
                fix="Ensure rate limits are also applied specifically to critical endpoints (login, password reset, search, API).",
                url=url,
                evidence=evidence_str,
            )
        elif rl_headers_map:
            # Headers found but threshold not exceeded in N requests
            sample_hdr = rl_headers_map[0]
            limit_val = sample_hdr.get("x-ratelimit-limit") or sample_hdr.get("ratelimit-limit", "unknown")
            rem_val = sample_hdr.get("x-ratelimit-remaining") or sample_hdr.get("ratelimit-remaining", "unknown")
            reset_val = sample_hdr.get("x-ratelimit-reset") or sample_hdr.get("ratelimit-reset", "unknown")

            # Algorithm classification
            algo = "fixed-window"
            if len(rl_headers_map) >= 2:
                rems = [int(h.get("x-ratelimit-remaining") or h.get("ratelimit-remaining", -1)) for h in rl_headers_map if (h.get("x-ratelimit-remaining") or h.get("ratelimit-remaining", "")).isdigit()]
                if len(rems) >= 2 and all(rems[i] >= rems[i + 1] for i in range(len(rems) - 1)):
                    algo = "token-bucket / sliding counter"

            evidence_str = f"Headers present: Limit={limit_val}, Remaining={rem_val}, Reset={reset_val}. Behavior: {algo}."
            info["Rate limiter"] = f"Configured ({algo}), threshold > {n} requests"
            self.add(
                severity=Severity.INFO,
                title="Rate limit headers detected (un-throttled burst)",
                detail=f"Rate limit tracking headers detected ({algo}), but {n} requests were within allowed quota.",
                fix="Verify that tighter limits apply to authentication, registration, and resource-heavy endpoints.",
                url=url,
                evidence=evidence_str,
            )
        else:
            evidence_str = f"Sent {n} rapid requests in {dur:.2f}s; received status {code_counts} with no 429 or rate headers."
            info["Rate limiter"] = "Not detected"
            self.add(
                code="RATE_LIMIT_NOT_DETECTED",
                severity=Severity.MEDIUM,
                title="Rate limiting not detected on target",
                detail=f"No HTTP 429 or throttling headers (X-RateLimit-*) observed after {n} rapid burst requests.",
                fix="Implement rate limiting using Nginx limit_req, Cloudflare WAF, or application middleware (e.g. express-rate-limit, django-ratelimit).",
                url=url,
                evidence=evidence_str,
                owasp="A04:2021",
            )

        # 2. Check for crawled auth endpoints
        pages = list(self.ctx.get("pages", {}).keys())
        auth_pages = [u for u in pages if any(kw in u.lower() for kw in ("login", "auth", "signin", "signup", "register"))]
        if auth_pages:
            self.add(
                severity=Severity.INFO,
                title="Authentication endpoints identified for targeted rate limiting",
                detail=f"Found {len(auth_pages)} authentication/login pages that require strict credential stuffing and brute-force protection.",
                fix="Apply strict per-IP and per-account rate limits, CAPTCHA, or account lockout policies on login endpoints.",
                url=auth_pages[0],
                evidence=f"Endpoints: {', '.join(auth_pages[:3])}",
            )

        return self.findings