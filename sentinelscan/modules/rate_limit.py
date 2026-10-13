"""Rate limiter detection (safe burst)."""
from __future__ import annotations

import asyncio
import time
from collections import Counter

from sentinelscan.core.findings import Severity
from sentinelscan.modules.base import BaseModule


class RateLimitModule(BaseModule):
    name = "rate_limit"
    description = "Rate limiting burst test (homepage)"

    async def run(self):
        n = self.ctx.get("rate_requests", 20)
        url = self.target.root
        codes = []
        rl_headers = set()
        first_block = None

        start = time.time()
        sem = asyncio.Semaphore(5)

        async def hit(i):
            nonlocal first_block
            async with sem:
                r = await self.session.get(url, follow_redirects=False)
                if r is None:
                    return 0, {}
                return r.status_code, dict(r.headers)

        results = await asyncio.gather(*(hit(i) for i in range(1, n + 1)))
        for i, (code, hdrs) in enumerate(results, 1):
            codes.append(code)
            for h in hdrs:
                if h.lower().startswith(("x-ratelimit", "ratelimit", "retry-after", "x-rate-limit")):
                    rl_headers.add(h)
            if code in (429, 503) and first_block is None:
                first_block = i

        dur = time.time() - start
        info = self.ctx.setdefault("info", {})
        info["Rate limit test"] = f"{n} requests in {dur:.1f}s -> {dict(Counter(codes))}"
        if rl_headers:
            info["Rate limit headers"] = ", ".join(sorted(rl_headers))

        if first_block:
            info["Rate limiter"] = f"Detected at request #{first_block}"
        elif rl_headers:
            info["Rate limiter"] = "Headers mile, block nahi hua"
        else:
            self.add(severity=Severity.MEDIUM,
                     title="Rate limiter detect nahi hua",
                     detail=f"{n} tez requests par koi 429 / header nahi aaya (homepage only).",
                     fix="Login/register/OTP/API par throttle lagayein (nginx limit_req, Cloudflare, Laravel throttle, express-rate-limit).",
                     url=url, owasp="A04:2021")
            info["Rate limiter"] = "Detect nahi hua"

        if any("login" in u.lower() or "auth" in u.lower() for u in list(self.ctx.get("pages", {}))):
            self.add(severity=Severity.INFO,
                     title="Login/auth endpoints mile",
                     detail="Brute-force protection verify karein (lockout, CAPTCHA, 2FA).",
                     fix="Manual test staging mein.",
                     url=url)
        return self.findings