"""Async HTTP session with retries, proxy, TLS config."""
from __future__ import annotations

import httpx

from veylance.config import DEFAULT_UA


class HttpSession:
    def __init__(self, timeout=10, verify_tls=True, proxy=None,
                 user_agent=None, cookie=None, extra_headers=None, concurrency=10):
        headers = {
            "User-Agent": user_agent or DEFAULT_UA,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }
        if cookie:
            headers["Cookie"] = cookie
        if extra_headers:
            headers.update(extra_headers)

        limits = httpx.Limits(
            max_connections=concurrency,
            max_keepalive_connections=concurrency,
        )

        # httpx >= 0.28 uses `proxy=`, older used `proxies=`
        client_kwargs = dict(
            timeout=timeout,
            verify=verify_tls,
            headers=headers,
            limits=limits,
            follow_redirects=True,
            http2=True,
        )
        try:
            # modern httpx
            self.client = httpx.AsyncClient(proxy=proxy, **client_kwargs)
        except TypeError:
            # legacy fallback
            self.client = httpx.AsyncClient(proxies=proxy, **client_kwargs)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        await self.client.aclose()

    async def get(self, url, **kw):
        try:
            return await self.client.get(url, **kw)
        except httpx.HTTPError:
            return None

    async def post(self, url, **kw):
        try:
            return await self.client.post(url, **kw)
        except httpx.HTTPError:
            return None

    async def request(self, method, url, **kw):
        try:
            return await self.client.request(method, url, **kw)
        except httpx.HTTPError:
            return None