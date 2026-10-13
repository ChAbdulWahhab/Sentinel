"""Async crawler — pages, links, forms, JS endpoints."""
from __future__ import annotations

import asyncio
import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse, urldefrag

from sentinelscan.core.session import HttpSession
from sentinelscan.core.target import Target

SKIP_EXT = re.compile(
    r"\.(png|jpe?g|gif|svg|ico|css|woff2?|ttf|eot|pdf|zip|tar|gz|mp4|mp3|webp|avi|mov|webm|exe|dmg|iso)(\?|$)",
    re.I,
)

TECH_PATTERNS = [
    (r"wp-content|wp-includes", "WordPress"),
    (r"/_next/", "Next.js"),
    (r"/_nuxt/", "Nuxt.js"),
    (r"ng-version=", "Angular"),
    (r"data-reactroot|__REACT|react(\.min)?\.js", "React"),
    (r"vue(\.min)?\.js|data-v-[0-9a-f]{6,}", "Vue.js"),
    (r"csrfmiddlewaretoken", "Django"),
    (r"livewire", "Laravel Livewire"),
    (r"jquery", "jQuery"),
    (r"bootstrap", "Bootstrap"),
    (r"tailwind", "Tailwind CSS"),
    (r"cdn\.jsdelivr|cdnjs\.cloudflare|unpkg", "Public CDN"),
    (r"googletagmanager|google-analytics|gtag\(", "GA/GTM"),
    (r"Shopify\.", "Shopify"),
    (r"Drupal", "Drupal"),
    (r"Joomla", "Joomla"),
    (r"__NEXT_DATA__", "Next.js (data)"),
    (r"hotjar|segment\.com|mixpanel", "Analytics"),
]

JS_ENDPOINT_RX = re.compile(
    r"""["'`]((?:/|https?://[^"'`\s]+/)(?:api|v\d|graphql|rest|auth|oauth|admin|user|users|login|logout|register|account|profile|upload|webhook)[A-Za-z0-9_\-/{}.:?=&]*)["'`]"""
)


class PageParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links: set[str] = set()
        self.scripts: set[str] = set()
        self.forms: list[dict] = []
        self.meta: dict[str, str] = {}
        self._form: dict | None = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag in ("a", "link") and a.get("href"):
            self.links.add(a["href"])
        elif tag == "script":
            if a.get("src"):
                self.scripts.add(a["src"])
        elif tag == "meta" and a.get("name"):
            self.meta[a["name"].lower()] = a.get("content", "")
        elif tag == "form":
            self._form = {
                "action": a.get("action", ""),
                "method": (a.get("method") or "GET").upper(),
                "inputs": [],
            }
            self.forms.append(self._form)
        elif tag in ("input", "textarea", "select") and self._form is not None:
            self._form["inputs"].append((a.get("name", ""), a.get("type", tag)))

    def handle_endtag(self, tag):
        if tag == "form":
            self._form = None


class Crawler:
    def __init__(self, target: Target, session: HttpSession, max_pages: int, concurrency: int):
        self.target = target
        self.session = session
        self.max_pages = max_pages
        self.sem = asyncio.Semaphore(concurrency)
        self.pages: dict[str, tuple[int, str]] = {}
        self.scripts: set[str] = set()
        self.forms: list[tuple[str, dict]] = []
        self.js_endpoints: set[str] = set()
        self.tech: set[str] = set()
        self._seen: set[str] = set()

    def _same_site(self, url: str) -> bool:
        return urlparse(url).netloc == self.target.netloc

    async def _fetch(self, url: str):
        async with self.sem:
            return await self.session.get(url)

    async def _process(self, url: str):
        if url in self._seen or len(self.pages) >= self.max_pages:
            return
        self._seen.add(url)
        r = await self._fetch(url)
        if r is None:
            return
        ctype = r.headers.get("content-type", "").split(";")[0]
        self.pages[str(r.url)] = (r.status_code, ctype)
        if "html" not in ctype:
            return
        text = r.text

        # tech
        for pat, name in TECH_PATTERNS:
            if re.search(pat, text, re.I):
                self.tech.add(name)

        p = PageParser()
        try:
            p.feed(text)
        except Exception:
            return

        gen = p.meta.get("generator")
        if gen:
            self.tech.add(f"Generator: {gen}")

        for s in p.scripts:
            self.scripts.add(urljoin(str(r.url), s))

        for f in p.forms:
            self.forms.append((str(r.url), f))

        # follow links
        next_urls = []
        for href in p.links:
            full = urldefrag(urljoin(str(r.url), href))[0]
            if not full.startswith(("http://", "https://")):
                continue
            if not self._same_site(full):
                continue
            if SKIP_EXT.search(full):
                continue
            if full in self._seen:
                continue
            next_urls.append(full)

        await asyncio.gather(*(self._process(u) for u in next_urls[: self.max_pages]))

    async def crawl(self):
        await self._process(self.target.root)

    async def mine_js(self):
        """Extract API endpoints from JS files."""
        for js in list(self.scripts)[:30]:
            if not self._same_site(js):
                continue
            r = await self._fetch(js)
            if r is None or r.status_code != 200:
                continue
            for m in JS_ENDPOINT_RX.findall(r.text):
                self.js_endpoints.add(m)