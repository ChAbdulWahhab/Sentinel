"""Detection of publicly accessible JavaScript source maps."""
from __future__ import annotations

import asyncio
import hashlib
import json
import re
from urllib.parse import urljoin

from veylance.core.findings import Severity
from veylance.modules.base import BaseModule
from veylance.utils.baseline import get_or_create_baseline


class SourceMapExposureModule(BaseModule):
    name = "source_map_exposure"
    description = "Publicly accessible JavaScript source maps"
    requires_crawl = True

    async def run(self):
        baseline = await get_or_create_baseline(self.session, self.target.base, self.ctx)
        scripts: set[str] = set(self.ctx.get("scripts", []))

        # Fallback to homepage scripts if none crawled
        if not scripts:
            try:
                r = await self.session.get(self.target.base)
                if r is not None and r.text:
                    for src in re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', r.text, re.I):
                        scripts.add(urljoin(self.target.base, src))
            except Exception:
                pass

        map_candidates: set[str] = set()

        sem = asyncio.Semaphore(6)

        async def inspect_bundle(script_url: str):
            async with sem:
                # Add adjacent .map candidate
                if not script_url.endswith(".map"):
                    map_candidates.add(script_url + ".map")

                r = await self.session.get(script_url)
                if r is not None and r.status_code == 200 and r.text:
                    match = re.search(r"//#\s*sourceMappingURL=([^\s]+)", r.text)
                    if match:
                        map_candidates.add(urljoin(script_url, match.group(1)))

        await asyncio.gather(*(inspect_bundle(s) for s in list(scripts)[:20]))

        async def verify_map(map_url: str):
            async with sem:
                r = await self.session.get(map_url)
                if r is None or r.status_code != 200:
                    return

                content = getattr(r, "content", None)
                if content is None:
                    content = r.text.encode("utf-8") if getattr(r, "text", None) else b""
                b_hash = hashlib.sha256(content).hexdigest()

                text = r.text or ""
                is_html = bool(re.search(r"<!doctype\s+html|<html|<body", text[:500], re.I))

                # Baseline diff check: if matches baseline and is HTML, suppress
                if is_html or baseline.matches(r.status_code, len(content), b_hash):
                    if is_html:
                        return

                # Verify genuine source map format (JSON with version 3 and sources or mappings)
                is_valid_map = False
                sources_preview = ""

                if '"version":' in text and ('"sources":' in text or '"mappings":' in text):
                    try:
                        data = json.loads(text)
                        if isinstance(data, dict) and data.get("version") in (3, "3"):
                            is_valid_map = True
                            sources = data.get("sources", [])
                            if sources and isinstance(sources, list):
                                sources_preview = f"Sources ({len(sources)}): " + ", ".join(str(s) for s in sources[:5])
                    except Exception:
                        if '"mappings":' in text:
                            is_valid_map = True

                if is_valid_map:
                    evidence_str = sources_preview or text[:120]
                    self.add(
                        code="SOURCE_MAP_EXPOSURE",
                        severity=Severity.HIGH,
                        title=f"Public JavaScript source map exposed: {map_url.split('/')[-1]}",
                        detail=(
                            f"Production source map is accessible at {map_url}.\n"
                            "Source maps expose original unminified source code, internal file structures, "
                            "and build-time comments to anyone on the internet."
                        ),
                        fix="Disable source map emission in production builds (e.g. 'productionSourceMap: false' in Webpack/Vite) or block public HTTP access to *.map files in web server / CDN rules.",
                        url=map_url,
                        evidence=evidence_str,
                        cwe="CWE-540",
                        owasp="A05:2021",
                    )

        await asyncio.gather(*(verify_map(u) for u in list(map_candidates)[:25]))
        return self.findings
