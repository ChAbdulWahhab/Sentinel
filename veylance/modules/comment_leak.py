"""Detection of sensitive developer comments and internal infrastructure references in HTML and JS."""
from __future__ import annotations

import re

from veylance.core.findings import Severity
from veylance.modules.base import BaseModule

COMMENT_PATTERNS = [
    (
        "Auth Bypass / Credential Comment",
        re.compile(r"""(?://|/\*|<!--)\s*.*?(?:remove\s+(?:auth|before\s+prod)|auth\s+bypass|temp\s+admin|disable\s+security|hardcoded\s+pass).*?(?:\*/|-->|$)""", re.I | re.M),
        Severity.HIGH,
    ),
    (
        "Sensitive Action Item (TODO/FIXME)",
        re.compile(r"""(?://|/\*|<!--)\s*(?:TODO|FIXME|HACK|XXX)[\s:]+.*?(?:credentials?|password|secret|token|api_key|auth|internal|staging|bypass).*?(?:\*/|-->|$)""", re.I | re.M),
        Severity.MEDIUM,
    ),
    (
        "Internal IP Leak in Code",
        re.compile(r"""https?://(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|localhost|127\.0\.0\.1)(?::\d+)?[^\s'"<>]*""", re.I),
        Severity.LOW,
    ),
    (
        "Staging / Dev Endpoint Leak in Code",
        re.compile(r"""https?://(?:staging|dev|internal|corp|uat|test-api)\.[a-zA-Z0-9_\-\.]+\.[a-zA-Z]{2,}[^\s'"<>]*""", re.I),
        Severity.LOW,
    ),
]


def _mask_comment_evidence(text: str) -> str:
    """Mask any literal credentials in comment snippet."""
    masked = re.sub(r"((?:password|pass|secret|key|token)\s*[:=]\s*['\"]?)([^\s'\"&>]+)", r"\1****MASKED****", text, flags=re.I)
    return masked.strip()[:150]


class CommentLeakModule(BaseModule):
    name = "comment_leak"
    description = "Scan HTML and JS for developer comments leaking internal URLs, auth bypasses, or credentials"
    requires_crawl = True

    async def run(self):
        urls_to_scan = set(self.ctx.get("pages", {}).keys())
        for s in self.ctx.get("scripts", []):
            urls_to_scan.add(s)

        if not urls_to_scan:
            urls_to_scan.add(self.target.base)

        seen_findings: set[str] = set()

        for url in list(urls_to_scan)[:20]:
            r = await self.session.get(url)
            if r is None or not r.text:
                continue

            body = r.text

            for category, pattern, sev in COMMENT_PATTERNS:
                for match in pattern.finditer(body):
                    snippet = match.group(0).strip()
                    # Filter benign or standard boilerplates
                    if any(x in snippet.lower() for x in ("reactjs.org", "w3.org", "github.com/facebook", "polyfill", "license")):
                        continue

                    masked_snippet = _mask_comment_evidence(snippet)
                    dedup_key = f"{category}:{masked_snippet[:60]}"
                    if dedup_key in seen_findings:
                        continue
                    seen_findings.add(dedup_key)

                    self.add(
                        code="COMMENT_LEAK",
                        severity=sev,
                        title=f"Information leakage in developer comments: {category}",
                        detail=(
                            f"Discovered {category.lower()} in {url}.\n"
                            "Developer comments in production client-facing assets can reveal staging endpoints, "
                            "internal IP addresses, or unfinished security controls."
                        ),
                        fix="Strip comments and sanitize internal endpoints during the production build/bundling pipeline.",
                        url=url,
                        evidence=masked_snippet,
                        cwe="CWE-615",
                        owasp="A01:2021",
                    )

        return self.findings
