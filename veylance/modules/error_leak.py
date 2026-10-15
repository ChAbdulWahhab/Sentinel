"""Error page internal information leakage detection with edge error filtering."""
from __future__ import annotations

import re
import time

from veylance.core.findings import Severity
from veylance.modules.base import BaseModule

ERROR_PATTERNS = [
    r"Traceback \(most recent call last\)",
    r"Stack trace:",
    r"at [\w.$]+\([\w.]+\.java:\d+\)",
    r"Fatal error:",
    r"Warning: .* on line \d+",
    r"SQLSTATE\[",
    r"mysqli?_",
    r"ORA-\d{5}",
    r"Whoops, looks like something went wrong",
    r"Werkzeug Debugger",
    r"DEBUG = True",
    r"Exception in thread",
    r"node_modules/",
    r"\bat Object\.<anonymous>",
    r"Microsoft OLE DB Provider for SQL Server",
    r"System\.Data\.SqlClient",
    r"Django Version:",
    r"Laravel",
    r"Symfony\\Component",
    r"<b>Notice</b>:",
]


class ErrorLeakModule(BaseModule):
    name = "error_leak"
    description = "Internal information leakage in error pages"

    async def run(self):
        probes = [
            f"/this-page-not-exist-{int(time.time())}",
            "/%00",
            "/?id='",
            "/?q=<script>alert(1)</script>",
            "/index.php?x[]=1",
            "/..%2f..%2f..%2fetc%2fpasswd",
            "/%7B%7B7*7%7D%7D",
        ]
        for p in probes:
            r = await self.session.get(self.target.base + p)
            if r is None:
                continue

            # Skip CDN/Cloudflare generic edge error pages (520-526) to avoid false positives
            if r.status_code in (520, 521, 522, 523, 524, 525, 526) and "cloudflare" in r.text.lower():
                continue

            for pat in ERROR_PATTERNS:
                m = re.search(pat, r.text, re.I)
                if m:
                    # Guard against matching Cloudflare or generic CDN error pages
                    snippet = r.text[max(0, m.start() - 80):m.end() + 120]
                    self.add(
                        severity=Severity.HIGH,
                        title="Error page internal information leakage",
                        detail=f"Found application debug pattern '{m.group(0)[:80]}' at path '{p}' (HTTP {r.status_code}).",
                        fix="Disable debug mode in production (DEBUG=False) and configure custom generic error pages.",
                        url=self.target.base + p,
                        evidence=f"Matched pattern '{pat}': ...{snippet.strip()}...",
                        cwe="CWE-209",
                        owasp="A04:2021",
                    )
                    return self.findings
        return self.findings