"""Error page info leak."""
from __future__ import annotations

import re
import time

from sentinelscan.core.findings import Severity
from sentinelscan.modules.base import BaseModule

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
    description = "Error page se internal info leak"

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
            for pat in ERROR_PATTERNS:
                m = re.search(pat, r.text, re.I)
                if m:
                    self.add(
                        severity=Severity.HIGH,
                        title="Error page internal info leak",
                        detail=f"Path `{p}` par `{m.group(0)[:80]}` mila (HTTP {r.status_code})",
                        fix="Production me debug off karein aur custom error pages lagayein.",
                        url=self.target.base + p,
                        evidence=r.text[max(0, m.start()-80):m.end()+120],
                        cwe="CWE-209", owasp="A04:2021",
                    )
                    return self.findings
        return self.findings