"""HTTP methods (OPTIONS, TRACE, PUT, DELETE)."""
from __future__ import annotations

from sentinelscan.core.findings import Severity
from sentinelscan.modules.base import BaseModule


class HttpMethodsModule(BaseModule):
    name = "http_methods"
    description = "OPTIONS/TRACE/PUT/DELETE exposure"

    async def run(self):
        r = await self.session.request("OPTIONS", self.target.root)
        if r is not None:
            allow = r.headers.get("allow", "")
            if allow:
                self.ctx.setdefault("info", {})["Allowed methods"] = allow
                bad = [m for m in allow.upper().split(",") if m.strip() in ("PUT", "DELETE", "TRACE", "CONNECT", "PATCH")]
                if bad:
                    self.add(severity=Severity.LOW,
                             title="Risky HTTP methods allowed",
                             detail=allow,
                             fix="Unnecessary methods disable karein (nginx: if ($request_method !~ ^(GET|POST|HEAD)$)).",
                             url=self.target.root)

        r = await self.session.request("TRACE", self.target.root)
        if r is not None and r.status_code == 200 and "TRACE" in r.text:
            self.add(severity=Severity.MEDIUM,
                     title="HTTP TRACE enabled",
                     detail="Server request echo kar raha (XST risk).",
                     fix="TraceEnable off (Apache) / disable TRACE (nginx).",
                     url=self.target.root, cwe="CWE-693")

        # PUT/DELETE probe
        for method in ("PUT", "DELETE"):
            r = await self.session.request(method, self.target.root + "sentinelscan_test_probe.txt",
                                           content=b"sentinel-probe")
            if r is not None and r.status_code in (200, 201, 204):
                self.add(severity=Severity.HIGH,
                         title=f"HTTP {method} allowed",
                         detail=f"Status {r.status_code} — file create/delete possible.",
                         fix=f"{method} disable karein.",
                         url=self.target.root, cwe="CWE-650")
        return self.findings