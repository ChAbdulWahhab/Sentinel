"""Form CSRF / password over HTTP."""
from __future__ import annotations

from sentinelscan.core.findings import Severity
from sentinelscan.modules.base import BaseModule


class FormsCsrfModule(BaseModule):
    name = "forms_csrf"
    description = "CSRF tokens, password form transport"
    requires_crawl = True

    async def run(self):
        forms = self.ctx.get("forms", [])
        for page, f in forms:
            names = [n.lower() for n, _ in f["inputs"]]
            types = [t.lower() for _, t in f["inputs"]]
            has_pw = "password" in types
            has_csrf = any(
                "csrf" in n or n in ("_token", "authenticity_token", "__requestverificationtoken")
                for n in names
            )

            if f["method"] == "POST" and not has_csrf:
                self.add(severity=Severity.MEDIUM,
                         title=f"POST form me CSRF token missing ({page})",
                         detail=f"action=`{f['action'] or '(same page)'}`",
                         fix="CSRF token / SameSite cookies / Origin check lagayein.",
                         url=page, cwe="CWE-352", owasp="A01:2021")

            if has_pw and self.target.scheme != "https":
                self.add(severity=Severity.HIGH,
                         title="Password form HTTP par",
                         detail=page,
                         fix="HTTPS enforce karein.",
                         url=page, cwe="CWE-319")

            if has_pw and f["method"] == "GET":
                self.add(severity=Severity.HIGH,
                         title="Password form GET method use kar raha",
                         detail=page,
                         fix="POST use karein.",
                         url=page, cwe="CWE-598")

            # autocomplete check
            for n, t in f["inputs"]:
                if t == "password":
                    autocomplete = "off"
                    if autocomplete not in (f.get("attrs") or {}).get("autocomplete", ""):
                        pass
        return self.findings