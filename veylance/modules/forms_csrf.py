"""Form CSRF / password over HTTP."""
from __future__ import annotations

from veylance.core.findings import Severity
from veylance.modules.base import BaseModule


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
                self.add(code="CSRF_TOKEN_MISSING",
                         severity=Severity.MEDIUM,
                         title=f"CSRF token missing in POST form ({page})",
                         detail=f"action=`{f['action'] or '(same page)'}`",
                         fix="Implement CSRF tokens, SameSite cookies, or Origin header checks.",
                         url=page, cwe="CWE-352", owasp="A01:2021")

            if has_pw and self.target.scheme != "https":
                self.add(severity=Severity.HIGH,
                         title="Password form served over HTTP",
                         detail=page,
                         fix="Enforce HTTPS.",
                         url=page, cwe="CWE-319")

            if has_pw and f["method"] == "GET":
                self.add(severity=Severity.HIGH,
                         title="Password form uses GET method",
                         detail=page,
                         fix="Use the POST method.",
                         url=page, cwe="CWE-598")

            # autocomplete check
            for n, t in f["inputs"]:
                if t == "password":
                    autocomplete = "off"
                    if autocomplete not in (f.get("attrs") or {}).get("autocomplete", ""):
                        pass
        return self.findings