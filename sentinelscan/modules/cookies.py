"""Cookie flags check."""
from __future__ import annotations

from sentinelscan.core.findings import Severity
from sentinelscan.modules.base import BaseModule

COOKIE_TECH = {
    "PHPSESSID": "PHP", "laravel_session": "Laravel", "XSRF-TOKEN": "Laravel/Angular",
    "connect.sid": "Node.js Express", "csrftoken": "Django", "sessionid": "Django",
    "JSESSIONID": "Java Servlet/Spring", "ASP.NET_SessionId": "ASP.NET",
    "_rails": "Ruby on Rails", "ci_session": "CodeIgniter",
    "__cfduid": "Cloudflare", "__cf_bm": "Cloudflare",
}


class CookiesModule(BaseModule):
    name = "cookies"
    description = "Cookie flags (HttpOnly, Secure, SameSite, prefix)"

    async def run(self):
        r = await self.session.get(self.target.root)
        if r is None:
            return self.findings

        # use get_list in httpx
        try:
            raw = r.headers.get_list("set-cookie")
        except Exception:
            raw = [v for k, v in r.headers.items() if k.lower() == "set-cookie"]

        for c in raw:
            name = c.split("=", 1)[0].strip()
            low = c.lower()

            # tech fingerprint
            for k, v in COOKIE_TECH.items():
                if name.startswith(k):
                    self.ctx.setdefault("tech", set()).add(f"{v} ({name})")

            missing = []
            if "httponly" not in low: missing.append("HttpOnly")
            if "secure" not in low and self.target.scheme == "https": missing.append("Secure")
            if "samesite" not in low: missing.append("SameSite")

            if missing:
                self.add(
                    severity=Severity.MEDIUM,
                    title=f"Cookie `{name}` missing security flags",
                    detail="Missing: " + ", ".join(missing),
                    fix="Add HttpOnly, Secure, and SameSite=Lax or Strict flags to Set-Cookie.",
                    url=self.target.base,
                    cwe="CWE-1004", owasp="A05:2021",
                )

            # __Host- / __Secure- prefix check
            if name.startswith("__Host-") and ("secure" not in low or "path=/" not in low):
                self.add(severity=Severity.MEDIUM, title=f"`__Host-` prefix violation: {name}",
                         detail="__Host- cookies require both the Secure attribute and Path=/.",
                         fix="Follow the cookie prefix requirements defined in RFC 6265bis.", url=self.target.base)
        return self.findings