"""Cookie security flags, prefix compliance, and domain scoping checks."""
from __future__ import annotations

from veylance.core.findings import Severity
from veylance.modules.base import BaseModule

KNOWN_SESSION_NAMES = {
    "phpsessid", "jsessionid", "aspsessionid", "asp.net_sessionid",
    "sessionid", "connect.sid", "laravel_session", "session",
    "auth", "token", "jwt", "access_token", "id_token",
    "csrftoken", "xsrf-token", "ci_session", "_rails",
}


def _is_session_cookie(name: str) -> bool:
    name_low = name.lower()
    return name_low in KNOWN_SESSION_NAMES or any(
        kw in name_low for kw in ("session", "auth", "token", "jwt", "user")
    )


class CookiesModule(BaseModule):
    name = "cookies"
    description = "Cookie flags (HttpOnly, Secure, SameSite), prefix (__Host-/__Secure-), and Domain scoping"

    async def run(self):
        r = await self.session.get(self.target.root)
        if r is None:
            return self.findings

        try:
            raw_cookies = r.headers.get_list("set-cookie")
        except Exception:
            raw_cookies = [v for k, v in r.headers.items() if k.lower() == "set-cookie"]

        for cookie_str in raw_cookies:
            self._analyze_cookie(cookie_str)

        return self.findings

    def _analyze_cookie(self, cookie_str: str) -> None:
        parts = [p.strip() for p in cookie_str.split(";")]
        if not parts:
            return
        name_val = parts[0]
        cookie_name = name_val.split("=", 1)[0].strip()
        low_str = cookie_str.lower()

        # Parse cookie attributes
        attrs: dict[str, str] = {}
        for part in parts[1:]:
            if "=" in part:
                k, v = part.split("=", 1)
                attrs[k.strip().lower()] = v.strip()
            else:
                attrs[part.strip().lower()] = "true"

        is_sensitive = _is_session_cookie(cookie_name)
        is_https = self.target.scheme == "https"

        # 1. Missing Core Flags: HttpOnly, Secure, SameSite
        missing_flags = []
        if "httponly" not in attrs:
            missing_flags.append("HttpOnly")
        if is_https and "secure" not in attrs:
            missing_flags.append("Secure")
        if "samesite" not in attrs:
            missing_flags.append("SameSite")

        if missing_flags:
            sev = Severity.HIGH if (is_sensitive and "HttpOnly" in missing_flags) else Severity.MEDIUM
            self.add(
                severity=sev,
                title=f"Cookie '{cookie_name}' missing security flags",
                detail=f"Cookie lacks essential protection attributes: {', '.join(missing_flags)}.",
                fix="Add HttpOnly, Secure, and SameSite=Lax (or Strict) attributes to the Set-Cookie header.",
                url=self.target.base,
                evidence=f"Set-Cookie: {cookie_str}",
                cwe="CWE-1004" if "HttpOnly" in missing_flags else "CWE-614",
                owasp="A05:2021",
            )

        # 2. SameSite Policy Quality for Session/Auth Cookies
        samesite_val = attrs.get("samesite", "").lower()
        if is_sensitive:
            if samesite_val == "none":
                self.add(
                    severity=Severity.MEDIUM,
                    title=f"Sensitive cookie '{cookie_name}' configured with SameSite=None",
                    detail="SameSite=None permits the cookie to be sent with cross-site requests, increasing Cross-Site Request Forgery (CSRF) risk.",
                    fix="Change SameSite attribute to 'Strict' or 'Lax' for authentication/session cookies.",
                    url=self.target.base,
                    evidence=f"Set-Cookie: {cookie_str}",
                    cwe="CWE-352",
                    owasp="A01:2021",
                )
            elif samesite_val == "lax":
                self.add(
                    severity=Severity.INFO,
                    title=f"Session cookie '{cookie_name}' uses SameSite=Lax instead of Strict",
                    detail="SameSite=Lax sends cookies on top-level GET navigations. SameSite=Strict provides maximal CSRF protection for sensitive sessions.",
                    fix="Evaluate using SameSite=Strict if cross-site links do not need immediate authenticated state.",
                    url=self.target.base,
                    evidence=f"Set-Cookie: {cookie_str}",
                )

        # 3. Overly Broad Domain Attributes
        if "domain" in attrs:
            domain_val = attrs["domain"].lstrip(".")
            self.add(
                severity=Severity.LOW,
                title=f"Cookie '{cookie_name}' has broad Domain attribute: '{attrs['domain']}'",
                detail="Explicitly setting the Domain attribute makes the cookie accessible to all subdomains of the target domain. "
                       "If any subdomain is compromised or hijacked, attackers can read or tamper with this cookie.",
                fix="Omit the Domain attribute entirely to restrict the cookie strictly to the host (host-only cookie).",
                url=self.target.base,
                evidence=f"Domain={attrs['domain']} in Set-Cookie: {cookie_str}",
                cwe="CWE-287",
            )

        # 4. __Host- and __Secure- Prefix Compliance
        if is_https and is_sensitive and not cookie_name.startswith("__Host-") and not cookie_name.startswith("__Secure-"):
            self.add(
                severity=Severity.LOW,
                title=f"Session cookie '{cookie_name}' does not use '__Host-' prefix",
                detail="The '__Host-' prefix enforces that the cookie is secure, path=/, and restricted to the origin host without subdomains.",
                fix=f"Rename cookie to '__Host-{cookie_name}' and set Secure and Path=/ attributes with no Domain attribute.",
                url=self.target.base,
                evidence=f"Cookie name: '{cookie_name}'",
                references=["https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis#section-4.1.3"],
            )

        if cookie_name.startswith("__Host-"):
            violations = []
            if "secure" not in attrs:
                violations.append("missing 'Secure'")
            if attrs.get("path") != "/":
                violations.append("missing 'Path=/'")
            if "domain" in attrs:
                violations.append(f"Domain attribute must not be present (found Domain={attrs['domain']})")

            if violations:
                self.add(
                    severity=Severity.HIGH,
                    title=f"Cookie prefix violation: '{cookie_name}'",
                    detail=f"__Host- cookies must be Secure, Path=/, and have no Domain attribute: {', '.join(violations)}.",
                    fix="Follow RFC 6265bis specifications for __Host- prefixed cookies.",
                    url=self.target.base,
                    evidence=f"Set-Cookie: {cookie_str}",
                    cwe="CWE-1004",
                )
        elif cookie_name.startswith("__Secure-"):
            if "secure" not in attrs:
                self.add(
                    severity=Severity.HIGH,
                    title=f"Cookie prefix violation: '{cookie_name}' lacks Secure flag",
                    detail="__Secure- cookies must include the Secure attribute.",
                    fix="Add the 'Secure' attribute to the Set-Cookie header.",
                    url=self.target.base,
                    evidence=f"Set-Cookie: {cookie_str}",
                )