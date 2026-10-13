"""WAF / CDN fingerprint."""
from __future__ import annotations

from sentinelscan.core.findings import Severity
from sentinelscan.modules.base import BaseModule

SIGNATURES = {
    "cloudflare": "Cloudflare",
    "akamai": "Akamai",
    "sucuri": "Sucuri",
    "incapsula": "Imperva Incapsula",
    "aws waf": "AWS WAF",
    "cloudfront": "AWS CloudFront",
    "fastly": "Fastly",
    "f5 big-ip": "F5 BIG-IP",
    "barracuda": "Barracuda",
    "fortiweb": "FortiWeb",
    "mod_security": "ModSecurity",
}


class WafDetectModule(BaseModule):
    name = "waf_detect"
    description = "WAF / CDN fingerprint"

    async def run(self):
        # Payload jo usually WAF trigger karta hai (harmless)
        payload = "/?q=<script>alert(1)</script>"
        r = await self.session.get(self.target.base + payload)
        detected = set()
        if r:
            headers = {k.lower(): v for k, v in r.headers.items()}
            cookies = r.headers.get("Set-Cookie", "")
            blob = (str(headers) + cookies + r.text[:5000]).lower()
            for sig, name in SIGNATURES.items():
                if sig in blob:
                    detected.add(name)
            if r.status_code in (403, 406, 429) and "attack" in r.text.lower():
                detected.add("Unknown WAF (block page)")

        if detected:
            self.add(
                severity=Severity.INFO,
                title="WAF / CDN detected",
                detail=", ".join(sorted(detected)),
                fix="Review WAF rules; perform bypass testing in staging.",
                url=self.target.base,
            )
        return self.findings