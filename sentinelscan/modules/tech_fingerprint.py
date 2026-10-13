"""Tech fingerprint — server headers, cookies, body patterns."""
from __future__ import annotations

from sentinelscan.core.findings import Severity
from sentinelscan.modules.base import BaseModule


class TechFingerprintModule(BaseModule):
    name = "tech_fingerprint"
    description = "Server, framework, CMS, libraries detection"

    async def run(self):
        r = await self.session.get(self.target.root)
        if r is None:
            return self.findings

        info = self.ctx.setdefault("info", {})
        tech = self.ctx.setdefault("tech", set())

        # ye headers sirf info me collect karo — headers module already finding banata hai
        for h in ("server", "x-powered-by", "x-aspnet-version", "x-generator",
                  "x-drupal-cache", "x-shopify-stage", "x-vercel-id", "x-amz-cf-id"):
            v = None
            for k, val in r.headers.items():
                if k.lower() == h:
                    v = val
                    break
            if v:
                tech.add(f"{h}: {v}")

        # Body patterns se tech detect karo (agar crawler ne nahi kiya)
        try:
            body = r.text or ""
        except Exception:
            body = ""

        import re
        patterns = [
            (r"wp-content|wp-includes", "WordPress"),
            (r"/_next/", "Next.js"),
            (r"/_nuxt/", "Nuxt.js"),
            (r"ng-version=", "Angular"),
            (r"data-reactroot|__REACT", "React"),
            (r"vue(\.min)?\.js", "Vue.js"),
            (r"csrfmiddlewaretoken", "Django"),
            (r"livewire", "Laravel Livewire"),
            (r"jquery", "jQuery"),
            (r"bootstrap", "Bootstrap"),
            (r"tailwind", "Tailwind CSS"),
            (r"Shopify\.", "Shopify"),
            (r"Drupal", "Drupal"),
            (r"Joomla", "Joomla"),
        ]
        for pat, name in patterns:
            if re.search(pat, body, re.I):
                tech.add(name)

        info["Detected tech"] = sorted(tech)
        return self.findings