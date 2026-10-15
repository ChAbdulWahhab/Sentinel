"""Tech fingerprinting and local CVE advisory version-matching."""
from __future__ import annotations

import re

from veylance.core.findings import Severity
from veylance.modules.base import BaseModule
from veylance.utils.cve import match_cves


class TechFingerprintModule(BaseModule):
    name = "tech_fingerprint"
    description = "Server, framework, and CMS fingerprinting with local CVE advisory matching"

    async def run(self):
        r = await self.session.get(self.target.root)
        if r is None:
            return self.findings

        info = self.ctx.setdefault("info", {})
        tech = self.ctx.setdefault("tech", set())

        # 1. Header Analysis
        header_map = {k.lower(): v for k, v in r.headers.items()}

        server_hdr = header_map.get("server", "")
        if server_hdr:
            tech.add(f"Server: {server_hdr}")
            # Check for Apache or Nginx with version
            m_apache = re.search(r"apache/([0-9\.]+)", server_hdr, re.I)
            if m_apache:
                ver = m_apache.group(1)
                for f in match_cves("apache", ver, self.target.base):
                    self.findings.append(f)

            m_nginx = re.search(r"nginx/([0-9\.]+)", server_hdr, re.I)
            if m_nginx:
                ver = m_nginx.group(1)
                for f in match_cves("nginx", ver, self.target.base):
                    self.findings.append(f)

            m_openssl = re.search(r"openssl/([0-9a-z\.]+)", server_hdr, re.I)
            if m_openssl:
                ver = m_openssl.group(1)
                for f in match_cves("openssl", ver, self.target.base):
                    self.findings.append(f)

        x_powered = header_map.get("x-powered-by", "")
        if x_powered:
            tech.add(f"X-Powered-By: {x_powered}")
            m_php = re.search(r"php/([0-9\.]+)", x_powered, re.I)
            if m_php:
                ver = m_php.group(1)
                for f in match_cves("php", ver, self.target.base):
                    self.findings.append(f)

        # 2. Body Patterns and Script Inclusions
        try:
            body = r.text or ""
        except Exception:
            body = ""

        # Framework and CMS detection
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

        # Check for WordPress version in meta generator
        m_wp = re.search(r'<meta\s+name=["\']generator["\']\s+content=["\']WordPress\s+([0-9\.]+)["\']', body, re.I)
        if m_wp:
            ver = m_wp.group(1)
            tech.add(f"WordPress {ver}")
            for f in match_cves("wordpress", ver, self.target.base):
                self.findings.append(f)

        # Check for jQuery version in script filenames or comments
        m_jq = re.search(r"jquery[-/]([0-9\.]+)(?:\.min)?\.js", body, re.I)
        if not m_jq:
            m_jq = re.search(r"jQuery\s+v([0-9\.]+)", body, re.I)
        if m_jq:
            ver = m_jq.group(1)
            tech.add(f"jQuery {ver}")
            for f in match_cves("jquery", ver, self.target.base):
                self.findings.append(f)

        info["Detected tech"] = sorted(tech)
        return self.findings