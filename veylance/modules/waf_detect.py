"""WAF / CDN fingerprinting and edge proxy awareness."""
from __future__ import annotations

from veylance.core.findings import Severity
from veylance.modules.base import BaseModule

CDN_WAF_SIGNATURES = {
    "Cloudflare": {
        "headers": ["cf-ray", "cf-cache-status", "cf-mitigated", "cf-request-id"],
        "server": ["cloudflare"],
        "cookies": ["__cfduid", "__cf_bm", "cf_clearance"],
        "body": ["cloudflare ray id", "cf-browser-verification", "attention required! | cloudflare"],
    },
    "AWS CloudFront": {
        "headers": ["x-amz-cf-id", "x-amz-cf-pop"],
        "server": ["cloudfront"],
        "cookies": [],
        "body": ["cloudfront"],
    },
    "AWS WAF": {
        "headers": ["x-amzn-waf-action", "x-amzn-errortype"],
        "server": ["awswaf"],
        "cookies": ["awswaf"],
        "body": ["awswaf"],
    },
    "Fastly": {
        "headers": ["x-fastly-request-id", "fastly-restarts"],
        "server": ["fastly"],
        "cookies": [],
        "body": ["fastly"],
    },
    "Akamai": {
        "headers": ["x-akamai-transformed", "akamai-origin-hop", "x-akamai-request-id"],
        "server": ["akamaighost"],
        "cookies": ["ak_bmsc", "bm_sz"],
        "body": ["akamai"],
    },
    "Imperva / Incapsula": {
        "headers": ["x-iinfo", "x-cdn"],
        "server": ["incapsula"],
        "cookies": ["incap_ses", "_incapsula_"],
        "body": ["incapsula", "imperva"],
    },
    "Sucuri": {
        "headers": ["x-sucuri-id", "x-sucuri-cache"],
        "server": ["sucuri"],
        "cookies": [],
        "body": ["sucuri"],
    },
    "F5 BIG-IP": {
        "headers": ["x-cnection", "x-wa-info"],
        "server": ["big-ip"],
        "cookies": ["bigipserver", "ts"],
        "body": [],
    },
}


class WafDetectModule(BaseModule):
    name = "waf_detect"
    description = "WAF / CDN detection (Cloudflare, CloudFront, Akamai, etc.) and edge proxy awareness"

    async def run(self):
        detected_wafs: set[str] = set()
        matched_evidence: list[str] = []

        # 1. Inspect root page response
        r_root = await self.session.get(self.target.root)
        if r_root is not None:
            self._evaluate_response(r_root, detected_wafs, matched_evidence)

        # 2. Safe probe to detect active inspection / block page
        probe_url = self.target.base + "/?q=%3Cscript%3Ealert(1)%3C/script%3E"
        r_probe = await self.session.get(probe_url)
        if r_probe is not None:
            self._evaluate_response(r_probe, detected_wafs, matched_evidence)
            if r_probe.status_code in (403, 406, 429) and any(
                w in r_probe.text.lower() for w in ("waf", "firewall", "blocked", "incident id", "security policy")
            ):
                if not detected_wafs:
                    detected_wafs.add("Generic WAF / Security Gateway")
                    matched_evidence.append(f"HTTP {r_probe.status_code} block page on XSS probe: '{probe_url}'")

        # Record findings and context info
        info = self.ctx.setdefault("info", {})
        if detected_wafs:
            waf_names = sorted(detected_wafs)
            info["WAF / CDN"] = ", ".join(waf_names)
            info["is_behind_waf"] = True
            info["waf_names"] = waf_names

            # Explicit Cloudflare detection and proxy awareness advisory
            if "Cloudflare" in detected_wafs:
                info["cloudflare_detected"] = True
                self.add(
                    severity=Severity.INFO,
                    title="Target is behind Cloudflare edge proxy / WAF",
                    detail=(
                        "Target is behind Cloudflare — results reflect the edge/proxy, not necessarily the origin server; "
                        "some modules (e.g., header/tech fingerprinting) may show Cloudflare’s values instead of the origin’s."
                    ),
                    fix="For origin infrastructure security, audit the origin host directly in staging/internal environment, and ensure origin IP is not exposed.",
                    url=self.target.base,
                    evidence="; ".join(matched_evidence[:3]),
                )

            other_wafs = [w for w in waf_names if w != "Cloudflare"]
            if other_wafs:
                self.add(
                    severity=Severity.INFO,
                    title=f"WAF / CDN detected: {', '.join(other_wafs)}",
                    detail=f"Target traffic is routed through {', '.join(other_wafs)}. Results reflect edge proxy behavior.",
                    fix="Verify WAF rules, rate limits, and origin shielding in your security console.",
                    url=self.target.base,
                    evidence="; ".join(matched_evidence[:3]),
                )

        return self.findings

    def _evaluate_response(self, resp, detected_wafs: set[str], matched_evidence: list[str]) -> None:
        headers_lower = {k.lower(): v.lower() for k, v in resp.headers.items()}
        server_val = headers_lower.get("server", "")
        cookies_val = resp.headers.get("set-cookie", "").lower()
        body_snippet = (resp.text[:4000] if resp.text else "").lower()

        for waf_name, sigs in CDN_WAF_SIGNATURES.items():
            # Check headers
            for h in sigs["headers"]:
                if h in headers_lower:
                    detected_wafs.add(waf_name)
                    matched_evidence.append(f"Header '{h}: {headers_lower[h]}'")

            # Check server header
            for s in sigs["server"]:
                if s in server_val:
                    detected_wafs.add(waf_name)
                    matched_evidence.append(f"Server: {resp.headers.get('server')}")

            # Check cookies
            for c in sigs["cookies"]:
                if c in cookies_val:
                    detected_wafs.add(waf_name)
                    matched_evidence.append(f"Cookie signature '{c}'")

            # Check body
            for b in sigs["body"]:
                if b in body_snippet:
                    detected_wafs.add(waf_name)
                    matched_evidence.append(f"Response body signature '{b}'")