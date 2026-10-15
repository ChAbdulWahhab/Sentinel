"""Unit tests for WAF / CDN awareness (Cloudflare, etc.) and proxy filtering."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock
import pytest
import httpx

from veylance.core.target import Target
from veylance.modules.error_leak import ErrorLeakModule
from veylance.modules.open_redirect import OpenRedirectModule
from veylance.modules.waf_detect import WafDetectModule


class MockResponse:
    def __init__(self, status_code=200, headers=None, text=""):
        self.status_code = status_code
        self.headers = httpx.Headers(headers or {})
        self.text = text


@pytest.mark.asyncio
async def test_cloudflare_detection_and_explicit_advisory():
    target = Target("https://example.com")
    session = MagicMock()
    # Cloudflare response headers and cookies
    session.get = AsyncMock(return_value=MockResponse(
        status_code=200,
        headers={
            "server": "cloudflare",
            "cf-ray": "8d394b29381c818b-LHR",
            "set-cookie": "__cf_bm=randomtoken123; path=/; domain=.example.com; HttpOnly; Secure"
        },
        text="<html>Cloudflare ray id: 8d394b29381c818b</html>"
    ))

    ctx = {}
    mod = WafDetectModule(target, session, ctx)
    findings = await mod.run()

    # Verify context info
    assert ctx["info"].get("cloudflare_detected") is True
    assert "Cloudflare" in ctx["info"].get("WAF / CDN", "")

    # Verify explicit user advisory text
    cf_findings = [f for f in findings if "Cloudflare" in f.title]
    assert len(cf_findings) == 1
    f = cf_findings[0]
    expected_advisory = (
        "Target is behind Cloudflare — results reflect the edge/proxy, not necessarily the origin server; "
        "some modules (e.g., header/tech fingerprinting) may show Cloudflare’s values instead of the origin’s."
    )
    assert expected_advisory in f.detail
    assert "cf-ray" in f.evidence or "cloudflare" in f.evidence.lower()


@pytest.mark.asyncio
async def test_other_cdns_detection():
    target = Target("https://example.com")
    session = MagicMock()
    # AWS CloudFront response headers
    session.get = AsyncMock(return_value=MockResponse(
        status_code=200,
        headers={
            "x-amz-cf-id": "abcdef123456==",
            "server": "CloudFront"
        }
    ))

    ctx = {}
    mod = WafDetectModule(target, session, ctx)
    findings = await mod.run()

    assert "AWS CloudFront" in ctx["info"].get("WAF / CDN", "")
    assert any("CloudFront" in f.title for f in findings)


@pytest.mark.asyncio
async def test_open_redirect_waf_filtering():
    target = Target("https://example.com")
    session = MagicMock()

    # Cloudflare challenge redirect should NOT trigger open redirect finding
    session.get = AsyncMock(return_value=MockResponse(
        status_code=302,
        headers={
            "location": "/cdn-cgi/challenge-platform/h/b/scripts/cf-browser-verification",
            "cf-ray": "123456"
        }
    ))

    mod = OpenRedirectModule(target, session, {"pages": {"https://example.com/login": (200, "text/html")}})
    findings = await mod.run()
    assert len(findings) == 0


@pytest.mark.asyncio
async def test_error_leak_cloudflare_error_filtering():
    target = Target("https://example.com")
    session = MagicMock()

    # Cloudflare 521 Web server is down page should NOT be flagged as internal source leak
    session.get = AsyncMock(return_value=MockResponse(
        status_code=521,
        headers={"server": "cloudflare"},
        text="<html><title>Error 521: Web server is down</title>Cloudflare Ray ID: 8d394b29381c818b</html>"
    ))

    mod = ErrorLeakModule(target, session, {})
    findings = await mod.run()
    assert len(findings) == 0
