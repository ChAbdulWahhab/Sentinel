"""Unit tests for deepened module checks: TLS, CSP, Cookies, JWT, Rate Limiting, CVE matching, CORS."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import httpx

from veylance.core.findings import Severity
from veylance.core.target import Target
from veylance.modules.cookies import CookiesModule
from veylance.modules.cors import CorsModule
from veylance.modules.csp_analyzer import CspAnalyzerModule
from veylance.modules.headers import HeadersModule
from veylance.modules.jwt_probe import JwtProbeModule
from veylance.modules.rate_limit import RateLimitModule
from veylance.modules.tech_fingerprint import TechFingerprintModule
from veylance.modules.tls_https import TlsHttpsModule
from veylance.utils.cve import match_cves


class MockResponse:
    def __init__(self, status_code=200, headers=None, text=""):
        self.status_code = status_code
        self.headers = httpx.Headers(headers or {})
        self.text = text


# ----------------------------------------------------------------------
# 1. TLS / HTTPS & HSTS Preload Tests
# ----------------------------------------------------------------------
@pytest.mark.asyncio
async def test_tls_https_hsts_preload_deficiencies():
    target = Target("https://example.com")
    session = MagicMock()
    # HSTS with short max-age and missing preload
    session.get = AsyncMock(return_value=MockResponse(
        status_code=200,
        headers={"Strict-Transport-Security": "max-age=86400; includeSubDomains"}
    ))

    mod = TlsHttpsModule(target, session, {})
    with patch.object(mod, "_inspect_tls"):
        findings = await mod.run()

    preload_findings = [f for f in findings if "preload" in f.title.lower()]
    assert len(preload_findings) == 1
    f = preload_findings[0]
    assert f.severity == Severity.LOW
    assert "missing 'preload'" in f.detail
    assert "Strict-Transport-Security" in f.evidence
    assert f.fix != ""


@pytest.mark.asyncio
async def test_tls_https_weak_cipher_and_downgrade():
    target = Target("https://example.com")
    session = MagicMock()
    session.get = AsyncMock(return_value=MockResponse(status_code=200))

    mod = TlsHttpsModule(target, session, {})
    # Simulate weak cipher finding
    mod.add(
        severity=Severity.MEDIUM,
        title="Weak cipher suite in use: TLS_RSA_WITH_3DES_EDE_CBC_SHA",
        detail="Cipher utilizes 3DES CBC.",
        fix="Configure AEAD ciphers only.",
        url=target.base,
        evidence="Cipher: TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    )
    assert any("3DES" in f.evidence for f in mod.findings)


# ----------------------------------------------------------------------
# 2. Security Headers & CSP Conflict Tests
# ----------------------------------------------------------------------
@pytest.mark.asyncio
async def test_headers_xfo_csp_conflict_and_permissions_policy():
    target = Target("https://example.com")
    session = MagicMock()
    # X-Frame-Options is DENY, but CSP allows frame-ancestors 'self'
    session.get = AsyncMock(return_value=MockResponse(
        status_code=200,
        headers={
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": "default-src 'self'; frame-ancestors 'self' https://trusted.com",
            # Missing Permissions-Policy
        }
    ))

    mod = HeadersModule(target, session, {})
    findings = await mod.run()

    conflict_findings = [f for f in findings if "conflict" in f.title.lower()]
    assert len(conflict_findings) == 1
    assert "DENY" in conflict_findings[0].evidence

    missing_perm = [f for f in findings if "Permissions-Policy" in f.title]
    assert len(missing_perm) == 1
    assert missing_perm[0].fix != ""


# ----------------------------------------------------------------------
# 3. CSP Analyzer Dangerous Token Tests
# ----------------------------------------------------------------------
@pytest.mark.asyncio
async def test_csp_analyzer_unsafe_and_wildcards():
    target = Target("https://example.com")
    session = MagicMock()
    session.get = AsyncMock(return_value=MockResponse(
        status_code=200,
        headers={
            "Content-Security-Policy": "default-src 'self' *; script-src 'self' 'unsafe-inline' 'unsafe-eval' data:; object-src https:;"
        }
    ))

    mod = CspAnalyzerModule(target, session, {})
    findings = await mod.run()

    titles = [f.title for f in findings]
    assert any("unsafe-inline" in t for t in titles)
    assert any("unsafe-eval" in t for t in titles)
    assert any("data:" in t for t in titles)
    assert any("*" in t for t in titles)
    assert any("object-src" in t for t in titles)


# ----------------------------------------------------------------------
# 4. Cookie Prefixes, Broad Domain, and SameSite Quality Tests
# ----------------------------------------------------------------------
@pytest.mark.asyncio
async def test_cookies_prefixes_broad_domain_and_samesite():
    target = Target("https://example.com")
    session = MagicMock()
    session.get = AsyncMock(return_value=MockResponse(
        status_code=200,
        headers={
            "Set-Cookie": "session_id=abc12345; Path=/; Domain=.example.com; SameSite=None; Secure"
        }
    ))

    mod = CookiesModule(target, session, {})
    findings = await mod.run()

    titles = [f.title for f in findings]
    # Check for missing HttpOnly
    assert any("missing security flags" in t for t in titles)
    # Check for broad domain warning
    assert any("broad Domain attribute" in t for t in titles)
    # Check for SameSite=None on sensitive session cookie
    assert any("SameSite=None" in t for t in titles)
    # Check for __Host- prefix recommendation
    assert any("__Host-" in t for t in titles)


# ----------------------------------------------------------------------
# 5. JWT Probe: alg: none, Weak HMAC Secret, Missing Claims
# ----------------------------------------------------------------------
@pytest.mark.asyncio
async def test_jwt_probe_alg_none_and_weak_secret():
    target = Target("https://example.com")
    session = MagicMock()

    # Generate a JWT with secret "secret" and missing exp/iat
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"sub": "1234567890", "name": "Admin User", "admin": True}
    h_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
    p_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    signing_input = f"{h_b64}.{p_b64}".encode()
    sig = hmac.new(b"secret", signing_input, hashlib.sha256).digest()
    sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
    valid_weak_jwt = f"{h_b64}.{p_b64}.{sig_b64}"

    # Also an alg: none token
    h_none_b64 = base64.urlsafe_b64encode(json.dumps({"alg": "none"}).encode()).rstrip(b"=").decode()
    none_jwt = f"{h_none_b64}.{p_b64}."

    session.get = AsyncMock(return_value=MockResponse(
        status_code=200,
        text=f"window.__TOKEN__ = '{valid_weak_jwt}'; window.__GUEST__ = '{none_jwt}';"
    ))

    mod = JwtProbeModule(target, session, {"scripts": {"https://example.com/app.js"}, "pages": {}})
    findings = await mod.run()

    titles = [f.title for f in findings]
    assert any("alg: none" in t for t in titles)
    assert any("weak HMAC secret" in t and "'secret'" in t for t in titles)
    assert any("missing 'exp'" in t for t in titles)
    assert any("missing 'iat'" in t for t in titles)


# ----------------------------------------------------------------------
# 6. Rate Limiting Tests (Threshold Identification & Window Behavior)
# ----------------------------------------------------------------------
@pytest.mark.asyncio
async def test_rate_limit_threshold_reporting():
    target = Target("https://example.com")
    session = MagicMock()

    # Return 200 for first 5 requests, then 429 starting at #6
    call_count = 0

    async def mock_get(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count >= 6:
            return MockResponse(429, headers={
                "Retry-After": "30",
                "X-RateLimit-Limit": "5",
                "X-RateLimit-Remaining": "0"
            })
        return MockResponse(200, headers={
            "X-RateLimit-Limit": "5",
            "X-RateLimit-Remaining": str(5 - call_count)
        })

    session.get = AsyncMock(side_effect=mock_get)
    ctx = {"rate_requests": 10}
    mod = RateLimitModule(target, session, ctx)
    findings = await mod.run()

    threshold_finding = [f for f in findings if "threshold identified" in f.title]
    assert len(threshold_finding) == 1
    f = threshold_finding[0]
    assert "request #6" in f.evidence
    assert "Retry-After: 30" in f.evidence


# ----------------------------------------------------------------------
# 7. Tech Fingerprint CVE Version Matching Tests
# ----------------------------------------------------------------------
def test_tech_fingerprint_cve_matching():
    # Apache 2.4.49 -> CVE-2021-41773
    apache_findings = match_cves("apache", "2.4.49", "https://example.com")
    assert len(apache_findings) >= 1
    assert any("CVE-2021-41773" in f.title for f in apache_findings)

    # Nginx 1.18.0 -> CVE-2021-23017
    nginx_findings = match_cves("nginx", "1.18.0", "https://example.com")
    assert len(nginx_findings) >= 1
    assert any("CVE-2021-23017" in f.title for f in nginx_findings)

    # Clean / patched version should return no findings
    clean_findings = match_cves("apache", "2.4.58", "https://example.com")
    assert len(clean_findings) == 0


# ----------------------------------------------------------------------
# 8. CORS Reflected Origin, Wildcard + Credentials, and Null Origin
# ----------------------------------------------------------------------
@pytest.mark.asyncio
async def test_cors_reflection_and_null_origin():
    target = Target("https://example.com")
    session = MagicMock()

    async def mock_get(url, headers=None, **kwargs):
        origin = (headers or {}).get("Origin")
        if origin == "https://evil.example.com":
            return MockResponse(200, headers={
                "Access-Control-Allow-Origin": "https://evil.example.com",
                "Access-Control-Allow-Credentials": "true"
            })
        elif origin == "null":
            return MockResponse(200, headers={
                "Access-Control-Allow-Origin": "null",
                "Access-Control-Allow-Credentials": "false"
            })
        return MockResponse(200)

    session.get = AsyncMock(side_effect=mock_get)
    mod = CorsModule(target, session, {})
    findings = await mod.run()

    titles = [f.title for f in findings]
    assert any("arbitrary Origin reflection with credentials" in t for t in titles)
    assert any("'null' origin" in t for t in titles)
