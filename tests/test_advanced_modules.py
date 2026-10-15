"""Tests for Part 2 Advanced / Hidden Exposure detection modules and reporting."""
from __future__ import annotations

import httpx
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from veylance.core.findings import Finding, ScanResult, Severity
from veylance.core.target import Target
from veylance.modules.cache_poisoning_headers import CachePoisoningHeadersModule
from veylance.modules.cert_transparency_recon import CertTransparencyReconModule
from veylance.modules.ci_cd_exposure import CiCdExposureModule
from veylance.modules.comment_leak import CommentLeakModule
from veylance.modules.dependency_exposure import DependencyExposureModule
from veylance.modules.git_exposure import GitExposureModule
from veylance.modules.secrets_in_js import SecretsInJsModule, mask_secret
from veylance.modules.source_map_exposure import SourceMapExposureModule
from veylance.modules.sri_check import SriCheckModule
from veylance.modules.subdomain_takeover import SubdomainTakeoverModule
from veylance.report.html_report import HtmlReporter
from veylance.report.json_report import JsonReporter
from veylance.report.markdown import MarkdownReporter
from veylance.ui.tables import render_findings


class MockResponse:
    def __init__(self, content: bytes | str = b"", status_code: int = 200, headers: dict | None = None):
        if isinstance(content, str):
            self.content = content.encode("utf-8")
            self.text = content
        else:
            self.content = content
            self.text = content.decode("utf-8", errors="replace")
        self.status_code = status_code
        self.headers = httpx.Headers(headers or {})


# ---------------------------------------------------------------------------
# 1. secrets_in_js
# ---------------------------------------------------------------------------
def test_mask_secret_helper():
    assert mask_secret("AKIAIOSFODNN7EXAMPLE") == "AKIA************MPLE"
    assert "EXAMPLE" not in mask_secret("sk_live_1234567890abcdefghijklmnopqrstuv")
    assert mask_secret("short") == "sh****rt"
    assert mask_secret("-----BEGIN RSA PRIVATE KEY-----") == "-----BEGIN [REDACTED PRIVATE KEY]-----"
    assert mask_secret("postgres://user:supersecretpass@db.local:5432/prod") == "postgres://****:****@db.local:5432/prod"


@pytest.mark.asyncio
async def test_secrets_in_js_detection_and_masking():
    target = Target("https://example.com")
    ctx = {"scripts": {"https://example.com/assets/app.js"}}

    raw_aws = "AKIA1234567890ABCDEF"
    raw_stripe = "sk_live_9876543210abcdefghijklmnop"
    js_content = f"""
    const config = {{
        awsKey: "{raw_aws}",
        stripeKey: "{raw_stripe}",
        dbUri: "mongodb+srv://admin:mysecretpassword@cluster0.mongodb.net/test"
    }};
    """

    session = MagicMock()
    session.get = AsyncMock(return_value=MockResponse(js_content, 200))

    mod = SecretsInJsModule(target, session, ctx)
    findings = await mod.run()

    assert len(findings) >= 2
    for f in findings:
        assert raw_aws not in f.evidence
        assert raw_stripe not in f.evidence
        assert "mysecretpassword" not in f.evidence
        assert "****" in f.evidence
        assert f.severity in (Severity.CRITICAL, Severity.HIGH)


# ---------------------------------------------------------------------------
# 2. source_map_exposure
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_source_map_exposure():
    target = Target("https://example.com")
    ctx = {"scripts": {"https://example.com/bundle.js"}}

    map_json = '{"version": 3, "file": "bundle.js", "sources": ["src/index.ts", "src/auth.ts"], "mappings": "AAAA"}'

    async def mock_get(url, **kwargs):
        if url.endswith(".map"):
            return MockResponse(map_json, 200, {"content-type": "application/json"})
        return MockResponse("console.log('test');\n//# sourceMappingURL=bundle.js.map", 200)

    session = MagicMock()
    session.get = AsyncMock(side_effect=mock_get)

    mod = SourceMapExposureModule(target, session, ctx)
    findings = await mod.run()

    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert "source map" in findings[0].title.lower()
    assert "src/index.ts" in findings[0].evidence


# ---------------------------------------------------------------------------
# 3. git_exposure
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_git_exposure_detection():
    target = Target("https://example.com")
    ctx = {}

    async def mock_get(url, **kwargs):
        if url.endswith("/.git/HEAD"):
            return MockResponse("ref: refs/heads/main\n", 200)
        if url.endswith("/.git/config"):
            return MockResponse("[core]\n\trepositoryformatversion = 0\n", 200)
        return MockResponse("404 Not Found", 404)

    session = MagicMock()
    session.get = AsyncMock(side_effect=mock_get)

    mod = GitExposureModule(target, session, ctx)
    findings = await mod.run()

    assert len(findings) >= 1
    git_finding = findings[0]
    assert git_finding.severity == Severity.CRITICAL
    assert "BLAST RADIUS" in git_finding.detail
    assert "refs/heads/main" in git_finding.evidence


# ---------------------------------------------------------------------------
# 4. subdomain_takeover
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_subdomain_takeover():
    target = Target("https://example.com")
    ctx = {"discovered_subdomains": {"blog.example.com"}}

    session = MagicMock()
    session.get = AsyncMock(return_value=MockResponse(
        "<html><head><title>404</title></head><body>There isn't a GitHub Pages site here.</body></html>",
        404
    ))

    mod = SubdomainTakeoverModule(target, session, ctx)
    with patch.object(mod, "_resolve_cname", AsyncMock(side_effect=lambda h, loop: "myuser.github.io" if h == "blog.example.com" else None)):
        findings = await mod.run()

    assert len(findings) == 1
    f = findings[0]
    assert f.severity == Severity.CRITICAL
    assert "GitHub Pages" in f.title
    assert "myuser.github.io" in f.evidence


# ---------------------------------------------------------------------------
# 5. dependency_exposure
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_dependency_exposure():
    target = Target("https://example.com")
    ctx = {}

    pkg_json = '{"name": "internal-app", "dependencies": {"express": "4.18.2", "lodash": "4.17.21"}}'
    npmrc_content = "registry=https://registry.npmjs.org/\n//registry.npmjs.org/:_authToken=npm_secrettoken123456789\n"

    async def mock_get(url, **kwargs):
        if url.endswith("/package.json"):
            return MockResponse(pkg_json, 200, {"content-type": "application/json"})
        if url.endswith("/.npmrc"):
            return MockResponse(npmrc_content, 200, {"content-type": "text/plain"})
        return MockResponse("404 Not Found", 404)

    session = MagicMock()
    session.get = AsyncMock(side_effect=mock_get)

    mod = DependencyExposureModule(target, session, ctx)
    findings = await mod.run()

    assert len(findings) == 2
    npmrc_f = next(f for f in findings if "/.npmrc" in f.title)
    assert npmrc_f.severity == Severity.CRITICAL
    assert "npm_secrettoken123456789" not in npmrc_f.evidence
    assert "****MASKED****" in npmrc_f.evidence


# ---------------------------------------------------------------------------
# 6. ci_cd_exposure
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_ci_cd_exposure():
    target = Target("https://example.com")
    ctx = {}

    env_text = "DB_PASSWORD=SuperSecretDatabasePass1234\nAWS_SECRET=sk_live_myawssecretkey999\nNODE_ENV=production\n"
    workflow_text = "name: Deploy to Production\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n"

    async def mock_get(url, **kwargs):
        if url.endswith("/.env"):
            return MockResponse(env_text, 200, {"content-type": "text/plain"})
        if url.endswith("/.github/workflows/deploy.yml"):
            return MockResponse(workflow_text, 200, {"content-type": "text/yaml"})
        return MockResponse("404 Not Found", 404)

    session = MagicMock()
    session.get = AsyncMock(side_effect=mock_get)

    mod = CiCdExposureModule(target, session, ctx)
    findings = await mod.run()

    assert len(findings) == 2
    env_f = next(f for f in findings if "/.env" in f.title)
    assert env_f.severity == Severity.CRITICAL
    assert "SuperSecretDatabasePass1234" not in env_f.evidence
    assert "****" in env_f.evidence


# ---------------------------------------------------------------------------
# 7. sri_check
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_sri_check():
    target = Target("https://example.com")
    ctx = {"pages": {"https://example.com/": (200, "text/html")}}

    html = """
    <!doctype html>
    <html>
    <head>
      <!-- Third party script without SRI -->
      <script src="https://cdnjs.cloudflare.com/ajax/libs/lodash.js/4.17.21/lodash.min.js"></script>
      <!-- Third party script with SRI (valid) -->
      <script src="https://code.jquery.com/jquery-3.6.0.min.js" integrity="sha256-/xUj+3OJU5yExlq6GSYGSHk7tPXikynS7ogEvDej/m4=" crossorigin="anonymous"></script>
    </head>
    <body><h1>Hello</h1></body>
    </html>
    """

    session = MagicMock()
    session.get = AsyncMock(return_value=MockResponse(html, 200))

    mod = SriCheckModule(target, session, ctx)
    findings = await mod.run()

    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM
    assert "cdnjs.cloudflare.com" in findings[0].title
    assert "lodash.min.js" in findings[0].url


# ---------------------------------------------------------------------------
# 8. comment_leak
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_comment_leak():
    target = Target("https://example.com")
    ctx = {"pages": {"https://example.com/": (200, "text/html")}}

    html = """
    <html>
      <!-- TODO: remove auth bypass before prod release -->
      <!-- temp admin pass: SuperSecretPass999 -->
      <script>
        // Internal test API: http://10.0.1.25:8080/v1/auth
      </script>
    </html>
    """

    session = MagicMock()
    session.get = AsyncMock(return_value=MockResponse(html, 200))

    mod = CommentLeakModule(target, session, ctx)
    findings = await mod.run()

    assert len(findings) >= 2
    auth_bypass = next(f for f in findings if "Auth Bypass" in f.title)
    assert auth_bypass.severity == Severity.HIGH
    assert "SuperSecretPass999" not in auth_bypass.evidence


# ---------------------------------------------------------------------------
# 9. cert_transparency_recon
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_cert_transparency_recon():
    target = Target("https://myapp.example.com")
    ctx = {}

    crt_data = '[{"name_value": "staging.example.com\\nvpn.example.com"}, {"name_value": "admin.example.com"}]'

    session = MagicMock()
    session.get = AsyncMock(return_value=MockResponse(crt_data, 200, {"content-type": "application/json"}))

    mod = CertTransparencyReconModule(target, session, ctx)
    findings = await mod.run()

    assert len(findings) == 1
    assert "staging.example.com" in ctx["discovered_subdomains"]
    assert "vpn.example.com" in ctx["discovered_subdomains"]
    assert findings[0].severity in (Severity.LOW, Severity.INFO)


# ---------------------------------------------------------------------------
# 10. cache_poisoning_headers
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_cache_poisoning_headers():
    target = Target("https://example.com")
    ctx = {}

    reflected_body = """
    <html>
    <head><script src="//veylance-cache-canary.internal/main.js"></script></head>
    </html>
    """

    session = MagicMock()
    session.get = AsyncMock(return_value=MockResponse(
        reflected_body,
        200,
        {"Cache-Control": "public, max-age=3600", "X-Cache": "HIT"}
    ))

    mod = CachePoisoningHeadersModule(target, session, ctx)
    findings = await mod.run()

    assert len(findings) == 1
    assert "Cache Poisoning" in findings[0].title
    assert "veylance-cache-canary.internal" in findings[0].evidence
    assert findings[0].severity in (Severity.HIGH, Severity.MEDIUM)


# ---------------------------------------------------------------------------
# 11. Part 3 Reporting Tests (Markdown, HTML, JSON, Console UI)
# ---------------------------------------------------------------------------
def test_reporting_advanced_grouping():
    from datetime import datetime

    f_std = Finding(
        severity=Severity.MEDIUM,
        title="Missing X-Frame-Options",
        detail="Clickjacking header missing.",
        module="headers",
        url="https://example.com",
    )
    f_adv = Finding(
        severity=Severity.CRITICAL,
        title="Git repository exposure: /.git/HEAD",
        detail="Commit tree accessible.",
        module="git_exposure",
        url="https://example.com/.git/HEAD",
        evidence="ref: refs/heads/main",
    )

    result = ScanResult(
        target="https://example.com",
        timestamp=datetime.now(),
        findings=[f_std, f_adv],
        pages={"https://example.com": (200, "text/html")},
        tech={"Nginx"},
        info={},
        forms=[],
        scripts=set(),
        js_endpoints=set(),
        duration=1.5,
        modules_run=["headers", "git_exposure"],
    )

    # 1. Markdown Report
    md = MarkdownReporter().render(result)
    assert "## Standard Security Findings" in md
    assert "## Advanced / Hidden Exposure" in md
    assert "prevents full source code and history leaks" in md

    # 2. HTML Report
    html = HtmlReporter().render(result)
    assert "Standard Security Findings" in html
    assert "Advanced / Hidden Exposure" in html
    assert "git_exposure" in html

    # 3. JSON Report
    json_str = JsonReporter().render(result)
    assert "advanced_modules" in json_str
    assert "git_exposure" in json_str
    assert "spa_catchall_suppressed" in json_str

    # 4. Console UI table render
    from rich.console import Console
    c = Console(record=True, width=120)
    render_findings(c, result, show_details=True)
    out = c.export_text()
    assert "Standard Findings" in out
    assert "Advanced / Hidden Exposure" in out
