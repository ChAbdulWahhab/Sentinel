"""Regression tests for SPA catch-all false positives and baseline diffing."""
from __future__ import annotations

import httpx
import pytest
from unittest.mock import AsyncMock, MagicMock

from veylance.core.findings import Severity
from veylance.core.target import Target
from veylance.modules.directory_list import DirectoryListModule
from veylance.modules.error_leak import ErrorLeakModule
from veylance.modules.exposed_files import ExposedFilesModule
from veylance.modules.sensitive_paths import SensitivePathsModule


class MockSpaResponse:
    def __init__(self, content: bytes, status_code: int = 200, headers: dict | None = None):
        self.status_code = status_code
        self.content = content
        self.text = content.decode("utf-8", errors="replace")
        self.headers = httpx.Headers(headers or {"content-type": "text/html; charset=utf-8"})


SPA_HTML = b"<!doctype html><html><head><title>My SPA</title></head><body><div id='app'>React App</div><script src='/main.js'></script></body></html>"


@pytest.mark.asyncio
async def test_spa_catch_all_zero_false_criticals():
    """Ensure mock SPA returning 200 + HTML for every path yields ZERO CRITICAL findings."""
    target = Target("https://spa-mock.example.com")
    ctx = {}

    session = MagicMock()
    # Mock server always returns 200 with the exact same SPA HTML for any URL
    session.get = AsyncMock(return_value=MockSpaResponse(SPA_HTML, 200))

    # Test SensitivePathsModule
    sp_mod = SensitivePathsModule(target, session, ctx)
    sp_findings = await sp_mod.run()
    critical_sp = [f for f in sp_findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
    assert len(critical_sp) == 0, f"Expected 0 CRITICAL/HIGH findings in sensitive_paths, got: {critical_sp}"
    # Collapsed into single summary INFO finding
    assert len(sp_findings) == 1
    assert "SPA catch-all suppressed" in sp_findings[0].title

    # Test ExposedFilesModule
    ef_mod = ExposedFilesModule(target, session, ctx)
    ef_findings = await ef_mod.run()
    critical_ef = [f for f in ef_findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
    assert len(critical_ef) == 0, f"Expected 0 CRITICAL/HIGH findings in exposed_files, got: {critical_ef}"
    # Collapsed into single summary INFO finding
    assert len(ef_findings) == 1
    assert "SPA catch-all suppressed" in ef_findings[0].title

    # Verify programmatic spa_catchall_suppressed collection in ctx['info']
    suppressed = ctx.get("info", {}).get("spa_catchall_suppressed", [])
    assert len(suppressed) > 40, f"Expected captured suppressed paths in ctx, got {len(suppressed)}"

    # Test DirectoryListModule
    dl_mod = DirectoryListModule(target, session, ctx)
    dl_findings = await dl_mod.run()
    assert len(dl_findings) == 0, f"Expected 0 findings in directory_list, got: {dl_findings}"

    # Test ErrorLeakModule
    el_mod = ErrorLeakModule(target, session, ctx)
    el_findings = await el_mod.run()
    assert len(el_findings) == 0, f"Expected 0 findings in error_leak, got: {el_findings}"


@pytest.mark.asyncio
async def test_spa_catch_all_detects_authentic_exposure():
    """Ensure genuine files (e.g. PEM private key or DB credentials) are escalated despite SPA router."""
    target = Target("https://spa-mock.example.com")
    ctx = {}

    pem_content = b"-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0\n-----END RSA PRIVATE KEY-----\n"
    env_content = b"DB_PASSWORD=SuperSecretPass123!\nAPI_SECRET=sk_live_xyz\n"

    async def mock_get(url, follow_redirects=False):
        if url.endswith("/id_rsa"):
            return MockSpaResponse(pem_content, 200, {"content-type": "application/octet-stream"})
        if url.endswith("/.env"):
            return MockSpaResponse(env_content, 200, {"content-type": "text/plain"})
        # Default SPA catch-all response
        return MockSpaResponse(SPA_HTML, 200)

    session = MagicMock()
    session.get = AsyncMock(side_effect=mock_get)

    # 1. ExposedFiles should catch the authentic /id_rsa PEM key
    ef_mod = ExposedFilesModule(target, session, ctx)
    ef_findings = await ef_mod.run()
    rsa_finding = next((f for f in ef_findings if "/id_rsa" in f.title), None)
    assert rsa_finding is not None
    assert rsa_finding.severity == Severity.CRITICAL

    # 2. SensitivePaths should catch the authentic /.env
    sp_mod = SensitivePathsModule(target, session, ctx)
    sp_findings = await sp_mod.run()
    env_finding = next((f for f in sp_findings if "/.env" in f.title), None)
    assert env_finding is not None
    assert env_finding.severity == Severity.CRITICAL
