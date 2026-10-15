"""Regression tests for Bug 2: cert_transparency_recon query scope on multi-level hosting domains."""
import pytest
from unittest.mock import AsyncMock, MagicMock

from veylance.core.target import Target
from veylance.modules.cert_transparency_recon import (
    CertTransparencyReconModule,
    get_ct_query_target,
)


@pytest.mark.parametrize(
    "hostname,expected_query_target",
    [
        ("dealsafe.pages.dev", "dealsafe.pages.dev"),
        ("sub.dealsafe.pages.dev", "dealsafe.pages.dev"),
        ("decorum.pythonanywhere.com", "decorum.pythonanywhere.com"),
        ("sub.decorum.pythonanywhere.com", "decorum.pythonanywhere.com"),
        ("my-app.vercel.app", "my-app.vercel.app"),
        ("api.my-app.vercel.app", "my-app.vercel.app"),
        ("chabdulwahhab.github.io", "chabdulwahhab.github.io"),
        ("production.herokuapp.com", "production.herokuapp.com"),
        ("example.co.uk", "example.co.uk"),
        ("sub.example.co.uk", "example.co.uk"),
        ("app.example.com", "example.com"),
        ("example.com", "example.com"),
    ],
)
def test_get_ct_query_target_multilevel_domains(hostname: str, expected_query_target: str):
    """Assert query target uses the full registered tenant hostname on multi-level hosting domains."""
    actual = get_ct_query_target(hostname)
    assert actual == expected_query_target, f"Expected {expected_query_target} for {hostname}, got {actual}"


@pytest.mark.asyncio
async def test_cert_transparency_recon_queries_exact_tenant_scope():
    """Verify crt.sh query URL uses %.dealsafe.pages.dev, NOT %.pages.dev."""
    target = Target("https://dealsafe.pages.dev")
    ctx = {}
    session = MagicMock()
    mock_get = AsyncMock(return_value=MagicMock(status_code=200, text="[]"))
    session.get = mock_get

    mod = CertTransparencyReconModule(target, session, ctx)
    await mod.run()

    assert mock_get.called
    called_url = mock_get.call_args[0][0]
    assert "q=%.dealsafe.pages.dev" in called_url
    assert "q=%.pages.dev" not in called_url
