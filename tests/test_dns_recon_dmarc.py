"""Unit tests for Part 0a: DMARC finding detail must contain actual DMARC syntax, not SPF."""
import pytest
from unittest.mock import MagicMock, patch

from veylance.core.target import Target
from veylance.modules.dns_recon import DnsReconModule


class MockTxtRecord:
    def __init__(self, text: str):
        self._text = text

    def to_text(self) -> str:
        return f'"{self._text}"'


@pytest.mark.asyncio
async def test_dmarc_finding_detail_contains_dmarc_syntax():
    """Assert DMARC finding contains actual DMARC value (v=DMARC1; ...), not SPF syntax."""
    target = Target("https://example.com")
    ctx = {}
    session = MagicMock()
    mod = DnsReconModule(target, session, ctx)

    # Mock DNS resolution
    def mock_resolve(qname, rtype, lifetime=5):
        if rtype == "TXT":
            if qname == "_dmarc.example.com":
                return [MockTxtRecord("v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com")]
            elif qname == "example.com":
                return [MockTxtRecord("v=spf1 include:_spf.google.com ~all")]
        raise Exception("No record")

    with patch("dns.resolver.resolve", side_effect=mock_resolve):
        findings = await mod.run()

    dmarc_f = next((f for f in findings if (f.code or "") == "DMARC_RECORD_PRESENT"), None)
    assert dmarc_f is not None, "DMARC_RECORD_PRESENT finding was not emitted"
    assert "v=DMARC1" in dmarc_f.detail
    assert "p=quarantine" in dmarc_f.detail
    assert "v=spf1" not in dmarc_f.detail, "SPF record was mistakenly used in DMARC detail"


@pytest.mark.asyncio
async def test_dmarc_ignores_non_dmarc_txt_record():
    """Assert a TXT record under _dmarc without v=DMARC1 is treated as missing, not valid DMARC."""
    target = Target("https://decorum.pythonanywhere.com")
    ctx = {}
    session = MagicMock()
    mod = DnsReconModule(target, session, ctx)

    # pythonanywhere wildcard case where _dmarc returns v=spf1 -all
    def mock_resolve(qname, rtype, lifetime=5):
        if rtype == "TXT":
            if qname == "_dmarc.decorum.pythonanywhere.com":
                return [MockTxtRecord("v=spf1 -all")]
            elif qname == "decorum.pythonanywhere.com":
                return [MockTxtRecord("v=spf1 -all")]
        raise Exception("No record")

    with patch("dns.resolver.resolve", side_effect=mock_resolve):
        findings = await mod.run()

    present_f = next((f for f in findings if (f.code or "") == "DMARC_RECORD_PRESENT"), None)
    assert present_f is None, "Should not emit DMARC_RECORD_PRESENT for an SPF record under _dmarc"

    missing_f = next((f for f in findings if (f.code or "") == "DMARC_RECORD_MISSING"), None)
    assert missing_f is not None, "Should report DMARC missing when only non-DMARC TXT is present"
