"""Unit tests for Bug 5: Correlation Rule 3 (dangling subdomain + mail trust) inverted condition."""
import pytest
from unittest.mock import MagicMock

from veylance.core.findings import Finding, Severity
from veylance.core.target import Target
from veylance.modules.combined_risk_scenarios import CombinedRiskScenariosModule


@pytest.mark.asyncio
async def test_rule_3_does_not_fire_when_spf_missing():
    """Bug 5: Rule 3 must NOT fire when SPF is missing (premise is active mail trust increases risk)."""
    target = Target("https://app.test")
    ctx = {
        "info": {},
        "findings": [
            Finding(
                code="SUBDOMAIN_TAKEOVER_CANDIDATE",
                severity=Severity.CRITICAL,
                title="Dangling subdomain takeover",
                url="blog.app.test",
                detail="",
            ),
            Finding(
                code="SPF_RECORD_MISSING",
                severity=Severity.MEDIUM,
                title="SPF record missing",
                module="dns_recon",
                detail="No SPF record found",
            ),
            Finding(
                code="DMARC_RECORD_MISSING",
                severity=Severity.MEDIUM,
                title="DMARC record missing",
                module="dns_recon",
                detail="No DMARC record found",
            ),
        ],
    }
    mod = CombinedRiskScenariosModule(target, MagicMock(), ctx)
    results = await mod.run()

    # Rule 3 MUST NOT trigger because mail setup is absent
    rule3_finding = next((r for r in results if "RULE_03_DANGLING_SUBDOMAIN_PHISHING" in r.evidence), None)
    assert rule3_finding is None, "Rule 3 incorrectly triggered on missing SPF/DMARC findings"


@pytest.mark.asyncio
async def test_rule_3_fires_when_spf_and_dmarc_present():
    """Bug 5: Rule 3 MUST fire when SPF and DMARC are positively present and active."""
    target = Target("https://app.test")
    ctx = {
        "info": {
            "spf_record": "v=spf1 include:_spf.google.com ~all",
            "dmarc_record": "v=DMARC1; p=reject",
        },
        "findings": [
            Finding(
                code="SUBDOMAIN_TAKEOVER_CANDIDATE",
                severity=Severity.CRITICAL,
                title="Dangling subdomain takeover",
                url="mail.app.test",
                detail="",
            ),
            Finding(
                code="SPF_RECORD_PRESENT",
                severity=Severity.INFO,
                title="SPF record configured",
                module="dns_recon",
                detail="v=spf1 include:_spf.google.com ~all",
            ),
            Finding(
                code="DMARC_RECORD_PRESENT",
                severity=Severity.INFO,
                title="DMARC record configured",
                module="dns_recon",
                detail="v=DMARC1; p=reject",
            ),
        ],
    }
    mod = CombinedRiskScenariosModule(target, MagicMock(), ctx)
    results = await mod.run()

    rule3_finding = next((r for r in results if "RULE_03_DANGLING_SUBDOMAIN_PHISHING" in r.evidence), None)
    assert rule3_finding is not None
    assert rule3_finding.severity == Severity.CRITICAL
