"""Unit tests for Bug 4: Stable finding codes in correlation rule evaluators."""
import pytest
from unittest.mock import MagicMock

from veylance.core.findings import Finding, Severity
from veylance.core.target import Target
from veylance.modules.combined_risk_scenarios import CombinedRiskScenariosModule


@pytest.mark.asyncio
async def test_rule_1_fires_by_finding_code():
    """Rule 1 (CORS wildcard + no rate limit) must fire using stable codes, regardless of arbitrary title changes."""
    target = Target("https://app.test")
    ctx = {
        "findings": [
            Finding(
                code="CORS_WILDCARD",
                severity=Severity.LOW,
                title="Completely Renamed Custom Title: CORS Permissive Setting",
                detail="Wildcard allowed",
                url="https://app.test/api/admin/users",
            ),
            Finding(
                code="RATE_LIMIT_NOT_DETECTED",
                severity=Severity.MEDIUM,
                title="Rate limiting not detected on target",
                detail="No throttling headers found",
                url="https://app.test",
            ),
        ]
    }
    mod = CombinedRiskScenariosModule(target, MagicMock(), ctx)
    results = await mod.run()

    rule1_finding = next((r for r in results if "RULE_01_CORS_ADMIN_NO_RATE_LIMIT" in r.evidence), None)
    assert rule1_finding is not None
    assert rule1_finding.severity == Severity.CRITICAL


@pytest.mark.asyncio
async def test_rule_2_fires_by_finding_code():
    """Rule 2 (XSS + CSP missing + CSRF missing) fires using stable finding codes."""
    target = Target("https://app.test")
    ctx = {
        "findings": [
            Finding(
                code="XSS_REFLECTION",
                severity=Severity.HIGH,
                title="Arbitrary wording reflection",
                detail="",
            ),
            Finding(
                code="CSP_MISSING",
                severity=Severity.HIGH,
                title="Content Security Policy absent",
                detail="",
            ),
            Finding(
                code="CSRF_TOKEN_MISSING",
                severity=Severity.MEDIUM,
                title="Anti-forgery token not verified",
                detail="",
            ),
        ]
    }
    mod = CombinedRiskScenariosModule(target, MagicMock(), ctx)
    results = await mod.run()

    rule2_finding = next((r for r in results if "RULE_02_XSS_NO_CSP_NO_CSRF" in r.evidence), None)
    assert rule2_finding is not None
    assert rule2_finding.severity == Severity.HIGH


@pytest.mark.asyncio
async def test_rule_3_fires_by_finding_code():
    """Rule 3 fires with SUBDOMAIN_TAKEOVER_CANDIDATE and SPF_RECORD_PRESENT codes."""
    target = Target("https://app.test")
    ctx = {
        "findings": [
            Finding(
                code="SUBDOMAIN_TAKEOVER_CANDIDATE",
                severity=Severity.CRITICAL,
                title="Dangling pointer",
                detail="",
                url="sub.app.test",
            ),
            Finding(
                code="SPF_RECORD_PRESENT",
                severity=Severity.INFO,
                title="SPF configured",
                detail="",
            ),
        ]
    }
    mod = CombinedRiskScenariosModule(target, MagicMock(), ctx)
    results = await mod.run()

    rule3_finding = next((r for r in results if "RULE_03_DANGLING_SUBDOMAIN_PHISHING" in r.evidence), None)
    assert rule3_finding is not None
    assert rule3_finding.severity == Severity.CRITICAL


@pytest.mark.asyncio
async def test_rule_4_fires_by_finding_code():
    """Rule 4 (Git + Secret) fires with GIT_EXPOSURE and SECRET_IN_JS codes."""
    target = Target("https://app.test")
    ctx = {
        "findings": [
            Finding(
                code="GIT_EXPOSURE",
                severity=Severity.CRITICAL,
                title="Arbitrary wording git finding",
                detail="",
            ),
            Finding(
                code="SECRET_IN_JS",
                severity=Severity.HIGH,
                title="Arbitrary wording secret finding",
                detail="",
            ),
        ]
    }
    mod = CombinedRiskScenariosModule(target, MagicMock(), ctx)
    results = await mod.run()

    rule4_finding = next((r for r in results if "RULE_04_GIT_HISTORY_WITH_SECRETS" in r.evidence), None)
    assert rule4_finding is not None
    assert rule4_finding.severity == Severity.CRITICAL


@pytest.mark.asyncio
async def test_rule_5_fires_by_finding_code():
    """Rule 5 (Sourcemap + Comment) fires with SOURCE_MAP_EXPOSURE and COMMENT_LEAK codes."""
    target = Target("https://app.test")
    ctx = {
        "findings": [
            Finding(
                code="SOURCE_MAP_EXPOSURE",
                severity=Severity.HIGH,
                title="Arbitrary map finding",
                detail="",
            ),
            Finding(
                code="COMMENT_LEAK",
                severity=Severity.LOW,
                title="Arbitrary comment finding",
                detail="",
            ),
        ]
    }
    mod = CombinedRiskScenariosModule(target, MagicMock(), ctx)
    results = await mod.run()

    rule5_finding = next((r for r in results if "RULE_05_SOURCEMAP_LEAK_AMPLIFICATION" in r.evidence), None)
    assert rule5_finding is not None
    assert rule5_finding.severity == Severity.HIGH
