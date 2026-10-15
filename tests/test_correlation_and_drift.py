"""Unit and integration tests for Part 3 Correlation and Temporal Drift modules."""
from __future__ import annotations

from datetime import datetime
import json
from pathlib import Path
import pytest
from unittest.mock import MagicMock

from veylance.core.findings import Finding, ScanResult, Severity
from veylance.core.target import Target
from veylance.modules.combined_risk_scenarios import CombinedRiskScenariosModule, CORRELATION_RULES
from veylance.modules.scan_drift import ScanDriftModule
from veylance.report.html_report import HtmlReporter
from veylance.report.json_report import JsonReporter
from veylance.report.markdown import MarkdownReporter
from veylance.utils.drift import (
    compute_scan_drift,
    get_target_hash,
    load_prior_fingerprint,
    save_target_fingerprint,
)


@pytest.fixture
def tmp_history(tmp_path: Path):
    hdir = tmp_path / "veylance_history"
    hdir.mkdir(parents=True, exist_ok=True)
    return hdir


# ==============================================================================
# Part 3a: Combined Risk Scenarios Correlation Rule Engine Tests
# ==============================================================================

@pytest.mark.asyncio
async def test_correlation_cors_admin_no_rate_limit():
    target = Target("https://app.example.com")
    ctx = {
        "pages": {"https://app.example.com/api/admin/users": (200, "application/json")},
        "findings": [
            Finding(
                severity=Severity.MEDIUM,
                title="CORS Wildcard Allowed on sensitive route",
                detail="Access-Control-Allow-Origin: *",
                module="cors",
                url="https://app.example.com/api/admin/users",
            ),
            Finding(
                severity=Severity.LOW,
                title="Missing rate limiting on API endpoints",
                detail="100 requests accepted without HTTP 429",
                module="rate_limit",
                url="https://app.example.com/api/admin/users",
            ),
        ],
    }
    session = MagicMock()
    mod = CombinedRiskScenariosModule(target, session, ctx)
    results = await mod.run()

    assert len(results) >= 1
    f = next(r for r in results if "RULE_01_CORS_ADMIN_NO_RATE_LIMIT" in r.evidence)
    assert f.severity == Severity.CRITICAL
    assert "Unauthenticated cross-origin access to admin endpoint with no rate limiting" in f.title or "Unauthenticated CORS" in f.title
    assert "remote attackers can enumerate/abuse this endpoint from any origin without throttling" in f.detail


@pytest.mark.asyncio
async def test_correlation_xss_no_csp_no_csrf():
    target = Target("https://app.example.com")
    ctx = {
        "forms": [("https://app.example.com/contact", {"action": "/contact", "inputs": ["email"]})],
        "findings": [
            Finding(
                severity=Severity.MEDIUM,
                title="Reflected XSS in search query",
                detail="Payload reflected in HTML body",
                module="xss_reflection",
                url="https://app.example.com/search",
            ),
            Finding(
                severity=Severity.LOW,
                title="Missing Content-Security-Policy (CSP) Header",
                detail="No CSP defined",
                module="headers",
                url="https://app.example.com/",
            ),
            Finding(
                severity=Severity.MEDIUM,
                title="Form lacks CSRF anti-forgery protection",
                detail="No CSRF token found in post form",
                module="forms_csrf",
                url="https://app.example.com/contact",
            ),
        ],
    }
    session = MagicMock()
    mod = CombinedRiskScenariosModule(target, session, ctx)
    results = await mod.run()

    assert len(results) >= 1
    f = next(r for r in results if "RULE_02_XSS_NO_CSP_NO_CSRF" in r.evidence)
    assert f.severity == Severity.HIGH
    assert "Compounded Client-Side Exploitation" in f.title
    assert "Missing defense-in-depth" in f.detail


@pytest.mark.asyncio
async def test_correlation_dangling_subdomain_mail():
    target = Target("https://example.com")
    ctx = {
        "findings": [
            Finding(
                severity=Severity.HIGH,
                title="Subdomain Takeover candidate: dangling CNAME to GitHub Pages",
                detail="CNAME points to deleted service",
                module="subdomain_takeover",
                url="https://blog.example.com",
            ),
            Finding(
                severity=Severity.INFO,
                title="SPF / DMARC mail policy configured",
                detail="v=spf1 include:_spf.google.com ~all",
                module="dns_recon",
                url="https://example.com",
            ),
        ],
        "info": {"dns": {"TXT": ["v=spf1 include:_spf.google.com ~all"]}},
    }
    session = MagicMock()
    mod = CombinedRiskScenariosModule(target, session, ctx)
    results = await mod.run()

    assert len(results) >= 1
    f = next(r for r in results if "RULE_03_DANGLING_SUBDOMAIN_PHISHING" in r.evidence)
    assert f.severity == Severity.CRITICAL
    assert "phishing" in f.detail.lower() or "mail" in f.detail.lower()


@pytest.mark.asyncio
async def test_correlation_git_exposure_with_secrets():
    target = Target("https://example.com")
    ctx = {
        "findings": [
            Finding(
                severity=Severity.CRITICAL,
                title="Exposed Git repository: valid HEAD and refs discovered",
                detail="Full commit history accessible",
                module="git_exposure",
                url="https://example.com/.git/HEAD",
            ),
            Finding(
                severity=Severity.HIGH,
                title="AWS API Key leaked in JavaScript bundle",
                detail="Pattern match found",
                module="secrets_in_js",
                url="https://example.com/assets/app.js",
            ),
        ],
    }
    session = MagicMock()
    mod = CombinedRiskScenariosModule(target, session, ctx)
    results = await mod.run()

    assert len(results) >= 1
    f = next(r for r in results if "RULE_04_GIT_HISTORY_WITH_SECRETS" in r.evidence)
    assert f.severity == Severity.CRITICAL
    assert "git history" in f.detail.lower() or "source history" in f.detail.lower()


@pytest.mark.asyncio
async def test_correlation_sourcemap_with_comments():
    target = Target("https://example.com")
    ctx = {
        "findings": [
            Finding(
                severity=Severity.MEDIUM,
                title="JavaScript Source Map exposed",
                detail="Unminified source tree recovered",
                module="source_map_exposure",
                url="https://example.com/app.js.map",
            ),
            Finding(
                severity=Severity.LOW,
                title="Sensitive developer comments in production bundle",
                detail="TODO: remove staging credentials",
                module="comment_leak",
                url="https://example.com/app.js",
            ),
        ],
    }
    session = MagicMock()
    mod = CombinedRiskScenariosModule(target, session, ctx)
    results = await mod.run()

    assert len(results) >= 1
    f = next(r for r in results if "RULE_05_SOURCEMAP_LEAK_AMPLIFICATION" in r.evidence)
    assert f.severity == Severity.HIGH
    assert "source code" in f.detail.lower() or "source maps" in f.detail.lower()


@pytest.mark.asyncio
async def test_correlation_no_false_combines_on_benign():
    target = Target("https://example.com")
    ctx = {
        "findings": [
            Finding(
                severity=Severity.INFO,
                title="TLS Certificate valid",
                detail="Issued by Let's Encrypt",
                module="tls_https",
            ),
        ],
    }
    session = MagicMock()
    mod = CombinedRiskScenariosModule(target, session, ctx)
    results = await mod.run()
    assert results == []


# ==============================================================================
# Part 3b: Scan Drift Detection Tests
# ==============================================================================

def test_target_hash_determinism():
    h1 = get_target_hash("https://example.com/")
    h2 = get_target_hash("https://EXAMPLE.com")
    assert h1 == h2
    assert len(h1) == 16


@pytest.mark.asyncio
async def test_scan_drift_first_scan_skips(tmp_history: Path):
    target = Target("https://newsite.local")
    ctx = {
        "history_dir": tmp_history,
        "findings": [
            Finding(
                severity=Severity.MEDIUM,
                title="Missing HSTS Header",
                detail="Strict-Transport-Security missing",
                module="headers",
                url="https://newsite.local",
            )
        ],
        "js_endpoints": ["/api/v1/auth"],
        "discovered_subdomains": ["dev.newsite.local"],
        "info": {},
    }
    session = MagicMock()
    mod = ScanDriftModule(target, session, ctx)
    findings = await mod.run()

    # First scan must produce no drift findings and ctx['scan_drift'] is None
    assert findings == []
    assert ctx.get("scan_drift") is None


@pytest.mark.asyncio
async def test_scan_drift_sequential_scans_diff_computation(tmp_history: Path):
    target_url = "https://app.test.local"
    target = Target(target_url)

    # Initial scan: Finding A and endpoint /api/v1
    finding_a = Finding(
        severity=Severity.HIGH,
        title="Outdated TLS 1.0 Enabled",
        detail="Server accepts TLS 1.0 connections",
        module="tls_https",
        url=target_url,
    )
    save_target_fingerprint(
        target_url=target_url,
        findings=[finding_a],
        js_endpoints={"/api/v1/status"},
        subdomains={"api.test.local"},
        history_dir=tmp_history,
    )

    # Verify fingerprint file exists
    prior = load_prior_fingerprint(target_url, history_dir=tmp_history)
    assert prior is not None
    assert len(prior["findings"]) == 1

    # Second scan: Finding A is still present, plus new Finding B (CRITICAL),
    # new endpoint /api/v2/users, and new subdomain staging.test.local
    finding_b = Finding(
        severity=Severity.CRITICAL,
        title="Git Exposure Detected",
        detail="/.git/HEAD exposed",
        module="git_exposure",
        url=f"{target_url}/.git/HEAD",
    )

    ctx = {
        "history_dir": tmp_history,
        "findings": [finding_a, finding_b],
        "js_endpoints": {"/api/v1/status", "/api/v2/users"},
        "discovered_subdomains": {"api.test.local", "staging.test.local"},
        "info": {},
    }
    session = MagicMock()
    mod = ScanDriftModule(target, session, ctx)
    drift_findings = await mod.run()

    # Should detect regression (Finding B)
    assert any("Security Regression" in f.title for f in drift_findings)
    assert ctx["scan_drift"] is not None
    drift = ctx["scan_drift"]
    assert len(drift.new_findings) == 1
    assert drift.new_findings[0]["title"] == "Git Exposure Detected"
    assert drift.new_findings[0]["severity"] == "CRITICAL"
    assert drift.new_js_endpoints == ["/api/v2/users"]
    assert drift.new_subdomains == ["staging.test.local"]
    assert len(drift.resolved_findings) == 0

    # Save second fingerprint with only finding B (simulating finding A was resolved)
    save_target_fingerprint(
        target_url=target_url,
        findings=[finding_b],
        js_endpoints={"/api/v1/status", "/api/v2/users"},
        subdomains={"api.test.local", "staging.test.local"},
        history_dir=tmp_history,
    )

    # Third scan: finding B remains, finding A resolved
    ctx3 = {
        "history_dir": tmp_history,
        "findings": [finding_b],
        "js_endpoints": {"/api/v1/status", "/api/v2/users"},
        "discovered_subdomains": {"api.test.local", "staging.test.local"},
        "info": {},
    }
    mod3 = ScanDriftModule(target, session, ctx3)
    drift_findings3 = await mod3.run()

    # Should report progress (Finding A was resolved between scan 2 and 3)
    # Note: between scan 2 and 3 both had finding_b, but finding_a was dropped in scan 2
    # So drift between scan 2 and 3 is 0 new, 0 resolved.
    assert len(drift_findings3) == 0


@pytest.mark.asyncio
async def test_scan_drift_resolved_findings_detection(tmp_history: Path):
    target_url = "https://resolve.test.local"
    target = Target(target_url)

    # Initial scan: 2 findings
    f1 = Finding(severity=Severity.HIGH, title="Missing CSP", detail="", module="headers", url=target_url)
    f2 = Finding(severity=Severity.LOW, title="X-Powered-By Header", detail="", module="headers", url=target_url)

    save_target_fingerprint(
        target_url=target_url,
        findings=[f1, f2],
        js_endpoints=[],
        subdomains=[],
        history_dir=tmp_history,
    )

    # Next scan: f1 is resolved (only f2 remains)
    ctx = {
        "history_dir": tmp_history,
        "findings": [f2],
        "js_endpoints": [],
        "discovered_subdomains": [],
        "info": {},
    }
    mod = ScanDriftModule(target, MagicMock(), ctx)
    drift_findings = await mod.run()

    assert any("Security Progress" in f.title for f in drift_findings)
    drift = ctx["scan_drift"]
    assert len(drift.resolved_findings) == 1
    assert drift.resolved_findings[0]["title"] == "Missing CSP"


@pytest.mark.asyncio
async def test_scan_drift_no_history_flag(tmp_history: Path):
    target_url = "https://nohistory.test.local"
    target = Target(target_url)

    # Prepopulate a fingerprint
    f1 = Finding(severity=Severity.HIGH, title="Old finding", detail="", module="headers", url=target_url)
    save_target_fingerprint(target_url, [f1], [], [], history_dir=tmp_history)

    ctx = {
        "history_dir": tmp_history,
        "no_history": True,  # User passed --no-history
        "findings": [],
        "js_endpoints": [],
        "discovered_subdomains": [],
        "info": {},
    }
    mod = ScanDriftModule(target, MagicMock(), ctx)
    drift_findings = await mod.run()
    assert drift_findings == []
    assert "scan_drift" not in ctx


# ==============================================================================
# Report Section Tests: Combined Risk Scenarios & Drift in MD, HTML, and JSON
# ==============================================================================

def test_report_formats_render_combined_and_drift():
    f_comb = Finding(
        severity=Severity.CRITICAL,
        title="Unauthenticated CORS Wildcard on Admin Endpoint without Rate Limiting",
        detail="Remote attackers can enumerate/abuse this endpoint from any origin without throttling.",
        fix="Restrict CORS and enforce auth.",
        module="combined_risk_scenarios",
        url="https://target.com/api/admin",
        evidence="CORS + Admin + No rate limit",
    )
    f_std = Finding(
        severity=Severity.MEDIUM,
        title="Missing X-Frame-Options Header",
        detail="Clickjacking vulnerability",
        module="headers",
        url="https://target.com",
    )

    r = ScanResult(
        target="https://target.com",
        timestamp=datetime(2026, 10, 16, 1, 30),
        findings=[f_comb, f_std],
        pages={"https://target.com": (200, "text/html")},
        tech={"Nginx"},
        info={
            "scan_drift": {
                "prior_timestamp": "2026-10-15T12:00:00",
                "new_findings": [{"title": "Unauthenticated CORS Wildcard on Admin Endpoint", "severity": "CRITICAL"}],
                "resolved_findings": [{"title": "Old Cookie Vulnerability", "severity": "LOW"}],
                "new_js_endpoints": ["/api/v2/new_route"],
                "new_subdomains": ["staging.target.com"],
            }
        },
        forms=[],
        scripts=set(),
        js_endpoints={"/api/v2/new_route"},
        duration=1.2,
        modules_run=["headers", "combined_risk_scenarios", "scan_drift"],
    )

    # 1. Markdown
    md = MarkdownReporter().render(r)
    # Must render Combined Risk Scenarios ABOVE Standard Findings
    idx_comb = md.find("## Combined Risk Scenarios")
    idx_std = md.find("## Standard Security Findings")
    idx_drift = md.find("## Changes Since Last Scan")

    assert idx_comb != -1, "Combined Risk Scenarios missing in Markdown"
    assert idx_std != -1, "Standard Security Findings missing in Markdown"
    assert idx_drift != -1, "Changes Since Last Scan missing in Markdown"
    assert idx_comb < idx_std, "Combined Risk Scenarios must be ABOVE Standard Findings in Markdown"
    assert "Old Cookie Vulnerability" in md
    assert "/api/v2/new_route" in md

    # 2. HTML
    html = HtmlReporter().render(r)
    h_idx_comb = html.find("Combined Risk Scenarios")
    h_idx_std = html.find("Standard Security Findings")
    h_idx_drift = html.find("Changes Since Last Scan")

    assert h_idx_comb != -1, "Combined Risk Scenarios missing in HTML"
    assert h_idx_std != -1, "Standard Security Findings missing in HTML"
    assert h_idx_drift != -1, "Changes Since Last Scan missing in HTML"
    assert h_idx_comb < h_idx_std, "Combined Risk Scenarios must be ABOVE Standard Findings in HTML"
    assert "Old Cookie Vulnerability" in html

    # 3. JSON
    js = json.loads(JsonReporter().render(r))
    assert "findings_combined" in js
    assert len(js["findings_combined"]) == 1
    assert js["findings_combined"][0]["title"] == f_comb.title
    assert "scan_drift" in js
    assert js["scan_drift"]["prior_timestamp"] == "2026-10-15T12:00:00"
    assert len(js["scan_drift"]["new_findings"]) == 1
    assert len(js["scan_drift"]["resolved_findings"]) == 1
