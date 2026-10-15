"""Unit tests for Claude Code CLI aesthetic terminal UI and progressive disclosure."""
from __future__ import annotations

import io
from datetime import datetime
from rich.console import Console

from veylance.core.findings import Finding, ScanResult, Severity
from veylance.ui.banner import print_banner
from veylance.ui.tables import render_findings, render_status_line, render_summary


def _create_test_scan_result():
    findings = [
        Finding(
            severity=Severity.CRITICAL,
            title="Arbitrary CORS reflection with credentials",
            detail="Server reflects evil origin.",
            fix="Use explicit allowlist of trusted origins.",
            url="https://example.com/api/user",
            evidence="ACAO: https://evil.com, ACAC: true",
            module="cors",
            cwe="CWE-942",
        ),
        Finding(
            severity=Severity.HIGH,
            title="Deprecated protocol supported: TLSv1.0",
            detail="Server accepted TLS 1.0 connection.",
            fix="Disable TLS 1.0 and 1.1 in web server.",
            url="https://example.com",
            evidence="Negotiated TLSv1.0",
            module="tls_https",
        ),
    ]
    return ScanResult(
        target="https://example.com",
        timestamp=datetime.now(),
        findings=findings,
        pages={"https://example.com/": (200, "text/html")},
        tech={"Nginx/1.20.0"},
        info={"WAF / CDN": "Cloudflare", "cloudflare_detected": True},
        forms=[],
        scripts={"https://example.com/app.js"},
        js_endpoints=set(),
        duration=3.45,
        modules_run=["cors", "tls_https", "waf_detect"],
        errors=[],
    )


def test_claude_ui_banner_monospace():
    buf = io.StringIO()
    console = Console(file=buf, width=80)
    print_banner(console, no_color=False)
    output = buf.getvalue()
    assert "veylance" in output.lower()
    assert "security self-audit" in output.lower()


def test_claude_ui_summary_and_waf_notice():
    res = _create_test_scan_result()
    buf = io.StringIO()
    console = Console(file=buf, width=80, force_terminal=True, color_system=None)
    render_summary(console, res)
    output = buf.getvalue()

    assert "Veylance Audit Summary" in output
    assert "Target:" in output
    assert "https://example.com" in output
    # Check WAF Notice appears
    assert "Edge Notice:" in output
    assert "Cloudflare" in output
    assert "CRITICAL" in output
    assert "Total findings: 2" in output


def test_claude_ui_progressive_disclosure_detail_cards():
    res = _create_test_scan_result()
    buf = io.StringIO()
    console = Console(file=buf, width=90, force_terminal=True, color_system=None)
    render_findings(console, res, show_details=True)
    output = buf.getvalue()

    assert "Findings Overview" in output
    assert "Actionable Finding Details" in output
    assert "Arbitrary CORS reflection with credentials" in output
    assert "Evidence:" in output
    assert "ACAO: https://evil.com" in output
    assert "Remediation:" in output
    assert "Use explicit allowlist" in output


def test_claude_ui_status_line():
    res = _create_test_scan_result()
    buf = io.StringIO()
    console = Console(file=buf, width=100)
    render_status_line(console, res, concurrency=10)
    output = buf.getvalue()

    assert "veyl" in output
    assert "target: https://example.com" in output
    assert "concurrency: 10" in output
    assert "elapsed:" in output
    assert "findings: 2" in output
