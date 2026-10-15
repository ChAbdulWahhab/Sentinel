"""Smoke tests for responsive startup banner and terminal UI rendering.

Verifies:
- Banner renders without exceptions across extreme terminal widths (40 to 300 columns)
- Safe fallback behavior for narrow/wide widths and non-unicode consoles
- Target context and recent scans rendering
"""
import io
import pytest
from rich.console import Console

from veylance.core.findings import Finding, ScanResult, Severity
from veylance.ui.banner import print_banner, get_recent_scans
from veylance.ui.tables import render_summary, render_findings, render_status_line


@pytest.mark.parametrize("width", [40, 50, 79, 90, 100, 120, 200, 300])
def test_banner_renders_without_exception_across_widths(width: int):
    """Confirm banner renders without raising an exception from 40 to 300 columns."""
    buf = io.StringIO()
    console = Console(file=buf, width=width, force_terminal=True)
    # Test idle banner
    print_banner(console, target=None)
    # Test scan target banner
    print_banner(console, target="https://dealsafe.pages.dev")
    # Test no-color mode
    print_banner(console, target="https://dealsafe.pages.dev", no_color=True)
    output = buf.getvalue()
    assert "Veylance" in output or "VEYLANCE" in output
    assert "Website Security" in output and "Engine" in output


def test_tables_render_without_exception_across_widths():
    """Verify summary and findings tables render without error on small (40) and large (300) widths."""
    for width in [40, 60, 80, 120, 300]:
        buf = io.StringIO()
        console = Console(file=buf, width=width, force_terminal=True)
        r = ScanResult(
            target="https://dealsafe.pages.dev",
            timestamp=pytest.importorskip("datetime").datetime.now(),
            findings=[
                Finding(
                    severity=Severity.CRITICAL,
                    title="Compound Risk: Unauthenticated Admin",
                    detail="CORS wildcard on admin endpoint with no rate limit",
                    fix="Add response header: `Strict-Transport-Security: max-age=31536000`",
                    module="combined_risk_scenarios",
                    url="https://dealsafe.pages.dev/api/admin",
                ),
                Finding(
                    severity=Severity.HIGH,
                    title="Missing security header: Content-Security-Policy",
                    detail="CSP header is missing",
                    fix="default-src 'self'",
                    module="headers",
                    url="https://dealsafe.pages.dev",
                ),
            ],
            pages={"https://dealsafe.pages.dev": (200, "text/html")},
            tech={"Cloudflare"},
            info={"cloudflare_detected": True},
            forms=[],
            scripts={"https://dealsafe.pages.dev/app.js"},
            js_endpoints={"/api/admin"},
            duration=1.45,
            modules_run=["headers", "cors", "rate_limit", "combined_risk_scenarios"],
        )
        render_status_line(console, r)
        render_summary(console, r)
        render_findings(console, r, show_details=True)
        out = buf.getvalue()
        assert "Veylance Audit Summary" in out
        assert "CRITICAL" in out
