import io
from datetime import datetime
from rich.console import Console

from veylance.core.findings import Finding, ScanResult, Severity
from veylance.ui.tables import render_findings, render_summary


def _create_sample_result(target="https://example.com/very/long/target/path/to/test/overflow"):
    findings = [
        Finding(
            severity=Severity.CRITICAL,
            title="Extremely long vulnerability title that should properly wrap across lines instead of overflowing right edge",
            detail="Detail here",
            fix="Fix here",
            url="https://example.com/sub/deep/path/with/a/lot/of/parameters/id=1234567890&token=abcdefghijklmnopqrstuvwxyz1234567890",
            module="cors_misconfig",
        ),
        Finding(
            severity=Severity.HIGH,
            title="Another finding with a normal title",
            detail="Detail",
            fix="Fix",
            url="https://example.com/short",
            module="tls_https",
        ),
    ]
    return ScanResult(
        target=target,
        timestamp=datetime.now(),
        findings=findings,
        pages={"https://example.com/": (200, "text/html")},
        tech={"Nginx"},
        info={},
        forms=[],
        scripts=set(),
        js_endpoints=set(),
        duration=2.5,
        modules_run=["headers", "tls_https", "cors"],
        errors=[],
    )


def test_render_findings_narrow_terminal():
    """Verify render_findings adapts to a narrow 60-character terminal width."""
    res = _create_sample_result()
    buf = io.StringIO()
    console = Console(file=buf, width=60, force_terminal=True, color_system=None)
    
    render_findings(console, res)
    output = buf.getvalue()
    
    assert "Findings" in output
    assert "CRITICAL" in output
    assert "cors_misconfig" in output
    # Check that no rendered line exceeds console width
    for line in output.splitlines():
        assert len(line) <= 60, f"Line exceeded width 60: len={len(line)}: {line}"


def test_render_summary_narrow_terminal():
    """Verify render_summary adapts to a narrow 60-character terminal width."""
    res = _create_sample_result()
    buf = io.StringIO()
    console = Console(file=buf, width=60, force_terminal=True, color_system=None)
    
    render_summary(console, res)
    output = buf.getvalue()
    
    assert "Summary" in output
    assert "Total findings" in output
    for line in output.splitlines():
        assert len(line) <= 60, f"Line exceeded width 60: len={len(line)}: {line}"


def test_render_findings_wide_terminal():
    """Verify render_findings expands to 120-character terminal width."""
    res = _create_sample_result()
    buf = io.StringIO()
    console = Console(file=buf, width=120, force_terminal=True, color_system=None)
    
    render_findings(console, res)
    output = buf.getvalue()
    
    assert "Findings" in output
    assert "CRITICAL" in output
    for line in output.splitlines():
        assert len(line) <= 120, f"Line exceeded width 120: len={len(line)}: {line}"


def test_render_findings_empty():
    """Verify empty findings render clean message."""
    res = ScanResult(
        target="https://example.com",
        timestamp=datetime.now(),
        findings=[],
        pages={},
        tech=set(),
        info={},
        forms=[],
        scripts=set(),
        js_endpoints=set(),
        duration=0.5,
        modules_run=[],
        errors=[],
    )
    buf = io.StringIO()
    console = Console(file=buf, width=80)
    render_findings(console, res)
    assert "No findings found" in buf.getvalue()


def test_render_menu_narrow_terminal(monkeypatch):
    """Verify interactive menu table and panel wrap without exceeding width."""
    from veylance.ui.menu import _render_menu
    import veylance.ui.menu as menu_mod

    buf = io.StringIO()
    test_console = Console(file=buf, width=65, force_terminal=True, color_system=None)
    monkeypatch.setattr(menu_mod, "console", test_console)

    _render_menu()
    output = buf.getvalue()

    assert "Veylance" in output
    for line in output.splitlines():
        assert len(line) <= 65, f"Menu line exceeded 65: len={len(line)}: {line}"


def test_render_modules_list_narrow_terminal():
    """Verify modules list table wraps within terminal width."""
    from typer.testing import CliRunner
    from veylance.cli import app

    runner = CliRunner()
    result = runner.invoke(app, ["modules-list"], env={"COLUMNS": "70"})
    assert result.exit_code == 0
    assert "Available Modules" in result.stdout

