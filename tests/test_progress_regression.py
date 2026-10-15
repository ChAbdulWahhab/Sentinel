"""Regression test for Bug 1: Progress-bar rendering stability on fast scans."""
import asyncio
import io
import time
from rich.console import Console

from veylance.ui.progress import ScanProgress


def test_scan_progress_rapid_succession_settle():
    """Verify that rapid sub-10ms module completions flush cleanly and stop() settles."""
    buf = io.StringIO()
    console = Console(file=buf, width=80, force_terminal=True)
    p = ScanProgress(console=console, quiet=False)

    # Simulate fast multi-module scan (crawl + 4 modules in quick succession)
    p.start("crawl", status="discovering pages...")
    p.done("crawl", "1 pages")

    modules = ["headers", "cors", "cookies", "tls_https"]
    for m in modules:
        p.start(m, status="scanning...")

    # Rapid sub-10ms completion
    for m in modules:
        p.done(m, "0 findings")

    # stop() must join refresh thread, flush buffers, and reset state
    p.stop()
    assert not p._entered

    output = buf.getvalue()
    # Confirm output contains completed checkmarks and module lines
    assert "crawl" in output
    assert "headers" in output
    assert "cors" in output
    assert "cookies" in output
    assert "tls_https" in output


def test_scan_progress_stop_idempotent():
    """Verify multiple stop calls are safe and do not raise."""
    console = Console(file=io.StringIO(), width=80)
    p = ScanProgress(console=console, quiet=False)
    p.start("test", status="running...")
    p.done("test", "done")
    p.stop()
    p.stop()  # Second call should be no-op
    assert not p._entered
