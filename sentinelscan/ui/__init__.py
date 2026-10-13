"""SentinelScan terminal UI package."""

from sentinelscan.ui.banner import print_banner
from sentinelscan.ui.progress import ScanProgress
from sentinelscan.ui.tables import render_summary, render_findings

# Lazy import — menu module may not be available without Textual/Prompt
# (e.g. in CI environments). Only load when needed.

def run_interactive_menu():
    from sentinelscan.ui.menu import run_interactive_menu as _run
    return _run()


__all__ = [
    "print_banner",
    "ScanProgress",
    "render_summary",
    "render_findings",
    "run_interactive_menu",
]