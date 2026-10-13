"""SentinelScan terminal UI package."""

from sentinelscan.ui.banner import print_banner
from sentinelscan.ui.progress import ScanProgress
from sentinelscan.ui.tables import render_summary, render_findings

# Lazy import — menu module kabhi kabhi Textual/Prompt ke bina
# available nahi hoga (CI env me). Sirf jab zarurat ho tab load karo.

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