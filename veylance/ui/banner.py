"""Minimalist monospace banner for Claude Code CLI aesthetic."""
from __future__ import annotations

from rich.console import Console
from rich.text import Text

from veylance.config import APP_NAME, VERSION


def print_banner(console: Console, no_color: bool = False) -> None:
    """Print clean, minimal monospace header."""
    if no_color:
        console.print(f"\n--- {APP_NAME} v{VERSION} -- Website Security Self-Audit ---\n")
        return

    console.print()
    console.print(
        f"[dim]╶─[/dim] [bold white]{APP_NAME.lower()}[/bold white] [dim]v{VERSION} ─ website security self-audit ───────────────────────────╴[/dim]"
    )
    console.print()