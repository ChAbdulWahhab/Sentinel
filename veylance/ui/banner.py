"""Startup and welcome banner for Veylance CLI.

Two-column Claude-Code aesthetic adapted to Veylance's crimson/black theme:
- Left panel: Large Veylance wordmark, subtitle, version, engine stats, and target context.
- Right panel: Stacked Recent Scans (from local scan history) and Quick Reference flags.
- Fully responsive across Windows Terminal, PowerShell, CMD, and Bash.
"""
from __future__ import annotations

from datetime import datetime
import json
from pathlib import Path
import sys
from typing import Optional

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from veylance.config import APP_NAME, CONFIG_DIR, VERSION


def is_unicode_supported(console: Console) -> bool:
    """Check if console supports Unicode characters safely without throwing."""
    try:
        enc = getattr(console.file, "encoding", None) or sys.stdout.encoding or "utf-8"
        # Test encode sample unicode characters
        "■✓╭─".encode(enc)
        return True
    except Exception:
        return False


def get_safe_box(console: Console) -> box.Box:
    """Return appropriate box drawing style based on terminal encoding."""
    if not is_unicode_supported(console):
        return box.ASCII
    return box.ROUNDED


def get_recent_scans(limit: int = 3) -> list[tuple[str, str]]:
    """Retrieve the most recent audit targets and relative scan times from history."""
    history_dir = CONFIG_DIR / "history"
    if not history_dir.is_dir():
        return []

    entries: list[tuple[datetime, str]] = []
    for file_path in history_dir.glob("*.json"):
        try:
            data = json.loads(file_path.read_text(encoding="utf-8"))
            target = data.get("target")
            timestamp = data.get("timestamp")
            if target and timestamp:
                dt = datetime.fromisoformat(timestamp)
                entries.append((dt, target))
        except Exception:
            continue

    if not entries:
        return []

    entries.sort(key=lambda x: x[0], reverse=True)
    now = datetime.now()
    results: list[tuple[str, str]] = []

    for dt, raw_target in entries[:limit]:
        diff = (now - dt).total_seconds()
        if diff < 60:
            rel = "just now"
        elif diff < 3600:
            rel = f"{max(1, int(diff // 60))}m ago"
        elif diff < 86400:
            rel = f"{max(1, int(diff // 3600))}h ago"
        else:
            rel = f"{max(1, int(diff // 86400))}d ago"

        clean = raw_target.replace("https://", "").replace("http://", "").rstrip("/")
        results.append((clean, rel))

    return results


def print_banner(
    console: Console,
    target: Optional[str] = None,
    no_color: bool = False,
) -> None:
    """Print two-column startup banner with Veylance crimson-red branding."""
    if no_color:
        console.print(f"\n============================================================")
        console.print(f" {APP_NAME} v{VERSION} -- Website Security Audit Engine")
        if target:
            console.print(f" Target: {target}")
        console.print(f"============================================================\n")
        return

    term_width = console.width if (console and console.width) else 80
    box_style = get_safe_box(console)
    use_unicode = is_unicode_supported(console)

    # 1. Left Panel (Brand, Engine & Target context)
    left_table = Table(box=None, show_header=False, padding=0, expand=True)
    left_table.add_column("Content", ratio=1)

    inner_col_width = (term_width // 2) - 6 if term_width >= 96 else term_width - 6

    # Select ASCII wordmark if terminal column is wide enough (>= 45), else stylized bold typography
    if inner_col_width >= 45:
        logo_lines = [
            r" _  _ ____ _   _ _    ____ _  _ ____ ____ ",
            r" |  | |___  \_/  |    |__| |\ | |    |___ ",
            r"  \/  |___   |   |___ |  | | \| |___ |___ ",
        ]
        logo_text = Text()
        for line in logo_lines:
            logo_text.append(line + "\n", style="bold #dc2626")
        left_table.add_row(logo_text)
    else:
        title_sym = "■" if use_unicode else "*"
        title_text = Text()
        title_text.append(f"{title_sym} VEYLANCE\n", style="bold #dc2626")
        left_table.add_row(title_text)

    meta_text = Text()
    meta_text.append("Website Security Self-Audit Engine\n", style="bold white")
    meta_text.append("Version:   ", style="dim")
    meta_text.append(f"v{VERSION} (AST-grade heuristics)\n", style="white")
    meta_text.append("Engine:    ", style="dim")
    meta_text.append("35 security modules active\n", style="white")
    if target:
        meta_text.append("Target:    ", style="dim")
        meta_text.append(f"{target}\n", style="bold cyan underline")
    else:
        meta_text.append("Status:    ", style="dim")
        meta_text.append("Ready (interactive / CLI)\n", style="green")

    left_table.add_row(meta_text)

    panel_left = Panel(
        left_table,
        border_style="#dc2626",
        box=box_style,
        padding=(1, 2),
        expand=True,
        title="[bold white]Veylance[/bold white]",
        title_align="left",
    )

    # 2. Right Panel (Stacked: Recent Scans + Quick Reference)
    recent_scans = get_recent_scans(limit=3)
    t_rec = Table(box=None, show_header=False, padding=(0, 1), expand=True)
    t_rec.add_column("Target", style="bold white", overflow="ellipsis", ratio=2)
    t_rec.add_column("Time", style="dim", justify="right", no_wrap=True, ratio=1)

    if recent_scans:
        for tgt, rel_time in recent_scans:
            t_rec.add_row(tgt, rel_time)
    else:
        t_rec.add_row("[dim]No prior audit history found[/dim]", "")

    panel_recent = Panel(
        t_rec,
        border_style="bright_black",
        box=box_style,
        title="[bold #dc2626]Recent Scans[/bold #dc2626]",
        title_align="left",
        padding=(0, 1),
        expand=True,
    )

    flag_w = 16 if inner_col_width > 36 else 14
    t_ref = Table(box=None, show_header=False, padding=(0, 1), expand=True)
    t_ref.add_column("Flag", style="bold cyan", width=flag_w, no_wrap=True)
    t_ref.add_column("Desc", style="dim", overflow="fold")
    t_ref.add_row("--i-own-this", "Declare domain authorization")
    t_ref.add_row("-m <modules>", "Run specific security checks")
    t_ref.add_row("--debug", "Verbose diagnostic logging")
    t_ref.add_row("--no-history", "Disable drift tracking")

    panel_ref = Panel(
        t_ref,
        border_style="bright_black",
        box=box_style,
        title="[bold #dc2626]Quick Reference[/bold #dc2626]",
        title_align="left",
        padding=(0, 1),
        expand=True,
    )

    right_stack = Table(box=None, show_header=False, padding=0, expand=True)
    right_stack.add_column("Box")
    right_stack.add_row(panel_recent)
    right_stack.add_row(panel_ref)

    # 3. Responsive Layout Assembly
    console.print()
    if term_width >= 96:
        container = Table(box=None, show_header=False, padding=(0, 1), expand=True)
        container.add_column("Left", ratio=12)
        container.add_column("Right", ratio=11)
        container.add_row(panel_left, right_stack)
        console.print(container)
    else:
        container = Table(box=None, show_header=False, padding=0, expand=True)
        container.add_column("Col")
        container.add_row(panel_left)
        container.add_row(panel_recent)
        container.add_row(panel_ref)
        console.print(container)
    console.print()