"""Rich tables for findings + summary."""
from __future__ import annotations
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from sentinelscan.core.findings import ScanResult, Severity


def render_summary(console: Console, r: ScanResult) -> None:
    counts = r.counts()
    total = len(r.findings)

    header = f"[bold]Target:[/bold] {r.target}\n" \
             f"[bold]Duration:[/bold] {r.duration:.1f}s | " \
             f"[bold]Pages:[/bold] {len(r.pages)} | " \
             f"[bold]Forms:[/bold] {len(r.forms)} | " \
             f"[bold]JS:[/bold] {len(r.scripts)}"

    lines = [header, ""]
    for sev, n in counts.items():
        color = sev.color
        bar = "█" * min(n, 40)
        lines.append(f"[{color}]{sev.name:<9}[/{color}] {n:>3}  [{color}]{bar}[/{color}]")
    lines.append("")
    lines.append(f"[bold]Total findings:[/bold] {total}")

    console.print(Panel("\n".join(lines), title="📊 Summary", border_style="cyan"))


def render_findings(console: Console, r: ScanResult) -> None:
    if not r.findings:
        console.print("[green]✓ Koi finding nahi mili.[/green]")
        return

    t = Table(title="🔍 Findings", show_lines=True, header_style="bold cyan")
    t.add_column("#", width=3, justify="right")
    t.add_column("Sev", width=9)
    t.add_column("Module", width=18)
    t.add_column("Title", overflow="fold")
    t.add_column("URL", overflow="fold", max_width=40)

    for i, f in enumerate(sorted(r.findings, key=lambda x: x.severity), 1):
        t.add_row(
            str(i),
            f"[{f.severity.color}]{f.severity.name}[/{f.severity.color}]",
            f.module,
            f.title,
            f.url or "-",
        )
    console.print(t)