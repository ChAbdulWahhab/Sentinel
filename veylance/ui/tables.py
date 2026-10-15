"""Terminal UI rendering matching Claude Code's minimal monospace aesthetic.

Features:
- Monospace clean box-drawing borders (box.ROUNDED)
- Muted accent color palette (no rainbow colors)
- Slim status line showing elapsed time, concurrency, findings count
- Progressive disclosure (summary first, detailed evidence/remediation cards)
"""
from __future__ import annotations

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from veylance.core.findings import ScanResult, Severity

SEV_BADGES = {
    Severity.CRITICAL: "[bold red]CRITICAL[/bold red]",
    Severity.HIGH: "[red]HIGH[/red]",
    Severity.MEDIUM: "[yellow]MEDIUM[/yellow]",
    Severity.LOW: "[cyan]LOW[/cyan]",
    Severity.INFO: "[dim]INFO[/dim]",
}


def render_status_line(console: Console, r: ScanResult, concurrency: int = 10) -> None:
    """Slim monospace status line."""
    crit = sum(1 for f in r.findings if f.severity == Severity.CRITICAL)
    high = sum(1 for f in r.findings if f.severity == Severity.HIGH)
    med = sum(1 for f in r.findings if f.severity == Severity.MEDIUM)
    low = sum(1 for f in r.findings if f.severity == Severity.LOW)
    info = sum(1 for f in r.findings if f.severity == Severity.INFO)

    status_parts = [
        "[bold cyan]veyl[/bold cyan]",
        f"[dim]target:[/dim] {r.target}",
        f"[dim]concurrency:[/dim] {concurrency}",
        f"[dim]elapsed:[/dim] {r.duration:.1f}s",
        f"[dim]findings:[/dim] {len(r.findings)} [dim]({crit}c {high}h {med}m {low}l {info}i)[/dim]",
    ]
    console.print()
    console.print(" │ ".join(status_parts))


def render_summary(console: Console, r: ScanResult) -> None:
    """Render executive summary panel with Claude Code minimalist aesthetic."""
    counts = r.counts()
    total = len(r.findings)
    term_width = console.width if (console and console.width) else 80

    lines: list[str] = []

    # 1. Monospace metadata header
    lines.append(f"[bold white]Target:[/bold white]     {r.target}")
    lines.append(
        f"[dim]Duration:[/dim]   {r.duration:.2f}s  "
        f"[dim]Pages:[/dim] {len(r.pages)}  "
        f"[dim]Forms:[/dim] {len(r.forms)}  "
        f"[dim]Scripts:[/dim] {len(r.scripts)}  "
        f"[dim]Modules:[/dim] {len(r.modules_run)}"
    )

    # 2. WAF / Edge proxy awareness notice (if detected)
    waf_info = r.info.get("WAF / CDN") or (r.info.get("waf_names")[0] if r.info.get("waf_names") else None)
    if r.info.get("cloudflare_detected") or waf_info:
        edge_name = "Cloudflare" if r.info.get("cloudflare_detected") else waf_info
        lines.append("")
        lines.append(
            f"[dim yellow]●[/dim yellow] [bold white]Edge Notice:[/bold white] Target is behind [bold]{edge_name}[/bold]. "
            "Results reflect edge proxy configuration rather than raw origin behavior."
        )

    # 3. Severity breakdown bar
    lines.append("")
    max_bar = max(6, min(36, term_width - 28))
    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
        n = counts.get(sev, 0)
        badge = SEV_BADGES[sev]
        bar = "■" * min(n, max_bar)
        color = sev.color
        lines.append(f"  {badge:<10}  {n:>3}  [{color}]{bar}[/{color}]")

    lines.append("")
    lines.append(f"[bold white]Total findings:[/bold white] {total}")

    if r.errors:
        lines.append(f"[dim yellow]Modules skipped/warnings:[/dim yellow] {len(r.errors)} (see debug.log)")

    console.print()
    console.print(
        Panel(
            "\n".join(lines),
            title="[dim]╭─[/dim] [bold white]Veylance Audit Summary[/bold white] [dim]─╮[/dim]",
            title_align="left",
            border_style="bright_black",
            box=box.ROUNDED,
            expand=True,
            padding=(1, 2),
        )
    )


def render_findings(console: Console, r: ScanResult, show_details: bool = True) -> None:
    """Render findings table and progressive disclosure detail cards."""
    if not r.findings:
        console.print("\n[dim green]✓[/dim green] [bold white]No findings found.[/bold white]\n")
        return

    # 1. Main Findings Table (Monospace, Clean Box-Drawing)
    t = Table(
        title="[bold white]Findings Overview[/bold white]",
        title_justify="left",
        show_lines=True,
        box=box.ROUNDED,
        border_style="bright_black",
        header_style="bold dim white",
        expand=True,
    )
    t.add_column("#", width=4, justify="right", style="dim", no_wrap=True)
    t.add_column("Sev", width=7, justify="center", no_wrap=True)
    t.add_column("Module", style="dim", overflow="fold", no_wrap=False, min_width=10, max_width=16)
    t.add_column("Title", overflow="fold", no_wrap=False, ratio=3)
    t.add_column("Endpoint", overflow="fold", no_wrap=False, ratio=2, style="dim")

    sorted_findings = sorted(r.findings, key=lambda x: x.severity)
    for i, f in enumerate(sorted_findings, 1):
        badge = SEV_BADGES.get(f.severity, f.severity.name)
        t.add_row(
            str(i),
            badge,
            f.module,
            f.title,
            f.url or "-",
        )

    console.print()
    console.print(t)

    # 2. Progressive Disclosure: Detailed Evidence & Actionable Fix Cards
    if show_details:
        # Prioritize actionable findings (Critical, High, Medium, or all if small)
        detail_findings = [f for f in sorted_findings if f.severity <= Severity.MEDIUM]
        if not detail_findings:
            detail_findings = sorted_findings[:5]

        if detail_findings:
            console.print()
            console.print("[dim]╭──[/dim] [bold white]Actionable Finding Details[/bold white] [dim]────────────────────────────╮[/dim]")
            for f in detail_findings:
                badge = SEV_BADGES.get(f.severity, f.severity.name)
                card_lines = [
                    f"[bold white]{f.title}[/bold white]  {badge}  [dim]({f.module})[/dim]",
                    f"[dim]Endpoint:[/dim]     {f.url or '-'}",
                ]
                if f.evidence:
                    card_lines.append(f"[dim]Evidence:[/dim]     [bright_white]{f.evidence}[/bright_white]")
                if f.detail and f.detail != f.title:
                    card_lines.append(f"[dim]Details:[/dim]      {f.detail}")
                if f.fix:
                    card_lines.append(f"[dim green]Remediation:[/dim green]  [bold white]{f.fix}[/bold white]")
                if f.cwe or f.owasp:
                    meta = []
                    if f.cwe: meta.append(f.cwe)
                    if f.owasp: meta.append(f"OWASP {f.owasp}")
                    card_lines.append(f"[dim]References:[/dim]   {', '.join(meta)}")

                console.print(
                    Panel(
                        "\n".join(card_lines),
                        border_style="bright_black",
                        box=box.ROUNDED,
                        padding=(0, 2),
                        expand=True,
                    )
                )
            console.print("[dim]╰─────────────────────────────────────────────────────────────────╯[/dim]")