"""Terminal UI rendering matching Veylance's crimson/black aesthetic.

Features:
- Responsive box-drawing borders (box.ROUNDED with ASCII fallback for legacy shells)
- Veylance crimson-red accent theme (#dc2626)
- Slim status line showing elapsed time, concurrency, findings count
- Progressive disclosure (summary first, detailed evidence/remediation cards)
- Syntax highlighting for flags, directives, and code snippets
"""
from __future__ import annotations

import re
import sys
from typing import Optional

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from veylance.core.findings import ScanResult, Severity

SEV_BADGES = {
    Severity.CRITICAL: "[bold #dc2626]CRITICAL[/bold #dc2626]",
    Severity.HIGH: "[bold #ea580c]HIGH[/bold #ea580c]",
    Severity.MEDIUM: "[bold #f59e0b]MEDIUM[/bold #f59e0b]",
    Severity.LOW: "[#60a5fa]LOW[/#60a5fa]",
    Severity.INFO: "[dim #94a3b8]INFO[/dim #94a3b8]",
}


def is_unicode_supported(console: Console) -> bool:
    """Check if console supports Unicode characters safely without throwing."""
    try:
        enc = getattr(console.file, "encoding", None) or sys.stdout.encoding or "utf-8"
        "■✓╭─".encode(enc)
        return True
    except Exception:
        return False


def get_safe_box(console: Console) -> box.Box:
    """Return appropriate box drawing style based on terminal encoding."""
    if not is_unicode_supported(console):
        return box.ASCII
    return box.ROUNDED


def format_remediation_syntax(fix: str) -> str:
    """Format remediation snippets, literal config directives, and CLI flags with inline code styling."""
    if not fix:
        return fix
    bt = chr(96)
    if bt in fix:
        fix = re.sub(bt + r"([^" + bt + r"]+)" + bt, r"[bold white on #1f232b] \1 [/bold white on #1f232b]", fix)
    elif fix.startswith("Add response header: "):
        directive = fix[len("Add response header: "):]
        fix = f"Add response header: [bold white on #1f232b] {directive} [/bold white on #1f232b]"
    elif fix.startswith(("v=DMARC1", "v=spf1", "default-src", "DENY", "Strict-Transport-Security")):
        fix = f"[bold white on #1f232b] {fix} [/bold white on #1f232b]"

    # CLI flags formatting: e.g. --i-own-this, -m, --debug
    fix = re.sub(r"(?<!\w)(--[a-z0-9\-]+|-[a-zA-Z])(?!\w)", r"[bold cyan]\1[/bold cyan]", fix)
    return fix


def render_status_line(console: Console, r: ScanResult, concurrency: int = 10) -> None:
    """Slim monospace status line with crimson accent."""
    crit = sum(1 for f in r.findings if f.severity == Severity.CRITICAL)
    high = sum(1 for f in r.findings if f.severity == Severity.HIGH)
    med = sum(1 for f in r.findings if f.severity == Severity.MEDIUM)
    low = sum(1 for f in r.findings if f.severity == Severity.LOW)
    info = sum(1 for f in r.findings if f.severity == Severity.INFO)

    sep = " │ " if is_unicode_supported(console) else " | "
    status_parts = [
        "[bold #dc2626]veyl[/bold #dc2626]",
        f"[dim]target:[/dim] [cyan]{r.target}[/cyan]",
        f"[dim]concurrency:[/dim] {concurrency}",
        f"[dim]elapsed:[/dim] {r.duration:.1f}s",
        f"[dim]findings:[/dim] {len(r.findings)} [dim]({crit}c {high}h {med}m {low}l {info}i)[/dim]",
    ]
    console.print()
    console.print(sep.join(status_parts))


def render_summary(console: Console, r: ScanResult) -> None:
    """Render executive summary panel with Claude Code minimalist aesthetic and crimson theme."""
    counts = r.counts()
    total = len(r.findings)
    term_width = console.width if (console and console.width) else 80
    box_style = get_safe_box(console)
    use_unicode = is_unicode_supported(console)

    lines: list[str] = []

    # 1. Monospace metadata header
    lines.append(f"[bold white]Target:[/bold white]     [bold underline cyan]{r.target}[/bold underline cyan]")
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
        bullet = "●" if use_unicode else "*"
        lines.append("")
        lines.append(
            f"[bold #dc2626]{bullet}[/bold #dc2626] [bold white]Edge Notice:[/bold white] Target is behind [bold]{edge_name}[/bold]. "
            "Results reflect edge proxy configuration rather than raw origin behavior."
        )

    # 3. Severity breakdown bar
    lines.append("")
    max_bar = max(6, min(36, term_width - 28))
    bar_char = "■" if use_unicode else "#"
    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
        n = counts.get(sev, 0)
        badge = SEV_BADGES[sev]
        bar = bar_char * min(n, max_bar)
        color = sev.color
        lines.append(f"  {badge:<10}  {n:>3}  [{color}]{bar}[/{color}]")

    lines.append("")
    lines.append(f"[bold white]Total findings:[/bold white] {total}")

    if r.errors:
        lines.append(f"[dim yellow]Modules skipped/warnings:[/dim yellow] {len(r.errors)} (see debug.log)")

    title_text = (
        "[bold #dc2626]╭─[/bold #dc2626] [bold white]Veylance Audit Summary[/bold white] [bold #dc2626]─╮[/bold #dc2626]"
        if use_unicode
        else "[bold white]Veylance Audit Summary[/bold white]"
    )

    console.print()
    console.print(
        Panel(
            "\n".join(lines),
            title=title_text,
            title_align="left",
            border_style="#dc2626" if total > 0 and counts.get(Severity.CRITICAL, 0) > 0 else "bright_black",
            box=box_style,
            expand=True,
            padding=(1, 2),
        )
    )


def render_findings(console: Console, r: ScanResult, show_details: bool = True) -> None:
    """Render findings table and progressive disclosure detail cards with crimson/black theme."""
    if not r.findings:
        check = "✓" if is_unicode_supported(console) else "+"
        console.print(f"\n[bold green]{check}[/bold green] [bold white]No findings found.[/bold white]\n")
        return

    from veylance.modules import ADVANCED_MODULES, ADVANCED_MODULE_EXPLAINERS

    box_style = get_safe_box(console)
    use_unicode = is_unicode_supported(console)

    comb_findings = [f for f in r.findings if f.module == "combined_risk_scenarios"]
    adv_findings = [f for f in r.findings if f.module in ADVANCED_MODULES and f.module != "combined_risk_scenarios"]
    std_findings = [f for f in r.findings if f.module not in ADVANCED_MODULES and f.module != "combined_risk_scenarios"]

    def _build_table(findings: list, title: str, border_color: str = "bright_black") -> Table:
        t = Table(
            title=title,
            title_justify="left",
            show_lines=True,
            box=box_style,
            border_style=border_color,
            header_style="bold dim white",
            expand=True,
        )
        t.add_column("#", width=4, justify="right", style="dim", no_wrap=True)
        t.add_column("Sev", width=7, justify="center", no_wrap=True)
        t.add_column("Module", style="dim", overflow="fold", no_wrap=False, min_width=12, max_width=24)
        t.add_column("Title", overflow="fold", no_wrap=False, ratio=3)
        t.add_column("Endpoint", overflow="fold", no_wrap=False, ratio=2, style="dim")

        for i, f in enumerate(sorted(findings, key=lambda x: x.severity), 1):
            badge = SEV_BADGES.get(f.severity, f.severity.name)
            t.add_row(str(i), badge, f.module, f.title, f.url or "-")
        return t

    # 1. Combined Risk Scenarios (Rendered ABOVE Standard Findings)
    if comb_findings:
        console.print()
        console.print(
            _build_table(
                comb_findings,
                "[bold #dc2626]Combined Risk Scenarios[/bold #dc2626] [dim]── Chained Attack Vectors[/dim]",
                border_color="#dc2626",
            )
        )

    # 2. Standard Findings Table
    if std_findings:
        console.print()
        console.print(_build_table(std_findings, "[bold white]Standard Findings Overview[/bold white]", border_color="bright_black"))

    # 3. Advanced / Hidden Exposure Table
    if adv_findings:
        console.print()
        console.print(
            _build_table(
                adv_findings,
                "[bold #dc2626]Advanced / Hidden Exposure Findings[/bold #dc2626]",
                border_color="#dc2626",
            )
        )

        active_adv_mods = sorted(set(f.module for f in adv_findings))
        bullet = "•" if use_unicode else "*"
        explainer_lines = [
            f"[bold #dc2626]{bullet}[/bold #dc2626] [bold white]{m}:[/bold white] [dim]{ADVANCED_MODULE_EXPLAINERS.get(m, '')}[/dim]"
            for m in active_adv_mods if m in ADVANCED_MODULE_EXPLAINERS
        ]
        if explainer_lines:
            panel_title = (
                "[bold #dc2626]╭─[/bold #dc2626] [bold white]Advanced Detection Focus & Incident Prevention[/bold white] [bold #dc2626]─╮[/bold #dc2626]"
                if use_unicode
                else "[bold white]Advanced Detection Focus & Incident Prevention[/bold white]"
            )
            console.print(
                Panel(
                    "\n".join(explainer_lines),
                    title=panel_title,
                    title_align="left",
                    border_style="#dc2626",
                    box=box_style,
                    expand=True,
                    padding=(0, 2),
                )
            )

    # 4. Changes Since Last Scan (Temporal Drift)
    drift = r.info.get("scan_drift")
    if drift and (isinstance(drift, dict) or hasattr(drift, "new_findings")):
        prior_time = drift.get("prior_timestamp") if isinstance(drift, dict) else drift.prior_timestamp
        new_cnt = drift.get("new_findings_count") if isinstance(drift, dict) else len(drift.new_findings)
        res_cnt = drift.get("resolved_findings_count") if isinstance(drift, dict) else len(drift.resolved_findings)
        new_eps = drift.get("new_js_endpoints_count") if isinstance(drift, dict) else len(drift.new_js_endpoints)
        new_subs = drift.get("new_subdomains_count") if isinstance(drift, dict) else len(drift.new_subdomains)

        drift_lines = [
            f"[bold white]Comparison Date:[/bold white] {prior_time}",
            f"[bold #dc2626]+ New Findings:[/bold #dc2626] {new_cnt}",
            f"[bold green]✓ Resolved Findings:[/bold green] {res_cnt}",
            f"[dim]+ New JS Endpoints:[/dim] {new_eps}   [dim]+ New Subdomains:[/dim] {new_subs}",
        ]
        panel_drift_title = (
            f"[bold #dc2626]╭─[/bold #dc2626] [bold white]Changes Since Last Scan ({prior_time[:16]})[/bold white] [bold #dc2626]─╮[/bold #dc2626]"
            if use_unicode
            else f"[bold white]Changes Since Last Scan ({prior_time[:16]})[/bold white]"
        )
        console.print()
        console.print(
            Panel(
                "\n".join(drift_lines),
                title=panel_drift_title,
                title_align="left",
                border_style="#dc2626",
                box=box_style,
                expand=True,
                padding=(0, 2),
            )
        )

    sorted_findings = sorted(r.findings, key=lambda x: x.severity)

    # 5. Progressive Disclosure: Actionable Details & Remediation Cards
    if show_details:
        detail_findings = [f for f in sorted_findings if f.severity <= Severity.MEDIUM]
        if not detail_findings:
            detail_findings = sorted_findings[:5]

        if detail_findings:
            console.print()
            header_prefix = "[bold #dc2626]╭──[/bold #dc2626] " if use_unicode else ""
            header_suffix = " [bold #dc2626]────────────────────────────╮[/bold #dc2626]" if use_unicode else ""
            console.print(f"{header_prefix}[bold white]Actionable Finding Details[/bold white]{header_suffix}")

            for f in detail_findings:
                badge = SEV_BADGES.get(f.severity, f.severity.name)
                card_lines = [
                    f"[bold white]{f.title}[/bold white]  {badge}  [dim]({f.module})[/dim]",
                    f"[dim]Endpoint:[/dim]     [underline dim]{f.url or '-'}[/underline dim]",
                ]
                if f.evidence:
                    card_lines.append(f"[dim]Evidence:[/dim]     [bright_white]{f.evidence}[/bright_white]")
                if f.detail and f.detail != f.title:
                    card_lines.append(f"[dim]Details:[/dim]      {f.detail}")
                if f.fix:
                    card_lines.append(f"[dim green]Remediation:[/dim green]  {format_remediation_syntax(f.fix)}")
                if f.cwe or f.owasp:
                    meta = []
                    if f.cwe: meta.append(f.cwe)
                    if f.owasp: meta.append(f"OWASP {f.owasp}")
                    card_lines.append(f"[dim]References:[/dim]   {', '.join(meta)}")

                border_card = "#dc2626" if f.severity <= Severity.HIGH else "bright_black"
                console.print(
                    Panel(
                        "\n".join(card_lines),
                        border_style=border_card,
                        box=box_style,
                        padding=(0, 2),
                        expand=True,
                    )
                )

            if use_unicode:
                console.print("[bold #dc2626]╰─────────────────────────────────────────────────────────────────╯[/bold #dc2626]")