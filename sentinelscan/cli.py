"""SentinelScan CLI - interactive security audit tool."""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

if sys.platform == "win32":
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, OSError, ValueError):
        pass
    try:
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8")
    except (AttributeError, OSError, ValueError):
        pass
from rich.prompt import Confirm, Prompt

from sentinelscan.config import APP_NAME, VERSION, DEFAULT_FORMATS
from sentinelscan.core.engine import ScanEngine
from sentinelscan.core.target import Target
from sentinelscan.report import get_reporter
from sentinelscan.ui.banner import print_banner
from sentinelscan.ui.progress import ScanProgress
from sentinelscan.ui.tables import render_summary, render_findings
from sentinelscan.utils.logger import setup_logger

app = typer.Typer(
    name="sentinelscan",
    help="🛡️ Interactive website security self-audit tool.",
    no_args_is_help=False,
    rich_markup_mode="rich",
)
console = Console()


@app.callback(invoke_without_command=True)
def main_callback(
    ctx: typer.Context,
    version: bool = typer.Option(
        False, "--version", "-V",
        help="Show version and exit",
        is_eager=True,
    ),
) -> None:
    """SentinelScan — interactive security audit.

    Run without subcommand to open interactive menu:

        $ sscan

    Or run a direct scan:

        $ sscan scan https://example.com
    """
    if version:
        from sentinelscan.config import APP_NAME, VERSION
        typer.echo(f"{APP_NAME} v{VERSION}")
        raise typer.Exit(0)

    # No subcommand given -> interactive menu if TTY, else help
    if ctx.invoked_subcommand is None:
        if sys.stdout.isatty():
            from sentinelscan.ui.menu import run_interactive_menu
            run_interactive_menu()
        else:
            typer.echo(ctx.get_help())
            raise typer.Exit(0)


@app.command()
def scan(
    url: str = typer.Argument(..., help="Target URL e.g. https://example.com"),
    output: Path = typer.Option(
        Path("./reports"), "--output", "-o",
        help="Output directory (one report file per format)",
    ),
    formats: str = typer.Option(
        "markdown,json,html", "--formats", "-f",
        help="Comma separated: markdown,json,html,sarif,csv,pdf",
    ),
    modules: Optional[str] = typer.Option(
        None, "--modules", "-m",
        help="Run only these modules (comma-separated). Default: all.",
    ),
    exclude: Optional[str] = typer.Option(
        None, "--exclude", "-x",
        help="Skip these modules (comma-separated).",
    ),
    max_pages: int = typer.Option(40, "--max-pages", help="Crawl limit"),
    concurrency: int = typer.Option(10, "--concurrency", "-c", help="Parallel requests"),
    rate: int = typer.Option(20, "--rate", "-r", help="Rate-limit test requests"),
    timeout: int = typer.Option(10, "--timeout", help="Per-request timeout (s)"),
    insecure: bool = typer.Option(False, "--insecure", "-k", help="Skip TLS certificate verification"),
    proxy: Optional[str] = typer.Option(None, "--proxy", help="http://host:port"),
    user_agent: Optional[str] = typer.Option(None, "--ua", help="Custom User-Agent"),
    cookie: Optional[str] = typer.Option(None, "--cookie", help="Cookie header"),
    header: Optional[list[str]] = typer.Option(None, "--header", "-H", help="Extra header (repeatable)"),
    interactive: bool = typer.Option(False, "--interactive", "-i", help="Full-screen TUI dashboard"),
    no_color: bool = typer.Option(False, "--no-color"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Show final summary only"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip authorization prompt"),
    config: Optional[Path] = typer.Option(None, "--config", help="TOML config file"),
) -> None:
    """Run a security audit against a target URL."""
    print_banner(console, no_color=no_color)
    setup_logger(verbose=verbose, quiet=quiet)

    # 1) Target validate
    try:
        target = Target(url)
    except ValueError as e:
        console.print(f"[red]✗ Invalid URL:[/red] {e}")
        raise typer.Exit(1)

    # 2) Authorization confirmation
    if not yes:
        console.print(
            f"\n[yellow]⚠️  Legal reminder:[/yellow] Scan only [bold]{target.host}[/bold] "
            "if you own it or have explicit written permission.\n"
        )
        if not Confirm.ask("Are you authorized to scan this target?", default=False):
            console.print("[red]Cancelled.[/red]")
            raise typer.Exit(0)

    # 3) Build module list
    from sentinelscan.modules import ALL_MODULES
    selected = list(ALL_MODULES.keys())
    if modules:
        wanted = {m.strip() for m in modules.split(",")}
        selected = [m for m in selected if m in wanted]
    if exclude:
        skip = {m.strip() for m in exclude.split(",")}
        selected = [m for m in selected if m not in skip]
    if not selected:
        console.print("[red]No modules selected.[/red]")
        raise typer.Exit(1)

    # 4) Extra headers
    extra_headers = {}
    if header:
        for h in header:
            if ":" in h:
                k, v = h.split(":", 1)
                extra_headers[k.strip()] = v.strip()

    # 5) Run engine
    engine = ScanEngine(
        target=target,
        modules=selected,
        max_pages=max_pages,
        concurrency=concurrency,
        rate_requests=rate,
        timeout=timeout,
        verify_tls=not insecure,
        proxy=proxy,
        user_agent=user_agent,
        cookie=cookie,
        extra_headers=extra_headers,
        interactive=interactive,
    )

    try:
        result = asyncio.run(engine.run(progress=ScanProgress(console, quiet=quiet)))
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user.[/yellow]")
        raise typer.Exit(130)

    # 6) Render
    if not quiet:
        render_summary(console, result)
        render_findings(console, result)

    # 7) Write reports
    output.mkdir(parents=True, exist_ok=True)
    fmt_list = [f.strip() for f in formats.split(",") if f.strip()]
    written = []
    for fmt in fmt_list:
        if fmt not in DEFAULT_FORMATS:
            console.print(f"[yellow]Unknown format skipped:[/yellow] {fmt}")
            continue
        reporter = get_reporter(fmt)
        path = output / f"{target.host}_{result.timestamp:%Y%m%d_%H%M%S}.{reporter.extension}"
        reporter.write(result, path)
        written.append(path)

    console.print("\n[bold green]✓ Reports saved:[/bold green]")
    for p in written:
        console.print(f"  • [cyan]{p}[/cyan]")


@app.command()
def modules_list() -> None:
    """List available scan modules."""
    from sentinelscan.modules import ALL_MODULES
    from rich.table import Table
    t = Table(title="Available Modules", show_lines=False)
    t.add_column("Name", style="cyan", no_wrap=True)
    t.add_column("Description", style="white")
    for name, cls in sorted(ALL_MODULES.items()):
        t.add_row(name, cls.description)
    console.print(t)


@app.command()
def version() -> None:
    """Show version."""
    console.print(f"[bold]{APP_NAME}[/bold] v{VERSION}")


def main() -> None:
    app()


if __name__ == "__main__":
    main()