"""Veylance CLI - interactive security audit tool."""
from __future__ import annotations

import asyncio
import os
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

from veylance.config import APP_NAME, VERSION, DEFAULT_FORMATS
from veylance.core.engine import ScanEngine
from veylance.core.target import Target
from veylance.report import get_reporter
from veylance.ui.banner import print_banner
from veylance.ui.progress import ScanProgress
from veylance.ui.tables import render_summary, render_findings, render_status_line
from veylance.utils.logger import setup_logger

app = typer.Typer(
    name="veylance",
    help="Interactive website security self-audit tool.",
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
    """Veylance — interactive security audit.

    Run without subcommand to open interactive menu:

        $ veyl

    Or run a direct scan:

        $ veyl scan https://example.com
    """
    if version:
        from veylance.config import APP_NAME, VERSION
        typer.echo(f"{APP_NAME} v{VERSION}")
        raise typer.Exit(0)

    # No subcommand given -> interactive menu if TTY, else help
    if ctx.invoked_subcommand is None:
        if sys.stdout.isatty():
            from veylance.ui.menu import run_interactive_menu
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
    max_concurrency: Optional[int] = typer.Option(None, "--max-concurrency", help="Alias for concurrency limit"),
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
    debug: bool = typer.Option(False, "--debug", help="Show full stack traces and verbose debug logs on error"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip authorization prompt"),
    i_own_this: Optional[str] = typer.Option(
        None, "--i-own-this",
        help="Declare domain ownership (e.g. example.com) to bypass interactive consent prompt",
    ),
    no_history: bool = typer.Option(
        False, "--no-history",
        help="Opt-out of saving target fingerprint history in ~/.veylance/history for drift detection",
    ),
    config: Optional[Path] = typer.Option(None, "--config", help="TOML config file"),
) -> None:
    """Run a security audit against a target URL."""
    # Defensively unwrap any Typer OptionInfo objects if called directly in Python
    def _unwrap(val, fallback=None):
        if hasattr(val, "default"):
            return fallback if val.default is ... else val.default
        return val

    output = Path(_unwrap(output, "./reports"))
    formats = str(_unwrap(formats, "markdown,json,html"))
    modules = _unwrap(modules, None)
    exclude = _unwrap(exclude, None)
    max_pages = int(_unwrap(max_pages, 40))
    concurrency = int(_unwrap(concurrency, 10))
    max_c = _unwrap(max_concurrency, None)
    if max_c is not None:
        concurrency = int(max_c)
    rate = int(_unwrap(rate, 20))
    timeout = int(_unwrap(timeout, 10))
    insecure = bool(_unwrap(insecure, False))
    proxy = _unwrap(proxy, None)
    user_agent = _unwrap(user_agent, None)
    cookie = _unwrap(cookie, None)
    header = _unwrap(header, None)
    interactive = bool(_unwrap(interactive, False))
    no_color = bool(_unwrap(no_color, False))
    quiet = bool(_unwrap(quiet, False))
    verbose = bool(_unwrap(verbose, False))
    debug = bool(_unwrap(debug, False))
    yes = bool(_unwrap(yes, False))
    i_own_this = _unwrap(i_own_this, None)
    no_history = bool(_unwrap(no_history, False))
    config = _unwrap(config, None)

    print_banner(console, target=url, no_color=no_color)
    setup_logger(verbose=verbose, quiet=quiet, debug=debug)


    # 1) Target validate
    try:
        target = Target(url)
    except ValueError as e:
        console.print(f"[red]✗ Invalid URL:[/red] {e}")
        raise typer.Exit(1)

    # 2) Authorization and consent verification
    from veylance.ui.consent import has_consent, prompt_for_consent
    from veylance.utils.audit import log_audit_event

    auth_method = "none"
    if i_own_this and isinstance(i_own_this, str):
        declared = i_own_this.strip().lower()
        host = target.host.lower()
        if declared == host or host.endswith("." + declared):
            auth_method = "i-own-this"
        else:
            console.print(
                f"[red]✗ Domain mismatch:[/red] Declared ownership for '{i_own_this}' "
                f"does not match target host '{target.host}'."
            )
            log_audit_event(
                action="SCAN_BLOCKED_DOMAIN_MISMATCH",
                target=target.base,
                auth_method="i-own-this-failed",
                extra={"declared_domain": i_own_this, "target_host": target.host},
                output_dir=output,
            )
            raise typer.Exit(1)
    elif yes:
        auth_method = "yes-flag"
    elif has_consent(domain=target.host):
        auth_method = "saved-consent"
    else:
        # Prompt if interactive TTY or running under test runner with stdin input, else block
        can_prompt = (
            "PYTEST_CURRENT_TEST" in os.environ
            or (hasattr(sys.stdin, "isatty") and sys.stdin.isatty())
            or (hasattr(sys.stdout, "isatty") and sys.stdout.isatty())
        )
        if can_prompt:
            try:
                if prompt_for_consent(console, target.host):
                    auth_method = "interactive-consent"
                else:
                    console.print("[red]Cancelled. Authorization required to perform scan.[/red]")
                    log_audit_event(
                        action="SCAN_CANCELLED_NO_CONSENT",
                        target=target.base,
                        auth_method="declined",
                        output_dir=output,
                    )
                    raise typer.Exit(0)
            except (EOFError, KeyboardInterrupt):
                console.print("\n[red]Cancelled. Authorization required to perform scan.[/red]")
                log_audit_event(
                    action="SCAN_CANCELLED_NO_CONSENT",
                    target=target.base,
                    auth_method="declined",
                    output_dir=output,
                )
                raise typer.Exit(0)
        else:
            console.print(
                "[red]Error:[/red] Terms and domain authorization required. Run interactively to authorize, "
                "or pass --yes or --i-own-this <domain>."
            )
            log_audit_event(
                action="SCAN_BLOCKED_NON_INTERACTIVE_NO_CONSENT",
                target=target.base,
                auth_method="none",
                output_dir=output,
            )
            raise typer.Exit(1)

    # 3) Build module list
    from veylance.modules import ALL_MODULES
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
    log_audit_event(
        action="SCAN_STARTED",
        target=target.base,
        auth_method=auth_method,
        extra={"modules": selected, "concurrency": concurrency, "rate": rate},
        output_dir=output,
    )
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
        no_history=no_history,
    )

    try:
        result = asyncio.run(engine.run(progress=ScanProgress(console, quiet=quiet)))
        log_audit_event(
            action="SCAN_COMPLETED",
            target=target.base,
            auth_method=auth_method,
            extra={
                "duration": round(result.duration, 2),
                "findings_count": len(result.findings),
                "counts": {s.name: n for s, n in result.counts().items()},
            },
            output_dir=output,
        )
    except KeyboardInterrupt:
        log_audit_event(
            action="SCAN_INTERRUPTED",
            target=target.base,
            auth_method=auth_method,
            output_dir=output,
        )
        console.print("\n[yellow]Interrupted by user.[/yellow]")
        raise typer.Exit(130)
    except typer.Exit:
        raise
    except Exception as exc:
        import logging
        import traceback
        from veylance.config import DEBUG_LOG_FILE
        logging.getLogger("veylance").error("Unhandled exception during scan: %s", exc, exc_info=True)
        if debug:
            console.print("\n[bold red]Traceback (most recent call last):[/bold red]")
            console.print(traceback.format_exc())
        else:
            console.print(f"\n[bold red]✗ Scan Error:[/bold red] {type(exc).__name__}: {exc}")
            console.print(f"[dim]Full error logged to {DEBUG_LOG_FILE}. Run with --debug to reveal full stack trace.[/dim]\n")
        raise typer.Exit(1)

    # 6) Render
    if not quiet:
        render_summary(console, result)
        render_findings(console, result)
        render_status_line(console, result, concurrency=concurrency)


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

    if not no_history:
        from veylance.utils.drift import save_target_fingerprint
        subdomains = list(result.info.get("discovered_subdomains", [])) or [
            h.split(" -> ")[0].strip() for h in result.info.get("Subdomains (A record)", [])
        ]
        save_target_fingerprint(
            target_url=target.base,
            findings=result.findings,
            js_endpoints=result.js_endpoints,
            subdomains=subdomains,
        )


@app.command()
def modules_list() -> None:
    """List available scan modules."""
    from veylance.modules import ALL_MODULES
    from rich.table import Table
    t = Table(title="Available Modules", show_lines=False, expand=True)
    t.add_column("Name", style="cyan", no_wrap=True, min_width=12, max_width=20)
    t.add_column("Description", style="white", overflow="fold", no_wrap=False, ratio=1)
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