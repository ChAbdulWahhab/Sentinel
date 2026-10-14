"""Interactive menu — launched when running `veyl` without subcommands.

Usage:
    $ veyl          -> interactive menu
    $ veyl scan ... -> direct scan (skips menu)
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table
from rich.text import Text

from veylance.config import APP_NAME, LEGAL_NOTICE, VERSION
from veylance.ui.banner import print_banner

console = Console()


# ---------- Menu entries ----------
MENU_OPTIONS = [
    ("1", "New Scan",          "Scan a new target"),
    ("2", "View Past Reports", "Browse reports folder"),
    ("3", "List Modules",      "View all 23 scan modules"),
    ("4", "Check Target Health","Headers + TLS + DNS checks only"),
    ("5", "Settings",          "Configuration and defaults"),
    ("6", "Legal & Terms",     "Legal disclaimer and usage terms"),
    ("7", "About",             "Version and project credits"),
    ("0", "Exit",              "Exit application"),
]


# ---------- Rendering ----------
def _render_menu() -> None:
    t = Table(show_header=False, box=None, padding=(0, 2))
    t.add_column("Key", style="bold cyan", width=4, justify="right")
    t.add_column("Option", style="bold white", width=24)
    t.add_column("Description", style="dim")
    for key, label, desc in MENU_OPTIONS:
        t.add_row(f"[{key}]", label, desc)

    console.print()
    console.print(
        Panel(
            t,
            title=f"[bold cyan]{APP_NAME}[/bold cyan] v{VERSION}",
            border_style="cyan",
            padding=(1, 2),
        )
    )


def _prompt_choice() -> str:
    choices = [k for k, _, _ in MENU_OPTIONS]
    try:
        return Prompt.ask(
            "\n[bold cyan]Enter choice[/bold cyan]",
            choices=choices,
            default="1",
            show_choices=False,
        )
    except (KeyboardInterrupt, EOFError):
        return "0"


# ---------- Menu handlers ----------
def _menu_new_scan() -> None:
    console.print("\n[bold cyan]▸ New Scan[/bold cyan]\n")

    url = Prompt.ask("[bold]Target URL[/bold] (e.g. example.com)").strip()
    if not url:
        console.print("[yellow]Target URL cannot be empty — cancelled.[/yellow]")
        return

    formats = Prompt.ask(
        "[bold]Report formats[/bold] (comma-separated)",
        default="markdown,json,html",
    ).strip()

    output = Prompt.ask(
        "[bold]Output directory[/bold]",
        default="./reports",
    ).strip()

    max_pages = Prompt.ask(
        "[bold]Max pages to crawl[/bold]",
        default="40",
    ).strip()

    # Extra modules filter
    console.print(
        "\n[dim]Tip: All 23 modules will run. "
        "To run specific modules, use the `-m` flag in the CLI.[/dim]"
    )

    # Authorization
    console.print(
        f"\n[yellow]⚠️  Legal: Scan only [bold]{url}[/bold] if you own it "
        "or have explicit written permission.[/yellow]"
    )
    if not Confirm.ask("Are you authorized to scan this target?", default=False):
        console.print("[red]Cancelled.[/red]")
        return

    # Scan command build
    from veylance.cli import scan as scan_cmd

    try:
        scan_cmd(
            url=url,
            output=Path(output),
            formats=formats,
            modules=None,
            exclude=None,
            max_pages=int(max_pages) if max_pages.isdigit() else 40,
            concurrency=10,
            rate=20,
            timeout=10,
            insecure=False,
            proxy=None,
            user_agent=None,
            cookie=None,
            header=None,
            interactive=False,
            no_color=False,
            quiet=False,
            verbose=False,
            yes=True,   # consent already granted
            i_own_this=None,
            config=None,
        )
    except SystemExit:
        pass
    except Exception as e:
        console.print(f"[red]Scan error:[/red] {type(e).__name__}: {e}")


def _menu_view_reports() -> None:
    console.print("\n[bold cyan]▸ Past Reports[/bold cyan]\n")

    reports_dir = Path("./reports")
    if not reports_dir.exists():
        console.print(
            "[yellow]Reports folder `./reports` not found.[/yellow]\n"
            "Run a scan first: [cyan]sscan scan example.com[/cyan]"
        )
        return

    files = sorted(
        [f for f in reports_dir.iterdir() if f.is_file()],
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    if not files:
        console.print("[yellow]Reports folder is empty.[/yellow]")
        return

    t = Table(title=f"Reports ({len(files)})", show_lines=False)
    t.add_column("#", width=4, justify="right", style="dim")
    t.add_column("Name", style="cyan", overflow="fold")
    t.add_column("Size", justify="right", style="dim")
    t.add_column("Modified", style="dim")

    for i, f in enumerate(files[:30], 1):
        import datetime as _dt
        mtime = _dt.datetime.fromtimestamp(f.stat().st_mtime)
        size = f.stat().st_size
        size_str = f"{size} B" if size < 1024 else f"{size // 1024} KB"
        t.add_row(str(i), f.name, size_str, mtime.strftime("%Y-%m-%d %H:%M"))
    console.print(t)

    # Optionally open folder
    if Confirm.ask("Do you want to open the reports folder?", default=False):
        _open_folder(reports_dir)


def _open_folder(path: Path) -> None:
    """Cross-platform folder open."""
    try:
        if sys.platform == "darwin":
            subprocess.run(["open", str(path)], check=False)
        elif sys.platform.startswith("linux"):
            subprocess.run(["xdg-open", str(path)], check=False)
        elif sys.platform == "win32":
            subprocess.run(["explorer", str(path)], check=False)
        else:
            console.print(f"[dim]Path: {path}[/dim]")
    except Exception as e:
        console.print(f"[yellow]Failed to open folder: {e}[/yellow]")
        console.print(f"[dim]Path: {path}[/dim]")


def _menu_list_modules() -> None:
    console.print("\n[bold cyan]▸ Available Modules[/bold cyan]\n")
    from veylance.modules import ALL_MODULES

    t = Table(title=f"{len(ALL_MODULES)} Modules", show_lines=False)
    t.add_column("Name", style="cyan", no_wrap=True)
    t.add_column("Description", style="white")
    t.add_column("Crawl", justify="center", style="dim", width=6)

    for name, cls in sorted(ALL_MODULES.items()):
        crawl = "yes" if getattr(cls, "requires_crawl", False) else "-"
        t.add_row(name, cls.description, crawl)
    console.print(t)


def _menu_target_health() -> None:
    console.print("\n[bold cyan]▸ Quick Target Health Check[/bold cyan]\n")
    console.print("[dim]Only headers, TLS, and DNS checks will run (~5 sec)[/dim]\n")

    url = Prompt.ask("[bold]Target URL[/bold]").strip()
    if not url:
        return

    console.print(
        f"\n[yellow]Please confirm authorized testing.[/yellow]"
    )
    if not Confirm.ask(f"Are you authorized to scan {url}?", default=False):
        console.print("[red]Cancelled.[/red]")
        return

    from veylance.cli import scan as scan_cmd

    try:
        scan_cmd(
            url=url,
            output=Path("./reports"),
            formats="markdown",
            modules="headers,tls_https,dns_recon,cookies,cors",
            exclude=None,
            max_pages=1,
            concurrency=5,
            rate=10,
            timeout=10,
            insecure=False,
            proxy=None,
            user_agent=None,
            cookie=None,
            header=None,
            interactive=False,
            no_color=False,
            quiet=False,
            verbose=False,
            yes=True,
            i_own_this=None,
            config=None,
        )
    except SystemExit:
        pass
    except Exception as e:
        console.print(f"[red]Error:[/red] {type(e).__name__}: {e}")


def _menu_settings() -> None:
    console.print("\n[bold cyan]▸ Settings[/bold cyan]\n")

    from veylance.config import CONFIG_DIR

    config_file = CONFIG_DIR / "config.toml"

    t = Table(show_header=False, box=None, padding=(0, 2))
    t.add_column("Key", style="bold")
    t.add_column("Value", style="dim")
    t.add_row("Config dir", str(CONFIG_DIR))
    t.add_row("Config file", str(config_file))
    t.add_row("Reports dir", str(Path("./reports").resolve()))
    console.print(t)

    console.print(
        "\n[dim]Configuration file is not implemented yet. "
        "Use CLI flags for now:[/dim]"
    )
    console.print(
        "  [cyan]sscan scan example.com --max-pages 100 --concurrency 5[/cyan]\n"
        "  [cyan]sscan scan example.com -m headers,tls_https,cors[/cyan]"
    )


def _menu_legal() -> None:
    console.print("\n[bold cyan]▸ Legal & Terms[/bold cyan]\n")
    console.print(Panel(LEGAL_NOTICE, border_style="yellow", title="⚖️  Legal Notice"))

    console.print(
        "\n[bold]Usage terms:[/bold]\n"
        "  • Scan only websites you own or are authorized to test\n"
        "  • Unauthorized scanning is illegal (IT Act, CFAA, etc.)\n"
        "  • Reports are the user's responsibility — store them securely\n"
        "  • Tool is provided 'as-is' without warranty\n"
        "  • Follow ethical disclosure: report issues to the owner, do not leak them\n"
    )


def _menu_about() -> None:
    console.print(
        f"\n[bold cyan]{APP_NAME}[/bold cyan] v{VERSION}\n"
        "[dim]Interactive CLI website security self-audit tool.[/dim]\n\n"
        "Made with Python + Typer + Rich + httpx + dnspython\n"
        "23 modules — headers, TLS, CORS, DNS, GraphQL, JWT, and more.\n\n"
        "[dim]GitHub: github.com/ChAbdulWahhab/veylance[/dim]"
    )


# ---------- Dispatcher ----------
HANDLERS = {
    "1": _menu_new_scan,
    "2": _menu_view_reports,
    "3": _menu_list_modules,
    "4": _menu_target_health,
    "5": _menu_settings,
    "6": _menu_legal,
    "7": _menu_about,
    "0": None,   # exit
}


def run_interactive_menu() -> None:
    """Main loop — display menu, prompt for choice, invoke handler."""
    print_banner(console)

    while True:
        _render_menu()
        choice = _prompt_choice()

        if choice == "0":
            console.print("\n[cyan]Bye![/cyan]\n")
            sys.exit(0)

        handler = HANDLERS.get(choice)
        if handler is None:
            console.print("[red]Unknown choice.[/red]")
            continue

        try:
            handler()
        except KeyboardInterrupt:
            console.print("\n[yellow]Interrupted.[/yellow]")
        except Exception as e:
            console.print(f"\n[red]Error:[/red] {type(e).__name__}: {e}")

        # pause before next menu
        console.print()
        try:
            Prompt.ask(
                "[dim]Press Enter to return to the menu[/dim]",
                default="",
                show_default=False,
            )
        except (KeyboardInterrupt, EOFError):
            console.print("\n[cyan]Bye![/cyan]")
            sys.exit(0)