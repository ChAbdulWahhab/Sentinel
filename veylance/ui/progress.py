"""Live scan progress with Rich.

Can be used in two ways:

  1. Simple (context manager):
        with ScanProgress(console) as p:
            p.start("crawl")
            ...
            p.done("crawl", "12 pages")

  2. With engine (no-op fallback for quiet):
        progress = ScanProgress(console, quiet=False)
        engine.run(progress=progress)
        # engine itself calls start/done/fail
"""
from __future__ import annotations

from rich.console import Console
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
    BarColumn,
)


class _NoopProgress:
    """Stub for quiet mode — renders nothing."""
    def start(self, *_a, **_kw): ...
    def done(self, *_a, **_kw): ...
    def fail(self, *_a, **_kw): ...
    def update(self, *_a, **_kw): ...
    def __enter__(self): return self
    def __exit__(self, *_a): return False


class ScanProgress:
    def __init__(self, console: Console | None = None, quiet: bool = False):
        self.quiet = quiet
        if quiet:
            # Proxy self — engine will gracefully ignore
            self._noop = _NoopProgress()
            return

        self.console = console or Console()
        self.progress = Progress(
            SpinnerColumn(style="dim cyan"),
            TextColumn("[bold white]{task.description}"),
            BarColumn(bar_width=None, complete_style="dim cyan", finished_style="dim green"),
            TextColumn("[dim]{task.fields[status]}"),
            TimeElapsedColumn(),
            console=self.console,
            transient=False,
        )
        self._tasks: dict[str, int] = {}
        self._entered = False

    # ---- context manager ----
    def __enter__(self):
        if self.quiet:
            return self._noop
        self.progress.__enter__()
        self._entered = True
        return self

    def __exit__(self, *exc):
        if self.quiet:
            return False
        if self._entered:
            self.progress.__exit__(*exc)
        return False

    # ---- public API ----
    def start(self, name: str, status: str = "running..."):
        if self.quiet:
            return
        if not self._entered:
            self.progress.start()
            self._entered = True
        tid = self.progress.add_task(name, total=100, status=status)
        self._tasks[name] = tid

    def update(self, name: str, status: str, completed: float | None = None):
        if self.quiet:
            return
        tid = self._tasks.get(name)
        if tid is None:
            return
        kw = {"status": status}
        if completed is not None:
            kw["completed"] = completed
        self.progress.update(tid, **kw)

    def done(self, name: str, msg: str = ""):
        if self.quiet:
            return
        tid = self._tasks.pop(name, None)
        if tid is not None:
            self.progress.update(
                tid,
                status=f"[green]✓[/green] {msg}",
                completed=100,
            )

    def fail(self, name: str, msg: str):
        if self.quiet:
            return
        tid = self._tasks.pop(name, None)
        if tid is not None:
            self.progress.update(
                tid,
                status=f"[red]✗ {msg}[/red]",
                completed=100,
            )