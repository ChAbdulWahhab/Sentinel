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
        # engine itself calls start/done/fail/stop
"""
from __future__ import annotations

import sys
import time
import threading
from rich.console import Console
from rich.table import Column
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
    def stop(self): ...
    def __enter__(self): return self
    def __exit__(self, *_a): return False


class ScanProgress:
    def __init__(self, console: Console | None = None, quiet: bool = False):
        self.quiet = quiet
        if quiet:
            self._noop = _NoopProgress()
            return

        self.console = console or Console()
        self.progress = Progress(
            SpinnerColumn(style="bold #dc2626", finished_text="[green]✓[/green]"),
            TextColumn(
                "[bold white]{task.description:<20}",
                table_column=Column(width=20, no_wrap=True, overflow="ellipsis"),
            ),
            BarColumn(
                bar_width=16,
                complete_style="bold #dc2626",
                finished_style="dim green",
                table_column=Column(width=16, no_wrap=True),
            ),
            TextColumn(
                "[dim]{task.fields[status]:<24}",
                table_column=Column(width=24, no_wrap=True, overflow="ellipsis"),
            ),
            TimeElapsedColumn(table_column=Column(width=8, no_wrap=True)),
            console=self.console,
            transient=False,
            auto_refresh=True,
            refresh_per_second=10,
            expand=False,
        )
        self._tasks: dict[str, int] = {}
        self._entered = False
        self._lock = threading.Lock()

    # ---- context manager ----
    def __enter__(self):
        if self.quiet:
            return self._noop
        with self._lock:
            self.progress.__enter__()
            self._entered = True
        return self

    def __exit__(self, *exc):
        if self.quiet:
            return False
        with self._lock:
            if self._entered:
                self.progress.__exit__(*exc)
                self._entered = False
        return False

    def stop(self):
        if self.quiet:
            return
        with self._lock:
            if self._entered:
                live = getattr(self.progress, "live", None)
                refresh_thread = getattr(live, "_refresh_thread", None) if live else None
                self.progress.stop()
                if refresh_thread is not None and refresh_thread.is_alive():
                    refresh_thread.join(timeout=0.2)
                self._entered = False
                try:
                    if hasattr(self.console.file, "flush"):
                        self.console.file.flush()
                    sys.stdout.flush()
                except Exception:
                    pass
                # Settle terminal buffer before subsequent Rich renders
                time.sleep(0.05)

    # ---- public API ----
    def start(self, name: str, status: str = "running..."):
        if self.quiet:
            return
        with self._lock:
            if not self._entered:
                self.progress.start()
                self._entered = True
            tid = self.progress.add_task(name, total=100, status=status[:24])
            self._tasks[name] = tid
            self.progress.refresh()

    def update(self, name: str, status: str, completed: float | None = None):
        if self.quiet:
            return
        with self._lock:
            tid = self._tasks.get(name)
            if tid is None:
                return
            kw = {"status": status[:24]}
            if completed is not None:
                kw["completed"] = completed
            self.progress.update(tid, refresh=True, **kw)

    def done(self, name: str, msg: str = ""):
        if self.quiet:
            return
        with self._lock:
            tid = self._tasks.pop(name, None)
            if tid is not None:
                status_text = (msg if msg else "completed")[:24]
                self.progress.update(
                    tid,
                    status=status_text,
                    completed=100,
                    refresh=True,
                )

    def fail(self, name: str, msg: str):
        if self.quiet:
            return
        with self._lock:
            tid = self._tasks.pop(name, None)
            if tid is not None:
                status_text = f"[red]✗ {msg}[/red]"[:34]
                self.progress.update(
                    tid,
                    status=status_text,
                    completed=100,
                    refresh=True,
                )