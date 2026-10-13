"""Base class for all report generators."""
from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from sentinelscan.core.findings import ScanResult


class BaseReporter(ABC):
    extension: str = "txt"

    @abstractmethod
    def render(self, result: ScanResult) -> str:
        ...

    def write(self, result: ScanResult, path: Path) -> None:
        """Write report to disk with strict UTF-8."""
        path.parent.mkdir(parents=True, exist_ok=True)
        content = self.render(result)
        # UTF-8 explicit + newline="" (Windows CRLF issue avoid)
        with path.open("w", encoding="utf-8", newline="\n") as fh:
            fh.write(content)