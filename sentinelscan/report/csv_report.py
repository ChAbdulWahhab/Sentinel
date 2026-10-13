"""CSV reporter — Excel-friendly output.

Excel ko UTF-8 BOM chahiye warna Hindi/emoji galat dikhte hain.
Isliye ye reporter `write()` override karta hai aur `utf-8-sig` use karta hai.

Notes:
    - newline=""        -> csv module apna line terminator manage kare
    - lineterminator="\\n" -> mixed CRLF/LF newlines avoid
    - utf-8-sig         -> Excel me Hindi/emoji sahi dikhe
    - Excel cell limit  -> 32767 chars per cell
"""
from __future__ import annotations

import csv
import io
from pathlib import Path
from typing import Any

from sentinelscan.core.findings import ScanResult
from sentinelscan.report.base import BaseReporter


# Column order — user friendly
COLUMNS = [
    "#",
    "Severity",
    "Module",
    "Title",
    "URL",
    "Detail",
    "Fix",
    "CWE",
    "OWASP",
    "Evidence",
    "Timestamp",
]

# Excel cell character limit
EXCEL_CELL_LIMIT = 32000
# Evidence shorter rakhna hai (readability ke liye)
EVIDENCE_LIMIT = 500


def _clean(value: Any, limit: int | None = None) -> str:
    """Sanitize a cell value for CSV.

    - None -> ""
    - Newlines/CR -> space
    - Control chars -> strip
    - Optional length limit
    """
    if value is None:
        return ""
    s = str(value)
    # CRLF, CR, LF sabko single space me
    s = s.replace("\r\n", " ").replace("\n", " ").replace("\r", " ")
    # Null bytes aur other control chars hata do (CSV/Excel crash karte hain)
    s = "".join(ch for ch in s if ch == "\t" or ord(ch) >= 32)
    # Multiple spaces ko single me collapse (optional)
    s = " ".join(s.split())
    if limit and len(s) > limit:
        s = s[: limit - 3] + "..."
    return s


def _strip_backticks(value: str) -> str:
    """Markdown-style backtick wrapper hata do."""
    s = value.strip()
    if s.startswith("`") and s.endswith("`"):
        return s[1:-1].strip()
    return s


class CsvReporter(BaseReporter):
    extension = "csv"

    def render(self, r: ScanResult) -> str:
        """Return CSV string with UTF-8 content."""
        buf = io.StringIO()
        writer = csv.writer(
            buf,
            quoting=csv.QUOTE_MINIMAL,
            lineterminator="\n",
            doublequote=True,
        )

        # Header
        writer.writerow(COLUMNS)

        # Sort: severity (CRITICAL first) -> module -> title
        sorted_findings = sorted(
            r.findings,
            key=lambda f: (
                int(f.severity),
                f.module or "",
                f.title or "",
            ),
        )

        for i, f in enumerate(sorted_findings, 1):
            timestamp = ""
            if f.timestamp:
                try:
                    timestamp = f.timestamp.strftime("%Y-%m-%d %H:%M:%S")
                except Exception:
                    timestamp = str(f.timestamp)

            writer.writerow([
                i,
                f.severity.name if f.severity else "",
                _clean(f.module, 100),
                _clean(f.title, 300),
                _clean(f.url, 500),
                _clean(f.detail, EXCEL_CELL_LIMIT),
                _clean(_strip_backticks(f.fix or ""), EXCEL_CELL_LIMIT),
                _clean(f.cwe, 50),
                _clean(f.owasp, 50),
                _clean(f.evidence, EVIDENCE_LIMIT),
                timestamp,
            ])

        return buf.getvalue()

    def write(self, result: ScanResult, path: Path) -> None:
        """Write CSV with UTF-8 BOM (Excel-compatible)."""
        path.parent.mkdir(parents=True, exist_ok=True)
        content = self.render(result)
        # utf-8-sig = UTF-8 + BOM -> Excel sahi khole
        # newline="" = csv module apna newline manage karega
        with path.open("w", encoding="utf-8-sig", newline="") as fh:
            fh.write(content)