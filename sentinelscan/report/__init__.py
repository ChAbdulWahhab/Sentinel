"""Report generators.

Har format ek class hai jo BaseReporter inherit karti hai.
CLI `get_reporter(fmt)` call karta hai.

Supported formats:
  - markdown / md
  - json
  - html
  - sarif  (GitHub code scanning)
  - csv
  - pdf    (requires reportlab)
"""
from sentinelscan.report.base import BaseReporter
from sentinelscan.report.markdown import MarkdownReporter
from sentinelscan.report.json_report import JsonReporter
from sentinelscan.report.html_report import HtmlReporter
from sentinelscan.report.sarif import SarifReporter
from sentinelscan.report.csv_report import CsvReporter
from sentinelscan.report.pdf_report import PdfReporter

REPORTERS: dict[str, type[BaseReporter]] = {
    "markdown": MarkdownReporter,
    "md": MarkdownReporter,
    "json": JsonReporter,
    "html": HtmlReporter,
    "sarif": SarifReporter,
    "csv": CsvReporter,
    "pdf": PdfReporter,
}


def get_reporter(name: str) -> BaseReporter:
    cls = REPORTERS.get(name.lower())
    if not cls:
        raise ValueError(
            f"Unknown format: {name}. "
            f"Available: {', '.join(sorted(set(REPORTERS)))}"
        )
    return cls()


__all__ = ["REPORTERS", "get_reporter", "BaseReporter"]