"""Report generators.

Each format is a class inheriting from BaseReporter.
The CLI calls `get_reporter(fmt)`.

Supported formats:
  - markdown / md
  - json
  - html
  - sarif  (GitHub code scanning)
  - csv
  - pdf    (requires reportlab)
"""
from veylance.report.base import BaseReporter
from veylance.report.markdown import MarkdownReporter
from veylance.report.json_report import JsonReporter
from veylance.report.html_report import HtmlReporter
from veylance.report.sarif import SarifReporter
from veylance.report.csv_report import CsvReporter
from veylance.report.pdf_report import PdfReporter

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