"""Veylance core package.

Central orchestration layer:
  - engine.py     -> ScanEngine (module runner)
  - session.py    -> HttpSession (async httpx wrapper)
  - crawler.py    -> Crawler (HTML parser + link extraction)
  - findings.py   -> Finding / Severity / ScanResult models
  - target.py     -> Target (URL validation + normalization)
"""

from veylance.core.findings import Finding, ScanResult, Severity
from veylance.core.target import Target
from veylance.core.session import HttpSession
from veylance.core.crawler import Crawler
from veylance.core.engine import ScanEngine

__all__ = [
    "Finding",
    "ScanResult",
    "Severity",
    "Target",
    "HttpSession",
    "Crawler",
    "ScanEngine",
]

from veylance.config import VERSION

__version__ = VERSION