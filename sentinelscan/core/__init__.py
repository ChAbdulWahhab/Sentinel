"""SentinelScan core package.

Central orchestration layer:
  - engine.py     -> ScanEngine (module runner)
  - session.py    -> HttpSession (async httpx wrapper)
  - crawler.py    -> Crawler (HTML parser + link extraction)
  - findings.py   -> Finding / Severity / ScanResult models
  - target.py     -> Target (URL validation + normalization)
"""

from sentinelscan.core.findings import Finding, ScanResult, Severity
from sentinelscan.core.target import Target
from sentinelscan.core.session import HttpSession
from sentinelscan.core.crawler import Crawler
from sentinelscan.core.engine import ScanEngine

__all__ = [
    "Finding",
    "ScanResult",
    "Severity",
    "Target",
    "HttpSession",
    "Crawler",
    "ScanEngine",
]

__version__ = "0.1.0"