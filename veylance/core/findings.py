"""Finding model — returned by each check."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import IntEnum
from typing import Any, Optional


class Severity(IntEnum):
    CRITICAL = 0
    HIGH = 1
    MEDIUM = 2
    LOW = 3
    INFO = 4

    @property
    def color(self) -> str:
        return {
            Severity.CRITICAL: "#dc2626",
            Severity.HIGH: "#ea580c",
            Severity.MEDIUM: "#f59e0b",
            Severity.LOW: "#60a5fa",
            Severity.INFO: "#6b7280",
        }[self]

    @property
    def label(self) -> str:
        return self.name.capitalize()


@dataclass
class Finding:
    severity: Severity
    title: str
    detail: str
    code: Optional[str] = None          # Stable identifier, e.g. "RATE_LIMIT_NOT_DETECTED"
    finding_code: Optional[str] = None  # Alias for code
    fix: str = ""
    module: str = ""
    url: str = ""
    evidence: Optional[str] = None
    cwe: Optional[str] = None          # e.g. "CWE-79"
    owasp: Optional[str] = None        # e.g. "A03:2021"
    references: list[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)

    def __post_init__(self):
        if self.code and not self.finding_code:
            self.finding_code = self.code
        elif self.finding_code and not self.code:
            self.code = self.finding_code


@dataclass
class ScanResult:
    target: str
    timestamp: datetime
    findings: list[Finding]
    pages: dict[str, tuple[int, str]]         # url -> (status, ctype)
    tech: set[str]
    info: dict[str, Any]
    forms: list[tuple[str, dict]]
    scripts: set[str]
    js_endpoints: set[str]
    duration: float
    modules_run: list[str]
    errors: list[str] = field(default_factory=list)

    def counts(self) -> dict[Severity, int]:
        from collections import Counter
        c = Counter(f.severity for f in self.findings)
        return {s: c.get(s, 0) for s in Severity}