"""Base class for all scan modules."""
from __future__ import annotations

from abc import ABC, abstractmethod

from sentinelscan.core.findings import Finding
from sentinelscan.core.session import HttpSession
from sentinelscan.core.target import Target


class BaseModule(ABC):
    name: str = "base"
    description: str = "Base module"
    requires_crawl: bool = False   # agar True, engine pehle crawl karega

    def __init__(self, target: Target, session: HttpSession, ctx: dict):
        self.target = target
        self.session = session
        self.ctx = ctx                # shared crawl data, findings store
        self.findings: list[Finding] = []

    def add(self, **kw) -> None:
        self.findings.append(Finding(module=self.name, **kw))

    @abstractmethod
    async def run(self) -> list[Finding]:
        ...

    async def cleanup(self) -> None:
        pass