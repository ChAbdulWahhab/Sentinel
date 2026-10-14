"""Base class for all scan modules."""
from __future__ import annotations

from abc import ABC, abstractmethod

from veylance.core.findings import Finding
from veylance.core.session import HttpSession
from veylance.core.target import Target


class BaseModule(ABC):
    name: str = "base"
    description: str = "Base module"
    requires_crawl: bool = False   # if True, engine crawls first

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