"""Bundled wordlist loader."""
from __future__ import annotations
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "data"


def load(name: str) -> list[str]:
    p = DATA_DIR / name
    if not p.exists():
        return []
    return [l.strip() for l in p.read_text(encoding="utf-8").splitlines() if l.strip() and not l.startswith("#")]