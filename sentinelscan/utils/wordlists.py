"""Bundled wordlist loader."""
from __future__ import annotations

import sys
from pathlib import Path

if sys.version_info >= (3, 9):
    from importlib.resources import files
else:
    from importlib_resources import files  # type: ignore

DATA_DIR = Path(__file__).resolve().parent.parent / "data"


def load(name: str) -> list[str]:
    """Load line-delimited wordlist from bundled package data."""
    try:
        data_path = files("sentinelscan.data").joinpath(name)
        text = data_path.read_text(encoding="utf-8")
        return [
            line.strip()
            for line in text.splitlines()
            if line.strip() and not line.startswith("#")
        ]
    except Exception:
        p = DATA_DIR / name
        if not p.exists():
            return []
        return [
            line.strip()
            for line in p.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#")
        ]