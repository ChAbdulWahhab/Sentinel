"""Target URL validation and normalization."""
from __future__ import annotations

from urllib.parse import urlparse, urlunparse


class Target:
    def __init__(self, raw: str):
        raw = raw.strip()
        if not raw:
            raise ValueError("Target URL cannot be empty")
        if not raw.startswith(("http://", "https://")):
            raw = "https://" + raw

        p = urlparse(raw)
        if not p.netloc:
            raise ValueError(f"Invalid host: {raw}")
        if "." not in p.hostname and p.hostname not in ("localhost",):
            raise ValueError(f"Invalid target host: {p.hostname}")

        self.scheme = p.scheme
        self.hostname = p.hostname
        self.port = p.port
        self.host = p.hostname if not p.port else f"{p.hostname}:{p.port}"
        self.netloc = p.netloc
        self.path = p.path or "/"

        # normalize base
        self.base = urlunparse((p.scheme, p.netloc, "", "", "", "")).rstrip("/")

    @property
    def url(self) -> str:
        return self.base + self.path

    def __repr__(self) -> str:
        return f"Target({self.base})"

    @property
    def root(self) -> str:
        return self.base + "/"