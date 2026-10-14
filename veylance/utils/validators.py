"""Reusable validators."""
from __future__ import annotations
import ipaddress
import re
from urllib.parse import urlparse


HOSTNAME_RX = re.compile(r"^(?=.{1,253}$)([a-zA-Z0-9_]([a-zA-Z0-9_\-]{0,61}[a-zA-Z0-9_])?\.)+[a-zA-Z]{2,}$")


def is_valid_host(host: str) -> bool:
    if not host:
        return False
    if host in ("localhost",):
        return True
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return bool(HOSTNAME_RX.match(host))


def is_url(url: str) -> bool:
    try:
        p = urlparse(url)
        return p.scheme in ("http", "https") and bool(p.netloc)
    except Exception:
        return False