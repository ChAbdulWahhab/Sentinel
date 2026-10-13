"""Global configuration constants."""
from __future__ import annotations

from pathlib import Path

APP_NAME = "SentinelScan"
VERSION = "0.1.0"
DEFAULT_UA = f"SentinelScan/{VERSION} (+https://github.com/ChAbdulWahhab/sentinelscan) SelfAudit"

# Report formats jo CLI accept karta hai
DEFAULT_FORMATS = {
    "markdown", "md",
    "json",
    "html",
    "sarif",
    "csv",
    "pdf",
}

# User config dir
CONFIG_DIR = Path.home() / ".sentinelscan"
CONFIG_DIR.mkdir(parents=True, exist_ok=True)

CACHE_DIR = CONFIG_DIR / "cache"
CACHE_DIR.mkdir(parents=True, exist_ok=True)

# Default scan limits
DEFAULT_MAX_PAGES = 40
DEFAULT_CONCURRENCY = 10
DEFAULT_RATE_REQUESTS = 20
DEFAULT_TIMEOUT = 10

# Legal notice — CLI pe dikhta hai
LEGAL_NOTICE = (
    "Ye tool sirf apni ya authorized websites par use karein. "
    "Unauthorized scanning illegal hai (IT Act 2000 Sec 43/66, CFAA, etc.). "
    "User khud zimmedar hai kisi bhi misuse ke liye."
)