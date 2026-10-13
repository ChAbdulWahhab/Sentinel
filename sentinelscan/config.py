"""Global configuration constants."""
from __future__ import annotations

from pathlib import Path

APP_NAME = "SentinelScan"
VERSION = "0.1.0"
DEFAULT_UA = f"SentinelScan/{VERSION} (+https://github.com/ChAbdulWahhab/sentinelscan) SelfAudit"

# Report formats accepted by the CLI
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

# Legal notice — displayed in the CLI
LEGAL_NOTICE = (
    "Use this tool only on websites you own or have explicit authorization to test. "
    "Unauthorized scanning is illegal (IT Act 2000 Sec 43/66, CFAA, etc.). "
    "The user assumes full responsibility for any misuse."
)