"""Global configuration constants."""
from __future__ import annotations

from pathlib import Path

APP_NAME = "Veylance"
VERSION = "0.1.2"
DEFAULT_UA = f"Veylance/{VERSION} (+https://github.com/ChAbdulWahhab/veylance) SelfAudit"

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
CONFIG_DIR = Path.home() / ".veylance"
CONFIG_DIR.mkdir(parents=True, exist_ok=True)

CACHE_DIR = CONFIG_DIR / "cache"
CACHE_DIR.mkdir(parents=True, exist_ok=True)

CONSENT_FILE = CONFIG_DIR / "consent.json"
AUDIT_LOG_FILE = CONFIG_DIR / "audit.log"
DEBUG_LOG_FILE = CONFIG_DIR / "debug.log"

# Default scan limits
DEFAULT_MAX_PAGES = 40
DEFAULT_CONCURRENCY = 10
DEFAULT_RATE_REQUESTS = 20
DEFAULT_TIMEOUT = 10

# Legal configuration & disclaimers
TERMS_VERSION = "1.0"

LEGAL_NOTICE = (
    "Use this tool only on websites you own or have explicit authorization to test. "
    "Unauthorized scanning is illegal (IT Act 2000 Sec 43/66, CFAA, etc.). "
    "The user assumes full responsibility for any misuse."
)

REPORT_DISCLAIMER = (
    "This report is generated for authorized security auditing purposes only. "
    "Veylance and its maintainers assume no liability for any unauthorized testing, "
    "damage, or misuse of this report. All testing must comply with applicable computer crime laws."
)