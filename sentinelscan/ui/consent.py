"""User consent tracking and persistence for legal authorization."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from rich.prompt import Confirm

from sentinelscan.config import CONSENT_FILE, LEGAL_NOTICE, TERMS_VERSION

if TYPE_CHECKING:
    from rich.console import Console


def has_consent(
    consent_path: Path = CONSENT_FILE,
    required_version: str = TERMS_VERSION,
) -> bool:
    """Check if the user has recorded active consent for the current terms version."""
    if not consent_path.exists():
        return False
    try:
        data = json.loads(consent_path.read_text(encoding="utf-8"))
        return (
            bool(data.get("consented"))
            and str(data.get("terms_version")) == str(required_version)
        )
    except Exception:
        return False


def record_consent(
    consent_path: Path = CONSENT_FILE,
    version: str = TERMS_VERSION,
) -> None:
    """Record consent with timestamp and terms version."""
    data = {
        "consented": True,
        "terms_version": version,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    try:
        consent_path.parent.mkdir(parents=True, exist_ok=True)
        consent_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    except Exception:
        pass


def prompt_for_consent(
    console: Console,
    target_host: str,
    consent_path: Path = CONSENT_FILE,
    version: str = TERMS_VERSION,
) -> bool:
    """Display legal reminder and prompt for authorization/terms consent.

    If accepted, persists consent and returns True. Otherwise returns False.
    """
    console.print(
        f"\n[yellow]⚠️  Legal reminder:[/yellow] Scan only [bold]{target_host}[/bold] "
        "if you own it or have explicit written permission.\n"
        f"[dim]{LEGAL_NOTICE}[/dim]\n"
    )
    agreed = Confirm.ask(
        "Are you authorized to scan this target and do you agree to the terms?",
        default=False,
    )
    if agreed:
        record_consent(consent_path=consent_path, version=version)
        return True
    return False
