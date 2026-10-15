"""User consent tracking and persistence for legal authorization."""
from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional, Union

from rich.prompt import Confirm

from veylance.config import CONSENT_FILE, LEGAL_NOTICE, TERMS_VERSION

if TYPE_CHECKING:
    from rich.console import Console


def has_consent(
    domain: Optional[Union[str, Path]] = None,
    consent_path: Optional[Union[Path, str]] = None,
    required_version: str = TERMS_VERSION,
) -> bool:
    """Check if the user has recorded active consent.

    If domain is provided, checks whether this exact domain or its parent domain
    has an active consent record matching required_version.
    If domain is None, checks general terms consent.
    Supports legacy positional call has_consent(path, version).
    """
    if isinstance(domain, Path):
        actual_path = domain
        actual_version = consent_path if isinstance(consent_path, str) else required_version
        actual_domain = None
    else:
        actual_path = consent_path if isinstance(consent_path, Path) else CONSENT_FILE
        actual_version = required_version
        actual_domain = str(domain).strip().lower() if domain is not None else None

    if not actual_path.exists():
        return False
    try:
        data: dict[str, Any] = json.loads(actual_path.read_text(encoding="utf-8"))
        if not bool(data.get("consented")):
            return False
        if str(data.get("terms_version")) != str(actual_version):
            return False

        if actual_domain is None:
            return True

        domains = data.get("domains")
        if not isinstance(domains, dict):
            return False

        for saved_domain, meta in domains.items():
            if not isinstance(meta, dict):
                continue
            if str(meta.get("terms_version", data.get("terms_version"))) != str(actual_version):
                continue
            sd = saved_domain.strip().lower()
            if actual_domain == sd or actual_domain.endswith("." + sd):
                return True

        return False
    except Exception:
        return False


def record_consent(
    domain: Optional[Union[str, Path]] = None,
    consent_path: Optional[Union[Path, str]] = None,
    version: str = TERMS_VERSION,
) -> None:
    """Record consent with timestamp, terms version, and optional domain authorization.

    Supports legacy positional call record_consent(path, version).
    """
    if isinstance(domain, Path):
        actual_path = domain
        actual_version = consent_path if isinstance(consent_path, str) else version
        actual_domain = None
    else:
        actual_path = consent_path if isinstance(consent_path, Path) else CONSENT_FILE
        actual_version = version
        actual_domain = str(domain).strip().lower() if domain is not None else None

    data: dict[str, Any] = {}
    if actual_path.exists():
        try:
            data = json.loads(actual_path.read_text(encoding="utf-8"))
        except Exception:
            data = {}

    data["consented"] = True
    data["terms_version"] = actual_version
    data["timestamp"] = datetime.now(timezone.utc).isoformat()

    if actual_domain:
        domains = data.get("domains")
        if not isinstance(domains, dict):
            domains = {}
        domains[actual_domain] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "terms_version": actual_version,
        }
        data["domains"] = domains

    try:
        actual_path.parent.mkdir(parents=True, exist_ok=True)
        actual_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    except Exception:
        pass


def prompt_for_consent(
    console: Console,
    target_host: str,
    consent_path: Optional[Path] = None,
    version: str = TERMS_VERSION,
) -> bool:
    """Display legal reminder and prompt for authorization/terms consent.

    Asks the user if they own or are authorized to test the target.
    If yes, asks whether to save this authorization for future scans.
    Returns True if authorized, False otherwise.
    """
    clean_host = target_host.strip().lower()
    target_path = consent_path or CONSENT_FILE

    console.print(
        f"\n[yellow]Legal reminder:[/yellow] Scan only [bold]{clean_host}[/bold] "
        "if you own it or have explicit written authorization.\n"
        f"[dim]{LEGAL_NOTICE}[/dim]\n"
    )
    agreed = Confirm.ask(
        f"Do you own '{clean_host}' or have explicit written authorization to test it?",
        default=False,
    )
    if not agreed:
        return False

    save_choice = Confirm.ask(
        f"Save authorization for '{clean_host}' to ~/.veylance/consent.json for future scans?",
        default=True,
    )
    if save_choice:
        record_consent(domain=clean_host, consent_path=target_path, version=version)
    else:
        record_consent(domain=None, consent_path=target_path, version=version)

    return True
