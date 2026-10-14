"""Audit logging for Veylance scan actions."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from veylance.config import AUDIT_LOG_FILE


def log_audit_event(
    action: str,
    target: str,
    auth_method: str = "none",
    extra: dict[str, Any] | None = None,
    output_dir: Path | None = None,
    log_file: Path = AUDIT_LOG_FILE,
) -> None:
    """Record an action in the audit log (JSON Lines format)."""
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action": action,
        "target": target,
        "auth_method": auth_method,
    }
    if extra:
        record.update(extra)

    entry = json.dumps(record, ensure_ascii=False) + "\n"

    # Global log (~/.veylance/audit.log)
    try:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        with log_file.open("a", encoding="utf-8") as fh:
            fh.write(entry)
    except Exception:
        pass

    # Per-scan output log if output directory is provided
    if output_dir:
        try:
            output_dir.mkdir(parents=True, exist_ok=True)
            with (output_dir / "audit.log").open("a", encoding="utf-8") as fh:
                fh.write(entry)
        except Exception:
            pass
