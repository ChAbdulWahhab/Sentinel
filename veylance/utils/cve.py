"""CVE advisory matcher for detected components."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from veylance.core.findings import Finding, Severity

ADVISORIES_FILE = Path(__file__).resolve().parent.parent / "data" / "cve_advisories.json"


def _parse_version(v_str: str) -> tuple[int, ...] | None:
    """Parse version string into tuple of ints for comparison."""
    if not v_str:
        return None
    # Strip any leading 'v' or non-digits
    cleaned = v_str.strip().lstrip("vV")
    parts = []
    for chunk in cleaned.split("."):
        # Take digits only from chunk (e.g. '1f' -> 1)
        digits = ""
        for ch in chunk:
            if ch.isdigit():
                digits += ch
            else:
                break
        if digits:
            parts.append(int(digits))
        else:
            break
    return tuple(parts) if parts else None


def _version_in_range(ver: tuple[int, ...], min_ver: tuple[int, ...], max_ver: tuple[int, ...]) -> bool:
    """Check if version is within [min_ver, max_ver] inclusive."""
    # Pad to equal length for safe tuple comparison
    max_len = max(len(ver), len(min_ver), len(max_ver))
    v_padded = ver + (0,) * (max_len - len(ver))
    min_padded = min_ver + (0,) * (max_len - len(min_ver))
    max_padded = max_ver + (0,) * (max_len - len(max_ver))
    return min_padded <= v_padded <= max_padded


def load_advisories() -> dict[str, list[dict[str, Any]]]:
    """Load local CVE dataset."""
    if not ADVISORIES_FILE.exists():
        return {}
    try:
        return json.loads(ADVISORIES_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def match_cves(component: str, version_str: str, target_url: str) -> list[Finding]:
    """Match detected component and version against local CVE advisories (informational only)."""
    parsed = _parse_version(version_str)
    if not parsed:
        return []

    advisories = load_advisories()
    comp_key = component.lower().strip()
    matches = advisories.get(comp_key, [])

    findings = []
    for adv in matches:
        min_v = _parse_version(adv.get("min_version", "0"))
        max_v = _parse_version(adv.get("max_version", "9999"))
        if min_v and max_v and _version_in_range(parsed, min_v, max_v):
            sev_str = adv.get("severity", "MEDIUM")
            # All CVE advisories are informational / assessment guidance
            sev = Severity.INFO if sev_str == "LOW" else getattr(Severity, sev_str, Severity.MEDIUM)
            cve = adv.get("cve", "CVE-UNKNOWN")
            findings.append(
                Finding(
                    severity=sev,
                    title=f"Known CVE Advisory: {cve} ({component} {version_str})",
                    detail=adv.get("summary", ""),
                    fix=adv.get("fix", f"Upgrade {component} to a patched version."),
                    module="tech_fingerprint",
                    url=target_url,
                    evidence=f"Detected {component} version {version_str} falls in advisory range {adv.get('min_version')} - {adv.get('max_version')}",
                    references=[f"https://nvd.nist.gov/vuln/detail/{cve.split()[0]}"],
                )
            )
    return findings
