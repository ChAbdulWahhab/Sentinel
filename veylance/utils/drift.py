"""Scan history persistence and temporal drift detection across audits.

STORAGE LOCATION & FORMAT:
History fingerprints are stored locally under:
  ~/.veylance/history/<target_hash>.json

Each file contains:
  {
    "target": "https://example.com",
    "timestamp": "2026-10-16T01:25:00.000000",
    "findings": [
      {"title": "...", "severity": "HIGH", "module": "headers", "url": "..."}
    ],
    "js_endpoints": ["/api/v1/users", ...],
    "subdomains": ["api.example.com", ...]
  }

This allows Veylance to detect new exposures, verify remediations,
and track attack surface expansion without maintaining a database.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
from typing import Any

from veylance.config import CONFIG_DIR
from veylance.core.findings import Finding

HISTORY_DIR = CONFIG_DIR / "history"
HISTORY_DIR.mkdir(parents=True, exist_ok=True)


def get_target_hash(target_url: str) -> str:
    """Compute a deterministic 16-character hex hash for the normalized target URL."""
    clean_url = target_url.strip().rstrip("/").lower()
    return hashlib.sha256(clean_url.encode("utf-8")).hexdigest()[:16]


def get_history_file_path(target_url: str) -> Path:
    """Return the absolute path to the target's history fingerprint file."""
    thash = get_target_hash(target_url)
    return HISTORY_DIR / f"{thash}.json"


def load_prior_fingerprint(target_url: str, history_dir: Path | None = None) -> dict[str, Any] | None:
    """Load the most recent prior fingerprint for the target, if it exists."""
    hdir = history_dir or HISTORY_DIR
    thash = get_target_hash(target_url)
    path = hdir / f"{thash}.json"
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict) and "findings" in data:
            return data
    except Exception:
        pass
    return None


def save_target_fingerprint(
    target_url: str,
    findings: list[Finding],
    js_endpoints: set[str] | list[str],
    subdomains: set[str] | list[str],
    history_dir: Path | None = None,
) -> Path:
    """Save a lightweight fingerprint for the current scan."""
    hdir = history_dir or HISTORY_DIR
    hdir.mkdir(parents=True, exist_ok=True)
    thash = get_target_hash(target_url)
    path = hdir / f"{thash}.json"

    from datetime import datetime
    fp_data = {
        "target": target_url,
        "timestamp": datetime.now().isoformat(),
        "findings": [
            {
                "title": f.title,
                "severity": f.severity.name,
                "module": f.module,
                "url": f.url,
            }
            for f in findings
            if f.module not in ("scan_drift",)  # Don't store drift findings recursively
        ],
        "js_endpoints": sorted(set(js_endpoints)),
        "subdomains": sorted(set(subdomains)),
    }

    path.write_text(json.dumps(fp_data, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


MAX_SUBDOMAIN_DELTA_SANITY: int = 50


@dataclass
class ScanDriftResult:
    prior_timestamp: str
    new_findings: list[dict[str, str]]
    resolved_findings: list[dict[str, str]]
    new_js_endpoints: list[str]
    new_subdomains: list[str]
    subdomain_delta_anomalous: bool = False
    subdomain_warning: str | None = None

    @property
    def has_changes(self) -> bool:
        return bool(
            self.new_findings
            or self.resolved_findings
            or self.new_js_endpoints
            or self.new_subdomains
            or self.subdomain_delta_anomalous
        )


def compute_scan_drift(
    target_url: str,
    current_findings: list[Finding],
    current_js_endpoints: set[str] | list[str],
    current_subdomains: set[str] | list[str],
    history_dir: Path | None = None,
    max_subdomain_delta: int = MAX_SUBDOMAIN_DELTA_SANITY,
) -> ScanDriftResult | None:
    """Compare current scan data with the most recent prior fingerprint."""
    prior = load_prior_fingerprint(target_url, history_dir=history_dir)
    if not prior:
        return None

    # Key findings by (module, title, url)
    def _finding_key(item: Any) -> tuple[str, str, str]:
        if isinstance(item, Finding):
            return (item.module, item.title, item.url or "")
        return (item.get("module", ""), item.get("title", ""), item.get("url", ""))

    prior_finding_map = {_finding_key(f): f for f in prior.get("findings", [])}
    current_finding_map = {_finding_key(f): f for f in current_findings if f.module not in ("scan_drift", "combined_risk_scenarios")}

    new_findings = []
    for k, f in current_finding_map.items():
        if k not in prior_finding_map:
            new_findings.append({
                "title": f.title,
                "severity": f.severity.name,
                "module": f.module,
                "url": f.url or "",
            })

    resolved_findings = []
    for k, pf in prior_finding_map.items():
        if k not in current_finding_map:
            resolved_findings.append(pf)

    prior_endpoints = set(prior.get("js_endpoints", []))
    new_endpoints = sorted(set(current_js_endpoints) - prior_endpoints)

    prior_subs = set(prior.get("subdomains", []))
    raw_new_subs = sorted(set(current_subdomains) - prior_subs)

    subdomain_delta_anomalous = False
    subdomain_warning = None
    if len(raw_new_subs) > max_subdomain_delta:
        import logging
        logging.getLogger("veylance.drift").warning(
            "Subdomain delta of +%d exceeds sanity threshold of %d. Flagging as upstream anomaly.",
            len(raw_new_subs),
            max_subdomain_delta,
        )
        subdomain_delta_anomalous = True
        subdomain_warning = (
            f"Subdomain delta (+{len(raw_new_subs)}) exceeded sanity threshold ({max_subdomain_delta}) "
            "— suppressed as probable upstream wildcard/platform scope anomaly."
        )
        # Suppress reporting thousands of anomalous hostnames
        new_subs = []
    else:
        new_subs = raw_new_subs

    return ScanDriftResult(
        prior_timestamp=prior.get("timestamp", ""),
        new_findings=new_findings,
        resolved_findings=resolved_findings,
        new_js_endpoints=new_endpoints,
        new_subdomains=new_subs,
        subdomain_delta_anomalous=subdomain_delta_anomalous,
        subdomain_warning=subdomain_warning,
    )
