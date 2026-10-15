"""Regression tests for Bug 3: scan_drift subdomain sanity threshold and DNS verification."""
from pathlib import Path
import pytest
from unittest.mock import MagicMock

from veylance.core.findings import Finding, Severity
from veylance.core.target import Target
from veylance.modules.scan_drift import ScanDriftModule
from veylance.utils.drift import (
    compute_scan_drift,
    save_target_fingerprint,
    MAX_SUBDOMAIN_DELTA_SANITY,
)


def test_compute_scan_drift_subdomain_delta_sanity(tmp_path: Path):
    """Confirm single-scan subdomain deltas over threshold (e.g. 50) are suppressed with a warning."""
    target_url = "https://dealsafe.pages.dev"

    # Prior fingerprint with 2 subdomains
    save_target_fingerprint(
        target_url=target_url,
        findings=[],
        js_endpoints=[],
        subdomains=["dealsafe.pages.dev", "api.dealsafe.pages.dev"],
        history_dir=tmp_path,
    )

    # Next scan: simulated upstream bug returning 1668 subdomains
    massive_subdomains = [f"host-{i}.pages.dev" for i in range(1668)]

    drift = compute_scan_drift(
        target_url=target_url,
        current_findings=[],
        current_js_endpoints=[],
        current_subdomains=massive_subdomains,
        history_dir=tmp_path,
        max_subdomain_delta=50,
    )

    assert drift is not None
    assert drift.subdomain_delta_anomalous is True
    assert drift.subdomain_warning is not None
    assert "exceeded sanity threshold (50)" in drift.subdomain_warning
    # Crucial: clean list must NOT contain 1668 subdomains
    assert len(drift.new_subdomains) == 0


@pytest.mark.asyncio
async def test_scan_drift_module_flags_anomalous_expansion(tmp_path: Path):
    """Verify ScanDriftModule emits an informative finding when delta exceeds sanity limit."""
    target_url = "https://anomaly.test"
    target = Target(target_url)

    save_target_fingerprint(
        target_url=target_url,
        findings=[],
        js_endpoints=[],
        subdomains=["sub1.anomaly.test"],
        history_dir=tmp_path,
    )

    ctx = {
        "history_dir": tmp_path,
        "findings": [],
        "js_endpoints": [],
        "discovered_subdomains": [f"candidate-{i}.anomaly.test" for i in range(100)],
        "info": {},
    }

    mod = ScanDriftModule(target, MagicMock(), ctx)
    findings = await mod.run()

    # Must emit the anomaly suppression finding
    anomaly_finding = next(
        (f for f in findings if "Anomalous Subdomain Expansion" in f.title),
        None,
    )
    assert anomaly_finding is not None
    assert anomaly_finding.severity == Severity.LOW
    assert "sanity threshold" in anomaly_finding.detail


@pytest.mark.asyncio
async def test_scan_drift_normal_delta_preserved(tmp_path: Path):
    """Verify genuine small subdomain growth (<50) is reported normally."""
    target_url = "https://normal.test"
    target = Target(target_url)

    save_target_fingerprint(
        target_url=target_url,
        findings=[],
        js_endpoints=[],
        subdomains=["normal.test"],
        history_dir=tmp_path,
    )

    ctx = {
        "history_dir": tmp_path,
        "findings": [],
        "js_endpoints": [],
        "discovered_subdomains": ["normal.test", "staging.normal.test", "dev.normal.test"],
        "info": {},
    }

    mod = ScanDriftModule(target, MagicMock(), ctx)
    await mod.run()

    drift = ctx["scan_drift"]
    assert drift is not None
    assert not drift.subdomain_delta_anomalous
    assert drift.subdomain_warning is None
    assert sorted(drift.new_subdomains) == ["dev.normal.test", "staging.normal.test"]
