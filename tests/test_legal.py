from datetime import datetime
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from sentinelscan.cli import app
from sentinelscan.config import LEGAL_NOTICE, REPORT_DISCLAIMER, TERMS_VERSION
from sentinelscan.core.findings import Finding, ScanResult, Severity
from sentinelscan.report.csv_report import CsvReporter
from sentinelscan.report.html_report import HtmlReporter
from sentinelscan.report.json_report import JsonReporter
from sentinelscan.report.markdown import MarkdownReporter
from sentinelscan.report.sarif import SarifReporter
from sentinelscan.ui.consent import has_consent, record_consent
from sentinelscan.utils.audit import log_audit_event

runner = CliRunner()


def test_consent_persistence(tmp_path: Path):
    consent_file = tmp_path / "consent.json"
    assert not has_consent(consent_file, TERMS_VERSION)

    record_consent(consent_file, TERMS_VERSION)
    assert has_consent(consent_file, TERMS_VERSION)

    # Version bump invalidates consent
    assert not has_consent(consent_file, "2.0")


def test_audit_logging(tmp_path: Path):
    audit_file = tmp_path / "audit.log"
    log_audit_event(
        action="TEST_ACTION",
        target="https://example.com",
        auth_method="test-method",
        extra={"note": "test"},
        log_file=audit_file,
    )
    assert audit_file.exists()
    lines = audit_file.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    data = json.loads(lines[0])
    assert data["action"] == "TEST_ACTION"
    assert data["target"] == "https://example.com"
    assert data["auth_method"] == "test-method"


def test_report_formats_disclaimers():
    sample_finding = Finding(
        severity=Severity.LOW,
        title="Sample Finding",
        detail="Sample Detail",
        fix="Sample Fix",
        url="https://example.com",
    )
    result = ScanResult(
        target="https://example.com",
        timestamp=datetime(2026, 1, 1, 12, 0, 0),
        findings=[sample_finding],
        pages={"https://example.com/": (200, "text/html")},
        tech={"Nginx"},
        info={},
        forms=[],
        scripts=set(),
        js_endpoints=set(),
        duration=1.0,
        modules_run=["headers"],
        errors=[],
    )

    # 1. Markdown
    md = MarkdownReporter().render(result)
    assert "Legal Notice" in md
    assert "Disclaimer" in md

    # 2. JSON
    js = JsonReporter().render(result)
    assert "legal_banner" in js
    assert "legal_disclaimer" in js

    # 3. HTML
    htm = HtmlReporter().render(result)
    assert "Legal Notice" in htm
    assert "Disclaimer" in htm

    # 4. SARIF
    sar = SarifReporter().render(result)
    assert "legalNotice" in sar
    assert "disclaimer" in sar

    # 5. CSV
    csv_out = CsvReporter().render(result)
    assert "# LEGAL NOTICE" in csv_out
    assert "# LEGAL DISCLAIMER" in csv_out


def test_i_own_this_mismatch():
    res = runner.invoke(app, ["scan", "https://example.com", "--i-own-this", "otherdomain.com", "-m", "headers"])
    assert res.exit_code != 0
    assert "Domain mismatch" in res.output
