from datetime import datetime
from pathlib import Path
import json

from veylance.core.findings import Finding, ScanResult, Severity
from veylance.report.json_report import JsonReporter


def test_json_reporter_utf8_non_ascii(tmp_path: Path):
    reporter = JsonReporter()
    hindi_text = "सुरक्षा ऑडिट"
    emoji = "🛡️"
    sample_finding = Finding(
        severity=Severity.HIGH,
        title=f"{emoji} {hindi_text}",
        detail="विवरण: संवेदनशील डेटा मिला",
        fix="सुरक्षित कॉन्फ़िगरेशन लागू करें",
        url="https://example.com/api",
    )
    result = ScanResult(
        target="https://example.com",
        timestamp=datetime(2026, 1, 1, 12, 0, 0),
        findings=[sample_finding],
        pages={"https://example.com/": (200, "text/html")},
        tech={"Nginx"},
        info={"server": "Nginx"},
        forms=[],
        scripts=set(),
        js_endpoints=set(),
        duration=1.23,
        modules_run=["headers"],
        errors=[],
    )

    out_file = tmp_path / "test_report.json"
    reporter.write(result, out_file)

    # 1. Read raw content with utf-8 encoding
    raw_content = out_file.read_text(encoding="utf-8")

    # 2. Assert raw content preserves unicode characters literally without \u escaping
    assert hindi_text in raw_content
    assert emoji in raw_content
    assert "\\u0938" not in raw_content

    # 3. Verify valid JSON parse back
    data = json.loads(raw_content)
    assert data["findings"][0]["title"] == f"{emoji} {hindi_text}"
