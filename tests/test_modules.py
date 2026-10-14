import pytest
from veylance.core.findings import Severity, Finding


def test_severity_order():
    assert Severity.CRITICAL < Severity.HIGH < Severity.MEDIUM < Severity.LOW < Severity.INFO


def test_finding_defaults():
    f = Finding(severity=Severity.HIGH, title="x", detail="y")
    assert f.fix == ""
    assert f.module == ""